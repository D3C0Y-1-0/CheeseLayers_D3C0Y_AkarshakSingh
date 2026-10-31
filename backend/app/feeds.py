"""Member 2 endpoints: health, threat feed, source health, overview, demo CVE injection. Contract: docs/API.md."""
import json
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from collectors.schema import ThreatItem

from . import hooks
from .database import DEMO_MODE, get_db
from .models import IOCRow, RawPayload, SourceStatus, Threat

router = APIRouter()
HIGH_EPSS = 0.5  # "more likely than not to be exploited in the next 30 days"
SEVERITIES = ("critical", "high", "medium", "low", "none", "unknown")  # unknown = severity is null


# ---------- response models ----------
class Health(BaseModel):
    status: Literal["ok"]
    demo_mode: bool
    threats: int
    time: datetime


class ThreatPage(BaseModel):
    items: list[ThreatItem]
    total: int
    page: int
    page_size: int
    pages: int


class RawPayloadRef(BaseModel):
    id: int
    source: str
    path: str  # repo-relative, e.g. backend/data/raw/kev/latest.json
    sha256: str | None  # None = file referenced but missing on disk
    size_bytes: int | None
    fetched_at: datetime | None


class ThreatDetail(ThreatItem):
    raw_payload: RawPayloadRef | None


class SourceStatusOut(BaseModel):
    source: str
    status: str  # ok | stale | failed | skipped | cache
    last_attempt: datetime | None
    last_success: datetime | None
    age_minutes: int | None  # minutes since last_success
    error: str | None
    record_count: int | None


class Overview(BaseModel):
    threats_total: int
    threats_by_source: dict[str, int]
    threats_by_severity: dict[str, int]  # includes "unknown" for severity = null
    kev_count: int
    high_epss_count: int
    high_epss_threshold: float
    public_exploit_count: int
    simulated_count: int
    ioc_count: int
    iocs_by_type: dict[str, int]
    sources: list[SourceStatusOut]
    newest_retrieved_at: datetime | None
    matched_assets: int | None  # TODO(Member 3): count of assets matched to any threat
    open_alerts: int | None  # TODO(Member 3): count of alerts with status != resolved
    notes: list[str]


class InjectRequest(BaseModel):
    fixture_id: str


class InjectResult(BaseModel):
    injected: ThreatItem
    fixture_file: str
    hook_called: str


# ---------- helpers ----------
def _threat(row: Threat) -> ThreatItem:
    return ThreatItem.model_validate(row, from_attributes=True)


def _status(row: SourceStatus, now: datetime) -> SourceStatusOut:
    age = int((now - row.last_success).total_seconds() // 60) if row.last_success else None
    return SourceStatusOut(source=row.source, status=row.status, last_attempt=row.last_attempt, last_success=row.last_success,
                           age_minutes=age, error=row.error, record_count=row.record_count)


# ---------- endpoints ----------
@router.get("/health", response_model=Health, tags=["system"])
def health(db: Session = Depends(get_db)):
    """Liveness + whether we're running offline from cache (DEMO_MODE)."""
    return Health(status="ok", demo_mode=DEMO_MODE, threats=db.scalar(select(func.count()).select_from(Threat)),
                  time=datetime.now(timezone.utc))


@router.get("/api/threats", response_model=ThreatPage, tags=["threats"])
def list_threats(
    source: str | None = Query(None, description="Comma-separated, e.g. `kev,certin`"),
    severity: str | None = Query(None, description="Comma-separated from critical,high,medium,low,none,unknown (unknown = null)"),
    kev: bool | None = Query(None, description="true = KEV-listed only; false = checked and not listed (null excluded)"),
    min_epss: float | None = Query(None, ge=0, le=1, description="EPSS >= this (threats with null EPSS excluded)"),
    q: str | None = Query(None, min_length=2, description="Case-insensitive search in threat_id, title, description"),
    simulated: bool | None = Query(None, description="true = synthetic fixtures only, false = real intel only"),
    sort: Literal["retrieved", "published"] = Query("retrieved", description="retrieved = newest arrival first (default); published = newest publication first"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Paginated threat feed, newest first."""
    filters = []
    if source:
        filters.append(Threat.source.in_(source.split(",")))
    if severity:
        sev = severity.lower().split(",")
        if bad := set(sev) - set(SEVERITIES):
            raise HTTPException(422, f"unknown severity {sorted(bad)}; use {SEVERITIES}")
        cond = Threat.severity.in_(sev)
        filters.append(or_(cond, Threat.severity.is_(None)) if "unknown" in sev else cond)
    if kev is not None:
        filters.append(Threat.kev_listed.is_(kev))
    if min_epss is not None:
        filters.append(Threat.epss >= min_epss)
    if q:
        like = f"%{q}%"
        filters.append(or_(Threat.threat_id.ilike(like), Threat.title.ilike(like), Threat.description.ilike(like)))
    if simulated is not None:
        filters.append(Threat.is_simulated.is_(simulated))
    total = db.scalar(select(func.count()).select_from(Threat).where(*filters))
    published = (Threat.published_at.is_(None), Threat.published_at.desc())  # nulls last
    order = (Threat.retrieved_at.desc(), *published) if sort == "retrieved" else (*published, Threat.retrieved_at.desc())
    rows = db.scalars(select(Threat).where(*filters).order_by(*order, Threat.threat_id)
                      .offset((page - 1) * page_size).limit(page_size)).all()
    return ThreatPage(items=[_threat(r) for r in rows], total=total, page=page, page_size=page_size,
                      pages=(total + page_size - 1) // page_size)


@router.get("/api/threats/{threat_id}", response_model=ThreatDetail, tags=["threats"], responses={404: {"description": "Unknown threat_id"}})
def get_threat(threat_id: str, db: Session = Depends(get_db)):
    """One threat with every contract field plus a reference to the raw payload it was parsed from."""
    row = db.get(Threat, threat_id)
    if not row:
        raise HTTPException(404, f"threat {threat_id!r} not found")
    raw = db.get(RawPayload, row.raw_payload_id) if row.raw_payload_id else None
    return ThreatDetail(**_threat(row).model_dump(), raw_payload=RawPayloadRef.model_validate(raw, from_attributes=True) if raw else None)


@router.get("/api/source-status", response_model=list[SourceStatusOut], tags=["system"])
def source_status(db: Session = Depends(get_db)):
    """Health of every collector, written by collectors/run_all.py on each run."""
    now = datetime.now(timezone.utc)
    return [_status(r, now) for r in db.scalars(select(SourceStatus).order_by(SourceStatus.source))]


@router.get("/api/overview", response_model=Overview, tags=["threats"])
def overview(db: Session = Depends(get_db)):
    """Dashboard KPIs in one call."""
    count = lambda *where: db.scalar(select(func.count()).select_from(Threat).where(*where))
    by_source = dict(db.execute(select(Threat.source, func.count()).group_by(Threat.source).order_by(func.count().desc())).all())
    sev_col = case((Threat.severity.is_(None), "unknown"), else_=Threat.severity)
    by_sev = dict(db.execute(select(sev_col, func.count()).group_by(sev_col)).all())
    now = datetime.now(timezone.utc)
    return Overview(
        threats_total=count(),
        threats_by_source=by_source,
        threats_by_severity={s: by_sev.get(s, 0) for s in SEVERITIES},
        kev_count=count(Threat.kev_listed.is_(True)),
        high_epss_count=count(Threat.epss >= HIGH_EPSS),
        high_epss_threshold=HIGH_EPSS,
        public_exploit_count=count(Threat.public_exploit.is_(True)),
        simulated_count=count(Threat.is_simulated.is_(True)),
        ioc_count=db.scalar(select(func.count()).select_from(IOCRow)),
        iocs_by_type=dict(db.execute(select(IOCRow.ioc_type, func.count()).group_by(IOCRow.ioc_type)).all()),
        sources=[_status(r, now) for r in db.scalars(select(SourceStatus).order_by(SourceStatus.source))],
        newest_retrieved_at=db.scalar(select(func.max(Threat.retrieved_at))),
        matched_assets=None,
        open_alerts=None,
        notes=["matched_assets and open_alerts are null until Member 3's correlation/alerts land (TODO)."],
    )


@router.post("/api/demo/inject-cve", response_model=InjectResult, tags=["demo"], responses={400: {"description": "fixture_id not in the allowlist"}})
def inject_cve(body: InjectRequest, db: Session = Depends(get_db)):
    """Demo trigger: (re)insert one allowlisted fixture with retrieved_at = now so it tops the feed as "just arrived".

    Allowlist = threat_ids in data/demo_cves.json (real KEV CVEs) + data/threats_synthetic.json (DEMO-VULN-*).
    Anything else -> 400. Then calls hooks.on_new_threat(threat_id) (Member 3).
    """
    from ingestion.loader import DEMO_CVES, SYNTHETIC, fixture_threat, upsert_threats  # app <-> ingestion: import late

    allow = {r["threat_id"]: (r, f) for f in (DEMO_CVES, SYNTHETIC) for r in json.loads(f.read_text())}
    if body.fixture_id not in allow:
        raise HTTPException(400, f"fixture_id {body.fixture_id!r} is not an allowed demo fixture; allowed: {sorted(allow)}")
    rec, f = allow[body.fixture_id]
    t = fixture_threat(rec)
    t.retrieved_at = datetime.now(timezone.utc)
    t.is_simulated = f == SYNTHETIC  # synthetic fixtures are always simulated; demo CVEs are real KEV records
    upsert_threats(db, [t])
    db.commit()
    hooks.on_new_threat(t.threat_id)
    return InjectResult(injected=t, fixture_file=f.relative_to(f.parents[1]).as_posix(), hook_called="on_new_threat")
