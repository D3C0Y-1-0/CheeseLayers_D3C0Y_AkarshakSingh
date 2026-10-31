"""Member 2 endpoints: health, threat feed, source health, overview, signals, demo controls. Contract: docs/API.md."""
import json
from datetime import date, datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import case, delete, func, or_, select
from sqlalchemy.orm import Session

from collectors.schema import ThreatItem

from . import hooks
from .database import DEMO_MODE, get_db
from .models import IOCRow, RawPayload, SourceStatus, Threat, ThreatSignal

router = APIRouter()
HIGH_EPSS = 0.5  # "more likely than not to be exploited in the next 30 days"
SEVERITIES = ("critical", "high", "medium", "low", "none", "unknown")  # unknown = severity is null


# ---------- response models ----------
class Health(BaseModel):
    status: Literal["ok"]
    demo_mode: bool
    threats: int
    time: datetime
    scheduler: list[dict] | None  # [{id, every_hours, next_run_time}]; null = disabled (DEMO_MODE)


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
    raw_payloads: list[RawPayloadRef]  # one per raw_refs entry, same order (primary first)


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
def health(request: Request, db: Session = Depends(get_db)):
    """Liveness, whether we're offline from cache (DEMO_MODE), and the feed scheduler's next runs."""
    sched = getattr(request.app.state, "scheduler", None)
    jobs = [{"id": j.id, "every_hours": j.trigger.interval.total_seconds() / 3600,
             "next_run_time": j.next_run_time.isoformat() if j.next_run_time else None} for j in sched.get_jobs()] if sched else None
    return Health(status="ok", demo_mode=DEMO_MODE, threats=db.scalar(select(func.count()).select_from(Threat)),
                  time=datetime.now(timezone.utc), scheduler=jobs)


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
    """One threat with every contract field plus references to every raw payload it was built from."""
    row = db.get(Threat, threat_id)
    if not row:
        raise HTTPException(404, f"threat {threat_id!r} not found")
    by_path = {r.path: r for r in db.scalars(select(RawPayload).where(RawPayload.path.in_(row.raw_refs or [])))}
    raws = [RawPayloadRef.model_validate(by_path[p], from_attributes=True) for p in row.raw_refs or [] if p in by_path]
    return ThreatDetail(**_threat(row).model_dump(), raw_payloads=raws)


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
    Anything else -> 400. Then calls hooks.on_new_threat(threat_id, "demo_inject") (Member 3).
    """
    from ingestion.loader import upsert_threats  # app <-> ingestion: import late

    t, f = _fixture(body.fixture_id)
    t.retrieved_at = datetime.now(timezone.utc)
    upsert_threats(db, [t])
    db.commit()
    hooks.on_new_threat(t.threat_id, "demo_inject")
    return InjectResult(injected=t, fixture_file=f.relative_to(f.parents[1]).as_posix(), hook_called="on_new_threat")


def _fixture(fixture_id: str) -> tuple[ThreatItem, "Path"]:
    """Allowlisted demo fixture -> (ThreatItem, file). Allowlist = data/demo_cves.json (real KEV CVEs) +
    data/threats_synthetic.json (DEMO-VULN-*). Anything else -> 400."""
    from ingestion.loader import DEMO_CVES, SYNTHETIC, fixture_threat

    allow = {r["threat_id"]: (r, f) for f in (DEMO_CVES, SYNTHETIC) for r in json.loads(f.read_text())}
    if fixture_id not in allow:
        raise HTTPException(400, f"fixture_id {fixture_id!r} is not an allowed demo fixture; allowed: {sorted(allow)}")
    rec, f = allow[fixture_id]
    t = fixture_threat(rec)
    t.is_simulated = f == SYNTHETIC  # synthetic fixtures are always simulated; demo CVEs are real KEV records
    return t, f


# ---------- early-warning signals (ingestion/changes.py) ----------
SignalType = Literal["new_kev", "epss_jump", "new_public_exploit", "new_certin_advisory", "new_critical_cve"]


class SignalOut(BaseModel):
    signal_id: str
    threat_id: str
    signal_type: str
    old_value: Any
    new_value: Any
    detected_at: datetime
    source: str
    details: dict
    is_simulated: bool
    threat_title: str | None  # convenience for the feed UI (joined from threats)
    severity: str | None
    kev_listed: bool | None


class SignalPage(BaseModel):
    items: list[SignalOut]
    count: int
    newest_detected_at: datetime | None  # poll with ?since=<this> to get only newer signals


class SignalSummary(BaseModel):
    last_24h: dict[str, int]
    last_7d: dict[str, int]
    total: int
    simulated_last_24h: int
    latest_detected_at: datetime | None
    thresholds: dict


def _signal_out(sig: ThreatSignal, t: Threat | None) -> SignalOut:
    return SignalOut(**{c: getattr(sig, c) for c in ("signal_id", "threat_id", "signal_type", "old_value", "new_value",
                                                     "detected_at", "source", "details", "is_simulated")},
                     threat_title=t.title if t else None, severity=t.severity if t else None, kev_listed=t.kev_listed if t else None)


@router.get("/api/signals", response_model=SignalPage, tags=["signals"])
def list_signals(
    since: datetime | None = Query(None, description="Only signals detected strictly after this ISO time (poll with newest_detected_at)"),
    type: str | None = Query(None, description="Comma-separated signal types"),
    simulated: bool | None = Query(None, description="false = real feed changes only"),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Early-warning signals, newest first. The frontend polls this."""
    from ingestion.changes import TYPES
    where = []
    if since:
        where.append(ThreatSignal.detected_at > (since if since.tzinfo else since.replace(tzinfo=timezone.utc)))
    if type:
        types = type.split(",")
        if bad := set(types) - set(TYPES):
            raise HTTPException(422, f"unknown signal type {sorted(bad)}; use {TYPES}")
        where.append(ThreatSignal.signal_type.in_(types))
    if simulated is not None:
        where.append(ThreatSignal.is_simulated.is_(simulated))
    rows = db.execute(select(ThreatSignal, Threat).outerjoin(Threat, Threat.threat_id == ThreatSignal.threat_id).where(*where)
                      .order_by(ThreatSignal.detected_at.desc(), ThreatSignal.signal_id).limit(limit)).all()
    items = [_signal_out(sig, t) for sig, t in rows]
    return SignalPage(items=items, count=len(items), newest_detected_at=items[0].detected_at if items else None)


@router.get("/api/signals/summary", response_model=SignalSummary, tags=["signals"])
def signals_summary(db: Session = Depends(get_db)):
    """Signal counts by type for the last 24 h and 7 days (dashboard tiles)."""
    from ingestion.changes import SIGNALS, TYPES
    now = datetime.now(timezone.utc)

    def by_type(since: datetime) -> dict[str, int]:
        got = dict(db.execute(select(ThreatSignal.signal_type, func.count()).where(ThreatSignal.detected_at >= since)
                              .group_by(ThreatSignal.signal_type)).all())
        return {t: got.get(t, 0) for t in TYPES}

    return SignalSummary(
        last_24h=by_type(now - timedelta(hours=24)), last_7d=by_type(now - timedelta(days=7)),
        total=db.scalar(select(func.count()).select_from(ThreatSignal)),
        simulated_last_24h=db.scalar(select(func.count()).select_from(ThreatSignal).where(
            ThreatSignal.is_simulated.is_(True), ThreatSignal.detected_at >= now - timedelta(hours=24))),
        latest_detected_at=db.scalar(select(func.max(ThreatSignal.detected_at))), thresholds=SIGNALS)


class SimulateRequest(BaseModel):
    fixture_id: str
    signal_type: SignalType


SOURCE_OF = {"new_kev": "kev", "epss_jump": "epss", "new_public_exploit": "github_poc", "new_certin_advisory": "certin",
             "new_critical_cve": "nvd"}


@router.post("/api/demo/simulate-signal", response_model=SignalOut, tags=["demo"],
             responses={400: {"description": "fixture_id not in the allowlist"}, 422: {"description": "unknown signal_type"}})
def simulate_signal(body: SimulateRequest, db: Session = Depends(get_db)):
    """Live-demo trigger: create a realistic early-warning signal on an allowlisted fixture and fire the hook.

    Always stored with is_simulated=true and details.simulated=true. Real fixtures (KEV CVEs) are never altered:
    the signal ends at their real current value. Synthetic DEMO-VULN-* rows are updated to match the signal
    (e.g. epss -> 0.62), so the dashboard stays consistent. POST /api/demo/reset undoes all of it.
    """
    from ingestion import changes
    from ingestion.loader import upsert_threats

    fx, f = _fixture(body.fixture_id)
    row = db.get(Threat, fx.threat_id)
    if row is None:  # e.g. fixture not loaded yet: insert it first
        upsert_threats(db, [fx])
        db.flush()
        row = db.get(Threat, fx.threat_id)
    synthetic, typ, today = fx.is_simulated, body.signal_type, date.today()
    details = {"simulated": True, "fixture_file": f.relative_to(f.parents[1]).as_posix(),
               "note": "Demo signal created by POST /api/demo/simulate-signal; not a real feed change."}
    if typ == "epss_jump":
        if synthetic:
            old, new = row.epss if row.epss is not None else 0.04, 0.62
            row.epss = new
        else:
            new = row.epss
            old = round(max(0.01, (new or 0.6) - 0.35), 5)
        details |= {"delta": round((new or 0) - old, 5), "crossed": old < changes.SIGNALS["epss_cross"] <= (new or 0)}
    elif typ == "new_kev":
        old, new = False, True
        if synthetic:
            row.kev_listed, row.kev_date_added = True, today
        details |= {"cve_id": row.cve_id, "kev_date_added": str(row.kev_date_added or today), "title": row.title}
    elif typ == "new_public_exploit":
        old = None
        new = {"source": "github_poc", "repo": f"netrax-demo/{row.threat_id.lower()}-poc"}
        if synthetic:
            row.public_exploit = True
        details |= new | {"quality_filtered": True}
    elif typ == "new_certin_advisory":
        old, new = None, f"SIMULATED-CIAD-{today.year}-{int(datetime.now().timestamp()) % 10000:04d}"
        details |= {"cve_ids": row.cve_ids, "severity": row.severity, "title": f"[SIMULATED] CERT-In advisory on {row.title}"}
    else:  # new_critical_cve
        old = None
        if synthetic and (row.cvss is None or row.cvss < changes.SIGNALS["critical_cvss"]):
            row.cvss, row.cvss_version, row.severity = 9.1, "3.1", "critical"
        new = row.cvss
        details |= {"cvss_version": row.cvss_version}
    now = datetime.now(timezone.utc)
    sig = changes.make(row.threat_id, typ, old, new, SOURCE_OF[typ], details, now, simulated=True, salt=now.isoformat())
    changes.emit(db, [sig])
    db.commit()
    changes.fire_hooks([sig])
    return _signal_out(db.get(ThreatSignal, sig["signal_id"]), db.get(Threat, row.threat_id))


class ResetResult(BaseModel):
    deleted_simulated_signals: int
    before: dict[str, int]
    after: dict[str, int]


@router.post("/api/demo/reset", response_model=ResetResult, tags=["demo"])
def demo_reset(db: Session = Depends(get_db)):
    """Restore Member 2's tables to the cached baseline: delete simulated signals, reload threats/IOCs from cache
    (undoes inject-cve / simulate-signal edits). Real signals and other members' tables are left untouched."""
    from collectors.run_all import LOCK
    from ingestion.loader import counts, load

    with LOCK:  # never interleave with a scheduler ingest
        before = counts()
        n = db.execute(delete(ThreatSignal).where(ThreatSignal.is_simulated.is_(True))).rowcount
        db.commit()
        load(detect=False)  # a reload is not a feed change: no signals
        return ResetResult(deleted_simulated_signals=n, before=before, after=counts())
