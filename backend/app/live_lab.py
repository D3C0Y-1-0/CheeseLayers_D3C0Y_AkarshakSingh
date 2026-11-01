"""Opt-in local control plane plus a separate, bounded live-traffic lab app.

    VECTRA_LAB_ENABLED=true python -m uvicorn app.live_lab:portal_app --port 8010 --no-proxy-headers

Only the portal listener needs LAN access. Vectra's control/API listener stays on loopback.
Both processes share the configured SQLite database; one worker per listener is required.
"""
import hmac
import ipaddress
import os
import secrets
import re
from threading import RLock
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlencode, unquote_plus

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, model_validator
from sqlalchemy import select, update
from starlette.concurrency import run_in_threadpool

from .asset_store import get_asset_store
from .contracts import Asset, SecurityEvent, SoftwareItem, ThreatRecord
from .correlator import CorrelationEngine, threat_from_row
from .database import SessionLocal, init_db
from .matcher import match_asset, norm, parse_version
from .models import InventoryOverride, LabAction, LabObservation, LabSetting, Threat
from shadow_watch.live import verdict, virtual_document
from shadow_watch import lab_ml

ASSET_ID = "LAB-GOV-WEB-01"
THREAT_ID = "DEMO-VULN-LAB-TRAVERSAL"
TOKEN = secrets.token_urlsafe(32)
RECORD_LOCK = RLock()
router = APIRouter(tags=["Live lab control"])
portal_app = FastAPI(title="Vectra fictional district portal", docs_url=None, redoc_url=None, openapi_url=None)


def now():
    return datetime.now(timezone.utc)


def peer_address(value):
    address = ipaddress.ip_address(value)
    return str(address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address)


DEFAULT_POLICY = {"auto_block": False, "renew_on_retry": True, "ttl_seconds": 300}


def request_metadata(request):
    from .detection import signature_hits
    # Never inspect credential bodies or headers. Bounded query fields with sensitive keys
    # redacted; these are the same web signatures used by the historical replay analyser.
    fields = [(k[:64], "[redacted]" if re.search(
        r"pass|pwd|secret|token|key|auth|cookie|session|credential|email|phone|aadhaar", k, re.I) else v[:256])
        for k, v in list(request.query_params.multi_items())[:24]]
    target = (request.url.path[:256] + ("?" + urlencode(fields) if fields else ""))[:2048]
    decoded = unquote_plus(unquote_plus(target))
    return dict(request_target=target, signatures=[h for h in signature_hits(decoded) if h["strong"]])


@portal_app.middleware("http")
async def enforce_portal_boundary(request: Request, call_next):
    # Before routing/body validation: changing URL, verb, port or JSON cannot bypass a block.
    if os.getenv("VECTRA_LAB_ENABLED", "false").lower() == "true":
        peer = peer_address(request.client.host)
        if await run_in_threadpool(blocked, peer, True):
            eid, _ = await run_in_threadpool(record, "request", request, 429,
                                            path=request.url.path[:256], method=request.method)
            return PlainTextResponse("Temporary lab restriction. Continued retries may renew the quiet period.",
                                     status_code=429, headers={"X-Vectra-Event-ID": eid,
                                     "Cache-Control": "no-store", "Retry-After": "300"})
    response = await call_next(request)
    if os.getenv("VECTRA_LAB_ENABLED", "false").lower() == "true" and "X-Vectra-Event-ID" not in response.headers:
        # Observe other routes, validation failures and scanning as well. Never copy bodies,
        # credentials or cookies into evidence. Query inspection is bounded/redacted.
        with SessionLocal() as db:
            ready = db.get(InventoryOverride, ASSET_ID) is not None
        if ready:
            eid, _ = await run_in_threadpool(record, "request", request, response.status_code,
                                            path=request.url.path[:256], method=request.method)
            response.headers["X-Vectra-Event-ID"] = eid
    response.headers["Cache-Control"] = "no-store"
    return response


def enabled():
    if os.getenv("VECTRA_LAB_ENABLED", "false").lower() != "true":
        raise HTTPException(404, "live lab disabled; set VECTRA_LAB_ENABLED=true explicitly")


def loopback(request):
    try:
        host = request.url.hostname
        local_host = host == "localhost" or ipaddress.ip_address(host).is_loopback
        return ipaddress.ip_address(request.client.host).is_loopback and local_host
    except (ValueError, AttributeError):
        return False


def admin(request: Request):
    enabled()
    if not loopback(request) or not hmac.compare_digest(request.headers.get("x-vectra-lab-token", ""), TOKEN):
        raise HTTPException(403, "local lab console token required")


def initialise():
    """Register truthful lab inventory and a DEMO vulnerability; never assign it a real CVE."""
    init_db()
    with SessionLocal() as db:
        if db.get(InventoryOverride, ASSET_ID) is None:
            asset = Asset(asset_id=ASSET_ID, hostname="fictional-district-portal", ip="127.0.0.1",
                          organisation="Fictional Indian District Citizen Services", sector="govt",
                          role="Live lab portal; dummy applications only", os=None,
                          software=[SoftwareItem(vendor="vectra_lab", product="citizen_portal", version="1.0.0", cpe=None)],
                          criticality=4, internet_facing=False, owner="lab-soc", is_simulated=True)
            db.add(InventoryOverride(asset_id=ASSET_ID, data=asset.model_dump(mode="json")))
        if db.get(Threat, THREAT_ID) is None:
            threat = ThreatRecord(threat_id=THREAT_ID, source="vectra_lab", type="vulnerability",
                title="[LAB] Document boundary bypass in fictional citizen portal", is_simulated=True,
                description="Custom lab weakness (CWE-22), not a published CVE or a CERT-In advisory.",
                severity="high", cvss=None, epss=None, kev_listed=None, public_exploit=None,
                affected_configurations=[dict(vendor="vectra_lab", product="citizen_portal",
                    version_start_including="1.0.0", version_end_excluding="1.1.0")],
                raw_ref="backend/shadow_watch/live.py", references=[], tags=["india-context", "lab-only"])
            db.add(Threat(**threat.model_dump()))
        db.commit()


def setting(db, key, default):
    row = db.get(LabSetting, key)
    return row.data if row else default


def save_setting(db, key, data):
    row = db.get(LabSetting, key)
    if row:
        row.data = data
    else:
        db.add(LabSetting(key=key, data=data))


def reassess(asset_id, trigger):
    """All relevant stored intelligence, including CVEs referenced by CERT-In, is considered."""
    asset = get_asset_store().get(asset_id)
    if not asset:
        raise HTTPException(404, "unknown asset")
    products = {(norm(s.vendor), norm(s.product))
                for s in asset.software}
    with SessionLocal() as db:
        rows = list(db.scalars(select(Threat)))
        relevant = [r for r in rows if any((norm(c.get("vendor")), norm(c.get("product"))) in products
                                         for c in r.affected_configurations or [])]
        # Include previous alerts so removing a product also retires stale exposure.
        from .correlator import AlertRow
        old_ids = {tid for a in db.scalars(select(AlertRow).where(AlertRow.kind == "vulnerability"))
                   if asset_id in a.data["asset_ids"] for tid in a.data["threat_ids"]}
        selected = {r.threat_id: r for r in relevant}
        selected.update({r.threat_id: r for r in rows if r.threat_id in old_ids})
        engine = CorrelationEngine(db)
        # Inventory change affects this asset only; do not generate unrelated alerts for every asset.
        engine.assets = get_asset_store()
        engine.assets._assets = {asset_id: asset}
        results = []
        for row in selected.values():
            threat = threat_from_row(row)
            matched = match_asset(asset, threat)
            cves = set(row.cve_ids or []) | ({row.cve_id} if row.cve_id else set())
            advisories = [dict(threat_id=a.threat_id, title=a.title, references=a.references, is_simulated=a.is_simulated,
                               retrieved_at=a.retrieved_at.isoformat()) for a in rows
                          if a.source == "certin" and cves.intersection(a.cve_ids or [])]
            result = engine.correlate_threat(threat, trigger=trigger)
            results.append(dict(threat_id=row.threat_id, cve_id=row.cve_id, source=row.source,
                is_simulated=row.is_simulated, match_detail=matched.match_detail, reason=matched.reason,
                certin_advisories=advisories, created=result["created"], updated=result["updated"],
                retrieved_at=row.retrieved_at.isoformat()))
        unknown = not asset.software and (not asset.is_simulated or asset.model_extra.get("inventory_complete") is False)
        return dict(evaluated_at=now().isoformat(), asset=asset.model_dump(mode="json"), assessments=results,
                    assessment_status="inventory_unknown" if unknown else "assessed" if results else "no_structured_product_matches",
                    limitations=["Inventory observations are operator supplied, not remotely verified software scans.",
                                 "Cached advisory relevance does not establish Indian targeting or successful exploitation."])


def record(kind, request, status, **details):
    # Serialise in-process requests so simultaneous failures cannot bypass the sequence threshold.
    with RECORD_LOCK:
        return _record(kind, request, status, **details)


def _record(kind, request, status, **details):
    stamp = now()
    event_id = "LIVE-" + uuid4().hex
    peer = peer_address(request.client.host)
    details = request_metadata(request) | details
    observation = dict(event_id=event_id, kind=kind, at=stamp, peer_ip=peer,
        peer_port=request.client.port, status=status, **details,
        attribution="TCP peer observed by service; no attacker identity or origin beyond NAT/proxies established",
        forwarded_for_trusted=False, is_simulated=True)
    with SessionLocal() as db:
        history = [dict(r.data, at=r.at) for r in db.scalars(select(LabObservation)
                   .where(LabObservation.at >= stamp - timedelta(seconds=60)).order_by(LabObservation.at))]
        finding = verdict(observation, history)
        data = dict(observation, at=stamp.isoformat(), finding=finding)
        db.add(LabObservation(event_id=event_id, at=stamp, data=data))
        d = dict(src_ip=peer, src_port=request.client.port, observed_status=status,
                 observation_ref=f"/api/lab/observations/{event_id}", **details)
        if finding:
            d.update(attack_signal=finding["signal"], attack_label=finding["label"],
                     detection_reason=finding["reason"], supporting_evidence_ids=finding["evidence_ids"])
        event = SecurityEvent(event_id=event_id, asset_id=ASSET_ID, timestamp=stamp,
            event_type="auth" if kind == "login" else "http", source_sensor="vectra-live-portal",
            details=d, is_simulated=True, rule_id=finding["rule_id"] if finding else None,
            confidence=finding["confidence"] if finding else None, shadow_watch_evaluated=True,
            source="vectra_live_lab", retrieved_at=stamp.isoformat(), raw_ref=d["observation_ref"])
        # This commit stores original observation and correlated evidence in the same transaction.
        result = CorrelationEngine(db).ingest_events([event])
        policy = setting(db, "response_policy", DEFAULT_POLICY)
        if finding and policy["auto_block"]:
            # Deterministic findings only; ML outliers never trigger this policy.
            aid = "ACT-" + uuid4().hex
            db.add(LabAction(action_id=aid, at=stamp, data=dict(action_id=aid, kind="block", state="applied",
                at=stamp.isoformat(), peer_ip=peer, evidence_id=event_id, source="deterministic_policy",
                rule_id=finding["rule_id"], reason="Opt-in deterministic live-portal response policy",
                ttl_seconds=policy["ttl_seconds"],
                expires_at=(stamp + timedelta(seconds=policy["ttl_seconds"])).isoformat(),
                scope="fictional lab portal only; no OS firewall or Apache changes")))
        # Verification requires an actual later request hitting the enforcement boundary.
        for action in db.scalars(select(LabAction)):
            a = action.data
            if (a["state"] == "applied" and ((a["kind"] == "block" and a.get("peer_ip") == peer and status == 429
                    and stamp < datetime.fromisoformat(a["expires_at"]))
                    or (a["kind"] == "patch" and kind == "document" and details.get("traversal") and status == 403))):
                db.execute(update(LabAction).where(LabAction.action_id == action.action_id, LabAction.data == a)
                    .values(data=dict(a, state="verified", verified_at=stamp.isoformat(), verification_event_id=event_id))
                    .execution_options(synchronize_session=False))
        db.commit()
    return event_id, result


def blocked(peer, retry=False):
    with RECORD_LOCK:
        return _blocked(peer, retry)


def _blocked(peer, retry=False):
    peer = peer_address(peer)
    active = False
    with SessionLocal() as db:
        policy = setting(db, "response_policy", DEFAULT_POLICY)
        stamp = now()
        for row in db.scalars(select(LabAction)):
            a = row.data
            if a["kind"] == "block" and a["state"] in ("applied", "verified"):
                if stamp >= datetime.fromisoformat(a["expires_at"]):
                    db.execute(update(LabAction).where(LabAction.action_id == row.action_id, LabAction.data == a)
                        .values(data=dict(a, state="expired")).execution_options(synchronize_session=False))
                elif a["peer_ip"] == peer:
                    active = True
                    if retry and policy["renew_on_retry"]:
                        duration = a.get("ttl_seconds", max(15, min(300, int((
                            datetime.fromisoformat(a["expires_at"]) - datetime.fromisoformat(a["at"])).total_seconds()))))
                        changed = dict(a, expires_at=max(datetime.fromisoformat(a["expires_at"]),
                            stamp + timedelta(seconds=duration)).isoformat(),
                            last_retry_at=stamp.isoformat(), renewal_count=a.get("renewal_count", 0) + 1)
                        # Compare-and-set prevents a portal retry from overwriting a concurrent
                        # explicit release committed by the separate control process.
                        db.execute(update(LabAction).where(LabAction.action_id == row.action_id, LabAction.data == a)
                            .values(data=changed).execution_options(synchronize_session=False))
        db.commit()
    return active


def portal_ready():
    enabled()
    # The control plane initialises the tables/profile before launching this listener.
    with SessionLocal() as db:
        if not db.get(InventoryOverride, ASSET_ID):
            raise HTTPException(503, "initialise the lab from Vectra's local /lab console first")


@portal_app.get("/", response_class=HTMLResponse, dependencies=[Depends(enabled)])
def portal_home():
    return HTMLResponse(Path(__file__).with_name("portal.html").read_text(encoding="utf-8"),
        headers={"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'"})


@portal_app.get("/document", dependencies=[Depends(portal_ready)])
def document(request: Request, name: str = Query("notice.txt", max_length=256)):
    from shadow_watch.live import traversal
    with SessionLocal() as db:
        patched = setting(db, "portal", {"patched": False})["patched"]
    status, text = (429, "Temporary lab restriction") if blocked(peer_address(request.client.host)) else virtual_document(name, patched)
    eid, _ = record("document", request, status, name=name, traversal=traversal(name), response_bytes=len(text.encode()))
    return PlainTextResponse(text, status_code=status, headers={"X-Vectra-Event-ID": eid, "Cache-Control": "no-store"})


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(max_length=128)


@portal_app.post("/login", dependencies=[Depends(portal_ready)])
def login(body: Login, request: Request):
    success = body.username == "demo-user" and hmac.compare_digest(body.password, "lab-only-password")
    status = 429 if blocked(peer_address(request.client.host)) else 200 if success else 401
    eid, _ = record("login", request, status, username=body.username)  # Never record passwords.
    return PlainTextResponse("Lab login accepted" if status == 200 else "Lab login rejected", status_code=status,
                             headers={"X-Vectra-Event-ID": eid})


@router.get("/lab", response_class=HTMLResponse)
def console(request: Request):
    enabled()
    if not loopback(request):
        raise HTTPException(403, "console is local only")
    initialise()
    page = (Path(__file__).with_name("live_lab.html")).read_text(encoding="utf-8")
    return HTMLResponse(page.replace("__TOKEN__", TOKEN), headers={"Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'"})


@router.get("/lab/activity.js")
def activity_script(request: Request):
    enabled()
    if not loopback(request):
        raise HTTPException(403, "console is local only")
    return PlainTextResponse(Path(__file__).with_name("live_lab_activity.js").read_text(encoding="utf-8"),
                             media_type="text/javascript", headers={"Cache-Control": "no-store"})


@router.get("/api/lab/state", dependencies=[Depends(admin)])
def state():
    # Expire restrictions before reporting their effective state.
    blocked("0.0.0.0")
    with SessionLocal() as db:
        observations = list(db.scalars(select(LabObservation).order_by(LabObservation.at.desc()).limit(100)))
        actions = list(db.scalars(select(LabAction).order_by(LabAction.at.desc()).limit(100)))
        return dict(organisation="Fictional Indian District Citizen Services", timezone="Asia/Kolkata",
            response_policy=setting(db, "response_policy", DEFAULT_POLICY),
            observations=[r.data for r in observations], actions=[r.data for r in actions],
            portal=setting(db, "portal", {"patched": False}), assets=[a.model_dump(mode="json") for a in get_asset_store().all()],
            ml_status="Lab ML uses only an explicitly collected, frozen portal baseline. Historical SecRepo models stay separate.",
            lab_ml=lab_ml.status(),
            prediction_status="No future-attack probability is estimated; exposure is a preventive warning.")


class MLControl(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=5, max_length=256)


@router.post("/api/lab/ml/start", dependencies=[Depends(admin)])
def start_ml(body: MLControl):
    return lab_ml.start(body.reason)


@router.post("/api/lab/ml/freeze", dependencies=[Depends(admin)])
def freeze_ml():
    try:
        return lab_ml.freeze()
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None


@router.post("/api/lab/ml/disable", dependencies=[Depends(admin)])
def disable_ml():
    return lab_ml.disable()


@router.post("/api/lab/ml/tick", dependencies=[Depends(admin)])
def tick_ml():
    lab_ml.tick()
    return lab_ml.status()


@router.get("/api/lab/ml/windows/{window_id}", dependencies=[Depends(admin)])
def ml_window(window_id: str):
    from .models import LabMLWindow
    with SessionLocal() as db:
        row = db.get(LabMLWindow, window_id)
        if row is None:
            raise HTTPException(404, "unknown lab ML window")
        return row.data


@router.get("/api/lab/observations/{event_id}", dependencies=[Depends(admin)])
def observation(event_id: str):
    with SessionLocal() as db:
        row = db.get(LabObservation, event_id)
        if row is None:
            raise HTTPException(404, "unknown observation")
        return row.data


class InventoryChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    software: list[SoftwareItem] = Field(max_length=30)
    reason: str = Field(min_length=5, max_length=256)

    @model_validator(mode="after")
    def cpe_consistency(self):
        for sw in self.software:
            if not sw.cpe:
                continue
            parts = sw.cpe.split(":")
            if len(parts) != 13 or norm(parts[3]) != norm(sw.vendor) or norm(parts[4]) != norm(sw.product):
                raise ValueError("CPE must describe the reported product; clear it if the CPE is unknown or unsupported")
            if sw.version is not None and parts[5] not in ("*", "-") and parts[5] != sw.version:
                installed, encoded = parse_version(sw.version), parse_version(parts[5])
                if installed is None or encoded is None or installed != encoded:
                    raise ValueError("CPE version conflicts with reported version; update the CPE or set it to null")
        return self


@router.put("/api/lab/inventory/{asset_id}", dependencies=[Depends(admin)])
def inventory(asset_id: str, body: InventoryChange):
    if asset_id in {ASSET_ID, "LAB-APACHE-VULN", "LAB-APACHE-PATCHED"}:
        raise HTTPException(409, "use the service-specific patch/rollback controls for verified running lab services")
    asset = get_asset_store().get(asset_id)
    if not asset or not asset.is_simulated:
        raise HTTPException(400, "only registered simulated assets can be updated here")
    changed = Asset.model_validate(asset.model_dump() | {"software": body.software, "inventory_complete": bool(body.software)})
    stamp = now()
    with SessionLocal() as db:
        row = db.get(InventoryOverride, asset_id)
        if row:
            row.data = changed.model_dump(mode="json")
        else:
            db.add(InventoryOverride(asset_id=asset_id, data=changed.model_dump(mode="json")))
        db.add(LabAction(action_id="ACT-" + uuid4().hex, at=stamp, data=dict(kind="inventory", state="recorded",
            at=stamp.isoformat(), asset_id=asset_id, reason=body.reason, before=asset.model_dump(mode="json"),
            after=changed.model_dump(mode="json"))))
        db.commit()
    return reassess(asset_id, "inventory_change")


@router.post("/api/lab/reassess/{asset_id}", dependencies=[Depends(admin)])
def exposure(asset_id: str):
    return reassess(asset_id, "operator_reassessment")


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(pattern=r"^(block|patch|rollback|release)$")
    evidence_id: str | None = Field(default=None, max_length=128)
    peer_ip: IPvAnyAddress | None = None
    ttl_seconds: int = Field(default=300, ge=15, le=300)
    reason: str = Field(min_length=5, max_length=256)


@router.post("/api/lab/actions", dependencies=[Depends(admin)])
def action(body: ActionRequest):
    stamp = now()
    aid = "ACT-" + uuid4().hex
    peer = peer_address(str(body.peer_ip)) if body.peer_ip else None
    with SessionLocal() as db:
        if body.kind == "block":
            evidence = db.get(LabObservation, body.evidence_id) if body.evidence_id else None
            if not evidence or not evidence.data.get("finding") or evidence.data["peer_ip"] != peer:
                raise HTTPException(400, "block requires a detected observation from that exact TCP peer")
        if body.kind == "release":
            if body.peer_ip is None:
                raise HTTPException(422, "peer_ip required")
            for row in db.scalars(select(LabAction)):
                if row.data["kind"] == "block" and row.data.get("peer_ip") == peer and row.data["state"] in ("applied", "verified"):
                    row.data = dict(row.data, state="released", released_at=stamp.isoformat())
        if body.kind in ("patch", "rollback"):
            patched = body.kind == "patch"
            save_setting(db, "portal", {"patched": patched})
            row = db.get(InventoryOverride, ASSET_ID)
            if row is None:
                raise HTTPException(409, "initialise /lab first")
            a = dict(row.data)
            a["software"] = [dict(vendor="vectra_lab", product="citizen_portal", version="1.1.0" if patched else "1.0.0", cpe=None)]
            row.data = a
            # A rollback invalidates the previous patch's current-state verification.
            if not patched:
                for previous in db.scalars(select(LabAction)):
                    if previous.data["kind"] == "patch" and previous.data["state"] in ("applied", "verified"):
                        previous.data = dict(previous.data, state="rolled_back", rolled_back_at=stamp.isoformat())
        data = dict(action_id=aid, kind=body.kind, state="applied", at=stamp.isoformat(),
            peer_ip=peer, evidence_id=body.evidence_id, reason=body.reason,
            ttl_seconds=body.ttl_seconds if body.kind == "block" else None,
            expires_at=(stamp + timedelta(seconds=body.ttl_seconds)).isoformat() if body.kind == "block" else None,
            scope="fictional lab portal only; no OS firewall or external changes")
        db.add(LabAction(action_id=aid, at=stamp, data=data))
        db.commit()
    assessment = reassess(ASSET_ID, "lab_" + body.kind) if body.kind in ("patch", "rollback") else None
    return dict(action=data, exposure=assessment)


class ResponsePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    auto_block: bool
    renew_on_retry: bool = True
    ttl_seconds: int = Field(default=300, ge=15, le=300)
    reason: str = Field(min_length=5, max_length=256)


@router.put("/api/lab/policy", dependencies=[Depends(admin)])
def response_policy(body: ResponsePolicy):
    stamp = now()
    aid = "ACT-" + uuid4().hex
    with SessionLocal() as db:
        before = setting(db, "response_policy", DEFAULT_POLICY)
        after = body.model_dump(exclude={"reason"})
        save_setting(db, "response_policy", after)
        db.add(LabAction(action_id=aid, at=stamp, data=dict(action_id=aid, kind="policy", state="recorded",
            at=stamp.isoformat(), before=before, after=after, reason=body.reason)))
        db.commit()
    return after


from .assistant import Question  # shared bounded schema; no model-selected actions


@router.post("/api/lab/assistant", dependencies=[Depends(admin)])
def lab_assistant(body: Question):
    from .assistant import answer
    return answer(body.message, allow_actions=True)
