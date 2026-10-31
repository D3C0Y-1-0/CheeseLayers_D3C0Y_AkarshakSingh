"""Member 3 endpoints: incident alerts, lifecycle, and the correlation entry points for Members 2 and 4."""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .asset_store import get_asset_store
from .contracts import LifecycleStatus, Priority, Sector, SecurityEvent, ThreatRecord
from .correlator import AlertRow, CorrelationEngine
from .database import get_db
from .models import Threat

router = APIRouter()


class AckRequest(BaseModel):
    status: LifecycleStatus | None = None  # omit = advance one step (detected -> investigating -> ...)
    reason: str = "acknowledged"
    by: str | None = None


@router.get("/api/alerts", tags=["alerts"])
def list_alerts(
    priority: Priority | None = None,
    status: str | None = Query(None, description="contract status (new/ack/resolved) or lifecycle_status"),
    sector: Sector | None = None,
    match_status: str | None = Query(None, description="contract match_status or match_detail value"),
    kind: str | None = Query(None, description="vulnerability | behaviour"),
    asset_id: str | None = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Alerts, most urgent first (priority, then most recently updated)."""
    store = get_asset_store()
    rows = db.scalars(select(AlertRow).order_by(AlertRow.priority_rank.desc(), AlertRow.updated_at.desc()))
    items = []
    for row in rows:
        a = CorrelationEngine.to_alert(row)
        if priority and a["priority"] != priority:
            continue
        if status and status not in (a["status"], a["lifecycle_status"]):
            continue
        if match_status and match_status not in (a["match_status"], a["match_detail"]):
            continue
        if kind and a["kind"] != kind:
            continue
        if asset_id and asset_id not in a["asset_ids"]:
            continue
        if sector and not any((x := store.get(i)) and x.sector == sector for i in a["asset_ids"]):
            continue
        items.append(a)
    return {"items": items, "total": len(items)}


@router.get("/api/alerts/{alert_id}", tags=["alerts"])
def get_alert(alert_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Full incident: alert + score breakdown + timeline + the assets and threats behind it."""
    row = db.get(AlertRow, alert_id)
    if row is None:
        raise HTTPException(404, f"alert {alert_id} not found")
    a = CorrelationEngine.to_alert(row)
    store = get_asset_store()
    assets = [store.get(i).model_dump(mode="json") for i in a["asset_ids"] if store.get(i)]
    threats = []
    for tid in a["threat_ids"]:
        t = db.get(Threat, tid)
        threats.append({"threat_id": tid, "in_database": t is not None} | ({
            k: getattr(t, k) for k in ("cve_id", "title", "source", "severity", "cvss", "epss", "kev_listed",
                                       "public_exploit", "is_simulated")} if t else {}))
    return a | {"assets": assets, "threats": threats}


@router.post("/api/alerts/{alert_id}/acknowledge", tags=["alerts"],
             responses={404: {"description": "unknown alert"}, 409: {"description": "invalid transition"}})
def acknowledge(alert_id: str, body: AckRequest | None = None, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Move an alert forward in its lifecycle: detected -> investigating -> confirmed -> action_required ->
    mitigated -> closed. Records who, when and why in the timeline. Never moves backwards."""
    body = body or AckRequest()
    try:
        return CorrelationEngine(db).acknowledge(alert_id, body.status, body.reason, body.by)
    except KeyError:
        raise HTTPException(404, f"alert {alert_id} not found")
    except ValueError as e:
        raise HTTPException(409, str(e))


@router.post("/api/correlate/threat", tags=["correlation"])
def correlate_threat(threat: ThreatRecord, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Member 2 -> Member 3: match a threat against all assets, score, and create/update alerts."""
    return CorrelationEngine(db).correlate_threat(threat, trigger="api")


@router.post("/api/correlate/events", tags=["correlation"])
def correlate_events(events: list[SecurityEvent], db: Session = Depends(get_db)) -> dict[str, Any]:
    """Member 4 -> Member 3: ingest sensor events, correlate per asset, and create/update incidents."""
    return CorrelationEngine(db).ingest_events(events)


@router.post("/api/demo/reset-alerts", tags=["demo"])
def reset_alerts(db: Session = Depends(get_db)) -> dict[str, int]:
    """Delete all alerts and ingested events (Member 2's /api/demo/reset leaves other members' tables alone)."""
    return CorrelationEngine(db).reset()
