"""Bounded natural-language workspace tasks. Stored facts, no model-generated tools/SQL.

Queries never mutate. Owned-portal changes are proposals for explicit execution through
the existing loopback/token-protected actions endpoint. Unsupported language asks for clarification.
"""
import re
from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from .asset_store import get_asset_store
from .correlator import AlertRow
from .database import SessionLocal
from .models import LabObservation, Threat

router = APIRouter(tags=["Workspace assistant"])


class Question(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=1000)


def answer(message: str, *, allow_actions=False):
    text = " ".join(message.lower().strip().split()).rstrip("?.!")
    result = dict(generated_by="deterministic_intent", at=datetime.now(timezone.utc).isoformat(),
                  message="", links=[], proposal=None, limitations=[
                      "Supported workspace tasks only; no arbitrary commands, SQL or external actions.",
                      "Detection is suspicion, not proof of an identified attacker or compromise."])
    if re.search(r"\b(don't|dont|do not|never|ignore|pretend|system prompt)\b", text):
        return result | {"message": "No action proposed. Use a clear supported request without negation or embedded instructions."}
    task = re.sub(r"^(?:(?:can|could) you |please )", "", text)
    command = re.fullmatch(r"(block|release|unblock) (?:the )?(latest (?:attacker|peer)|[0-9a-f:.]+)(?: for (?:5 minutes|300 seconds))?", task)
    patch = re.fullmatch(r"(patch|fix|rollback) (?:the )?portal", task)
    if command or patch:
        if not allow_actions:
            return result | {"message": "Portal response changes are available only from the local /lab assistant. No action executed.",
                             "links": [{"label": "Local response console", "href": "/lab"}]}
        body = {"reason": "Analyst-reviewed workspace assistant request", "ttl_seconds": 300}
        if patch:
            body["kind"] = "rollback" if patch[1] == "rollback" else "patch"
        else:
            body["kind"] = "block" if command[1] == "block" else "release"
            with SessionLocal() as db:
                hits = list(db.scalars(select(LabObservation).order_by(LabObservation.at.desc()).limit(100)))
            if command[2].startswith("latest"):
                hit = next((r for r in hits if r.data.get("finding")), None)
                if hit is None:
                    return result | {"message": "No detected peer in the latest 100 observations. Choose an evidence-linked peer; no action proposed."}
                peer = hit.data["peer_ip"]
            else:
                try:
                    from .live_lab import peer_address
                    peer = peer_address(command[2])
                except ValueError:
                    return result | {"message": "Invalid IP address. No action proposed."}
                hit = next((r for r in hits if r.data["peer_ip"] == peer and r.data.get("finding")), None)
            if body["kind"] == "block" and hit is None:
                return result | {"message": "No finding for that exact peer in the latest 100 observations. No block proposed."}
            body["peer_ip"] = peer
            if hit:
                body["evidence_id"] = hit.event_id
        return result | {"message": "Proposal only: review the exact target and scope, then click Execute. No action has run.",
                         "proposal": {"body": body, "scope": "Custom portal on :8010 only; not Apache, the OS firewall or other hosts."}}
    with SessionLocal() as db:
        if any(word in text for word in ("hardcoded", "data source", "where does", "data come")):
            result["message"] = ("Threats use stored public-feed caches plus labelled lab fixtures. Inventory starts with 40 synthetic assets "
                "and persisted overrides. Incidents/scores derive from stored events and correlation. Attack Replay uses historical "
                "traffic; the :8010 portal records actual requests. Analytics is calculated from those datasets. Landing visuals "
                "and API-failure bundled samples are illustrative. DEMO_MODE disables scheduled feed refresh, not live portal requests.")
        elif any(word in text for word in ("incident", "alert", "investigat", "report", "attacks")):
            requested = re.search(r"\bALR-[A-Za-z0-9-]+\b", message, re.I)
            rows = list(db.scalars(select(AlertRow).order_by(AlertRow.priority_rank.desc(), AlertRow.updated_at.desc())))
            if requested:
                rows = [r for r in rows if r.alert_id.lower() == requested[0].lower()]
            else:
                rows = [r for r in rows if (r.data.get("status") == "resolved" if any(w in text for w in ('resolved', 'closed')) else r.data.get("status") != "resolved")]
            priorities = [p for p in ('critical', 'high', 'medium', 'low') if re.search(r'\b' + p + r'\b', text)]
            if priorities:
                rows = [r for r in rows if r.data.get('priority') in priorities]
            selected = rows[:5]
            result["message"] = f"{len(rows)} matching stored incidents. " + ("; ".join(
                f"{r.alert_id}: {r.data.get('priority', 'unknown')} / {r.data.get('lifecycle_status', 'unknown')}, "
                f"{len(r.data.get('evidence_ids', []))} linked events" for r in selected) or "No matching records.")
            result["links"] = [{"label": "Inspect evidence / investigate / draft: " + r.alert_id,
                                "href": "/app/incidents/" + r.alert_id} for r in selected]
            if any(w in text for w in ("report", "investigat")):
                result["message"] += " Open the incident and use its evidence-backed investigation or draft control; no report has been generated by this query."
        elif any(word in text for word in ("asset", "inventory")):
            assets = get_asset_store().all()
            result["message"] = f"{len(assets)} registered inventory assets; {sum(a.is_simulated for a in assets)} labelled synthetic targets. Inventory alone does not prove a running version."
            result["links"] = [{"label": "Inspect inventory", "href": "/app/assets"}]
        elif any(word in text for word in ("threat", "cve", "intelligence")):
            total = db.scalar(select(func.count()).select_from(Threat))
            result["message"] = f"{total} stored threat records. This is a database count, not a count of attacks against this organisation."
            result["links"] = [{"label": "Inspect threat provenance", "href": "/app/threats"}]
        elif any(word in text for word in ("predict", "isolation", "behavio", "ml ")):
            result["message"] = "Exposure warns before an attack. Rules detect observed patterns. The live portal Isolation Forest needs a collected, frozen baseline; outliers are triage, not future-attack probabilities. Historical replay/SHAP uses a separate model."
            result["links"] = [{"label": "Inspect analytics and limitations", "href": "/app/analytics"}]
        else:
            result["message"] = "Try: show open incidents; show assets; how many threats; where does data come from; explain prediction. In local /lab: block latest peer; release <IP>; patch portal. Unsupported requests do not execute tasks."
    return result


@router.post("/api/assistant/query")
def query(body: Question):
    return answer(body.message)
