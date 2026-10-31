"""Bridge Member 4 evidence to Member 3's existing tables and score engine. No new DB."""
from sqlalchemy import select

from ai.llm import demo_mode
from ai.schemas import EvidenceCitation, IncidentContext
from ai.tools import InvestigationScope, ReadOnlyTools
from app.contracts import SecurityEvent
from app.correlator import AlertRow, CorrelationEngine, EventRow
from app.models import Threat
from .normalize import EVENT
from .schemas import DetectionFinding


FINDING_LABEL = {"unusual_http_window": "Unusual HTTP error burst", "unexpected_process_activity": "Web server spawned a shell",
                 "new_outbound_destination": "New outbound destination", "login_failure_burst": "SSH password guessing",
                 "statistical_anomaly": "Statistical anomaly (Isolation Forest)"}


def to_security_event(event, findings) -> SecurityEvent:
    d = event.details
    if event.event_type == "http_window":
        kind = "http"
        details = {**d.model_dump(mode="json"), "requests_last_minute": d.request_count * 60 / d.window_seconds,
                   "http_4xx_ratio": d.http_4xx_count / d.request_count if d.request_count else 0}
    elif event.event_type == "process_start":
        kind, details = "process", {**d.model_dump(mode="json"), "child_process": d.process_name}
    elif event.event_type == "auth_window":
        kind = "auth"
        details = {**d.model_dump(mode="json"), "failed_logins_last_minute": d.failed_count * 60 / d.window_seconds}
    elif event.event_type == "network_connection":
        kind = "network"
        details = {**d.model_dump(mode="json"), "dest_ip": str(d.destination_ip), "dest_port": d.destination_port,
                   "direction": "outbound" if d.outbound else "inbound", "first_seen_destination": d.is_new_destination}
    else:
        kind, details = "maintenance", d.model_dump(mode="json")
        if d.approved:
            details.update(window_start=d.start_at.isoformat(), window_end=d.end_at.isoformat())
    own = [f for f in findings if event.event_id in f.evidence_ids]
    if own:  # readable name for the incident title (the correlator titles incidents by attack label)
        details["attack_label"] = FINDING_LABEL[own[0].finding_type]
    return SecurityEvent(event_id=event.event_id, asset_id=event.asset_id, timestamp=event.observed_at,
                         event_type=kind, source_sensor=event.sensor_id, details=details, is_simulated=event.is_simulated,
                         rule_id=own[0].detector_id if own else None, confidence=own[0].confidence if own else None,
                         shadow_watch_evaluated=True, normalized_event=event.model_dump(mode="json"),
                         shadow_findings=[f.model_dump(mode="json") for f in own])


class DatabaseFindingSink:
    def __init__(self, session_factory):
        self.sessions = session_factory

    def accept_findings(self, *, run_id, scenario, events, findings):
        if not demo_mode() or not all(e.is_simulated for e in events):
            raise PermissionError("predefined simulated ingestion requires DEMO_MODE")
        records = [to_security_event(e, findings) for e in events]
        with self.sessions() as db:
            for record in records:
                existing = db.get(EventRow, record.event_id)
                if existing and existing.data != record.model_dump(mode="json"):
                    raise ValueError("conflicting stored event ID")
            CorrelationEngine(db, window_minutes=5).ingest_events(records)
            ids = db.scalars(select(EventRow.alert_id).where(EventRow.event_id.in_([e.event_id for e in records])))
            return tuple(sorted({i for i in ids if i}))


class StoredIncidentProvider:
    def __init__(self, session_factory):
        self.sessions = session_factory

    def get_incident(self, incident_id: str) -> IncidentContext:
        with self.sessions() as db:
            row = db.get(AlertRow, incident_id)
            if row is None:
                raise KeyError(incident_id)
            a = row.data
            records = list(db.scalars(select(EventRow).where(EventRow.event_id.in_(a["evidence_ids"]))
                                     .order_by(EventRow.timestamp, EventRow.event_id).limit(101)))
            limitations = list(a.get("limitations", []))
            if len(records) > 100:
                limitations.append("Investigation limited to the first 100 stored observations")
            records = records[:100]
            evidence, additional, findings = [], [], []
            for record in records:
                raw = record.data
                if raw.get("is_simulated") != a["is_simulated"]:
                    limitations.append(f"{record.event_id}: excluded because telemetry simulation status differs from incident")
                    continue
                if raw.get("normalized_event"):
                    evidence.append(EVENT.validate_python(raw["normalized_event"]))
                    findings.extend(DetectionFinding.model_validate(f) for f in raw.get("shadow_findings", []))
                else:
                    additional.append(EvidenceCitation(evidence_id=record.event_id, asset_id=record.asset_id,
                        observed_at=record.timestamp, sensor_id=raw["source_sensor"], source=raw.get("source") or raw["source_sensor"],
                        retrieved_at=None, raw_ref=f"/api/alerts/{incident_id}/evidence#{record.event_id}", event_type=raw["event_type"]))
            ids = {e.event_id for e in evidence}
            findings = [f for f in findings if set(f.evidence_ids + f.maintenance_evidence_ids) <= ids]
            verified, references = [], []
            for tid in a["threat_ids"]:
                threat = db.get(Threat, tid)
                if threat:
                    references.extend(threat.references or [])
                    if threat.cve_id and a.get("match_detail") == "confirmed_affected":
                        verified.append(threat.cve_id)
            if additional:
                limitations.append("Legacy events have no stored ingestion timestamp; retrieved_at remains unknown")
            if a["kind"] == "vulnerability":
                assessment = "vulnerability_exposure" if a.get("match_detail") == "confirmed_affected" else "needs_verification"
            else:
                assessment = "suspected_activity" if a.get("behavioural_suspicion_score", 0) >= 55 else "needs_verification"
                limitations.append("Signals share an asset/time window; process-to-network causality is not verified")
            return IncidentContext(incident_id=incident_id, assessment=assessment, asset_ids=tuple(a["asset_ids"]),
                evidence=tuple(evidence), additional_evidence=tuple(additional), findings=tuple(findings),
                verified_cve_ids=tuple(dict.fromkeys(verified)), references=tuple(dict.fromkeys(references))[:30],
                limitations=tuple(dict.fromkeys(limitations)), is_simulated=a["is_simulated"], integration_status="persisted")


def demo_investigation_factory(session_factory):
    def factory(request, incident_id):
        if not demo_mode():
            raise PermissionError("demo evidence access disabled")
        provider = StoredIncidentProvider(session_factory)
        ctx = provider.get_incident(incident_id)
        if not ctx.is_simulated:
            raise PermissionError("production incidents require an authenticated provider")
        return ReadOnlyTools(provider, InvestigationScope(incident_id, frozenset(ctx.asset_ids),
                                                        demo_only=False, simulated_only=True))
    return factory
