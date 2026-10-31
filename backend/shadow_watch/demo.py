"""Bounded mock handoff, NOT a second correlation or persistence engine.

Only predefined synthetic cases are grouped according to their fixture manifest.
Member 3 supplies the real finding sink + EvidenceProvider in the application.
"""
import hashlib
import json
from collections import OrderedDict
from pathlib import Path
from threading import RLock
from typing import Literal, Protocol

from pydantic import TypeAdapter

from ai.schemas import IncidentContext
from . import real
from .engine import ShadowWatchEngine
from .normalize import normalize_events
from .schemas import DetectionContext, DetectionFinding, FrozenDTO, Identifier, NormalizedEvent

ROOT = Path(__file__).resolve().parents[2]
Scenario = Literal["no_cve_suspicious_chain", "benign_maintenance", "missing_telemetry",
                   "real_ssh_bruteforce", "real_ssh_distributed_spray", "real_web_crawler"]


class DemoRequest(FrozenDTO):
    scenario: Scenario
    run_id: Identifier = "demo-session-1"


class FindingSink(Protocol):
    def accept_findings(self, *, run_id: str, scenario: str,
                        events: tuple[NormalizedEvent, ...], findings: tuple[DetectionFinding, ...]) -> tuple[str, ...]:
        """Member 3 atomically stores evidence, deduplicates findings and returns alert IDs."""
        ...


class HandoffUnavailable(RuntimeError):
    pass


class DemoResult(FrozenDTO):
    scenario: Scenario
    run_id: str
    incident_id: str
    alert_ids: tuple[Identifier, ...] = ()
    findings: tuple[DetectionFinding, ...]
    evidence: tuple[NormalizedEvent, ...]
    integration_status: Literal["demo_adapter"] = "demo_adapter"
    handoff_status: Literal["pending_member3", "delivered"]
    is_simulated: Literal[True] = True
    note: str = "Reviewable synthetic preview; central alert persistence and priority are owned by Member 3"


class DemoAdapter:
    def __init__(self, maximum_runs: int = 100):
        if not 1 <= maximum_runs <= 100:
            raise ValueError("maximum_runs must be 1..100")
        self._runs: OrderedDict[str, tuple[IncidentContext, DemoResult]] = OrderedDict()
        self._lock, self.maximum_runs = RLock(), maximum_runs

    def replay(self, request: DemoRequest, sink: FindingSink | None = None) -> DemoResult:
        key = hashlib.sha256(f"{request.run_id}|{request.scenario}".encode()).hexdigest()[:24]
        incident_id = "SW-DEMO-" + key
        with self._lock:
            if incident_id in self._runs:
                self._runs.move_to_end(incident_id)
                ctx, result = self._runs[incident_id]
                if sink and result.handoff_status == "pending_member3":
                    alert_ids = self._deliver(sink, request, result.evidence, result.findings)
                    result = DemoResult.model_validate({**result.model_dump(), "alert_ids": alert_ids, "handoff_status": "delivered"})
                    self._runs[incident_id] = (ctx, result)
                return result
            if request.scenario in real.SCENARIOS:  # real SecRepo windows, replayed against our asset
                from datetime import datetime, timezone
                selected = real.events(request.scenario, datetime.now(timezone.utc).isoformat())
                if not selected:
                    raise ValueError("no real SecRepo windows cached for this scenario")
            else:
                manifest = json.loads((ROOT / "data/fixtures/demo_scenarios.json").read_text(encoding="utf-8"))
                records = json.loads((ROOT / "data/fixtures/events_shadow.json").read_text(encoding="utf-8"))
                wanted = set(manifest[request.scenario])
                selected = [r for r in records if r["event_id"] in wanted]
                if {r["event_id"] for r in selected} != wanted or len(selected) != len(wanted):
                    raise ValueError("scenario manifest has missing or duplicate evidence")
            for raw in selected:
                raw["event_id"] = key + ":" + raw["event_id"]
            events = normalize_events(selected)
            if not events or not all(e.is_simulated for e in events):
                raise ValueError("demo fixtures must contain only simulated events")
            assets = {a["asset_id"] for a in json.loads((ROOT / "data/assets.json").read_text(encoding="utf-8"))}
            if any(e.asset_id not in assets for e in events):
                raise ValueError("unknown demo asset")
            findings = ShadowWatchEngine().evaluate(events, DetectionContext(protected_asset_ids=frozenset(assets)))
            # Scenario expectations are fixture metadata, not a production incident classifier.
            rule_hit = any(f.detector_id != "SW-ML-001" for f in findings)
            assessment = ("suspected_activity" if request.scenario == "no_cve_suspicious_chain"
                          or (request.scenario in real.SCENARIOS and rule_hit) else "needs_verification")
            limitations = ("Signals share a simulated asset and time window; a causal process/network join is not verified",)
            ctx = IncidentContext(incident_id=incident_id, assessment=assessment,
                                  asset_ids=tuple(sorted({e.asset_id for e in events})), evidence=tuple(events),
                                  findings=tuple(findings), is_simulated=True, integration_status="demo_adapter", limitations=limitations)
            alert_ids = self._deliver(sink, request, tuple(events), tuple(findings)) if sink else ()
            result = DemoResult(scenario=request.scenario, run_id=request.run_id, incident_id=incident_id,
                                findings=tuple(findings), evidence=tuple(events), alert_ids=alert_ids,
                                handoff_status="delivered" if sink else "pending_member3")
            self._runs[incident_id] = (ctx, result)
            while len(self._runs) > self.maximum_runs:
                self._runs.popitem(last=False)
            return result

    @staticmethod
    def _deliver(sink, request, events, findings):
        try:
            alert_ids = sink.accept_findings(run_id=request.run_id, scenario=request.scenario, events=events, findings=findings)
            return TypeAdapter(tuple[Identifier, ...]).validate_python(alert_ids)
        except Exception:
            raise HandoffUnavailable("Member 3 handoff unavailable; retry with the same run_id") from None

    def get_incident(self, incident_id: str) -> IncidentContext:
        with self._lock:
            if incident_id not in self._runs:
                raise KeyError(incident_id)
            return self._runs[incident_id][0]
