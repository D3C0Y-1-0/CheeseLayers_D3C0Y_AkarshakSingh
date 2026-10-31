"""Three bounded read-only tools. Authorisation is injected by backend, never by a model."""
from dataclasses import dataclass
from typing import Protocol

from pydantic import TypeAdapter

from shadow_watch.schemas import Identifier, Timestamp
from .schemas import IncidentContext

ID = TypeAdapter(Identifier)
TIME = TypeAdapter(Timestamp)


class EvidenceProvider(Protocol):
    def get_incident(self, incident_id: str) -> IncidentContext: ...


@dataclass(frozen=True)
class InvestigationScope:
    incident_id: str
    asset_ids: frozenset[str]
    demo_only: bool = True
    simulated_only: bool = False


class ReadOnlyTools:
    def __init__(self, provider: EvidenceProvider, scope: InvestigationScope):
        self._provider, self._scope = provider, scope
        self._calls = 0

    def _context(self) -> IncidentContext:
        if self._calls >= 3:
            raise PermissionError("three-call retrieval budget exceeded")
        self._calls += 1
        ctx = IncidentContext.model_validate(self._provider.get_incident(self._scope.incident_id))
        if ctx.incident_id != self._scope.incident_id or not set(ctx.asset_ids) <= self._scope.asset_ids:
            raise PermissionError("incident outside authorised scope")
        if self._scope.demo_only and (not ctx.is_simulated or ctx.integration_status != "demo_adapter"):
            raise PermissionError("demo-only evidence scope")
        if self._scope.simulated_only and not ctx.is_simulated:
            raise PermissionError("simulated evidence only")
        return ctx

    def get_incident_context(self, incident_id: str) -> dict:
        if ID.validate_python(incident_id) != self._scope.incident_id:
            raise PermissionError("incident outside authorised scope")
        return self._context().model_dump(mode="json")

    def get_asset_evidence(self, asset_id: str, time_window: dict | None = None) -> dict:
        ID.validate_python(asset_id)
        if asset_id not in self._scope.asset_ids:
            raise PermissionError("asset outside authorised scope")
        start = end = None
        if time_window is not None:
            if set(time_window) != {"start_at", "end_at"}:
                raise ValueError("time_window requires only start_at/end_at")
            start, end = TIME.validate_python(time_window["start_at"]), TIME.validate_python(time_window["end_at"])
            if end <= start:
                raise ValueError("invalid time window")
        ctx = self._context()
        evidence = [e for e in ctx.evidence if e.asset_id == asset_id
                    and (start is None or start <= e.observed_at < end)]
        citations = [e for e in ctx.additional_evidence if e.asset_id == asset_id
                     and (start is None or start <= e.observed_at < end)]
        return {"asset_id": asset_id, "items": [e.model_dump(mode="json") for e in evidence],
                "additional_citations": [e.model_dump(mode="json") for e in citations], "limit": 100}

    def get_remediation_guidance(self, threat_id: str | None) -> dict:
        if threat_id is not None:
            ID.validate_python(threat_id)
        ctx = self._context()
        if threat_id is not None and threat_id not in ctx.verified_cve_ids:
            raise PermissionError("threat not verified for this incident")
        return {"threat_id": threat_id, "references": list(ctx.references) if threat_id else [],
                "patch_verified": False, "analyst_review_required": True}
