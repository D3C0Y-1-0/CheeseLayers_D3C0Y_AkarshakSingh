from typing import Annotated, Literal

from pydantic import Field, model_validator

from shadow_watch.schemas import DetectionFinding, FrozenDTO, Identifier, NormalizedEvent, Timestamp

Assessment = Literal["vulnerability_exposure", "suspected_activity", "needs_verification"]
CVE = Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,}$")]


class IncidentContext(FrozenDTO):
    """Trusted Member 3 adapter output, scoped and checked before retrieval."""
    incident_id: Identifier
    assessment: Assessment
    asset_ids: tuple[Identifier, ...] = Field(max_length=20)
    evidence: tuple[NormalizedEvent, ...] = Field(max_length=100)
    additional_evidence: tuple["EvidenceCitation", ...] = Field(default=(), max_length=100)
    findings: tuple[DetectionFinding, ...] = Field(max_length=100)
    verified_cve_ids: tuple[CVE, ...] = ()
    references: tuple[str, ...] = Field(default=(), max_length=30)
    limitations: tuple[str, ...] = ()
    is_simulated: bool
    integration_status: Literal["demo_adapter", "persisted"]

    @model_validator(mode="after")
    def consistent_evidence(self):
        ids = {e.event_id for e in self.evidence}
        if len(ids) != len(self.evidence):
            raise ValueError("duplicate evidence in incident context")
        extra_ids = {e.evidence_id for e in self.additional_evidence}
        if len(extra_ids) != len(self.additional_evidence) or ids & extra_ids or len(ids | extra_ids) > 100:
            raise ValueError("duplicate or excessive evidence citations")
        if any(e.asset_id is not None and e.asset_id not in self.asset_ids for e in self.additional_evidence):
            raise ValueError("citation outside incident scope")
        by_id = {e.event_id: e for e in self.evidence}
        if any(e.asset_id not in self.asset_ids or e.is_simulated != self.is_simulated for e in self.evidence):
            raise ValueError("evidence outside incident scope or mixed simulation status")
        if len({f.finding_id for f in self.findings}) != len(self.findings):
            raise ValueError("duplicate finding IDs")
        for finding in self.findings:
            if finding.asset_id not in self.asset_ids or finding.is_simulated != self.is_simulated:
                raise ValueError("finding outside incident scope")
            if not set(finding.evidence_ids + finding.maintenance_evidence_ids) <= ids:
                raise ValueError("finding cites evidence missing from context")
            if any(by_id[eid].asset_id != finding.asset_id for eid in finding.evidence_ids + finding.maintenance_evidence_ids):
                raise ValueError("finding cites another asset's evidence")
        if self.integration_status == "demo_adapter" and not self.is_simulated:
            raise ValueError("demo adapter cannot hold real incidents")
        return self


class EvidenceCitation(FrozenDTO):
    evidence_id: str
    asset_id: str | None
    observed_at: Timestamp
    sensor_id: str
    source: str
    retrieved_at: Timestamp | None
    raw_ref: str
    event_type: str


IncidentContext.model_rebuild()


class InvestigationReport(FrozenDTO):
    incident_id: Identifier
    assessment: Assessment
    summary: str = Field(min_length=1, max_length=4000)
    asset_ids: tuple[str, ...]
    verified_cve_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    evidence: tuple[EvidenceCitation, ...]
    why_relevant: str = Field(max_length=4000)
    limitations: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    references: tuple[str, ...]
    generated_by: Literal["template", "llm", "llm_cached"]
    is_simulated: bool
    integration_status: Literal["demo_adapter", "persisted"]
    validation: dict | None = None  # grounding check result (ai/grounded.py): passed, checked_tokens, rejected_tokens, note
    fallback_reason: Literal["disabled", "offline_mode", "unconfigured", "timeout", "invalid_output", "provider_error"] | None = None
    analyst_review_required: bool = True
