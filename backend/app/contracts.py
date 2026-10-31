"""Pydantic v2 models for the shared Vectra contracts.

data/contracts.json is the source of truth. These models mirror it field-for-field; nothing in it is
renamed here. Member 3 needs a few extra fields (the 3 decoupled scores, a 6-stage lifecycle, a 4-state
match result). The contract allows additions, so those live in clearly marked "additions" sections
under NEW names instead of redefining contract fields.

Rule that matters most: None = unknown / unverified. Never coerce a missing CVSS, EPSS or KEV flag to 0
or False.
"""
from ipaddress import IPv4Address
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from collectors.schema import AffectedConfiguration as _M2AffectedConfiguration
from collectors.schema import ThreatItem

Sector = Literal["power", "banking", "govt", "health", "telecom", "water"]
EventType = Literal["http", "process", "network", "auth", "maintenance"]
Priority = Literal["low", "medium", "high", "critical"]

# Contract enums for alerts.
AlertKind = Literal["vulnerability", "behaviour"]
AlertStatus = Literal["new", "ack", "resolved"]
MatchStatus = Literal["confirmed", "uncertain", "requires_manual_review"]

# Member 3 additions: finer-grained versions of the two contract enums above.
LifecycleStatus = Literal["detected", "investigating", "confirmed", "action_required", "mitigated", "closed"]
MatchDetail = Literal["confirmed_affected", "confirmed_unaffected", "needs_verification", "no_cve_behavioural"]

LIFECYCLE_ORDER: list[str] = ["detected", "investigating", "confirmed", "action_required", "mitigated", "closed"]

# Each fine-grained value maps onto exactly one contract value, so anyone reading only the contract
# fields still gets a correct picture.
LIFECYCLE_TO_STATUS: dict[str, str] = {
    "detected": "new",
    "investigating": "ack",
    "confirmed": "ack",
    "action_required": "ack",
    "mitigated": "resolved",
    "closed": "resolved",
}


class _Model(BaseModel):
    # The contract allows extra fields as additions, so other members' extras pass through untouched.
    model_config = ConfigDict(extra="allow")


# --- Asset --------------------------------------------------------------------------------------------

class SoftwareItem(_Model):
    vendor: str
    product: str
    version: str | None  # None = version not known -> any match on it must be uncertain, never confirmed
    cpe: str | None = Field(pattern=r"^cpe:2\.3:[aoh]:")


class Asset(_Model):
    asset_id: str
    hostname: str
    ip: IPv4Address
    organisation: str
    sector: Sector
    role: str
    os: str | None
    software: list[SoftwareItem]
    criticality: int = Field(ge=1, le=5)  # 5 = outage hurts people / national services
    internet_facing: bool
    owner: str | None
    is_simulated: bool


# --- Threat -------------------------------------------------------------------------------------------

# Member 2's ThreatItem (collectors/schema.py) already mirrors the contract `threat`; we extend it rather
# than keep a second copy that could drift.

class AffectedConfiguration(_M2AffectedConfiguration):
    model_config = ConfigDict(extra="allow")

    # Additions (Member 3).
    exact_version: str | None = None  # explicit single affected version, if the feed gives one
    raw_cpe_complex: bool = False  # True = NVD config has AND/OR nesting we did not model -> never auto-confirm


class ThreatRecord(ThreatItem):
    """kev_listed: True = exploited in the wild, False = checked and not listed, None = not checked."""
    model_config = ConfigDict(extra="allow")
    affected_configurations: list[AffectedConfiguration] = []


# --- Security event -----------------------------------------------------------------------------------

class SecurityEvent(_Model):
    event_id: str
    asset_id: str | None  # None = sensor could not tell which asset
    timestamp: AwareDatetime
    event_type: EventType
    source_sensor: str
    details: dict[str, Any]  # sensor-specific; process names, dest_ip, change_id etc. live here
    is_simulated: bool

    # Additions (Member 4 may fill these from Shadow Watch).
    rule_id: str | None = None
    confidence: Literal["low", "medium", "high"] | None = None


# --- Incident alert -----------------------------------------------------------------------------------

class AlertFactors(_Model):
    """Contract factors, each normalised 0..1. None = could not be determined."""
    severity: float | None = Field(default=None, ge=0, le=1)
    exploitation: float | None = Field(default=None, ge=0, le=1)
    criticality: float | None = Field(default=None, ge=0, le=1)
    exposure: float | None = Field(default=None, ge=0, le=1)
    confidence: float | None = Field(default=None, ge=0, le=1)


class TimelineEntry(_Model):
    at: AwareDatetime
    event: str
    ref: str | None = None


class IncidentAlert(_Model):
    # Contract fields.
    alert_id: str
    kind: AlertKind
    priority: Priority
    status: AlertStatus
    asset_ids: list[str]
    threat_ids: list[str]
    evidence_ids: list[str]
    risk_score: float | None = Field(ge=0, le=100)
    factors: AlertFactors
    match_status: MatchStatus | None  # None for behaviour alerts with no version match
    reasons: list[str]
    limitations: list[str]  # what we could NOT verify
    timeline: list[TimelineEntry]
    created_at: AwareDatetime

    # Additions (Member 3).
    title: str = ""
    lifecycle_status: LifecycleStatus = "detected"  # fine-grained status; `status` is derived from it
    remediation_target_at: AwareDatetime | None = None  # v1.3: computed on read (correlator.remediation)
    overdue: bool | None = None
    match_detail: MatchDetail | None = None  # fine-grained match_status
    vulnerability_priority_score: float = Field(default=0, ge=0, le=100)
    behavioural_suspicion_score: float = Field(default=0, ge=0, le=100)
    evidence_confidence_score: float = Field(default=0, ge=0, le=100)
    score_factors: dict[str, Any] = Field(default_factory=dict)  # full breakdown shown on the dashboard
    escalation_reasons: list[str] = Field(default_factory=list)  # audit trail for why priority is what it is
    is_simulated: bool = True
