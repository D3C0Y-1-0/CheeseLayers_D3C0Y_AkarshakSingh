"""Additive Member 4 DTOs. Shared fixture fields are never renamed in place."""
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, StrictBool, StrictInt, AfterValidator, BeforeValidator, model_validator


def iso_timestamp(value):
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO-8601 string or aware datetime, not an epoch number")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone-aware observation required")
    return value.astimezone(timezone.utc)


Timestamp = Annotated[datetime, BeforeValidator(iso_timestamp), AfterValidator(utc)]
Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")]
Count = Annotated[StrictInt, Field(ge=0, le=10**9)]


class FrozenDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HTTPDetails(FrozenDTO):
    request_count: Count
    http_4xx_count: Count
    failed_auth_count: Count
    unique_client_count: Count
    window_seconds: Annotated[StrictInt, Field(ge=1, le=3600)]
    path_category: Annotated[str, Field(max_length=100)] | None = None

    @model_validator(mode="after")
    def counts_fit(self):
        if any(v > self.request_count for v in (self.http_4xx_count, self.failed_auth_count, self.unique_client_count)):
            raise ValueError("HTTP counts cannot exceed request_count")
        return self


class ProcessDetails(FrozenDTO):
    process_name: Annotated[str, Field(min_length=1, max_length=256)]
    parent_process: Annotated[str, Field(min_length=1, max_length=256)]
    process_id: Annotated[StrictInt, Field(gt=0)] | None = None
    parent_process_id: Annotated[StrictInt, Field(gt=0)] | None = None


class NetworkDetails(FrozenDTO):
    destination_ip: IPvAnyAddress
    destination_port: Annotated[StrictInt, Field(ge=1, le=65535)]
    outbound: StrictBool
    is_new_destination: StrictBool
    connection_uid: Identifier | None = None


class MaintenanceDetails(FrozenDTO):
    asset_id: Identifier
    start_at: Timestamp
    end_at: Timestamp
    change_id: Identifier
    approved: StrictBool

    @model_validator(mode="after")
    def ordered(self):
        if self.end_at <= self.start_at:
            raise ValueError("maintenance end must follow start")
        return self


class EventEnvelope(FrozenDTO):
    event_id: Identifier
    asset_id: Identifier
    sensor_id: Identifier
    observed_at: Timestamp
    ingested_at: Timestamp
    source_type: Literal["synthetic_http", "synthetic_host", "synthetic_network", "synthetic_change",
                         "http_sensor", "host_sensor", "network_sensor", "change_management"]
    is_simulated: StrictBool
    source: Annotated[str, Field(min_length=1, max_length=128)]
    raw_ref: Annotated[str, Field(min_length=1, max_length=512)]

    @model_validator(mode="after")
    def source_matches(self):
        allowed = {"http_window": ("synthetic_http", "http_sensor"),
                   "process_start": ("synthetic_host", "host_sensor"),
                   "network_connection": ("synthetic_network", "network_sensor"),
                   "maintenance_window": ("synthetic_change", "change_management")}
        if self.source_type not in allowed[self.event_type]:
            raise ValueError("event type requires a compatible sensor (processes need host telemetry)")
        if self.source_type.startswith("synthetic_") and not self.is_simulated:
            raise ValueError("synthetic source must be marked simulated")
        if self.ingested_at < self.observed_at:
            raise ValueError("ingestion cannot precede observation")
        if self.event_type == "maintenance_window" and self.details.asset_id != self.asset_id:
            raise ValueError("maintenance asset must match envelope")
        return self


class HTTPEvent(EventEnvelope):
    event_type: Literal["http_window"]
    details: HTTPDetails


class ProcessEvent(EventEnvelope):
    event_type: Literal["process_start"]
    details: ProcessDetails


class NetworkEvent(EventEnvelope):
    event_type: Literal["network_connection"]
    details: NetworkDetails


class MaintenanceEvent(EventEnvelope):
    event_type: Literal["maintenance_window"]
    details: MaintenanceDetails


NormalizedEvent = Annotated[HTTPEvent | ProcessEvent | NetworkEvent | MaintenanceEvent, Field(discriminator="event_type")]


class DetectionContext(FrozenDTO):
    # Supplied by the authorised inventory adapter; never inferred from a destination address.
    protected_asset_ids: frozenset[str]
    approved_process_pairs: frozenset[tuple[str, str]] = frozenset()


class DetectionFinding(FrozenDTO):
    finding_id: Identifier
    asset_id: Identifier
    detector_id: Literal["SW-HTTP-001", "SW-PROC-001", "SW-NET-001"]
    detector_version: str = "rules-v1"
    finding_type: Literal["unusual_http_window", "unexpected_process_activity", "new_outbound_destination"]
    observed_at: Timestamp
    severity_hint: Literal["low", "medium", "high"]
    evidence_ids: tuple[str, ...]
    reason: str
    confidence: Literal["low", "medium"]
    is_simulated: StrictBool
    source: str
    retrieved_at: Timestamp
    raw_ref: str
    maintenance_evidence_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
