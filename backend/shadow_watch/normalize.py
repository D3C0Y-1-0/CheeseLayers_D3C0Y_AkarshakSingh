"""Strict normalized loader and a conservative adapter for the existing flat fixtures."""
import json
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from .schemas import NormalizedEvent

EVENT = TypeAdapter(NormalizedEvent)


def normalize_events(records: list[dict]) -> list[NormalizedEvent]:
    if len(records) > 1000:
        raise ValueError("at most 1000 events per evaluation")
    unique = {}
    for raw in records:
        event = EVENT.validate_python(raw)
        if event.event_id in unique and unique[event.event_id] != event:
            raise ValueError(f"conflicting duplicate event_id: {event.event_id}")
        unique[event.event_id] = event
    return sorted(unique.values(), key=lambda e: (e.observed_at, e.event_id))


def load_events(path: Path) -> list[NormalizedEvent]:
    return normalize_events(json.loads(path.read_text(encoding="utf-8")))


def adapt_shared_events(records: list[dict], *, ingested_at: str, raw_ref: str) -> tuple[list[NormalizedEvent], list[dict]]:
    """Return supported evidence and explicit rejects; never guess missing aggregate counts.

    In particular a single HTTP status is not an aggregate 4xx count, and approved_by
    is not a machine-verified maintenance approval. Original records remain in raw_ref.
    """
    accepted, issues = [], []
    for raw in records:
        try:
            details = raw["details"]
            kind = raw["event_type"]
            if kind == "process":
                event_type, source_type = "process_start", "synthetic_host"
                if raw["source_sensor"] != "edr-agent" or raw["is_simulated"] is not True:
                    raise ValueError("unverified host sensor; use an authorised source mapping")
                mapped = {"process_name": details["child_process"], "parent_process": details["parent_process"]}
            elif kind == "network":
                event_type, source_type = "network_connection", "synthetic_network"
                if details["direction"] not in ("inbound", "outbound"):
                    raise ValueError("unknown network direction")
                mapped = {"destination_ip": details["dest_ip"], "destination_port": details["dest_port"],
                          "outbound": details["direction"] == "outbound", "is_new_destination": details["first_seen_destination"]}
            else:
                raise ValueError("unsupported or incomplete aggregate/approval fields; preserve raw evidence")
            accepted.append({"event_id": raw["event_id"], "asset_id": raw["asset_id"],
                             "sensor_id": raw["source_sensor"], "observed_at": raw["timestamp"],
                             "ingested_at": ingested_at, "event_type": event_type, "source_type": source_type,
                             "is_simulated": raw["is_simulated"], "source": "netrax_synthetic", "raw_ref": raw_ref, "details": mapped})
            EVENT.validate_python(accepted[-1])
        except (ValueError, KeyError, ValidationError) as exc:
            if accepted and accepted[-1].get("event_id") == raw.get("event_id"):
                accepted.pop()
            issues.append({"event_id": raw.get("event_id"), "reason": str(exc).splitlines()[0]})
    return normalize_events(accepted), issues
