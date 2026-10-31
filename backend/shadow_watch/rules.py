"""Prototype heuristics: evidence confidence is never an attack probability."""
import hashlib
import re
from dataclasses import dataclass

from .schemas import DetectionContext, DetectionFinding, NormalizedEvent


@dataclass(frozen=True)
class RuleConfig:
    minimum_requests_per_minute: int = 200
    minimum_4xx_ratio: float = 0.60
    minimum_window_seconds: int = 60
    maximum_window_seconds: int = 60
    minimum_failed_logins: int = 10  # SW-AUTH-001: failed logins in one window

    def __post_init__(self):
        if self.minimum_requests_per_minute < 1 or not 0 <= self.minimum_4xx_ratio <= 1:
            raise ValueError("invalid HTTP thresholds")
        if not 1 <= self.minimum_window_seconds <= self.maximum_window_seconds <= 3600:
            raise ValueError("invalid HTTP window bounds")


def process_basename(name: str) -> str:
    return name.replace("\\", "/").rsplit("/", 1)[-1].lower()


def evaluate_rule(event: NormalizedEvent, context: DetectionContext, maintenance: tuple[str, ...],
                  config: RuleConfig) -> DetectionFinding | None:
    d = event.details
    limitations = ["Heuristic observation; compromise not confirmed"]
    if event.event_type == "http_window":
        ratio = d.http_4xx_count / d.request_count if d.request_count else 0
        rpm = 60 * d.request_count / d.window_seconds
        if not (config.minimum_window_seconds <= d.window_seconds <= config.maximum_window_seconds
                and rpm >= config.minimum_requests_per_minute and ratio >= config.minimum_4xx_ratio):
            return None
        detector, kind = "SW-HTTP-001", "unusual_http_window"
        severity, confidence = ("low", "low") if maintenance else ("medium", "medium")
        reason = f"{d.http_4xx_count}/{d.request_count} HTTP 4xx responses ({ratio:.1%}) in {d.window_seconds}s ({rpm:.1f} requests/min)"
    elif event.event_type == "process_start":
        parent, child = process_basename(d.parent_process), process_basename(d.process_name)
        if (parent, child) in context.approved_process_pairs:
            return None
        web_parent = re.fullmatch(r"(?:nginx|apache2?|httpd|w3wp\.exe|web-server|php-fpm(?:\d+(?:\.\d+)*)?)", parent)
        if not web_parent or child not in {"sh", "bash", "dash", "zsh", "cmd.exe", "powershell.exe", "pwsh.exe"}:
            return None
        detector, kind = "SW-PROC-001", "unexpected_process_activity"
        severity, confidence = "high", "medium"
        reason = f"Host sensor observed unexpected process relationship: {parent} -> {child}"
    elif event.event_type == "network_connection":
        if event.asset_id not in context.protected_asset_ids or not d.outbound or not d.is_new_destination:
            return None
        detector, kind = "SW-NET-001", "new_outbound_destination"
        severity, confidence = "low", "low"
        reason = f"First-seen outbound destination {d.destination_ip}:{d.destination_port} on protected asset"
        limitations.append("New destination alone does not establish malicious activity; no destination was contacted")
    elif event.event_type == "auth_window":
        if d.failed_count < config.minimum_failed_logins:
            return None
        detector, kind = "SW-AUTH-001", "login_failure_burst"
        severity, confidence = ("high", "medium") if d.failed_count >= 3 * config.minimum_failed_logins else ("medium", "medium")
        reason = (f"{d.failed_count} failed logins in {d.window_seconds}s ({d.invalid_user_count} for non-existent users) "
                  f"from {d.unique_source_count} source(s) trying {d.unique_user_count} username(s)"
                  + (f": {', '.join(d.top_users)}" if d.top_users else ""))
        limitations.append("Failures only: the sensor does not show whether any later login succeeded")
    else:
        return None
    if maintenance:
        limitations.append("Approved maintenance overlaps this observation; independent process signals still require review")
    key = f"rules-v1|{detector}|{event.asset_id}|{event.event_id}"
    return DetectionFinding(finding_id="FIND-" + hashlib.sha256(key.encode()).hexdigest()[:24],
                            asset_id=event.asset_id, detector_id=detector, finding_type=kind,
                            observed_at=event.observed_at, severity_hint=severity, evidence_ids=(event.event_id,),
                            reason=reason, confidence=confidence, is_simulated=event.is_simulated,
                            source=event.source, retrieved_at=event.ingested_at, raw_ref=event.raw_ref,
                            maintenance_evidence_ids=maintenance, limitations=tuple(limitations))
