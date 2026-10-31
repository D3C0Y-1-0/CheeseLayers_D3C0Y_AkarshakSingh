import hashlib

from . import ml
from .normalize import normalize_events
from .rules import RuleConfig, evaluate_rule
from .schemas import DetectionContext, DetectionFinding, NormalizedEvent


class ShadowWatchEngine:
    def __init__(self, config: RuleConfig | None = None):
        self.config = config or RuleConfig()

    def evaluate(self, events: list[NormalizedEvent], context: DetectionContext) -> list[DetectionFinding]:
        ordered = normalize_events([e.model_dump(mode="json") for e in events])
        windows = [e for e in ordered if e.event_type == "maintenance_window" and e.details.approved]
        findings = []
        for event in ordered:
            maintenance = tuple(w.event_id for w in windows if w.asset_id == event.asset_id
                                and w.is_simulated == event.is_simulated
                                and w.details.start_at <= event.observed_at < w.details.end_at)
            finding = evaluate_rule(event, context, maintenance, self.config)
            if finding:
                findings.append(finding)
            elif (s := ml.score_event(event)) and s["flagged"]:
                findings.append(anomaly_finding(event, s))
        return findings


def anomaly_finding(event, s: dict) -> DetectionFinding:
    """SW-ML-001: a real-sensor minute the Isolation Forest finds unusual and no rule flagged."""
    feats = ", ".join(f"{k} {v}" for k, v in s["features"].items())
    key = f"iforest-v1|SW-ML-001|{event.asset_id}|{event.event_id}"
    return DetectionFinding(
        finding_id="FIND-" + hashlib.sha256(key.encode()).hexdigest()[:24], asset_id=event.asset_id,
        detector_id="SW-ML-001", detector_version="iforest-v1", finding_type="statistical_anomaly",
        observed_at=event.observed_at, severity_hint="low", evidence_ids=(event.event_id,),
        reason=(f"Isolation Forest: more unusual than {s['unusual_percentile']}% of {s['training_minutes']} real training "
                f"minutes from this sensor (outlier score {s['score']}); {feats}"),
        confidence="low", is_simulated=event.is_simulated, source=event.source, retrieved_at=event.ingested_at,
        raw_ref=event.raw_ref,
        limitations=("Statistical outlier against this sensor's own history, not proof of an attack",
                     "No rule fired on this window; review the raw lines before acting"))
