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
        return findings
