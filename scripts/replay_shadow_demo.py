"""Replay a predefined synthetic case locally, with no API server or network required."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from ai.fallback import build_fallback_report
from shadow_watch.demo import DemoAdapter, DemoRequest


def replay(scenario: str, run_id: str = "demo-session-1") -> dict:
    adapter = DemoAdapter()
    result = adapter.replay(DemoRequest(scenario=scenario, run_id=run_id))
    report = build_fallback_report(adapter.get_incident(result.incident_id))
    return {"injection": result.model_dump(mode="json"), "investigation": report.model_dump(mode="json")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=["no_cve_suspicious_chain", "benign_maintenance", "missing_telemetry"])
    parser.add_argument("--run-id", default="demo-session-1")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.dumps(replay(args.scenario, args.run_id), indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload)
