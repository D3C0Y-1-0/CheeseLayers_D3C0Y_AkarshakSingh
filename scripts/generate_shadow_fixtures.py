"""Build explicitly synthetic, complete Member 4 fixtures without touching shared data."""
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from shadow_watch.normalize import normalize_events

FIXTURES = ROOT / "data" / "fixtures"


def generate() -> dict:
    events = []

    def add(eid, asset, kind, timestamp, details):
        source_type = {"http_window": "synthetic_http", "process_start": "synthetic_host",
                       "network_connection": "synthetic_network", "maintenance_window": "synthetic_change"}[kind]
        observed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        events.append(dict(event_id=eid, asset_id=asset, event_type=kind, sensor_id=source_type + "-01",
                           observed_at=observed.isoformat(), ingested_at=(observed + timedelta(seconds=2)).isoformat(),
                           source_type=source_type, source="vectra_synthetic", is_simulated=True,
                           raw_ref=f"data/fixtures/events_shadow.json#{eid}", details=details))

    def http(count, errors):
        return dict(request_count=count, http_4xx_count=errors, failed_auth_count=0,
                    unique_client_count=12, window_seconds=60)

    def network():
        return dict(destination_ip="203.0.113.250", destination_port=4444, outbound=True,
                    is_new_destination=True, connection_uid="sim-connection-01")

    add("SW-EV-0001", "HLT-WEB-01", "http_window", "2026-10-31T09:32:10Z", http(340, 240))
    add("SW-EV-0002", "HLT-WEB-01", "process_start", "2026-10-31T09:33:40Z",
        dict(parent_process="php-fpm8.3", process_name="/bin/sh", parent_process_id=1100, process_id=1201))
    add("SW-EV-0003", "HLT-WEB-01", "network_connection", "2026-10-31T09:36:05Z", network())
    add("SW-EV-0004", "BNK-NET-01", "maintenance_window", "2026-10-30T20:30:00Z",
        dict(asset_id="BNK-NET-01", start_at="2026-10-30T20:30:00Z", end_at="2026-10-30T22:30:00Z",
             change_id="CHG-2026-1031-07", approved=True))
    add("SW-EV-0005", "BNK-NET-01", "http_window", "2026-10-30T20:50:00Z", http(2100, 21))
    add("SW-EV-0006", "BNK-NET-01", "process_start", "2026-10-30T21:05:00Z",
        dict(parent_process="systemd", process_name="/usr/bin/apt-get"))
    add("SW-EV-0007", "HLT-WEB-01", "http_window", "2026-10-31T10:00:00Z", http(300, 200))
    add("SW-EV-0008", "HLT-WEB-01", "network_connection", "2026-10-31T10:02:00Z", network())
    scenarios = {"no_cve_suspicious_chain": ["SW-EV-0001", "SW-EV-0002", "SW-EV-0003"],
                 "benign_maintenance": ["SW-EV-0004", "SW-EV-0005", "SW-EV-0006"],
                 "missing_telemetry": ["SW-EV-0007", "SW-EV-0008"]}
    normalized = normalize_events(events)
    assets = {a["asset_id"] for a in json.loads((ROOT / "data" / "assets.json").read_text(encoding="utf-8"))}
    if any(e.asset_id not in assets for e in normalized):
        raise ValueError("fixture asset absent from shared inventory")
    FIXTURES.mkdir(parents=True, exist_ok=True)
    files = {"events_shadow.json": events, "demo_scenarios.json": scenarios,
             "maintenance_windows.json": [e for e in events if e["event_type"] == "maintenance_window"]}
    for name, data in files.items():
        (FIXTURES / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return {"events": len(events), "scenarios": list(scenarios), "is_simulated": True}


if __name__ == "__main__":
    print(json.dumps(generate(), indent=2))
