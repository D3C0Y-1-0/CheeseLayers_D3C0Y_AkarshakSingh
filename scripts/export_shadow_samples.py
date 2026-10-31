"""Capture actual Member 4 route responses for frontend mocks (no feed DB required)."""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ["DEMO_MODE"] = "true"
from fastapi.testclient import TestClient
from app.main import app


if __name__ == "__main__":
    # Route-only client: the independent lifespan smoke checks feed loading separately.
    client = TestClient(app)
    for scenario in ("no_cve_suspicious_chain", "benign_maintenance", "missing_telemetry"):
        response = client.post("/api/demo/inject-behaviour", json={"scenario": scenario})
        response.raise_for_status()
        injection = response.json()
        response = client.post(f"/api/alerts/{injection['incident_id']}/investigate")
        response.raise_for_status()
        payload = {"injection": injection, "investigation": response.json()}
        path = ROOT / "docs" / "samples" / f"shadow_{scenario}.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(path.name)
    client.close()
