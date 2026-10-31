"""Exercise the real app lifespan and Member 4 routes offline with a temporary DB."""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def smoke() -> dict:
    # Set before importing the existing app/database configuration.
    os.environ["DEMO_MODE"] = "true"
    from tempfile import TemporaryDirectory
    with TemporaryDirectory(prefix="vectra-shadow-smoke-") as directory:
        os.environ["VECTRA_DB_URL"] = "sqlite:///" + (Path(directory) / "smoke.db").as_posix()
        from fastapi.testclient import TestClient
        from app.main import app
        from app.database import engine
        results = []
        try:
            with TestClient(app) as client:
                assert client.get("/health").status_code == 200
                for scenario in ("no_cve_suspicious_chain", "benign_maintenance", "missing_telemetry"):
                    response = client.post("/api/demo/inject-behaviour", json={"scenario": scenario})
                    assert response.status_code == 200, response.text
                    payload = response.json()
                    report = client.post(f"/api/alerts/{payload['incident_id']}/investigate")
                    assert report.status_code == 200, report.text
                    results.append({"scenario": scenario, "findings": len(payload["findings"]),
                                    "evidence_count": len(report.json()["evidence_ids"]),
                                    "assessment": report.json()["assessment"], "generated_by": report.json()["generated_by"]})
        finally:
            engine.dispose()  # Release SQLite handles before deleting the temporary DB on Windows.
    return {"demo_mode": True, "lifespan_loaded": True, "scenarios": results}


if __name__ == "__main__":
    print(json.dumps(smoke(), indent=2))
