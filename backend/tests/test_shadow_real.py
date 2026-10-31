"""Shadow Watch on REAL SecRepo windows: SSH rule, Isolation Forest triage, persistence and investigation."""
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.correlator import CorrelationEngine
from app.database import SessionLocal
from app.main import app
from shadow_watch import ml, real
from shadow_watch.normalize import EVENT

client: TestClient


@pytest.fixture(scope="module", autouse=True)
def _app():
    global client
    with TestClient(app) as c:
        client = c
        yield


@pytest.fixture(autouse=True)
def clean(monkeypatch, _app):
    monkeypatch.setenv("DEMO_MODE", "true")
    with SessionLocal() as db:
        CorrelationEngine(db).reset()
    client.app.state.shadow_demo_adapter.__init__()


def inject(scenario):
    r = client.post("/api/demo/inject-behaviour", json={"scenario": scenario})
    assert r.status_code == 200, r.text
    return r.json()


def test_real_ssh_bruteforce_trips_the_rule():
    b = inject("real_ssh_bruteforce")
    assert b["findings"] and {f["detector_id"] for f in b["findings"]} == {"SW-AUTH-001"}
    assert all(e["source"] == "secrepo:ssh" and e["event_type"] == "auth_window" for e in b["evidence"])
    [aid] = b["alert_ids"]
    a = client.get(f"/api/alerts/{aid}").json()
    assert a["title"].startswith("SSH password guessing") and a["asset_ids"] == ["GOV-VPN-01"]
    report = client.post(f"/api/alerts/{aid}/investigate").json()
    assert report["evidence_ids"] and report["analyst_review_required"] is True


@pytest.mark.parametrize("scenario", ["real_ssh_distributed_spray", "real_web_crawler"])
def test_isolation_forest_catches_what_the_rules_miss(scenario):
    b = inject(scenario)
    assert b["findings"] and {f["detector_id"] for f in b["findings"]} == {"SW-ML-001"}
    for f in b["findings"]:
        assert f["severity_hint"] == "low" and f["confidence"] == "low" and f["detector_version"] == "iforest-v1"
        assert "not proof of an attack" in " ".join(f["limitations"])
    [aid] = b["alert_ids"]
    a = client.get(f"/api/alerts/{aid}").json()
    assert a["priority"] in ("low", "medium") and a["title"].startswith("Statistical anomaly (Isolation Forest)")


def test_model_is_trained_on_earlier_minutes_only():
    for kind in ("web", "ssh"):
        train, test = ml.split(kind)
        _, _, n, last = ml.model(kind)
        assert n == len(train) and last < test[0]["minute"]  # temporal holdout


def test_model_never_scores_other_sensors():
    synthetic = EVENT.validate_python({
        "event_id": "X1", "asset_id": "HLT-WEB-01", "sensor_id": "s", "observed_at": "2026-10-31T10:00:00Z",
        "ingested_at": "2026-10-31T10:00:01Z", "event_type": "http_window", "source_type": "synthetic_http",
        "is_simulated": True, "source": "vectra_synthetic", "raw_ref": "x",
        "details": {"request_count": 900, "http_4xx_count": 800, "failed_auth_count": 0, "unique_client_count": 1,
                    "window_seconds": 60}})
    assert ml.score_event(synthetic) is None


def test_synthetic_scenarios_unchanged():
    assert inject("benign_maintenance")["findings"] == []
    assert {f["detector_id"] for f in inject("no_cve_suspicious_chain")["findings"]} == {"SW-HTTP-001", "SW-PROC-001", "SW-NET-001"}


def auth_event(**details):
    return {"event_id": "A1", "asset_id": "GOV-VPN-01", "sensor_id": "sshd", "observed_at": "2014-12-02T04:14:00Z",
            "ingested_at": "2026-11-01T00:00:00Z", "event_type": "auth_window", "source_type": "auth_sensor",
            "is_simulated": True, "source": "secrepo:ssh", "raw_ref": "x",
            "details": {"failed_count": 5, "invalid_user_count": 5, "unique_source_count": 1, "unique_user_count": 1,
                        "window_seconds": 60} | details}


def test_auth_window_schema_is_strict():
    assert EVENT.validate_python(auth_event()).details.failed_count == 5
    with pytest.raises(ValidationError):
        EVENT.validate_python(auth_event(invalid_user_count=6))  # more invalid users than failures
    with pytest.raises(ValidationError):
        EVENT.validate_python(auth_event() | {"source_type": "http_sensor"})  # auth windows need an auth sensor


def test_real_scenarios_are_described():
    for s in real.SCENARIOS:
        d = real.describe(s)
        assert d["windows"] >= 1 and d["first_minute"] and d["target"] in ("GOV-VPN-01", "HLT-WEB-01")
