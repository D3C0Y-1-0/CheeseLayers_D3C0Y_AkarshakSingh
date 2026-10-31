"""Step 5: remediation targets (organisation policy, not a regulatory deadline)."""
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.correlator import remediation
from app.main import app
from app.scoring import CONFIG

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


def test_targets_per_priority_and_overdue():
    for p, days in {"critical": 7, "high": 14, "medium": 30, "low": 90}.items():
        r = remediation({"priority": p, "created_at": T0.isoformat(), "lifecycle_status": "detected"}, now=T0 + timedelta(days=days - 1))
        assert r["remediation_target_at"] == (T0 + timedelta(days=days)).isoformat() and r["overdue"] is False
        late = remediation({"priority": p, "created_at": T0.isoformat(), "lifecycle_status": "investigating"}, now=T0 + timedelta(days=days + 1))
        assert late["overdue"] is True
    done = remediation({"priority": "critical", "created_at": T0.isoformat(), "lifecycle_status": "mitigated"}, now=T0 + timedelta(days=99))
    assert done["overdue"] is False
    assert done["remediation_policy"] == CONFIG["remediation_policy_label"]


def test_alerts_api_carries_target():
    with TestClient(app) as c:
        c.post("/api/demo/reset-alerts")
        c.post("/api/demo/inject-cve", json={"fixture_id": "CVE-2024-21762"})
        items = c.get("/api/alerts").json()["items"]
        assert items and all(a["remediation_target_at"] and a["overdue"] is False for a in items)
        a = c.get(f"/api/alerts/{items[0]['alert_id']}").json()
        assert a["remediation_policy"] == "organisation-defined policy, not a regulatory deadline"
        assert a["remediation_target_days"] == CONFIG["remediation_targets_days"][a["priority"]]
