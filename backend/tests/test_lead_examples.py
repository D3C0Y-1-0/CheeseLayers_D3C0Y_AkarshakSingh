"""Step 6: lead-time example timelines drawn from the backtest."""
from fastapi.testclient import TestClient

from app.main import app


def test_examples_from_backtest():
    with TestClient(app) as c:
        rep = c.get("/api/insights/lead-time?days=90").json()
        d = c.get("/api/insights/lead-time/examples?days=90").json()
    by = {e["example"]: e for e in d["examples"]}
    rows = {r["cve_id"]: r for r in rep["rows"]}
    assert by, "backtest window has no KEV additions"
    for e in d["examples"]:
        r = rows[e["cve_id"]]  # every example is a real backtest row, same numbers
        assert e["lead_days"] == r["lead_days"] and e["kev_date_added"] == r["kev_date_added"]
        dates = [t["date"] for t in e["timeline"]]
        assert dates == sorted(dates) and any(t["event"].startswith("Added to CISA KEV") for t in e["timeline"])
        assert all(t["before_kev"] == (t["date"] < e["kev_date_added"]) for t in e["timeline"])
    if "largest_lead" in by and "near_zero_lead" in by:
        assert by["largest_lead"]["lead_days"] >= by["near_zero_lead"]["lead_days"]
    if "miss" in by:
        assert by["miss"]["lead_days"] is None and by["miss"]["flagged_at"] is None
