import json
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.correlator import CorrelationEngine
from app.database import SessionLocal, init_db
from app.main import app

DATA = Path(__file__).resolve().parents[2] / "data"
EVENTS = {e["event_id"]: e for e in json.loads((DATA / "events.json").read_text(encoding="utf-8"))}
DEMO = {t["threat_id"]: t for t in json.loads((DATA / "demo_cves.json").read_text(encoding="utf-8"))
        + json.loads((DATA / "threats_synthetic.json").read_text(encoding="utf-8"))}
SCENARIO_B = ["EVT-0001", "EVT-0002", "EVT-0003"]
SCENARIO_C = ["EVT-0004", "EVT-0005", "EVT-0006"]

client = TestClient(app)  # no lifespan: we don't need Member 2's 19k threats loaded for these tests


@pytest.fixture(autouse=True)
def clean():
    init_db()
    with SessionLocal() as db:
        CorrelationEngine(db).reset()


def post_events(*ids, **overrides):
    evs = [EVENTS[i] | overrides.get(i, {}) for i in ids]
    r = client.post("/api/correlate/events", json=evs)
    assert r.status_code == 200, r.text
    return r.json()


def alerts(**params):
    r = client.get("/api/alerts", params=params)
    assert r.status_code == 200
    return r.json()["items"]


def event(event_id, asset_id, ts, event_type, details):
    return {"event_id": event_id, "asset_id": asset_id, "timestamp": ts, "event_type": event_type,
            "source_sensor": "test", "details": details, "is_simulated": True}


# --- the five required scenarios ---------------------------------------------------------------------

def test_duplicate_advisory_does_not_duplicate_incident():
    first = client.post("/api/correlate/threat", json=DEMO["CVE-2024-21762"]).json()
    assert sorted(m["asset_id"] for m in first["matches"]) == ["BNK-FW-01", "PWR-FW-01"]
    assert len(first["created"]) == 2 and first["assets_checked"] == 40

    second = client.post("/api/correlate/threat", json=DEMO["CVE-2024-21762"]).json()
    assert second["created"] == [] and sorted(second["updated"]) == sorted(first["created"])
    assert len(alerts()) == 2
    detail = client.get(f"/api/alerts/{first['created'][0]}").json()
    assert any("duplicate advisory" in t["event"] for t in detail["timeline"])


def test_same_asset_http_process_outbound_become_one_no_cve_incident():
    out = post_events(*SCENARIO_B)
    assert len(out["created"]) == 1
    [a] = alerts()
    assert a["kind"] == "behaviour" and a["asset_ids"] == ["HLT-WEB-01"]
    assert a["match_detail"] == "no_cve_behavioural" and a["match_status"] is None and a["threat_ids"] == []
    assert a["priority"] == "critical"
    assert a["evidence_ids"] == SCENARIO_B
    assert a["score_factors"]["behaviour"]["distinct_signal_types"] == ["http_anomaly", "outbound_connection",
                                                                         "unexpected_process"]


def test_unrelated_events_on_different_assets_do_not_merge():
    other = event("X-1", "WTR-WEB-01", "2026-10-31T15:03:00+05:30", "auth", {"failed_logins_last_minute": 80})
    client.post("/api/correlate/events", json=[EVENTS[i] for i in SCENARIO_B] + [other])
    got = {a["asset_ids"][0]: a for a in alerts()}
    assert set(got) == {"HLT-WEB-01", "WTR-WEB-01"}
    assert got["WTR-WEB-01"]["evidence_ids"] == ["X-1"]
    assert "X-1" not in got["HLT-WEB-01"]["evidence_ids"]
    assert not got["HLT-WEB-01"]["related_alert_ids"]  # no shared indicator -> not even linked


def test_out_of_order_events_give_the_same_incident():
    post_events(*SCENARIO_B)
    in_order = alerts()[0]
    client.post("/api/demo/reset-alerts")
    for i in reversed(SCENARIO_B):  # outbound first, HTTP last, one request each
        post_events(i)
    [a] = alerts()
    for k in ("asset_ids", "evidence_ids", "priority", "behavioural_suspicion_score", "match_detail"):
        assert a[k] == in_order[k], k
    times = [datetime.fromisoformat(t["at"]) for t in a["timeline"]]  # sensor (+05:30) and audit (Z) times mixed
    assert times == sorted(times)
    assert [t["ref"] for t in a["timeline"] if t["ref"] in SCENARIO_B] == SCENARIO_B


def test_maintenance_prevents_false_critical_but_stays_visible():
    post_events(*SCENARIO_C)
    [a] = alerts(asset_id="BNK-NET-01")
    assert a["priority"] == "low"
    assert a["title"].startswith("Maintenance activity")
    assert "EVT-0004" in a["evidence_ids"] and "EVT-0005" in a["evidence_ids"]  # context kept as evidence
    audit = " ".join(t["event"] for t in a["timeline"])
    assert "suppressed" in audit and "CHG-2026-1031-07" in audit
    assert a in alerts(priority="low")  # visible in the normal list, not hidden


# --- more correlation behaviour ----------------------------------------------------------------------

def test_replayed_event_id_updates_instead_of_duplicating():
    post_events(*SCENARIO_B)
    out = post_events("EVT-0002")
    assert out["duplicates"] == ["EVT-0002"] and out["created"] == []
    assert len(alerts()) == 1


def test_events_outside_the_window_are_separate_incidents():
    a = event("W-1", "GOV-WEB-02", "2026-10-31T10:00:00+05:30", "auth", {"failed_logins_last_minute": 50})
    b = event("W-2", "GOV-WEB-02", "2026-10-31T10:16:00+05:30", "auth", {"failed_logins_last_minute": 50})
    client.post("/api/correlate/events", json=[a, b])
    assert len(alerts(asset_id="GOV-WEB-02")) == 2


def test_late_event_bridging_two_incidents_merges_them():
    a = event("M-1", "GOV-WEB-02", "2026-10-31T10:00:00+05:30", "auth", {"failed_logins_last_minute": 50})
    c = event("M-3", "GOV-WEB-02", "2026-10-31T10:20:00+05:30", "auth", {"failed_logins_last_minute": 50})
    client.post("/api/correlate/events", json=[a, c])
    assert len(alerts(asset_id="GOV-WEB-02")) == 2
    b = event("M-2", "GOV-WEB-02", "2026-10-31T10:10:00+05:30", "http", {"path": "/../../etc/passwd"})
    out = client.post("/api/correlate/events", json=[b]).json()
    assert len(out["merged"]) == 1
    [merged] = alerts(asset_id="GOV-WEB-02")
    assert merged["evidence_ids"] == ["M-1", "M-2", "M-3"]


def test_shared_malicious_dest_ip_links_but_does_not_merge():
    twin = event("L-1", "WTR-WEB-01", "2026-10-31T15:05:00+05:30", "network",
                 {"direction": "outbound", "dest_ip": "203.0.113.250", "dest_port": 4444})
    client.post("/api/correlate/events", json=[EVENTS[i] for i in SCENARIO_B] + [twin])
    got = {a["asset_ids"][0]: a for a in alerts()}
    assert set(got) == {"HLT-WEB-01", "WTR-WEB-01"}  # still two incidents
    assert got["HLT-WEB-01"]["related_alert_ids"] == [got["WTR-WEB-01"]["alert_id"]]
    assert got["WTR-WEB-01"]["related_alert_ids"] == [got["HLT-WEB-01"]["alert_id"]]
    assert any("203.0.113.250" in r for r in got["HLT-WEB-01"]["reasons"])


def test_unattributed_event_stays_visible_and_capped():
    out = post_events("EVT-0007", "EVT-0008")
    assert len(out["unattributed"]) == 1
    a = client.get(f"/api/alerts/{out['unattributed'][0]}").json()
    assert a["asset_ids"] == [] and a["priority"] in ("low", "medium")
    assert any("asset" in l for l in a["limitations"])
    wtr = alerts(asset_id="WTR-WEB-01")[0]
    assert any("client_ip is missing" in l for l in wtr["limitations"])


# --- lifecycle + API ---------------------------------------------------------------------------------

def test_acknowledge_lifecycle():
    post_events(*SCENARIO_B)
    aid = alerts()[0]["alert_id"]
    r = client.post(f"/api/alerts/{aid}/acknowledge", json={"reason": "looking into it", "by": "analyst1"}).json()
    assert r["lifecycle_status"] == "investigating" and r["status"] == "ack"
    r = client.post(f"/api/alerts/{aid}/acknowledge", json={"status": "mitigated", "reason": "host isolated"}).json()
    assert r["status"] == "resolved"
    assert any("investigating -> mitigated" in t["event"] and "host isolated" in t["event"] for t in r["timeline"])
    back = client.post(f"/api/alerts/{aid}/acknowledge", json={"status": "detected", "reason": "oops"})
    assert back.status_code == 409
    assert client.post("/api/alerts/NOPE/acknowledge", json={}).status_code == 404
    # a later re-ingest must not reset the analyst's progress
    post_events("EVT-0002", **{"EVT-0002": {"details": EVENTS["EVT-0002"]["details"] | {"user": "root"}}})
    assert alerts()[0]["lifecycle_status"] == "mitigated"


def test_alert_filters_and_detail():
    client.post("/api/correlate/threat", json=DEMO["DEMO-VULN-003"])
    post_events(*SCENARIO_B)
    assert [a["asset_ids"] for a in alerts(sector="health")] != []
    assert alerts(sector="power") == []
    assert len(alerts(match_status="no_cve_behavioural")) == 1
    assert len(alerts(match_status="requires_manual_review")) == 1  # contract value works too
    assert len(alerts(status="new")) == 2 and len(alerts(status="detected")) == 2
    vuln = alerts(kind="vulnerability")[0]
    d = client.get(f"/api/alerts/{vuln['alert_id']}").json()
    assert d["assets"][0]["asset_id"] == "HLT-PACS-01"
    assert d["title"].startswith("[SIMULATED]")
    assert {"vulnerability", "behaviour", "confidence", "priority"} <= set(d["score_factors"])
    assert d["limitations"]
    assert client.get("/api/alerts/NOPE").status_code == 404


def test_scenario_a_end_to_end_via_member2_inject():
    r = client.post("/api/demo/inject-cve", json={"fixture_id": "CVE-2024-21762"})
    assert r.status_code == 200, r.text
    got = alerts(kind="vulnerability")
    assert sorted(a["asset_ids"][0] for a in got) == ["BNK-FW-01", "PWR-FW-01"]
    assert all(a["priority"] == "critical" and a["match_status"] == "confirmed" for a in got)
    detail = client.get(f"/api/alerts/{got[0]['alert_id']}").json()
    assert detail["threats"][0]["in_database"] is True and detail["threats"][0]["kev_listed"] is True
