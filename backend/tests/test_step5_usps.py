import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.asset_store import get_asset_store
from app.correlator import CorrelationEngine
from app.database import SessionLocal, init_db
from app.main import app

DATA = Path(__file__).resolve().parents[2] / "data"
DEMO = {t["threat_id"]: t for t in json.loads((DATA / "demo_cves.json").read_text(encoding="utf-8"))
        + json.loads((DATA / "threats_synthetic.json").read_text(encoding="utf-8"))}
EVENTS = json.loads((DATA / "events.json").read_text(encoding="utf-8"))
client = TestClient(app)


@pytest.fixture(autouse=True)
def clean():
    init_db()
    with SessionLocal() as db:
        CorrelationEngine(db).reset()


def posture():
    r = client.get("/api/sectors/posture")
    assert r.status_code == 200
    body = r.json()
    return body, {s["sector"]: s for s in body["sectors"]}


def simulate(**body):
    return client.post("/api/simulation/patch-impact", json=body)


# --- sector posture ----------------------------------------------------------------------------------

def test_posture_is_honestly_labelled_and_covers_every_asset():
    body, s = posture()
    assert body["data_classification"] == "Simulated Sector Exposure (Synthetic Asset Inventory)"
    assert set(s) == {"power", "banking", "govt", "health", "telecom", "water"}
    assert sum(x["total_assets"] for x in s.values()) == 40
    assert all(x["weighted_sector_risk_score"] == 0 for x in s.values())  # no alerts yet


def test_posture_reflects_active_alerts():
    client.post("/api/correlate/threat", json=DEMO["CVE-2024-21762"])  # PWR-FW-01 + BNK-FW-01
    client.post("/api/correlate/threat", json=DEMO["DEMO-VULN-003"])  # HLT-PACS-01 needs verification
    client.post("/api/correlate/events", json=EVENTS[:3])  # HLT-WEB-01 behaviour incident
    body, s = posture()
    for sec in ("power", "banking"):
        assert s[sec]["confirmed_affected_assets"] == 1
        assert s[sec]["active_critical_high_incidents"] == 1
        assert s[sec]["top_threat_ids"] == ["CVE-2024-21762"]
        assert s[sec]["max_asset_priority_score"] >= 95
    assert s["health"]["needs_verification_assets"] == 1 and s["health"]["active_incidents"] == 2
    assert s["water"]["active_incidents"] == 0
    # weighted mean over all 7 power assets: one crit-5 asset at 99.4 out of total criticality 28
    power_crit = sum(a.criticality for a in get_asset_store().by_sector("power"))
    assert s["power"]["weighted_sector_risk_score"] == round(5 * s["power"]["max_asset_priority_score"] / power_crit, 1)
    assert body["sectors"][0]["weighted_sector_risk_score"] >= body["sectors"][-1]["weighted_sector_risk_score"]


def test_resolved_alerts_leave_the_posture():
    out = client.post("/api/correlate/threat", json=DEMO["CVE-2024-21762"]).json()
    for aid in out["created"]:
        client.post(f"/api/alerts/{aid}/acknowledge", json={"status": "mitigated", "reason": "patched"})
    _, s = posture()
    assert s["power"]["confirmed_affected_assets"] == 0 and s["power"]["weighted_sector_risk_score"] == 0


# --- what-if patch simulator -------------------------------------------------------------------------

def test_patching_to_a_fixed_version_drops_risk_to_zero():
    before_inventory = [a.model_dump() for a in get_asset_store().all()]
    r = simulate(threat_id="CVE-2024-21762", patched_version="7.4.11")
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["before_affected_count"] == 2 and b["after_affected_count"] == 0
    assert b["before_aggregate_exposure_score"] > 190
    assert b["after_aggregate_exposure_score"] == 0
    assert b["modelled_exposure_reduction_pct"] == 100.0
    by = {t["asset_id"]: t for t in b["transitions"]}
    assert set(by) == {"PWR-FW-01", "BNK-FW-01"}
    assert by["PWR-FW-01"]["summary"] == "PWR-FW-01: confirmed_affected (score 99.4) -> confirmed_unaffected (score 0)"
    assert by["PWR-FW-01"]["before"]["version"] == "7.2.6" and by["PWR-FW-01"]["after"]["version"] == "7.4.11"
    # nothing live changed
    assert [a.model_dump() for a in get_asset_store().all()] == before_inventory
    assert get_asset_store().get("PWR-FW-01").software[0].version == "7.2.6"


def test_simulator_uses_the_real_engine_for_partial_fixes():
    # "Patching" to 7.2.5 is no fix: it's still inside NVD's >= 7.2.0, < 7.2.7 range, and the matcher says so.
    b = simulate(threat_id="CVE-2024-21762", patched_version="7.2.5").json()
    assert b["after_affected_count"] == 2 and b["modelled_exposure_reduction_pct"] == 0
    assert any("still inside a vulnerable range" in n for n in b["notes"])


def test_unparseable_patch_version_is_not_counted_as_safe():
    b = simulate(threat_id="CVE-2024-21762", patched_version="7.4.11-custombuild").json()
    assert b["after_affected_count"] == 0 and b["after_needs_verification_count"] == 2
    assert b["after_aggregate_exposure_score"] > 0  # uncertain is not zero risk
    assert any("can't confirm" in n for n in b["notes"])


def test_does_not_touch_alerts():
    out = client.post("/api/correlate/threat", json=DEMO["CVE-2024-21762"]).json()
    before = client.get("/api/alerts").json()
    simulate(threat_id="CVE-2024-21762", patched_version="7.4.11")
    assert client.get("/api/alerts").json() == before
    assert len(out["created"]) == 2


def test_asset_ids_only_uses_their_open_alerts():
    client.post("/api/correlate/threat", json=DEMO["CVE-2024-21762"])
    b = simulate(asset_ids=["PWR-FW-01"], patched_version="7.4.11").json()
    assert b["threat_ids"] == ["CVE-2024-21762"] and b["assets_simulated"] == 1
    assert b["transitions"][0]["after"]["score"] == 0


def test_synthetic_threat_and_unknown_version():
    b = simulate(threat_id="DEMO-VULN-001", patched_version="4.2.3").json()
    assert b["before_affected_count"] == 1 and b["after_affected_count"] == 0
    b = simulate(threat_id="DEMO-VULN-003", patched_version="6.1.0").json()  # version was unknown before
    assert b["before_needs_verification_count"] == 1 and b["after_aggregate_exposure_score"] == 0


@pytest.mark.parametrize("body,code", [
    ({"patched_version": "1.0"}, 422),
    ({"threat_id": "CVE-1999-0001", "patched_version": "1.0"}, 404),
    ({"asset_ids": ["NOPE"], "patched_version": "1.0"}, 404),
    ({"asset_ids": ["WTR-FS-01"], "patched_version": "1.0"}, 400),  # no open alerts
])
def test_simulator_errors(body, code):
    assert simulate(**body).status_code == code
