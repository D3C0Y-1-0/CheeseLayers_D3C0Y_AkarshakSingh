import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.asset_store import get_asset_store
from app.contracts import Asset, IncidentAlert, SecurityEvent, ThreatRecord
from app.main import app

DATA = Path(__file__).resolve().parents[2] / "data"
client = TestClient(app)


def test_store_loads_40_assets():
    store = get_asset_store()
    assert len(store) == 40
    assert {a.sector for a in store.all()} == {"power", "banking", "govt", "health", "telecom", "water"}


def test_store_lookups():
    store = get_asset_store()
    assert store.get("PWR-FW-01").hostname == "nrldc-edge-fw01"
    assert store.get("NOPE") is None
    assert len(store.by_sector("power")) == 7
    fortios = {a.asset_id for a in store.by_product("Fortinet", "FortiOS")}
    assert fortios == {"PWR-FW-01", "PWR-FW-02", "BNK-FW-01", "BNK-FW-02"}


def test_models_accept_every_shared_fixture():
    # If a teammate changes a fixture or contracts.json, this fails before the demo does.
    for item in json.loads((DATA / "threats_synthetic.json").read_text()):
        ThreatRecord.model_validate(item)
    for item in json.loads((DATA / "demo_cves.json").read_text()):
        ThreatRecord.model_validate(item)
    for item in json.loads((DATA / "events.json").read_text()):
        SecurityEvent.model_validate(item)


def test_unknown_values_stay_null():
    t = ThreatRecord.model_validate(json.loads((DATA / "threats_synthetic.json").read_text())[2])
    assert t.cvss is None and t.epss is None
    pacs = get_asset_store().get("HLT-PACS-01")
    assert pacs.software[0].version is None


def test_alert_model_contract_fields():
    alert = IncidentAlert(
        alert_id="ALR-0001", kind="vulnerability", priority="critical", status="new",
        asset_ids=["PWR-FW-01"], threat_ids=["CVE-2024-21762"], evidence_ids=[], risk_score=91,
        factors={"severity": 0.98, "exploitation": 1.0, "criticality": 1.0, "exposure": 1.0, "confidence": 1.0},
        match_status="confirmed", reasons=[], limitations=[], timeline=[], created_at="2026-10-31T14:00:00+05:30",
    )
    dumped = alert.model_dump(mode="json")
    contract = json.loads((DATA / "contracts.json").read_text())["entities"]["alert"]["fields"]
    assert set(contract) <= set(dumped)
    assert dumped["lifecycle_status"] == "detected"


def test_list_assets_endpoint():
    r = client.get("/api/assets")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 40
    assert body[0]["ip"] == "203.0.113.10"  # serialised as a plain string


@pytest.mark.parametrize("params,expected", [
    ({"sector": "banking"}, 7),
    ({"criticality": 5}, None),
    ({"internet_facing": "true"}, None),
    ({"sector": "power", "internet_facing": "true"}, 3),
])
def test_list_assets_filters(params, expected):
    r = client.get("/api/assets", params=params)
    assert r.status_code == 200
    body = r.json()
    if expected is not None:
        assert len(body) == expected
    for a in body:
        if "sector" in params:
            assert a["sector"] == params["sector"]
        if "criticality" in params:
            assert a["criticality"] == params["criticality"]
        if "internet_facing" in params:
            assert a["internet_facing"] is True


def test_bad_filter_is_rejected():
    assert client.get("/api/assets", params={"sector": "transport"}).status_code == 422
    assert client.get("/api/assets", params={"criticality": 9}).status_code == 422


def test_get_asset_endpoint():
    r = client.get("/api/assets/GOV-WEB-01")
    assert r.status_code == 200
    assert r.json()["software"][0]["version"] == "8.1.28"
    assert client.get("/api/assets/NOPE").status_code == 404
