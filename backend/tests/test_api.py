import json

import pytest
from fastapi.testclient import TestClient

from app.database import DEMO_MODE
from app.main import app
from collectors.test_merge import test as merge_selfcheck
from ingestion.loader import CACHE, SYNTHETIC, load


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:  # lifespan loads the empty test DB from cache
        yield c


def test_demo_mode_on():
    assert DEMO_MODE is True


def test_loader_idempotent(client):
    first, second = load(), load()
    assert first == second
    cached = len(json.loads((CACHE / "threat_items.json").read_text()))
    assert first["threats"] == cached + len(json.loads(SYNTHETIC.read_text()))  # nothing duplicated or dropped
    assert first["iocs"] == len(json.loads((CACHE / "iocs.json").read_text()))


def test_merge_null_preservation():
    merge_selfcheck()


def test_null_preserved_through_db_and_api(client):
    # DEMO-VULN-003: no CVSS, no EPSS, exploit status unknown -> must come back null, never 0/false.
    t = client.get("/api/threats/DEMO-VULN-003").json()
    assert t["cvss"] is None and t["severity"] is None and t["epss"] is None and t["epss_percentile"] is None
    assert t["public_exploit"] is None and t["cve_id"] is None and t["is_simulated"] is True
    # A real NVD record not scored yet keeps cvss null.
    unscored = next(i for i in json.loads((CACHE / "threat_items.json").read_text()) if i["cvss"] is None)
    got = client.get(f"/api/threats/{unscored['threat_id']}").json()
    assert got["cvss"] is None and got["cvss_version"] is None and got["kev_listed"] == unscored["kev_listed"]
    # No-CVE campaign: KEV status is unknown (null), not false.
    camp = client.get("/api/threats", params={"source": "ransomware", "page_size": 1}).json()["items"][0]
    assert camp["kev_listed"] is None


@pytest.mark.parametrize("path", ["/health", "/api/threats", "/api/threats/CVE-2024-21762", "/api/source-status", "/api/overview",
                                  "/api/threats?severity=critical,unknown&kev=true&min_epss=0.5&q=fortinet&simulated=false&page=1&page_size=5",
                                  "/api/threats?sort=published"])
def test_endpoints_200(client, path):
    r = client.get(path)
    assert r.status_code == 200, r.text


def test_threat_detail_has_raw_payloads(client):
    t = client.get("/api/threats/CVE-2024-21762").json()
    assert [r["path"] for r in t["raw_payloads"]] == t["raw_refs"] and t["raw_refs"][0] == t["raw_ref"]
    assert len(t["raw_refs"]) == 2 and all(r["sha256"] for r in t["raw_payloads"])  # KEV dump + NVD page
    assert t["kev_date_added"] == "2024-02-09" and t["published_at"].startswith("2024-02-09T09:15")  # NVD date, not KEV's


def test_api_output_matches_contract(client):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "data"))
    import validate as V
    V.errors.clear()
    page = client.get("/api/threats", params={"page_size": 200}).json()["items"]
    page += client.get("/api/threats", params={"simulated": "true"}).json()["items"]
    V.check_file("threat", page)
    assert not V.errors, V.errors[:5]


def test_overview_member3_fields_connected(client):
    o = client.get("/api/overview").json()
    active = [a for a in client.get('/api/alerts').json()['items'] if a['status'] != 'resolved']
    assert o['open_alerts'] == len(active)
    assert o['matched_assets'] == len({i for a in active if a['kind'] == 'vulnerability' for i in a['asset_ids']})
    assert o["threats_total"] == sum(o["threats_by_source"].values()) == sum(o["threats_by_severity"].values())


@pytest.mark.parametrize("bad", ["CVE-2021-44228", "DEMO-VULN-999", "", "../etc/passwd", "cve-2024-21762"])
def test_inject_rejects_unknown(client, bad):
    assert client.post("/api/demo/inject-cve", json={"fixture_id": bad}).status_code == 400


def test_inject_rejects_malformed(client):
    assert client.post("/api/demo/inject-cve", json={}).status_code == 422


@pytest.mark.parametrize("fid,simulated", [("CVE-2024-21762", False), ("DEMO-VULN-001", True)])
def test_inject_tops_feed(client, fid, simulated, monkeypatch):
    called = []
    monkeypatch.setattr("app.hooks.on_new_threat", lambda tid, typ: called.append((tid, typ)))
    before = client.get("/api/overview").json()["threats_total"]
    r = client.post("/api/demo/inject-cve", json={"fixture_id": fid})
    assert r.status_code == 200, r.text
    assert called == [(fid, "demo_inject")] and r.json()["injected"]["is_simulated"] is simulated
    top = client.get("/api/threats", params={"page_size": 1}).json()["items"][0]
    assert top["threat_id"] == fid  # "just arrived"
    assert client.get("/api/overview").json()["threats_total"] == before  # refresh, not a duplicate
