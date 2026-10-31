import json
from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient
from stix2validator import ValidationOptions, validate_string

from app.main import app
from collectors import abusech, certin, ip_reputation, kev, nvd, nvd_kev, otx, ransomware
from collectors.common import load_cache


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ---------- lead time ----------
def test_lead_time_invariants(client):
    r = client.get("/api/insights/lead-time", params={"days": 90}).json()
    assert r["population"] == len(r["rows"]) > 0
    assert r["flagged_before_kev"] == sum(x["lead_days"] is not None for x in r["rows"])
    assert r["config"]["epss_threshold"] == 0.1 and r["methodology"] and r["limitations"]
    for row in r["rows"]:
        kd = date.fromisoformat(row["kev_date_added"])
        assert (date.today() - kd).days <= 91
        fired = [date.fromisoformat(s["date"]) for s in row["signals"].values() if s]
        assert all(d < kd for d in fired)  # no look-ahead: every counted signal predates KEV
        if row["flagged_at"]:
            assert date.fromisoformat(row["flagged_at"]) == min(fired)
            assert row["lead_days"] == (kd - min(fired)).days > 0
    assert sum(c["population"] for c in r["cohorts"].values()) == r["population"]
    assert sum(c["flagged_before_kev"] for c in r["cohorts"].values()) == r["flagged_before_kev"]
    for s in r["per_signal"].values():
        assert s["earliest_signal"] <= s["fired_before_kev"] <= s["data_available"] <= r["population"]


def test_lead_time_no_lookahead(client, monkeypatch):
    row = client.get("/api/insights/lead-time", params={"days": 90}).json()["rows"][0]
    cve, kd = row["cve_id"], row["kev_date_added"]
    poc_day = (date.fromisoformat(kd) - timedelta(days=5)).isoformat()
    fake = {"epss_history": {cve: {kd: 0.99, "2000-01-01": 0.0}},  # high EPSS only ON the KEV day -> must not count
            "exploit_signals": {cve: {"exploitdb_date": "2099-01-01"}},  # after KEV -> must not count
            "github_poc_dates": {cve: f"{poc_day}T00:00:00Z"}}  # 5 days before KEV -> counts
    monkeypatch.setattr("app.insights.load_cache", lambda name: fake.get(name, {}))
    got = next(x for x in client.get("/api/insights/lead-time", params={"days": 90}).json()["rows"] if x["cve_id"] == cve)
    assert got["signals"]["epss"] is None and got["signals"]["exploitdb"] is None
    assert got["signals"]["github_poc"]["date"] == poc_day and got["lead_days"] >= 5


def test_lead_time_ignores_poc_repo_older_than_cve(client, monkeypatch):
    rows = client.get("/api/insights/lead-time", params={"days": 90}).json()["rows"]
    row = next(r for r in rows if r["published_at"])
    cve, pub = row["cve_id"], date.fromisoformat(row["published_at"][:10])
    for repo_created, counted in ((date(pub.year - 3, 1, 1), False), (pub, True)):
        fake = {"github_poc_dates": {cve: f"{repo_created}T00:00:00Z"}}
        monkeypatch.setattr("app.insights.load_cache", lambda name, f=fake: f.get(name, {}))
        got = next(x for x in client.get("/api/insights/lead-time", params={"days": 90}).json()["rows"] if x["cve_id"] == cve)
        assert (got["signals"]["github_poc"] is not None) is (counted and repo_created < date.fromisoformat(got["kev_date_added"]))


def test_lead_time_days_bounds(client):
    assert client.get("/api/insights/lead-time", params={"days": 181}).status_code == 422


# ---------- India ----------
def test_india_panel(client):
    r = client.get("/api/insights/india").json()
    assert r["certin_advisories"] and all(t["source"] == "certin" and t["references"] for t in r["certin_advisories"])
    assert r["ransomware_victims_total"] == sum(g["count"] for g in r["ransomware_groups"]) == sum(r["ransomware_by_sector"].values())
    assert all(v["references"] for g in r["ransomware_groups"] for v in g["victims"])
    for p in r["otx_pulses"]:  # "British Indian Ocean Territory" alone must not count as India
        assert any(t.lower() in ("india", "target:india") for t in p["tags"]) or "india" in p["title"].lower()


# ---------- STIX ----------
def _valid(text: str) -> bool:
    res = validate_string(text, ValidationOptions(version="2.1"))
    if not res.is_valid:
        print([str(e) for e in res.errors][:5])
    return res.is_valid


@pytest.mark.parametrize("tid", ["CVE-2024-21762", "DEMO-VULN-001"])
def test_stix_vulnerability_valid(client, tid):
    r = client.get("/api/export/stix", params={"threat_id": tid})
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/stix+json")
    assert _valid(r.text)
    b = r.json()
    types = {o["type"] for o in b["objects"]}
    assert {"identity", "vulnerability"} <= types
    v = next(o for o in b["objects"] if o["type"] == "vulnerability")
    if tid.startswith("CVE"):
        assert {"source_name": "cve", "external_id": tid} in v["external_references"] and "attack-pattern" in types
    else:
        assert v["labels"] == ["simulated"] and all(e["source_name"] != "cve" for e in v["external_references"])


def test_stix_bundle_with_indicators_valid(client):
    ids = [client.get("/api/threats", params={"source": s, "page_size": 1}).json()["items"][0]["threat_id"]
           for s in ("feodotracker", "otx", "certin", "ransomware")]
    r = client.get("/api/export/stix", params={"ids": ",".join(ids)})
    assert r.status_code == 200 and _valid(r.text)
    types = [o["type"] for o in r.json()["objects"]]
    assert "indicator" in types and "relationship" in types and "report" in types and "campaign" in types
    assert client.get("/api/export/stix", params={"ids": ",".join(ids)}).text == r.text  # deterministic


@pytest.mark.parametrize("params,code", [({}, 400), ({"threat_id": "CVE-0000-0000"}, 404),
                                         ({"ids": ",".join(f"x{i}" for i in range(51))}, 400)])
def test_stix_errors(client, params, code):
    assert client.get("/api/export/stix", params=params).status_code == code


# ---------- collectors emit contract names natively: re-parsing raw reproduces the cache ----------
@pytest.mark.parametrize("name,mod", [("nvd", nvd), ("nvd_kev", nvd_kev), ("kev", kev), ("certin", certin), ("otx", otx),
                                      ("abusech", abusech), ("ip_reputation", ip_reputation), ("ransomware", ransomware)])
def test_from_raw_matches_cache(name, mod):
    cached = load_cache(name)
    rebuilt = mod.from_raw()
    assert sorted(i.threat_id for i in rebuilt["items"]) == sorted(i["threat_id"] for i in cached["items"])  # order may differ (CERT-In)
    assert len(rebuilt.get("iocs", [])) == len(cached.get("iocs", []))
    assert set(cached["items"][0]) == set(rebuilt["items"][0].model_dump())  # same (contract) field names
