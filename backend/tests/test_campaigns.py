"""Step 2: campaign link rules, caps, determinism and API."""
import json
import random
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import campaigns
from app.database import Base
from app.main import app
from app.models import Threat

NOW = datetime(2026, 10, 30, tzinfo=timezone.utc)


def T(tid, source="otx", days=1, cves=(), tech=(), products=(), title=None, desc=None, kev=None):
    rnd = random.Random(tid)  # distinct random words: no accidental text similarity between fixtures
    words = " ".join("".join(rnd.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(7)) for _ in range(8))
    return Threat(threat_id=tid, cve_id=tid if tid.startswith("CVE-") else None, source=source, title=title or words[:15],
                  description=desc or words,
                  affected_configurations=[{"vendor": v, "product": p} for v, p in products], references=[],
                  attack_techniques=list(tech), published_at=NOW - timedelta(days=days), retrieved_at=NOW,
                  raw_refs=[], is_simulated=False, type="campaign", cve_ids=list(cves), tags=[], kev_listed=kev)


def build(rows):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with sessionmaker(engine)() as db:
        db.add_all(rows)
        db.commit()
        return campaigns.build(db)


def ids(result):
    return [sorted(c["threat_ids"]) for c in result["campaigns"]]


def test_shared_cve_links_and_reason_text():
    r = build([T("CVE-2026-1", "kev", cves=["CVE-2026-1"], kev=True), T("CERTIN-1", "certin", cves=["CVE-2026-1", "CVE-2026-2"]),
               T("OTX-1", cves=["CVE-2026-1"]), T("OTX-2")])
    assert ids(r) == [["CERTIN-1", "CVE-2026-1", "OTX-1"]]
    c = r["campaigns"][0]
    assert c["link_reasons"][0]["text"] == "3 share CVE-2026-1" and c["kev_listed_members"] == 1


def test_min_size_and_product_link():
    assert ids(build([T("A", cves=["CVE-2026-9"]), T("B", cves=["CVE-2026-9"])])) == []  # 2 < min_size
    r = build([T(f"K{i}", "kev", days=1 + 2 * i, products=[("ivanti", "connect_secure")]) for i in range(3)])
    assert ids(r) == [["K0", "K1", "K2"]] and r["campaigns"][0]["title"] == "Ivanti Connect Secure"
    assert r["campaigns"][0]["kind"] == "campaign"  # spread over days: an exploitation wave, not one release


def test_generic_keys_are_skipped():
    r = build([T(f"P{i}", tech=["T1190"]) for i in range(30)])
    assert ids(r) == [] and any(k.startswith("technique:T1190") for k in r["meta"]["skipped_generic_keys"])


def test_text_similarity_groups_ransomware_actor():
    rows = [T(f"R{i}", "ransomware", title=f"qilin ransomware claims victim{i}", desc="qilin leak site posting data extortion")
            for i in range(4)] + [T(f"N{i}") for i in range(20)]
    r = build(rows)
    assert ids(r) == [["R0", "R1", "R2", "R3"]]
    assert r["campaigns"][0]["link_reasons"][0]["type"] == "text_similarity" and "qilin" in r["campaigns"][0]["title"]


def test_growth_and_emerging():
    r = build([T(f"E{i}", cves=["CVE-2026-5"], days=1 + i) for i in range(4)])
    c = r["campaigns"][0]
    assert c["growth_7d"] == {"last_7d": 4, "prev_7d": 0, "ratio": None} and c["is_emerging"]
    one_day = build([T(f"D{i}", cves=["CVE-2026-8"], days=1) for i in range(4)])["campaigns"][0]
    assert not one_day["is_emerging"]  # everything on one day is a release day, not a growing campaign
    old = build([T(f"O{i}", cves=["CVE-2026-6"], days=20) for i in range(4)] + [T("NEWEST", days=1)])["campaigns"][0]
    assert old["growth_7d"]["last_7d"] == 0 and not old["is_emerging"]  # "7 days" = before the newest record


def test_size_cap(monkeypatch):
    monkeypatch.setitem(campaigns.CONFIG, "max_campaign_size", 3)
    r = build([T(f"S{i}", cves=["CVE-2026-7"]) for i in range(7)])
    assert all(c["size"] <= 3 for c in r["campaigns"])


def test_deterministic_regardless_of_insert_order():
    rows = lambda: [T("CVE-2026-1", "kev", cves=["CVE-2026-1"]), T("C1", "certin", cves=["CVE-2026-1"]),  # noqa: E731
                    T("O1", cves=["CVE-2026-1"])] + [T(f"K{i}", "kev", products=[("acme", "gw")]) for i in range(4)]
    a = rows()
    b = rows()
    random.Random(7).shuffle(b)
    ra, rb = build(a), build(b)
    assert json.dumps(ra, sort_keys=True, default=str) == json.dumps(rb, sort_keys=True, default=str)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_campaign_api_and_threat_reference(client):
    r = client.get("/api/campaigns?limit=5").json()
    assert r["total"] >= 1 and r["items"] and r["meta"]["threats_in_scope"] > 0
    c = r["items"][0]
    assert {"campaign_id", "title", "threat_ids", "link_reasons", "first_seen", "last_seen", "growth_7d",
            "is_emerging", "affected_asset_count", "top_recommended_action"} <= set(c)
    d = client.get(f"/api/campaigns/{c['campaign_id']}").json()
    assert len(d["members"]) == c["size"] and d["link_reasons"] == c["link_reasons"]
    t = client.get(f"/api/threats/{c['threat_ids'][0]}").json()
    assert c["campaign_id"] in t["campaign_ids"]
    assert client.get("/api/campaigns/CMP-NOPE").status_code == 404
    assert client.get("/api/campaigns?emerging=true").json()["total"] == r["emerging_total"]


# ---------- quality rules: patch batches, weak evidence, roundups, titles, ranking ----------
def cpe(vendor, product):
    return [{"vendor": vendor, "product": product, "cpe": f"cpe:2.3:a:{vendor}:{product}:*"}]


def release(prefix, n, vendor="acme", product="router"):
    """n NVD CVEs published the same day by one vendor (EPSS set so they are in campaign scope)."""
    rows = [T(f"{prefix}{i}", "nvd", days=1, products=[(vendor, product)]) for i in range(n)]
    for r in rows:
        r.affected_configurations, r.epss = cpe(vendor, product), 0.2
    return rows


def test_vendor_release_day_is_a_patch_batch_and_never_emerging():
    c = build(release("CVE-2026-10", 5))["campaigns"][0]
    assert c["kind"] == "patch_batch" and not c["is_emerging"]
    assert c["title"] == f"Acme patch release {(NOW - timedelta(days=1)).date()} (5 vulnerabilities)"
    assert c["top_recommended_action"].startswith("Routine patching")


def test_threat_activity_on_one_day_is_not_a_patch_batch():
    rows = [T(f"R{i}", "ransomware", days=1, title=f"qilin ransomware claims v{i}", desc="qilin leak site posting extortion")
            for i in range(4)]
    for r in rows:
        r.tags = ["ransomware", "group:qilin"]
    c = build(rows + [T(f"N{i}") for i in range(20)])["campaigns"][0]
    assert c["kind"] == "campaign" and c["title"] == "Qilin ransomware activity (4 victim claims)"


def test_weak_evidence_only_links_inside_the_window():
    old = [T(f"K{i}", "kev", days=100 + 200 * i, products=[("ivanti", "connect_secure")]) for i in range(3)]
    assert ids(build(old + [T("NEWEST", days=1)])) == []  # one product's history across years is not a campaign
    named = [T(f"CVE-2020-{i}", "kev", days=900, cves=[f"CVE-2020-{i}"]) for i in range(2)]
    report = T("OTX-NOW", days=1, cves=["CVE-2020-0", "CVE-2020-1"])  # a current report naming old CVEs: strong link
    assert ids(build(named + [report])) == [["CVE-2020-0", "CVE-2020-1", "OTX-NOW"]]


def test_redistributor_products_are_not_evidence():
    rows = [T(f"X{i}", "kev", days=1 + i, products=[("debian", "debian_linux")]) for i in range(4)]
    assert ids(build(rows)) == []


def test_roundup_report_is_not_a_hub():
    cves = [f"CVE-2026-2{i:02d}" for i in range(12)]
    rows = [T(c, "kev", days=1 + i, cves=[c]) for i, c in enumerate(cves)] + [T("ROUNDUP", days=1, cves=cves)]
    assert ids(build(rows)) == []  # 12 CVEs > max_report_cves: naming them all proves no shared campaign


def test_patch_batch_halves_rejoin_across_the_cap(monkeypatch):
    monkeypatch.setitem(campaigns.CONFIG, "max_campaign_size", 3)
    [c] = build(release("CVE-2026-30", 7))["campaigns"]
    assert c["kind"] == "patch_batch" and c["size"] == 7  # one release, not three look-alike pieces


def test_titles_are_unique():
    out = [{"title": "Acme VPN", "threat_ids": ["A1"]}, {"title": "Acme VPN", "threat_ids": ["B1"]},
           {"title": "Other", "threat_ids": ["C1"]}]
    campaigns._unique_titles(out)
    assert [c["title"] for c in out] == ["Acme VPN · incl. A1", "Acme VPN · incl. B1", "Other"]


def test_ranked_by_actionability_with_explained_factors():
    kev = [T(f"K{i}", "kev", days=1 + i, cves=["CVE-2026-51"], kev=True) for i in range(3)]
    plain = [T(f"P{i}", "certin", days=1 + i, cves=["CVE-2026-52"]) for i in range(3)]
    cs = build(plain + kev)["campaigns"]
    assert [sorted(c["threat_ids"])[0] for c in cs] == ["K0", "P0"]
    for c in cs:
        assert c["actionability_score"] == round(sum(c["actionability_factors"].values()), 1)
    assert cs[0]["actionability_factors"]["kev_members"] == 15.0  # 3 of 5 KEV members for full points


def test_api_serves_memo_and_refreshes_stale_copy_in_background(monkeypatch):
    """Requests must not re-scan threats each time (that timed out the dashboard on a 0.1-CPU host)."""
    calls, started = [], []
    monkeypatch.setattr(campaigns, "get", lambda db: calls.append(1) or {"n": len(calls)})
    monkeypatch.setattr(campaigns, "refresh_in_background", lambda factory: started.append(1))
    monkeypatch.setattr(campaigns, "_MEMO", {"data": None, "at": 0.0})
    monkeypatch.setattr(campaigns, "_REFRESHING", campaigns.threading.Event())  # other tests' app startup may hold the real one
    assert campaigns.serve(None) == {"n": 1} and campaigns.serve(None) == {"n": 1}  # 2nd call: memo, no get()
    assert calls == [1] and started == []
    campaigns._MEMO["at"] -= campaigns.MEMO_TTL_S + 1  # copy is now stale
    assert campaigns.serve(None) == {"n": 1}  # still answered instantly from the memo...
    assert started == [1]  # ...while a background refresh was started
