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
    r = build([T(f"K{i}", "kev", products=[("ivanti", "connect_secure")]) for i in range(3)])
    assert ids(r) == [["K0", "K1", "K2"]] and r["campaigns"][0]["title"] == "ivanti connect_secure"


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
    r = build([T(f"E{i}", cves=["CVE-2026-5"], days=1) for i in range(4)])
    c = r["campaigns"][0]
    assert c["growth_7d"] == {"last_7d": 4, "prev_7d": 0, "ratio": None} and c["is_emerging"]
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
