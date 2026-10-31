from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.database import SessionLocal
from app.main import app
from app.models import Threat, ThreatSignal
from collectors import history
from collectors.schema import ThreatItem
from ingestion import changes, scheduler
from ingestion.loader import counts, load

NOW = datetime(2026, 10, 31, 12, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def hook_calls(monkeypatch):
    calls = []
    monkeypatch.setattr("app.hooks.on_new_threat", lambda tid, typ: calls.append((tid, typ)))
    return calls


# ---------- thresholds (one config: changes.SIGNALS) ----------
@pytest.mark.parametrize("old,new,fires", [
    (0.10, 0.30, True),    # +0.20 absolute
    (0.10, 0.29, False),   # +0.19, no crossing
    (0.45, 0.51, True),    # crossed 0.5
    (0.50, 0.60, False),   # already above 0.5, +0.1
    (0.60, 0.40, False),   # went down
    (None, 0.90, False),   # unknown before: not a "jump" (null is not 0)
    (0.20, None, False),
])
def test_epss_thresholds(old, new, fires):
    assert changes.epss_jumped(old, new) is fires


def T(tid, **kw) -> ThreatItem:
    return ThreatItem(threat_id=tid, source=kw.pop("source", "nvd"), title=tid, type=kw.pop("type", "vulnerability"), **kw)


def test_detect_rules():
    old = changes.State(threats={"CVE-1": (False, 0.1, 7.0), "CVE-2": (True, 0.3, 9.8), "CVE-3": (False, None, None)},
                        evidence={"CVE-2": (False, None, False)})
    recent, stale = NOW - timedelta(days=2), NOW - timedelta(days=60)
    items = [T("CVE-1", cve_id="CVE-1", cve_ids=["CVE-1"], kev_listed=True, epss=0.35, cvss=7.0),       # new_kev + epss_jump
             T("CVE-2", cve_id="CVE-2", cve_ids=["CVE-2"], kev_listed=True, epss=0.31, cvss=9.8),       # nothing changed
             T("CVE-3", cve_id="CVE-3", cve_ids=["CVE-3"], kev_listed=False, cvss=9.1, nvd_published_at=recent),  # newly scored critical
             T("CVE-4", cve_id="CVE-4", cve_ids=["CVE-4"], kev_listed=False, cvss=9.9, nvd_published_at=stale),   # old: no signal
             T("CIVN-1", source="certin", type="advisory", cve_ids=["CVE-2", "CVE-9"])]                  # new advisory
    ev = {"CVE-2": {"exploitdb": True, "exploitdb_date": "2026-10-30", "github_poc_ok": True, "github_poc_repo": "a/b", "github_poc_date": "x"}}
    got = sorted((s["threat_id"], s["signal_type"], s["source"]) for s in changes.detect(old, items, ev, NOW))
    assert got == [("CIVN-1", "new_certin_advisory", "certin"), ("CVE-1", "epss_jump", "epss"), ("CVE-1", "new_kev", "kev"),
                   ("CVE-2", "new_public_exploit", "exploitdb"), ("CVE-2", "new_public_exploit", "github_poc"),
                   ("CVE-3", "new_critical_cve", "nvd")]
    adv = next(s for s in changes.detect(old, items, ev, NOW) if s["signal_type"] == "new_certin_advisory")
    assert adv["details"]["cve_ids"] == ["CVE-2", "CVE-9"] and adv["details"]["kev_cves"] == ["CVE-2"]


def test_poc_first_quality_check_is_not_a_new_exploit():
    # Regression: 91 false signals when PoCs that were already listed got quality-checked for the first time.
    ok = {"exploitdb": False, "exploitdb_date": None, "github_poc_listed": True, "github_poc_ok": True, "github_poc_repo": "a/b", "github_poc_date": "x"}
    items = [T(c, cve_id=c, cve_ids=[c]) for c in ("CVE-A", "CVE-B", "CVE-C")]
    old = changes.State(threats={t.threat_id: (False, None, None) for t in items},
                        evidence={"CVE-A": (False, None, True),     # listed, never checked -> first check: NO signal
                                  "CVE-B": (False, False, True)})   # listed, failed before, passes now -> signal
    # CVE-C: not listed before at all -> brand-new PoC -> signal
    got = {s["threat_id"] for s in changes.detect(old, items, {c: ok for c in ("CVE-A", "CVE-B", "CVE-C")}, NOW)}
    assert got == {"CVE-B", "CVE-C"}


def test_first_load_is_baseline():
    assert changes.detect(changes.State(), [T("CVE-1", cve_id="CVE-1", kev_listed=True)], {}, NOW) == []


# ---------- end-to-end: DB diff -> signals -> hook, never duplicated ----------
def test_ingest_emits_once_and_fires_hook(client, hook_calls):
    assert load(detect=True)["signals_emitted"] == 0  # nothing changed since startup load
    with SessionLocal.begin() as s:  # make the DB look like the moment before CISA listed it + EPSS was low
        t = s.get(Threat, "CVE-2024-21762")
        t.kev_listed, t.epss = False, 0.2
    first = load(detect=True)
    assert first["signals_emitted"] == 2
    assert sorted(hook_calls) == [("CVE-2024-21762", "epss_jump"), ("CVE-2024-21762", "new_kev")]
    assert load(detect=True)["signals_emitted"] == 0  # replay: same state, no new signal
    with SessionLocal.begin() as s:  # the exact same change happens again -> same signal_id -> not duplicated
        t = s.get(Threat, "CVE-2024-21762")
        t.kev_listed, t.epss = False, 0.2
    assert load(detect=True)["signals_emitted"] == 0
    with SessionLocal() as s:
        n = s.scalar(select(func.count()).select_from(ThreatSignal).where(ThreatSignal.threat_id == "CVE-2024-21762",
                                                                         ThreatSignal.is_simulated.is_(False)))
    assert n == 2 and len(hook_calls) == 2
    sig = client.get("/api/signals", params={"type": "new_kev", "simulated": "false"}).json()["items"][0]
    assert sig["threat_id"] == "CVE-2024-21762" and sig["old_value"] is False and sig["new_value"] is True


# ---------- PoC quality filter ----------
def test_poc_quality_filter(monkeypatch):
    repos = [{"full_name": "old/reused", "created_at": "2020-01-01T00:00:00Z"},       # older than CVE - 30d: skipped
             {"full_name": "a/readme-only", "created_at": "2026-05-02T00:00:00Z"},     # only README/LICENSE/image
             {"full_name": "b/real-poc", "created_at": "2026-05-03T00:00:00Z"},        # has exploit.py -> first good one
             {"full_name": "c/later", "created_at": "2026-06-01T00:00:00Z"}]
    trees = {"a/readme-only": [{"type": "blob", "path": "README.md"}, {"type": "blob", "path": "LICENSE"}, {"type": "blob", "path": "img/x.png"}],
             "b/real-poc": [{"type": "blob", "path": "README.md"}, {"type": "blob", "path": "src/exploit.py"}]}
    seen = []

    class R:
        def __init__(self, data): self.data = data
        def json(self): return self.data

    def fake_get(url, **kw):
        if "PoC-in-GitHub" in url:
            return R(repos)
        name = url.split("/repos/")[1].split("/git/")[0]
        seen.append(name)
        return R({"tree": trees[name]})

    monkeypatch.setattr(history, "get", fake_get)
    monkeypatch.setattr(history, "load_cache", lambda name: {})
    out = history.poc_quality(["CVE-2026-1234"], {"CVE-2026-1234": datetime(2026, 5, 1).date()})["CVE-2026-1234"]
    assert out["ok"] and out["first_ok_repo"] == "b/real-poc" and out["first_ok_created_at"].startswith("2026-05-03")
    assert seen == ["a/readme-only", "b/real-poc"]  # stopped at the first good repo, never fetched the old one

    def limited(url, **kw):  # GitHub rate limit -> unknown, must not be cached as "no PoC"
        if "PoC-in-GitHub" in url:
            return R(repos)
        raise httpx.HTTPStatusError("403", request=httpx.Request("GET", url), response=httpx.Response(403))
    monkeypatch.setattr(history, "get", limited)
    assert "CVE-2026-1234" not in history.poc_quality(["CVE-2026-1234"], {"CVE-2026-1234": datetime(2026, 5, 1).date()})


# ---------- scheduler ----------
def test_demo_mode_disables_scheduler(client):
    assert scheduler.start() is None and app.state.scheduler is None
    assert client.get("/health").json()["scheduler"] is None


def test_scheduler_jobs_and_intervals(monkeypatch):
    monkeypatch.setattr(scheduler, "DEMO_MODE", False)
    sched = scheduler.start()
    try:
        jobs = {j.id: j for j in sched.get_jobs()}
        assert {k: j.trigger.interval.total_seconds() / 3600 for k, j in jobs.items()} == \
               {"kev": 1, "nvd": 2, "epss": 24, "certin": 6, "abusech": 1}
        assert all(j.next_run_time > datetime.now(timezone.utc) for j in jobs.values())  # nothing fires at boot
    finally:
        sched.shutdown(wait=False)


def test_scheduled_nvd_is_incremental(monkeypatch):
    from collectors import nvd, run_all
    saved = {}
    monkeypatch.setattr(nvd, "fetch", lambda: pytest.fail("scheduler must never refetch the full NVD window"))
    old_cve = T("CVE-2010-0001", cve_id="CVE-2010-0001", published_at=datetime(2010, 1, 1, tzinfo=timezone.utc))
    kev_cve = T("CVE-2024-21762", cve_id="CVE-2024-21762", cvss=9.9, published_at=datetime(2024, 2, 9, tzinfo=timezone.utc))
    since = []
    monkeypatch.setattr(nvd, "modified_since", lambda s: since.append(s) or [old_cve, kev_cve])
    monkeypatch.setattr(run_all, "save_cache", lambda name, data: saved.__setitem__(name, data))
    out = run_all.nvd_incremental({"CVE-2024-21762"})
    ids = {i.threat_id for i in out["items"]}
    assert since and "CVE-2010-0001" not in ids  # a modified OLD CVE is not added to the 30-day nvd cache
    kev_items = {i.threat_id: i for i in saved["nvd_kev"]["items"]}
    assert kev_items["CVE-2024-21762"].cvss == 9.9  # KEV record refreshed with NVD's latest


# ---------- demo endpoints ----------
def test_simulate_signal(client, hook_calls):
    r = client.post("/api/demo/simulate-signal", json={"fixture_id": "DEMO-VULN-001", "signal_type": "epss_jump"})
    assert r.status_code == 200, r.text
    s = r.json()
    assert s["is_simulated"] and s["details"]["simulated"] and s["old_value"] < 0.5 <= s["new_value"]
    assert hook_calls == [("DEMO-VULN-001", "epss_jump")]
    assert client.get("/api/signals", params={"limit": 1}).json()["items"][0]["signal_id"] == s["signal_id"]
    assert client.get("/api/threats/DEMO-VULN-001").json()["epss"] == s["new_value"]  # synthetic row kept consistent
    real = client.post("/api/demo/simulate-signal", json={"fixture_id": "CVE-2024-4577", "signal_type": "epss_jump"}).json()
    assert real["new_value"] == client.get("/api/threats/CVE-2024-4577").json()["epss"]  # real data never altered
    assert client.get("/api/signals/summary").json()["simulated_last_24h"] >= 2


@pytest.mark.parametrize("body,code", [({"fixture_id": "CVE-2021-44228", "signal_type": "new_kev"}, 400),
                                       ({"fixture_id": "DEMO-VULN-001", "signal_type": "made_up"}, 422)])
def test_simulate_signal_rejects(client, body, code):
    assert client.post("/api/demo/simulate-signal", json=body).status_code == code


def test_reset_restores_counts(client):
    client.post("/api/demo/reset")
    base = counts()
    for typ in ("new_kev", "new_critical_cve", "new_public_exploit"):
        assert client.post("/api/demo/simulate-signal", json={"fixture_id": "DEMO-VULN-003", "signal_type": typ}).status_code == 200
    client.post("/api/demo/inject-cve", json={"fixture_id": "CVE-2024-21762"})  # + its own labelled demo signal
    assert counts()["threat_signals"] == base["threat_signals"] + 4
    r = client.post("/api/demo/reset").json()
    assert r["deleted_simulated_signals"] == 4 and r["after"] == base
    t = client.get("/api/threats/DEMO-VULN-003").json()
    assert t["cvss"] is None and t["kev_listed"] is False and t["public_exploit"] is None  # fixture values back
    assert client.get("/api/signals", params={"simulated": "true"}).json()["count"] == 0


def test_signals_api(client):
    assert client.get("/api/signals", params={"type": "bogus"}).status_code == 422
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    assert client.get("/api/signals", params={"since": future}).json()["count"] == 0
    summ = client.get("/api/signals/summary").json()
    assert set(summ["last_24h"]) == set(changes.TYPES) and summ["thresholds"]["epss_jump_abs"] == 0.2


# ---------- inject records a signal; seed prepares the demo ----------
def test_inject_records_one_labelled_signal(client, hook_calls):
    client.post("/api/demo/reset")
    r = client.post("/api/demo/inject-cve", json={"fixture_id": "CVE-2024-21762"}).json()
    s = r["signal"]
    assert s["signal_type"] == "new_kev" and s["is_simulated"] and s["details"]["replay"] and s["details"]["simulated"]
    assert hook_calls == [("CVE-2024-21762", "demo_inject")]  # the matcher runs once, not once more for the signal
    # Only demo signals: earlier tests leave REAL signals for this CVE, which a demo reset rightly keeps.
    demo = lambda: [x["signal_id"] for x in client.get("/api/signals", params={"simulated": "true", "limit": 500}).json()["items"]  # noqa: E731
                    if x["threat_id"] == "CVE-2024-21762"]
    assert demo() == [s["signal_id"]]
    again = client.post("/api/demo/inject-cve", json={"fixture_id": "CVE-2024-21762"}).json()["signal"]
    assert again["signal_id"] == s["signal_id"] and again["detected_at"] >= s["detected_at"]  # refreshed, not duplicated
    assert demo() == [s["signal_id"]]


@pytest.mark.parametrize("fid,typ", [("DEMO-VULN-001", "new_critical_cve"), ("DEMO-VULN-002", None), ("DEMO-VULN-003", None)])
def test_inject_signal_type_is_honest(client, fid, typ):
    client.post("/api/demo/reset")
    r = client.post("/api/demo/inject-cve", json={"fixture_id": fid}).json()
    assert (r["signal"] or {}).get("signal_type") == typ
    assert (r["signal_note"] is None) == (typ is not None)  # no honest type -> no invented signal, and it says why


def test_seed_is_idempotent_reseedable_and_creates_no_alerts(client, hook_calls):
    client.post("/api/demo/reset")
    client.post("/api/demo/reset-alerts")
    first = client.post("/api/demo/seed").json()
    assert {(s["threat_id"], s["signal_type"]) for s in first["seeded"]} == {
        ("CVE-2024-4577", "new_kev"), ("CVE-2023-22515", "new_kev"), ("CVE-2024-4577", "new_public_exploit"),
        ("CVE-2023-22515", "new_public_exploit"), ("DEMO-VULN-001", "new_critical_cve")}
    assert all(s["is_simulated"] and s["details"]["replay"] for s in first["seeded"]) and not first["skipped"]
    n = counts()["threat_signals"]
    second = client.post("/api/demo/seed").json()
    assert counts()["threat_signals"] == n
    assert sorted(s["signal_id"] for s in second["seeded"]) == sorted(s["signal_id"] for s in first["seeded"])
    seeded = [x for x in client.get("/api/signals", params={"simulated": "true", "limit": 500}).json()["items"]
              if x["details"].get("purpose") == "seed"]
    assert sorted(x["signal_type"] for x in seeded) == ["new_critical_cve", "new_kev", "new_kev",
                                                       "new_public_exploit", "new_public_exploit"]
    assert hook_calls == [] and client.get("/api/alerts").json()["total"] == 0  # incidents still start clean
    assert client.post("/api/demo/reset").json()["deleted_simulated_signals"] == 5
    assert len(client.post("/api/demo/seed").json()["seeded"]) == 5  # re-seedable after reset


def test_seed_is_demo_mode_only(client, monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    assert client.post("/api/demo/seed").status_code == 403
