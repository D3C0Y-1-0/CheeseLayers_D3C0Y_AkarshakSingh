"""Attack Lab on REAL traffic (data/cache/isc.json from SANS ISC): detection, intel links, correlation."""
import pytest
from fastapi.testclient import TestClient

from app import attack_lab
from app.asset_store import get_asset_store
from app.correlator import CorrelationEngine
from app.database import SessionLocal, init_db
from app.detection import analyze_lines, known_exploit
from app.main import app

client: TestClient


@pytest.fixture(scope="module", autouse=True)
def _app():
    """Full app startup: loads the cached NVD/KEV feed, which the intel links look CVEs up in."""
    global client
    with TestClient(app) as c:
        client = c
        yield


@pytest.fixture(autouse=True)
def clean(monkeypatch, _app):
    monkeypatch.setenv("DEMO_MODE", "true")
    init_db()
    with SessionLocal() as db:
        CorrelationEngine(db).reset()


@pytest.fixture(scope="module")
def attackers():
    r = client.get("/api/attack-lab/attackers")
    assert r.status_code == 200, r.text
    return r.json()


def first(attackers, rule):
    return next(p for p in attackers["items"] if p["rules"] and p["rules"][0] == rule)


def run(ip, **kw):
    r = client.post("/api/attack-lab/run", json={"attacker_ip": ip, **kw})
    assert r.status_code == 200, r.text
    return r.json()


# --- the catalogue is real ISC data ---------------------------------------------------------------------------

def test_catalogue_is_real_attribued_traffic(attackers):
    assert "SANS Internet Storm Center" in attackers["source"] and attackers["web_requests"] > 1000
    assert attackers["items"] and all(p["ip"].count(".") == 3 or ":" in p["ip"] for p in attackers["items"])
    kinds = {p["kind"] for p in attackers["items"]}
    assert {"web", "login", "scan"} <= kinds
    assert any(not p["detected"] for p in attackers["items"])  # real traffic that our rules leave alone (control)


# --- a real exploit attacker, linked to our feed and inventory ------------------------------------------------

def test_real_exploit_attacker_is_linked_to_our_intel(attackers):
    p = first(attackers, "WEB-EXPLOIT-001")
    b = run(p["ip"])
    assert "REAL attack traffic" in b["data_classification"] and b["is_simulated"] is False
    assert b["replayed"] == min(b["total_records"], attack_lab.MAX_REPLAY)
    ex = next(d for d in b["detections"] if d["rule_id"] == "WEB-EXPLOIT-001")
    assert set(ex["indicators"]["cve_ids"]) == set(p["cve_ids"])
    for cve in b["intel"]["cves"]:  # every exploited CVE is looked up in our NVD/KEV feed and matched to the target
        assert cve["in_feed"] and cve["kev_listed"] is True and cve["epss"] is not None
        assert cve["target_match"] in ("confirmed_affected", "needs_verification", "confirmed_unaffected")
    [inc] = b["correlation"]["incidents"]
    assert inc["title"].startswith("Known-CVE exploit attempt") and inc["asset_ids"] == [b["target"]["asset_id"]]
    assert all(l["raw"].startswith(p["ip"]) for l in b["lines"])  # only this attacker's real requests


def test_exploit_against_a_vulnerable_asset_escalates():
    asset = get_asset_store().get("GOV-WEB-01")
    det = analyze_lines([f'198.51.100.9 - - [30/Oct/2026:00:00:00 +0000] "GET /vendor/phpunit/phpunit/src/Util/PHP/'
                         f'eval-stdin.php HTTP/1.1" 404 0 "-" "x"'])["detections"]
    [plain] = attack_lab.to_events("T1", asset, det)
    [vuln] = attack_lab.to_events("T2", asset, det, vulnerable={"CVE-2017-9841"})
    assert plain.details["attack_signal"] == "exploit_attempt"
    assert vuln.details["attack_signal"] == "exploit_on_vulnerable_asset" and "vulnerable to CVE-2017-9841" in \
        vuln.details["detection_reason"]


# --- real network attackers -----------------------------------------------------------------------------------

def test_real_login_hammering(attackers):
    b = run(first(attackers, "NET-LOGIN-001")["ip"])
    d = next(x for x in b["detections"] if x["rule_id"] == "NET-LOGIN-001")
    assert "source gives dates, not times" in d["reason"]  # honest about the missing time of day
    assert b["target"]["asset_id"] == "GOV-VPN-01" and b["correlation"]["incidents"]


def test_real_port_scan(attackers):
    b = run(first(attackers, "NET-SCAN-001")["ip"])
    assert "NET-SCAN-001" in [d["rule_id"] for d in b["detections"]] and b["verdict"]["stage"] == "Reconnaissance"


def test_undetected_real_traffic_creates_nothing(attackers):
    quiet = next(p for p in attackers["items"] if not p["detected"])
    b = run(quiet["ip"])
    assert b["detections"] == [] and b["correlation"]["incidents"] == []
    assert client.get("/api/alerts").json()["total"] == 0


def test_errors(attackers, monkeypatch):
    assert client.post("/api/attack-lab/run", json={"attacker_ip": "203.0.113.1"}).status_code == 404
    ip = attackers["items"][0]["ip"]
    assert client.post("/api/attack-lab/run", json={"attacker_ip": ip, "target_asset_id": "NOPE"}).status_code == 404
    monkeypatch.setenv("DEMO_MODE", "false")
    assert client.post("/api/attack-lab/run", json={"attacker_ip": ip}).status_code == 403
    assert client.post("/api/attack-lab/analyze", json={"lines": ["x"]}).status_code == 200  # read-only: always on


# --- detection rules for what real attackers do --------------------------------------------------------------

@pytest.mark.parametrize("path,cve", [("/lib/phpunit/Util/PHP/eval-stdin.php", "CVE-2017-9841"),
                                      ("/cgi-bin/.%2e/.%2e/.%2e/bin/sh", "CVE-2021-41773"),
                                      ("/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession", "CVE-2018-13379"),
                                      ("/?%ADd+allow_url_include%3d1", "CVE-2024-4577"),
                                      ("/index.php?-d+allow_url_include%3don", "CVE-2012-1823"),
                                      ("/GponForm/diag_Form?images/", "CVE-2018-10562"),
                                      ("/index.html", None)])
def test_known_exploit_paths(path, cve):
    assert (known_exploit(path) or (None,))[0] == cve


def test_recon_threshold():
    line = lambda p: f'198.51.100.7 - - [30/Oct/2026:00:00:00 +0000] "GET {p} HTTP/1.1" 404 0 "-" "x"'  # noqa: E731
    four = [line(p) for p in ("/.env", "/.git/config", "/phpinfo.php", "/wp-login.php")]
    assert analyze_lines(four)["detections"] == []
    [d] = analyze_lines(four + [line("/server-status")])["detections"]
    assert d["rule_id"] == "WEB-RECON-001" and d["stage"] == "recon"


def test_login_hammering_threshold():
    fw = lambda i: (f"2026-10-30T00:00:00+00:00 h kernel: [FW] IN=eth0 SRC=198.51.100.8 DST=10.0.0.5 PROTO=TCP "  # noqa: E731
                    f"SPT={40000 + i} DPT=22 FLAGS=SYN ACTION=DROP")
    assert analyze_lines([fw(i) for i in range(19)])["detections"] == []
    [d] = analyze_lines([fw(i) for i in range(20)])["detections"]
    assert d["rule_id"] == "NET-LOGIN-001" and d["indicators"]["login_ports"] == {22: 20}


# --- paste-your-own-logs analyzer (unchanged behaviour) ------------------------------------------------------

@pytest.mark.parametrize("line,rule", [("/login?user=admin' OR 1=1--", "WEB-SQLI-001"),
                                       ("id=5%20UNION%20SELECT%20password%20FROM%20users", "WEB-SQLI-001"),
                                       ("host=127.0.0.1;cat /etc/passwd", "WEB-CMDI-001"),
                                       ("file=../../../../etc/shadow", "WEB-TRAV-001"),
                                       ('comment=<script>alert(1)</script>', "WEB-XSS-001")])
def test_pasted_payloads_are_recognised(line, rule):
    b = client.post("/api/attack-lab/analyze", json={"lines": [line]}).json()
    assert [d["rule_id"] for d in b["detections"]] == [rule]
    m = b["lines"][0]["matches"][0]
    assert b["lines"][0]["decoded"][m["start"]:m["end"]] == m["text"]


@pytest.mark.parametrize("line", ["search?q=O'Neil Road", "name=Rock and Roll", "/report?from=2026-10-01&to=2026-10-31"])
def test_ordinary_input_is_not_flagged(line):
    assert client.post("/api/attack-lab/analyze", json={"lines": [line]}).json()["detections"] == []


def test_timed_brute_force_window():
    fail = lambda s: f"2026-10-31T10:00:{s:02d}+05:30 vpn sshd[1]: Failed password for admin from 203.0.113.5 port 1 ssh2"  # noqa: E731
    assert analyze_lines([fail(s) for s in range(9)])["detections"] == []
    [d] = analyze_lines([fail(s) for s in range(10)])["detections"]
    assert d["rule_id"] == "AUTH-BF-001" and "within 9s" in d["reason"]


def test_input_limits():
    assert client.post("/api/attack-lab/analyze", json={"lines": ["x" * 4097]}).status_code == 422
    assert client.post("/api/attack-lab/analyze", json={"lines": ["x"] * 501}).status_code == 422


def test_rulebook_lists_real_world_rules():
    rules = client.get("/api/attack-lab/rules").json()
    ids = {r["rule_id"] for r in rules["rules"]}
    assert {"WEB-EXPLOIT-001", "WEB-RECON-001", "NET-LOGIN-001", "NET-SCAN-001"} <= ids
    assert {e["cve_id"] for e in rules["known_exploits"]} >= {"CVE-2017-9841", "CVE-2021-41773"}
