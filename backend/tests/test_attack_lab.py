import pytest
from fastapi.testclient import TestClient

from app.correlator import CorrelationEngine
from app.database import SessionLocal, init_db
from app.detection import analyze_lines
from app.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    init_db()
    with SessionLocal() as db:
        CorrelationEngine(db).reset()


def run(scenario, **kw):
    r = client.post("/api/attack-lab/run", json={"scenario": scenario, **kw})
    assert r.status_code == 200, r.text
    return r.json()


def fired(body):
    return [d["rule_id"] for d in body["detections"]]


# --- each simulated attack is recognised from the log text, and the right incident comes out ---------

@pytest.mark.parametrize("scenario,succeed,rules,attack,stage,priority", [
    ("brute_force", True, ["AUTH-BF-001", "AUTH-BF-002"], "Brute-force login", "Compromise likely", "critical"),
    ("brute_force", False, ["AUTH-BF-001"], "Brute-force login", "Attack attempt", "medium"),
    ("sql_injection", True, ["WEB-SQLI-001", "WEB-SQLI-002"], "SQL injection", "Compromise likely", "critical"),
    ("sql_injection", False, ["WEB-SQLI-001"], "SQL injection", "Attack attempt", "high"),
    ("port_scan", True, ["NET-SCAN-001"], "Port scan", "Reconnaissance", "medium"),
    ("command_injection", True, ["WEB-CMDI-001", "HOST-PROC-001", "NET-C2-001"], "Command injection", "Compromise likely", "critical"),
    ("command_injection", False, ["WEB-CMDI-001"], "Command injection", "Attack attempt", "high"),
])
def test_attack_is_detected_classified_and_correlated(scenario, succeed, rules, attack, stage, priority):
    b = run(scenario, succeed=succeed)
    assert fired(b) == rules
    v = b["verdict"]
    assert v["attack_detected"] and v["headline"].startswith(attack) and v["stage"] == stage
    assert v["mitre"] and all(m["url"].startswith("https://attack.mitre.org/") for m in v["mitre"])
    [inc] = b["correlation"]["incidents"]
    assert inc["priority"] == priority and inc["kind"] == "behaviour" and inc["is_simulated"]
    assert inc["title"].startswith(attack) and inc["asset_ids"] == [b["target"]["asset_id"]]
    assert [c["rule_id"] for c in inc["attack_classification"]] == rules
    assert inc["evidence_ids"] == [e["event_id"] for e in b["events_sent"]]
    assert b["correlation"]["created"] == [inc["alert_id"]]


def test_normal_traffic_is_not_flagged():
    b = run("normal_traffic")
    assert b["detections"] == [] and b["events_sent"] == [] and b["correlation"]["incidents"] == []
    assert not b["verdict"]["attack_detected"]
    assert any("AUTH-BF-001" in p for p in b["verdict"]["decision_path"])  # says how close it came
    assert client.get("/api/alerts").json()["total"] == 0


def test_the_detector_is_never_told_the_answer():
    # Same lines through the stateless analyzer give the same verdict: detection works on text alone.
    b = run("sql_injection")
    again = analyze_lines([l["raw"] for l in b["lines"]])
    assert [d["rule_id"] for d in again["detections"]] == fired(b)
    assert again["verdict"]["headline"] == b["verdict"]["headline"]


def test_steps_cover_every_line_and_flag_only_attacker_lines():
    b = run("sql_injection")
    assert sorted(n for s in b["steps"] for n in s["line_nos"]) == [l["line_no"] for l in b["lines"]]
    flagged = {l["line_no"] for l in b["lines"] if l["flagged_by"]}
    customer = next(s for s in b["steps"] if s["actor"] == "customers")
    assert not flagged & set(customer["line_nos"])  # O'Neil search is not SQL injection
    assert all(l["raw"].startswith("203.0.113.77") for l in b["lines"] if l["flagged_by"])


def test_rerun_on_same_asset_joins_the_open_incident():
    first = run("port_scan")
    second = run("port_scan")
    assert second["correlation"]["created"] == [] and second["correlation"]["updated"]
    assert "existing incident" in second["correlation"]["note"]
    assert second["correlation"]["incidents"][0]["alert_id"] == first["correlation"]["incidents"][0]["alert_id"]


def test_custom_target_and_errors(monkeypatch):
    assert run("brute_force", target_asset_id="PWR-JUMP-01")["target"]["hostname"] == "ot-jumphost-01"
    assert client.post("/api/attack-lab/run", json={"scenario": "brute_force", "target_asset_id": "NOPE"}).status_code == 404
    assert client.post("/api/attack-lab/run", json={"scenario": "ddos"}).status_code == 422
    monkeypatch.setenv("DEMO_MODE", "false")
    assert client.post("/api/attack-lab/run", json={"scenario": "port_scan"}).status_code == 403
    assert client.post("/api/attack-lab/analyze", json={"lines": ["x"]}).status_code == 200  # read-only: always on


# --- paste-your-own-logs analyzer --------------------------------------------------------------------

@pytest.mark.parametrize("line,rule,technique", [
    ("/login?user=admin' OR 1=1--", "WEB-SQLI-001", "Always-true condition (' OR '1'='1)"),
    ("id=5%20UNION%20SELECT%20password%20FROM%20users", "WEB-SQLI-001", "UNION SELECT (pulls rows from other tables)"),
    ("q=1';DROP TABLE users", "WEB-SQLI-001", "Stacked query (; DROP / INSERT ...)"),
    ("host=127.0.0.1;cat /etc/passwd", "WEB-CMDI-001", "Shell command chained onto a parameter"),
    ("file=../../../../etc/shadow", "WEB-TRAV-001", "Directory traversal (../)"),
    ('comment=<script>alert(1)</script>', "WEB-XSS-001", "Script injected into a page"),
])
def test_pasted_payloads_are_recognised(line, rule, technique):
    b = client.post("/api/attack-lab/analyze", json={"lines": [line]}).json()
    [d] = b["detections"]
    assert d["rule_id"] == rule and technique in d["techniques"]
    m = b["lines"][0]["matches"][0]
    assert b["lines"][0]["decoded"][m["start"]:m["end"]] == m["text"]  # highlight offsets are usable


@pytest.mark.parametrize("line", ["search?q=O'Neil Road", "name=Rock and Roll", "SELECT your plan below",
                                  "/report?from=2026-10-01&to=2026-10-31"])
def test_ordinary_input_is_not_flagged(line):
    assert client.post("/api/attack-lab/analyze", json={"lines": [line]}).json()["detections"] == []


def test_brute_force_needs_the_threshold_inside_the_window():
    def fail(sec, ip="203.0.113.5"):
        return f"2026-10-31T10:00:{sec:02d}+05:30 vpn sshd[1]: Failed password for admin from {ip} port 1 ssh2"
    assert analyze_lines([fail(s) for s in range(9)])["detections"] == []  # 9 < 10
    assert [d["rule_id"] for d in analyze_lines([fail(s) for s in range(10)])["detections"]] == ["AUTH-BF-001"]
    spread = [f"2026-10-31T10:{m:02d}:00+05:30 vpn sshd[1]: Failed password for admin from 203.0.113.5 port 1 ssh2"
              for m in range(0, 20, 2)]  # 10 failures but one every 2 minutes
    assert analyze_lines(spread)["detections"] == []
    sprayed = [f"2026-10-31T10:00:{s:02d}+05:30 vpn sshd[1]: Failed password for invalid user u{s} from 203.0.113.5 port 1 ssh2"
               for s in range(12)]
    [d] = analyze_lines(sprayed)["detections"]
    assert d["attack_type"] == "password_spraying" and d["mitre"][0]["id"] == "T1110.003"


def test_rulebook_and_playbooks_are_published():
    rules = client.get("/api/attack-lab/rules").json()
    assert {r["rule_id"] for r in rules["rules"]} >= {"AUTH-BF-001", "NET-SCAN-001", "WEB-SQLI-001", "WEB-CMDI-001"}
    assert all(r["logic"] and r["why_it_works"] and r["mitre"] for r in rules["rules"])
    assert rules["thresholds"]["brute_force_failures"] == 10
    pbs = {p["scenario"]: p for p in client.get("/api/attack-lab/playbooks").json()}
    assert set(pbs) == {"brute_force", "sql_injection", "port_scan", "command_injection", "normal_traffic"}
