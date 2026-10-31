"""Attack detection from raw log lines: parse -> per-line signatures -> per-source thresholds -> verdict.

The detector only ever sees log TEXT. It is never told which attack was simulated, so the Attack Lab is an honest
test of the rules: what it reports is what these rules would report on the same lines from a real server.

Two kinds of rules, both listed in RULES with their exact logic so the dashboard can show them:
  signature rules  one request is enough (e.g. `UNION SELECT` inside a URL parameter)
  threshold rules  a pattern across many lines from one source in a time window (e.g. 10+ failed logins in 60s)
"""
import re
import statistics
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from ipaddress import ip_address
from urllib.parse import unquote_plus

from .scoring import SHELLS, SUSPICIOUS_PORTS, WEB_PARENTS

CONFIG = {
    "window_seconds": 60,
    "brute_force_failures": 10,  # failed logins from one source inside the window
    "spraying_distinct_users": 5,  # ...spread over this many usernames = password spraying, not guessing
    "compromise_min_failures": 5,  # a success after this many failures = the guess probably worked
    "port_scan_distinct_ports": 15,  # distinct destination ports from one source inside the window
    "exfil_min_bytes": 10000,  # an injected request returning this much (and 5x the normal page) = data came back
    "exfil_vs_median": 5,
}

MITRE = {
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1213": ("Data from Information Repositories", "Collection"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1095": ("Non-Application Layer Protocol (reverse shell)", "Command and Control"),
    "T1189": ("Drive-by Compromise (XSS)", "Initial Access"),
}


def mitre(tid: str) -> dict:
    name, tactic = MITRE[tid]
    return {"id": tid, "name": name, "tactic": tactic, "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}


# --- 1. parsing ----------------------------------------------------------------------------------------

WEB_LINE = re.compile(r'^(?P<src>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
                      r'(?P<status>\d{3}) (?P<bytes>\d+|-)(?: "[^"]*" "(?P<ua>[^"]*)")?')
SYSLOG_LINE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\dT\S+) (?P<host>\S+) (?P<prog>[\w./-]+?)(?:\[\d+\])?: (?P<msg>.*)$")
AUTH_FAIL = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src>\S+)")
AUTH_OK = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<src>\S+)")
FIREWALL = re.compile(r"SRC=(?P<src>\S+) DST=(?P<dst>\S+).*?DPT=(?P<dpt>\d+)(?:.*?ACTION=(?P<action>\w+))?")
PROCESS = re.compile(r'parent=(?P<parent>\S+).*?exe=(?P<exe>\S+)(?: cmd="(?P<cmd>.*)")?')
CONNECTION = re.compile(r"src=(?P<src>\S+) .*?dst=(?P<dst>\S+) dport=(?P<dport>\d+).*?dir=(?P<dir>\w+)")
ATTACK_TOOLS = re.compile(r"sqlmap|nikto|nmap|masscan|hydra|gobuster|dirbuster|wpscan|zgrab|nuclei", re.I)


@dataclass
class LogRecord:
    line_no: int
    raw: str
    source: str  # web | auth | firewall | process | network | unknown
    at: datetime | None
    src_ip: str | None = None
    fields: dict = field(default_factory=dict)


def _ts(text: str) -> datetime | None:
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", None):
        try:
            return datetime.strptime(text, fmt) if fmt else datetime.fromisoformat(text)
        except ValueError:
            continue
    return None


def parse_line(line_no: int, raw: str) -> LogRecord:
    raw = raw.rstrip("\r\n")
    if m := WEB_LINE.match(raw):
        decoded = unquote_plus(unquote_plus(m["path"]))  # attackers often double-encode to slip past filters
        return LogRecord(line_no, raw, "web", _ts(m["ts"]), m["src"], {
            "method": m["method"], "path": m["path"], "decoded": decoded, "status": int(m["status"]),
            "bytes": int(m["bytes"]) if m["bytes"].isdigit() else 0, "user_agent": m["ua"] or ""})
    if m := SYSLOG_LINE.match(raw):
        at, msg = _ts(m["ts"]), m["msg"]
        if a := AUTH_FAIL.search(msg):
            return LogRecord(line_no, raw, "auth", at, a["src"], {"result": "failure", "user": a["user"], "host": m["host"]})
        if a := AUTH_OK.search(msg):
            return LogRecord(line_no, raw, "auth", at, a["src"], {"result": "success", "user": a["user"], "host": m["host"]})
        if f := FIREWALL.search(msg):
            return LogRecord(line_no, raw, "firewall", at, f["src"], {"dst": f["dst"], "dpt": int(f["dpt"]),
                                                                        "action": (f["action"] or "").upper()})
        if p := PROCESS.search(msg):
            return LogRecord(line_no, raw, "process", at, None, {"parent": p["parent"], "exe": p["exe"],
                                                                  "cmd": p["cmd"] or "", "host": m["host"]})
        if c := CONNECTION.search(msg):
            return LogRecord(line_no, raw, "network", at, c["src"], {"dst": c["dst"], "dport": int(c["dport"]),
                                                                      "direction": c["dir"], "host": m["host"]})
    # Not a log format we know: still check it as raw request/input text (e.g. a pasted payload or URL).
    return LogRecord(line_no, raw, "raw", None, None, {"decoded": unquote_plus(unquote_plus(raw)), "status": 0,
                                                       "bytes": 0, "user_agent": ""})


# --- 2. per-line signatures ----------------------------------------------------------------------------

@dataclass(frozen=True)
class Signature:
    sig_id: str
    family: str  # sql_injection | command_injection | path_traversal | xss
    technique: str  # plain-English name shown to the analyst
    pattern: re.Pattern
    strong: bool = True  # weak signatures alone only give low confidence


def _sig(sig_id, family, technique, pattern, strong=True):
    return Signature(sig_id, family, technique, re.compile(pattern, re.I), strong)


SIGNATURES = [
    _sig("SQLI-TAUT", "sql_injection", "Always-true condition (' OR '1'='1)",
         r"'\s*(?:or|\|\|)\s+'?[\w]+'?\s*=\s*'?[\w]+|\bor\s+1\s*=\s*1\b"),
    _sig("SQLI-UNION", "sql_injection", "UNION SELECT (pulls rows from other tables)", r"\bunion\b(?:\s+all)?\s+select\b"),
    _sig("SQLI-TIME", "sql_injection", "Time-delay probe (blind SQLi)",
         r"\b(?:sleep|pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\b"),
    _sig("SQLI-SCHEMA", "sql_injection", "Database schema enumeration", r"information_schema|pg_catalog|sysobjects|sqlite_master"),
    _sig("SQLI-STACK", "sql_injection", "Stacked query (; DROP / INSERT ...)", r";\s*(?:drop|insert|update|delete|exec|shutdown)\b"),
    _sig("SQLI-COMMENT", "sql_injection", "Quote closed then rest of query commented out", r"'\s*(?:--|#|/\*)", strong=False),
    _sig("CMDI-CHAIN", "command_injection", "Shell command chained onto a parameter",
         r"(?:;|\|\||&&|\||`|\$\()\s*(?:bash|sh|nc|ncat|curl|wget|cat|id|whoami|uname|powershell|cmd)\b"),
    _sig("CMDI-REVSHELL", "command_injection", "Reverse-shell payload", r"/dev/tcp/|\bbash\s+-i\b|\bnc\b[^&;|]*\s-e\s"),
    _sig("TRAV-DOTDOT", "path_traversal", "Directory traversal (../)", r"\.\./|\.\.\\"),
    _sig("XSS-TAG", "xss", "Script injected into a page", r"<\s*script|\bon(?:error|load)\s*=|javascript:"),
]


def signature_hits(text: str) -> list[dict]:
    hits = []
    for s in SIGNATURES:
        if m := s.pattern.search(text):
            hits.append({"signature": s.sig_id, "family": s.family, "technique": s.technique, "strong": s.strong,
                         "start": m.start(), "end": m.end(), "text": m.group(0)})
    return hits


# --- 3. rules ------------------------------------------------------------------------------------------

RULES = [
    {"rule_id": "AUTH-BF-001", "name": "Brute-force login", "log_source": "auth (sshd / VPN)", "kind": "threshold",
     "signal": "brute_force", "mitre": ["T1110.001", "T1110.003"],
     "logic": f"{CONFIG['brute_force_failures']}+ failed logins from ONE source IP within {CONFIG['window_seconds']}s. "
              f"Spread over {CONFIG['spraying_distinct_users']}+ usernames = password spraying, otherwise password guessing.",
     "why_it_works": "A person mistypes a password 1-3 times. Hundreds of guesses a minute is a tool, not a person."},
    {"rule_id": "AUTH-BF-002", "name": "Login succeeded after brute force", "log_source": "auth (sshd / VPN)",
     "kind": "sequence", "signal": "credential_compromise", "mitre": ["T1078"],
     "logic": f"A successful login from a source that had {CONFIG['compromise_min_failures']}+ failures just before it.",
     "why_it_works": "The guessing stopped because one guess worked: the attacker now holds a valid account."},
    {"rule_id": "NET-SCAN-001", "name": "Port scan", "log_source": "firewall", "kind": "threshold",
     "signal": "port_scan", "mitre": ["T1046"],
     "logic": f"One source touches {CONFIG['port_scan_distinct_ports']}+ different destination ports within "
              f"{CONFIG['window_seconds']}s.",
     "why_it_works": "Real clients connect to the one service they need. Knocking on many ports is mapping what is open."},
    {"rule_id": "WEB-SQLI-001", "name": "SQL injection attempt", "log_source": "web access log", "kind": "signature",
     "signal": "sql_injection", "mitre": ["T1190"],
     "logic": "URL-decoded request matches a SQL injection signature: " +
              "; ".join(s.technique for s in SIGNATURES if s.family == "sql_injection") + ".",
     "why_it_works": "Normal input is data (a name, an account number). SQL keywords and quote tricks inside a "
                     "parameter are an attempt to change the database query itself."},
    {"rule_id": "WEB-SQLI-002", "name": "Injected query returned data", "log_source": "web access log",
     "kind": "sequence", "signal": "data_exposure", "mitre": ["T1213"],
     "logic": f"A request that matched WEB-SQLI-001 got HTTP 200 and returned {CONFIG['exfil_min_bytes']}+ bytes and "
              f"{CONFIG['exfil_vs_median']}x the source's normal page size.",
     "why_it_works": "Blocked injections get errors or 403s. A large successful response means rows came back."},
    {"rule_id": "WEB-CMDI-001", "name": "Command injection attempt", "log_source": "web access log", "kind": "signature",
     "signal": "command_injection", "mitre": ["T1190"],
     "logic": "URL-decoded request chains a shell command (; | && $( ) or carries a reverse-shell payload.",
     "why_it_works": "A field like `host=8.8.8.8` never needs `;bash` after it; that is an attempt to run commands."},
    {"rule_id": "WEB-TRAV-001", "name": "Path traversal attempt", "log_source": "web access log", "kind": "signature",
     "signal": "http_anomaly", "mitre": ["T1190"], "logic": "Request path contains ../ sequences (after URL decoding).",
     "why_it_works": "Climbing out of the web root is how attackers read files like /etc/passwd."},
    {"rule_id": "WEB-XSS-001", "name": "Cross-site scripting attempt", "log_source": "web access log",
     "kind": "signature", "signal": "http_anomaly", "mitre": ["T1189"],
     "logic": "Request carries <script>, an inline event handler (onerror=) or a javascript: URL.",
     "why_it_works": "Script tags in input are meant to run in another user's browser."},
    {"rule_id": "HOST-PROC-001", "name": "Web server spawned a shell", "log_source": "host process audit",
     "kind": "signature", "signal": "unexpected_process", "mitre": ["T1059.004"],
     "logic": "Parent process is a web server / app runtime and the child is a shell (sh, bash, cmd, powershell).",
     "why_it_works": "Web servers serve pages; they do not open shells unless someone injected a command."},
    {"rule_id": "NET-C2-001", "name": "Suspicious outbound connection", "log_source": "connection tracking",
     "kind": "signature", "signal": "outbound_connection", "mitre": ["T1095"],
     "logic": f"Server opens an outbound connection to a reverse-shell port ({', '.join(map(str, sorted(SUSPICIOUS_PORTS)))}) "
              "or to an IP address that appeared inside an injected command.",
     "why_it_works": "Servers answer connections; one dialling out to an attacker-named address is a remote shell."},
]
RULE_BY_ID = {r["rule_id"]: r for r in RULES}

LABELS = {"brute_force": "Brute-force login", "password_spraying": "Password spraying",
          "credential_compromise": "Account compromised by brute force", "port_scan": "Port scan",
          "sql_injection": "SQL injection", "data_exposure": "SQL injection: data extracted",
          "command_injection": "Command injection", "reverse_shell": "Reverse shell",
          "path_traversal": "Path traversal", "xss": "Cross-site scripting"}
STAGES = {"recon": "Reconnaissance", "attempt": "Attack attempt", "success": "Compromise likely"}


@dataclass
class Detection:
    rule_id: str
    name: str
    attack_type: str
    label: str
    signal: str  # behaviour signal name the scoring engine understands
    mitre: list[dict]
    stage: str  # recon | attempt | success
    confidence: str  # low | medium | high
    src_ip: str | None
    target: str | None
    first_seen: str | None
    last_seen: str | None
    count: int
    reason: str
    evidence: list[dict]  # [{line_no, raw, matches:[{start,end,text,technique}]}]
    techniques: list[str] = field(default_factory=list)
    indicators: dict = field(default_factory=dict)


def _evidence(records: list[LogRecord], matches: dict[int, list[dict]] | None = None, limit: int = 8) -> list[dict]:
    out = []
    for r in records[:limit]:
        out.append({"line_no": r.line_no, "raw": r.raw, "decoded": r.fields.get("decoded"),
                    "matches": (matches or {}).get(r.line_no, [])})  # match offsets refer to `decoded`
    return out


def _iso(r: LogRecord) -> str | None:
    return r.at.isoformat() if r.at else None


def _densest_window(records: list[LogRecord], key) -> tuple[list[LogRecord], int]:
    """Largest set of records inside any `window_seconds` window, scored by len(set(key(r))). Untimed = one window."""
    if not records:
        return [], 0
    if any(r.at is None for r in records):
        return records, len({key(r) for r in records})
    rs = sorted(records, key=lambda r: r.at)
    best, best_n, j = rs[:1], 1, 0
    for i in range(len(rs)):
        while (rs[i].at - rs[j].at).total_seconds() > CONFIG["window_seconds"]:
            j += 1
        n = len({key(r) for r in rs[j:i + 1]})
        if n > best_n:
            best, best_n = rs[j:i + 1], n
    return best, best_n


def _is_public(ip: str | None) -> bool:
    try:
        return ip is not None and ip_address(ip).is_global
    except ValueError:
        return False


def detect(records: list[LogRecord]) -> tuple[list[Detection], list[dict]]:
    """Run every rule. Returns (detections, checks): checks records what each rule saw even when it did NOT fire."""
    detections: list[Detection] = []
    checks: list[dict] = []
    by_src: dict[str | None, list[LogRecord]] = defaultdict(list)  # None = raw text with no source address
    for r in records:
        if r.src_ip or r.source == "raw":
            by_src[r.src_ip].append(r)

    # Brute force and compromise (auth logs)
    worst_failures = (None, 0)
    for src, rs in by_src.items():
        fails = [r for r in rs if r.source == "auth" and r.fields["result"] == "failure"]
        window, n = _densest_window(fails, key=lambda r: r.line_no)
        if n > worst_failures[1]:
            worst_failures = (src, n)
        if n >= CONFIG["brute_force_failures"]:
            users = sorted({r.fields["user"] for r in fails})
            spraying = len(users) >= CONFIG["spraying_distinct_users"]
            kind = "password_spraying" if spraying else "brute_force"
            detections.append(Detection(
                "AUTH-BF-001", RULE_BY_ID["AUTH-BF-001"]["name"], kind, LABELS[kind], "brute_force",
                [mitre("T1110.003" if spraying else "T1110.001")], "attempt", "high" if n >= 3 * CONFIG["brute_force_failures"] else "medium",
                src, window[0].fields.get("host"), _iso(window[0]), _iso(window[-1]), len(fails),
                f"{n} failed logins from {src} within {CONFIG['window_seconds']}s (threshold {CONFIG['brute_force_failures']}) "
                f"against {len(users)} username(s): {', '.join(users[:6])}" + ("" if len(users) <= 6 else ", ..."),
                _evidence(window), indicators={"src_ips": [src], "usernames": users}))
        oks = [r for r in rs if r.source == "auth" and r.fields["result"] == "success"]
        for ok in oks:
            before = [f for f in fails if f.line_no < ok.line_no]
            if len(before) >= CONFIG["compromise_min_failures"]:
                detections.append(Detection(
                    "AUTH-BF-002", RULE_BY_ID["AUTH-BF-002"]["name"], "credential_compromise",
                    LABELS["credential_compromise"], "credential_compromise", [mitre("T1078")], "success", "high",
                    src, ok.fields.get("host"), _iso(ok), _iso(ok), 1,
                    f"login as '{ok.fields['user']}' SUCCEEDED from {src} right after {len(before)} failed attempts",
                    _evidence([ok]), indicators={"src_ips": [src], "usernames": [ok.fields["user"]]}))
                break
    checks.append({"rule_id": "AUTH-BF-001", "fired": any(d.rule_id == "AUTH-BF-001" for d in detections),
                   "observed": f"most failed logins from one source in {CONFIG['window_seconds']}s: {worst_failures[1]}"
                               + (f" ({worst_failures[0]})" if worst_failures[0] else ""),
                   "threshold": f">= {CONFIG['brute_force_failures']}"})

    # Port scan (firewall logs)
    worst_ports = (None, 0)
    for src, rs in by_src.items():
        fw = [r for r in rs if r.source == "firewall"]
        window, n = _densest_window(fw, key=lambda r: (r.fields["dst"], r.fields["dpt"]))
        if n > worst_ports[1]:
            worst_ports = (src, n)
        if n >= CONFIG["port_scan_distinct_ports"]:
            ports = sorted({r.fields["dpt"] for r in window})
            open_ports = sorted({r.fields["dpt"] for r in window if r.fields["action"] in ("ACCEPT", "ALLOW")})
            secs = (window[-1].at - window[0].at).total_seconds() if window[0].at and window[-1].at else None
            detections.append(Detection(
                "NET-SCAN-001", RULE_BY_ID["NET-SCAN-001"]["name"], "port_scan", LABELS["port_scan"], "port_scan",
                [mitre("T1046")], "recon", "high" if n >= 25 else "medium", src, window[0].fields["dst"],
                _iso(window[0]), _iso(window[-1]), len(fw),
                f"{src} probed {n} different ports" + (f" in {secs:.0f}s" if secs is not None else "") +
                f" (threshold {CONFIG['port_scan_distinct_ports']}); open: {', '.join(map(str, open_ports)) or 'none'}",
                _evidence(window), indicators={"src_ips": [src], "ports_probed": ports, "open_ports": open_ports}))
    checks.append({"rule_id": "NET-SCAN-001", "fired": any(d.rule_id == "NET-SCAN-001" for d in detections),
                   "observed": f"most distinct ports from one source in {CONFIG['window_seconds']}s: {worst_ports[1]}"
                               + (f" ({worst_ports[0]})" if worst_ports[0] else ""),
                   "threshold": f">= {CONFIG['port_scan_distinct_ports']}"})

    # Web signatures, grouped per source IP and attack family
    injected_ips: set[str] = set()
    web_rules = {"sql_injection": "WEB-SQLI-001", "command_injection": "WEB-CMDI-001",
                 "path_traversal": "WEB-TRAV-001", "xss": "WEB-XSS-001"}
    seen_web = 0
    for src, rs in by_src.items():
        web = [r for r in rs if r.source in ("web", "raw")]
        seen_web += len(web)
        who = src or "pasted input"
        hits = {r.line_no: signature_hits(r.fields["decoded"]) for r in web}
        tool = next((r.fields["user_agent"] for r in web if ATTACK_TOOLS.search(r.fields["user_agent"])), None)
        for family, rule_id in web_rules.items():
            matched = [r for r in web if any(h["family"] == family for h in hits[r.line_no])]
            if not matched:
                continue
            fam_hits = {r.line_no: [h for h in hits[r.line_no] if h["family"] == family] for r in matched}
            techniques = sorted({h["technique"] for hs in fam_hits.values() for h in hs})
            strong = any(h["strong"] for hs in fam_hits.values() for h in hs)
            confidence = "high" if (len(techniques) >= 2 or tool) and strong else "medium" if strong else "low"
            if family == "command_injection":  # only addresses AFTER the injection point (not the innocent ping target)
                for r in matched:
                    tail = r.fields["decoded"][min(h["start"] for h in fam_hits[r.line_no]):]
                    injected_ips.update(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", tail))
            blocked = sum(r.fields["status"] in (401, 403, 406, 429) for r in matched)
            why = (f"{len(matched)} request(s) from {who} matched {len(techniques)} {LABELS[family]} technique(s): "
                   f"{'; '.join(techniques)}")
            if tool:
                why += f". User-Agent identifies an attack tool: {tool[:60]}"
            if blocked:
                why += f". {blocked} of them were blocked (HTTP 4xx)"
            rule = RULE_BY_ID[rule_id]
            detections.append(Detection(
                rule_id, rule["name"], family, LABELS[family], rule["signal"], [mitre(t) for t in rule["mitre"]],
                "attempt", confidence, src, None, _iso(matched[0]), _iso(matched[-1]), len(matched), why,
                _evidence(matched, fam_hits), techniques, {"src_ips": [src] if src else [], "attack_tool": tool}))

            if family == "sql_injection":  # did any injection actually return data?
                normal = [r.fields["bytes"] for r in web if r.line_no not in fam_hits and r.fields["status"] == 200]
                base = statistics.median(normal) if normal else 0
                big = [r for r in matched if r.fields["status"] == 200 and r.fields["bytes"] >= CONFIG["exfil_min_bytes"]
                       and r.fields["bytes"] >= CONFIG["exfil_vs_median"] * max(base, 1)]
                if big:
                    top = max(big, key=lambda r: r.fields["bytes"])
                    detections.append(Detection(
                        "WEB-SQLI-002", RULE_BY_ID["WEB-SQLI-002"]["name"], "data_exposure", LABELS["data_exposure"],
                        "data_exposure", [mitre("T1213")], "success", "high", src, None, _iso(big[0]), _iso(big[-1]),
                        len(big), f"{len(big)} injected request(s) returned HTTP 200 with up to {top.fields['bytes']:,} bytes "
                                  f"vs a normal page of ~{base:,.0f} bytes: rows were very likely returned to the attacker",
                        _evidence(big, fam_hits), indicators={"src_ips": [src]}))
    for family, rule_id in web_rules.items():
        checks.append({"rule_id": rule_id, "fired": any(d.rule_id == rule_id for d in detections),
                       "observed": f"{seen_web} web request(s) checked against {sum(s.family == family for s in SIGNATURES)} "
                                   f"{LABELS[family]} signature(s)", "threshold": "any strong signature match"})

    # Host: web server -> shell
    procs = [r for r in records if r.source == "process"]
    shells = [r for r in procs if WEB_PARENTS.match(r.fields["parent"].rsplit("/", 1)[-1])
              and r.fields["exe"].replace("\\", "/").rsplit("/", 1)[-1].lower() in SHELLS]
    if shells:
        r = shells[0]
        detections.append(Detection(
            "HOST-PROC-001", RULE_BY_ID["HOST-PROC-001"]["name"], "command_injection", "Web server spawned a shell",
            "unexpected_process", [mitre("T1059.004")], "success", "high", None, r.fields["host"], _iso(r), _iso(shells[-1]),
            len(shells), f"web server process '{r.fields['parent']}' started '{r.fields['exe']}'"
                         + (f" running: {r.fields['cmd'][:120]}" if r.fields["cmd"] else ""), _evidence(shells)))
    checks.append({"rule_id": "HOST-PROC-001", "fired": bool(shells), "observed": f"{len(procs)} process start(s) checked",
                   "threshold": "web server parent -> shell child"})

    # Network: outbound to a reverse-shell port or to an IP named in an injected command
    conns = [r for r in records if r.source == "network" and r.fields["direction"] == "outbound"]
    bad = [r for r in conns if r.fields["dport"] in SUSPICIOUS_PORTS or r.fields["dst"] in injected_ips]
    for r in bad[:3]:
        why = [f"port {r.fields['dport']} is a common reverse-shell port"] if r.fields["dport"] in SUSPICIOUS_PORTS else []
        if r.fields["dst"] in injected_ips:
            why.append(f"{r.fields['dst']} is the address written inside the injected command")
        detections.append(Detection(
            "NET-C2-001", RULE_BY_ID["NET-C2-001"]["name"], "reverse_shell", LABELS["reverse_shell"],
            "outbound_connection", [mitre("T1095")], "success", "high" if r.fields["dst"] in injected_ips else "medium",
            r.src_ip, r.fields["host"], _iso(r), _iso(r), 1,
            f"server {r.src_ip} connected OUT to {r.fields['dst']}:{r.fields['dport']}: " + "; ".join(why),
            _evidence([r]), indicators={"dest_ip": r.fields["dst"], "dest_port": r.fields["dport"],
                                        "external": _is_public(r.fields["dst"])}))
    checks.append({"rule_id": "NET-C2-001", "fired": bool(bad), "observed": f"{len(conns)} outbound connection(s) checked",
                   "threshold": "reverse-shell port or attacker-named IP"})
    return detections, checks


# --- 4. verdict ----------------------------------------------------------------------------------------

_STAGE_RANK = {"recon": 0, "attempt": 1, "success": 2}
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}


def classify(detections: list[Detection], checks: list[dict], lines_total: int) -> dict:
    """One plain-English answer to 'what kind of attack is this?', with the decision path that led to it."""
    if not detections:
        return {"attack_detected": False, "headline": "No attack detected", "attack_types": [], "stage": None,
                "confidence": None, "mitre": [], "attacker_ips": [],
                "decision_path": [f"{lines_total} log line(s) checked against {len(RULES)} rules; none fired."] +
                                 [f"{c['rule_id']}: {c['observed']} (needs {c['threshold']})" for c in checks
                                  if "threshold" in c and c["threshold"].startswith(">=")]}
    stage = max(detections, key=lambda d: _STAGE_RANK[d.stage]).stage
    confidence = max(detections, key=lambda d: _CONF_RANK[d.confidence]).confidence
    types = list(dict.fromkeys(d.attack_type for d in sorted(detections, key=lambda d: -_STAGE_RANK[d.stage])))
    # Headline = how they got in (or tried to): the most advanced non-result rule, e.g. "SQL injection", not "data extracted".
    entry = [d for d in detections if d.stage != "success"] or detections
    headline = max(entry, key=lambda d: _STAGE_RANK[d.stage]).label
    outcome = {"recon": "reconnaissance only, nothing was exploited",
               "attempt": "attempted; no sign it succeeded",
               "success": "evidence it SUCCEEDED"}[stage]
    seen, mitre_list = set(), []
    for d in detections:
        for m in d.mitre:
            if m["id"] not in seen:
                seen.add(m["id"])
                mitre_list.append(m)
    path = [f"{d.rule_id} fired -> {d.label}: {d.reason}" for d in detections]
    path.append(f"Stage = {STAGES[stage]} because " + {
        "recon": "the attacker only looked for open services.",
        "attempt": "attack traffic was seen but no rule saw it succeed (no login, no data, no shell).",
        "success": "a follow-up rule saw the result: " + ", ".join(d.label for d in detections if d.stage == "success") + "."}[stage])
    path.append(f"Confidence = {confidence}: highest confidence of any fired rule "
                "(more distinct techniques, attack-tool fingerprints and corroborating rules raise it).")
    return {"attack_detected": True, "headline": f"{headline}: {outcome}", "attack_types": [LABELS[t] for t in types],
            "stage": STAGES[stage], "confidence": confidence, "mitre": mitre_list,
            "attacker_ips": sorted({ip for d in detections for ip in d.indicators.get("src_ips", [])}),
            "decision_path": path}


def analyze_lines(lines: list[str]) -> dict:
    """Full pipeline on raw text, nothing stored. Used by the Attack Lab and the 'paste your own logs' box."""
    records = [parse_line(i + 1, l) for i, l in enumerate(lines) if l.strip()]
    detections, checks = detect(records)
    flagged = {e["line_no"]: d.rule_id for d in detections for e in d.evidence}
    return {
        "lines": [{"line_no": r.line_no, "raw": r.raw, "source": r.source, "at": _iso(r), "flagged_by": flagged.get(r.line_no),
                   "decoded": r.fields.get("decoded"),  # match offsets refer to this URL-decoded path
                   "matches": signature_hits(r.fields["decoded"]) if r.source in ("web", "raw") else []} for r in records],
        "parsed": {s: sum(r.source == s for r in records) for s in ("web", "auth", "firewall", "process", "network", "raw")},
        "detections": [asdict(d) for d in detections],
        "checks": checks,
        "verdict": classify(detections, checks, len(records)),
    }
