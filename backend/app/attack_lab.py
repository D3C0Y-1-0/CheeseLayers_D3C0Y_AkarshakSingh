"""Attack Lab: replay a REAL attacker's real traffic against one of our assets, detect it, link it to our intel.

  GET  /api/attack-lab/attackers  real attackers from SANS ISC honeypots/firewall sensors (data/cache/isc.json)
  POST /api/attack-lab/run        replay one attacker -> detection.analyze_lines -> intel links -> CorrelationEngine
  POST /api/attack-lab/analyze    paste your own log lines; detection only, nothing stored
  GET  /api/attack-lab/rules      the detection rulebook (exact logic and thresholds)

What is real: every request URL, user agent, source IP, date, target port and the attacker's reputation (SANS ISC
CC BY-NC-SA 4.0), and the CVE / KEV / EPSS facts (our NVD + CISA feeds). What is not: the target. The traffic hit SANS
sensors, not us, so it is REPLAYED against an asset from our simulated inventory, and the incident says so. The source
gives dates but no time of day, so replays keep the original order and rules that need timing say "on <date>".
"""
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from collectors import isc

from . import detection
from .asset_store import get_asset_store
from .contracts import Asset, SecurityEvent
from .correlator import CorrelationEngine, threat_from_row
from .database import get_db
from .matcher import exposed, match_asset, match_threat
from .models import IOCRow, Threat

router = APIRouter()
MAX_REPLAY = 200  # lines replayed per run (the attacker's first N real records, in original order)
DEFAULT_TARGET = {"web": "GOV-WEB-01", "login": "GOV-VPN-01", "scan": "PWR-FW-01"}


# --- the real data -------------------------------------------------------------------------------------------

@lru_cache(maxsize=2)
def _traffic(stamp: str) -> tuple[dict, dict, dict]:
    data = isc.load() or {}
    web, fw = defaultdict(list), defaultdict(list)
    for r in data.get("web_requests", []):
        web[r["source"]].append(r)
    for r in data.get("firewall", []):
        fw[r["source"]].append(r)
    return web, fw, data


def traffic() -> tuple[dict, dict, dict]:
    path = isc.CACHE / "isc.json"
    return _traffic(str(path.stat().st_mtime) if path.exists() else "none")


def _host_ip(asset: Asset) -> str:
    return asset.ip or "10.0.0.1"


def raw_lines(ip: str, asset: Asset) -> list[str]:
    """The attacker's real records as the log lines our sensors would have written (date only: 00:00:00)."""
    web, fw, _ = traffic()
    out = []
    for r in web.get(ip, []):
        day = datetime.fromisoformat(r["date"]).strftime("%d/%b/%Y")
        url = r["url"].replace(" ", "%20").replace('"', "%22")
        ua = (r["user_agent"] or "-").replace('"', "'")
        # The honeypot answered 404 (ISC's 404 project): the request is real, the response is the honeypot's.
        out.append(f'{ip} - - [{day}:00:00:00 +0000] "GET {url} HTTP/1.1" 404 0 "-" "{ua}"')
    for r in fw.get(ip, []):
        out.append(f"{r['date']}T00:00:00+00:00 {asset.hostname} kernel: [FW] IN=eth0 SRC={ip} DST={_host_ip(asset)} "
                   f"PROTO=TCP SPT={r['source_port']} DPT={r['target_port']} FLAGS=SYN ACTION=DROP")
    return out


def _kind(dets: list[dict]) -> str:
    ids = {d["rule_id"] for d in dets}
    return "login" if "NET-LOGIN-001" in ids else "scan" if "NET-SCAN-001" in ids else "web"


@lru_cache(maxsize=2)
def _catalogue(stamp: str) -> list[dict]:
    web, fw, data = traffic()
    rep = data.get("reputation", {})
    probe = get_asset_store().get(DEFAULT_TARGET["web"])
    profiles = []
    for ip in set(web) | set(fw):
        a = detection.analyze_lines(raw_lines(ip, probe)[:MAX_REPLAY])
        dets = a["detections"]
        if not dets and ip not in rep:
            continue
        cves = sorted({c for d in dets for c in d["indicators"].get("cve_ids", [])})
        dates = sorted({r["date"] for r in web.get(ip, []) + fw.get(ip, [])})
        r = rep.get(ip, {})
        profiles.append({
            "ip": ip, "kind": _kind(dets), "headline": a["verdict"]["headline"],
            "attack_types": a["verdict"]["attack_types"], "rules": [d["rule_id"] for d in dets], "cve_ids": cves,
            "web_requests": len(web.get(ip, [])), "firewall_records": len(fw.get(ip, [])),
            "first_seen": dates[0] if dates else None, "last_seen": dates[-1] if dates else None,
            "country": r.get("country"), "as_name": r.get("as_name"), "threat_feeds": r.get("threat_feeds", []),
            "user_agents": [u for u, _ in Counter(x["user_agent"] for x in web.get(ip, [])).most_common(2)],
            "detected": bool(dets),
        })
    order = {"WEB-EXPLOIT-001": 0, "WEB-CMDI-001": 1, "WEB-SQLI-001": 1, "WEB-TRAV-001": 2, "WEB-XSS-001": 2,
             "NET-LOGIN-001": 3, "NET-SCAN-001": 4, "WEB-RECON-001": 5}
    rank = lambda p: (min((order.get(r, 9) for r in p["rules"]), default=10), -len(p["threat_feeds"]),  # noqa: E731
                      -(p["web_requests"] + p["firewall_records"]), p["ip"])
    profiles.sort(key=rank)
    # Keep the list readable: every exploit/injection attacker, the top 4 of each other kind, 2 undetected controls.
    out, seen = [], Counter()
    for p in profiles:
        key = p["rules"][0] if p["rules"] else "none"
        cap = 99 if key in ("WEB-EXPLOIT-001", "WEB-CMDI-001", "WEB-SQLI-001") else 2 if key == "none" else 4
        if seen[key] < cap:
            out.append(p)
            seen[key] += 1
    return out


def catalogue() -> list[dict]:
    path = isc.CACHE / "isc.json"
    return _catalogue(str(path.stat().st_mtime) if path.exists() else "none")


# --- linking the attack to our threat intelligence ------------------------------------------------------------

def intel(db: Session, ip: str, asset: Asset, dets: list[dict]) -> dict:
    """Attacker reputation (ISC + our IOC feeds) and, per exploited CVE, our feed facts + what the matcher says."""
    _, _, data = traffic()
    iocs = [{"source": s, "type": t, "malware_family": f} for s, t, f in
            db.execute(select(IOCRow.source, IOCRow.ioc_type, IOCRow.malware_family).where(IOCRow.value == ip))]
    store = get_asset_store()
    cves = []
    for cve in sorted({c for d in dets for c in d["indicators"].get("cve_ids", [])}):
        row = db.get(Threat, cve)
        if row is None:
            cves.append({"cve_id": cve, "in_feed": False})
            continue
        threat = threat_from_row(row)
        m = match_asset(asset, threat)
        others = [x.asset_id for x in exposed(match_threat(threat, store.all())) if x.asset_id != asset.asset_id]
        cves.append({"cve_id": cve, "in_feed": True, "title": row.title, "source": row.source, "kev_listed": row.kev_listed,
                     "epss": row.epss, "cvss": row.cvss, "kev_date_added": str(row.kev_date_added) if row.kev_date_added else None,
                     "target_match": m.match_detail, "target_reason": m.reason, "other_exposed_assets": others})
    return {"attacker": {"ip": ip, "reputation": data.get("reputation", {}).get(ip), "our_ioc_hits": iocs,
                         "source": "SANS Internet Storm Center (CC BY-NC-SA 4.0) + our abuse.ch/OTX/IP-reputation IOCs"},
            "cves": cves}


# --- detections -> SecurityEvents for the correlation engine --------------------------------------------------

EVENT_TYPE = {"brute_force": "auth", "credential_compromise": "auth", "port_scan": "network", "login_hammering": "network",
              "sql_injection": "http", "data_exposure": "http", "command_injection": "http", "http_anomaly": "http",
              "exploit_attempt": "http", "exploit_on_vulnerable_asset": "http", "recon_probe": "http",
              "unexpected_process": "process", "outbound_connection": "network"}


def to_events(run_id: str, asset: Asset, detections: list[dict], vulnerable: set[str] = frozenset()) -> list[SecurityEvent]:
    events = []
    for i, d in enumerate(detections):
        signal, reason = d["signal"], d["reason"]
        hit = sorted(set(d["indicators"].get("cve_ids", [])) & vulnerable)
        if d["rule_id"] == "WEB-EXPLOIT-001" and hit:
            signal = "exploit_on_vulnerable_asset"
            reason += f" — and our matcher says {asset.asset_id} runs a version vulnerable to {', '.join(hit)}"
        details: dict[str, Any] = {
            "attack_signal": signal, "attack_type": d["attack_type"], "attack_label": d["label"],
            "detection_reason": reason, "stage": d["stage"], "mitre": [m["id"] for m in d["mitre"]],
            "matched_lines": d["count"], "sample": d["evidence"][0]["raw"] if d["evidence"] else None,
            "cve_ids": d["indicators"].get("cve_ids", []), "replayed_real_traffic": True,
        }
        if d["src_ip"]:
            details["src_ip"] = d["src_ip"]
        if signal == "outbound_connection":
            details |= {"direction": "outbound", "dest_ip": d["indicators"]["dest_ip"], "dest_port": d["indicators"]["dest_port"]}
        at = d["last_seen"] or d["first_seen"]
        events.append(SecurityEvent(
            event_id=f"LAB-{run_id}-{i + 1:02d}-{d['rule_id']}", asset_id=asset.asset_id,
            timestamp=datetime.fromisoformat(at) if at else datetime.now(timezone.utc),
            event_type=EVENT_TYPE[signal], source_sensor=f"attack-lab/{d['rule_id']}", details=details,
            is_simulated=True,  # the traffic is real, but it never reached OUR asset: the incident is a replay
            rule_id=d["rule_id"], confidence=d["confidence"]))
    return events


def _steps(lines: list[dict]) -> list[dict]:
    """Group the replayed lines by what they are, in order of first appearance (lines keep their real order)."""
    names = {"exploit": ("Exploit attempts", "Requests carrying published exploits for specific CVEs."),
             "inject": ("Injection / traversal payloads", "Requests trying to run commands, read files or inject scripts."),
             "recon": ("Scanning for secrets and admin pages", "Wordlist requests for .env, .git, phpinfo, admin panels..."),
             "web": ("Other requests", "Requests that match no rule (probing, crawling)."),
             "login": ("Login-port hammering", "Connection attempts to SSH / Telnet / RDP / VNC."),
             "port": ("Port probes", "Connection attempts to other ports, mapping what is open.")}
    groups: dict[str, list[int]] = {}
    for l in lines:
        fam = {m["family"] for m in l["matches"]}
        dpt = l["raw"].split("DPT=")[1].split()[0] if "DPT=" in l["raw"] else None
        k = ("exploit" if "known_exploit" in fam else "inject" if fam - {"recon"} else "recon" if "recon" in fam
             else ("login" if int(dpt) in detection.CONFIG["login_ports"] else "port") if dpt else "web")
        groups.setdefault(k, []).append(l["line_no"])
    return [{"title": names[k][0], "detail": names[k][1], "actor": "attacker", "line_nos": v} for k, v in groups.items()]


# --- API ------------------------------------------------------------------------------------------------------

class RunRequest(BaseModel):
    attacker_ip: str = Field(min_length=3, max_length=64)
    target_asset_id: str | None = None  # default: an asset our matcher says is vulnerable to the exploited CVE


class AnalyzeRequest(BaseModel):
    lines: list[Annotated[str, Field(max_length=4096)]] = Field(min_length=1, max_length=500)  # 422 beyond


@router.get("/api/attack-lab/attackers", tags=["attack-lab"])
def attackers(db: Session = Depends(get_db)) -> dict:
    """Real attackers seen by SANS ISC honeypots/firewall sensors, with what our rules detect in their traffic."""
    _, _, data = traffic()
    items = catalogue()
    for p in items:
        p["default_target"] = _default_target(db, p)
    return {"source": "SANS Internet Storm Center (isc.sans.edu), CC BY-NC-SA 4.0", "retrieved_at": data.get("retrieved_at"),
            "note": data.get("note"), "web_requests": len(data.get("web_requests", [])),
            "firewall_records": len(data.get("firewall", [])), "items": items}


def _default_target(db: Session, p: dict) -> str:
    store = get_asset_store()
    for cve in p["cve_ids"]:  # prefer an asset that is actually vulnerable to what the attacker is exploiting
        row = db.get(Threat, cve)
        if row is not None:
            hit = exposed(match_threat(threat_from_row(row), store.all()))
            if hit:
                return sorted(hit, key=lambda m: (not store.get(m.asset_id).internet_facing, m.asset_id))[0].asset_id
    return DEFAULT_TARGET[p["kind"]]


@router.get("/api/attack-lab/rules", tags=["attack-lab"])
def rules() -> dict:
    return {"rules": [r | {"mitre": [detection.mitre(t) for t in r["mitre"]]} for r in detection.RULES],
            "signatures": [{"id": s.sig_id, "family": s.family, "technique": s.technique, "pattern": s.pattern.pattern,
                            "strong": s.strong} for s in detection.SIGNATURES],
            "known_exploits": [{"cve_id": cve, "name": name, "pattern": p.pattern} for p, cve, name in detection.KNOWN_EXPLOITS],
            "thresholds": detection.CONFIG}


@router.post("/api/attack-lab/analyze", tags=["attack-lab"])
def analyze(body: AnalyzeRequest) -> dict:
    """Run the detector on any log lines you paste. Nothing is stored and no alert is created."""
    return detection.analyze_lines(body.lines)


@router.post("/api/attack-lab/run", tags=["attack-lab"],
             responses={403: {"description": "demo mode only"}, 404: {"description": "unknown attacker or asset"}})
def run(body: RunRequest, db: Session = Depends(get_db)) -> dict:
    """Replay a real attacker's traffic against one of our (simulated) assets, detect it, link it to our intel."""
    from ai.llm import demo_mode
    if not demo_mode():
        raise HTTPException(403, "the attack lab writes replay incidents and is only available in DEMO_MODE")
    profile = next((p for p in catalogue() if p["ip"] == body.attacker_ip), None)
    if profile is None:
        raise HTTPException(404, f"attacker {body.attacker_ip} is not in the cached SANS ISC data")
    asset = get_asset_store().get(body.target_asset_id or _default_target(db, profile))
    if asset is None:
        raise HTTPException(404, f"asset {body.target_asset_id} not found")

    run_id = uuid.uuid4().hex[:8].upper()
    every = raw_lines(profile["ip"], asset)
    analysis = detection.analyze_lines(every[:MAX_REPLAY])
    link = intel(db, profile["ip"], asset, analysis["detections"])

    # Intel -> alert: an exploited CVE our matcher says this asset is vulnerable to gets its vulnerability alert too.
    engine = CorrelationEngine(db)
    vulnerable = {c["cve_id"] for c in link["cves"] if c.get("target_match") in ("confirmed_affected", "needs_verification")}
    vuln_alerts = []
    for cve in sorted(vulnerable):
        out = engine.correlate_threat(threat_from_row(db.get(Threat, cve)), trigger="attack_lab")
        vuln_alerts += [a for a in out["created"] + out["updated"]]
    events = to_events(run_id, asset, analysis["detections"], vulnerable)
    out = engine.ingest_events(events) if events else {"created": [], "updated": [], "incidents": []}
    note = ("No rule fired, so nothing was sent to the correlation engine and no incident exists." if not events else
            "Added to an existing incident: same asset and time window, so the correlator treats it as one campaign. "
            "Reset demo alerts to start clean." if not out["created"] else "New incident created.")
    return {
        "run_id": run_id, "scenario": profile["kind"], "kind": profile["kind"], "attacker": profile,
        "data_classification": (f"REAL attack traffic from SANS ISC sensors ({profile['first_seen']}"
                                f"{' to ' + profile['last_seen'] if profile['last_seen'] != profile['first_seen'] else ''}), "
                                f"replayed against a simulated asset. Dates are real; time of day is not in the source."),
        "is_simulated": False, "target_is_simulated": asset.is_simulated,
        "replayed": len(analysis["lines"]), "total_records": len(every),
        "target": {"asset_id": asset.asset_id, "hostname": asset.hostname, "role": asset.role, "sector": asset.sector,
                   "criticality": asset.criticality, "internet_facing": asset.internet_facing},
        "steps": _steps(analysis["lines"]), **analysis, "intel": link,
        "events_sent": [e.model_dump(mode="json") for e in events],
        "correlation": {"created": out["created"], "updated": out["updated"], "note": note,
                        "vulnerability_alerts": sorted(set(vuln_alerts)),
                        "incidents": [i for i in out["incidents"] if asset.asset_id in i["asset_ids"]]},
    }
