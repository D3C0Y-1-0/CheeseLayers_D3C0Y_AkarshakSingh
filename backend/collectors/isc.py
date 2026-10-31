"""SANS Internet Storm Center (DShield): REAL attack traffic seen by its honeypots and firewall sensors.

Used by the Attack Lab to replay real attackers instead of invented ones.
  web       /api/daily404detail/{date}/{limit}     real HTTP requests that hit web honeypots (URL, user agent, source, date)
  firewall  /api/openiocsources/{date}/{n}/{page}  real firewall log records (source IP, target port, source port, date)
  reputation /api/ip/{ip}                        ASN, country and the public threat feeds that list an attacker

The source gives a DATE but no time of day, so replays keep the original order and say so.
Data licence: CC BY-NC-SA 4.0, SANS Internet Storm Center (https://isc.sans.edu/api/). ISC asks for contact details in
the User-Agent and polite pacing; DEMO_MODE never calls it (cache only).

    DEMO_MODE=false backend/.venv/bin/python -m collectors.isc      # refresh data/cache/isc.json
"""
import json
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone

from .common import CACHE, RAW, get, log, raw_file, ref, save_cache, save_raw

SOURCE = "isc"
API = "https://isc.sans.edu/api"
HEADERS = {"User-Agent": "Vectra-hackathon-research (akarshaksingh@gmail.com)"}
WEB_DAYS, WEB_LIMIT = 3, 2000  # three days of honeypot web requests
FW_PAGES, FW_PER_PAGE = 5, 1000  # firewall records for the most recent full day
MAX_REPUTATION = 40  # attacker IPs looked up individually
NS = {"ioc": "http://schemas.mandiant.com/2010/ioc"}


def _json(path: str):
    return get(f"{API}/{path}?json", headers=HEADERS, min_interval=2.0).json()


def _rows(data) -> list[dict]:
    return [v for v in (data.values() if isinstance(data, dict) else data or []) if isinstance(v, dict)]


def _firewall(xml_text: str) -> list[dict]:
    """OpenIOC firewall export -> [{date, source, target_port, source_port}]."""
    out = []
    for group in ET.fromstring(xml_text).iter(f"{{{NS['ioc']}}}Indicator"):
        items = group.findall("ioc:IndicatorItem", NS)
        if not items:
            continue
        rec = {}
        for it in items:
            key = it.find("ioc:Context", NS).get("search").split("/")[-1]
            rec[key] = it.find("ioc:Content", NS).text
        if "remoteIP" in rec and "localPort" in rec:
            out.append({"date": (rec.get("CreationTime") or "")[:10], "source": rec["remoteIP"],
                        "target_port": int(rec["localPort"]), "source_port": int(rec.get("remotePort") or 0)})
    return out


def interesting_ips(web: list[dict], firewall: list[dict]) -> list[str]:
    """Attackers worth replaying: the busiest web attackers that tripped a rule, and the widest scanners."""
    from app.detection import KNOWN_EXPLOITS, RECON_PATHS, signature_hits
    score: Counter = Counter()
    for r in web:
        u = r["url"]
        if signature_hits(u) or any(p.search(u) for p, *_ in KNOWN_EXPLOITS) or RECON_PATHS.search(u):
            score[r["source"]] += 1
    ports: dict[str, set] = defaultdict(set)
    login: Counter = Counter()
    for r in firewall:
        ports[r["source"]].add(r["target_port"])
        if r["target_port"] in (22, 23, 2222, 3389, 5900):
            login[r["source"]] += 1
    picks = [ip for ip, _ in score.most_common(25)]
    picks += [ip for ip, _ in sorted(ports.items(), key=lambda kv: -len(kv[1]))[:10]]
    picks += [ip for ip, _ in login.most_common(5)]
    return list(dict.fromkeys(picks))[:MAX_REPUTATION]


def fetch() -> dict:
    today = datetime.now(timezone.utc).date()
    web = []
    for d in range(1, WEB_DAYS + 1):
        day = (today - timedelta(days=d)).isoformat()
        data = _json(f"daily404detail/{day}/{WEB_LIMIT}")
        save_raw(SOURCE, data, f"web_{day}")
        web += _rows(data)
    fw_day = (today - timedelta(days=1)).isoformat()
    firewall = []
    for page in range(1, FW_PAGES + 1):
        text = get(f"{API}/openiocsources/{fw_day}/{FW_PER_PAGE}/{page}", headers=HEADERS, min_interval=2.0).text
        save_raw(SOURCE, text, f"firewall_{fw_day}_{page}")
        firewall += _firewall(text)
    reputation = {}
    for ip in interesting_ips(web, firewall):
        try:
            data = _json(f"ip/{ip}")
            save_raw(SOURCE, data, f"ip_{ip}")
            reputation[ip] = data.get("ip", data)
        except Exception as e:  # one bad lookup never sinks the run
            log.warning("isc: reputation for %s failed (%s)", ip, e)
    return parse(web, firewall, reputation)


def from_raw() -> dict:
    web, firewall, reputation = [], [], {}
    for f in sorted((RAW / SOURCE).glob("web_*.json")):
        web += _rows(json.loads(f.read_text(encoding="utf-8")))
    for f in sorted((RAW / SOURCE).glob("firewall_*.txt")):
        firewall += _firewall(f.read_text(encoding="utf-8"))
    for f in (RAW / SOURCE).glob("ip_*.json"):
        data = json.loads(f.read_text(encoding="utf-8"))
        reputation[f.stem[3:]] = data.get("ip", data)
    if not web:
        raw_file(SOURCE, "web_*.json")  # raises Skipped with a clear message
    return parse(web, firewall, reputation)


def _rep(r: dict) -> dict:
    feeds = r.get("threatfeeds") or {}
    return {"asn": r.get("as"), "as_name": r.get("asname"), "country": r.get("ascountry"), "network": r.get("network"),
            "isc_reports": r.get("count"), "isc_targets": r.get("attacks"),
            "first_seen": r.get("mindate"), "last_seen": r.get("maxdate"),
            "threat_feeds": sorted(feeds) if isinstance(feeds, dict) else []}


def parse(web: list[dict], firewall: list[dict], reputation: dict) -> dict:
    web = [{"date": r.get("date"), "url": r.get("url") or "", "user_agent": r.get("user_agent") or "",
            "source": r.get("source")} for r in web if r.get("source") and r.get("url")]
    return {
        "source": SOURCE, "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "licence": "CC BY-NC-SA 4.0, SANS Internet Storm Center (isc.sans.edu)",
        "note": "Real traffic seen by SANS ISC/DShield honeypots and firewall sensors. Dates only (no time of day).",
        "web_requests": web, "firewall": firewall,
        "reputation": {ip: _rep(r) for ip, r in reputation.items()},
    }


def load() -> dict | None:
    path = CACHE / f"{SOURCE}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


if __name__ == "__main__":
    data = fetch()
    path = save_cache(SOURCE, data)
    print(f"{len(data['web_requests'])} web requests, {len(data['firewall'])} firewall records, "
          f"{len(data['reputation'])} attacker reputations -> {ref(path)}  (days: "
          f"{sorted({r['date'] for r in data['web_requests']})}; firewall day {date.today() - timedelta(days=1)})")
