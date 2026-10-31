"""abuse.ch: community-run feeds of live malicious infrastructure.

- ThreatFox: IOCs (IPs, domains, URLs, hashes) tied to a malware family
- URLhaus: URLs serving malware
- MalwareBazaar: hashes of fresh malware samples
- Feodo Tracker: botnet command-and-control (C2) server IPs — the only feed still public without a key

All three main APIs need a free Auth-Key (https://auth.abuse.ch/). The old no-key exports
(threatfox .../export/json/recent/, urlhaus .../downloads/csv_recent/) return 410 Gone since 2025,
so without a key we fall back to Feodo Tracker only.
"""
from collections import defaultdict

from .common import Skipped, env, get, log, request, save_raw
from .schema import IOC, ThreatItem

SOURCE = "abusech"
FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
TF_TYPES = {"ip:port": "ip", "domain": "domain", "url": "url", "sha256_hash": "sha256", "md5_hash": "md5"}


def _ts(s: str | None) -> str | None:
    return s.replace(" UTC", "") + "+00:00" if s else None  # abuse.ch: "2026-10-30 12:34:56 UTC"


def _threatfox(key: str) -> list[IOC]:
    data = request("POST", "https://threatfox-api.abuse.ch/api/v1/", json={"query": "get_iocs", "days": 7},
                   headers={"Auth-Key": key}).json()
    save_raw(SOURCE, data, "threatfox")
    out = []
    for r in data.get("data") or []:
        t = TF_TYPES.get(r["ioc_type"])
        if not t:
            continue  # e.g. sha1 — not in our schema
        value = r["ioc"].rsplit(":", 1)[0] if t == "ip" else r["ioc"]  # "1.2.3.4:443" -> "1.2.3.4"
        out.append(IOC(value=value, ioc_type=t, source="threatfox", malware_family=r.get("malware_printable"),
                       first_seen=_ts(r.get("first_seen")), confidence=r.get("confidence_level")))
    return out


def _urlhaus(key: str) -> list[IOC]:
    data = get("https://urlhaus-api.abuse.ch/v1/urls/recent/", headers={"Auth-Key": key}).json()  # GET-only endpoint
    save_raw(SOURCE, data, "urlhaus")
    return [IOC(value=r["url"], ioc_type="url", source="urlhaus", malware_family=(r.get("tags") or [None])[0],
                first_seen=_ts(r.get("date_added"))) for r in data.get("urls") or []]


def _bazaar(key: str) -> list[IOC]:
    # selector=time: samples from the last 60 minutes (selector=100 would be the latest 100).
    data = request("POST", "https://mb-api.abuse.ch/api/v1/", data={"query": "get_recent", "selector": "time"},
                   headers={"Auth-Key": key}).json()
    save_raw(SOURCE, data, "malwarebazaar")
    return [IOC(value=r["sha256_hash"], ioc_type="sha256", source="malwarebazaar", malware_family=r.get("signature"),
                first_seen=_ts(r.get("first_seen"))) for r in data.get("data") or [] if isinstance(r, dict)]


def _feodo() -> list[IOC]:
    data = get(FEODO).json()
    save_raw(SOURCE, data, "feodo")
    return [IOC(value=r["ip_address"], ioc_type="ip", source="feodotracker", malware_family=r.get("malware"),
                first_seen=_ts(r.get("first_seen"))) for r in data]


def fetch() -> dict:
    key = env("ABUSECH_AUTH_KEY")
    feeds = [lambda: _threatfox(key), lambda: _urlhaus(key), lambda: _bazaar(key), _feodo] if key else [_feodo]
    if not key:
        log.warning("abusech: no ABUSECH_AUTH_KEY — only Feodo Tracker (ThreatFox/URLhaus/MalwareBazaar need a free key)")
    iocs: list[IOC] = []
    for feed in feeds:
        try:
            iocs += feed()
        except Exception as e:  # one sub-feed down shouldn't drop the others
            log.warning("abusech: sub-feed failed: %s", e)
    if not iocs:
        raise Skipped("no abuse.ch data (add ABUSECH_AUTH_KEY)")

    # Group IOCs into one 'ioc_batch' ThreatItem per feed + malware family so the dashboard can show
    # "ThreatFox: 120 Cobalt Strike IOCs" and the IOC matcher can link a log hit back to a threat.
    groups: dict[tuple[str, str], list[IOC]] = defaultdict(list)
    for i in iocs:
        groups[(i.source, i.malware_family or "unknown")].append(i)
    items = []
    for (src, family), group in groups.items():
        tid = f"{src}:{family.lower().replace(' ', '_')}"
        for i in group:
            i.related_threat_id = tid
        items.append(ThreatItem(
            id=tid, source=src, type="ioc_batch", title=f"{src}: {len(group)} {family} indicators",
            description=f"{len(group)} indicators of compromise linked to {family}, reported by abuse.ch {src}.",
            published_at=max((i.first_seen for i in group if i.first_seen), default=None),
            url={"malwarebazaar": "https://bazaar.abuse.ch/"}.get(src, f"https://{src}.abuse.ch/"),
            tags=["abuse.ch", src, family],
        ))
    return {"items": items, "iocs": iocs}
