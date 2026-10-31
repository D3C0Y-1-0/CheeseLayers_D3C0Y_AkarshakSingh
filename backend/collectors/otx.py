"""AlienVault OTX: community 'pulses' = write-ups of an attack campaign, with IOCs and MITRE ATT&CK technique tags."""
from datetime import datetime, timedelta, timezone

import json

from .common import Skipped, env, get, raw_pages, ref, save_raw
from .schema import IOC, ThreatItem

SOURCE = "otx"
API = "https://otx.alienvault.com/api/v1"
MAX_PAGES = 4  # 50 pulses per page
OTX_TYPES = {"IPv4": "ip", "domain": "domain", "hostname": "domain", "URL": "url",
             "FileHash-SHA256": "sha256", "FileHash-MD5": "md5"}


def _names(values: list, key: str) -> list[str]:
    # /pulses/subscribed sends plain strings ("T1190"); other endpoints send objects ({"id": "T1190", ...}).
    return [v if isinstance(v, str) else v[key] for v in values]


def _pulses(path: str, headers: dict) -> list[tuple[dict, str]]:
    """(pulse, raw_ref of the page it came from)."""
    since = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
    url, out = f"{API}{path}", []
    params = {"limit": 50, "modified_since": since}
    for page in range(MAX_PAGES):
        data = get(url, params=params, headers=headers).json()
        ref = save_raw(SOURCE, data, f"{path.strip('/').replace('/', '_')}_{page}")
        out += [(p, ref) for p in data.get("results", [])]
        url, params = data.get("next"), None  # 'next' already carries the query string
        if not url:
            break
    return out


def fetch() -> dict:
    key = env("OTX_API_KEY")
    if not key:
        raise Skipped("no OTX_API_KEY")
    headers = {"X-OTX-API-KEY": key}
    # 'subscribed' = pulses from authors we follow; a fresh account follows nobody, so fall back to global activity.
    pulses = _pulses("/pulses/subscribed", headers) or _pulses("/pulses/activity", headers)
    return parse(pulses)


def from_raw() -> dict:
    return parse([(p, ref(f)) for f in raw_pages(SOURCE) for p in json.loads(f.read_text()).get("results", [])])


def parse(pulses: list[tuple[dict, str]]) -> dict:
    items, iocs = [], []
    for p, ref in pulses:
        tid = f"otx:{p['id']}"
        inds = p.get("indicators", [])
        items.append(ThreatItem(
            threat_id=tid, source=SOURCE, type="campaign", title=p["name"],
            description=p.get("description") or None, published_at=p["created"][:19] + "Z" if p.get("created") else None,
            references=list(dict.fromkeys([f"https://otx.alienvault.com/pulse/{p['id']}"] + [r for r in p.get("references") or [] if r])),
            raw_ref=ref,
            cve_ids=sorted({i["indicator"].upper() for i in inds if i["type"] == "CVE"}),
            # ATT&CK IDs like T1566 (phishing) let us map the campaign onto the ATT&CK heatmap.
            attack_techniques=[t for t in _names(p.get("attack_ids", []), "id") if t],  # OTX sometimes sends ""
            tags=p.get("tags", []) + _names(p.get("malware_families", []), "display_name")
                 + [f"target:{c}" for c in p.get("targeted_countries", [])],
        ))
        iocs += [IOC(value=i["indicator"], ioc_type=OTX_TYPES[i["type"]], source=SOURCE,
                     malware_family=next(iter(_names(p.get("malware_families", []), "display_name")), None),
                     first_seen=i.get("created", "")[:19] + "Z" if i.get("created") else None, related_threat_id=tid, raw_ref=ref)
                 for i in inds if i["type"] in OTX_TYPES]
    return {"items": items, "iocs": iocs}
