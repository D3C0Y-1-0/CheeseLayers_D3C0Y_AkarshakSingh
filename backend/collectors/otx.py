"""AlienVault OTX: community 'pulses' = write-ups of an attack campaign, with IOCs and MITRE ATT&CK technique tags."""
from datetime import datetime, timedelta, timezone

from .common import Skipped, env, get, save_raw
from .schema import IOC, ThreatItem

SOURCE = "otx"
API = "https://otx.alienvault.com/api/v1"
MAX_PAGES = 4  # 50 pulses per page
OTX_TYPES = {"IPv4": "ip", "domain": "domain", "hostname": "domain", "URL": "url",
             "FileHash-SHA256": "sha256", "FileHash-MD5": "md5"}


def _pulses(path: str, headers: dict) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
    url, out = f"{API}{path}", []
    params = {"limit": 50, "modified_since": since}
    for page in range(MAX_PAGES):
        data = get(url, params=params, headers=headers).json()
        save_raw(SOURCE, data, f"{path.strip('/').replace('/', '_')}_{page}")
        out += data.get("results", [])
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
    items, iocs = [], []
    for p in pulses:
        tid = f"otx:{p['id']}"
        inds = p.get("indicators", [])
        items.append(ThreatItem(
            id=tid, source=SOURCE, type="campaign", title=p["name"],
            description=p.get("description") or "", published_at=p.get("created", "")[:19] + "Z",
            url=f"https://otx.alienvault.com/pulse/{p['id']}",
            cve_ids=sorted({i["indicator"].upper() for i in inds if i["type"] == "CVE"}),
            # ATT&CK IDs like T1566 (phishing) let us map the campaign onto the ATT&CK heatmap.
            attack_techniques=[a["id"] for a in p.get("attack_ids", [])],
            tags=p.get("tags", []) + [m["display_name"] for m in p.get("malware_families", [])]
                 + [f"target:{c}" for c in p.get("targeted_countries", [])],
        ))
        iocs += [IOC(value=i["indicator"], ioc_type=OTX_TYPES[i["type"]], source=SOURCE,
                     malware_family=next((m["display_name"] for m in p.get("malware_families", [])), None),
                     first_seen=i.get("created", "")[:19] + "Z" if i.get("created") else None, related_threat_id=tid)
                 for i in inds if i["type"] in OTX_TYPES]
    return {"items": items, "iocs": iocs}
