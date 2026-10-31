"""CISA KEV (Known Exploited Vulnerabilities): CVEs attackers are exploiting right now. Strongest 'act now' signal."""
import re

from .common import get, save_raw
from .schema import AffectedConfiguration, ThreatItem

SOURCE = "kev"
URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch() -> dict:
    data = get(URL).json()
    return parse(data, save_raw(SOURCE, data))


def parse(data: dict, ref: str) -> dict:
    items = []
    for v in data["vulnerabilities"]:
        ransomware = v.get("knownRansomwareCampaignUse") == "Known"
        notes = [u.strip() for part in (v.get("notes") or "").split(";") for u in re.findall(r"https?://\S+", part)]
        items.append(ThreatItem(
            threat_id=v["cveID"], cve_id=v["cveID"], source=SOURCE, type="vulnerability",
            title=f"{v['cveID']}: {v['vulnerabilityName']}",
            # requiredAction/dueDate: what US federal agencies must do and by when — a good default remediation.
            description=f"{v['shortDescription']}\nRequired action: {v['requiredAction']} (due {v['dueDate']})",
            published_at=v["dateAdded"] + "T00:00:00Z",
            references=list(dict.fromkeys([f"https://nvd.nist.gov/vuln/detail/{v['cveID']}"] + notes)),
            cve_ids=[v["cveID"]], kev_listed=True,
            affected_configurations=[AffectedConfiguration(vendor=v["vendorProject"], product=v["product"])],
            tags=["kev"] + (["ransomware"] if ransomware else []) + v.get("cwes", []),
            raw_ref=ref,
        ))
    return {"items": items}


def cve_ids(items: list[dict | ThreatItem]) -> set[str]:
    """Set of CVE IDs in the KEV catalogue, for flagging items from other sources."""
    return {i["threat_id"] if isinstance(i, dict) else i.threat_id for i in items}
