"""CISA KEV (Known Exploited Vulnerabilities): CVEs attackers are exploiting right now. Strongest 'act now' signal."""
from .common import get, save_raw
from .schema import Affected, ThreatItem

SOURCE = "kev"
URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch() -> dict:
    data = get(URL).json()
    ref = save_raw(SOURCE, data)
    items = []
    for v in data["vulnerabilities"]:
        ransomware = v.get("knownRansomwareCampaignUse") == "Known"
        items.append(ThreatItem(
            id=v["cveID"], source=SOURCE, type="vulnerability",
            title=f"{v['cveID']}: {v['vulnerabilityName']}",
            # requiredAction/dueDate: what US federal agencies must do and by when — a good default remediation.
            description=f"{v['shortDescription']}\nRequired action: {v['requiredAction']} (due {v['dueDate']})",
            published_at=v["dateAdded"] + "T00:00:00Z",
            url=f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
            cve_ids=[v["cveID"]], in_kev=True,
            affected=[Affected(vendor=v["vendorProject"], product=v["product"])],
            tags=["kev"] + (["ransomware"] if ransomware else []) + v.get("cwes", []),
            raw_ref=ref,
        ))
    return {"items": items}


def cve_ids(items: list[dict | ThreatItem]) -> set[str]:
    """Set of CVE IDs in the KEV catalogue, for flagging items from other sources."""
    return {i["id"] if isinstance(i, dict) else i.id for i in items}
