"""CTID Mappings Explorer: expert mappings of KEV CVEs to MITRE ATT&CK techniques.

Each CVE gets up to three kinds of technique:
- exploitation_technique: how the attacker gets in (e.g. T1190 Exploit Public-Facing Application)
- primary_impact / secondary_impact: what they can do after (e.g. T1059 command execution)
Output data/cache/kev_attack_map.json -> {cve_id: [{id, name, mapping_type}]}
"""
import re
from collections import defaultdict

from .common import get, github_headers, save_raw

SOURCE = "kev_attack_map"
REPO = "center-for-threat-informed-defense/mappings-explorer"
# mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json
PATH_RE = re.compile(r"^mappings/kev/attack-[\d.]+/kev-(\d\d)\.(\d\d)\.(\d{4})/enterprise/[^/]+\.json$")


def fetch() -> dict:
    # Discover the newest KEV mapping file instead of hardcoding it — CTID publishes new snapshots over time.
    tree = get(f"https://api.github.com/repos/{REPO}/git/trees/main?recursive=1", headers=github_headers()).json()
    files = [(m.group(3), m.group(1), m.group(2), t["path"]) for t in tree["tree"] if (m := PATH_RE.match(t["path"]))]
    path = max(files)[-1]  # newest by (year, month, day)
    data = get(f"https://raw.githubusercontent.com/{REPO}/main/{path}").json()
    save_raw(SOURCE, data)
    out: dict[str, list[dict]] = defaultdict(list)
    for m in data["mapping_objects"]:
        if m.get("attack_object_id"):  # some rows are "non_mappable"
            out[m["capability_id"]].append({"id": m["attack_object_id"], "name": m["attack_object_name"], "mapping_type": m["mapping_type"]})
    return dict(out)


def apply(items, mapping: dict) -> None:
    for it in items:
        ids = [t["id"] for c in it.cve_ids for t in mapping.get(c, [])]
        it.attack_techniques = list(dict.fromkeys(it.attack_techniques + ids))  # union, order kept
