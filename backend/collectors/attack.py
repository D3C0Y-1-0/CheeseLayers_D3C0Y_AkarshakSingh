"""MITRE ATT&CK: the catalogue of attacker techniques (T1190 Exploit Public-Facing App, T1566 Phishing, ...).

The STIX bundle is ~45 MB, so we download it once into data/raw/ and reuse it.
Output: data/cache/attack_techniques.json -> [{id, name, tactics, description}]
"""
import json

from .common import RAW, get, log

SOURCE = "attack_techniques"
URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
RAW_FILE = RAW / "attack" / "enterprise-attack.json"


def fetch() -> list[dict]:
    if not RAW_FILE.exists():
        log.info("attack: downloading enterprise-attack.json (~45 MB, once)")
        RAW_FILE.parent.mkdir(parents=True, exist_ok=True)
        RAW_FILE.write_bytes(get(URL).content)
    bundle = json.loads(RAW_FILE.read_text(encoding="utf-8"))
    techniques = []
    for o in bundle["objects"]:
        # STIX 'attack-pattern' = an ATT&CK technique. Skip retired ones.
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext_id = next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if ext_id:
            techniques.append({
                "id": ext_id, "name": o["name"],
                # Tactic = the attacker's goal at that step (initial-access, persistence, exfiltration...).
                "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"],
                "description": o.get("description", ""),
            })
    return sorted(techniques, key=lambda t: t["id"])
