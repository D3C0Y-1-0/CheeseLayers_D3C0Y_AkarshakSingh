"""Validate every shared fixture in data/ against data/contracts.json. Exit 1 on any error.

    .venv/bin/python data/validate.py
"""
import csv
import ipaddress
import json
import re
import sys
from collections import Counter
from datetime import date, datetime
from pathlib import Path

DATA = Path(__file__).resolve().parent
C = json.loads((DATA / "contracts.json").read_text())
ENT = C["entities"]
errors: list[str] = []
warnings: list[str] = []


def fields_of(name: str) -> dict:
    e = ENT[name]
    return (fields_of(e["extends"]) if "extends" in e else {}) | e["fields"]


def check(v, spec: dict, path: str) -> None:
    if v is None:
        if not spec.get("nullable"):
            errors.append(f"{path}: null not allowed")
        return
    t = spec["type"]
    if t == "any":
        return
    ok = {"string": isinstance(v, str), "datetime": isinstance(v, str), "date": isinstance(v, str), "ipv4": isinstance(v, str), "enum": isinstance(v, str),
          "integer": isinstance(v, int) and not isinstance(v, bool),
          "number": isinstance(v, (int, float)) and not isinstance(v, bool),
          "boolean": isinstance(v, bool), "array": isinstance(v, list), "object": isinstance(v, dict)}[t]
    if not ok:
        errors.append(f"{path}: expected {t}, got {type(v).__name__} {v!r}")
        return
    if t == "enum" and v not in spec["enum"]:
        errors.append(f"{path}: {v!r} not in {spec['enum']}")
    if t == "datetime":
        try:
            if datetime.fromisoformat(v).tzinfo is None:
                errors.append(f"{path}: timestamp has no UTC offset: {v}")
        except ValueError:
            errors.append(f"{path}: not ISO 8601: {v}")
    if t == "date":
        try:
            date.fromisoformat(v)
        except ValueError:
            errors.append(f"{path}: not YYYY-MM-DD: {v}")
    if t == "ipv4":
        try:
            ipaddress.IPv4Address(v)
        except ValueError:
            errors.append(f"{path}: not IPv4: {v}")
    if "pattern" in spec and not re.match(spec["pattern"], v):
        errors.append(f"{path}: {v!r} does not match {spec['pattern']}")
    if "min" in spec and v < spec["min"] or "max" in spec and v > spec["max"]:
        errors.append(f"{path}: {v} outside [{spec.get('min')}, {spec.get('max')}]")
    if t == "array" and "items" in spec:
        for i, x in enumerate(v):
            check(x, spec["items"], f"{path}[{i}]")
    if t == "object" and "fields" in spec:
        check_record(v, spec["fields"], path)


def check_record(rec: dict, fields: dict, path: str) -> None:
    for k, spec in fields.items():
        if k not in rec:
            errors.append(f"{path}: missing field '{k}'")
        else:
            check(rec[k], spec, f"{path}.{k}")
    for k in rec.keys() - fields.keys():
        warnings.append(f"{path}: extra field '{k}' (allowed as an addition)")


def check_file(entity: str, records: list[dict]) -> list[dict]:
    f, idf = fields_of(entity), ENT[entity]["id_field"]
    for r in records:
        check_record(r, f, f"{entity}[{r.get(idf)}]")
    dupes = [k for k, n in Counter(r.get(idf) for r in records).items() if n > 1]
    if dupes:
        errors.append(f"{entity}: duplicate {idf}: {dupes}")
    return records


def load_csv(entity: str, path: Path) -> list[dict]:
    cast = {"integer": int, "number": float}
    f = fields_of(entity)
    with open(path) as fh:
        rows = list(csv.DictReader(fh))
    out = []
    for r in rows:
        try:
            out.append({k: (cast[f[k]["type"]](v) if k in f and f[k]["type"] in cast else v) for k, v in r.items()})
        except ValueError as e:
            errors.append(f"{entity}[{r.get('window_id')}]: {e}")
    return out


# --- version range sanity check (fixture QA only; the real matcher is Member 3's) ---
def vkey(v: str) -> tuple:
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.\-_]", v.lower()) if p)


def in_range(version: str, cfg: dict) -> bool:
    v = vkey(version)
    if not any(cfg[k] for k in ("version_start_including", "version_start_excluding", "version_end_including", "version_end_excluding")):
        exact = (cfg.get("cpe") or "").split(":")[5:6]
        return not exact or exact[0] == "*" or vkey(exact[0]) == v  # "-" = not applicable, NOT a wildcard
    return ((not cfg["version_start_including"] or v >= vkey(cfg["version_start_including"]))
            and (not cfg["version_start_excluding"] or v > vkey(cfg["version_start_excluding"]))
            and (not cfg["version_end_including"] or v <= vkey(cfg["version_end_including"]))
            and (not cfg["version_end_excluding"] or v < vkey(cfg["version_end_excluding"])))


def matches(asset: dict, configs: list[dict]) -> list[str]:
    hits = []
    for s in asset["software"]:
        for c in configs:
            if (s["vendor"], s["product"]) == (c["vendor"], c["product"]):
                hits.append(f"{s['product']} {s['version']}" + ("" if s["version"] is None or in_range(s["version"], c) else " OUT"))
    return [h for h in hits if not h.endswith(" OUT")]


def main() -> None:
    assets = check_file("asset", json.loads((DATA / "assets.json").read_text()))
    threats = check_file("threat", json.loads((DATA / "threats_synthetic.json").read_text()))
    demo = check_file("demo_cve", json.loads((DATA / "demo_cves.json").read_text()))
    events = check_file("event", json.loads((DATA / "events.json").read_text()))
    windows = check_file("window", load_csv("window", DATA / "windows.csv"))
    ids = {a["asset_id"] for a in assets}
    by_id = {a["asset_id"]: a for a in assets}

    # cross-file references + data-honesty rules
    for e in events:
        if e["asset_id"] is not None and e["asset_id"] not in ids:
            errors.append(f"event[{e['event_id']}]: unknown asset {e['asset_id']}")
    for w in windows:
        if w["asset_id"] not in ids:
            errors.append(f"window[{w['window_id']}]: unknown asset {w['asset_id']}")
    for t in threats:
        if not re.fullmatch(r"DEMO-VULN-\d{3}", t["threat_id"]) or t["cve_id"] is not None \
                or not t["is_simulated"] or not t["title"].startswith("[SIMULATED]"):
            errors.append(f"threat[{t['threat_id']}]: synthetic threat must be DEMO-VULN-NNN, cve_id null, is_simulated, [SIMULATED] title")
        if not any(matches(a, t["affected_configurations"]) for a in assets):
            errors.append(f"threat[{t['threat_id']}]: matches no asset")
    for r in assets + events:
        if r["is_simulated"] is not True:
            errors.append(f"{r.get('asset_id') or r.get('event_id')}: fixtures must be is_simulated=true")

    # Scenario A proof: vulnerable assets inside the real NVD range, patched twins outside it
    for d in demo:
        for a in d["vulnerable_asset_ids"] + d["patched_asset_ids"]:
            if a not in ids:
                errors.append(f"demo_cve[{d['threat_id']}]: unknown asset {a}")
        for a in d["vulnerable_asset_ids"]:
            if a in by_id and not matches(by_id[a], d["affected_configurations"]):
                errors.append(f"demo_cve[{d['threat_id']}]: {a} should be in range but is not")
        for a in d["patched_asset_ids"]:
            if a in by_id and matches(by_id[a], d["affected_configurations"]):
                errors.append(f"demo_cve[{d['threat_id']}]: patched twin {a} is still in range")

    # Noise check: which assets match ANY real KEV CVE in the backend cache (exact NVD ranges)?
    noise = Counter()
    raw = DATA.parent / "backend/data/raw/nvd_kev/all_0.json"
    if raw.exists():
        demo_pairs = {(a, d["threat_id"]) for d in demo for a in d["vulnerable_asset_ids"]}
        for v in json.loads(raw.read_text())["vulnerabilities"]:
            cfgs = []
            for cfg in v["cve"].get("configurations", []):
                for n in cfg["nodes"]:
                    for m in n["cpeMatch"]:
                        p = m["criteria"].split(":")
                        if m["vulnerable"]:
                            cfgs.append({"vendor": p[3], "product": p[4], "cpe": m["criteria"],
                                         **{k: m.get(c) for k, c in [("version_start_including", "versionStartIncluding"),
                                                                    ("version_start_excluding", "versionStartExcluding"),
                                                                    ("version_end_including", "versionEndIncluding"),
                                                                    ("version_end_excluding", "versionEndExcluding")]}})
            for a in assets:
                if (a["asset_id"], v["cve"]["id"]) not in demo_pairs and (h := matches(a, cfgs)):
                    noise[(a["asset_id"], h[0])] += 1

    # --- summary ---
    wc = Counter((w["split"], w["label"]) for w in windows)
    test_n = wc[("test", "normal")] + wc[("test", "suspicious")]
    if wc[("train", "suspicious")]:
        errors.append("windows: train split must be normal only")
    if not 0.03 <= wc[("test", "suspicious")] / max(test_n, 1) <= 0.07:
        errors.append("windows: test split should be ~5% suspicious")
    print(f"contracts.json v{C['contract_version']}  entities: {', '.join(ENT)}\n")
    print(f"{'file':<24}{'records':>8}  notes")
    print("-" * 78)
    print(f"{'assets.json':<24}{len(assets):>8}  sectors {dict(Counter(a['sector'] for a in assets))}")
    print(f"{'threats_synthetic.json':<24}{len(threats):>8}  {[t['threat_id'] for t in threats]}")
    print(f"{'demo_cves.json':<24}{len(demo):>8}  {[d['threat_id'] for d in demo]}")
    print(f"{'events.json':<24}{len(events):>8}  scenarios {dict(Counter(e['details'].get('scenario') for e in events))}")
    print(f"{'windows.csv':<24}{len(windows):>8}  train {wc[('train', 'normal')]} normal | test {wc[('test', 'normal')]} normal + "
          f"{wc[('test', 'suspicious')]} suspicious ({wc[('test', 'suspicious')] / max(test_n, 1):.1%})")
    print("\nScenario A version check (real NVD ranges):")
    for d in demo:
        hit = ", ".join(f"{a} ({matches(by_id[a], d['affected_configurations'])[0]})" for a in d["vulnerable_asset_ids"])
        safe = ", ".join(f"{a} ({next(s['version'] for s in by_id[a]['software'] if any((s['vendor'], s['product']) == (c['vendor'], c['product']) for c in d['affected_configurations']))})"
                         for a in d["patched_asset_ids"])
        print(f"  {d['threat_id']:<15} MATCH {hit}\n  {'':<15} SAFE  {safe}")
    print("\nSynthetic threat matches:")
    for t in threats:
        print(f"  {t['threat_id']:<15} -> {[(a['asset_id'], matches(a, t['affected_configurations'])) for a in assets if matches(a, t['affected_configurations'])]}")
    if raw.exists():
        print(f"\nOther KEV matches on fixture assets (null-version software counts as 'uncertain'): {len(noise)} asset/product pairs")
        for (a, h), n in sorted(noise.items()):
            print(f"  {a:<12} {h:<32} {n} KEV CVE(s)")
    print(f"\n{len(errors)} error(s), {len(warnings)} warning(s)")
    for w in sorted(set(re.sub(r"\[.*?\]", "[*]", w) for w in warnings)):
        print("  warn:", w)
    for e in errors:
        print("  ERROR:", e)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
