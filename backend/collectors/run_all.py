"""Run every collector, enrich + dedupe, write data/cache/threat_items.json and data/cache/iocs.json.

    cd backend && python -m collectors.run_all          # live
    DEMO_MODE=true python -m collectors.run_all         # offline, from data/cache only
"""
import time

from . import abusech, attack, attack_mappings, certin, epss, exploits, ip_reputation, kev, nvd, nvd_kev, otx, ransomware
from .common import DEMO_MODE, Skipped, load_cache, log, save_cache
from .schema import IOC, ThreatItem

summary: list[tuple[str, str, str, float]] = []


def _count(data) -> str:
    if isinstance(data, list):
        return str(len(data))
    if not data:
        return "0"
    if "scores" in data:
        return str(len(data["scores"]))
    if "items" not in data:
        return str(len(data))  # plain {cve: ...} maps (exploit signals, ATT&CK map)
    return f"{len(data.get('items', []))}" + (f" (+{len(data['iocs'])} IOCs)" if data.get("iocs") else "")


def run(name: str, fn, *args):
    """Run one collector in isolation. Failure falls back to its last cache, so one dead feed never stops the rest."""
    t0 = time.monotonic()
    if DEMO_MODE:
        data = load_cache(name)
        status = "cache" if data is not None else "no cache"
    else:
        try:
            data = fn(*args)
            save_cache(name, data)
            status = "ok"
        except Skipped as e:
            data, status = None, f"skipped: {e}"
        except Exception as e:
            log.warning("%s failed: %r — using last cache", name, e)
            data = load_cache(name)
            status = "failed, stale cache" if data is not None else f"failed: {type(e).__name__}"
    summary.append((name, status, _count(data), time.monotonic() - t0))
    return data


def _items(data) -> list[ThreatItem]:
    return [ThreatItem.model_validate(i) for i in (data or {}).get("items", [])]


def merge(nvd_items, nvd_kev_items, kev_items, other_items, scores, signals=None, attack_map=None) -> list[ThreatItem]:
    kev_set = kev.cve_ids(kev_items)
    # Dedupe vulnerabilities by CVE ID. For actively-exploited CVEs the KEV item is the base (CISA's name +
    # required action) and NVD fills in what KEV lacks: CVSS score and CPE version ranges.
    nvd_by_cve = {i.id: i for i in nvd_kev_items} | {i.id: i for i in nvd_items}
    for k in kev_items:
        n = nvd_by_cve.get(k.id)
        if n:
            k.cvss, k.severity = n.cvss, n.severity
            k.affected = n.affected or k.affected
            k.tags = sorted(set(k.tags) | set(n.tags))
    items = kev_items + [i for i in nvd_items if i.id not in kev_set] + other_items
    cvss_by_cve = {c: i.cvss for c, i in nvd_by_cve.items() if i.cvss is not None}
    for it in items:
        it.in_kev = it.in_kev or any(c in kev_set for c in it.cve_ids)
        if it.cvss is None and (known := [cvss_by_cve[c] for c in it.cve_ids if c in cvss_by_cve]):
            it.cvss = max(known)  # advisory is as severe as its worst CVE
    epss.apply(items, scores)
    exploits.apply(items, signals or {})
    attack_mappings.apply(items, attack_map or {})
    return items


def main() -> None:
    log.info("collectors starting (DEMO_MODE=%s)", DEMO_MODE)
    nvd_d = run("nvd", nvd.fetch)
    nvd_kev_d = run("nvd_kev", nvd_kev.fetch)
    kev_d = run("kev", kev.fetch)
    certin_d = run("certin", certin.fetch)
    abuse_d = run("abusech", abusech.fetch)
    otx_d = run("otx", otx.fetch)
    rep_d = run("ip_reputation", ip_reputation.fetch)
    ransom_d = run("ransomware", ransomware.fetch)
    run("attack_techniques", attack.fetch)
    attack_map = run("kev_attack_map", attack_mappings.fetch) or {}

    nvd_items, nvd_kev_items, kev_items = _items(nvd_d), _items(nvd_kev_d), _items(kev_d)
    other = _items(certin_d) + _items(abuse_d) + _items(otx_d) + _items(rep_d) + _items(ransom_d)
    cves = [c for i in nvd_items + kev_items + other for c in i.cve_ids]
    epss_d = run("epss", epss.fetch, cves) or {"scores": {}}
    # Vulnrichment fetch priority: CERT-In CVEs first (the India story), then the most severe recent CVEs.
    # KEV CVEs are skipped there: their exploitation status is already "active".
    kev_set = kev.cve_ids(kev_items)
    certin_cves = [c for i in _items(certin_d) for c in i.cve_ids]
    by_cvss = [i.id for i in sorted(nvd_items, key=lambda i: i.cvss or 0, reverse=True)]
    targets = [c for c in dict.fromkeys(certin_cves + by_cvss) if c not in kev_set]
    signals = run("exploit_signals", exploits.fetch, targets) or {}

    t0 = time.monotonic()
    items = merge(nvd_items, nvd_kev_items, kev_items, other, epss_d["scores"], signals, attack_map)
    seen, iocs = set(), []
    for d in (abuse_d, otx_d, rep_d):
        for raw in (d or {}).get("iocs", []):
            i = IOC.model_validate(raw)
            if (i.ioc_type, i.value) not in seen:  # same IOC from two feeds: keep the first
                seen.add((i.ioc_type, i.value))
                iocs.append(i)
    save_cache("threat_items", items)
    save_cache("iocs", iocs)
    summary.append(("merge", "ok", f"{len(items)} (+{len(iocs)} IOCs)", time.monotonic() - t0))

    print(f"\n{'source':<18} | {'status':<28} | {'count':>22} | duration")
    print("-" * 82)
    for name, status, count, dur in summary:
        print(f"{name:<18} | {status[:28]:<28} | {count:>22} | {dur:6.1f}s")


if __name__ == "__main__":
    main()
