"""Run every collector, enrich + dedupe, write data/cache/threat_items.json and data/cache/iocs.json.

    cd backend && python -m collectors.run_all          # live
    DEMO_MODE=true python -m collectors.run_all         # offline, from data/cache only
    python -m collectors.run_all --from-raw             # offline: re-parse data/raw/* with the collectors' own
                                                        # parsers (after a schema change), enrichment from cache
"""
import sys
import time
from datetime import datetime, timezone

from . import (abusech, attack, attack_mappings, certin, epss, exploits, history, ip_reputation, kev, nvd, nvd_kev,
               otx, ransomware)
from .common import BASE, DEMO_MODE, Skipped, cache_mtime, load_cache, log, mtime, save_cache

FROM_RAW = "--from-raw" in sys.argv
OFFLINE = DEMO_MODE or FROM_RAW
from .schema import IOC, ThreatItem

summary: list[tuple[str, str, str, float]] = []
statuses: list[dict] = []  # -> source_status table


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


def _records(data) -> int | None:
    if data is None:
        return None
    if isinstance(data, dict) and ("items" in data or "iocs" in data):
        return len(data.get("items", [])) + len(data.get("iocs", []))
    return len(data.get("scores", data)) if isinstance(data, dict) else len(data)


def _stamp(data, at: datetime) -> None:
    # One retrieved_at per source run, so a whole fetch shares one "arrived at" time.
    if isinstance(data, dict):
        for x in data.get("items", []) + data.get("iocs", []):
            x.retrieved_at = at


def _stamp_from_raw(data) -> datetime | None:
    # Rebuilt records arrived when their raw file was saved, not now.
    seen: dict[str, datetime] = {}
    for x in data.get("items", []) + data.get("iocs", []):
        if x.raw_ref:
            x.retrieved_at = seen.setdefault(x.raw_ref, mtime(BASE.parent / x.raw_ref))
    return max(seen.values(), default=None)


def run(name: str, fn, *args, raw=None):
    """Run one collector in isolation. Failure falls back to its last cache, so one dead feed never stops the rest.
    raw = the collector's from_raw(), used by --from-raw."""
    t0, started = time.monotonic(), datetime.now(timezone.utc)
    error, attempted, succeeded = None, None, None
    if FROM_RAW and raw:
        try:
            data = raw()
            succeeded = _stamp_from_raw(data)
            save_cache(name, data)
            status = "cache"
        except Exception as e:
            log.warning("%s: rebuild from raw failed: %r — using last cache", name, e)
            data, status, error, succeeded = load_cache(name), "stale", repr(e)[:500], cache_mtime(name)
    elif OFFLINE:
        data = load_cache(name)
        status = "cache" if data is not None else "failed"
        error = None if data is not None else "DEMO_MODE and no cache file"
        succeeded = cache_mtime(name)  # the cached data was fetched when the file was written
    else:
        attempted = started
        try:
            data = fn(*args)
            _stamp(data, started)
            save_cache(name, data)
            status, succeeded = "ok", started
        except Skipped as e:
            data, status, error = None, "skipped", str(e)
        except Exception as e:
            log.warning("%s failed: %r — using last cache", name, e)
            data = load_cache(name)
            status, error = ("stale" if data is not None else "failed"), repr(e)[:500]
    summary.append((name, status + (f": {error}" if error and status != "cache" else ""), _count(data), time.monotonic() - t0))
    statuses.append({"source": name, "status": status, "error": error, "record_count": _records(data),
                     "last_attempt": attempted, "last_success": succeeded})
    return data


def _items(data) -> list[ThreatItem]:
    return [ThreatItem.model_validate(i) for i in (data or {}).get("items", [])]


def merge(nvd_items, nvd_kev_items, kev_items, other_items, scores, signals=None, attack_map=None) -> list[ThreatItem]:
    kev_set = kev.cve_ids(kev_items)
    # Dedupe vulnerabilities by CVE ID. For actively-exploited CVEs the KEV item is the base (CISA's name +
    # required action) and NVD fills in what KEV lacks: CVSS score and CPE version ranges.
    nvd_by_cve = {i.threat_id: i for i in nvd_kev_items} | {i.threat_id: i for i in nvd_items}
    for k in kev_items:
        n = nvd_by_cve.get(k.threat_id)
        if n:
            k.cvss, k.cvss_version, k.severity = n.cvss, n.cvss_version, n.severity
            k.affected_configurations = n.affected_configurations or k.affected_configurations
            k.references = list(dict.fromkeys(k.references + n.references))
            # Original publication = NVD's date; KEV's own date stays in kev_date_added.
            k.published_at, k.nvd_published_at = n.published_at, n.nvd_published_at
            k.raw_refs = list(dict.fromkeys(k.raw_refs + n.raw_refs))  # KEV dump first (primary), then the NVD page
            k.tags = sorted(set(k.tags) | set(n.tags))
    items = kev_items + [i for i in nvd_items if i.threat_id not in kev_set] + other_items
    scored = {c: i for c, i in nvd_by_cve.items() if i.cvss is not None}
    for it in items:
        # KEV catalogue loaded -> every CVE was checked (True/False). No catalogue or no CVE -> None (unknown).
        if it.cve_ids and kev_set:
            it.kev_listed = it.kev_listed or any(c in kev_set for c in it.cve_ids)
        if it.cvss is None and (known := [scored[c] for c in it.cve_ids if c in scored]):
            worst = max(known, key=lambda i: i.cvss)  # advisory is as severe as its worst CVE
            it.cvss, it.cvss_version = worst.cvss, worst.cvss_version
    epss.apply(items, scores)
    exploits.apply(items, signals or {})
    attack_mappings.apply(items, attack_map or {})
    return items


def main() -> None:
    log.info("collectors starting (DEMO_MODE=%s)", DEMO_MODE)
    nvd_d = run("nvd", nvd.fetch, raw=nvd.from_raw)
    nvd_kev_d = run("nvd_kev", nvd_kev.fetch, raw=nvd_kev.from_raw)
    kev_d = run("kev", kev.fetch, raw=kev.from_raw)
    certin_d = run("certin", certin.fetch, raw=certin.from_raw)
    abuse_d = run("abusech", abusech.fetch, raw=abusech.from_raw)
    otx_d = run("otx", otx.fetch, raw=otx.from_raw)
    rep_d = run("ip_reputation", ip_reputation.fetch, raw=ip_reputation.from_raw)
    ransom_d = run("ransomware", ransomware.fetch, raw=ransomware.from_raw)
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
    by_cvss = [i.threat_id for i in sorted(nvd_items, key=lambda i: i.cvss or 0, reverse=True)]
    targets = [c for c in dict.fromkeys(certin_cves + by_cvss) if c not in kev_set]
    signals = run("exploit_signals", exploits.fetch, targets) or {}
    # Lead-time backtest history (what was knowable before each KEV date). Incremental: only missing keys are fetched.
    run("epss_history", history.epss_history, kev_items)
    run("github_poc_dates", history.poc_dates, kev_items, signals)

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

    # Imported here so collectors stay usable without the app package (e.g. a quick single-collector test).
    from ingestion.loader import load, record_source_status
    record_source_status(statuses)
    print("\nDB:", load())


if __name__ == "__main__":
    main()
