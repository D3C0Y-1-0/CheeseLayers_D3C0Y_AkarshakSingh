"""Run every collector, enrich + dedupe, write data/cache/threat_items.json and data/cache/iocs.json.

    cd backend && python -m collectors.run_all          # live
    DEMO_MODE=true python -m collectors.run_all         # offline, from data/cache only
    python -m collectors.run_all --from-raw             # offline: re-parse data/raw/* with the collectors' own
                                                        # parsers (after a schema change), enrichment from cache
"""
import sys
import threading
import time
from datetime import datetime, timezone

from . import (abusech, attack, attack_mappings, certin, epss, exploits, history, ip_reputation, kev, nvd, nvd_kev,
               otx, ransomware)
from .common import BASE, DEMO_MODE, Skipped, cache_mtime, load_cache, log, mtime, save_cache
from .schema import IOC, ThreatItem

FROM_RAW = "--from-raw" in sys.argv
OFFLINE = DEMO_MODE or FROM_RAW
# ponytail: one global lock = one pipeline at a time (scheduler jobs + manual runs share caches and the DB).
# Fine at hourly cadence; per-source locks only if jobs ever need to overlap.
LOCK = threading.Lock()


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


class Run:
    """One pipeline run. live = sources to fetch now (None = all); the rest come from cache, unrecorded."""

    def __init__(self, live: set[str] | None):
        self.live, self.summary, self.statuses = live, [], []

    def __call__(self, name: str, fn, *args, raw=None):
        """Run one collector in isolation. Failure falls back to its last cache, so one dead feed never stops the rest.
        raw = the collector's from_raw(), used by --from-raw."""
        if self.live is not None and name not in self.live and not OFFLINE:
            return load_cache(name)  # scheduler job for another source: just read the cache, don't touch its status
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
        self.summary.append((name, status + (f": {error}" if error and status != "cache" else ""), _count(data), time.monotonic() - t0))
        self.statuses.append({"source": name, "status": status, "error": error, "record_count": _records(data),
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


def _last_success(source: str) -> datetime | None:
    from ingestion.loader import last_success  # app package is optional for single collectors
    return last_success(source) or cache_mtime(source)


def nvd_incremental(kev_set: set[str]) -> dict:
    """Scheduler NVD job: only CVEs modified since the last success (never the full window).
    Updates nvd_kev.json too, so KEV records get NVD's latest CVSS/CPEs."""
    since = _last_success("nvd") or datetime.now(timezone.utc)
    upd = nvd.modified_since(since)
    now = datetime.now(timezone.utc)
    for x in upd:
        x.retrieved_at = now
    kev_cache = [ThreatItem.model_validate(i) for i in (load_cache("nvd_kev") or {}).get("items", [])]
    save_cache("nvd_kev", {"items": nvd.apply_updates(kev_cache, upd, nvd_kev.in_kev(kev_set))})
    base = [ThreatItem.model_validate(i) for i in (load_cache("nvd") or {}).get("items", [])]
    log.info("nvd incremental: %d modified since %s", len(upd), since.isoformat())
    return {"items": nvd.apply_updates(base, upd, nvd.keep_recent(now))}


def kev_nvd_missing(kev_set: set[str]) -> dict:
    """KEV job: fetch NVD records for KEV CVEs nvd_kev.json lacks (a CVE CISA just added), so it gets CVSS + CPEs."""
    cache = [ThreatItem.model_validate(i) for i in (load_cache("nvd_kev") or {}).get("items", [])]
    missing = sorted(kev_set - {i.threat_id for i in cache})[:50]  # ponytail: cap per run; KEV adds ~1-5/day
    upd = nvd.by_ids(missing) if missing else []
    if upd:  # same rule as the replay in nvd.from_raw: these pages update nvd.json too
        base = [ThreatItem.model_validate(i) for i in (load_cache("nvd") or {}).get("items", [])]
        save_cache("nvd", {"items": nvd.apply_updates(base, upd, nvd.keep_recent(datetime.now(timezone.utc)))})
    return {"items": nvd.apply_updates(cache, upd, nvd_kev.in_kev(kev_set))}


def pipeline(live: set[str] | None = None, nvd_mode: str = "full") -> dict:
    """Fetch `live` sources (None = all; ignored offline), re-merge everything from caches, load the DB and run
    change detection. nvd_mode="incremental" = scheduler (lastModStartDate), "full" = the 30-day window."""
    with LOCK:
        return _pipeline(Run(live), nvd_mode)


def _pipeline(run: Run, nvd_mode: str) -> dict:
    log.info("collectors starting (DEMO_MODE=%s, live=%s)", DEMO_MODE, sorted(run.live) if run.live else "all")
    kev_d = run("kev", kev.fetch, raw=kev.from_raw)
    kev_set = kev.cve_ids(_items(kev_d))
    if nvd_mode == "incremental":
        nvd_d = run("nvd", nvd_incremental, kev_set)
        nvd_kev_d = run("nvd_kev", kev_nvd_missing, kev_set)
    else:
        nvd_d = run("nvd", nvd.fetch, raw=nvd.from_raw)
        nvd_kev_d = run("nvd_kev", nvd_kev.fetch, raw=nvd_kev.from_raw)
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
    certin_cves = [c for i in _items(certin_d) for c in i.cve_ids]
    by_cvss = [i.threat_id for i in sorted(nvd_items, key=lambda i: i.cvss or 0, reverse=True)]
    targets = [c for c in dict.fromkeys(certin_cves + by_cvss) if c not in kev_set]
    prev_signals = load_cache("exploit_signals") or {}
    signals = run("exploit_signals", exploits.fetch, targets) or {}
    # Lead-time backtest history (what was knowable before each KEV date). Incremental: only missing keys are fetched.
    run("epss_history", history.epss_history, kev_items)
    # PoC quality check for: the backtest population + CVEs whose GitHub PoC just appeared (-> new_public_exploit).
    published = {i.threat_id: i.nvd_published_at.date() for i in nvd_kev_items + nvd_items if i.nvd_published_at}
    newly_poc = [c for c, v in signals.items() if v.get("github_poc") and not (prev_signals.get(c) or {}).get("github_poc")]
    pop = [c for c, _ in history.population(kev_items, history.LEAD_TIME["max_window_days"])
           if (signals.get(c) or {}).get("github_poc")]
    run("github_poc_quality", history.poc_quality, newly_poc + pop, published)

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
    run.summary.append(("merge", "ok", f"{len(items)} (+{len(iocs)} IOCs)", time.monotonic() - t0))

    # Imported here so collectors stay usable without the app package (e.g. a quick single-collector test).
    from ingestion.loader import load, record_source_status
    record_source_status(run.statuses)
    result = load(detect=True)  # diff vs the previous DB state -> threat_signals + on_new_threat hook
    return {"summary": run.summary, "db": result}


def main() -> None:
    out = pipeline()
    print(f"\n{'source':<18} | {'status':<28} | {'count':>22} | duration")
    print("-" * 82)
    for name, status, count, dur in out["summary"]:
        print(f"{name:<18} | {status[:28]:<28} | {count:>22} | {dur:6.1f}s")
    print("\nDB:", out["db"])


if __name__ == "__main__":
    main()
