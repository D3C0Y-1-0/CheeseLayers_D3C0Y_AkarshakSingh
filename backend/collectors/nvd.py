"""NVD (US National Vulnerability Database): every CVE published in the last N days, with CVSS + CPEs."""
from datetime import datetime, timedelta, timezone

import json

from .common import RAW, env, get, log, mtime, raw_pages, ref, save_raw
from .schema import AffectedConfiguration, ThreatItem, severity

SOURCE = "nvd"
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DAYS = 30
PAGE = 2000  # NVD max
WINDOW = timedelta(days=120)  # NVD rejects date ranges longer than 120 days


def _cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """(score, severity, version). CVSS = 0-10 "how bad could this be".
    Prefer v3.1, fall back to v3.0, v2, then v4.0 (newer CNAs often only send v4). None = not scored yet."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2", "cvssMetricV40"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        m = next((e for e in entries if e.get("type") == "Primary"), entries[0])  # Primary = NVD's own score
        data = m["cvssData"]
        return data.get("baseScore"), severity(data.get("baseSeverity") or m.get("baseSeverity")), data.get("version")  # v2 keeps severity outside cvssData
    return None, None, None


BOUNDS = {"version_start_including": "versionStartIncluding", "version_start_excluding": "versionStartExcluding",
          "version_end_including": "versionEndIncluding", "version_end_excluding": "versionEndExcluding"}


def _affected(cve: dict) -> list[AffectedConfiguration]:
    # CPE format: cpe:2.3:<part>:<vendor>:<product>:<version>:...  (part a=app, o=OS, h=hardware)
    # One entry per NVD cpeMatch, bounds copied verbatim, so the correlator sees exactly what NVD says.
    out = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue  # non-vulnerable entries are just "running on" context, e.g. the OS under an app
                p = m["criteria"].split(":")
                c = AffectedConfiguration(vendor=p[3], product=p[4], cpe=m["criteria"], **{k: m.get(v) for k, v in BOUNDS.items()})
                if c not in out:
                    out.append(c)
    return out


def _item(cve: dict, raw_ref: str) -> ThreatItem:
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), None)
    cvss, sev, version = _cvss(cve.get("metrics", {}))
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w["description"] if d["value"].startswith("CWE-")})
    short = (desc or "")[:100] + ("…" if len(desc or "") > 100 else "")
    return ThreatItem(
        threat_id=cve["id"], cve_id=cve["id"], source=SOURCE, type="vulnerability",
        title=f"{cve['id']}: {short}" if short else cve["id"],
        description=desc, published_at=cve["published"] + "Z", nvd_published_at=cve["published"] + "Z",  # NVD: UTC, no suffix
        references=list(dict.fromkeys([f"https://nvd.nist.gov/vuln/detail/{cve['id']}"] + [r["url"] for r in cve.get("references", [])])),
        cve_ids=[cve["id"]], cvss=cvss, cvss_version=version, severity=sev, affected_configurations=_affected(cve),
        tags=cwes,  # CWE = the *kind* of bug (CWE-79 XSS, CWE-787 out-of-bounds write…)
        raw_ref=raw_ref,
    )


def query(params: dict, source: str = SOURCE, url: str = URL, name: str | None = None) -> list[ThreatItem]:
    """All pages of one NVD query (startIndex pagination), normalised. Also used by nvd_kev.py."""
    key = env("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    # Public limit: 5 requests / 30 s (50 with a key). Space requests to stay under it.
    interval = 0.7 if key else 6.5
    items: list[ThreatItem] = []
    idx = 0
    while True:
        data = get(url, params={**params, "startIndex": idx, "resultsPerPage": PAGE}, headers=headers, min_interval=interval).json()
        ref = save_raw(source, data, f"{name or params.get('pubStartDate', 'all')[:10]}_{idx}")
        items += [_item(v["cve"], ref) for v in data["vulnerabilities"]]
        log.info("%s: %d/%d", source, min(idx + PAGE, data["totalResults"]), data["totalResults"])
        idx += PAGE
        if idx >= data["totalResults"]:
            return items


def from_raw(source: str = SOURCE, keep=None) -> dict:
    """Rebuild from the newest full run's pages in data/raw/<source>/, then replay incremental pages saved after it
    (data/raw/nvd_incremental/) with the same rule the scheduler used. No network."""
    pages = raw_pages(source)
    items = [_item(v["cve"], ref(f)) for f in pages for v in json.loads(f.read_text())["vulnerabilities"]]
    base_time = max(mtime(f) for f in pages)
    for f in sorted((RAW / INC).glob("*.json"), key=mtime):
        if mtime(f) > base_time:
            upd = [_item(v["cve"], ref(f)) for v in json.loads(f.read_text())["vulnerabilities"]]
            items = apply_updates(items, upd, keep or keep_recent(mtime(f)))
    return {"items": items}


# ---------- incremental (scheduler): never refetch the full window ----------
INC = "nvd_incremental"  # raw dir for incremental pages (kept apart so full-run page groups stay intact)


def keep_recent(at: datetime):
    """nvd.json holds CVEs *published* in the last DAYS days: a modified old CVE is not added, only updated."""
    return lambda i: i.published_at is not None and i.published_at >= at - timedelta(days=DAYS)


def apply_updates(base: list[ThreatItem], updates: list[ThreatItem], keep) -> list[ThreatItem]:
    """Replace records we already have; add new ones only if keep(item). Order: existing first, then additions."""
    by_id = {i.threat_id: i for i in base}
    for u in updates:
        if u.threat_id in by_id or keep(u):
            by_id[u.threat_id] = u
    return list(by_id.values())


def modified_since(since: datetime) -> list[ThreatItem]:
    """CVEs NVD added or changed since `since` (1 h overlap for NVD's indexing lag; NVD caps ranges at 120 days)."""
    end = datetime.now(timezone.utc)
    start = max(since - timedelta(hours=1), end - WINDOW + timedelta(minutes=1))
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    return query({"lastModStartDate": start.strftime(fmt), "lastModEndDate": end.strftime(fmt)}, source=INC,
                 name=f"mod_{end:%Y%m%dT%H%M%S}")


def by_ids(cves: list[str]) -> list[ThreatItem]:
    """Single-CVE lookups, e.g. a CVE CISA just added to KEV that our nvd_kev cache doesn't have yet."""
    return [i for c in cves for i in query({"cveId": c}, source=INC, name=f"cve_{c}")]


def fetch() -> dict:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=DAYS)
    items: list[ThreatItem] = []
    while start < end:
        w_end = min(start + WINDOW, end)
        items += query({"pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"), "pubEndDate": w_end.strftime("%Y-%m-%dT%H:%M:%S.000")})
        start = w_end
    return {"items": items}
