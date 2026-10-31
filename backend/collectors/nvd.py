"""NVD (US National Vulnerability Database): every CVE published in the last N days, with CVSS + CPEs."""
from datetime import datetime, timedelta, timezone

from .common import env, get, log, save_raw
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
        description=desc, published_at=cve["published"] + "Z",  # NVD timestamps are UTC without a suffix
        references=list(dict.fromkeys([f"https://nvd.nist.gov/vuln/detail/{cve['id']}"] + [r["url"] for r in cve.get("references", [])])),
        cve_ids=[cve["id"]], cvss=cvss, cvss_version=version, severity=sev, affected_configurations=_affected(cve),
        tags=cwes,  # CWE = the *kind* of bug (CWE-79 XSS, CWE-787 out-of-bounds write…)
        raw_ref=raw_ref,
    )


def query(params: dict, source: str = SOURCE, url: str = URL) -> list[ThreatItem]:
    """All pages of one NVD query (startIndex pagination), normalised. Also used by nvd_kev.py."""
    key = env("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    # Public limit: 5 requests / 30 s (50 with a key). Space requests to stay under it.
    interval = 0.7 if key else 6.5
    items: list[ThreatItem] = []
    idx = 0
    while True:
        data = get(url, params={**params, "startIndex": idx, "resultsPerPage": PAGE}, headers=headers, min_interval=interval).json()
        ref = save_raw(source, data, f"{params.get('pubStartDate', 'all')[:10]}_{idx}")
        items += [_item(v["cve"], ref) for v in data["vulnerabilities"]]
        log.info("%s: %d/%d", source, min(idx + PAGE, data["totalResults"]), data["totalResults"])
        idx += PAGE
        if idx >= data["totalResults"]:
            return items


def fetch() -> dict:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=DAYS)
    items: list[ThreatItem] = []
    while start < end:
        w_end = min(start + WINDOW, end)
        items += query({"pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"), "pubEndDate": w_end.strftime("%Y-%m-%dT%H:%M:%S.000")})
        start = w_end
    return {"items": items}
