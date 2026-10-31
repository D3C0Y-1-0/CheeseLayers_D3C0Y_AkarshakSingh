"""History for the lead-time backtest (GET /api/insights/lead-time): what was knowable BEFORE CISA added a CVE to KEV.

- epss_history.json     {cve: {"YYYY-MM-DD": epss | null}}  EPSS sampled at kev_date_added - N days (N in epss_offsets_days).
                        null = FIRST had no score for that CVE on that day (e.g. not published yet).
- github_poc_quality.json {cve: {ok, first_ok_repo, first_ok_created_at, ...}}: PoC-in-GitHub repos that pass the
                        quality filter (real code, not older than the CVE). Used by the backtest and new_public_exploit.
Past values never change, so each run only fetches keys we don't have yet (cheap re-runs).
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone

import re

import httpx

from .common import get, github_headers, load_cache, log, save_raw

# The ONE config for the backtest: collectors use it to decide what history to fetch, the API to score it.
LEAD_TIME = {
    "epss_threshold": 0.1,  # EPSS >= 10% chance of exploitation in 30 days counts as an early warning
    "epss_offsets_days": [1, 3, 7, 14, 30, 60, 90],  # EPSS sampled this many days before kev_date_added
    "max_window_days": 180,  # history is collected for KEV additions this far back; the endpoint's `days` <= this
    "new_cve_max_age_days": 365,  # cohort split: "new" = NVD-published at most this long before its KEV date
    # A PoC repo created long before the CVE was published is a reused/renamed repo, not evidence the PoC existed then.
    "poc_max_days_before_publication": 30,
    "signals": ["epss", "exploitdb", "github_poc", "certin"],
}
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_FIRST_DAY = date(2021, 4, 14)  # FIRST's history starts here
POC_RAW = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"
POC_MAX = 400  # ponytail: per-run cap on CVEs quality-checked (GitHub API budget); the cache makes later runs cheap


def population(kev_items, days: int, today: date | None = None) -> list[tuple[str, date]]:
    """(cve, kev_date_added) for CVEs CISA added to KEV in the last `days` days."""
    today = today or datetime.now(timezone.utc).date()
    out = []
    for k in kev_items:
        d = k.kev_date_added if not isinstance(k, dict) else (date.fromisoformat(k["kev_date_added"]) if k.get("kev_date_added") else None)
        cve = k.cve_id if not isinstance(k, dict) else k["cve_id"]
        if d and cve and 0 <= (today - d).days <= days:
            out.append((cve, d))
    return out


def epss_history(kev_items) -> dict:
    hist: dict[str, dict[str, float | None]] = load_cache("epss_history") or {}
    want: dict[str, set[str]] = {}  # sample date -> CVEs missing a value for it
    for cve, added in population(kev_items, LEAD_TIME["max_window_days"]):
        for off in LEAD_TIME["epss_offsets_days"]:
            d = added - timedelta(days=off)
            if d >= EPSS_FIRST_DAY and d.isoformat() not in hist.get(cve, {}):
                want.setdefault(d.isoformat(), set()).add(cve)
    for n, (d, cves) in enumerate(sorted(want.items())):
        cves = sorted(cves)
        for i in range(0, len(cves), 100):  # API max 100 CVEs per call
            data = get(EPSS_URL, params={"cve": ",".join(cves[i:i + 100]), "date": d}, min_interval=0.3).json()
            if n == 0 and i == 0:
                save_raw("epss_history", data, "sample")
            got = {r["cve"]: float(r["epss"]) for r in data["data"]}
            for c in cves[i:i + 100]:
                hist.setdefault(c, {})[d] = got.get(c)
        if n % 50 == 0:
            log.info("epss_history: %d/%d dates", n + 1, len(want))
    return hist


# Files that are NOT code: a repo holding only these is a placeholder / write-up, not a working PoC.
DOC_NAME = re.compile(r"^(readme|license|licence|changelog|contributing|code_of_conduct|security|notice|authors)(\..*)?$", re.I)
DOC_EXT = {".md", ".txt", ".rst", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".pdf", ".mp4", ".webp", ".ico"}


def _has_code(full_name: str) -> bool | None:
    """True if the repo's git tree has >= 1 file that isn't README/LICENSE/docs/images. None = couldn't check."""
    try:
        tree = get(f"https://api.github.com/repos/{full_name}/git/trees/HEAD?recursive=1",
                   headers=github_headers(), min_interval=0.2).json()
    except httpx.HTTPStatusError as e:
        return False if e.response.status_code in (404, 409, 451) else None  # deleted / empty / blocked repo
    except Exception:
        return None
    for t in tree.get("tree", []):
        name = t["path"].rsplit("/", 1)[-1]
        if t["type"] == "blob" and not name.startswith(".") and not DOC_NAME.match(name) \
                and not any(name.lower().endswith(x) for x in DOC_EXT):
            return True
    return False


def poc_quality(cves: list[str], published: dict[str, date | None]) -> dict:
    """{cve: {ok, first_ok_repo, first_ok_created_at, repos, checked_at}} for PoC-in-GitHub CVEs.

    A PoC counts only if its repo has >= 1 non-README code file AND was created no earlier than the CVE's NVD
    publication minus `poc_max_days_before_publication` (older = reused/renamed repo). Repos are tried oldest
    first and we stop at the first good one, so `first_ok_created_at` is the earliest credible PoC date.
    A CVE is re-checked only when its repo count changes. ok=None (unknown) is not cached -> retried next run.
    """
    out: dict = load_cache("github_poc_quality") or {}
    grace = timedelta(days=LEAD_TIME["poc_max_days_before_publication"])

    def one(cve: str) -> None:
        try:
            repos = get(POC_RAW.format(year=cve.split("-")[1], cve=cve), min_interval=0).json()
        except Exception as e:
            log.warning("github_poc_quality: %s list failed (%s)", cve, e)
            return
        if cve in out and out[cve]["repos"] == len(repos):
            return  # nothing new since last check
        floor = (published.get(cve) or date(int(cve.split("-")[1]), 1, 1)) - grace
        result = {"ok": False, "first_ok_repo": None, "first_ok_created_at": None, "repos": len(repos),
                  "floor": floor.isoformat(), "checked_at": datetime.now(timezone.utc).isoformat()}
        for r in sorted((r for r in repos if r.get("created_at")), key=lambda r: r["created_at"]):
            if date.fromisoformat(r["created_at"][:10]) < floor:
                continue  # older than the CVE itself: not evidence of an early PoC
            code = _has_code(r["full_name"])
            if code is None:
                return  # rate limit / network: unknown, don't cache a wrong "no"
            if code:
                result.update(ok=True, first_ok_repo=r["full_name"], first_ok_created_at=r["created_at"])
                break
        out[cve] = result

    todo = list(dict.fromkeys(cves))[:POC_MAX]
    with ThreadPoolExecutor(4) as pool:
        list(pool.map(one, todo))
    log.info("github_poc_quality: %d checked, %d known, %d pass", len(todo), len(out), sum(v["ok"] for v in out.values()))
    return out
