"""History for the lead-time backtest (GET /api/insights/lead-time): what was knowable BEFORE CISA added a CVE to KEV.

- epss_history.json     {cve: {"YYYY-MM-DD": epss | null}}  EPSS sampled at kev_date_added - N days (N in epss_offsets_days).
                        null = FIRST had no score for that CVE on that day (e.g. not published yet).
- github_poc_dates.json {cve: earliest created_at of a PoC repo in nomi-sec/PoC-in-GitHub | null}
Past values never change, so each run only fetches keys we don't have yet (cheap re-runs).
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone

from .common import get, load_cache, log, save_raw

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


def poc_dates(kev_items, signals: dict) -> dict:
    dates: dict[str, str | None] = load_cache("github_poc_dates") or {}
    todo = [c for c, _ in population(kev_items, LEAD_TIME["max_window_days"])
            if (signals.get(c) or {}).get("github_poc") and c not in dates]

    def one(cve: str) -> None:
        try:
            repos = get(POC_RAW.format(year=cve.split("-")[1], cve=cve), min_interval=0).json()
            dates[cve] = min((r["created_at"] for r in repos if r.get("created_at")), default=None)
        except Exception as e:  # one missing file shouldn't drop the rest; unknown stays absent -> retried next run
            log.warning("github_poc_dates: %s failed (%s)", cve, e)

    with ThreadPoolExecutor(8) as pool:
        list(pool.map(one, todo))
    log.info("github_poc_dates: %d fetched, %d known", len(todo), len(dates))
    return dates
