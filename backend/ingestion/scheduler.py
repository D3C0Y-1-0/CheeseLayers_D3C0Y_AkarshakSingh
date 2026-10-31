"""In-process feed scheduler (APScheduler), started by the FastAPI lifespan. Never runs in DEMO_MODE.

Each job fetches only its own sources live, re-merges everything else from cache, loads the DB and runs change
detection (-> threat_signals + on_new_threat). NVD is always incremental here (lastModStartDate since its last
success): the 30-day full fetch only happens on a manual `python -m collectors.run_all`.
"""
import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler

from collectors.common import DEMO_MODE

log = logging.getLogger("scheduler")

# job -> (every N hours, sources fetched live)
JOBS: dict[str, tuple[float, set[str]]] = {
    "kev": (1, {"kev", "nvd_kev", "epss_history", "github_poc_quality"}),  # + NVD records for newly added KEV CVEs
    "nvd": (2, {"nvd"}),  # incremental: also refreshes nvd_kev.json
    "epss": (24, {"epss", "exploit_signals", "github_poc_quality"}),  # daily scores + new exploits / PoCs
    "certin": (6, {"certin"}),
    "abusech": (1, {"abusech"}),
}
STAGGER = timedelta(minutes=2)  # first runs spaced out so a restart doesn't fire five fetches at once


def run_job(name: str) -> dict:
    from collectors.run_all import pipeline  # heavy import, only when a job actually runs
    try:
        out = pipeline(JOBS[name][1], nvd_mode="incremental")
        log.info("job %s done: %s", name, out["db"])
        return out
    except Exception:
        log.exception("job %s failed", name)  # source_status already records per-source failures
        return {}


def first_run(name: str, now: datetime, i: int) -> datetime:
    """Next due time = last success + interval (never in the past), so restarts don't refetch fresh sources."""
    from ingestion.loader import last_success
    hours, live = JOBS[name]
    soonest = now + STAGGER * (i + 1)
    last = min(filter(None, (last_success(s) for s in live)), default=None)
    return max(soonest, last + timedelta(hours=hours)) if last else soonest


def start() -> BackgroundScheduler | None:
    if DEMO_MODE:
        log.info("DEMO_MODE: scheduler disabled (offline, cache only)")
        return None
    now = datetime.now(timezone.utc)
    sched = BackgroundScheduler(timezone="UTC", job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 3600})
    for i, (name, (hours, _)) in enumerate(JOBS.items()):
        sched.add_job(run_job, "interval", hours=hours, args=[name], id=name, name=name, next_run_time=first_run(name, now, i))
    sched.start()
    log.info("scheduler started: %s", {j.id: j.next_run_time.isoformat() for j in sched.get_jobs()})
    return sched
