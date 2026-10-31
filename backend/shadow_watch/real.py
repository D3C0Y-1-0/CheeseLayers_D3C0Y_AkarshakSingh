"""REAL Shadow Watch scenarios: real one-minute windows from SecRepo (data/cache/secrepo.json), chosen by what our
rules and the Isolation Forest find in them, replayed against one of our assets.

  real_ssh_bruteforce         the busiest minutes of real SSH password guessing (rule SW-AUTH-001)
  real_ssh_distributed_spray  minutes where many IPs each try a few logins: under the rule's threshold, caught by the
                              Isolation Forest only (SW-ML-001)
  real_web_crawler            minutes where one automated client walks the site and guesses paths (mostly 404s): no
                              attack payload, so no rule fires;
                              caught by the Isolation Forest only (SW-ML-001)

The windows are real (counts, usernames, timestamps); the asset they are replayed against is from our simulated
inventory, so the events are marked is_simulated=true (the traffic never reached OUR asset).
"""
from datetime import datetime, timedelta
from functools import lru_cache

from . import ml

SCENARIOS = ("real_ssh_bruteforce", "real_ssh_distributed_spray", "real_web_crawler")
TARGET = {"ssh": "GOV-VPN-01", "web": "HLT-WEB-01"}
KIND = {"real_ssh_bruteforce": "ssh", "real_ssh_distributed_spray": "ssh", "real_web_crawler": "web"}


def _at(w: dict) -> datetime:
    return datetime.fromisoformat(w["minute"])


def _run(windows: list[dict], anchor: dict, minutes: int, keep) -> list[dict]:
    """The anchor window plus following windows within `minutes` that also satisfy `keep`."""
    end = _at(anchor) + timedelta(minutes=minutes)
    return [w for w in windows if _at(anchor) <= _at(w) <= end and (w is anchor or keep(w))]


@lru_cache(maxsize=4)
def windows_for(scenario: str) -> tuple[dict, ...]:
    kind = KIND[scenario]
    train, test = ml.split(kind)
    pool = train + test
    if not pool:
        return ()
    if scenario == "real_ssh_bruteforce":
        peak = max(pool, key=lambda w: (w["failed_logins"], w["minute"]))
        return tuple(_run(pool, peak, 4, lambda w: w["failed_logins"] >= 10))
    scored = [(ml.score_features(kind, ml.window_features(kind, w)), w) for w in test]  # held-out days only
    if scenario == "real_ssh_distributed_spray":
        cands = [(s, w) for s, w in scored if s and s["flagged"] and w["failed_logins"] < 10 and w["unique_sources"] >= 3]
    else:
        cands = [(s, w) for s, w in scored if s and s["flagged"] and w["attack_hits"] == 0 and w["unique_clients"] <= 2]
    if not cands:
        return ()
    _, top = min(cands, key=lambda c: (c[0]["score"], c[1]["minute"]))
    flagged = {w["minute"] for s, w in cands}
    return tuple(_run(test, top, 3, lambda w: w["minute"] in flagged))


def events(scenario: str, ingested_at: str) -> list[dict]:
    from collectors import secrepo
    kind = KIND[scenario]
    asset = TARGET[kind]
    out = []
    for w in windows_for(scenario):
        stamp = _at(w).strftime("%Y%m%dT%H%M")
        base = {"asset_id": asset, "observed_at": w["minute"], "ingested_at": ingested_at, "is_simulated": True,
                "source": f"secrepo:{kind}"}
        if kind == "web":
            out.append(base | {
                "event_id": f"SR-WEB-{stamp}", "sensor_id": "secrepo-web", "event_type": "http_window", "source_type": "http_sensor",
                "raw_ref": f"backend/data/raw/{secrepo.SOURCE}/access.log.{_at(w):%Y-%m-%d}.gz",
                "details": {"request_count": w["requests"], "http_4xx_count": w["http_4xx"], "failed_auth_count": w["failed_auth"],
                            "unique_client_count": w["unique_clients"], "window_seconds": 60,
                            "path_category": (w["top_paths"] or ["/"])[0][:100]}})
        else:
            out.append(base | {
                "event_id": f"SR-SSH-{stamp}", "sensor_id": "secrepo-sshd", "event_type": "auth_window", "source_type": "auth_sensor",
                "raw_ref": f"backend/data/raw/{secrepo.SOURCE}/auth.log.gz",
                "details": {"failed_count": w["failed_logins"], "invalid_user_count": w["invalid_users"],
                            "unique_source_count": w["unique_sources"], "unique_user_count": w["unique_users"],
                            "window_seconds": 60, "top_users": [u[:64] for u in w["top_users"][:5]]}})
    return out


def describe(scenario: str) -> dict:
    """What a real scenario contains, for the API and the dashboard."""
    ws = windows_for(scenario)
    kind = KIND[scenario]
    return {"scenario": scenario, "kind": kind, "target": TARGET[kind], "windows": len(ws),
            "first_minute": ws[0]["minute"] if ws else None, "last_minute": ws[-1]["minute"] if ws else None,
            "top_sources": sorted({ip for w in ws for ip in w.get("top_sources", w.get("top_clients", []))})[:6],
            "top_users": sorted({u for w in ws for u in w.get("top_users", [])})[:8]}
