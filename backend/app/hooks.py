"""Integration hooks between members. Member 2 calls them; owners fill them in."""


def on_new_threat(threat_id: str, signal_type: str) -> None:
    """Called once per NEW early-warning signal, after it is committed to the DB.

    signal_type: new_kev | epss_jump | new_public_exploit | new_certin_advisory | new_critical_cve
                 (from ingestion/changes.py, scheduled or manual ingests, and POST /api/demo/simulate-signal)
                 | demo_inject (POST /api/demo/inject-cve re-inserted an allowlisted fixture).
    threat_id: row in `threats` (for new_certin_advisory: the advisory; its CVEs are in threats.cve_ids).
    The signal itself: SELECT * FROM threat_signals WHERE threat_id=? AND signal_type=? ORDER BY detected_at DESC.

    TODO(Member 3): match the threat against data/assets.json, score it, create/update alerts.
    Runs in the ingest thread (scheduler or request): keep it fast; must not raise (errors are logged and swallowed).
    """
