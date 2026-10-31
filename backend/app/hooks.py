"""Integration hooks between members. Member 2 calls them; owners fill them in."""
import logging

log = logging.getLogger("vectra.hooks")


def on_new_threat(threat_id: str, signal_type: str) -> None:
    """Called once per NEW early-warning signal, after it is committed to the DB.

    signal_type: new_kev | epss_jump | new_public_exploit | new_certin_advisory | new_critical_cve
                 (from ingestion/changes.py, scheduled or manual ingests, and POST /api/demo/simulate-signal)
                 | demo_inject (POST /api/demo/inject-cve re-inserted an allowlisted fixture).
    threat_id: row in `threats` (for new_certin_advisory: the advisory; its CVEs are in threats.cve_ids).
    The signal itself: SELECT * FROM threat_signals WHERE threat_id=? AND signal_type=? ORDER BY detected_at DESC.

    Member 3: match the threat against the asset inventory, score it, create/update alerts. Every signal type gets
    the same treatment: re-matching re-scores existing alerts (new_kev / epss_jump raise exploitation) and creates
    alerts for newly exposed assets. Runs in the ingest thread: must not raise.
    """
    from .correlator import CorrelationEngine, threat_from_row
    from .database import SessionLocal
    from .models import Threat

    try:
        with SessionLocal() as db:
            row = db.get(Threat, threat_id)
            if row is None:
                log.warning("on_new_threat: %s not in threats table", threat_id)
                return
            rows = [row]
            if signal_type == "new_certin_advisory":  # also match each CVE's own record (it has the NVD ranges)
                rows += [r for c in row.cve_ids or [] if c != threat_id and (r := db.get(Threat, c))]
            engine = CorrelationEngine(db)
            for r in rows:
                if r.affected_configurations:
                    out = engine.correlate_threat(threat_from_row(r), trigger=signal_type)
                    log.info("on_new_threat %s (%s): %d created, %d updated", r.threat_id, signal_type,
                             len(out["created"]), len(out["updated"]))
    except Exception:
        log.exception("on_new_threat(%s, %s) failed", threat_id, signal_type)
