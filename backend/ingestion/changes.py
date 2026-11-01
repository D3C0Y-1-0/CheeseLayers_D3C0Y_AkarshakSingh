"""Change detection: diff each ingest against the previous DB state and emit ThreatSignal rows (early warnings).

Signal types (contracts.json `threat_signal.signal_type`):
  new_kev              CVE newly added to CISA KEV (exploited in the wild)
  epss_jump            EPSS rose >= epss_jump_abs, or crossed epss_cross
  new_public_exploit   Exploit-DB entry or a *quality* GitHub PoC newly appeared
  new_certin_advisory  new CERT-In advisory / vulnerability note (details.cve_ids = CVEs it mentions)
  new_critical_cve     CVE published in the last critical_max_age_days with CVSS >= critical_cvss (new or newly scored)

Idempotent: signal_id = hash(threat_id, type, old, new), inserted with ON CONFLICT DO NOTHING, so replaying the
same change never creates a second signal. The very first load (empty DB) is the baseline: no signals.
"""
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert

from app.models import ExploitEvidence, Threat, ThreatSignal
from collectors.schema import ThreatItem

log = logging.getLogger("changes")

# The ONE config for signal thresholds.
SIGNALS = {
    "epss_jump_abs": 0.2,  # EPSS rose by at least this much (absolute, 0-1 scale)...
    "epss_cross": 0.5,  # ...or crossed this line upwards ("more likely than not to be exploited in 30 days")
    "critical_cvss": 9.0,
    "critical_max_age_days": 14,  # only CVEs NVD published recently count as "new" criticals (no backfill noise)
}
TYPES = ("new_kev", "epss_jump", "new_public_exploit", "new_certin_advisory", "new_critical_cve")
TYPES += ("new_cve", "threat_updated")
MATERIAL_FIELDS = ("title", "description", "cvss", "cvss_version", "severity", "epss", "kev_listed",
                   "public_exploit", "affected_configurations", "references", "cve_ids")


def material(record):
    return {k: record.get(k) for k in MATERIAL_FIELDS}


@dataclass
class State:
    """What the DB held before this ingest."""
    threats: dict[str, tuple] = field(default_factory=dict)  # threat_id -> (kev_listed, epss, cvss)
    evidence: dict[str, tuple] = field(default_factory=dict)  # cve -> (exploitdb, github_poc_ok, github_poc_listed)
    material: dict[str, dict] = field(default_factory=dict)


def snapshot(s) -> State:
    return State(
        threats={tid: (k, e, c) for tid, k, e, c in s.execute(select(Threat.threat_id, Threat.kev_listed, Threat.epss, Threat.cvss))},
        evidence={c: (x, g, l) for c, x, g, l in s.execute(select(ExploitEvidence.cve_id, ExploitEvidence.exploitdb,
                                                                  ExploitEvidence.github_poc_ok, ExploitEvidence.github_poc_listed))},
        material={r.threat_id: material({k: getattr(r, k) for k in MATERIAL_FIELDS}) for r in s.scalars(select(Threat))},
    )


def signal_id(threat_id: str, signal_type: str, old, new) -> str:
    key = json.dumps([threat_id, signal_type, old, new], sort_keys=True, default=str)
    return "sig-" + hashlib.sha256(key.encode()).hexdigest()[:20]


def make(threat_id: str, signal_type: str, old, new, source: str, details: dict, now: datetime, simulated: bool = False,
         salt: str | None = None) -> dict:
    """salt: only for simulated demo signals, so pressing the demo button twice gives two signals."""
    return {"signal_id": signal_id(threat_id, signal_type, old, [new, salt] if salt else new), "threat_id": threat_id,
            "signal_type": signal_type, "old_value": old, "new_value": new, "detected_at": now, "source": source,
            "details": details, "is_simulated": simulated}


def epss_jumped(old: float | None, new: float | None) -> bool:
    # Unknown before or after = no evidence of a jump (null is not 0).
    if old is None or new is None:
        return False
    return new - old >= SIGNALS["epss_jump_abs"] - 1e-9 or old < SIGNALS["epss_cross"] <= new


def detect(old: State, items: list[ThreatItem], evidence: dict[str, dict], now: datetime) -> list[dict]:
    """Signals for what changed between `old` (DB before) and `items`/`evidence` (what we're loading now)."""
    if not old.threats:
        return []  # first load ever = baseline
    out = []
    recent = now - timedelta(days=SIGNALS["critical_max_age_days"])
    by_id = {t.threat_id: t for t in items}
    for t in items:
        prev = old.threats.get(t.threat_id)
        was_kev, was_epss, was_cvss = prev if prev else (None, None, None)
        sim = t.is_simulated
        if t.cve_id and t.kev_listed is True and was_kev is not True:
            out.append(make(t.threat_id, "new_kev", was_kev, True, "kev",
                            {"cve_id": t.cve_id, "kev_date_added": str(t.kev_date_added) if t.kev_date_added else None,
                             "title": t.title}, now, sim))
        if t.cve_id and prev and epss_jumped(was_epss, t.epss):
            out.append(make(t.threat_id, "epss_jump", was_epss, t.epss, "epss",
                            {"delta": round(t.epss - was_epss, 5), "crossed": was_epss < SIGNALS["epss_cross"] <= t.epss,
                             "epss_percentile": t.epss_percentile}, now, sim))
        if (t.cve_id and t.cvss is not None and t.cvss >= SIGNALS["critical_cvss"] and t.nvd_published_at
                and t.nvd_published_at >= recent and (was_cvss is None or was_cvss < SIGNALS["critical_cvss"])):
            out.append(make(t.threat_id, "new_critical_cve", was_cvss, t.cvss, "nvd",
                            {"cvss_version": t.cvss_version, "nvd_published_at": t.nvd_published_at.isoformat(),
                             "kev_listed": t.kev_listed}, now, sim))
        if t.source == "certin" and prev is None:
            out.append(make(t.threat_id, "new_certin_advisory", None, t.threat_id, "certin",
                            {"cve_ids": t.cve_ids, "severity": t.severity, "title": t.title,
                             "kev_cves": [c for c in t.cve_ids if (by_id.get(c) and by_id[c].kev_listed)],
                             "url": t.references[0] if t.references else None}, now, sim))
    if old.evidence:  # evidence table existed before -> diff it (else this load is its baseline)
        for cve, ev in evidence.items():
            if cve not in by_id:
                continue
            was_edb, was_poc, was_listed = old.evidence.get(cve, (False, None, False))
            if ev["exploitdb"] and not was_edb:
                out.append(make(cve, "new_public_exploit", None, {"source": "exploitdb", "date": ev["exploitdb_date"]},
                                "exploitdb", {"source": "exploitdb", "date": ev["exploitdb_date"]}, now))
            # A quality PoC is NEW only if the listing itself is new, or a previously failing PoC now passes.
            # "Listed before but never checked" -> first check is not a new exploit (that was a false-signal bug).
            if ev["github_poc_ok"] is True and (was_poc is False or not was_listed):
                out.append(make(cve, "new_public_exploit", None, {"source": "github_poc", "repo": ev["github_poc_repo"]},
                                "github_poc", {"source": "github_poc", "repo": ev["github_poc_repo"],
                                               "created_at": ev["github_poc_date"], "quality_filtered": True}, now))
    specialised = {x["threat_id"] for x in out}
    for t in items:
        if t.threat_id in specialised:
            continue
        before = old.material.get(t.threat_id)
        after = material(t.model_dump(mode="json"))
        if before is not None and before != after:
            changed = [k for k in MATERIAL_FIELDS if before.get(k) != after.get(k)]
            out.append(make(t.threat_id, "threat_updated", before, after, t.source,
                {"changed_fields": changed, "cve_ids": t.cve_ids, "note": "Material stored intelligence revision, not an attack."}, now, t.is_simulated))
        elif t.cve_id and t.threat_id not in old.threats:
            out.append(make(t.threat_id, "new_cve", None, after, t.source,
                {"cve_id": t.cve_id, "note": "New to this database; publication may be historical."}, now, t.is_simulated))
    return out


def emit(s, signals: list[dict]) -> list[dict]:
    """Insert new signals; returns only the ones that didn't exist yet (those get the hook)."""
    if not signals:
        return []
    ids = [x["signal_id"] for x in signals]
    have = set(s.scalars(select(ThreatSignal.signal_id).where(ThreatSignal.signal_id.in_(ids))))
    fresh = list({x["signal_id"]: x for x in signals if x["signal_id"] not in have}.values())
    for i in range(0, len(fresh), 500):
        s.execute(insert(ThreatSignal).values(fresh[i:i + 500]).on_conflict_do_nothing(index_elements=["signal_id"]))
    return fresh


def fire_hooks(signals: list[dict]) -> None:
    """Call Member 3's hook once per new signal. A hook error is logged, never allowed to break ingestion."""
    from app import hooks
    for x in signals:
        try:
            hooks.on_new_threat(x["threat_id"], x["signal_type"])
        except Exception:
            log.exception("on_new_threat(%s, %s) failed", x["threat_id"], x["signal_type"])
