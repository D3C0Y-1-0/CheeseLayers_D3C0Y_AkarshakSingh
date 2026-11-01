"""Load cached threat intel + shared synthetic fixtures into SQLite. Idempotent: run it as often as you like.

    cd backend && .venv/bin/python -m ingestion.loader

Reads backend/data/cache/threat_items.json + iocs.json (the merged output of collectors/run_all.py; the
per-source caches are its inputs, loading them too would duplicate un-merged copies) and
data/threats_synthetic.json (forced is_simulated=true). Upserts by threat_id / (ioc_type, value) / raw path.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.dialects.sqlite import insert

from app.database import BACKEND, ROOT, SessionLocal, init_db
from collectors import geo
from app.models import ExploitEvidence, IOCRow, RawPayload, SourceStatus, Threat, ThreatSignal
from collectors.common import load_cache
from collectors.schema import IOC, ThreatItem

from . import changes

log = logging.getLogger("loader")
CACHE = BACKEND / "data" / "cache"
SYNTHETIC = ROOT / "data" / "threats_synthetic.json"
DEMO_CVES = ROOT / "data" / "demo_cves.json"
CHUNK = 500  # rows per INSERT (stays under SQLite's bound-parameter limit)


def fixture_threat(rec: dict) -> ThreatItem:
    """Shared-fixture record (contract fields only) -> ThreatItem, filling our extras."""
    return ThreatItem.model_validate({"type": "vulnerability", "cve_ids": [rec["cve_id"]] if rec.get("cve_id") else [], **rec})


def synthetic_threats() -> list[ThreatItem]:
    items = [fixture_threat(r) for r in json.loads(SYNTHETIC.read_text())]
    for t in items:
        t.is_simulated = True  # data honesty: a fixture can never be loaded as real intel
    return items


def _upsert(s, model, rows: list[dict], keys: list[str]) -> None:
    for i in range(0, len(rows), CHUNK):
        stmt = insert(model).values(rows[i:i + CHUNK])
        s.execute(stmt.on_conflict_do_update(index_elements=keys,
                                             set_={c: stmt.excluded[c] for c in rows[0] if c not in keys}))


def _raw_payloads(s, refs: dict[str, str]) -> dict[str, int]:
    """Upsert one raw_payloads row per referenced file (hash + mtime). Returns {path: id}."""
    rows = []
    for path, source in refs.items():
        f = ROOT / path
        ok = f.is_file()
        rows.append({"path": path, "source": source,
                     "sha256": hashlib.sha256(f.read_bytes()).hexdigest() if ok else None,
                     "size_bytes": f.stat().st_size if ok else None,
                     "fetched_at": datetime.fromtimestamp(f.stat().st_mtime, timezone.utc) if ok else None})
    if rows:
        _upsert(s, RawPayload, rows, ["path"])
    return dict(s.execute(select(RawPayload.path, RawPayload.id)).all())


def upsert_threats(s, items: list[ThreatItem]) -> None:
    _raw_payloads(s, {r: t.source for t in items for r in t.raw_refs})
    _upsert(s, Threat, [t.model_dump() for t in items], ["threat_id"])


def evidence_rows(cves: set[str]) -> dict[str, dict]:
    """Per-CVE exploit evidence from the caches, for CVEs we hold as threats. PoC counts only if quality-filtered."""
    sig = load_cache("exploit_signals") or {}
    poc = load_cache("github_poc_quality") or {}
    out = {}
    for c in cves & (sig.keys() | poc.keys()):
        x, q = sig.get(c) or {}, poc.get(c)
        out[c] = {"cve_id": c, "exploitdb": bool(x.get("exploitdb")), "exploitdb_date": x.get("exploitdb_date"),
                  "github_poc_listed": bool(x.get("github_poc")),
                  "github_poc_ok": q["ok"] if q else None, "github_poc_repo": q.get("first_ok_repo") if q else None,
                  "github_poc_date": q.get("first_ok_created_at") if q else None}
    return out


def load(detect: bool = False) -> dict[str, int]:
    """Upsert cache + fixtures. detect=True: diff against the DB as it was and emit threat_signals (+ hooks)."""
    init_db()
    threats = [ThreatItem.model_validate(r) for r in json.loads((CACHE / "threat_items.json").read_text())]
    threats += synthetic_threats()
    from app.case_intelligence import reviewed_items
    # Explicit verified primary snapshots take precedence over older merged records.
    reviewed = reviewed_items()
    if reviewed:
        by_id = {t.threat_id: t for t in threats}
        by_id.update({t.threat_id: t for t in reviewed})
        threats = list(by_id.values())
    iocs = [IOC.model_validate(r) for r in json.loads((CACHE / "iocs.json").read_text())]
    evidence = evidence_rows({t.cve_id for t in threats if t.cve_id})
    with SessionLocal.begin() as s:
        old = changes.snapshot(s) if detect else None
        upsert_threats(s, threats)
        ids = _raw_payloads(s, {i.raw_ref: i.source for i in iocs if i.raw_ref})
        _upsert(s, IOCRow, [{**i.model_dump(), "raw_payload_id": ids.get(i.raw_ref),
                             "geo": geo.lookup(i.value) if i.ioc_type in ("ip", "cidr") else None} for i in iocs],
                ["ioc_type", "value"])
        if evidence:
            _upsert(s, ExploitEvidence, list(evidence.values()), ["cve_id"])
        fresh = changes.emit(s, changes.detect(old, threats, evidence, datetime.now(timezone.utc))) if detect else []
    changes.fire_hooks(fresh)  # after commit: Member 3 reads committed rows
    return counts() | {"signals_emitted": len(fresh)}


def counts() -> dict[str, int]:
    with SessionLocal() as s:
        return {m.__tablename__: s.scalar(select(func.count()).select_from(m))
                for m in (Threat, IOCRow, RawPayload, SourceStatus, ExploitEvidence, ThreatSignal)}


def last_success(source: str) -> datetime | None:
    init_db()
    with SessionLocal() as s:
        row = s.get(SourceStatus, source)
        return row.last_success if row else None


def record_source_status(rows: list[dict]) -> None:
    """Called by collectors/run_all.py once per run. A failed run never erases the last good timestamp."""
    init_db()
    with SessionLocal.begin() as s:
        for r in rows:
            row = s.get(SourceStatus, r["source"]) or SourceStatus(source=r["source"])
            row.status, row.error, row.record_count = r["status"], r["error"], r["record_count"]
            row.last_attempt = r["last_attempt"] or row.last_attempt
            row.last_success = r["last_success"] or row.last_success
            s.add(row)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(load())
