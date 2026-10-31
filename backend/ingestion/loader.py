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
from app.models import IOCRow, RawPayload, SourceStatus, Threat
from collectors.schema import IOC, ThreatItem

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
    ids = _raw_payloads(s, {t.raw_ref: t.source for t in items if t.raw_ref})
    _upsert(s, Threat, [{**t.model_dump(), "raw_payload_id": ids.get(t.raw_ref)} for t in items], ["threat_id"])


def load() -> dict[str, int]:
    init_db()
    threats = [ThreatItem.model_validate(r) for r in json.loads((CACHE / "threat_items.json").read_text())]
    threats += synthetic_threats()
    iocs = [IOC.model_validate(r) for r in json.loads((CACHE / "iocs.json").read_text())]
    with SessionLocal.begin() as s:
        upsert_threats(s, threats)
        ids = _raw_payloads(s, {i.raw_ref: i.source for i in iocs if i.raw_ref})
        _upsert(s, IOCRow, [{**i.model_dump(), "raw_payload_id": ids.get(i.raw_ref)} for i in iocs], ["ioc_type", "value"])
    return counts()


def counts() -> dict[str, int]:
    with SessionLocal() as s:
        return {m.__tablename__: s.scalar(select(func.count()).select_from(m)) for m in (Threat, IOCRow, RawPayload, SourceStatus)}


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
