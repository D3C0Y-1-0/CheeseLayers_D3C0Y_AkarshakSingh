"""Prepare the DB before the API starts (used by render.yaml; safe to run anywhere, offline, idempotent).

    python -X utf8 scripts/prestart.py && uvicorn ...

1. Loads backend/data/cache into SQLite if the DB is empty. Parsing ~140 MB of JSON peaks at several hundred MB;
   doing it in this short-lived process (instead of the API's startup) gives that memory back to the OS when it
   exits, so the API itself runs at roughly half the memory. That keeps it under a 512 MB free-host limit.
2. Seeds the Early warnings feed (same as scripts/seed_demo.py / POST /api/demo/seed).
3. Warms the campaigns cache so the first /api/campaigns request doesn't have to build it.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("DEMO_MODE", "true")

from sqlalchemy import func, select  # noqa: E402

from app import campaigns  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.feeds import seed_demo  # noqa: E402
from app.models import IOCRow, Threat  # noqa: E402

if __name__ == "__main__":
    init_db()
    with SessionLocal() as db:
        empty = not db.scalar(select(func.count()).select_from(Threat)) or not db.scalar(select(func.count()).select_from(IOCRow))
    if empty:
        from ingestion.loader import load
        print("loaded cache:", load())
    with SessionLocal() as db:
        r = seed_demo(db)
        print(f"seeded {len(r.seeded)} early-warning signals ({len(r.skipped)} skipped)")
        print("campaigns:", len(campaigns.get(db)["campaigns"]))
