"""Prepare the demo offline (no server needed): same as POST /api/demo/seed.

    backend/.venv/bin/python scripts/seed_demo.py        (Windows: backend\\.venv\\Scripts\\python scripts\\seed_demo.py)

Fills the Early warnings feed with labelled replay signals (is_simulated=true). Idempotent; run it again after a reset.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("DEMO_MODE", "true")

from app.database import SessionLocal, init_db  # noqa: E402
from app.feeds import seed_demo  # noqa: E402

if __name__ == "__main__":
    init_db()
    with SessionLocal() as db:
        r = seed_demo(db)
    for s in r.seeded:
        print(f"seeded {s.signal_type:<20} {s.threat_id}")
    for s in r.skipped:
        print(f"skipped {s}")
    print(r.note)
