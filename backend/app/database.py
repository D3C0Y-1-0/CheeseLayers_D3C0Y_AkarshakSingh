"""SQLAlchemy engine + session. SQLite file at backend/data/vectra.db (override with VECTRA_DB_URL, e.g. for tests)."""
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import DateTime, create_engine, inspect
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.types import TypeDecorator

from collectors.common import DEMO_MODE  # noqa: F401  (one place reads .env + DEMO_MODE)

BACKEND = Path(__file__).resolve().parent.parent
ROOT = BACKEND.parent
DB_URL = os.getenv("VECTRA_DB_URL", f"sqlite:///{BACKEND / 'data' / 'vectra.db'}")

engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator):
    """SQLite has no timezone type: store UTC, hand back tz-aware datetimes (contract requires an offset)."""
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, v: datetime | None, dialect):
        if v is None:
            return None
        return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, v: datetime | None, dialect):
        return v.replace(tzinfo=timezone.utc) if v else None


# Tables owned by Member 2 hold only data derived from backend/data/cache (+ source_status, rewritten every run),
# so when their columns change we drop and rebuild them instead of writing migrations. Never touches other tables.
DERIVED = ("threats", "iocs", "raw_payloads", "source_status", "exploit_evidence")  # NOT threat_signals (history)


def init_db() -> None:
    """Create tables (rebuilding Member 2's derived tables, empty, if their columns changed)."""
    from . import models  # noqa: F401  (registers tables)
    (BACKEND / "data").mkdir(exist_ok=True)
    insp = inspect(engine)
    stale = [t for t in DERIVED if insp.has_table(t)
             and {c["name"] for c in insp.get_columns(t)} != set(Base.metadata.tables[t].columns.keys())]
    if stale:
        Base.metadata.drop_all(engine, tables=[Base.metadata.tables[t] for t in stale])  # only the changed ones
    Base.metadata.create_all(engine)


def get_db():
    with SessionLocal() as s:
        yield s
