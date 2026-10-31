"""SQLAlchemy engine + session. SQLite file at backend/data/netrax.db (override with NETRAX_DB_URL, e.g. for tests)."""
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import DateTime, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.types import TypeDecorator

from collectors.common import DEMO_MODE  # noqa: F401  (one place reads .env + DEMO_MODE)

BACKEND = Path(__file__).resolve().parent.parent
ROOT = BACKEND.parent
DB_URL = os.getenv("NETRAX_DB_URL", f"sqlite:///{BACKEND / 'data' / 'netrax.db'}")

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


def init_db() -> None:
    from . import models  # noqa: F401  (registers tables)
    (BACKEND / "data").mkdir(exist_ok=True)
    Base.metadata.create_all(engine)


def get_db():
    with SessionLocal() as s:
        yield s
