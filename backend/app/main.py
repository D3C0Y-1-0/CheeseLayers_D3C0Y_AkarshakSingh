"""NETRA-X API.   cd backend && .venv/bin/uvicorn app.main:app --reload   ->  http://localhost:8000/docs

On startup: create tables; if the DB has no threats yet, load the cache + fixtures (works fully offline).
Each member adds their own router file here (M3: alerts/assets, M4: behaviour/investigate).
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select

from . import feeds, insights
from .database import SessionLocal, init_db
from .models import Threat

log = logging.getLogger("netrax")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()  # also rebuilds Member 2's derived tables if their columns changed -> they come back empty
    with SessionLocal() as s:
        empty = not s.scalar(select(func.count()).select_from(Threat))
    if empty:
        from ingestion.loader import load
        log.warning("empty DB, loading cache: %s", load())
    yield


app = FastAPI(title="NETRA-X API", version="0.1.0", lifespan=lifespan,
              description="National cyber threat early-warning API. Contract: data/contracts.json · docs/API.md")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],  # Vite dev server
                   allow_methods=["*"], allow_headers=["*"])
app.include_router(feeds.router)
app.include_router(insights.router)
