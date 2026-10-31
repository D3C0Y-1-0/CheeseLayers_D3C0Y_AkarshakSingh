"""Vectra API.   cd backend && .venv/bin/uvicorn app.main:app --reload   ->  http://localhost:8000/docs

On startup: create tables; if the DB has no threats yet, load the cache + fixtures (works fully offline).
Each member adds their own router file here (M3: alerts/assets, M4: behaviour/investigate).
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select

from . import alerts, analytics, assets, attack_lab, campaigns, certin_draft, feeds, frontend, insights, summaries
from .database import SessionLocal, init_db
from .models import IOCRow, Threat
from routes import investigation, shadow_watch
from shadow_watch.demo import DemoAdapter
from shadow_watch.integration import DatabaseFindingSink, demo_investigation_factory

log = logging.getLogger("vectra")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()  # also rebuilds Member 2's derived tables if their columns changed -> they come back empty
    with SessionLocal() as s:
        # Also reload when a derived table (e.g. iocs after a column change) was rebuilt empty.
        empty = not s.scalar(select(func.count()).select_from(Threat)) or not s.scalar(select(func.count()).select_from(IOCRow))
    if empty:
        from ingestion.loader import load
        log.warning("empty DB, loading cache: %s", load())
    campaigns.refresh_in_background(SessionLocal)  # warm backend/data/cache/campaigns.json (no-op if current)
    from ingestion import scheduler
    app.state.scheduler = scheduler.start()  # None in DEMO_MODE
    installed = []
    for name, adapter in (("shadow_finding_sink", DatabaseFindingSink(SessionLocal)),
                          ("investigation_tools_factory", demo_investigation_factory(SessionLocal))):
        if not hasattr(app.state, name):
            setattr(app.state, name, adapter)
            installed.append(name)
    try:
        yield
    finally:
        if app.state.scheduler:
            app.state.scheduler.shutdown(wait=False)
        for name in installed:
            delattr(app.state, name)


app = FastAPI(title="Vectra API", version="0.1.0", lifespan=lifespan,
              description="National cyber threat early-warning API. Contract: data/contracts.json · docs/API.md")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],  # Vite dev server
                   allow_methods=["*"], allow_headers=["*"])
app.include_router(feeds.router)
app.include_router(insights.router)
app.include_router(assets.router)  # Member 3
app.include_router(alerts.router)  # Member 3
app.include_router(analytics.router)  # Member 3
app.include_router(attack_lab.router)  # Member 3: attack simulation + detection
app.state.shadow_demo_adapter = DemoAdapter()
app.include_router(shadow_watch.router)
app.include_router(investigation.router)
app.include_router(summaries.router)  # AI threat summaries
app.include_router(campaigns.router)  # emerging campaigns
app.include_router(certin_draft.router)  # CERT-In report assistant
app.include_router(frontend.router)  # Last: API routes must win over the SPA history fallback.
