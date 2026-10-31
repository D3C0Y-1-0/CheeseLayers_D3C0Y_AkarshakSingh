"""Tests run against a throw-away SQLite file, offline (DEMO_MODE=true). Env must be set before app imports."""
import os
import sys
import tempfile
from pathlib import Path

os.environ["DEMO_MODE"] = "true"
os.environ["LLM_ALLOW_CLOUD"] = "false"  # tests never call a real provider, whatever .env says
os.environ["AI_CACHE_DIR"] = tempfile.mkdtemp()  # never read/write the real AI report cache
os.environ["CAMPAIGNS_CACHE"] = str(Path(tempfile.mkdtemp()) / "campaigns.json")
os.environ["VECTRA_DB_URL"] = f"sqlite:///{Path(tempfile.mkdtemp()) / 'test.db'}"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # backend/

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_ai_cache(tmp_path, monkeypatch):
    """Each test gets an empty AI report cache (a cached LLM answer must never leak between tests)."""
    from ai import grounded
    monkeypatch.setattr(grounded, "CACHE_DIR", tmp_path / "ai_reports")
