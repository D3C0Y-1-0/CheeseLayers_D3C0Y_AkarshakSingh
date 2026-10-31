"""Tests run against a throw-away SQLite file, offline (DEMO_MODE=true). Env must be set before app imports."""
import os
import sys
import tempfile
from pathlib import Path

os.environ["DEMO_MODE"] = "true"
os.environ["NETRAX_DB_URL"] = f"sqlite:///{Path(tempfile.mkdtemp()) / 'test.db'}"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # backend/
