"""The scoring formula shown to judges and in CLAUDE.md is generated from CONFIG; this fails if either drifts."""
import json
from pathlib import Path

import pytest

from app.asset_store import get_asset_store
from app.contracts import ThreatRecord
from app.matcher import match_asset
from app.scoring import DOC_BEGIN, DOC_END, explain_markdown, score_incident
from ingestion.loader import DEMO_CVES, fixture_threat

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("doc", ["docs/SCORING_AND_AI.md", "CLAUDE.md"])
def test_generated_formula_matches_config(doc):
    text = (ROOT / doc).read_text(encoding="utf-8")
    block = text[text.index(DOC_BEGIN) + len(DOC_BEGIN):text.index(DOC_END)].strip()
    assert block == explain_markdown().strip(), f"{doc} is stale: run scripts/gen_scoring_doc.py"


def test_worked_example_is_the_real_alert_score():
    rec = next(t for t in json.loads(DEMO_CVES.read_text(encoding="utf-8")) if t["threat_id"] == "CVE-2024-21762")
    threat = ThreatRecord.model_validate(fixture_threat(rec).model_dump())
    asset = get_asset_store().get("PWR-FW-01")
    score = score_incident(asset, threat, match_asset(asset, threat)).vulnerability_priority_score
    assert f"= {score} -> critical" in explain_markdown()
