"""Step 3: CERT-In incident report draft (never sent; analyst decides reportability)."""
import json

import pytest
from fastapi.testclient import TestClient

from ai import llm
from app.certin_draft import CERTIN_CATEGORIES
from app.main import app


@pytest.fixture(scope="module")
def ids():
    with TestClient(app) as c:
        c.post("/api/demo/reset-alerts")
        c.post("/api/demo/inject-cve", json={"fixture_id": "CVE-2024-21762"})
        behaviour = c.post("/api/demo/inject-behaviour", json={"scenario": "no_cve_suspicious_chain"}).json()["alert_ids"][0]
        vuln = next(a["alert_id"] for a in c.get("/api/alerts?kind=vulnerability").json()["items"]
                    if "CVE-2024-21762" in a["threat_ids"])
        yield c, vuln, behaviour


def test_vulnerability_alert_is_not_reportable_by_itself(ids):
    c, vuln, _ = ids
    d = c.post(f"/api/alerts/{vuln}/certin-draft").json()
    assert d["reportability_assessment"] == "vulnerability exposure only — not by itself a reportable incident"
    assert d["sent"] is False and d["status"] == "draft_for_analyst_review" and d["analyst_review_required"]
    assert all(x["status"] == "analyst to confirm" and x["category"] in CERTIN_CATEGORIES for x in d["category_candidates"])
    assert "6-hour" in d["disclaimer"] and "reportable incident types" in d["disclaimer"]
    assert {a["asset_id"] for a in d["affected_assets"]} and d["related_threats"][0]["cve_id"] == "CVE-2024-21762"
    assert d["generated_by"] == "template" and "[EMAIL]" in d["contact"]["email"]


def test_behaviour_alert_cites_stored_evidence(ids):
    c, _, behaviour = ids
    alert = c.get(f"/api/alerts/{behaviour}").json()
    d = c.post(f"/api/alerts/{behaviour}/certin-draft").json()
    assert d["reportability_assessment"] == "potential security incident — analyst must determine reportability"
    assert {e["evidence_id"] for e in d["observed_evidence"]} == set(alert["evidence_ids"])
    assert d["suggested_category"]["status"] == "analyst to confirm" and d["missing_information"]
    assert d["time_of_detection"] == alert["created_at"]


def test_markdown_download(ids):
    c, _, behaviour = ids
    r = c.post(f"/api/alerts/{behaviour}/certin-draft?format=markdown")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/markdown")
    assert f"certin-draft-{behaviour}.md" in r.headers["content-disposition"]
    assert r.text.startswith(f"# CERT-In incident report — DRAFT ({behaviour})") and "analyst to confirm" in r.text


def test_unknown_alert_404(ids):
    assert ids[0].post("/api/alerts/ALR-NOPE/certin-draft").status_code == 404


def test_llm_polish_is_grounded(ids, monkeypatch):
    c, vuln, _ = ids
    for k, v in {"LLM_PROVIDER": "groq", "LLM_MODEL": "m", "LLM_API_KEY": "k", "LLM_ALLOW_CLOUD": "true"}.items():
        monkeypatch.setenv(k, v)

    async def invents(prompt, settings):
        p = json.loads(prompt)
        return json.dumps({"incident_description": "Exploited via CVE-2030-1111.", "reportability_assessment": "reportable",
                           "recommended_next_actions": p["template"]["recommended_next_actions"]})
    monkeypatch.setattr(llm, "complete_json", invents)
    d = c.post(f"/api/alerts/{vuln}/certin-draft").json()
    assert d["generated_by"] == "template" and d["validation"]["passed"] is False
    assert d["reportability_assessment"].startswith("vulnerability exposure only")

    async def polishes(prompt, settings):
        p = json.loads(prompt)
        return json.dumps({"incident_description": p["template"]["incident_description"].replace("Vulnerability exposure:", "Exposure finding:"),
                           "recommended_next_actions": p["template"]["recommended_next_actions"]})
    monkeypatch.setattr(llm, "complete_json", polishes)
    d = c.post(f"/api/alerts/{vuln}/certin-draft").json()
    assert d["generated_by"] == "llm" and d["incident_description"].startswith("Exposure finding:") and d["sent"] is False
