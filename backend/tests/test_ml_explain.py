"""SHAP explanations of the Isolation Forest (SW-ML-001) and the PDF export."""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from shadow_watch import explain, ml

pytest.importorskip("shap")
needs_model = pytest.mark.skipif(ml.model("web") is None, reason="SecRepo cache missing")


@needs_model
def test_shap_matches_model_and_names_the_driver():
    _, test = ml.split("web")
    worst = min(test, key=lambda w: ml.score_features("web", ml.window_features("web", w))["score"])
    e = explain.explain("web", ml.window_features("web", worst))
    assert e["flagged"] and e["features"][0]["toward"] == "unusual"
    assert abs(sum(f["share_pct"] for f in e["features"]) - 100) < 0.5
    assert abs(e["path_length"] - (e["baseline_path_length"] + sum(f["shap_value"] for f in e["features"]))) < 0.01
    assert e["features"][0]["label"] in e["summary"] and "unusual" in e["features"][0]["sentence"]


@needs_model
def test_normal_minute_is_not_flagged():
    train, _ = ml.split("web")
    e = explain.explain("web", ml.window_features("web", train[len(train) // 2]))
    assert e["flagged"] is False and "did not flag" in e["summary"]


@needs_model
def test_incident_explanation_and_pdf():
    with TestClient(app) as c:
        c.post("/api/demo/reset-alerts")
        aid = c.post("/api/demo/inject-behaviour", json={"scenario": "real_web_crawler"}).json()["alert_ids"][0]
        d = c.get(f"/api/alerts/{aid}/ml-explanation").json()
        assert d["ml_findings"] >= 1 and d["explanations"][0]["features"] and d["model"]["sensors"]
        pdf = c.get(f"/api/alerts/{aid}/ml-explanation.pdf")
        assert pdf.status_code == 200 and pdf.content[:5] == b"%PDF-" and "attachment" in pdf.headers["content-disposition"]
        other = c.post("/api/demo/inject-behaviour", json={"scenario": "no_cve_suspicious_chain"}).json()["alert_ids"][0]
        none = c.get(f"/api/alerts/{other}/ml-explanation").json()
        assert none["ml_findings"] == 0 and none["note"]
        assert c.get("/api/alerts/ALR-NOPE/ml-explanation").status_code == 404
        assert c.get("/api/ml/model").json()["sensors"][0]["global_importance"]
