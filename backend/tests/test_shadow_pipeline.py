from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai.fallback import build_fallback_report
from app.main import app
from shadow_watch.demo import DemoAdapter, DemoRequest


def test_predefined_replay_idempotent_and_separate_assets():
    adapter = DemoAdapter()
    request = DemoRequest(scenario="no_cve_suspicious_chain")
    first, second = adapter.replay(request), adapter.replay(request)
    assert first == second
    assert first.handoff_status == "pending_member3" and first.alert_ids == ()
    assert len(first.findings) == len(first.evidence) == 3
    context = adapter.get_incident(first.incident_id)
    assert context.assessment == "suspected_activity" and context.verified_cve_ids == ()
    assert {eid for f in first.findings for eid in f.evidence_ids} == {e.event_id for e in context.evidence}
    assert (max(e.observed_at for e in context.evidence) - min(e.observed_at for e in context.evidence)).total_seconds() < 300
    benign = adapter.replay(DemoRequest(scenario="benign_maintenance"))
    assert not benign.findings
    assert benign.incident_id != first.incident_id
    assert set(adapter.get_incident(benign.incident_id).asset_ids).isdisjoint(context.asset_ids)
    assert "maintenance" in build_fallback_report(adapter.get_incident(benign.incident_id)).why_relevant


def test_handoff_invoked_once():
    class Sink:
        calls = []

        def accept_findings(self, **kwargs):
            self.calls.append(kwargs)
            return ("ALERT-M3-001",)

    adapter, sink = DemoAdapter(), Sink()
    request = DemoRequest(scenario="no_cve_suspicious_chain")
    result = adapter.replay(request, sink)
    adapter.replay(request, sink)
    assert result.handoff_status == "delivered"
    assert result.alert_ids == ("ALERT-M3-001",)
    assert len(sink.calls) == 1
    assert len(sink.calls[0]["events"]) == len(sink.calls[0]["findings"]) == 3


def test_failed_handoff_retryable():
    class BrokenSink:
        def accept_findings(self, **kwargs):
            raise RuntimeError("temporary integration failure")
    adapter = DemoAdapter()
    request = DemoRequest(scenario="missing_telemetry")
    with pytest.raises(RuntimeError):
        adapter.replay(request, BrokenSink())
    assert adapter.replay(request).handoff_status == "pending_member3"


def test_late_handoff_delivers_cached_preview_once():
    class Sink:
        count = 0

        def accept_findings(self, **kwargs):
            self.count += 1
            return ("M3-ALERT-001",)
    adapter, sink = DemoAdapter(), Sink()
    request = DemoRequest(scenario="no_cve_suspicious_chain")
    assert adapter.replay(request).handoff_status == "pending_member3"
    assert adapter.replay(request, sink).handoff_status == "delivered"
    assert adapter.replay(request, sink).handoff_status == "delivered"
    assert sink.count == 1


def test_bounded_adapter_eviction_and_reset():
    adapter = DemoAdapter(maximum_runs=1)
    request = DemoRequest(scenario="missing_telemetry")
    original = adapter.replay(request)
    adapter.replay(DemoRequest(scenario="benign_maintenance"))
    with pytest.raises(KeyError):
        adapter.get_incident(original.incident_id)
    assert adapter.replay(request) == original
    assert DemoAdapter().replay(request) == original


@pytest.fixture
def client():
    app.state.shadow_demo_adapter = DemoAdapter()
    # Member 4 route tests do not need the feed DB/startup loader.
    return TestClient(app)


@pytest.mark.parametrize("scenario,count", [("no_cve_suspicious_chain", 3), ("benign_maintenance", 0), ("missing_telemetry", 2)])
def test_api_replay_and_investigate(client, scenario, count):
    first = client.post("/api/demo/inject-behaviour", json={"scenario": scenario})
    assert first.status_code == 200, first.text
    result = first.json()
    assert len(result["findings"]) == count
    assert client.post("/api/demo/inject-behaviour", json={"scenario": scenario}).json() == result
    response = client.post(f"/api/alerts/{result['incident_id']}/investigate")
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["generated_by"] == "template" and report["fallback_reason"] == "offline_mode"
    assert report["evidence_ids"] == [e["event_id"] for e in result["evidence"]]
    assert report["is_simulated"] is True and report["integration_status"] == "demo_adapter"


@pytest.mark.parametrize("payload", [{}, {"scenario": "scan"}, {"scenario": "benign_maintenance", "url": "https://example.com"},
                                    {"scenario": "benign_maintenance", "run_id": "../../tmp"}])
def test_demo_rejects_arbitrary_input(client, payload):
    assert client.post("/api/demo/inject-behaviour", json=payload).status_code == 422


def test_production_disabled_and_missing_provider(client, monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    assert client.post("/api/demo/inject-behaviour", json={"scenario": "benign_maintenance"}).status_code == 404
    assert client.post("/api/alerts/ALERT-001/investigate").status_code == 503


def test_unknown_demo_incident_404(client):
    assert client.post("/api/alerts/SW-DEMO-missing/investigate").status_code == 404


def test_production_scoped_provider(client, monkeypatch):
    from ai.schemas import IncidentContext
    from ai.tools import InvestigationScope, ReadOnlyTools
    adapter = DemoAdapter()
    result = adapter.replay(DemoRequest(scenario="missing_telemetry"))
    raw = adapter.get_incident(result.incident_id).model_dump(mode="json")
    raw.update(incident_id="ALERT-M3-001", integration_status="persisted")
    ctx = IncidentContext.model_validate(raw)

    class Provider:
        def get_incident(self, incident_id):
            if incident_id != ctx.incident_id:
                raise KeyError(incident_id)
            return ctx

    def factory(request, incident_id):
        if request.headers.get("Authorization") != "Bearer test-token":
            raise PermissionError("unauthorised")
        return ReadOnlyTools(Provider(), InvestigationScope(incident_id, frozenset(ctx.asset_ids), demo_only=False))

    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("LLM_PROVIDER", "template")
    monkeypatch.setattr(app.state, "investigation_tools_factory", factory, raising=False)
    assert client.post("/api/alerts/ALERT-M3-001/investigate").status_code == 403
    response = client.post("/api/alerts/ALERT-M3-001/investigate", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200, response.text
    assert response.json()["integration_status"] == "persisted"
    assert response.json()["generated_by"] == "template"


def test_sink_failure_returns_retryable_503(client, monkeypatch):
    class Sink:
        def accept_findings(self, **kwargs):
            raise RuntimeError("sink failure")
    monkeypatch.setattr(app.state, "shadow_finding_sink", Sink(), raising=False)
    response = client.post("/api/demo/inject-behaviour", json={"scenario": "missing_telemetry"})
    assert response.status_code == 503
    assert "same run_id" in response.json()["detail"]


def test_samples_exist_and_match_schemas():
    import json
    from ai.schemas import InvestigationReport
    from shadow_watch.demo import DemoResult
    root = Path(__file__).resolve().parents[2]
    for scenario in ("no_cve_suspicious_chain", "benign_maintenance", "missing_telemetry"):
        sample = json.loads((root / f"docs/samples/shadow_{scenario}.json").read_text(encoding="utf-8"))
        DemoResult.model_validate(sample["injection"])
        InvestigationReport.model_validate(sample["investigation"])
        assert sample["investigation"]["fallback_reason"] == "offline_mode"
