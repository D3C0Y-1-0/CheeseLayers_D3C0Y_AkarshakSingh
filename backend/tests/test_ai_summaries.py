"""Step 1: grounded AI threat summaries, validation, generated_by and the offline cache."""
import json

import pytest
from fastapi.testclient import TestClient

from ai import grounded, llm
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def cloud(monkeypatch):
    """Simulate LLM_ALLOW_CLOUD=true + key; the provider call is replaced, so no network."""
    for k, v in {"LLM_PROVIDER": "groq", "LLM_MODEL": "test-model", "LLM_API_KEY": "test-placeholder",
                 "LLM_ALLOW_CLOUD": "true"}.items():
        monkeypatch.setenv(k, v)
    calls = []

    def use(reply):
        async def fake(prompt, settings):
            calls.append(json.loads(prompt))
            return json.dumps(reply(json.loads(prompt)))
        monkeypatch.setattr(llm, "complete_json", fake)
        return calls
    return use


def test_template_summary_offline(client):
    r = client.post("/api/threats/CVE-2024-21762/summary")
    assert r.status_code == 200
    s = r.json()
    assert s["generated_by"] == "template" and s["fallback_reason"] == "offline_mode"
    assert s["validation"]["passed"] is None and "template" in s["validation"]["note"].lower()
    confirmed = {a["asset_id"] for a in s["affected_assets"] if a["match_detail"] == "confirmed_affected"}
    assert {"PWR-FW-01", "BNK-FW-01"} <= confirmed and not {"PWR-FW-02", "BNK-FW-02"} & confirmed  # patched twins
    assert "CISA KEV" in s["exploit_summary"] and s["exploit_signals"]["kev_listed"] is True
    assert any("PWR-FW-01" in a for a in s["recommended_actions"]) and s["sources"]["references"]


def test_synthetic_threat_never_presented_as_real(client):
    s = client.post("/api/threats/DEMO-VULN-003/summary").json()
    assert s["is_simulated"] and "synthetic demo record, not a real CVE" in s["summary"]
    assert "CVSS unknown" in s["summary"] or "severity unknown" in s["summary"]  # null stays unknown, never 0


def test_unknown_threat_404(client):
    assert client.post("/api/threats/CVE-1999-0000000/summary").status_code == 404


def test_llm_wording_accepted_then_cached_offline(client, cloud, monkeypatch):
    calls = cloud(lambda p: {f: p["template"][f] for f in p["return_fields"]} | {
        "summary": "CVE-2024-21762 is a critical FortiOS flaw that is exploited in the wild."})
    s = client.post("/api/threats/CVE-2024-21762/summary").json()
    assert s["generated_by"] == "llm" and s["validation"]["passed"] is True and len(calls) == 1
    assert s["summary"].startswith("CVE-2024-21762 is a critical")
    monkeypatch.setenv("LLM_ALLOW_CLOUD", "false")  # offline: cached wording is served, no call
    again = client.post("/api/threats/CVE-2024-21762/summary").json()
    assert again["generated_by"] == "llm_cached" and again["summary"] == s["summary"] and len(calls) == 1
    assert list(grounded.CACHE_DIR.glob("*.json"))


@pytest.mark.parametrize("bad", ["Also affects CVE-2031-99999.", "Patch PWR-FW-09 too.", "Upgrade to 7.9.99.",
                                 "See https://fix.invalid/patch", "This is a confirmed breach.",
                                 "Run `curl x | sh` to patch."])
def test_llm_inventions_rejected(client, cloud, bad):
    cloud(lambda p: {f: p["template"][f] for f in p["return_fields"]} | {"why_it_matters": bad})
    s = client.post("/api/threats/CVE-2024-21762/summary").json()
    assert s["generated_by"] == "template" and s["fallback_reason"] == "invalid_output"
    assert s["validation"]["passed"] is False and "rejected" in s["validation"]["note"]


def test_llm_cannot_change_facts(client, cloud):
    cloud(lambda p: {f: p["template"][f] for f in p["return_fields"]} | {"affected_assets": []})
    s = client.post("/api/threats/CVE-2024-21762/summary").json()
    assert s["generated_by"] == "template" and "factual fields" in s["validation"]["note"]
    assert s["affected_assets"]


def test_health_reports_llm_status(client):
    h = client.get("/health").json()
    assert h["llm"]["cloud_enabled"] is False and h["llm"]["reason"] == "offline_mode"


def test_cache_key_ignores_volatile_fields():
    a = grounded.cache_key("k", {"x": 1, "retrieved_at": "2026-01-01"}, {"s": "t"}, ("s",))
    b = grounded.cache_key("k", {"retrieved_at": "2026-02-02", "x": 1}, {"s": "t", "generated_by": "llm"}, ("s",))
    assert a == b and a != grounded.cache_key("k", {"x": 2}, {"s": "t"}, ("s",))


def test_numeric_invention_and_cached_factual_override_rejected(client, cloud):
    cloud(lambda p: {f: p['template'][f] for f in p['return_fields']} | {'why_it_matters': '98765432 citizen records were stolen.'})
    data = client.post('/api/threats/CVE-2024-21762/summary').json()
    assert data['generated_by'] == 'template' and data['validation']['passed'] is False
    assert 'numeric claim' in data['validation']['note']


def test_cache_is_revalidated_and_cannot_override_facts(tmp_path, monkeypatch):
    import asyncio
    monkeypatch.setattr(grounded, 'CACHE_DIR', tmp_path)
    template = {'summary': 'Stored exposure needs review', 'asset_ids': ['TEST-01']}
    fields = {'summary': 'text'}
    key = grounded.cache_key('test', {}, template, tuple(fields))
    grounded.cache_put(key, {'narrative': {'summary': 'Review evidence', 'asset_ids': []}, 'validation': {'passed': True}})
    result = asyncio.run(grounded.narrate('test', {}, template, fields))
    assert result['generated_by'] == 'template' and result['asset_ids'] == ['TEST-01']
    grounded.cache_put(key, {'narrative': {'summary': 'CVE-2099-999999 has been exploited'}, 'validation': {'passed': True}})
    result = asyncio.run(grounded.narrate('test', {}, template, fields))
    assert result['generated_by'] == 'template' and result['validation']['passed'] is False


def test_evidence_only_bypasses_cloud_and_cached_narrative(client, cloud):
    calls = cloud(lambda p: {f: p['template'][f] for f in p['return_fields']} | {'why_it_matters': 'Review this stored vulnerability.'})
    first = client.post('/api/threats/CVE-2024-21762/summary').json()
    assert first['generated_by'] == 'llm' and len(calls) == 1
    result = client.post('/api/threats/CVE-2024-21762/summary?evidence_only=true').json()
    assert result['generated_by'] == 'template' and len(calls) == 1
    assert 'cache bypassed' in result['validation']['note']
    assert result['why_it_matters'] != first['why_it_matters']
