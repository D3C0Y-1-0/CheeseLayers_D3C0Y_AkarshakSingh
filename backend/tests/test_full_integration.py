import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import app
from app.correlator import CorrelationEngine, EventRow
from app.database import SessionLocal, init_db
from shadow_watch.demo import DemoAdapter
from shadow_watch.integration import DatabaseFindingSink, demo_investigation_factory

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def client(monkeypatch):
    init_db()
    with SessionLocal() as db:
        CorrelationEngine(db).reset()
    monkeypatch.setattr(app.state, 'shadow_demo_adapter', DemoAdapter(), raising=False)
    monkeypatch.setattr(app.state, 'shadow_finding_sink', DatabaseFindingSink(SessionLocal), raising=False)
    monkeypatch.setattr(app.state, 'investigation_tools_factory', demo_investigation_factory(SessionLocal), raising=False)
    with TestClient(app) as client:
        yield client
    with SessionLocal() as db:
        CorrelationEngine(db).reset()


def inject(client, scenario):
    r = client.post('/api/demo/inject-behaviour', json={'scenario': scenario})
    assert r.status_code == 200, r.text
    assert r.json()['handoff_status'] == 'delivered'
    return r.json()


def test_no_cve_persisted_incident_investigation_ack_replay(client):
    result = inject(client, 'no_cve_suspicious_chain')
    assert len(result['alert_ids']) == 1
    aid = result['alert_ids'][0]
    alert = client.get(f'/api/alerts/{aid}').json()
    assert alert['kind'] == 'behaviour' and alert['threat_ids'] == []
    assert len(alert['evidence_ids']) == 3 and alert['priority'] in ('high', 'critical')
    evidence = client.get(f'/api/alerts/{aid}/evidence').json()['items']
    assert len(evidence) == 3 and sum(len(e['shadow_findings']) for e in evidence) == 3
    report = client.post(f'/api/alerts/{aid}/investigate').json()
    assert report['integration_status'] == 'persisted' and report['generated_by'] == 'template'
    assert report['assessment'] == 'suspected_activity'
    assert set(report['evidence_ids']) == set(alert['evidence_ids'])
    assert 'No known CVE linkage' in report['summary']
    ack = client.post(f'/api/alerts/{aid}/acknowledge').json()
    assert ack['lifecycle_status'] == 'investigating'
    assert inject(client, 'no_cve_suspicious_chain')['alert_ids'] == [aid]
    assert client.get('/api/alerts').json()['total'] == 1
    # Process restart: IDs and persisted evidence remain idempotent.
    app.state.shadow_demo_adapter = DemoAdapter()
    assert inject(client, 'no_cve_suspicious_chain')['alert_ids'] == [aid]
    assert client.get('/api/alerts').json()['items'][0]['lifecycle_status'] == 'investigating'


def test_maintenance_retains_events_without_escalation(client):
    result = inject(client, 'benign_maintenance')
    assert result['findings'] == [] and result['alert_ids'] == []
    assert client.get('/api/alerts').json()['total'] == 0
    with SessionLocal() as db:
        records = list(db.scalars(select(EventRow)))
        assert len(records) == 3 and all(r.data['is_simulated'] for r in records)


def test_missing_telemetry_and_reset_replay(client):
    result = inject(client, 'missing_telemetry')
    aid = result['alert_ids'][0]
    report = client.post(f'/api/alerts/{aid}/investigate').json()
    assert any('Process telemetry not observed' in v for v in report['limitations'])
    assert len(report['evidence_ids']) == 2
    assert client.post('/api/demo/reset-alerts').status_code == 200
    assert client.get('/api/alerts').json()['total'] == 0
    assert inject(client, 'missing_telemetry')['alert_ids'] == [aid]


def test_real_cve_exposure_and_patch_impact(client):
    response = client.post('/api/demo/inject-cve', json={'fixture_id': 'CVE-2024-21762'})
    assert response.status_code == 200, response.text
    alerts = client.get('/api/alerts?kind=vulnerability').json()['items']
    match = next(a for a in alerts if a['asset_ids'] == ['PWR-FW-01'])
    report = client.post(f"/api/alerts/{match['alert_id']}/investigate").json()
    assert report['assessment'] == 'vulnerability_exposure'
    assert report['verified_cve_ids'] == ['CVE-2024-21762'] and report['evidence_ids'] == []
    before = client.get(f"/api/alerts/{match['alert_id']}").json()
    impact = client.post('/api/simulation/patch-impact', json={'threat_id': 'CVE-2024-21762', 'patched_version': '7.4.11'}).json()
    assert impact['before_affected_count'] == 2 and impact['after_affected_count'] == 0
    assert client.get(f"/api/alerts/{match['alert_id']}").json() == before
    relevant = client.get('/api/threats?relevant=true').json()
    assert relevant['total'] == 1 and relevant['items'][0]['threat_id'] == 'CVE-2024-21762'


def test_legacy_event_reports_cite_all_original_evidence(client):
    original = json.loads((ROOT / 'data/events.json').read_text(encoding='utf-8'))[:3]
    result = client.post('/api/correlate/events', json=original).json()
    aid = result['created'][0]
    r = client.post(f'/api/alerts/{aid}/investigate')
    assert r.status_code == 200, r.text
    report = r.json()
    assert set(report['evidence_ids']) == {e['event_id'] for e in original}
    assert all(e['retrieved_at'] is None for e in report['evidence'])


def test_overview_and_frontend_history_fallback(client):
    o = client.get('/api/overview').json()
    assert isinstance(o['trend'], list) and o['open_alerts'] == 0 and o['matched_assets'] == 0
    assert o['threats_total'] > 0
    for path in ('/app', '/app/incidents', '/app/analytics', '/app/signals'):
        r = client.get(path)
        assert r.status_code == 200 and 'text/html' in r.headers['content-type']
    for path in ('/api/not-real', '/.env', '/assets/missing.js'):
        assert client.get(path).status_code == 404


def test_simulated_signal_visible_and_correlated(client):
    response = client.post('/api/demo/simulate-signal', json={'fixture_id': 'DEMO-VULN-001', 'signal_type': 'epss_jump'})
    assert response.status_code == 200 and response.json()['is_simulated'] is True
    assert client.get('/api/signals').json()['count'] > 0
    assert any('DEMO-VULN-001' in a['threat_ids'] for a in client.get('/api/alerts').json()['items'])


def test_persisted_investigation_demo_scope_closed_when_demo_disabled(client, monkeypatch):
    result = inject(client, 'no_cve_suspicious_chain')
    monkeypatch.setenv('DEMO_MODE', 'false')
    assert client.post(f"/api/alerts/{result['alert_ids'][0]}/investigate").status_code == 403
