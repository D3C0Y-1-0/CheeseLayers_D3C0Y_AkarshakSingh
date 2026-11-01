import json
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app import live_lab
from app.asset_store import get_asset_store
from app.correlator import AlertRow, CorrelationEngine, EventRow
from app.database import SessionLocal, init_db
from app.main import app
from app.models import InventoryOverride, LabAction, LabObservation, LabSetting, Threat
from shadow_watch.integration import StoredIncidentProvider
from shadow_watch.live import verdict, virtual_document


@pytest.fixture
def lab(monkeypatch):
    monkeypatch.setenv("VECTRA_LAB_ENABLED", "true")
    init_db()
    with SessionLocal() as db:
        CorrelationEngine(db).reset()
        for table in (InventoryOverride, LabAction, LabObservation, LabSetting):
            db.execute(delete(table))
        db.commit()
    control = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 12345))
    portal = TestClient(live_lab.portal_app, client=("192.0.2.10", 23456))
    assert control.get("/lab").status_code == 200
    control.headers["X-Vectra-Lab-Token"] = live_lab.TOKEN
    yield control, portal
    with SessionLocal() as db:
        CorrelationEngine(db).reset()
        for table in (InventoryOverride, LabAction, LabObservation, LabSetting):
            db.execute(delete(table))
        db.execute(delete(Threat).where(Threat.threat_id == live_lab.THREAT_ID))
        db.commit()


def act(control, kind, **extra):
    response = control.post("/api/lab/actions", json=dict(kind=kind, reason="Authorised isolated lab check", **extra))
    assert response.status_code == 200, response.text
    return response.json()


def test_disabled_and_admin_boundary(lab, monkeypatch):
    control, portal = lab
    assert portal.get("/api/lab/state").status_code == 404
    remote = TestClient(app, client=("192.0.2.10", 123))
    assert remote.get("/lab").status_code == 403
    assert remote.get("/api/lab/state", headers={"X-Vectra-Lab-Token": live_lab.TOKEN}).status_code == 403
    assert control.get("/api/lab/state", headers={"X-Vectra-Lab-Token": "wrong"}).status_code == 403
    assert control.get("/lab", headers={"Host": "untrusted.example"}).status_code == 403
    monkeypatch.setenv("VECTRA_LAB_ENABLED", "false")
    assert control.get("/lab").status_code == 404
    assert portal.get("/document").status_code == 404


def test_live_request_detection_evidence_and_no_forged_attribution(lab):
    control, portal = lab
    assert portal.get("/document").status_code == 200
    with SessionLocal() as db:
        assert not list(db.scalars(select(AlertRow)))
    response = portal.get("/document", params={"name": "../internal/dummy-records.json"},
                          headers={"X-Forwarded-For": "8.8.8.8"})
    assert response.status_code == 200 and "FICTIONAL CITIZEN" in response.text
    eid = response.headers["X-Vectra-Event-ID"]
    evidence = control.get(f"/api/lab/observations/{eid}").json()
    assert evidence["peer_ip"] == "192.0.2.10" and evidence["forwarded_for_trusted"] is False
    assert evidence["finding"]["rule_id"] == "LIVE-WEB-001"
    with SessionLocal() as db:
        [alert] = list(db.scalars(select(AlertRow)))
        assert alert.data["threat_ids"] == []  # Never invent a CVE from a generic traversal.
        assert eid in alert.data["evidence_ids"]
        aid = alert.alert_id
    ctx = StoredIncidentProvider(SessionLocal).get_incident(aid)
    assert ctx.additional_evidence and all(c.retrieved_at for c in ctx.additional_evidence)
    from ai.fallback import build_fallback_report
    report = build_fallback_report(ctx)
    assert "LIVE-WEB-001" in report.summary and "Parent-directory segment" in report.summary


def test_block_effect_verification_peer_scope_release_and_expiry(lab, monkeypatch):
    control, portal = lab
    hit = portal.get("/document", params={"name": "../internal/dummy-records.json"})
    eid = hit.headers["X-Vectra-Event-ID"]
    bad = control.post("/api/lab/actions", json=dict(kind="block", peer_ip="192.0.2.11", evidence_id=eid, reason="Lab test"))
    assert bad.status_code == 400
    data = act(control, "block", peer_ip="192.0.2.10", evidence_id=eid, ttl_seconds=15)
    assert data["action"]["state"] == "applied"
    assert portal.get("/document").status_code == 429
    other = TestClient(live_lab.portal_app, client=("192.0.2.11", 123))
    assert other.get("/document").status_code == 200
    state = control.get("/api/lab/state").json()
    assert state["actions"][0]["state"] == "verified"
    actual_now = live_lab.now()
    monkeypatch.setattr(live_lab, "now", lambda: actual_now + timedelta(seconds=16))
    assert portal.get("/document").status_code == 200
    assert control.get("/api/lab/state").json()["actions"][0]["state"] == "expired"
    act(control, "block", peer_ip="192.0.2.10", evidence_id=eid)
    act(control, "release", peer_ip="192.0.2.10")
    assert portal.get("/document").status_code == 200


def test_exposure_actual_patch_recheck_and_reexposure_reopens(lab):
    control, portal = lab
    response = control.post(f"/api/lab/reassess/{live_lab.ASSET_ID}")
    assert response.status_code == 200, response.text
    [assessment] = response.json()["assessments"]
    assert assessment["match_detail"] == "confirmed_affected" and assessment["cve_id"] is None
    patched = act(control, "patch")
    assert patched["exposure"]["assessments"][0]["match_detail"] == "confirmed_unaffected"
    # Verification is absent until another request actually tests the boundary.
    assert patched["action"]["state"] == "applied"
    assert portal.get("/document", params={"name": "../internal/dummy-records.json"}).status_code == 403
    assert portal.get("/document").status_code == 200
    assert control.get("/api/lab/state").json()["actions"][0]["state"] == "verified"
    with SessionLocal() as db:
        row = next(a for a in db.scalars(select(AlertRow)) if a.kind == "vulnerability")
        assert row.data["lifecycle_status"] == "mitigated"
    act(control, "rollback")
    with SessionLocal() as db:
        row = next(a for a in db.scalars(select(AlertRow)) if a.kind == "vulnerability")
        assert row.data["lifecycle_status"] == "detected" and row.data["match_detail"] == "confirmed_affected"
    assert portal.get("/document", params={"name": "../internal/dummy-records.json"}).status_code == 200


def test_real_cve_reassessment_inventory_update_and_product_removal(lab):
    control, _ = lab
    path = Path(__file__).resolve().parents[2] / "data/demo_cves.json"
    raw = next(t for t in json.loads(path.read_text(encoding="utf-8")) if t["threat_id"] == "CVE-2024-21762")
    from app.contracts import ThreatRecord
    with SessionLocal() as db:
        if not db.get(Threat, raw["threat_id"]):
            values = ThreatRecord.model_validate(raw).model_dump()
            db.add(Threat(**{c.name: values[c.name] for c in Threat.__table__.columns}))
            db.commit()
    first = control.post("/api/lab/reassess/PWR-FW-01").json()
    matched = next(a for a in first["assessments"] if a["threat_id"] == raw["threat_id"])
    assert matched["match_detail"] == "confirmed_affected"
    sw = get_asset_store().get("PWR-FW-01").software[0].model_dump()
    sw.update(version="7.4.11", cpe=None)
    changed = control.put("/api/lab/inventory/PWR-FW-01", json=dict(software=[sw], reason="Lab inventory observation"))
    assert changed.status_code == 200, changed.text
    assert get_asset_store().get("PWR-FW-01").software[0].version == "7.4.11"
    matched = next(a for a in changed.json()["assessments"] if a["threat_id"] == raw["threat_id"])
    assert matched["match_detail"] == "confirmed_unaffected"
    removed = control.put("/api/lab/inventory/PWR-FW-01", json=dict(software=[], reason="Product removed in lab"))
    assert next(a for a in removed.json()["assessments"] if a["threat_id"] == raw["threat_id"])["match_detail"] == "needs_verification"


def test_missing_inventory_and_advisory_metadata_are_not_safe(lab):
    from app.contracts import ThreatRecord
    from app.matcher import match_asset
    asset = get_asset_store().get(live_lab.ASSET_ID)
    with SessionLocal() as db:
        from app.correlator import threat_from_row
        threat = threat_from_row(db.get(Threat, live_lab.THREAT_ID))
    unknown = type(asset).model_validate(asset.model_dump() | {"software": [], "inventory_complete": False})
    assert match_asset(unknown, threat).match_detail == "needs_verification"
    missing = ThreatRecord.model_validate(threat.model_dump() | {"affected_configurations": []})
    assert match_asset(asset, missing).match_detail == "needs_verification"


def test_certin_advisory_arrival_uses_cve_ranges_not_title_guessing(lab):
    control, _ = lab
    from app.hooks import on_new_threat
    from app.contracts import ThreatRecord
    with SessionLocal() as db:
        path = Path(__file__).resolve().parents[2] / "data/demo_cves.json"
        raw = next(t for t in json.loads(path.read_text(encoding="utf-8")) if t["threat_id"] == "CVE-2024-21762")
        if not db.get(Threat, raw["threat_id"]):
            values = ThreatRecord.model_validate(raw).model_dump()
            db.add(Threat(**{c.name: values[c.name] for c in Threat.__table__.columns}))
        # Deliberately synthetic IDs for the test: relationship logic must not invent a real advisory.
        record = ThreatRecord.model_validate(dict(threat_id="LAB-CERTIN-ADVISORY", source="certin", type="advisory",
            title="[SIMULATED TEST] advisory relation", is_simulated=True, cve_ids=["CVE-2024-21762"],
            references=["https://www.cert-in.org.in/"], raw_ref="backend/tests/test_live_lab.py"))
        db.add(Threat(**record.model_dump()))
        db.commit()
    try:
        on_new_threat("LAB-CERTIN-ADVISORY", "new_certin_advisory")
        result = control.post("/api/lab/reassess/PWR-FW-01").json()
        assessed = next(a for a in result["assessments"] if a["threat_id"] == "CVE-2024-21762")
        assert any(a["threat_id"] == "LAB-CERTIN-ADVISORY" for a in assessed["certin_advisories"])
        assert assessed["created"] == []  # The hook already created the exposure.
        assert assessed["updated"]
    finally:
        with SessionLocal() as db:
            db.execute(delete(Threat).where(Threat.threat_id == "LAB-CERTIN-ADVISORY"))
            db.commit()


def test_live_auth_sequence_and_passwords_not_stored(lab):
    control, portal = lab
    for _ in range(9):
        assert portal.post("/login", json=dict(username="demo-user", password="DO-NOT-STORE")).status_code == 401
    assert not any(o["finding"] for o in control.get("/api/lab/state").json()["observations"])
    portal.post("/login", json=dict(username="demo-user", password="DO-NOT-STORE"))
    observations = control.get("/api/lab/state").json()["observations"]
    assert observations[0]["finding"]["rule_id"] == "LIVE-AUTH-001"
    assert "DO-NOT-STORE" not in json.dumps(observations)
    portal.post("/login", json=dict(username="demo-user", password="lab-only-password"))
    success = control.get("/api/lab/state").json()["observations"][0]
    assert success["finding"]["rule_id"] == "LIVE-AUTH-002"
    assert len(success["finding"]["evidence_ids"]) == 11


def test_multi_account_pattern_and_expired_history(lab):
    control, portal = lab
    for username in ("alice", "bob", "carol", "dave", "erin"):
        portal.post("/login", json=dict(username=username, password="wrong"))
    assert control.get("/api/lab/state").json()["observations"][0]["finding"]["rule_id"] == "LIVE-AUTH-003"
    current = dict(event_id="now", kind="login", at=live_lab.now(), peer_ip="192.0.2.1", username="test", status=200)
    old = [dict(current, at=current["at"] - timedelta(seconds=61), status=401, event_id=str(i)) for i in range(12)]
    assert verdict(current, old) is None


@pytest.mark.parametrize("name", ["../../.env", "../../../Windows/win.ini", "/etc/passwd", "..\\..\\.env"])
def test_document_store_never_reads_host_files(name):
    assert virtual_document(name, False)[0] == 404
    assert virtual_document(name, True)[0] in (403, 404)


def test_auth_aggregate_requires_configured_window_and_valid_threshold():
    from shadow_watch.engine import ShadowWatchEngine
    from shadow_watch.normalize import EVENT
    from shadow_watch.rules import RuleConfig
    from shadow_watch.schemas import DetectionContext
    with pytest.raises(ValueError):
        RuleConfig(minimum_failed_logins=0)
    stamp = live_lab.now().isoformat()
    raw = dict(event_id="LIVE-AUTH-WINDOW-TEST", asset_id=live_lab.ASSET_ID, sensor_id="lab-auth",
        observed_at=stamp, ingested_at=stamp, source_type="auth_sensor", source="vectra_lab", is_simulated=True,
        raw_ref="backend/tests/test_live_lab.py", event_type="auth_window",
        details=dict(failed_count=10, invalid_user_count=0, unique_source_count=1, unique_user_count=1,
                     window_seconds=3600))
    engine = ShadowWatchEngine()
    context = DetectionContext(protected_asset_ids=frozenset({live_lab.ASSET_ID}))
    assert engine.evaluate([EVENT.validate_python(raw)], context) == []
    raw["details"]["window_seconds"] = 60
    assert engine.evaluate([EVENT.validate_python(raw)], context)[0].detector_id == "SW-AUTH-001"


def test_bounded_investigation_keeps_recent_detection_after_many_normal_events(lab):
    from app.contracts import SecurityEvent
    from datetime import timedelta
    control, _ = lab
    begin = live_lab.now() - timedelta(minutes=1)
    events = [SecurityEvent(event_id=f"BOUND-{i:03}", asset_id=live_lab.ASSET_ID,
        timestamp=begin + timedelta(milliseconds=i), event_type="http", source_sensor="test-portal",
        is_simulated=True, shadow_watch_evaluated=True, details={}) for i in range(130)]
    events[-1].rule_id = "LIVE-TEST-LATE"
    events[-1].confidence = "medium"
    events[-1].details = dict(attack_signal="http_anomaly", attack_label="Late observed finding",
        detection_reason="A detector finding arrived after ordinary traffic")
    with SessionLocal() as db:
        result = CorrelationEngine(db).ingest_events(events)
    aid = result["created"][0]
    ctx = StoredIncidentProvider(SessionLocal).get_incident(aid)
    assert len(ctx.additional_evidence) == 100
    assert events[-1].event_id in {e.evidence_id for e in ctx.additional_evidence}
    evidence = control.get(f"/api/alerts/{aid}/evidence").json()
    assert evidence["truncated"] and len(evidence["items"]) == 100
    assert events[-1].event_id in {e["event_id"] for e in evidence["items"]}


def test_inventory_change_rejects_conflicting_cpe(lab):
    control, _ = lab
    software = get_asset_store().get("PWR-FW-01").software[0].model_dump()
    software["version"] = "7.4.11"
    reply = control.put("/api/lab/inventory/PWR-FW-01", json=dict(software=[software], reason="Observed upgrade with stale CPE"))
    assert reply.status_code == 422
    assert get_asset_store().get("PWR-FW-01").software[0].version == "7.2.6"


def test_reassessment_uses_matcher_product_normalisation(lab):
    control, _ = lab
    from app.apache_lab import ensure_intelligence
    with SessionLocal() as db:
        existed = {tid for tid in ("CVE-2021-41773", "CIAD-2021-0039-REFERENCE") if db.get(Threat, tid)}
        ensure_intelligence(db)
    try:
        reply = control.put("/api/lab/inventory/GOV-LAND-01", json=dict(software=[dict(vendor="Apache",
            product="HTTP-Server", version="2.4.49", cpe=None)], reason="Observed product with a normalised alias"))
        assert reply.status_code == 200, reply.text
        match = next(a for a in reply.json()["assessments"] if a["threat_id"] == "CVE-2021-41773")
        assert match["match_detail"] == "confirmed_affected"
    finally:
        with SessionLocal() as db:
            for tid in ("CVE-2021-41773", "CIAD-2021-0039-REFERENCE"):
                if tid not in existed:
                    db.execute(delete(Threat).where(Threat.threat_id == tid))
            db.commit()


def test_portal_form_generic_observations_and_no_password_recording(lab):
    control, portal = lab
    page = portal.get("/")
    assert page.status_code == 200 and 'id="loginForm"' in page.text
    assert "fetch('/login'" in page.text
    assert page.headers["Cache-Control"] == "no-store"
    assert portal.post("/login", json={"username": "invalid user", "password": "BODY-SECRET"}).status_code == 422
    portal.get("/missing", params={"password": "QUERY-SECRET", "q": "ordinary search"})
    rows = control.get("/api/lab/state").json()["observations"]
    assert {r["status"] for r in rows} >= {200, 404, 422}
    assert not any(r["finding"] for r in rows)
    assert "BODY-SECRET" not in json.dumps(rows) and "QUERY-SECRET" not in json.dumps(rows)


@pytest.mark.parametrize("payload,label", [
    ("1 UNION SELECT name FROM demo", "SQL injection attempt"),
    ("<script>alert(1)</script>", "Cross-site scripting attempt"),
    ("127.0.0.1;whoami", "Command injection attempt"),
    ("../../internal/demo", "Path traversal attempt"),
])
def test_auto_classification_from_actual_url_not_a_selected_scenario(lab, payload, label):
    control, portal = lab
    response = portal.get("/search", params={"q": payload})
    assert response.status_code == 404  # No SQL engine, script or shell was executed.
    row = control.get('/api/lab/observations/' + response.headers['X-Vectra-Event-ID']).json()
    assert label in row['finding']['label']
    assert row['finding']['rule_id'] == 'LIVE-HTTP-SIGNATURE'
    with SessionLocal() as db:
        alerts = list(db.scalars(select(AlertRow)))
        assert alerts and all(not a.data['threat_ids'] for a in alerts)


def test_web_discovery_threshold_and_benign_near_miss(lab):
    control, portal = lab
    for i in range(7):
        portal.get(f"/missing-{i}")
    assert not any(o['finding'] for o in control.get('/api/lab/state').json()['observations'])
    response = portal.get('/missing-7')
    row = control.get('/api/lab/observations/' + response.headers['X-Vectra-Event-ID']).json()
    assert row['finding']['rule_id'] == 'LIVE-WEB-003'
    assert 'possible scanning' in row['finding']['reason']


def test_block_boundary_all_routes_methods_invalid_payload_and_spoofed_headers(lab):
    control, portal = lab
    eid = portal.get('/document', params={'name': '../internal/dummy-records.json'}).headers['X-Vectra-Event-ID']
    act(control, 'block', peer_ip='192.0.2.10', evidence_id=eid)
    reconnected = TestClient(live_lab.portal_app, client=('192.0.2.10', 50000))
    mapped = TestClient(live_lab.portal_app, client=('::ffff:192.0.2.10', 50001))
    for client in (portal, reconnected, mapped):
        for method, path in [('GET', '/'), ('POST', '/login'), ('HEAD', '/document'), ('OPTIONS', '/unknown')]:
            response = client.request(method, path, content='not-json', headers={'X-Forwarded-For': '192.0.2.99'})
            assert response.status_code == 429
    assert TestClient(live_lab.portal_app, client=('192.0.2.11', 123)).get('/').status_code == 200
    act(control, 'release', peer_ip='192.0.2.10')
    assert portal.get('/').status_code == 200


def test_sustained_retries_renew_then_quiet_expiry(lab, monkeypatch):
    control, portal = lab
    eid = portal.get('/document', params={'name': '../internal/dummy-records.json'}).headers['X-Vectra-Event-ID']
    started = live_lab.now()
    monkeypatch.setattr(live_lab, 'now', lambda: started)
    action = act(control, 'block', peer_ip='192.0.2.10', evidence_id=eid, ttl_seconds=300)['action']
    monkeypatch.setattr(live_lab, 'now', lambda: started + timedelta(seconds=299))
    assert portal.get('/').status_code == 429
    monkeypatch.setattr(live_lab, 'now', lambda: started + timedelta(seconds=301))
    assert live_lab.blocked('192.0.2.10') is True  # original deadline no longer bypasses enforcement
    with SessionLocal() as db:
        data = db.get(LabAction, action['action_id']).data
        assert data['renewal_count'] == 1 and data['state'] == 'verified'
    monkeypatch.setattr(live_lab, 'now', lambda: started + timedelta(seconds=600))
    assert portal.get('/').status_code == 200
    assert live_lab.blocked('192.0.2.10') is False


def test_opt_in_auto_policy_only_after_evidence_and_no_ml_autoblock(lab):
    control, portal = lab
    policy = control.put('/api/lab/policy', json=dict(auto_block=True, renew_on_retry=True,
        ttl_seconds=300, reason='Owned lab automated response test'))
    assert policy.status_code == 200
    for _ in range(9):
        assert portal.post('/login', json=dict(username='demo-user', password='wrong')).status_code == 401
    assert not live_lab.blocked('192.0.2.10')
    assert portal.post('/login', json=dict(username='demo-user', password='wrong')).status_code == 401
    assert portal.post('/login', json=dict(username='demo-user', password='wrong')).status_code == 429
    actions = control.get('/api/lab/state').json()['actions']
    auto = next(a for a in actions if a.get('source') == 'deterministic_policy')
    assert auto['rule_id'] == 'LIVE-AUTH-001' and auto['evidence_id']


def test_console_button_contract_and_activity_boundary(lab):
    import re
    control, portal = lab
    html = control.get('/lab').text
    js = control.get('/lab/activity.js')
    assert js.status_code == 200
    ids = set(re.findall(r'id="([^"]+)"', html))
    direct_refs = set(re.findall(r"el\('([^']+)'\)", html + js.text))
    assert direct_refs <= ids
    assert 'Replay retained events' in html and 'RECORDED REPLAY' in js.text
    assert portal.get('/lab/activity.js').status_code == 404


def test_assistant_queries_are_read_only_and_actions_need_review(lab):
    control, portal = lab
    before = control.get('/api/lab/state').json()['actions']
    empty = control.post('/api/lab/assistant', json={'message': 'block latest peer'}).json()
    assert empty['proposal'] is None
    portal.get('/document', params={'name': '../internal/dummy-records.json'})
    proposal = control.post('/api/lab/assistant', json={'message': 'block latest peer'}).json()
    assert proposal['proposal']['body']['peer_ip'] == '192.0.2.10'
    assert control.get('/api/lab/state').json()['actions'] == before
    assert control.post('/api/lab/actions', json=proposal['proposal']['body']).status_code == 200
    assert portal.get('/').status_code == 429
    public = control.post('/api/assistant/query', json={'message': 'patch portal'}).json()
    assert public['proposal'] is None
    assert control.post('/api/lab/assistant', json={'message': "don't block latest peer"}).json()['proposal'] is None
    assert control.post('/api/lab/assistant', json={'message': 'block 192.0.2.99'}).json()['proposal'] is None
    assert control.post('/api/assistant/query', json={'message': 'show open incidents'}).json()['links']


def test_distributed_failures_do_not_require_a_per_peer_burst(lab):
    control, _ = lab
    # Four observed test peers; each stays below the per-peer 10-failure threshold.
    peers = [TestClient(live_lab.portal_app, client=(f'192.0.2.{i}', 1234)) for i in range(30, 34)]
    for i in range(30):
        response = peers[i % 4].post('/login', json={'username': 'demo-user', 'password': 'wrong'})
        assert response.status_code == 401
    row = control.get('/api/lab/observations/' + response.headers['X-Vectra-Event-ID']).json()
    assert row['finding']['rule_id'] == 'LIVE-AUTH-004'
    assert 'not proof of a botnet' in row['finding']['reason']
