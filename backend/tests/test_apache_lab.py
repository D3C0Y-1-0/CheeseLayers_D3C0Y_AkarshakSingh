import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import delete, select

from test_live_lab import lab
from app import apache_lab
from app.asset_store import get_asset_store
from app.correlator import AlertRow
from app.database import SessionLocal
from app.models import ApacheObservation, LabAction, Threat
from shadow_watch.apache import parse
from shadow_watch.integration import StoredIncidentProvider

VULN, FIXED, RELAY = "a" * 64, "b" * 64, "c" * 64


@pytest.fixture
def apache(lab, monkeypatch, tmp_path):
    with SessionLocal() as db:
        preexisting = {tid for tid in (apache_lab.CVE, "CIAD-2021-0039-REFERENCE") if db.get(Threat, tid)}
    (tmp_path / "lab/apache/runtime").mkdir(parents=True)
    source = Path(__file__).resolve().parents[2] / "lab/apache"
    for name in ("advisory_sources.json", "httpd.conf", "nginx.conf"):
        (tmp_path / "lab/apache" / name).write_text((source / name).read_text(encoding="utf-8"), encoding="utf-8")
    runtime = tmp_path / "lab/apache/runtime/nginx.conf"
    runtime.write_text((source / "nginx.conf").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(apache_lab, "ROOT", tmp_path)
    def docker(*args):
        if args[0] == "inspect":
            cid = args[-1]
            service = "vulnerable" if cid == VULN else "patched" if cid == FIXED else "relay"
            return json.dumps({"Config": {"Labels": {"com.docker.compose.project": "vectra-apache-lab",
                "com.docker.compose.service": service}, "User": "1000:1000"},
                "HostConfig": {"ReadonlyRootfs": True, "CapDrop": ["ALL"]}, "State": {"Running": True},
                "Image": "sha256:" + cid})
        if args[:2] == ("image", "inspect"):
            version = "2.4.49" if args[2].endswith(VULN) else "2.4.51"
            return json.dumps(["httpd@" + apache_lab.DIGESTS[version]])
        if args[0] == "exec":
            if args[2] == "nginx":
                return ""
            return "Server version: Apache/" + ("2.4.49" if args[1] == VULN else "2.4.51") + " (Unix)"
        if args[0] == "compose":
            return {"vulnerable": VULN, "patched": FIXED, "relay": RELAY}.get(args[-1], "") + "\n"
        raise AssertionError(args)
    monkeypatch.setattr(apache_lab, "docker", docker)
    with SessionLocal() as db:
        db.execute(delete(ApacheObservation))
        db.commit()
    control, _ = lab
    for cid in (VULN, FIXED):
        result = control.post("/api/lab/apache/register", json={"container_id": cid})
        assert result.status_code == 200, result.text
    yield control, runtime, docker
    with SessionLocal() as db:
        db.execute(delete(ApacheObservation))
        for tid in (apache_lab.CVE, "CIAD-2021-0039-REFERENCE"):
            if tid not in preexisting:
                db.execute(delete(Threat).where(Threat.threat_id == tid))
        db.commit()


def line(asset="LAB-APACHE-VULN", status=200, path="/documents/.%2e/internal/dummy-records.txt", request_id="d" * 32):
    return f"2026-01-01T00:00:00.123456789Z 2026-01-01T00:00:00+0000|172.20.0.4|12345|GET|GET {path} HTTP/1.0|{status}|77|{asset}|192.0.2.10|{request_id}"


def test_strict_original_request_parser_and_identity():
    parsed = parse(VULN, line())
    assert parsed["signature_match"] and parsed["relay_observed_peer"] == "192.0.2.10"
    assert parsed["request_id"] == "d" * 32
    assert parse(VULN, line(path="/documents/notice.txt"))["signature_match"] is False
    query = parse(VULN, line(path="/documents/notice.txt?token=not-retained"))
    assert query["path"] == "/documents/notice.txt" and query["query_values_discarded"]
    for raw in ("Apache startup message", line().replace("|200|", "|999|"), line().replace("|LAB-APACHE-VULN|", "|OTHER|")):
        with pytest.raises(ValueError):
            parse(VULN, raw)


def test_verified_version_exposure_log_ingestion_and_cve_report(apache):
    control, _, _ = apache
    assert get_asset_store().get("LAB-APACHE-VULN").software[0].version == "2.4.49"
    result = control.post("/api/lab/apache/logs", json={"container_id": VULN, "lines": [line()]})
    assert result.status_code == 200, result.text
    assert len(result.json()["accepted"]) == 1
    again = control.post("/api/lab/apache/logs", json={"container_id": VULN, "lines": [line()]})
    assert again.json()["duplicates"] == result.json()["accepted"]
    with SessionLocal() as db:
        alerts = [a for a in db.scalars(select(AlertRow)) if a.kind == "behaviour"]
        assert len(alerts) == 1
        context = StoredIncidentProvider(SessionLocal).get_incident(alerts[0].alert_id)
    assert apache_lab.CVE in context.verified_cve_ids
    from ai.fallback import build_fallback_report
    report = build_fallback_report(context)
    assert apache_lab.CVE in report.summary and "APACHE-TRAVERSAL-001" in report.summary
    assert "Compromise not confirmed" in report.limitations
    draft = control.post(f"/api/alerts/{alerts[0].alert_id}/certin-draft")
    assert draft.status_code == 200, draft.text
    assert any(t["cve_id"] == apache_lab.CVE for t in draft.json()["related_threats"])
    assert draft.json()["sent"] is False


def test_same_attempt_on_fixed_version_is_not_verified_affected(apache):
    control, _, _ = apache
    response = control.post("/api/lab/apache/logs", json={"container_id": FIXED,
        "lines": [line(asset="LAB-APACHE-PATCHED", status=404)]})
    assert response.status_code == 200
    with SessionLocal() as db:
        alert = next(a for a in db.scalars(select(AlertRow)) if a.kind == "behaviour")
    context = StoredIncidentProvider(SessionLocal).get_incident(alert.alert_id)
    assert context.verified_cve_ids == () and context.candidate_cve_ids == (apache_lab.CVE,)


def test_actual_route_configuration_and_independent_verification(apache, monkeypatch):
    control, runtime, _ = apache
    applied = control.post("/api/lab/apache/patch", json={"action": "patch", "reason": "Owned live district service fix"})
    assert applied.status_code == 200, applied.text
    assert applied.json()["action"]["state"] == "applied"
    assert "proxy_pass http://vulnerable:8080;" not in runtime.read_text(encoding="utf-8")
    assert get_asset_store().get("LAB-APACHE-VULN").software[0].version == "2.4.51"
    def probe(target, kind):
        return dict(status=200 if kind == "public_notice" else 404,
            public_notice_verified=kind == "public_notice", dummy_record_disclosed=False, request_id="e" * 32)
    monkeypatch.setattr(apache_lab, "probe_request", probe)
    verified = control.post("/api/lab/apache/verify/" + applied.json()["action"]["action_id"])
    assert verified.json()["verified"] is True
    assert verified.json()["action"]["verification_request_id"] == "e" * 32
    rollback = control.post("/api/lab/apache/patch", json={"action": "rollback", "reason": "Restore controlled demonstration"})
    assert rollback.status_code == 200
    assert "proxy_pass http://vulnerable:8080;" in runtime.read_text(encoding="utf-8")
    assert get_asset_store().get("LAB-APACHE-VULN").software[0].version == "2.4.49"


def test_reload_failure_restores_configuration_without_false_patch(apache, monkeypatch):
    control, runtime, original_docker = apache
    original = runtime.read_text(encoding="utf-8")
    def failing(*args):
        if args[0] == "exec" and args[2] == "nginx":
            raise HTTPException(503, "test reload failure")
        return original_docker(*args)
    monkeypatch.setattr(apache_lab, "docker", failing)
    result = control.post("/api/lab/apache/patch", json={"action": "patch", "reason": "Test failed patch application"})
    assert result.status_code == 503
    assert runtime.read_text(encoding="utf-8") == original
    assert get_asset_store().get("LAB-APACHE-VULN").software[0].version == "2.4.49"
