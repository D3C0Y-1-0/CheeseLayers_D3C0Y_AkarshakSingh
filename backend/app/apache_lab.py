"""Local, opt-in independent Apache log ingestion. Commands are constrained to this lab project."""
import hashlib
import ipaddress
import json
import re
import subprocess
from datetime import datetime, timedelta
from uuid import uuid4
from typing import Literal
from threading import RLock

import httpx
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from .asset_store import get_asset_store
from .contracts import Asset, SecurityEvent, SoftwareItem, ThreatRecord
from .correlator import CorrelationEngine, threat_from_row
from .database import SessionLocal
from .live_lab import admin, now, reassess
from .matcher import match_asset
from .models import ApacheObservation, InventoryOverride, LabAction, LabSetting, Threat
from shadow_watch.apache import parse

router = APIRouter(tags=["Owned Apache CVE lab"], dependencies=[Depends(admin)])
CONTROL_LOCK = RLock()
ROOT = Path(__file__).resolve().parents[2]
SOURCE = "lab/apache/advisory_sources.json"
CVE = "CVE-2021-41773"
SERVICES = {"vulnerable": ("LAB-APACHE-VULN", "2.4.49"), "patched": ("LAB-APACHE-PATCHED", "2.4.51")}
DIGESTS = {"2.4.49": "sha256:dcba0d12e2362fb0c50ec524ae8aa1cca4a4ba7216617a57e7bbca20767e79cc",
           "2.4.51": "sha256:0c8dd1d9f90f0da8a29a25dcc092aed76b09a1c9e5e6e93c8db3903c8ce6ef29"}


def docker(*args):
    try:
        return subprocess.run(["docker", *args], check=True, capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        raise HTTPException(503, "Local Docker command failed; check only the owned lab containers") from None


def inspect_owned(container_id):
    if not re.fullmatch(r"[a-f0-9]{64}", container_id):
        raise HTTPException(422, "full container ID required")
    obj = json.loads(docker("inspect", "--format", "{{json .}}", container_id))
    labels = obj["Config"].get("Labels") or {}
    service = labels.get("com.docker.compose.service")
    if labels.get("com.docker.compose.project") != "vectra-apache-lab" or service not in SERVICES:
        raise HTTPException(403, "not an owned Apache lab target")
    host = obj["HostConfig"]
    if not host.get("ReadonlyRootfs") or "ALL" not in (host.get("CapDrop") or []) or obj["Config"].get("User") != "1000:1000":
        raise HTTPException(409, "lab target confinement differs from the approved configuration")
    return obj, service


def ensure_intelligence(db):
    source = json.loads((ROOT / SOURCE).read_text(encoding="utf-8"))
    cfg = dict(vendor="apache", product="http_server", cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    existing = db.get(Threat, CVE)
    if existing is None:
        record = ThreatRecord(threat_id=CVE, cve_id=CVE, cve_ids=[CVE], type="vulnerability",
            source="apache_vendor_reference", title="Apache HTTP Server 2.4.49 path traversal", severity="critical",
            affected_configurations=[cfg], references=[source["vendor_reference"], source["certin_reference"]],
            raw_ref=SOURCE, is_simulated=False, tags=["reviewed_reference_metadata"])
        db.add(Threat(**record.model_dump()))
    elif not existing.affected_configurations:
        existing.affected_configurations = [cfg]
        existing.raw_refs = list(dict.fromkeys((existing.raw_refs or []) + [SOURCE]))
    reference_id = "CIAD-2021-0039-REFERENCE"
    if db.get(Threat, reference_id) is None:
        record = ThreatRecord(threat_id=reference_id, source="certin", type="advisory", cve_ids=[CVE],
            title="CERT-In CIAD-2021-0039 (reviewed reference metadata)", references=[source["certin_reference"]],
            raw_ref=SOURCE, is_simulated=False, tags=["reviewed_reference_metadata", "not_a_fresh_scrape"])
        db.add(Threat(**record.model_dump()))
    db.commit()


class Registration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    container_id: str = Field(pattern=r"^[a-f0-9]{64}$")


@router.post("/api/lab/apache/register")
def register(body: Registration):
    with CONTROL_LOCK:
        return register_owned(body)


def register_owned(body):
    obj, service = inspect_owned(body.container_id)
    asset_id, expected = SERVICES[service]
    if not obj["State"]["Running"]:
        raise HTTPException(409, "start this lab target before registration")
    version = docker("exec", body.container_id, "/usr/local/apache2/bin/httpd", "-v")
    if f"Apache/{expected} " not in version:
        raise HTTPException(409, "unexpected Apache binary version")
    digests = json.loads(docker("image", "inspect", obj["Image"], "--format", "{{json .RepoDigests}}"))
    if not any(d.endswith("@" + DIGESTS[expected]) for d in digests):
        raise HTTPException(409, "unexpected lab image digest")
    asset = Asset(asset_id=asset_id, hostname=f"fictional-district-apache-{service}", ip="127.0.0.1",
        organisation="Fictional Indian District Citizen Services", sector="govt", role="Owned isolated Apache CVE lab",
        os=None, software=[SoftwareItem(vendor="apache", product="http_server", version=expected,
            cpe=f"cpe:2.3:a:apache:http_server:{expected}:*:*:*:*:*:*:*")], criticality=4,
        internet_facing=False, owner="lab-soc", is_simulated=True)
    metadata = dict(container_id=body.container_id, service=service, asset_id=asset_id,
        version=expected, image_id=obj["Image"], image_digest=DIGESTS[expected], verified_at=now().isoformat(),
        evidence="Local Docker inspect plus actual httpd -v; not an HTTP banner guess",
        config_sha256=hashlib.sha256((ROOT / "lab/apache/httpd.conf").read_bytes()).hexdigest())
    metadata["asset_snapshot"] = asset.model_dump(mode="json")
    with SessionLocal() as db:
        current_route = db.get(LabSetting, "apache_route")
        preserve_service = service == "vulnerable" and current_route and current_route.data.get("target") == "patched"
        old = db.get(InventoryOverride, asset_id)
        if old and not preserve_service:
            old.data = asset.model_dump(mode="json")
        elif old is None:
            db.add(InventoryOverride(asset_id=asset_id, data=asset.model_dump(mode="json")))
        setting = db.get(LabSetting, "apache:" + body.container_id)
        if setting:
            setting.data = metadata
        else:
            db.add(LabSetting(key="apache:" + body.container_id, data=metadata))
        ensure_intelligence(db)
    assessment = reassess(asset_id, "verified_lab_inventory")
    specific = next((a for a in assessment["assessments"] if a["threat_id"] == CVE), None)
    if service == "vulnerable" and specific and specific["match_detail"] == "confirmed_affected":
        with SessionLocal() as db:
            warning = dict(evaluated_at=assessment["evaluated_at"], cve_id=CVE, asset_id=asset_id,
                match_detail=specific["match_detail"], observed_version=expected,
                meaning="Preventive exposure warning, not a forecast of attacker timing or identity")
            row = db.get(LabSetting, "apache_warning")
            if row:
                row.data = warning
            else:
                db.add(LabSetting(key="apache_warning", data=warning))
            db.commit()
    return dict(registration=metadata, exposure=assessment)


@router.post("/api/lab/apache/discover")
def discover():
    ids = docker("compose", "-f", str(ROOT / "lab/apache/compose.yaml"), "ps", "-q", "vulnerable", "patched").splitlines()
    if not ids:
        raise HTTPException(409, "start the owned Apache lab first")
    return {"targets": [register(Registration(container_id=cid)) for cid in ids]}


class LogBatch(Registration):
    lines: list[str] = Field(max_length=200)


@router.post("/api/lab/apache/logs")
def ingest(body: LogBatch):
    with SessionLocal() as db:
        registry = db.get(LabSetting, "apache:" + body.container_id)
        if not registry:
            raise HTTPException(409, "register the verified owned container first")
        meta = registry.data
        threat = db.get(Threat, CVE)
        received, duplicates, rejected, events = [], [], [], []
        for line in body.lines:
            try:
                record = parse(body.container_id, line)
                observed = datetime.fromisoformat(record["observed_at"])
                if observed > now() + timedelta(minutes=5):
                    raise ValueError("observation clock is in the future")
            except ValueError as exc:
                rejected.append(str(exc))
                continue
            eid = record["event_id"]
            if db.get(ApacheObservation, eid):
                duplicates.append(eid)
                continue
            if meta["service"] == "vulnerable" and record["asset_id"] != "LAB-APACHE-VULN":
                rejected.append("unexpected route identity for vulnerable target")
                continue
            asset = Asset.model_validate(meta["asset_snapshot"] | {"asset_id": record["asset_id"]})
            matched = match_asset(asset, threat_from_row(threat))
            detected = record["signature_match"]
            record.update(container_id=body.container_id, asset_id=asset.asset_id, observed_version=meta["version"],
                version_match=matched.match_detail, candidate_cve_ids=[CVE] if detected else [],
                rule_id="APACHE-TRAVERSAL-001" if detected else None,
                attribution="Apache peer is the owned relay; relay-observed peer may still be behind Docker/host NAT", is_simulated=True)
            db.add(ApacheObservation(event_id=eid, at=observed, data=record))
            details = dict(src_ip=record["peer_ip"], src_port=record["peer_port"], path=record["path"],
                response_status=record["status"], response_bytes=record["response_bytes"], observed_version=meta["version"],
                candidate_cve_ids=record["candidate_cve_ids"], version_match=matched.match_detail,
                container_id=body.container_id, request_id=record["request_id"], relay_observed_peer=record["relay_observed_peer"])
            if detected:
                details.update(attack_signal="exploit_on_vulnerable_asset" if matched.match_detail == "confirmed_affected" else "exploit_attempt",
                    attack_label="Apache traversal attempt", attack_type="path_traversal", stage="attempt",
                    detection_reason=f"Original request has parent-directory traversal in the lab document alias; observed Apache {meta['version']}; "
                                     f"{CVE} applicability: {matched.match_detail}; HTTP {record['status']} does not alone verify disclosed content")
            events.append(SecurityEvent(event_id=eid, asset_id=asset.asset_id, timestamp=observed, event_type="http",
                source_sensor="independent-apache-access-log", source="vectra_apache_lab", is_simulated=True,
                rule_id=record["rule_id"], confidence="medium" if detected else None, details=details,
                shadow_watch_evaluated=True, retrieved_at=now().isoformat(), raw_ref=f"/api/lab/apache/observations/{eid}"))
            received.append(eid)
        out = CorrelationEngine(db).ingest_events(events) if events else None
        return dict(accepted=received, duplicates=duplicates, rejected=rejected, correlation=out)


@router.get("/api/lab/apache/state")
def state():
    with SessionLocal() as db:
        registry = [r.data for r in db.scalars(select(LabSetting).where(LabSetting.key.like("apache:%")))]
        records = [r.data for r in db.scalars(select(ApacheObservation).order_by(ApacheObservation.at.desc()).limit(30))]
        route = db.get(LabSetting, "apache_route")
        warning = db.get(LabSetting, "apache_warning")
        actions = [r.data for r in db.scalars(select(LabAction).order_by(LabAction.at.desc()).limit(100))
                   if r.data["kind"].startswith("apache_")]
        return dict(registrations=registry, observations=records, reference_source=SOURCE,
                    route=route.data if route else {"target": "vulnerable"}, actions=actions,
                    pre_attack_warning=warning.data if warning else None)


class Probe(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: Literal["district_service", "fixed_comparison"] = "district_service"
    request: Literal["public_notice", "dummy_traversal"] = "public_notice"


def probe_request(target, kind):
    port = 8011 if target == "district_service" else 8012
    relay_ids = docker("compose", "-f", str(ROOT / "lab/apache/compose.yaml"), "ps", "-q", "relay").splitlines()
    if len(relay_ids) != 1:
        raise HTTPException(409, "owned lab relay unavailable")
    relay = json.loads(docker("inspect", "--format", "{{json .}}", relay_ids[0]))
    labels = relay["Config"].get("Labels") or {}
    if labels.get("com.docker.compose.project") != "vectra-apache-lab" or labels.get("com.docker.compose.service") != "relay":
        raise HTTPException(403, "relay identity mismatch")
    binding = (relay["HostConfig"].get("PortBindings") or {}).get("8081/tcp" if port == 8011 else "8082/tcp", [])
    host = binding[0].get("HostIp") if binding else None
    try:
        address = ipaddress.ip_address(host)
        if address.version != 4 or address.is_unspecified or not (address.is_loopback or address.is_private):
            raise ValueError()
    except ValueError:
        raise HTTPException(409, "use a specific loopback/private IPv4 lab binding") from None
    path = "/documents/notice.txt" if kind == "public_notice" else "/documents/.%2e/internal/dummy-records.txt"
    try:
        with httpx.Client(trust_env=False, timeout=10) as client:
            response = client.get(f"http://{address}:{port}" + path)
    except httpx.HTTPError:
        raise HTTPException(503, "Owned lab HTTP listener unavailable") from None
    return dict(at=now().isoformat(), target=target, path=path, status=response.status_code,
        response_bytes=len(response.content), dummy_record_disclosed="VECTRA_DUMMY_RECORD_001" in response.text,
        public_notice_verified="VECTRA_APACHE_LAB" in response.text,
        request_id=response.headers.get("X-Vectra-Request-ID"), source="actual loopback HTTP response")


@router.post("/api/lab/apache/probe")
def probe(body: Probe):
    return probe_request(body.target, body.request)


class Patch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["patch", "rollback"]
    reason: str = Field(min_length=5, max_length=256)


@router.post("/api/lab/apache/patch")
def patch(body: Patch):
    with CONTROL_LOCK:
        return replace_backend(body)


def replace_backend(body):
    """Blue/green replacement: the same district endpoint routes to a verified fixed binary."""
    target = "patched" if body.action == "patch" else "vulnerable"
    ids = docker("compose", "-f", str(ROOT / "lab/apache/compose.yaml"), "ps", "-q", target).splitlines()
    if len(ids) != 1:
        raise HTTPException(409, "start the owned replacement target first")
    replacement = register(Registration(container_id=ids[0]))["registration"]
    relay_ids = docker("compose", "-f", str(ROOT / "lab/apache/compose.yaml"), "ps", "-q", "relay").splitlines()
    if len(relay_ids) != 1:
        raise HTTPException(409, "owned relay is unavailable")
    relay = json.loads(docker("inspect", "--format", "{{json .}}", relay_ids[0]))
    labels = relay["Config"].get("Labels") or {}
    if labels.get("com.docker.compose.project") != "vectra-apache-lab" or labels.get("com.docker.compose.service") != "relay":
        raise HTTPException(403, "relay identity mismatch")
    config_path = ROOT / "lab/apache/runtime/nginx.conf"
    if not config_path.is_file():
        raise HTTPException(409, "initialise the lab using scripts/start-apache-lab.ps1 first")
    original = config_path.read_text(encoding="utf-8")
    template = (ROOT / "lab/apache/nginx.conf").read_text(encoding="utf-8")
    changed = template.replace("proxy_pass http://vulnerable:8080;", f"proxy_pass http://{target}:8080;", 1)
    config_path.write_text(changed, encoding="utf-8")
    try:
        docker("exec", relay_ids[0], "nginx", "-t", "-c", "/etc/nginx/vectra-lab.conf")
        docker("exec", relay_ids[0], "nginx", "-s", "reload", "-c", "/etc/nginx/vectra-lab.conf")
    except HTTPException:
        config_path.write_text(original, encoding="utf-8")
        raise
    aid = "ACT-" + uuid4().hex
    data = dict(action_id=aid, kind="apache_" + body.action, state="applied", at=now().isoformat(),
        reason=body.reason, target=target, backend_container=ids[0], observed_binary_version=replacement["version"],
        scope="Blue/green route replacement of owned dummy district service; not an external patch deployment")
    with SessionLocal() as db:
        service_asset = db.get(InventoryOverride, "LAB-APACHE-VULN")
        snapshot = replacement["asset_snapshot"] | {"asset_id": "LAB-APACHE-VULN",
            "hostname": "fictional-district-live-service", "role": "Live district service (blue/green lab replacement)"}
        service_asset.data = snapshot
        route = db.get(LabSetting, "apache_route")
        if route:
            route.data = dict(target=target, action_id=aid, at=data["at"])
        else:
            db.add(LabSetting(key="apache_route", data=dict(target=target, action_id=aid, at=data["at"])))
        for previous in db.scalars(select(LabAction)):
            if previous.data["kind"] in ("apache_patch", "apache_rollback") and previous.data["state"] in ("applied", "verified"):
                previous.data = dict(previous.data, state="superseded")
        db.add(LabAction(action_id=aid, at=now(), data=data))
        db.commit()
    return dict(action=data, exposure=reassess("LAB-APACHE-VULN", "verified_backend_replacement"))


@router.post("/api/lab/apache/verify/{action_id}")
def verify(action_id: str):
    with CONTROL_LOCK:
        return verify_replacement(action_id)


def verify_replacement(action_id):
    with SessionLocal() as db:
        row = db.get(LabAction, action_id)
        if not row or row.data["kind"] not in ("apache_patch", "apache_rollback") or row.data["state"] == "superseded":
            raise HTTPException(409, "not a current Apache replacement action")
        public = probe_request("district_service", "public_notice")
        attempt = probe_request("district_service", "dummy_traversal")
        fixed = row.data["kind"] == "apache_patch"
        correct = public["status"] == 200 and public["public_notice_verified"] and (
            attempt["status"] in (403, 404) and not attempt["dummy_record_disclosed"] if fixed
            else attempt["status"] == 200 and attempt["dummy_record_disclosed"])
        if not correct:
            return dict(action=row.data, verified=False, public=public, attempt=attempt)
        row.data = dict(row.data, state="verified", verified_at=now().isoformat(),
                        verification_request_id=attempt["request_id"], public_check=public, traversal_check=attempt)
        db.commit()
        return dict(action=row.data, verified=True, public=public, attempt=attempt)


@router.get("/api/lab/apache/observations/{event_id}")
def evidence(event_id: str):
    with SessionLocal() as db:
        row = db.get(ApacheObservation, event_id)
        if row is None:
            raise HTTPException(404, "unknown Apache observation")
        return row.data
