"""Exercise actual loopback HTTP traffic and verify effects; never inserts fixture findings.

Start both listeners first (docs/LIVE_LAB.md). Changes only the opt-in dummy portal: releases
its rehearsal restriction and leaves the document boundary patched. Existing incidents remain.
"""
import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

import httpx


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-port", type=int, default=8000)
    parser.add_argument("--portal-port", type=int, default=8010)
    parser.add_argument("--output", type=Path, default=Path("logs/live-lab-rehearsal.json"))
    args = parser.parse_args()
    if not all(1024 <= p <= 65535 for p in (args.control_port, args.portal_port)):
        parser.error("ports must be in 1024..65535")
    control_url, portal_url = f"http://127.0.0.1:{args.control_port}", f"http://127.0.0.1:{args.portal_port}"
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "scope": "loopback dummy portal only",
              "checks": {}, "limitations": ["This is a controlled lab rehearsal, not production attack accuracy.",
              "Measured warning lead time depends on when the operator sends traffic, not a forecast model.",
              "DEMO-VULN-LAB-TRAVERSAL is not a published CVE."]}
    checks = report["checks"]
    with httpx.Client(base_url=control_url, timeout=60, trust_env=False) as control, \
         httpx.Client(base_url=portal_url, timeout=60, trust_env=False) as portal:
        page = control.get("/lab")
        page.raise_for_status()
        token = re.search(r"const token='([^']+)'", page.text)
        if token is None:
            raise RuntimeError("Expected the Vectra local lab console")
        control.headers["X-Vectra-Lab-Token"] = token.group(1)
        def command(kind, **extra):
            response = control.post("/api/lab/actions", json=dict(kind=kind, reason="Authorised loopback HTTP rehearsal", **extra))
            response.raise_for_status()
            return response.json()
        # Explicitly restores only the fictional portal's intentionally vulnerable mode.
        command("rollback")
        exposure = control.post("/api/lab/reassess/LAB-GOV-WEB-01")
        exposure.raise_for_status()
        assert exposure.json()["assessments"][0]["match_detail"] == "confirmed_affected"
        checks["preventive_exposure"] = {"match": "confirmed_affected", "evaluated_at": exposure.json()["evaluated_at"]}
        request_start = perf_counter()
        hit = portal.get("/document", params={"name": "../internal/dummy-records.json"},
                         headers={"X-Forwarded-For": "203.0.113.99"})
        assert hit.status_code == 200 and "FICTIONAL CITIZEN" in hit.text
        eid = hit.headers["X-Vectra-Event-ID"]
        observed = control.get(f"/api/lab/observations/{eid}").json()
        assert observed["peer_ip"] == "127.0.0.1" and observed["finding"]["rule_id"] == "LIVE-WEB-001"
        checks["live_traversal"] = {"status": hit.status_code, "event_id": eid, "rule": observed["finding"]["rule_id"],
            "request_to_persisted_finding_ms": round((perf_counter() - request_start) * 1000, 2),
            "peer_ip": observed["peer_ip"], "spoofed_forwarding_header_ignored": True}
        report["controlled_warning_lead_seconds"] = round((datetime.fromisoformat(observed["at"]) -
            datetime.fromisoformat(exposure.json()["evaluated_at"])).total_seconds(), 3)
        command("block", peer_ip="127.0.0.1", evidence_id=eid, ttl_seconds=30)
        try:
            assert portal.get("/document").status_code == 429
            with httpx.Client(base_url=portal_url, transport=httpx.HTTPTransport(local_address="127.0.0.2"),
                              timeout=30, trust_env=False) as other_peer:
                assert other_peer.get("/document").status_code == 200
            actions = control.get("/api/lab/state").json()["actions"]
            block = next(a for a in actions if a["kind"] == "block")
            assert block["state"] == "verified"
            checks["temporary_block"] = {"blocked_status": 429, "other_tcp_peer_status": 200,
                "state": block["state"], "verification_event_id": block["verification_event_id"]}
        finally:
            command("release", peer_ip="127.0.0.1")
        patched = command("patch")
        assert patched["exposure"]["assessments"][0]["match_detail"] == "confirmed_unaffected"
        assert portal.get("/document", params={"name": "../internal/dummy-records.json"}).status_code == 403
        assert portal.get("/document", params={"name": "notice.txt"}).status_code == 200
        assert next(a for a in control.get("/api/lab/state").json()["actions"] if a["kind"] == "patch")["state"] == "verified"
        checks["actual_fix"] = {"traversal_status": 403, "public_notice_status": 200,
                                "exposure": "confirmed_unaffected", "state": "verified"}
        for _ in range(10):
            assert portal.post("/login", json={"username": "demo-user", "password": "wrong"}).status_code == 401
        login = portal.post("/login", json={"username": "demo-user", "password": "lab-only-password"})
        assert login.status_code == 200
        observed = control.get("/api/lab/observations/" + login.headers["X-Vectra-Event-ID"]).json()
        assert observed["finding"]["rule_id"] == "LIVE-AUTH-002"
        checks["auth_sequence"] = {"rule": observed["finding"]["rule_id"],
                                   "supporting_requests": len(observed["finding"]["evidence_ids"])}
        incidents = control.get("/api/alerts", params={"asset_id": "LAB-GOV-WEB-01", "kind": "behaviour"}).json()["items"]
        assert incidents
        checks["central_incident"] = {"alert_id": incidents[0]["alert_id"], "evidence_count": len(incidents[0]["evidence_ids"])}
        investigation = control.post(f"/api/alerts/{incidents[0]['alert_id']}/investigate")
        investigation.raise_for_status()
        assert eid in investigation.json()["evidence_ids"]
        checks["investigation"] = {"generated_by": investigation.json()["generated_by"],
                                   "original_request_cited": True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
