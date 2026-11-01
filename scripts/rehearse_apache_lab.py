"""Actual owned Apache CVE demonstration: warn -> request -> collect -> replace -> verify.

Requires the local app, Docker lab and independent collector. Does not insert sensor events,
reset incidents or scan external hosts. Leaves the district endpoint routed to fixed Apache.
"""
import json
import re
import time
from pathlib import Path

import httpx


def main():
    with httpx.Client(base_url="http://127.0.0.1:8000", timeout=120, trust_env=False) as c:
        page = c.get("/lab")
        page.raise_for_status()
        c.headers["X-Vectra-Lab-Token"] = re.search(r"const token='([^']+)'", page.text).group(1)
        def post(path, data=None):
            r = c.post(path, json=data)
            r.raise_for_status()
            return r.json()
        post("/api/lab/apache/discover")
        restored = post("/api/lab/apache/patch", {"action": "rollback", "reason": "Begin authorised dummy-data CVE rehearsal"})
        post("/api/lab/apache/verify/" + restored["action"]["action_id"])
        exposure = post("/api/lab/reassess/LAB-APACHE-VULN")
        relevant = next(x for x in exposure["assessments"] if x["threat_id"] == "CVE-2021-41773")
        assert relevant["match_detail"] == "confirmed_affected"
        assert relevant["certin_advisories"], "Expected explicit CERT-In reference linkage"
        attack = post("/api/lab/apache/probe", {"request": "dummy_traversal"})
        assert attack["status"] == 200 and attack["dummy_record_disclosed"]
        # Request ID links a real HTTP response to a record from the independent log collector.
        source = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            state = c.get("/api/lab/apache/state").json()
            source = next((o for o in state["observations"] if o["request_id"] == attack["request_id"]), None)
            if source:
                break
            time.sleep(0.5)
        assert source and source["rule_id"] == "APACHE-TRAVERSAL-001", "Independent collector did not deliver the request"
        assert source["version_match"] == "confirmed_affected"
        patched = post("/api/lab/apache/patch", {"action": "patch", "reason": "Replace affected district backend with verified fixed binary"})
        assert patched["action"]["state"] == "applied"
        verified = post("/api/lab/apache/verify/" + patched["action"]["action_id"])
        assert verified["verified"] and verified["public"]["status"] == 200
        assert verified["attempt"]["status"] in (403, 404) and not verified["attempt"]["dummy_record_disclosed"]
        after = next(x for x in patched["exposure"]["assessments"] if x["threat_id"] == "CVE-2021-41773")
        assert after["match_detail"] == "confirmed_unaffected"
        incidents = c.get("/api/alerts", params={"asset_id": "LAB-APACHE-VULN", "kind": "behaviour"}).json()["items"]
        assert incidents
        investigation = post(f"/api/alerts/{incidents[0]['alert_id']}/investigate")
        assert "CVE-2021-41773" in investigation["verified_cve_ids"]
        report = dict(scope="Owned isolated fictional Indian district service; dummy records only",
            before=dict(evaluated_at=exposure["evaluated_at"], match=relevant["match_detail"], certin_references=relevant["certin_advisories"]),
            actual_attack_response=attack, independently_collected_observation=source,
            replacement_action=patched["action"], verification=verified, after_match=after["match_detail"],
            incident_id=incidents[0]["alert_id"], investigation_cve_ids=investigation["verified_cve_ids"],
            limitations=["Preventive exposure is not a validated forecast of attacker timing.",
                "2.4.51 is fixed for this CVE comparison, not a current production version recommendation.",
                "The same service endpoint is replaced through blue/green routing, not an OS package installer."])
        Path("logs").mkdir(exist_ok=True)
        Path("logs/apache-live-rehearsal.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps({"before": relevant["match_detail"], "attack_status": attack["status"],
            "dummy_disclosed": attack["dummy_record_disclosed"], "independent_event": source["event_id"],
            "fixed_binary": patched["action"]["observed_binary_version"], "after_status": verified["attempt"]["status"],
            "public_status": verified["public"]["status"], "after": after["match_detail"],
            "verified_action": verified["verified"], "incident": incidents[0]["alert_id"]}, indent=2))


if __name__ == "__main__":
    main()
