"""CERT-In Incident Report Assistant: POST /api/alerts/{alert_id}/certin-draft.

Builds a DRAFT for analyst review from stored alert facts. It is never sent anywhere: no email, no API call,
`sent: false` always. The deterministic template is complete on its own; an optional grounded LLM may only reword
`incident_description` and `recommended_next_actions` (same validation as every AI text, see ai/grounded.py).

Security context: CERT-In Directions of 28 April 2022 (IT Act section 70B(6)) require reporting the incident types
in their Annexure I within 6 hours of noticing them. A vulnerability on its own is not one of those types, so a
vulnerability-exposure alert is labelled "not by itself a reportable incident". Behaviour incidents get a
SUGGESTED category from the list; reportability is always the analyst's decision.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ai.translate import localise

from .asset_store import get_asset_store
from .correlator import AlertRow, EventRow
from .database import get_db
from .models import Threat

router = APIRouter(tags=["CERT-In"])

# CERT-In Directions (28 Apr 2022), Annexure I: types of cyber security incidents mandatorily reportable.
CERTIN_CATEGORIES = [
    "Targeted scanning/probing of critical networks/systems",
    "Compromise of critical systems/information",
    "Unauthorised access of IT systems/data",
    "Defacement of website or intrusion into a website and unauthorised changes such as inserting malicious code, links to external websites etc.",
    "Malicious code attacks such as spreading of virus/worm/Trojan/Bots/Spyware/Ransomware/Cryptominers",
    "Attack on servers such as Database, Mail and DNS and network devices such as Routers",
    "Identity Theft, spoofing and phishing attacks",
    "Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks",
    "Attacks on Critical infrastructure, SCADA and operational technology systems and Wireless networks",
    "Attacks on Application such as E-Governance, E-Commerce etc.",
    "Data Breach",
    "Data Leak",
    "Attacks on Internet of Things (IoT) devices and associated systems, networks, software, servers",
    "Attacks or incident affecting Digital Payment systems",
    "Attacks through Malicious mobile Apps",
    "Fake mobile Apps",
    "Unauthorised access to social media accounts",
    "Attacks or malicious/suspicious activities affecting Cloud computing systems/servers/software/applications",
    "Attacks or malicious/suspicious activities affecting systems/servers/networks/software/applications related to "
    "Big Data, Block chain, virtual assets, virtual asset exchanges, custodian wallets, Robotics, 3D and 4D Printing, "
    "additive manufacturing, Drones",
    "Attacks or malicious/suspicious activities affecting systems/servers/software/applications related to "
    "Artificial Intelligence and Machine Learning",
]
CATEGORY_SOURCE = ("CERT-In Directions under sub-section (6) of section 70B of the IT Act, 2000, dated 28 April 2022, "
                   "Annexure I. Verify against the current official text before filing.")
REPORTABILITY = {
    "vulnerability": "vulnerability exposure only — not by itself a reportable incident",
    "behaviour": "potential security incident — analyst must determine reportability",
}
DISCLAIMER = ("DRAFT for analyst review; not sent to CERT-In or anyone else. The 6-hour reporting obligation in the "
              "CERT-In Directions (28 April 2022) applies only to the reportable incident types listed in their "
              "Annexure I, counted from when the incident is noticed or brought to notice. A vulnerability on its own "
              "is not one of those types. Category suggestions are heuristics: the analyst must confirm. Assets and "
              "behaviour in this demo are simulated.")
NARRATIVE = {"incident_description": "text", "recommended_next_actions": "list"}
SECTOR_CATS = {"power": 8, "telecom": 8, "transport": 8}  # index into CERTIN_CATEGORIES: SCADA / OT / critical infra


def _categories(alert: dict, assets: list, events: list[dict]) -> list[dict]:
    """Suggested Annexure I categories with the reason, most likely first. Always 'analyst to confirm'."""
    out = []

    def add(i, why):
        if all(c["category"] != CERTIN_CATEGORIES[i] for c in out):
            out.append({"number": i + 1, "category": CERTIN_CATEGORIES[i], "reason": why, "status": "analyst to confirm"})

    types = {e.get("event_type") for e in events}
    roles = " ".join(f"{a.role} {a.hostname}".lower() for a in assets)
    if alert["kind"] == "vulnerability":
        if any(a.sector in SECTOR_CATS for a in assets):
            add(8, "Only if exploitation is observed: the affected asset is critical-infrastructure/OT")
        if any(w in roles for w in ("firewall", "router", "vpn", "gateway", "dns", "mail", "database")):
            add(5, "Only if exploitation is observed: the affected asset is a server/network device")
        add(2, "Only if exploitation or unauthorised access is observed")
        return out
    if any(a.sector in SECTOR_CATS for a in assets) or "scada" in roles or "hmi" in roles:
        add(8, "Activity on a critical-infrastructure / OT asset")
    if types & {"http", "http_window"}:
        add(9 if any(w in roles for w in ("portal", "web", "e-gov", "app")) else 2,
            "Suspicious HTTP requests against an application")
    if types & {"process", "process_start"} and types & {"network", "network_connection"}:
        add(4, "Unexpected process plus new outbound connection: possible malicious code")
    if "auth" in types:
        add(2, "Authentication anomalies: possible unauthorised access")
    add(2, "Default for suspicious activity of unconfirmed nature")
    return out


def draft_facts(db: Session, row: AlertRow) -> dict:
    a = row.data
    store = get_asset_store()
    assets = [x for x in (store.get(i) for i in a["asset_ids"]) if x]
    from .correlator import incident_evidence
    from .database import SessionLocal
    from shadow_watch.integration import StoredIncidentProvider
    selected, truncated = incident_evidence(db, a["evidence_ids"])
    events = [r.data for r in selected]
    context = StoredIncidentProvider(SessionLocal).get_incident(a["alert_id"])
    threats = []
    for tid in dict.fromkeys(a["threat_ids"] + list(context.verified_cve_ids)):
        t = db.get(Threat, tid)
        if t:
            threats.append({"threat_id": t.threat_id, "cve_id": t.cve_id, "title": t.title, "cvss": t.cvss,
                            "kev_listed": t.kev_listed, "is_simulated": t.is_simulated,
                            "references": (t.references or [])[:5]})
    steps = [t for t in a.get("timeline", []) if t["event"].startswith("status ")]
    return {
        "alert": {"alert_id": a["alert_id"], "kind": a["kind"], "title": a.get("title"), "priority": a["priority"],
                  "risk_score": a.get("risk_score"), "lifecycle_status": a.get("lifecycle_status"),
                  "match_detail": a.get("match_detail"), "created_at": a["created_at"],
                  "reasons": a.get("reasons", [])[:10], "limitations": a.get("limitations", [])[:10] +
                  (["Evidence bounded to 100 observations, prioritising recent detector findings"] if truncated else []),
                  "is_simulated": a.get("is_simulated", False)},
        "assets": [{"asset_id": x.asset_id, "hostname": x.hostname, "ip": x.ip, "organisation": x.organisation,
                    "sector": x.sector, "role": x.role, "criticality": x.criticality,
                    "internet_facing": x.internet_facing, "is_simulated": x.is_simulated} for x in assets],
        "evidence": [{"evidence_id": e["event_id"], "event_type": e.get("event_type"), "observed_at": e.get("timestamp"),
                      "asset_id": e.get("asset_id"), "sensor": e.get("source_sensor"),
                      "note": (e.get("details") or {}).get("detection_reason") or (e.get("details") or {}).get("note"),
                      "request_id": (e.get("details") or {}).get("request_id"), "is_simulated": e.get("is_simulated")}
                     for e in events],
        "threats": threats,
        "actions_taken": [{"at": t["at"], "action": t["event"]} for t in steps],
        "categories": _categories(a, assets, events),
    }


def draft_template(f: dict) -> dict:
    a, assets, ev = f["alert"], f["assets"], f["evidence"]
    hosts = ", ".join(f"{x['asset_id']} ({x['hostname']}, {x['sector']})" for x in assets) or "unknown asset"
    if a["kind"] == "vulnerability":
        cves = ", ".join(t["cve_id"] or t["threat_id"] for t in f["threats"]) or "an advisory"
        desc = (f"Vulnerability exposure: {cves} matches software on {hosts} ({(a['match_detail'] or 'match').replace('_', ' ')}). "
                "No exploitation has been observed in the stored evidence.")
    else:
        types = sorted({e["event_type"] for e in ev if e["event_type"]})
        desc = (f"Suspicious activity on {hosts}: {len(ev)} stored observation(s) ({', '.join(types) or 'no typed events'}). "
                "Compromise is not confirmed.")
    actions = ["Confirm scope: verify the affected assets and whether the activity/exposure is real",
               "Preserve relevant logs (CERT-In Directions require ICT system logs to be retained for 180 days)"]
    if a["kind"] == "vulnerability":
        actions += ["Apply the vendor patch or mitigation, or restrict exposure until patched",
                    "Hunt for signs of exploitation; if found, reassess reportability (6-hour clock starts when noticed)"]
    else:
        actions += ["Contain if confirmed: isolate the host per your incident response plan",
                    "Decide reportability now: if a listed incident type is confirmed, the 6-hour window applies"]
    missing = ["Reporting organisation, point of contact and designation",
               "Whether exploitation, data access or data exfiltration occurred",
               "Business impact and number of affected users/systems in production",
               "Availability of firewall, proxy, authentication and host logs for the period"]
    missing += [l for l in a["limitations"] if "not observed" in l or "unknown" in l.lower()][:3]
    status = REPORTABILITY.get(a["kind"], REPORTABILITY["behaviour"])
    return {
        "alert_id": a["alert_id"], "status": "draft_for_analyst_review", "sent": False,
        "reportability_assessment": status,
        "suggested_category": f["categories"][0] if f["categories"] else None,
        "category_candidates": f["categories"], "category_source": CATEGORY_SOURCE,
        "time_of_detection": a["created_at"], "incident_description": desc, "affected_assets": assets,
        "observed_evidence": ev, "related_threats": f["threats"],
        "actions_taken_so_far": f["actions_taken"] or [{"at": None, "action": "None recorded in the dashboard"}],
        "recommended_next_actions": actions, "missing_information": missing,
        "contact": {"organisation": "[ORGANISATION NAME]", "point_of_contact": "[NAME, DESIGNATION]",
                    "phone": "[PHONE]", "email": "[EMAIL]", "certin_submission": "[per current CERT-In reporting guidance]"},
        "disclaimer": DISCLAIMER, "is_simulated": a["is_simulated"], "analyst_review_required": True,
    }


def markdown(d: dict) -> str:
    cat = d["suggested_category"]
    lines = [f"# CERT-In incident report — DRAFT ({d['alert_id']})", "", f"> {d['disclaimer']}", "",
             f"**Reportability assessment:** {d['reportability_assessment']}", "",
             f"**Suggested incident category (analyst to confirm):** "
             + (f"{cat['number']}. {cat['category']} — {cat['reason']}" if cat else "none"), "",
             f"**Time of detection:** {d['time_of_detection']}", "", "## Description", d["incident_description"], "",
             "## Affected assets"]
    lines += [f"- {x['asset_id']} · {x['hostname']} · {x['ip']} · {x['organisation']} · {x['sector']} · {x['role']}"
              + (" · simulated" if x["is_simulated"] else "") for x in d["affected_assets"]] or ["- unknown"]
    lines += ["", "## Observed evidence"]
    lines += [f"- {e['evidence_id']} · {e['event_type']} · {e['observed_at']} · {e['sensor']}" + (f" · {e['note']}" if e["note"] else "")
              for e in d["observed_evidence"]] or ["- No behavioural telemetry (vulnerability exposure)"]
    lines += [f"- {t['cve_id'] or t['threat_id']}: {t['title']}" for t in d["related_threats"]]
    lines += ["", "## Actions taken so far"] + [f"- {x['at'] or ''} {x['action']}".replace("-  ", "- ") for x in d["actions_taken_so_far"]]
    lines += ["", "## Recommended next actions"] + [f"- {x}" for x in d["recommended_next_actions"]]
    lines += ["", "## Missing information (complete before filing)"] + [f"- {x}" for x in d["missing_information"]]
    lines += ["", "## Contact"] + [f"- {k.replace('_', ' ').title()}: {v}" for k, v in d["contact"].items()]
    lines += ["", "## Other candidate categories"] + [f"- {c['number']}. {c['category']} — {c['reason']}" for c in d["category_candidates"][1:]]
    lines += ["", f"_Category list: {d['category_source']}_", f"_Text generated by: {d.get('generated_by', 'template')}_", ""]
    return "\n".join(lines)


@router.post("/api/alerts/{alert_id}/certin-draft",
             responses={200: {"content": {"text/markdown": {}}}, 403: {}, 404: {}})
async def certin_draft(alert_id: str, request: Request, format: str = Query("json", pattern="^(json|markdown)$"),
                       lang: str = Query("en", pattern="^(en|hi)$"), evidence_only: bool = False, db: Session = Depends(get_db)):
    """Draft CERT-In incident report for analyst review. Never sent. `?format=markdown` downloads a .md file."""
    row = db.get(AlertRow, alert_id)
    if row is None:
        raise HTTPException(404, f"alert {alert_id} not found")
    from ai.llm import demo_mode
    if demo_mode() and not row.data.get("is_simulated"):
        raise HTTPException(403, "demo mode drafts simulated incidents only")
    if not demo_mode():  # same rule as GET /api/alerts/{id}/evidence: a real deployment must authorise access
        factory = getattr(request.app.state, "investigation_tools_factory", None)
        try:
            if factory is None:
                raise PermissionError
            factory(request, alert_id).get_incident_context(alert_id)
        except PermissionError:
            raise HTTPException(403, "authenticated incident access required") from None
    facts = draft_facts(db, row)
    d = await localise("certin_draft", facts, draft_template(facts), NARRATIVE, lang, evidence_only=evidence_only)
    d["generated_at"] = datetime.now(timezone.utc).isoformat()
    d["markdown"] = markdown(d)
    if format == "markdown":
        return PlainTextResponse(d["markdown"], media_type="text/markdown; charset=utf-8", headers={
            "Content-Disposition": f'attachment; filename="certin-draft-{alert_id}.md"'})
    return d
