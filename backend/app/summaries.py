"""Grounded AI threat summary: POST /api/threats/{threat_id}/summary.

Facts come only from our DB: the threat record, Member 3's matcher run read-only against the simulated inventory
(nothing is written), exploit evidence and early-warning signals. The deterministic template is always valid;
an LLM may only reword its narrative fields (see ai/grounded.py).
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ai.grounded import narrate

from .asset_store import get_asset_store
from .correlator import AlertRow, threat_from_row
from .database import get_db
from .matcher import exposed, match_threat
from .models import ExploitEvidence, Threat, ThreatSignal

router = APIRouter(tags=["AI"])
NARRATIVE = {"summary": "text", "affected_summary": "text", "exploit_summary": "text", "why_it_matters": "text",
             "recommended_actions": "list"}
LANGS = ("en", "hi")


def threat_facts(db: Session, row: Threat) -> dict:
    store = get_asset_store()
    exposure = []
    if row.affected_configurations:
        for m in exposed(match_threat(threat_from_row(row), store.all())):
            a = store.get(m.asset_id)
            cfg = m.configuration or {}
            exposure.append({"asset_id": a.asset_id, "hostname": a.hostname, "sector": a.sector,
                             "internet_facing": a.internet_facing, "criticality": a.criticality,
                             "installed": (m.software or {}).get("version"), "match_detail": m.match_detail,
                             "fixed_in": cfg.get("version_end_excluding"), "reason": m.reason})
    ev = db.get(ExploitEvidence, row.cve_id) if row.cve_id else None
    signals = db.scalars(select(ThreatSignal).where(ThreatSignal.threat_id == row.threat_id)
                         .order_by(ThreatSignal.detected_at.desc()).limit(10))
    alerts = [r.alert_id for r in db.scalars(select(AlertRow).where(AlertRow.kind == "vulnerability"))
              if row.threat_id in r.data.get("threat_ids", [])]
    return {
        "threat": {"threat_id": row.threat_id, "cve_id": row.cve_id, "title": row.title,
                   "description": (row.description or "")[:1500] or None, "source": row.source,
                   "severity": row.severity, "cvss": row.cvss, "cvss_version": row.cvss_version, "epss": row.epss,
                   "epss_percentile": row.epss_percentile, "kev_listed": row.kev_listed,
                   "kev_date_added": str(row.kev_date_added) if row.kev_date_added else None,
                   "public_exploit": row.public_exploit,
                   "published_at": row.published_at.isoformat() if row.published_at else None,
                   "attack_techniques": row.attack_techniques or [], "is_simulated": row.is_simulated},
        "exposure": exposure,
        "exploit_evidence": {"exploitdb": ev.exploitdb, "exploitdb_date": ev.exploitdb_date,
                             "github_poc_ok": ev.github_poc_ok, "github_poc_repo": ev.github_poc_repo} if ev else None,
        "signals": [{"signal_type": s.signal_type, "detected_at": s.detected_at.isoformat(),
                     "is_simulated": s.is_simulated} for s in signals],
        "alert_ids": sorted(alerts),
        "sources": {"references": (row.references or [])[:10], "raw_refs": row.raw_refs or []},
    }


def threat_template(f: dict) -> dict:
    t, exp = f["threat"], f["exposure"]
    label = t["cve_id"] or t["threat_id"]
    if t["is_simulated"]:
        label += " (synthetic demo record, not a real CVE)"
    sev = (f"{t['severity']} severity, CVSS {t['cvss']}" if t["cvss"] is not None
           else f"{t['severity']} severity, CVSS unknown" if t["severity"] else "severity unknown")
    title = t["title"].split(": ", 1)[1] if t["title"].startswith(f"{t['cve_id'] or t['threat_id']}: ") else t["title"]
    summary = f"{label}: {title}. {sev}. Source: {t['source']}."
    confirmed = [e for e in exp if e["match_detail"] == "confirmed_affected"]
    verify = [e for e in exp if e["match_detail"] == "needs_verification"]
    if not exp:
        affected = "No asset in our simulated inventory runs an affected product/version."
    else:
        parts = []
        if confirmed:
            parts.append(f"{len(confirmed)} asset(s) run an affected version: " + ", ".join(
                f"{e['asset_id']} ({e['hostname']}, {e['installed']}, {'internet-facing' if e['internet_facing'] else 'internal'})"
                for e in confirmed))
        if verify:
            parts.append(f"{len(verify)} asset(s) need version verification: " + ", ".join(e["asset_id"] for e in verify))
        affected = ". ".join(parts) + "."
    epss = (f"EPSS {t['epss']:.3f}" + (f" (percentile {t['epss_percentile']:.3f})" if t["epss_percentile"] is not None else "")
            if t["epss"] is not None else "EPSS unknown")
    kev = ({True: "listed in CISA KEV (exploited in the wild" + (f", added {t['kev_date_added']})" if t["kev_date_added"] else ")"),
            False: "not listed in CISA KEV", None: "KEV status unknown"})[t["kev_listed"]]
    ev = f["exploit_evidence"] or {}
    poc = ("public exploit code reported" if t["public_exploit"] else
           "no public exploit reported" if t["public_exploit"] is False else "public exploit status unknown")
    if ev.get("exploitdb"):
        poc += f"; Exploit-DB entry ({ev.get('exploitdb_date') or 'date unknown'})"
    if ev.get("github_poc_ok"):
        poc += f"; quality-checked GitHub PoC ({ev.get('github_poc_repo')})"
    sig = f"; {len(f['signals'])} early-warning signal(s): " + ", ".join(sorted({s['signal_type'] for s in f['signals']})) if f["signals"] else ""
    exploit = f"{kev[0].upper() + kev[1:]}; {epss}; {poc}{sig}."
    if confirmed and t["kev_listed"]:
        why = "Actively exploited elsewhere and present in our inventory: highest remediation priority."
    elif confirmed:
        why = "Present in our inventory; exploitation in the wild is not established by these facts."
    elif verify:
        why = "Possible exposure: installed versions must be verified before the risk can be judged."
    else:
        why = "No inventory exposure found; relevant for monitoring only."
    actions = []
    for e in confirmed:
        actions.append(f"Plan remediation for {e['asset_id']}: upgrade to {e['fixed_in']} or later, or apply the vendor mitigation"
                       if e["fixed_in"] else f"Plan remediation for {e['asset_id']} using the vendor advisory")
    if verify:
        actions.append("Verify installed versions on " + ", ".join(e["asset_id"] for e in verify))
    if confirmed and any(e["internet_facing"] for e in confirmed):
        actions.append("Restrict internet exposure of affected interfaces until patched")
    if exp:
        actions.append("Review the source references and the linked incident(s) before acting")
    else:
        actions.append("No action needed for our inventory; keep monitoring for new signals")
    return {"threat_id": t["threat_id"], "cve_id": t["cve_id"], "is_simulated": t["is_simulated"], "summary": summary,
            "affected_summary": affected, "exploit_summary": exploit, "why_it_matters": why,
            "recommended_actions": actions, "affected_assets": exp, "alert_ids": f["alert_ids"],
            "exploit_signals": {"kev_listed": t["kev_listed"], "epss": t["epss"], "public_exploit": t["public_exploit"],
                                "evidence": f["exploit_evidence"], "signals": f["signals"]},
            "sources": f["sources"], "language": "en", "analyst_review_required": True}


@router.post("/api/threats/{threat_id}/summary")
async def threat_summary(threat_id: str, lang: str = Query("en", pattern="^(en|hi)$"), evidence_only: bool = False, db: Session = Depends(get_db)) -> dict:
    """Grounded threat summary: what it is, who is affected in our inventory, exploit signals, recommended action,
    sources. generated_by = llm | llm_cached | template; `validation` records the grounding check."""
    row = db.get(Threat, threat_id)
    if row is None:
        raise HTTPException(404, f"threat {threat_id} not found")
    facts = threat_facts(db, row)
    from ai.translate import localise
    return await localise("threat_summary", facts, threat_template(facts), NARRATIVE, lang, evidence_only=evidence_only)
