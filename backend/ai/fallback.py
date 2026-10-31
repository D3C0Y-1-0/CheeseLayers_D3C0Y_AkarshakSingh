"""Deterministic facts and safe review steps; no network or model dependency."""
from .schemas import EvidenceCitation, IncidentContext, InvestigationReport


def build_fallback_report(incident_context: IncidentContext | dict) -> InvestigationReport:
    ctx = IncidentContext.model_validate(incident_context)
    ordered = sorted(ctx.evidence, key=lambda e: (e.observed_at, e.event_id))
    citations = sorted([EvidenceCitation(evidence_id=e.event_id, asset_id=e.asset_id,
                            observed_at=e.observed_at, sensor_id=e.sensor_id, source=e.source,
                            retrieved_at=e.ingested_at, raw_ref=e.raw_ref, event_type=e.event_type) for e in ordered]
                       + list(ctx.additional_evidence), key=lambda e: (e.observed_at, e.evidence_id))
    limitations = list(ctx.limitations) + ["Compromise not confirmed"]
    if not ctx.verified_cve_ids:
        limitations.append("No known CVE linkage; no vendor patch has been verified for these observations")
    # Missing telemetry is a visibility gap on each asset, never a negative proof.
    for asset in ctx.asset_ids:
        if not any(e.asset_id == asset and e.event_type in {"process_start", "process"} for e in citations):
            limitations.append(f"Process telemetry not observed for {asset}; process execution cannot be inferred or ruled out")
    maintenance = [e for e in ordered if e.event_type == "maintenance_window" and e.details.approved]
    if maintenance:
        limitations.append("Approved maintenance context retained; it does not rule out unrelated suspicious activity")
    if ctx.integration_status == "demo_adapter":
        limitations.append("Synthetic demo preview in memory; Member 3 persistence/correlation and final priority are not connected")
    if citations:
        span = f"{citations[0].observed_at.isoformat()} to {citations[-1].observed_at.isoformat()}"
        facts = "; ".join(f"{e.evidence_id}: {e.event_type} on {e.asset_id or 'unknown asset'} at {e.observed_at.isoformat()}" for e in citations[:10])
        summary = f"{len(citations)} stored observations ({span}). {facts}."
        if len(citations) > 10:
            limitations.append("Summary shows first 10 observations; complete bounded evidence citations are included")
    else:
        summary = "No behavioural observations were supplied. Review the verified vulnerability exposure context."
    if ctx.verified_cve_ids:
        summary += " Verified CVE association: " + ", ".join(ctx.verified_cve_ids) + "."
    else:
        summary += " No known CVE linkage."
    why = "Stored observations warrant analyst review; temporal proximity does not establish causality."
    if ctx.assessment == "vulnerability_exposure":
        why = "Verified vulnerability association supports exposure review; it does not establish exploitation."
    elif not ctx.findings:
        why = "No typed Shadow Watch finding was supplied. Review the stored evidence and any maintenance context."
    if ctx.findings:
        why += " Observed rule evidence: " + "; ".join(f.reason for f in ctx.findings[:5]) + "."
    actions = ["Review the stored source evidence and validate sensor coverage"]
    types = {e.event_type for e in citations}
    if types & {"http_window", "http"}:
        actions.append("Review application request logs and compare the HTTP window with the normal baseline")
    if types & {"process_start", "process"}:
        actions.append("Validate process ancestry against authorised service and change records")
    if types & {"network_connection", "network"}:
        actions.append("Verify outbound destination purpose using authorised connection logs")
    if maintenance:
        actions.append("Confirm the approved maintenance window and load-test scope with change records")
    if ctx.verified_cve_ids:
        actions.append("Verify asset applicability and consult the supplied vendor guidance before planning remediation")
    return InvestigationReport(incident_id=ctx.incident_id, assessment=ctx.assessment, summary=summary,
                               asset_ids=ctx.asset_ids, verified_cve_ids=ctx.verified_cve_ids,
                               evidence_ids=tuple(e.evidence_id for e in citations), evidence=tuple(citations),
                               why_relevant=why, limitations=tuple(dict.fromkeys(limitations)),
                               recommended_actions=tuple(actions), references=ctx.references,
                               generated_by="template", is_simulated=ctx.is_simulated, integration_status=ctx.integration_status)
