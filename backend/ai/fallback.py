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
    if not ctx.verified_cve_ids and not ctx.candidate_cve_ids:
        limitations.append("No known CVE linkage; no vendor patch has been verified for these observations")
    # Missing telemetry is a visibility gap on each asset, never a negative proof.
    for asset in ctx.asset_ids:
        if not any(e.asset_id == asset and e.event_type in {"process_start", "process"} for e in citations):
            limitations.append(f"Process telemetry not observed for {asset}; process execution cannot be inferred or ruled out")
    maintenance = [e for e in ordered if e.event_type == "maintenance_window" and e.details.approved]
    live_reasons = [f"{c.detector_id}: {c.finding_reason}" for c in ctx.additional_evidence
                    if c.detector_id and c.finding_reason]
    if maintenance:
        limitations.append("Approved maintenance context retained; it does not rule out unrelated suspicious activity")
    if ctx.integration_status == "demo_adapter":
        limitations.append("Synthetic demo preview in memory; Member 3 persistence/correlation and final priority are not connected")
    if citations:
        span = f"{citations[0].observed_at.isoformat()} to {citations[-1].observed_at.isoformat()}"
        facts = "; ".join(f"{e.evidence_id}: {e.event_type} on {e.asset_id or 'unknown asset'} at {e.observed_at.isoformat()}" for e in citations[:5])
        # Lead with what the detectors found (their own reasons carry the real counts), then the evidence trail.
        found = "; ".join(list(dict.fromkeys([f"{f.detector_id}: {f.reason}" for f in ctx.findings[:3]] + live_reasons))[:3])
        summary = (f"Detected: {found}. " if found else "") + f"{len(citations)} stored observations ({span}). {facts}."
        if len(citations) > 5:
            limitations.append("Summary shows first 5 observations; complete bounded evidence citations are included")
    else:
        summary = "No behavioural observations were supplied. Review the verified vulnerability exposure context."
    if ctx.verified_cve_ids:
        summary += " Verified CVE association: " + ", ".join(ctx.verified_cve_ids) + "."
    elif ctx.candidate_cve_ids:
        summary += " Candidate CVE attempt pattern: " + ", ".join(ctx.candidate_cve_ids) + "; target applicability/exploitation require review."
    else:
        summary += " No known CVE linkage."
    why = "Stored observations warrant analyst review; temporal proximity does not establish causality."
    if ctx.assessment == "vulnerability_exposure":
        why = "Verified vulnerability association supports exposure review; it does not establish exploitation."
    elif not ctx.findings and not live_reasons:
        why = "No typed Shadow Watch finding was supplied. Review the stored evidence and any maintenance context."
    if ctx.findings:
        why += " Observed rule evidence: " + "; ".join(f.reason for f in ctx.findings[:5]) + "."
    elif live_reasons:
        why += " Observed detector evidence: " + "; ".join(live_reasons[:5]) + "."
    actions = ["Review the stored source evidence and validate sensor coverage"]
    types = {e.event_type for e in citations}
    if types & {"http_window", "http"}:
        actions.append("Review application request logs and compare the HTTP window with the normal baseline")
    if types & {"process_start", "process"}:
        actions.append("Validate process ancestry against authorised service and change records")
    if types & {"network_connection", "network"}:
        actions.append("Verify outbound destination purpose using authorised connection logs")
    if types & {"auth_window", "auth"}:
        actions.append("Check the login service's success log for the same window: failures alone do not show whether a guess worked")
        actions.append("Rate-limit or block the failing sources at the edge and confirm no listed username exists with a weak password")
    if any(f.detector_id == "SW-ML-001" for f in ctx.findings):
        actions.append("Read the raw log lines for the flagged minute: a statistical outlier is a lead for review, not evidence of compromise")
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
