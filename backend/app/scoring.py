"""Transparent risk & confidence scoring. Three separate 0-100 scores, never merged into one black box:

  vulnerability_priority_score  how urgently a known vulnerability on this asset needs patching
  behavioural_suspicion_score   how suspicious the asset's own recent activity looks (Shadow Watch events)
  evidence_confidence_score     how much we trust the evidence behind the alert

Priority = the higher of the first two, mapped to low/medium/high/critical. Every weight is in CONFIG so the
dashboard can show exactly what contributed. Unknown inputs (CVSS/EPSS null) never count as 0: they get a
conservative fallback AND a limitation note saying we didn't know.
"""
import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .contracts import AlertFactors, Asset, Priority, SecurityEvent, ThreatRecord
from .matcher import MatchResult

CONFIG: dict[str, Any] = {
    "vulnerability": {
        # Asset context (criticality + exposure) is 45% so the SAME CVE ranks clearly lower on an internal or
        # less critical asset; the vulnerability itself (severity + exploitation) is 55%.
        "weights": {"severity": 0.25, "exploitation": 0.30, "criticality": 0.25, "exposure": 0.20},
        "cvss_missing_fallback": 0.5,  # unscored CVE: assume "medium", not "harmless"
        "epss_missing_fallback": 0.25,  # no EPSS: conservative baseline, not 0
        "epss_exponent": 0.5,  # sqrt: stops low-but-real EPSS values collapsing to ~0
        "public_exploit_floor": 0.6,  # public exploit code exists -> exploitation at least this
        # KEV = exploited somewhere (floor); EPSS spreads the rest = how widely. KEV alone no longer saturates,
        # so two KEV CVEs with EPSS 0.04 and 0.94 don't tie.
        "kev_exploitation_floor": 0.8,
        "exposure": {"internet_facing": 1.0, "internal": 0.25},
    },
    "behaviour": {
        # How bad each suspicious signal is on its own (0-1).
        "signal_severity": {
            "unexpected_process": 0.8,  # e.g. a web server spawning a shell
            "outbound_connection": 0.7,  # new destination / reverse-shell port
            "http_anomaly": 0.5,  # path traversal, request spike
            "auth_anomaly": 0.5,  # failed-login burst
            "inbound_ids_alert": 0.4,  # perimeter IDS signature
            # Attack Lab rule signals (app/detection.py), named after the attack the rule recognised.
            "port_scan": 0.45,  # reconnaissance only: nothing exploited yet
            "brute_force": 0.6,  # password guessing in progress
            "sql_injection": 0.75,  # attempt against the database behind a web app
            "command_injection": 0.85,  # attempt to run OS commands on the server
            "credential_compromise": 0.95,  # a guessed password worked
            "data_exposure": 0.95,  # an injected query returned data
            "recon_probe": 0.35,  # wordlist scanning for secrets / admin pages
            "login_hammering": 0.5,  # many connections to SSH / RDP / Telnet / VNC
            "exploit_attempt": 0.7,  # a published exploit for a specific CVE
            "exploit_on_vulnerable_asset": 0.9,  # ...for a CVE our matcher says this asset is vulnerable to
        },
        "base_weight": 0.75,  # score from the single worst signal
        "diversity_bonus": 0.2,  # per extra DIFFERENT signal type: independent signals corroborate each other
        "maintenance_damping": 0.3,  # noisy-but-benign signals inside an approved change window are scaled down
        "benign_in_maintenance": ["http_anomaly", "auth_anomaly"],  # only these can be explained by maintenance
        "confidence_multiplier": {"low": 0.6, "medium": 0.8, "high": 1.0},  # if Shadow Watch says how sure it is
    },
    "confidence": {
        "provenance": {"kev": 30, "verified": 25, "simulated": 15, "other": 10, "telemetry": 20},
        "verified_sources": ["nvd", "kev", "nvd+kev", "certin"],
        "match_certainty": {"confirmed_affected": 40, "needs_verification": 15},
        "corroboration_per_signal": 10,
        "corroboration_max": 30,
        "incomplete_evidence_penalty": 5,  # per event with a missing key field (asset, IP...)
    },
    "priority_thresholds": {"critical": 80, "high": 55, "medium": 30},  # score >= threshold
    "needs_verification_cap": "high",  # an unconfirmed version match can never be "critical"
    # Organisation-defined remediation policy (days from detection), NOT a regulatory deadline.
    "remediation_targets_days": {"critical": 7, "high": 14, "medium": 30, "low": 90},
    "remediation_policy_label": "organisation-defined policy, not a regulatory deadline",
}

_LEVELS: list[str] = ["low", "medium", "high", "critical"]

# --- event classification (rule-based; Member 4's Shadow Watch can override via rule_id/confidence) ------

WEB_PARENTS = re.compile(r"^(php-fpm|php|nginx|apache2?|httpd|w3wp|java|tomcat|node|python|gunicorn|uwsgi)", re.I)
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "cmd.exe", "powershell.exe", "pwsh", "powershell"}
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 9001}  # common reverse-shell / IRC / Tor ports
TRAVERSAL = re.compile(r"\.\./|\.\.\\|%2e%2e", re.I)
SPIKE_RATIO = 5  # requests this many times above baseline = spike
FAILED_LOGIN_BURST = 20


class EventSignal(BaseModel):
    event_id: str
    asset_id: str | None
    at: datetime
    signal: str | None  # None = not suspicious on its own (normal activity or context)
    reason: str
    in_maintenance: bool = False
    limitations: list[str] = Field(default_factory=list)


def classify_event(e: SecurityEvent) -> EventSignal:
    """Turn one raw sensor event into a named suspicious signal (or None) with a human-readable reason."""
    d, limits = e.details, []
    if e.asset_id is None:
        limits.append(f"{e.event_id}: sensor did not record which asset was involved")
    for key in ("client_ip", "src_ip", "dest_ip"):
        if key in d and d[key] is None:
            limits.append(f"{e.event_id}: {key} is missing, so the source/destination is unverified")

    signal, reason = None, "no suspicious pattern"
    if e.rule_id and d.get("attack_signal") in CONFIG["behaviour"]["signal_severity"]:
        # Attack Lab: the detection rule already named the attack from the raw log lines; keep its explanation.
        return EventSignal(event_id=e.event_id, asset_id=e.asset_id, at=e.timestamp, signal=d["attack_signal"],
                           reason=f"{e.rule_id} {d.get('attack_label', '')}: {d.get('detection_reason', '')}",
                           limitations=limits)
    if e.model_extra.get("shadow_watch_evaluated") and e.event_type != "maintenance":
        # The typed detector has already checked source capability and exact rules.
        # Do not reclassify approved/benign observations with looser legacy heuristics.
        findings = e.model_extra.get("shadow_findings", [])
        if findings:
            signal = {"http": "http_anomaly", "process": "unexpected_process", "network": "outbound_connection",
                      "auth": "auth_anomaly"}.get(e.event_type)
            reason = findings[0]["reason"]
            limits.extend(findings[0].get("limitations", []))
        return EventSignal(event_id=e.event_id, asset_id=e.asset_id, at=e.timestamp,
                           signal=signal, reason=reason, limitations=limits)
    if e.event_type == "maintenance":
        reason = f"approved change {d.get('change_id')} ({d.get('window_start')} to {d.get('window_end')})"
    elif e.event_type == "http":
        path, rpm, base = str(d.get("path") or ""), d.get("requests_last_minute"), d.get("baseline_requests_per_minute")
        hits = []
        if TRAVERSAL.search(path):
            hits.append("path traversal pattern in request")
        if rpm and base and rpm >= SPIKE_RATIO * base:
            hits.append(f"request spike {rpm / base:.0f}x baseline")
        if hits:
            signal, reason = "http_anomaly", "; ".join(hits)
    elif e.event_type == "process":
        parent, child = str(d.get("parent_process") or ""), str(d.get("child_process") or "")
        if WEB_PARENTS.match(parent) and child.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower() in SHELLS:
            signal, reason = "unexpected_process", f"web server process {parent} spawned shell {child}"
    elif e.event_type == "network":
        port = d.get("dest_port")
        if d.get("direction") == "outbound" and (d.get("first_seen_destination") or port in SUSPICIOUS_PORTS):
            why = [w for w, ok in (("never-seen destination", d.get("first_seen_destination")),
                                   (f"suspicious port {port}", port in SUSPICIOUS_PORTS)) if ok]
            signal, reason = "outbound_connection", f"outbound to {d.get('dest_ip')}: {', '.join(why)}"
        elif d.get("direction") == "inbound" and d.get("signature"):
            signal, reason = "inbound_ids_alert", f"IDS signature: {d['signature']}"
    elif e.event_type == "auth":
        n = d.get("failed_logins_last_minute") or 0
        if n >= FAILED_LOGIN_BURST:
            signal, reason = "auth_anomaly", f"{n} failed logins in one minute"

    if signal is None and e.rule_id and e.event_type != "maintenance":
        # Shadow Watch flagged it with a rule we don't have: trust it, with a generic signal for its type.
        signal = {"http": "http_anomaly", "process": "unexpected_process", "network": "outbound_connection",
                  "auth": "auth_anomaly"}[e.event_type]
        reason = f"Shadow Watch rule {e.rule_id}"
    return EventSignal(event_id=e.event_id, asset_id=e.asset_id, at=e.timestamp, signal=signal, reason=reason,
                       limitations=limits)


def maintenance_windows(events: list[SecurityEvent]) -> list[tuple[str | None, datetime, datetime, str]]:
    """(asset_id, start, end, change_id) for every maintenance event with a usable window."""
    out = []
    for e in events:
        if e.event_type != "maintenance":
            continue
        if e.details.get("approved") is False:
            continue
        try:
            start = datetime.fromisoformat(e.details["window_start"])
            end = datetime.fromisoformat(e.details["window_end"])
        except (KeyError, TypeError, ValueError):
            continue  # no usable window -> no suppression (fail safe)
        out.append((e.asset_id, start, end, e.details.get("change_id") or e.event_id))
    return out


# --- the three scores --------------------------------------------------------------------------------

class ScoreResult(BaseModel):
    vulnerability_priority_score: float
    behavioural_suspicion_score: float
    evidence_confidence_score: float
    risk_score: float  # contract field: the score that drove the priority
    priority: Priority
    factors: AlertFactors  # contract 0-1 factors
    score_factors: dict[str, Any]  # full breakdown for the dashboard
    escalation_reasons: list[str]
    limitations: list[str]
    warnings: list[str]
    signals: list[EventSignal]


def level(score: float) -> str:
    t = CONFIG["priority_thresholds"]
    return "critical" if score >= t["critical"] else "high" if score >= t["high"] else \
        "medium" if score >= t["medium"] else "low"


def vulnerability_priority(asset: Asset, threat: ThreatRecord | None, match: MatchResult | None) -> tuple[float, dict, list[str]]:
    """Returns (score, breakdown, limitations). 0 when there's no threat or the asset is confirmed unaffected."""
    cfg = CONFIG["vulnerability"]
    if threat is None or match is None or match.match_detail == "confirmed_unaffected":
        why = "no known vulnerability" if threat is None else "asset is not running an affected version"
        return 0.0, {"score": 0.0, "reason": why, "weights": cfg["weights"]}, []

    limits = []
    if threat.cvss is None:
        severity = cfg["cvss_missing_fallback"]
        limits.append(f"{threat.threat_id} has no CVSS score yet; severity assumed medium ({severity}), not zero")
    else:
        severity = threat.cvss / 10

    if threat.kev_listed:
        floor = cfg["kev_exploitation_floor"]
        epss = threat.epss if threat.epss is not None else cfg["epss_missing_fallback"]
        exploitation = floor + (1 - floor) * epss ** cfg["epss_exponent"]
        why_exp = (f"CISA KEV: exploited in the wild (floor {floor}) + EPSS "
                   f"{'unknown, fallback ' if threat.epss is None else ''}{epss:.3f} spreads the rest -> {exploitation:.2f}")
        if threat.epss is None:
            limits.append(f"{threat.threat_id} has no EPSS score; KEV floor used with a conservative EPSS fallback")
    elif threat.epss is None:
        exploitation, why_exp = cfg["epss_missing_fallback"], "no EPSS score; conservative fallback used"
        limits.append(f"{threat.threat_id} has no EPSS score; exploitation assumed {exploitation}, not zero")
    else:
        exploitation = threat.epss ** cfg["epss_exponent"]
        why_exp = f"EPSS {threat.epss:.3f} -> sqrt = {exploitation:.2f}"
    if threat.kev_listed is None and threat.cve_id:
        limits.append(f"{threat.threat_id}: CISA KEV status was not checked")
    if threat.public_exploit and exploitation < cfg["public_exploit_floor"]:
        exploitation, why_exp = cfg["public_exploit_floor"], why_exp + "; raised: public exploit code exists"

    criticality = asset.criticality / 5
    exposure = cfg["exposure"]["internet_facing" if asset.internet_facing else "internal"]
    factors = {"severity": severity, "exploitation": exploitation, "criticality": criticality, "exposure": exposure}
    contributions = {k: round(100 * cfg["weights"][k] * v, 1) for k, v in factors.items()}
    score = round(min(100.0, sum(contributions.values())), 1)
    return score, {
        "score": score,
        "weights": cfg["weights"],
        "inputs": {"cvss": threat.cvss, "epss": threat.epss, "kev_listed": threat.kev_listed,
                   "public_exploit": threat.public_exploit, "criticality": asset.criticality,
                   "internet_facing": asset.internet_facing, "match_detail": match.match_detail},
        "factors": {k: round(v, 3) for k, v in factors.items()},
        "contributions": contributions,  # points out of 100 from each factor; these sum to the score
        "exploitation_reason": why_exp,
    }, limits


def behavioural_suspicion(asset_id: str | None, events: list[SecurityEvent]) -> tuple[float, dict, list[EventSignal]]:
    """Score this asset's own events. 0 if there are none or nothing suspicious."""
    cfg = CONFIG["behaviour"]
    mine = [e for e in events if e.asset_id == asset_id]
    windows = [w for w in maintenance_windows(mine) if w[0] == asset_id]
    signals = sorted((classify_event(e) for e in mine), key=lambda s: s.at)
    conf = {e.event_id: e.confidence for e in mine}

    for s in signals:
        s.in_maintenance = any(start <= s.at <= end for _, start, end, _ in windows)

    suspicious = [s for s in signals if s.signal]
    if not suspicious:
        return 0.0, {"score": 0.0, "reason": "no suspicious activity on this asset", "signals": []}, signals

    sev = cfg["signal_severity"]
    worst = max(sev[s.signal] * cfg["confidence_multiplier"].get(conf.get(s.event_id) or "high") for s in suspicious)
    kinds = sorted({s.signal for s in suspicious})
    bonus = cfg["diversity_bonus"] * (len(kinds) - 1)
    score = min(1.0, worst * cfg["base_weight"] + bonus) * 100

    # Maintenance only explains noisy-but-benign signals. A shell or a new outbound connection is never "maintenance".
    explainable = all(s.signal in cfg["benign_in_maintenance"] and s.in_maintenance for s in suspicious)
    damped = bool(windows) and explainable
    if damped:
        score *= cfg["maintenance_damping"]
    score = round(score, 1)
    return score, {
        "score": score,
        "signals": [{"event_id": s.event_id, "signal": s.signal, "severity": sev[s.signal], "reason": s.reason,
                     "in_maintenance": s.in_maintenance} for s in suspicious],
        "distinct_signal_types": kinds,
        "worst_signal_severity": round(worst, 2),
        "diversity_bonus": round(bonus, 2),
        "maintenance_windows": [{"change_id": c, "start": st.isoformat(), "end": en.isoformat()} for _, st, en, c in windows],
        "maintenance_damping_applied": damped,
        "config": {k: cfg[k] for k in ("base_weight", "diversity_bonus", "maintenance_damping")},
    }, signals


def evidence_confidence(threat: ThreatRecord | None, match: MatchResult | None, signals: list[EventSignal]) -> tuple[float, dict]:
    cfg = CONFIG["confidence"]
    if threat is None:
        provenance, prov_why = (cfg["provenance"]["telemetry"], "local sensor telemetry") if signals else (0, "no evidence")
    elif threat.kev_listed:
        provenance, prov_why = cfg["provenance"]["kev"], "CISA KEV (government-verified exploitation)"
    elif threat.is_simulated:
        provenance, prov_why = cfg["provenance"]["simulated"], "simulated advisory (demo data)"
    elif threat.source in cfg["verified_sources"]:
        provenance, prov_why = cfg["provenance"]["verified"], f"verified source ({threat.source})"
    else:
        provenance, prov_why = cfg["provenance"]["other"], f"unverified source ({threat.source})"

    certainty = cfg["match_certainty"].get(match.match_detail, 0) if match else 0
    kinds = {s.signal for s in signals if s.signal}
    corroboration = min(cfg["corroboration_max"], cfg["corroboration_per_signal"] * len(kinds))
    incomplete = sum(1 for s in signals if s.limitations)
    penalty = cfg["incomplete_evidence_penalty"] * incomplete  # every event with a missing key field lowers trust
    score = float(max(0, min(100, provenance + certainty + corroboration - penalty)))
    return score, {"score": score, "provenance": provenance, "provenance_reason": prov_why,
                   "match_certainty": certainty, "telemetry_corroboration": corroboration,
                   "incomplete_evidence_penalty": penalty}


def score_incident(asset: Asset, threat: ThreatRecord | None = None, match: MatchResult | None = None,
                   events: list[SecurityEvent] | None = None) -> ScoreResult:
    """Score one asset's incident from an optional vulnerability match and any local events."""
    events = events or []
    vuln, vuln_bd, limits = vulnerability_priority(asset, threat, match)
    behav, behav_bd, signals = behavioural_suspicion(asset.asset_id, events)
    conf, conf_bd = evidence_confidence(threat, match, signals)
    limits += [l for s in signals for l in s.limitations]

    reasons, warnings = [], []
    vuln_level, behav_level = level(vuln), level(behav)
    if vuln > 0:
        reasons.append(f"vulnerability priority {vuln} -> {vuln_level}")
    if match is not None and match.match_detail == "needs_verification":
        cap = CONFIG["needs_verification_cap"]
        warnings.append(f"version match needs manual verification: {match.reason}")
        if _LEVELS.index(vuln_level) > _LEVELS.index(cap):
            reasons.append(f"capped {vuln_level} -> {cap}: the affected version is not confirmed")
            vuln_level = cap
    if behav > 0:
        reasons.append(f"behavioural suspicion {behav} -> {behav_level}"
                       f" ({len(behav_bd['distinct_signal_types'])} signal type(s): {', '.join(behav_bd['distinct_signal_types'])})")
    if behav_bd.get("maintenance_damping_applied"):
        changes = ", ".join(w["change_id"] for w in behav_bd["maintenance_windows"])
        reasons.append(f"suppressed: activity falls inside approved maintenance window {changes} and shows no "
                       f"malicious process or outbound indicators")

    priority = max(vuln_level, behav_level, key=_LEVELS.index)
    driver = "vulnerability" if _LEVELS.index(vuln_level) >= _LEVELS.index(behav_level) and vuln > 0 else \
        "behaviour" if behav > 0 else "none"
    reasons.append(f"priority {priority} (driven by {driver})")

    vf = vuln_bd.get("factors", {})
    return ScoreResult(
        vulnerability_priority_score=vuln, behavioural_suspicion_score=behav, evidence_confidence_score=conf,
        risk_score=max(vuln, behav), priority=priority,
        factors=AlertFactors(severity=vf.get("severity"), exploitation=vf.get("exploitation"),
                             criticality=vf.get("criticality", asset.criticality / 5),
                             exposure=vf.get("exposure"), confidence=round(conf / 100, 3)),
        score_factors={"vulnerability": vuln_bd, "behaviour": behav_bd, "confidence": conf_bd,
                       "priority": {"driver": driver, "vulnerability_level": vuln_level,
                                    "behaviour_level": behav_level, "thresholds": CONFIG["priority_thresholds"]}},
        escalation_reasons=reasons, limitations=limits, warnings=warnings, signals=signals,
    )


# --- documentation generated from CONFIG (docs/SCORING_AND_AI.md, CLAUDE.md §9; a test fails if they drift) ---------

DOC_BEGIN = "<!-- BEGIN GENERATED: scoring formula (scripts/gen_scoring_doc.py, from backend/app/scoring.py CONFIG) -->"
DOC_END = "<!-- END GENERATED: scoring formula -->"


def explain_markdown(cfg: dict[str, Any] | None = None) -> str:
    """The exact formula with the current numbers, as Markdown."""
    c = cfg or CONFIG
    v, b, k, t = c["vulnerability"], c["behaviour"], c["confidence"], c["priority_thresholds"]
    w, e = v["weights"], v["exposure"]
    sev = ", ".join(f"{s} {x}" for s, x in sorted(b["signal_severity"].items(), key=lambda i: -i[1]))
    prov = " · ".join(f"{s} {x}" for s, x in sorted(k["provenance"].items(), key=lambda i: -i[1]))
    days = " · ".join(f"{p} {d}d" for p, d in c["remediation_targets_days"].items())
    flat = lambda d: " · ".join(f"{x} {y}" for x, y in d.items())  # noqa: E731
    # Worked example with the demo's real inputs: CVE-2024-21762 (CVSS 9.8, EPSS 0.846, KEV) on PWR-FW-01.
    floor = v["kev_exploitation_floor"]
    ex = {"severity": 0.98, "exploitation": floor + (1 - floor) * 0.846 ** v["epss_exponent"],
          "criticality": 1.0, "exposure": e["internet_facing"]}
    pts = {f: round(100 * w[f] * x, 1) for f, x in ex.items()}
    return "\n".join([
        "Three separate 0-100 scores, never merged into one number. Priority comes from the higher of the first two.",
        "",
        "```text",
        "vulnerability_priority_score = 100 × ( "
        f"{w['severity']}·severity + {w['exploitation']}·exploitation + {w['criticality']}·criticality + {w['exposure']}·exposure )",
        f"  severity     = CVSS / 10                     (CVSS unknown -> {v['cvss_missing_fallback']} + a limitation note, never 0)",
        f"  exploitation = KEV-listed: {v['kev_exploitation_floor']} + {round(1 - v['kev_exploitation_floor'], 2)}·EPSS^{v['epss_exponent']}"
        f"   (KEV = exploited somewhere; EPSS = how widely)",
        f"                 otherwise:  EPSS^{v['epss_exponent']}                  (EPSS unknown -> {v['epss_missing_fallback']})",
        f"                 public exploit code -> at least {v['public_exploit_floor']}",
        "  criticality  = asset criticality (1-5) / 5",
        f"  exposure     = {e['internet_facing']} internet-facing · {e['internal']} internal",
        "  0 when the asset runs a version outside the vulnerable range (confirmed_unaffected)",
        f"  version match needs manual verification -> priority capped at {c['needs_verification_cap']}",
        "",
        f"behavioural_suspicion_score = 100 × min(1, {b['base_weight']}·worst_signal × confidence_multiplier"
        f" + {b['diversity_bonus']}·(distinct signal types − 1))",
        f"  confidence_multiplier (from the detector): {flat(b['confidence_multiplier'])}",
        f"  × {b['maintenance_damping']} only if EVERY signal is {' / '.join(b['benign_in_maintenance'])} inside an approved"
        " maintenance window",
        f"  signal severities: {sev}",
        "",
        "evidence_confidence_score = provenance + match certainty + corroboration − missing-field penalty",
        f"  provenance: {prov}",
        f"  match certainty: {flat(k['match_certainty'])}",
        f"  corroboration: {k['corroboration_per_signal']} per distinct signal type, max {k['corroboration_max']}",
        f"  penalty: {k['incomplete_evidence_penalty']} per event with a missing key field",
        "",
        f"priority = critical >= {t['critical']} · high >= {t['high']} · medium >= {t['medium']} · else low",
        f"remediation target ({c['remediation_policy_label']}): {days}",
        "",
        "worked example: CVE-2024-21762 (CVSS 9.8, EPSS 0.846, KEV) on PWR-FW-01 (criticality 5, internet-facing)",
        "  " + " + ".join(f"{f} {pts[f]}" for f in pts) + f" = {round(sum(pts.values()), 1)} -> "
        + level(sum(pts.values())),
        "```",
    ])
