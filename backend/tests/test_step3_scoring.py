import json
from pathlib import Path

import pytest

from app.asset_store import get_asset_store
from app.contracts import Asset, SecurityEvent, ThreatRecord
from app.matcher import match_asset
from app.scoring import CONFIG, score_incident

DATA = Path(__file__).resolve().parents[2] / "data"
EVENTS = [SecurityEvent.model_validate(e) for e in json.loads((DATA / "events.json").read_text(encoding="utf-8"))]
DEMO = {t["threat_id"]: ThreatRecord.model_validate(t)
        for t in json.loads((DATA / "demo_cves.json").read_text(encoding="utf-8"))
        + json.loads((DATA / "threats_synthetic.json").read_text(encoding="utf-8"))}


def asset(criticality=5, internet_facing=True, version="1.4.2") -> Asset:
    return Asset(asset_id="T-1", hostname="h", ip="10.0.0.1", organisation="Sim Org", sector="power", role="test",
                 os=None, software=[{"vendor": "acme", "product": "widget", "version": version, "cpe": None}],
                 criticality=criticality, internet_facing=internet_facing, owner=None, is_simulated=True)


def threat(**kw) -> ThreatRecord:
    base = dict(threat_id="CVE-2099-0001", cve_id="CVE-2099-0001", source="nvd", title="t", type="vulnerability",
                cvss=9.8, epss=None, kev_listed=False,
                affected_configurations=[{"vendor": "acme", "product": "widget", "version_start_including": "1.4.0",
                                          "version_end_excluding": "1.5.0"}])
    return ThreatRecord(**(base | kw))


def score(a: Asset, t: ThreatRecord, events=None):
    return score_incident(a, t, match_asset(a, t), events)


# --- required ----------------------------------------------------------------------------------------

def test_missing_epss_is_not_zero_exploitation():
    a = asset()
    missing, zero = score(a, threat(epss=None)), score(a, threat(epss=0.0))
    exp = missing.score_factors["vulnerability"]["factors"]["exploitation"]
    assert exp == CONFIG["vulnerability"]["epss_missing_fallback"] > 0
    assert missing.vulnerability_priority_score > zero.vulnerability_priority_score
    assert any("no EPSS" in l for l in missing.limitations)
    assert not any("no EPSS" in l for l in zero.limitations)  # a real 0.0 is a fact, not a gap


def test_not_kev_listed_does_not_zero_high_epss():
    r = score(asset(), threat(kev_listed=False, epss=0.95))
    assert r.score_factors["vulnerability"]["factors"]["exploitation"] > 0.9
    assert r.priority == "critical"


def test_kev_sets_an_exploitation_floor_and_epss_spreads_the_rest():
    low = score(asset(), threat(kev_listed=True, epss=0.01))
    high = score(asset(), threat(kev_listed=True, epss=0.94))
    assert low.score_factors["vulnerability"]["factors"]["exploitation"] == 0.82  # 0.8 + 0.2 * sqrt(0.01)
    assert high.vulnerability_priority_score > low.vulnerability_priority_score  # KEV alone no longer ties
    not_kev = score(asset(), threat(epss=0.5))
    assert low.score_factors["vulnerability"]["factors"]["exploitation"] >         not_kev.score_factors["vulnerability"]["factors"]["exploitation"]  # KEV still outranks a high EPSS alone


def test_critical_internet_facing_beats_internal_low_criticality():
    t = threat(epss=0.3)
    high = score(asset(criticality=5, internet_facing=True), t)
    low = score(asset(criticality=1, internet_facing=False), t)
    assert high.vulnerability_priority_score > low.vulnerability_priority_score
    assert high.score_factors["vulnerability"]["contributions"]["exposure"] == 20.0
    assert low.score_factors["vulnerability"]["contributions"]["exposure"] == 5.0


def test_same_kev_cve_ranks_clearly_lower_on_internal_or_less_critical_assets():
    t = threat(kev_listed=True, epss=0.9)
    top = score(asset(criticality=5, internet_facing=True), t).vulnerability_priority_score
    internal = score(asset(criticality=5, internet_facing=False), t).vulnerability_priority_score
    less_critical = score(asset(criticality=3, internet_facing=True), t).vulnerability_priority_score
    assert top - internal >= 14 and top - less_critical >= 9


@pytest.mark.parametrize("case", ["vuln", "unaffected", "behaviour_only", "nothing"])
def test_every_output_is_explainable(case):
    if case == "vuln":
        r = score(asset(), threat())
    elif case == "unaffected":
        r = score(asset(version="1.5.1"), threat())
    elif case == "behaviour_only":
        r = score_incident(get_asset_store().get("HLT-WEB-01"), events=EVENTS)
    else:
        r = score_incident(asset())
    sf = r.score_factors
    assert set(sf) == {"vulnerability", "behaviour", "confidence", "priority"}
    assert all("score" in sf[k] for k in ("vulnerability", "behaviour", "confidence"))
    assert sf["priority"]["driver"] in ("vulnerability", "behaviour", "none")
    assert r.escalation_reasons
    json.dumps(r.model_dump(mode="json"))  # serialisable for the API


# --- correctness details -----------------------------------------------------------------------------

def test_contributions_add_up_to_score():
    r = score(asset(), threat(epss=0.4))
    v = r.score_factors["vulnerability"]
    assert abs(sum(v["contributions"].values()) - r.vulnerability_priority_score) < 0.2
    assert abs(sum(CONFIG["vulnerability"]["weights"].values()) - 1.0) < 1e-9


def test_missing_cvss_is_not_zero():
    r = score(asset(), threat(cvss=None))
    assert r.score_factors["vulnerability"]["factors"]["severity"] == 0.5
    assert any("no CVSS" in l for l in r.limitations)


def test_unaffected_asset_has_zero_vulnerability_score():
    r = score(asset(version="1.5.1"), threat(kev_listed=True))
    assert r.vulnerability_priority_score == 0 and r.priority == "low"


def test_needs_verification_is_capped_at_high():
    r = score(asset(version="1.4.2-custom"), threat(kev_listed=True))  # would be ~99 if confirmed
    assert r.vulnerability_priority_score >= 80
    assert r.priority == "high"
    assert r.warnings and "manual verification" in r.warnings[0]
    assert any("capped critical -> high" in x for x in r.escalation_reasons)


def test_confirmed_match_is_more_confident_than_uncertain():
    t = threat(kev_listed=True)
    assert score(asset(), t).evidence_confidence_score > score(asset(version="1.4.2-x"), t).evidence_confidence_score


# --- demo scenarios ----------------------------------------------------------------------------------

def test_scenario_a_real_kev_cve_is_critical():
    a = get_asset_store().get("PWR-FW-01")
    r = score(a, DEMO["CVE-2024-21762"])
    assert r.priority == "critical" and r.vulnerability_priority_score >= 95
    assert r.factors.exploitation >= 0.98  # KEV floor 0.8 + EPSS 0.85 spread


@pytest.mark.parametrize("threat_id,asset_id,priority", [
    ("DEMO-VULN-001", "PWR-HMI-01", "high"),
    ("DEMO-VULN-002", "BNK-CBS-01", "high"),
    ("DEMO-VULN-003", "HLT-PACS-01", "medium"),  # CVSS + EPSS unknown, version unknown
])
def test_synthetic_threat_priorities(threat_id, asset_id, priority):
    r = score(get_asset_store().get(asset_id), DEMO[threat_id])
    assert r.priority == priority
    if threat_id == "DEMO-VULN-003":
        assert len(r.limitations) >= 2 and r.warnings


def test_scenario_b_multi_signal_behaviour_is_critical():
    r = score_incident(get_asset_store().get("HLT-WEB-01"), events=EVENTS)
    b = r.score_factors["behaviour"]
    assert b["distinct_signal_types"] == ["http_anomaly", "outbound_connection", "unexpected_process"]
    assert r.vulnerability_priority_score == 0 and r.priority == "critical"
    assert r.score_factors["priority"]["driver"] == "behaviour"


def test_scenario_b_single_signal_is_lower():
    one = [e for e in EVENTS if e.event_id == "EVT-0002"]
    r = score_incident(get_asset_store().get("HLT-WEB-01"), events=one)
    assert r.priority == "high"  # a shell from a web server alone is serious, but not yet critical


def test_scenario_c_maintenance_is_suppressed():
    r = score_incident(get_asset_store().get("BNK-NET-01"), events=EVENTS)
    b = r.score_factors["behaviour"]
    assert b["maintenance_damping_applied"] is True
    assert [s["signal"] for s in b["signals"]] == ["http_anomaly"]  # apt-get from systemd is not suspicious
    assert r.priority == "low"
    assert any("CHG-2026-1031-07" in x for x in r.escalation_reasons)


def test_maintenance_never_hides_a_shell():
    shell = SecurityEvent(event_id="X-1", asset_id="BNK-NET-01", timestamp="2026-10-31T02:30:00+05:30",
                          event_type="process", source_sensor="edr-agent", is_simulated=True,
                          details={"parent_process": "nginx", "child_process": "/bin/bash"})
    r = score_incident(get_asset_store().get("BNK-NET-01"), events=EVENTS + [shell])
    assert r.score_factors["behaviour"]["maintenance_damping_applied"] is False
    assert r.priority in ("high", "critical")


def test_incomplete_evidence_is_flagged():
    r = score_incident(get_asset_store().get("WTR-WEB-01"), events=EVENTS)
    assert any("client_ip is missing" in l for l in r.limitations)
    assert r.score_factors["confidence"]["incomplete_evidence_penalty"] > 0
