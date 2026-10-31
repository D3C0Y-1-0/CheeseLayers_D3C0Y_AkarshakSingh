import json
from pathlib import Path

import pytest

from app.asset_store import get_asset_store
from app.contracts import Asset, ThreatRecord
from app.matcher import exposed, match_asset, match_threat, parse_version

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"


def make_asset(vendor="acme", product="widget", version="1.4.2", asset_id="T-1") -> Asset:
    return Asset(asset_id=asset_id, hostname="h", ip="10.0.0.1", organisation="Sim Org", sector="power",
                 role="test", os=None, software=[{"vendor": vendor, "product": product, "version": version,
                                                  "cpe": None}],
                 criticality=3, internet_facing=False, owner=None, is_simulated=True)


def make_threat(configs: list[dict], threat_id="DEMO-T") -> ThreatRecord:
    full = [{"vendor": "acme", "product": "widget", "version_start_including": None, "version_start_excluding": None,
             "version_end_including": None, "version_end_excluding": None, "cpe": None} | c for c in configs]
    return ThreatRecord(threat_id=threat_id, source="test", title="t", type="vulnerability",
                        affected_configurations=full, is_simulated=True)


RANGE = {"version_start_including": "1.4.0", "version_end_excluding": "1.5.0"}


# --- the four required cases -------------------------------------------------------------------------

def test_vulnerable_version_is_confirmed_affected():
    r = match_asset(make_asset(version="1.4.2"), make_threat([RANGE]))
    assert r.match_detail == "confirmed_affected"
    assert r.match_status == "confirmed"
    assert ">= 1.4.0" in r.reason and "< 1.5.0" in r.reason


def test_patched_version_is_confirmed_unaffected():
    r = match_asset(make_asset(version="1.5.1"), make_threat([RANGE]))
    assert r.match_detail == "confirmed_unaffected"
    assert r.match_status is None


def test_unrelated_product_is_confirmed_unaffected():
    r = match_asset(make_asset(product="other_thing"), make_threat([RANGE]))
    assert r.match_detail == "confirmed_unaffected"
    assert "none of the affected" in r.reason


@pytest.mark.parametrize("version,config,why", [
    ("1.4.2p1", RANGE, "non-standard"),  # vendor suffix
    ("1.4.2-build77", RANGE, "non-standard"),
    (None, RANGE, "unknown"),  # inventory doesn't know the version
    ("1.4.2", RANGE | {"raw_cpe_complex": True}, "complex"),
    ("1.4.2", {}, "no parseable version range"),  # no bounds and no CPE
    ("1.4.2", {"cpe": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}, "every version"),
    ("1.4.2", {"version_end_excluding": "1.5.0-hotfix"}, "bound"),  # bad bound
    ("1.4.2", {"versions_text": "prior to 1.5"}, "prior to 1.5"),  # CERT-In style free text
])
def test_uncertain_is_needs_verification(version, config, why):
    r = match_asset(make_asset(version=version), make_threat([config]))
    assert r.match_detail == "needs_verification", r.reason
    assert why in r.reason
    assert r.match_status == ("requires_manual_review" if version is None else "uncertain")


# --- semantics ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("version,config,expected", [
    ("1.4.0", {"version_start_including": "1.4.0"}, "confirmed_affected"),
    ("1.4.0", {"version_start_excluding": "1.4.0"}, "confirmed_unaffected"),
    ("1.5.0", {"version_end_including": "1.5.0"}, "confirmed_affected"),
    ("1.5.0", {"version_end_excluding": "1.5.0"}, "confirmed_unaffected"),
    ("1.4", {"version_start_including": "1.4.0", "version_end_excluding": "1.5"}, "confirmed_affected"),  # 1.4 == 1.4.0
    ("1.10.0", {"version_end_excluding": "1.9.0"}, "confirmed_unaffected"),  # numeric, not string, compare
    ("2.0.0", {"exact_version": "2.0.0"}, "confirmed_affected"),
    ("2.0.1", {"cpe": "cpe:2.3:a:acme:widget:2.0.0:*:*:*:*:*:*:*"}, "confirmed_unaffected"),
])
def test_bound_semantics(version, config, expected):
    assert match_asset(make_asset(version=version), make_threat([config])).match_detail == expected


@pytest.mark.parametrize("installed,exact,expected", [
    ("17.18.2", "cpe:2.3:o:cisco:ios_xe:3.7.0e:*:*:*:*:*:*:*", "confirmed_unaffected"),  # 3.7.0 can't be 17.18.2
    ("17.18.2", "cpe:2.3:o:cisco:ios_xe:15.2\\(2\\)e4:*:*:*:*:*:*:*", "confirmed_unaffected"),
    ("3.7.0", "cpe:2.3:o:cisco:ios_xe:3.7.0e:*:*:*:*:*:*:*", "needs_verification"),  # same release: is 3.7.0 == 3.7.0e?
])
def test_non_standard_exact_versions(installed, exact, expected):
    t = make_threat([{"vendor": "cisco", "product": "ios_xe", "cpe": exact}])
    assert match_asset(make_asset("cisco", "ios_xe", installed), t).match_detail == expected


def test_vendor_product_match_is_case_insensitive():
    r = match_asset(make_asset(vendor="ACME", product="Widget"), make_threat([RANGE]))
    assert r.match_detail == "confirmed_affected"


def test_one_vulnerable_branch_is_enough_but_doubt_beats_unaffected():
    branches = [{"version_start_including": "1.0", "version_end_excluding": "1.1"}, RANGE]
    assert match_asset(make_asset(version="1.4.2"), make_threat(branches)).match_detail == "confirmed_affected"
    # outside one range, uncertain on the other -> not confidently unaffected
    mixed = [{"version_start_including": "1.0", "version_end_excluding": "1.1"}, {"raw_cpe_complex": True}]
    assert match_asset(make_asset(version="1.4.2"), make_threat(mixed)).match_detail == "needs_verification"


def test_parse_version_rejects_wildcards():
    assert parse_version("*") is None and parse_version("-") is None and parse_version(None) is None
    assert parse_version("9.9p1") is None


# --- 3 real-world CVE patterns (configs copied from NVD) ---------------------------------------------

def test_log4shell_cve_2021_44228():
    cfg = lambda s, e: {"vendor": "apache", "product": "log4j", "version_start_including": s,
                        "version_end_excluding": e, "cpe": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"}
    t = make_threat([cfg("2.0.1", "2.3.1"), cfg("2.4.0", "2.12.2"), cfg("2.13.0", "2.15.0"),
                     {"vendor": "apache", "product": "log4j", "cpe": "cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*"}],
                    threat_id="CVE-2021-44228")
    assert match_asset(make_asset("apache", "log4j", "2.14.1"), t).match_detail == "confirmed_affected"
    assert match_asset(make_asset("apache", "log4j", "2.17.1"), t).match_detail == "confirmed_unaffected"
    assert match_asset(make_asset("apache", "log4j", "2.12.2"), t).match_detail == "confirmed_unaffected"  # patched 2.12 line
    # 2.0-beta9 is listed as an exact CPE with an update qualifier: we refuse to guess
    assert match_asset(make_asset("apache", "log4j", "2.0"), t).match_detail == "needs_verification"


def test_pan_os_cve_2024_3400_hotfix_suffix():
    t = make_threat([{"vendor": "paloaltonetworks", "product": "pan-os",
                      "cpe": "cpe:2.3:o:paloaltonetworks:pan-os:11.1.2:-:*:*:*:*:*:*"},
                     {"vendor": "paloaltonetworks", "product": "pan-os",
                      "cpe": "cpe:2.3:o:paloaltonetworks:pan-os:11.1.2:h1:*:*:*:*:*:*"}], threat_id="CVE-2024-3400")
    assert match_asset(make_asset("paloaltonetworks", "pan-os", "11.1.2"), t).match_detail == "confirmed_affected"
    # Palo Alto hotfix builds ("-h3") aren't standard versions -> verify, never auto-confirm
    r = match_asset(make_asset("paloaltonetworks", "pan-os", "11.1.2-h3"), t)
    assert r.match_detail == "needs_verification"


def test_ivanti_cve_2024_21887_release_suffix():
    t = make_threat([{"vendor": "ivanti", "product": "connect_secure",
                      "cpe": "cpe:2.3:a:ivanti:connect_secure:22.6:r2:*:*:*:*:*:*"}], threat_id="CVE-2024-21887")
    for installed in ("22.6R2.2", "22.6"):  # vendor format, or a plain version that can't express "R2"
        assert match_asset(make_asset("ivanti", "connect_secure", installed), t).match_detail == "needs_verification"


# --- the shared demo fixtures -------------------------------------------------------------------------

DEMO_CVES = json.loads((DATA / "demo_cves.json").read_text(encoding="utf-8"))
SYNTHETIC = {t["threat_id"]: t for t in json.loads((DATA / "threats_synthetic.json").read_text(encoding="utf-8"))}


@pytest.mark.parametrize("fixture", DEMO_CVES, ids=lambda f: f["threat_id"])
def test_demo_cves_match_exactly_the_documented_assets(fixture):
    results = match_threat(ThreatRecord.model_validate(fixture), get_asset_store().all())
    affected = {r.asset_id for r in results if r.match_detail == "confirmed_affected"}
    assert affected == set(fixture["vulnerable_asset_ids"])
    for r in results:
        if r.asset_id in fixture["patched_asset_ids"]:
            assert r.match_detail == "confirmed_unaffected", r.reason
    assert not [r for r in results if r.match_detail == "needs_verification"]


@pytest.mark.parametrize("threat_id,asset_id,detail,status", [
    ("DEMO-VULN-001", "PWR-HMI-01", "confirmed_affected", "confirmed"),
    ("DEMO-VULN-002", "BNK-CBS-01", "confirmed_affected", "confirmed"),
    ("DEMO-VULN-003", "HLT-PACS-01", "needs_verification", "requires_manual_review"),
])
def test_synthetic_threats(threat_id, asset_id, detail, status):
    results = exposed(match_threat(ThreatRecord.model_validate(SYNTHETIC[threat_id]), get_asset_store().all()))
    assert [(r.asset_id, r.match_detail, r.match_status) for r in results] == [(asset_id, detail, status)]


def test_no_cached_kev_cve_confirms_an_asset_outside_the_demo_set():
    """data/README: every asset other than the documented vulnerable ones matches zero cached KEV CVEs."""
    cache = ROOT / "backend" / "data" / "cache" / "threat_items.json"
    kev = [ThreatRecord.model_validate(t) for t in json.loads(cache.read_text(encoding="utf-8"))
           if t.get("kev_listed") and t.get("affected_configurations")]
    assert len(kev) > 1000
    allowed = {a for f in DEMO_CVES for a in f["vulnerable_asset_ids"]}
    assets = get_asset_store().all()
    hits = {(r.asset_id, r.threat_id) for t in kev for r in match_threat(t, assets)
            if r.match_detail == "confirmed_affected"}
    assert {a for a, _ in hits} <= allowed, sorted(h for h in hits if h[0] not in allowed)
