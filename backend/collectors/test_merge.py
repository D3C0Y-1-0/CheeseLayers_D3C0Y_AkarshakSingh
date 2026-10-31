"""Self-check for the parsing + merge logic. Run: python -m collectors.test_merge"""
from .certin import _affected
from .nvd import _version
from .run_all import merge
from .schema import ThreatItem


def test() -> None:
    assert _version({"versionStartIncluding": "1.0", "versionEndExcluding": "1.5"}, "*") == ">=1.0,<1.5"
    assert _version({}, "2.4.49") == "2.4.49"
    a = _affected("Mozilla Firefox versions prior to 159")
    assert (a.vendor, a.product, a.versions) == ("Mozilla", "Firefox", ["prior to 159"])

    nvd = [ThreatItem(id="CVE-1", source="nvd", type="vulnerability", title="t", cve_ids=["CVE-1"], cvss=9.8)]
    kev = [ThreatItem(id="CVE-1", source="kev", type="vulnerability", title="t", cve_ids=["CVE-1"], in_kev=True,
                      description="x\nRequired action: patch", tags=["kev"]),
           ThreatItem(id="CVE-0", source="kev", type="vulnerability", title="old", cve_ids=["CVE-0"], in_kev=True)]
    adv = [ThreatItem(id="CIAD-1", source="certin", type="advisory", title="a", cve_ids=["CVE-1", "CVE-9"])]
    signals = {"CVE-9": {"exploitdb": False, "github_poc": False, "nuclei": False, "vulnrichment": {"exploitation": "poc"}}}
    attack_map = {"CVE-1": [{"id": "T1190", "name": "Exploit Public-Facing Application", "mapping_type": "exploitation_technique"}]}
    out = {i.id: i for i in merge(nvd, [], kev, adv, {"CVE-1": {"epss": 0.4}, "CVE-9": {"epss": 0.9}}, signals, attack_map)}
    assert set(out) == {"CVE-1", "CVE-0", "CIAD-1"}  # NVD+KEV deduped by CVE, KEV-only kept
    assert out["CVE-1"].in_kev and out["CVE-1"].cvss == 9.8 and "Required action" in out["CVE-1"].description
    assert out["CIAD-1"].in_kev and out["CIAD-1"].cvss == 9.8 and out["CIAD-1"].epss == 0.9  # enriched from its CVEs
    assert out["CIAD-1"].public_exploit and not out["CVE-1"].public_exploit  # SSVC "poc" counts as public exploit
    assert out["CVE-1"].attack_techniques == ["T1190"] and out["CVE-1"].source == "kev"  # KEV is the base record
    print("ok")


if __name__ == "__main__":
    test()
