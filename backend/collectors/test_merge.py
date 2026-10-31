"""Self-check for the parsing + merge logic. Run: python -m collectors.test_merge  (or pytest)"""
from .certin import _affected
from .nvd import _affected as nvd_affected
from .run_all import merge
from .schema import ThreatItem


def T(tid, source, **kw) -> ThreatItem:
    return ThreatItem(threat_id=tid, source=source, title="t", type=kw.pop("type", "vulnerability"), **kw)


def test() -> None:
    cfg = nvd_affected({"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "versionStartIncluding": "7.2.0", "versionEndExcluding": "7.2.7"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}]}]})
    assert len(cfg) == 1 and (cfg[0].version_start_including, cfg[0].version_end_excluding, cfg[0].version_end_including) == ("7.2.0", "7.2.7", None)
    a = _affected("Mozilla Firefox versions prior to 159")
    assert (a.vendor, a.product, a.versions_text, a.version_end_excluding) == ("Mozilla", "Firefox", "prior to 159", None)

    nvd = [T("CVE-1", "nvd", cve_id="CVE-1", cve_ids=["CVE-1"], cvss=9.8, cvss_version="3.1", severity="critical",
             published_at="2024-01-01T10:00:00Z", nvd_published_at="2024-01-01T10:00:00Z", raw_ref="raw/nvd_0.json")]
    kev = [T("CVE-1", "kev", cve_id="CVE-1", cve_ids=["CVE-1"], kev_listed=True, description="x\nRequired action: patch", tags=["kev"],
             kev_date_added="2024-02-09", raw_ref="raw/kev.json"),
           T("CVE-0", "kev", cve_id="CVE-0", cve_ids=["CVE-0"], kev_listed=True)]
    adv = [T("CIAD-1", "certin", type="advisory", cve_ids=["CVE-1", "CVE-9"]),
           T("CIAD-2", "certin", type="advisory", cve_ids=["CVE-7"]),
           T("otx:1", "otx", type="campaign")]
    signals = {"CVE-9": {"exploitdb": False, "github_poc": False, "nuclei": False, "vulnrichment": {"exploitation": "poc"}}}
    attack_map = {"CVE-1": [{"id": "T1190", "name": "Exploit Public-Facing Application", "mapping_type": "exploitation_technique"}]}
    scores = {"CVE-1": {"epss": 0.4, "percentile": 0.9}, "CVE-9": {"epss": 0.9, "percentile": 0.99}}
    out = {i.threat_id: i for i in merge(nvd, [], kev, adv, scores, signals, attack_map)}
    assert set(out) == {"CVE-1", "CVE-0", "CIAD-1", "CIAD-2", "otx:1"}  # NVD+KEV deduped by CVE, KEV-only kept
    assert out["CVE-1"].kev_listed and out["CVE-1"].cvss == 9.8 and out["CVE-1"].cvss_version == "3.1"
    assert "Required action" in out["CVE-1"].description and out["CVE-1"].source == "kev"  # KEV is the base record
    assert out["CIAD-1"].kev_listed and out["CIAD-1"].cvss == 9.8 and (out["CIAD-1"].epss, out["CIAD-1"].epss_percentile) == (0.9, 0.99)
    assert out["CIAD-1"].public_exploit and out["CVE-1"].public_exploit is False  # SSVC "poc" counts; checked-and-absent = False
    assert out["CVE-1"].attack_techniques == ["T1190"]
    # Dates stay separate; every contributing raw payload is listed, KEV (base record) first.
    c1 = out["CVE-1"]
    assert c1.published_at.isoformat() == c1.nvd_published_at.isoformat() == "2024-01-01T10:00:00+00:00"
    assert str(c1.kev_date_added) == "2024-02-09" and c1.raw_refs == ["raw/kev.json", "raw/nvd_0.json"] and c1.raw_ref == "raw/kev.json"
    assert out["CVE-0"].published_at is None and out["CVE-0"].nvd_published_at is None  # KEV-only: NVD date unknown
    # Null preservation: unknown stays None, never 0 / False.
    c2 = out["CIAD-2"]  # CVE we have no NVD/EPSS data for
    assert c2.kev_listed is False and c2.cvss is None and c2.epss is None and c2.epss_percentile is None and c2.severity is None
    o = out["otx:1"]  # no CVE at all -> KEV / exploit status not checkable
    assert o.kev_listed is None and o.public_exploit is None and o.cvss is None and o.epss is None
    # No KEV catalogue / no exploit feeds -> unknown, not False.
    bare = merge([T("CVE-5", "nvd", cve_ids=["CVE-5"])], [], [], [], {}, {}, {})[0]
    assert bare.kev_listed is None and bare.public_exploit is None
    print("ok")


if __name__ == "__main__":
    test()
