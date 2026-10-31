"""NVD records for every CVE in CISA KEV (NVD's `hasKev` filter). Gives KEV items the CVSS + CPEs they lack.

KEV only names vendor/product in plain words; NVD's CPEs carry exact version ranges, which the
correlator needs to tell "we run the vulnerable version" from "we run that product".
"""
import json

from . import nvd
from .common import raw_file
from .nvd import query

SOURCE = "nvd_kev"


def fetch() -> dict:
    return {"items": query({"hasKev": ""}, source=SOURCE)}


def from_raw() -> dict:
    kev_set = {v["cveID"] for v in json.loads(raw_file("kev", "latest.json").read_text())["vulnerabilities"]}
    return nvd.from_raw(SOURCE, keep=in_kev(kev_set))


def in_kev(kev_set: set[str]):
    """nvd_kev.json holds NVD records of KEV CVEs: an update is added only if the CVE is in KEV."""
    return lambda i: i.threat_id in kev_set
