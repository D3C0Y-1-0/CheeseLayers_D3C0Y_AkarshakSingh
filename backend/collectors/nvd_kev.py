"""NVD records for every CVE in CISA KEV (NVD's `hasKev` filter). Gives KEV items the CVSS + CPEs they lack.

KEV only names vendor/product in plain words; NVD's CPEs carry exact version ranges, which the
correlator needs to tell "we run the vulnerable version" from "we run that product".
"""
from . import nvd
from .nvd import query

SOURCE = "nvd_kev"


def fetch() -> dict:
    return {"items": query({"hasKev": ""}, source=SOURCE)}


def from_raw() -> dict:
    return nvd.from_raw(SOURCE)
