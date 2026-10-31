"""FIRST EPSS: probability (0-1) that a CVE gets exploited in the next 30 days. Complements CVSS (impact) with likelihood."""
from .common import get, log, save_raw
from .schema import ThreatItem

SOURCE = "epss"
URL = "https://api.first.org/data/v1/epss"
BATCH = 100  # API returns max 100 rows per call


def fetch(cve_ids: list[str]) -> dict:
    cves = sorted(set(cve_ids))
    scores: dict[str, dict] = {}
    for i in range(0, len(cves), BATCH):
        data = get(URL, params={"cve": ",".join(cves[i:i + BATCH])}, min_interval=0.3).json()
        if i == 0:
            save_raw(SOURCE, data)  # one sample page is enough for debugging
        for row in data["data"]:
            scores[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
        if i // BATCH % 20 == 0:
            log.info("epss: %d/%d", min(i + BATCH, len(cves)), len(cves))
    return {"scores": scores}


def apply(items: list[ThreatItem], scores: dict[str, dict]) -> None:
    # An item with several CVEs (e.g. a CERT-In advisory) is as likely to be exploited as its most likely CVE.
    for it in items:
        vals = [scores[c]["epss"] for c in it.cve_ids if c in scores]
        if vals:
            it.epss = max(vals)
