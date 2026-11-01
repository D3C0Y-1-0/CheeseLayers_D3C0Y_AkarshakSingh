"""Explicit refresh of a bounded primary-source case; never fabricates KEV/change events.

Vendor + CERT-In fixed-version lists must agree. Raw payloads/hashes are retained locally.
The reviewed snapshot is also consumed by normal ingestion, so stale merged copies cannot
restore unrelated product ranges after the correction. No network calls at import/startup.
"""
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
from bs4 import BeautifulSoup

from collectors.schema import ThreatItem
from .database import ROOT, SessionLocal
from .models import LabSetting, Threat

CVE = "CVE-2026-109619"
ADVISORY = "CIVN-2026-0528"
VENDOR = "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"
CERTIN = "https://www.cert-in.org.in/s2cMainServlet?VLCODE=CIVN-2026-0528&pageid=PUBVLNOTES01"
CISA = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REVIEWED = ROOT / "backend/data/cache/reviewed_primary.json"


def parse_sources(vendor: bytes, certin: bytes, cisa: bytes, stamp: datetime, cve=CVE):
    v = BeautifulSoup(vendor, "html.parser").get_text(" ", strip=True)
    c = BeautifulSoup(certin, "html.parser").get_text(" ", strip=True)
    if cve not in v or CVE not in c or ADVISORY not in c:
        raise ValueError("Primary source identity mismatch; no update applied")
    section = v.split("Patched versions", 1)[1].split("Description", 1)[0]
    fixes = sorted(set(re.findall(r"\b8\.\d+\.\d+\b", section)), key=lambda x: tuple(map(int, x.split('.'))))
    cert_fixes = re.findall(r"PHP (8\.\d+) versions prior to (8\.\d+\.\d+)", c)
    if len(fixes) < 4 or set(fixes) != {fixed for _, fixed in cert_fixes}:
        raise ValueError("Vendor/CERT-In patch versions disagree; analyst review required")
    # Preserve the vendor's first '<8.2.35' range, including unsupported older branches.
    # Later supported branches get explicit lower bounds to avoid cross-branch comparisons.
    ranges = [dict(vendor="php", product="php", version_start_including=None if i == 0 else '.'.join(f.split('.')[:2])+'.0',
                   version_end_excluding=f, cpe="cpe:2.3:a:php:php:*:*:*:*:*:*:*:*") for i, f in enumerate(fixes)]
    kev = next((r for r in json.loads(cisa)["vulnerabilities"] if r.get("cveID") == cve), None)
    score = re.search(r"Severity\s+Critical\s+(\d+(?:\.\d+)?)\s+CVSS", v, re.I)
    # Score is omitted if the source layout cannot establish it; never retain a suspect cached score.
    vendor_url = VENDOR if cve == CVE else "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w"
    refs = [vendor_url, "https://www.php.net/archive/2026.php"] + ([CERTIN] if cve == CVE else [])
    raw = ["backend/data/raw/case_review/"+name for name in ('php-ghsa-109619.html','certin-0528.html','cisa-catalog.json')]
    raw[0] = "backend/data/raw/case_review/" + ('php-ghsa-109619.html' if cve == CVE else 'php-ghsa-109618.html')
    threat = ThreatItem(threat_id=cve, cve_id=cve, cve_ids=[cve], source="vendor_review", type="vulnerability",
        title=cve+(": PHP stale request-state vulnerability" if cve == CVE else ": PHP out-of-memory corruption")+" (primary-source review)",
        description=("PHP worker state can retain references to a previous request." if cve == CVE else "PHP out-of-memory handling can leave internal request data partially initialised.")+" Applicability requires deployment review; no organisational compromise or outage is established.",
        cvss=float(score[1]) if score else None, cvss_version="4.0" if score else None, severity="critical",
        kev_listed=kev is not None, kev_date_added=kev.get('dateAdded') if kev else None,
        affected_configurations=ranges, references=refs, raw_refs=raw, retrieved_at=stamp,
        published_at="2026-10-21T00:00:00Z", tags=["primary-source-reviewed", "india-context", "php-worker-state"])
    advisory = ThreatItem(threat_id=ADVISORY, source="certin", type="advisory", cve_ids=[CVE],
        title=ADVISORY+": Remote Code Execution Vulnerability in PHP", severity="critical",
        description="CERT-In advises applying the vendor's PHP security update. This is public advisory relevance, not evidence of an attack on our organisation.",
        references=[CERTIN,VENDOR], affected_configurations=ranges, retrieved_at=stamp,
        published_at="2026-10-27T00:00:00+05:30", raw_ref=raw[1], tags=["cert-in","india","primary-source-reviewed"])
    return [threat, advisory] if cve == CVE else [threat]


def reviewed_items():
    if not REVIEWED.exists():
        return []
    return [ThreatItem.model_validate(r) for r in json.loads(REVIEWED.read_text(encoding='utf-8'))['records']]


def apply_sources(payloads: dict[str, bytes], stamp=None):
    from ingestion import changes
    from ingestion.loader import upsert_threats
    stamp = stamp or datetime.now(timezone.utc)
    records = parse_sources(payloads['php-ghsa-109619.html'], payloads['certin-0528.html'], payloads['cisa-catalog.json'], stamp)
    records += parse_sources(payloads['php-ghsa-109618.html'], payloads['certin-0528.html'], payloads['cisa-catalog.json'], stamp, 'CVE-2026-109618')
    # Validation above must finish before any cache or DB write.
    root = ROOT / 'backend/data/raw/case_review'
    root.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for name, content in payloads.items():
        (root/name).write_bytes(content)
        hashes[name] = hashlib.sha256(content).hexdigest()
    snapshot = dict(reviewed_at=stamp.isoformat(), source_hashes=hashes,
                    records=[r.model_dump(mode='json') for r in records])
    REVIEWED.parent.mkdir(parents=True, exist_ok=True)
    temporary = REVIEWED.with_suffix('.tmp')
    temporary.write_text(json.dumps(snapshot, indent=2), encoding='utf-8')
    temporary.replace(REVIEWED)
    with SessionLocal.begin() as db:
        old = changes.snapshot(db)
        for record in records:
            previous = db.get(Threat, record.threat_id)
            if previous and db.get(LabSetting, 'case_previous_intelligence:'+record.threat_id) is None:
                db.add(LabSetting(key='case_previous_intelligence:'+record.threat_id,
                    data=json.loads(json.dumps({col.name:getattr(previous,col.name) for col in Threat.__table__.columns},default=str))))
        upsert_threats(db, records)
        fresh = changes.emit(db, changes.detect(old, records, {}, stamp))
    changes.fire_hooks(fresh)
    # Reassess on unchanged refresh too; initial cached intelligence may predate asset registration.
    from .hooks import on_new_threat
    for record in records:
        on_new_threat(record.threat_id, "primary_source_review")
    return dict(checked_at=stamp.isoformat(), signals_emitted=len(fresh),
                signal_ids=[x['signal_id'] for x in fresh], source_hashes=hashes,
                message="Primary sources checked; material differences emitted as stored signals. Identical content emits no new signal.")


def refresh():
    payloads = {}
    with httpx.Client(timeout=15, follow_redirects=False, trust_env=False,
                      headers={'User-Agent':'Vectra-owned-lab-source-review/1.0'}) as client:
        for name, url in [('php-ghsa-109619.html',VENDOR),
                         ('php-ghsa-109618.html','https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w'),
                         ('certin-0528.html',CERTIN),('cisa-catalog.json',CISA)]:
            with client.stream('GET', url) as response:
                response.raise_for_status()
                content = bytearray()
                for block in response.iter_bytes():
                    content.extend(block)
                    if len(content) > 12_000_000:
                        raise ValueError("Primary source exceeds the review budget")
                payloads[name] = bytes(content)
    return apply_sources(payloads)
