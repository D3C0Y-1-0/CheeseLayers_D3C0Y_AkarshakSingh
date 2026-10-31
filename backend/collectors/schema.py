"""Normalised schemas. Field names/enums come from data/contracts.json (team source of truth) — change it there first.

Rule: None = unknown / not checked. Never store 0 or False for "we don't know".
Every field here is in the contract (v1.1: type, cve_ids, tags, versions_text, raw_refs, dates were added officially).
"""
from datetime import date, datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, model_validator

Severity = Literal["critical", "high", "medium", "low", "none"]


def now() -> datetime:
    return datetime.now(timezone.utc)


def severity(s: str | None) -> Severity | None:
    """'HIGH' / 'High' -> 'high'; 'Unknown' / '' / None -> None (unknown, not 'none' = scored as no impact)."""
    s = (s or "").strip().lower()
    return s if s in ("critical", "high", "medium", "low", "none") else None


class AffectedConfiguration(BaseModel):
    # CPE = standard product string, e.g. cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
    # Bounds follow NVD: all four null -> the CPE's version field is the exact version ('*' = every version).
    vendor: str
    product: str
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    cpe: str | None = None
    versions_text: str | None = None  # free-text range we couldn't parse (CERT-In: "prior to 159")


class ThreatItem(BaseModel):
    threat_id: str
    cve_id: str | None = None  # only when this threat IS one CVE; advisories list theirs in cve_ids
    source: str
    title: str
    description: str | None = None
    cvss: float | None = None  # 0-10 severity: how bad it *could* be
    cvss_version: Literal["2.0", "3.0", "3.1", "4.0"] | None = None
    severity: Severity | None = None
    epss: float | None = None  # 0-1 probability it gets exploited in the next 30 days
    epss_percentile: float | None = None
    kev_listed: bool | None = None  # CISA: exploited in the wild right now. None = not checked / no CVE
    public_exploit: bool | None = None  # exploit code public (Exploit-DB, GitHub PoC, Nuclei, CISA SSVC). None = not checked
    affected_configurations: list[AffectedConfiguration] = []
    references: list[str] = []
    attack_techniques: list[str] = []  # MITRE ATT&CK IDs, e.g. T1190
    # Three different dates, never mixed up (the lead-time backtest depends on it):
    published_at: datetime | None = None  # original publication: NVD's date for a CVE, the advisory/pulse date otherwise
    nvd_published_at: datetime | None = None  # when NVD published the CVE
    kev_date_added: date | None = None  # when CISA added it to KEV (= "confirmed exploited in the wild" date)
    retrieved_at: datetime = Field(default_factory=now)  # when WE fetched it (one stamp per source run)
    raw_ref: str | None = None  # primary raw payload (= raw_refs[0]), repo-relative
    raw_refs: list[str] = []  # every raw payload that contributed (e.g. KEV dump + NVD page)
    is_simulated: bool = False
    type: Literal["vulnerability", "advisory", "campaign", "ioc_batch"]
    cve_ids: list[str] = []  # every CVE this threat mentions (drives KEV/EPSS/exploit enrichment)
    tags: list[str] = []

    @model_validator(mode="after")
    def _sync_raw(self):
        # raw_ref and raw_refs always agree: raw_ref is the first (primary) payload.
        if self.raw_ref and self.raw_ref not in self.raw_refs:
            self.raw_refs = [self.raw_ref, *self.raw_refs]
        self.raw_ref = self.raw_refs[0] if self.raw_refs else None
        return self


class IOC(BaseModel):
    # contracts.json entity `ioc`. Indicator of Compromise: something seen in an attack
    # that we can look for in our own logs.
    value: str
    ioc_type: Literal["ip", "cidr", "domain", "url", "sha256", "md5"]  # cidr = whole IP range, e.g. 1.10.16.0/20
    source: str
    malware_family: str | None = None
    first_seen: datetime | None = None
    confidence: int | None = None  # 0-100
    related_threat_id: str | None = None
    retrieved_at: datetime = Field(default_factory=now)
    raw_ref: str | None = None
    is_simulated: bool = False
