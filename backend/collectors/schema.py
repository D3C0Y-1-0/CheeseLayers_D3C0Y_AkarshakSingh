"""Normalised schemas (CLAUDE.md §8). Core contract — tell the team before changing."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class Affected(BaseModel):
    # CPE = standard product string, e.g. cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
    # The correlator matches these against our asset inventory.
    vendor: str
    product: str
    versions: list[str] = []  # e.g. ["2.4.49"], ["<2.4.51"], [">=1.0,<1.5"]
    cpe: str | None = None


class ThreatItem(BaseModel):
    id: str
    source: str
    type: Literal["vulnerability", "advisory", "campaign", "ioc_batch"]
    title: str
    description: str = ""
    published_at: datetime | None = None
    url: str | None = None
    cve_ids: list[str] = []
    cvss: float | None = None  # 0-10 severity: how bad it *could* be
    severity: str = "Unknown"  # Critical | High | Medium | Low | None | Unknown
    epss: float | None = None  # 0-1 probability it gets exploited in the next 30 days
    in_kev: bool = False  # CISA says it is being exploited in the wild right now
    public_exploit: bool = False  # working exploit code is public (Exploit-DB, GitHub PoC, Nuclei template, CISA SSVC)
    affected: list[Affected] = []
    attack_techniques: list[str] = []  # MITRE ATT&CK IDs, e.g. T1190
    tags: list[str] = []
    raw_ref: str | None = None  # file under data/raw/ this came from


class IOC(BaseModel):
    # Indicator of Compromise: something seen in an attack we can look for in our own logs.
    value: str
    ioc_type: Literal["ip", "cidr", "domain", "url", "sha256", "md5"]  # cidr = whole IP range, e.g. 1.10.16.0/20
    source: str
    malware_family: str | None = None
    first_seen: datetime | None = None
    confidence: int | None = None  # 0-100
    related_threat_id: str | None = None
