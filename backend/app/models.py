"""DB tables. Threat columns = data/contracts.json `threat` fields; IOCRow = `ioc`."""
from sqlalchemy import JSON, Boolean, Date, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base, UTCDateTime


class RawPayload(Base):
    """One untouched response file under backend/data/raw/ (or a fixture file). Proves where a record came from."""
    __tablename__ = "raw_payloads"
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String, index=True)
    path: Mapped[str] = mapped_column(String, unique=True)  # repo-relative
    sha256: Mapped[str | None] = mapped_column(String)  # None = file missing on disk
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    fetched_at: Mapped[object | None] = mapped_column(UTCDateTime)  # file mtime = when the collector saved it


class Threat(Base):
    __tablename__ = "threats"
    threat_id: Mapped[str] = mapped_column(String, primary_key=True)
    cve_id: Mapped[str | None] = mapped_column(String, index=True)
    source: Mapped[str] = mapped_column(String, index=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    cvss: Mapped[float | None] = mapped_column(Float)
    cvss_version: Mapped[str | None] = mapped_column(String)
    severity: Mapped[str | None] = mapped_column(String, index=True)
    epss: Mapped[float | None] = mapped_column(Float, index=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    kev_listed: Mapped[bool | None] = mapped_column(Boolean, index=True)
    public_exploit: Mapped[bool | None] = mapped_column(Boolean)
    affected_configurations: Mapped[list] = mapped_column(JSON, default=list)
    references: Mapped[list] = mapped_column(JSON, default=list)
    attack_techniques: Mapped[list] = mapped_column(JSON, default=list)
    published_at: Mapped[object | None] = mapped_column(UTCDateTime, index=True)
    nvd_published_at: Mapped[object | None] = mapped_column(UTCDateTime)
    kev_date_added: Mapped[object | None] = mapped_column(Date, index=True)
    retrieved_at: Mapped[object] = mapped_column(UTCDateTime, index=True)
    raw_ref: Mapped[str | None] = mapped_column(String)
    raw_refs: Mapped[list] = mapped_column(JSON, default=list)  # -> raw_payloads.path (every contributing payload)
    is_simulated: Mapped[bool] = mapped_column(Boolean, index=True, default=False)
    type: Mapped[str] = mapped_column(String)
    cve_ids: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)


class IOCRow(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("ioc_type", "value"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    ioc_type: Mapped[str] = mapped_column(String, index=True)
    source: Mapped[str] = mapped_column(String, index=True)
    malware_family: Mapped[str | None] = mapped_column(String)
    first_seen: Mapped[object | None] = mapped_column(UTCDateTime)
    confidence: Mapped[int | None] = mapped_column(Integer)
    related_threat_id: Mapped[str | None] = mapped_column(String, index=True)  # -> threats.threat_id (not enforced)
    retrieved_at: Mapped[object] = mapped_column(UTCDateTime)
    raw_ref: Mapped[str | None] = mapped_column(String)
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_payload_id: Mapped[int | None] = mapped_column(ForeignKey("raw_payloads.id"))


class SourceStatus(Base):
    """One row per collector, rewritten by collectors/run_all.py on every run."""
    __tablename__ = "source_status"
    source: Mapped[str] = mapped_column(String, primary_key=True)
    last_attempt: Mapped[object | None] = mapped_column(UTCDateTime)  # last live fetch try (None in DEMO_MODE-only history)
    last_success: Mapped[object | None] = mapped_column(UTCDateTime)  # when the data we hold was fetched
    status: Mapped[str] = mapped_column(String)  # ok | stale | failed | skipped | cache
    error: Mapped[str | None] = mapped_column(Text)
    record_count: Mapped[int | None] = mapped_column(Integer)


class ExploitEvidence(Base):
    """Per-CVE public-exploit evidence (derived from caches) so change detection can diff it against the last load."""
    __tablename__ = "exploit_evidence"
    cve_id: Mapped[str] = mapped_column(String, primary_key=True)
    exploitdb: Mapped[bool] = mapped_column(Boolean, default=False)
    exploitdb_date: Mapped[str | None] = mapped_column(String)
    github_poc_listed: Mapped[bool] = mapped_column(Boolean, default=False)  # PoC-in-GitHub lists any repo
    github_poc_ok: Mapped[bool | None] = mapped_column(Boolean)  # quality-filtered PoC; None = not checked
    github_poc_repo: Mapped[str | None] = mapped_column(String)
    github_poc_date: Mapped[str | None] = mapped_column(String)


class ThreatSignal(Base):
    """An early-warning change seen on a threat (contracts.json `threat_signal`). History: never auto-dropped."""
    __tablename__ = "threat_signals"
    signal_id: Mapped[str] = mapped_column(String, primary_key=True)  # deterministic hash -> same change, same id
    threat_id: Mapped[str] = mapped_column(String, index=True)
    signal_type: Mapped[str] = mapped_column(String, index=True)
    old_value: Mapped[object | None] = mapped_column(JSON)
    new_value: Mapped[object | None] = mapped_column(JSON)
    detected_at: Mapped[object] = mapped_column(UTCDateTime, index=True)
    source: Mapped[str] = mapped_column(String)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
