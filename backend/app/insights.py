"""Member 2 insight endpoints: lead-time backtest, India threat panel, STIX 2.1 export. Contract: docs/API.md."""
import math
import re
import statistics
import uuid
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache

import stix2
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from collectors.common import load_cache
from collectors.history import LEAD_TIME
from collectors.schema import ThreatItem

from .database import get_db
from .models import IOCRow, Threat

router = APIRouter()
IST = timezone(timedelta(hours=5, minutes=30))


def _threat(row: Threat) -> ThreatItem:
    return ThreatItem.model_validate(row, from_attributes=True)


# =====================================================================================================
# Lead-time backtest: would our signals have warned BEFORE CISA confirmed exploitation (KEV)?
# =====================================================================================================
class SignalHit(BaseModel):
    date: date
    detail: str | None = None  # EPSS score / advisory id


class LeadRow(BaseModel):
    cve_id: str
    title: str
    kev_date_added: date
    published_at: datetime | None  # NVD publication (null if NVD lacks it)
    flagged_at: date | None  # earliest signal strictly before kev_date_added
    lead_days: int | None  # kev_date_added - flagged_at
    first_signal: str | None
    cve_age_at_kev_days: int | None  # kev_date_added - NVD publication; null if NVD date unknown
    cohort: str  # new_cves | old_cves | unknown_age
    signals: dict[str, SignalHit | None]  # one key per LEAD_TIME["signals"]; null = did not fire before KEV


class SignalStats(BaseModel):
    fired_before_kev: int  # CVEs where this signal fired before the KEV date
    earliest_signal: int  # CVEs where it was the first (or tied-first) signal
    data_available: int  # CVEs we actually have this signal's data for


class Cohort(BaseModel):
    population: int
    flagged_before_kev: int
    pct_flagged_before_kev: float | None
    median_lead_days: float | None
    p75_lead_days: float | None


def _cohort(rows: list["LeadRow"]) -> Cohort:
    leads = [r.lead_days for r in rows if r.lead_days is not None]
    return Cohort(population=len(rows), flagged_before_kev=len(leads),
                  pct_flagged_before_kev=round(100 * len(leads) / len(rows), 1) if rows else None,
                  median_lead_days=float(statistics.median(leads)) if leads else None, p75_lead_days=_p(leads, 0.75))


class LeadTimeReport(BaseModel):
    window_days: int
    as_of: date
    population: int
    flagged_before_kev: int
    pct_flagged_before_kev: float | None
    median_lead_days: float | None
    p75_lead_days: float | None
    per_signal: dict[str, SignalStats]
    cohorts: dict[str, Cohort]  # new_cves is the honest "early warning" number; old CVEs inflate lead days
    config: dict
    methodology: list[str]
    limitations: list[str]
    rows: list[LeadRow]


METHODOLOGY = [
    "Population: CVEs CISA added to KEV in the last `window_days` days (kev_date_added from the KEV catalogue).",
    "Only signals dated strictly BEFORE kev_date_added count (no look-ahead). A signal on the KEV day itself does not count.",
    "epss: FIRST EPSS score on past dates (historical API), sampled at kev_date_added minus each of `config.epss_offsets_days`; "
    "fires at the earliest sampled date with EPSS >= `config.epss_threshold`.",
    "exploitdb: earliest Exploit-DB date_published for an exploit listing the CVE.",
    "github_poc: earliest created_at of a proof-of-concept repo listed by nomi-sec/PoC-in-GitHub that passes the quality "
    "filter: >= 1 non-README code file in its git tree AND created no earlier than the CVE's NVD publication minus "
    "`config.poc_max_days_before_publication` (older = a reused repo, not an early PoC).",
    "certin: earliest CERT-In advisory / vulnerability note (Indian date) mentioning the CVE.",
    "flagged_at = earliest signal; lead_days = kev_date_added - flagged_at. Median / p75 are over flagged CVEs only (nearest-rank p75).",
    "Cohorts: new_cves = NVD-published at most `config.new_cve_max_age_days` before the KEV date; old_cves = older. "
    "Headline numbers mix both; use cohorts.new_cves for the early-warning claim.",
]
LIMITATIONS = [
    "EPSS is sampled, not daily: its lead is a lower bound with resolution set by epss_offsets_days (max lookback = largest offset).",
    "EPSS history uses the model version live on each date (FIRST changed models, e.g. v4 in March 2025), so thresholds aren't perfectly comparable over time.",
    "PoC-in-GitHub only lists repos that still exist; deleted early PoCs are missed (undercounts lead). created_at is when the repo was made, not when code was pushed.",
    "Exploit-DB covers curated exploits only; many in-the-wild exploits never appear there.",
    "CERT-In coverage is limited to the advisories we scrape (latest ~20 per list), so older CVEs rarely get a CERT-In signal.",
    "KEV's date is when CISA confirmed exploitation, not when exploitation started; real-world lead can be shorter (attacks often precede KEV).",
    "Old CVEs added to KEV years after disclosure get huge lead_days from years-old exploits; that's real but not an early warning. See cohorts.",
    "Small population (one window of KEV additions): percentages swing a lot; treat as indicative, not a benchmark.",
]


def _p(xs: list[int], q: float) -> float | None:
    if not xs:
        return None
    xs = sorted(xs)
    return float(xs[max(0, math.ceil(q * len(xs)) - 1)])


def _certin_dates(db: Session) -> dict[str, tuple[date, str]]:
    out: dict[str, tuple[date, str]] = {}
    for t in db.scalars(select(Threat).where(Threat.source == "certin", Threat.published_at.is_not(None))):
        d = t.published_at.astimezone(IST).date()  # CERT-In dates are Indian calendar dates
        for c in t.cve_ids:
            if c not in out or d < out[c][0]:
                out[c] = (d, t.threat_id)
    return out


@router.get("/api/insights/lead-time", response_model=LeadTimeReport, tags=["insights"])
def lead_time(days: int = Query(90, ge=1, le=LEAD_TIME["max_window_days"], description="KEV additions in the last N days"),
              db: Session = Depends(get_db)):
    """Backtest: how many recent KEV CVEs did our early signals flag before CISA confirmed exploitation, and how early."""
    today = datetime.now(timezone.utc).date()
    pop = db.scalars(select(Threat).where(Threat.kev_date_added >= today - timedelta(days=days), Threat.cve_id.is_not(None))
                     .order_by(Threat.kev_date_added.desc())).all()
    epss_hist = load_cache("epss_history") or {}
    exploit = load_cache("exploit_signals") or {}
    poc = load_cache("github_poc_quality") or {}  # quality-filtered: real code, not older than the CVE
    certin = _certin_dates(db)
    thr = LEAD_TIME["epss_threshold"]
    names = LEAD_TIME["signals"]
    stats = {n: SignalStats(fired_before_kev=0, earliest_signal=0, data_available=0) for n in names}
    rows: list[LeadRow] = []
    for t in pop:
        cve, kd = t.cve_id, t.kev_date_added
        h = epss_hist.get(cve) or {}
        hits = sorted(d for d, v in h.items() if v is not None and v >= thr and date.fromisoformat(d) < kd)
        ed = (exploit.get(cve) or {}).get("exploitdb_date")
        q = poc.get(cve)
        pd = q["first_ok_created_at"] if q and q.get("ok") else None
        # Earliest credible PoC date: NVD publication minus the grace period (CVE year start if NVD date unknown).
        pub = t.nvd_published_at.date() if t.nvd_published_at else date(int(cve.split("-")[1]), 1, 1)
        poc_floor = pub - timedelta(days=LEAD_TIME["poc_max_days_before_publication"])
        pd_ok = pd and poc_floor <= date.fromisoformat(pd[:10]) < kd
        sig = {
            "epss": SignalHit(date=hits[0], detail=f"epss={h[hits[0]]:.3f}") if hits else None,
            "exploitdb": SignalHit(date=ed) if ed and date.fromisoformat(ed) < kd else None,
            "github_poc": SignalHit(date=pd[:10]) if pd_ok else None,
            "certin": SignalHit(date=certin[cve][0], detail=certin[cve][1]) if cve in certin and certin[cve][0] < kd else None,
        }
        avail = {"epss": bool(h), "exploitdb": bool(ed), "github_poc": q is not None, "certin": cve in certin}
        fired = {n: s.date for n, s in sig.items() if s}
        flagged = min(fired.values(), default=None)
        for n in names:
            stats[n].data_available += avail[n]
            stats[n].fired_before_kev += n in fired
            stats[n].earliest_signal += fired.get(n) == flagged and flagged is not None
        age = (kd - t.nvd_published_at.date()).days if t.nvd_published_at else None
        rows.append(LeadRow(cve_id=cve, title=t.title, kev_date_added=kd, published_at=t.published_at, flagged_at=flagged,
                            lead_days=(kd - flagged).days if flagged else None,
                            first_signal=min(fired, key=fired.get) if fired else None, cve_age_at_kev_days=age,
                            cohort="unknown_age" if age is None else "new_cves" if age <= LEAD_TIME["new_cve_max_age_days"] else "old_cves",
                            signals=sig))
    rows.sort(key=lambda r: (r.lead_days is None, -(r.lead_days or 0), r.cve_id))
    total = _cohort(rows)
    return LeadTimeReport(
        window_days=days, as_of=today, **total.model_dump(), per_signal=stats,
        cohorts={c: _cohort([r for r in rows if r.cohort == c]) for c in ("new_cves", "old_cves", "unknown_age")},
        config=LEAD_TIME, methodology=METHODOLOGY, limitations=LIMITATIONS, rows=rows)


# =====================================================================================================
# India threat panel
# =====================================================================================================
class Victim(BaseModel):
    threat_id: str
    title: str
    published_at: datetime | None
    references: list[str]


class RansomGroup(BaseModel):
    sector: str
    group: str
    count: int
    victims: list[Victim]


class IndiaPanel(BaseModel):
    certin_advisories: list[ThreatItem]
    ransomware_victims_total: int
    ransomware_by_sector: dict[str, int]
    ransomware_by_group: dict[str, int]
    ransomware_groups: list[RansomGroup]  # one entry per (sector, ransomware group), largest first
    otx_pulses: list[ThreatItem]
    notes: list[str]


INDIA = re.compile(r"\bindia\b", re.I)  # word match: "British Indian Ocean Territory" must NOT count


def _tag(tags: list[str], prefix: str) -> str:
    v = next((t.split(":", 1)[1] for t in tags if t.startswith(prefix)), None)
    return "unknown" if not v or v.lower() in ("not found", "unknown", "") else v


def _mentions_india(t: Threat) -> bool:
    return any(x.lower() in ("india", "target:india", "country:in") for x in t.tags) or bool(INDIA.search(t.title or ""))


@router.get("/api/insights/india", response_model=IndiaPanel, tags=["insights"])
def india(limit: int = Query(10, ge=1, le=50, description="Max CERT-In advisories / OTX pulses returned"),
          db: Session = Depends(get_db)):
    """India-first view: latest CERT-In advisories, ransomware victims in India, OTX campaigns targeting India."""
    newest = (Threat.published_at.is_(None), Threat.published_at.desc())
    certin = db.scalars(select(Threat).where(Threat.source == "certin").order_by(*newest).limit(limit)).all()
    victims = [t for t in db.scalars(select(Threat).where(Threat.source == "ransomware").order_by(*newest)) if "india" in t.tags]
    groups: dict[tuple[str, str], list[Threat]] = {}
    for v in victims:
        groups.setdefault((_tag(v.tags, "sector:"), _tag(v.tags, "group:")), []).append(v)
    pulses = [t for t in db.scalars(select(Threat).where(Threat.source == "otx").order_by(*newest)) if _mentions_india(t)]
    count = lambda key: dict(sorted(((k, sum(len(g) for kk, g in groups.items() if kk[key] == k)) for k in {kk[key] for kk in groups}),
                                    key=lambda x: -x[1]))
    return IndiaPanel(
        certin_advisories=[_threat(t) for t in certin],
        ransomware_victims_total=len(victims),
        ransomware_by_sector=count(0), ransomware_by_group=count(1),
        ransomware_groups=[RansomGroup(sector=s, group=g, count=len(vs),
                                       victims=[Victim(threat_id=v.threat_id, title=v.title, published_at=v.published_at,
                                                       references=v.references) for v in vs])
                           for (s, g), vs in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))],
        otx_pulses=[_threat(t) for t in pulses[:limit]],
        notes=["Ransomware victims come from ransomware.live (country = IN). Links point to ransomware.live, never the leak site.",
               "OTX pulses count if a tag / targeted country is exactly India or the title says 'India'."],
    )


# =====================================================================================================
# STIX 2.1 export (for SIEMs / TAXII / other CERTs)
# =====================================================================================================
NS = uuid.UUID("6f1b3c1e-7d4a-4c1e-9a55-4e45545241ff")  # fixed namespace -> same object, same STIX id on every export
EPOCH = datetime(2026, 10, 31, tzinfo=timezone.utc)
IDENTITY = stix2.Identity(id=f"identity--{uuid.uuid5(NS, 'Vectra')}", name="Vectra", identity_class="system",
                          created=EPOCH, modified=EPOCH,
                          description="Vectra national cyber threat early-warning prototype (D3COY hackathon, PS 01).")
MAX_IDS = 50
MAX_INDICATORS = 1000  # per threat; a Note in the bundle says when we truncated
PATTERN = {"ip": "ipv4-addr:value", "cidr": "ipv4-addr:value", "domain": "domain-name:value", "url": "url:value",
           "sha256": "file:hashes.'SHA-256'", "md5": "file:hashes.MD5"}


def sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, f'{kind}:{key}')}"


@lru_cache(1)
def _attack_names() -> dict[str, str]:
    return {t["id"]: t["name"] for t in load_cache("attack_techniques") or []}


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")  # STIX pattern string literal escaping


def build_bundle(db: Session, threats: list[Threat]) -> stix2.Bundle:
    objs: dict[str, object] = {IDENTITY.id: IDENTITY}
    rel = lambda src, kind, dst: objs.setdefault(sid("relationship", f"{src}|{kind}|{dst}"), stix2.Relationship(
        id=sid("relationship", f"{src}|{kind}|{dst}"), source_ref=src, relationship_type=kind, target_ref=dst,
        created_by_ref=IDENTITY.id, created=EPOCH, modified=EPOCH))
    for t in threats:
        created = t.published_at or t.retrieved_at
        common = dict(created_by_ref=IDENTITY.id, created=created, modified=max(created, t.retrieved_at),
                      object_marking_refs=[stix2.TLP_WHITE], labels=["simulated"] if t.is_simulated else None)
        refs = [{"source_name": t.source, "url": u} for u in t.references[:20]]

        def vuln(cve: str | None, key: str) -> str:
            ext = [{"source_name": "cve", "external_id": cve}] if cve else [{"source_name": "vectra", "external_id": key}]
            v = stix2.Vulnerability(id=sid("vulnerability", key), name=cve or key, external_references=ext + (refs if key == t.threat_id else []),
                                    description=t.description if key == t.threat_id else None, **common)
            return objs.setdefault(v.id, v).id

        if t.type == "vulnerability":
            main = vuln(t.cve_id, t.threat_id)  # synthetic DEMO-VULN-*: no CVE external ref, labelled "simulated"
            vulns = [main]
        else:
            vulns = [vuln(c, c) for c in t.cve_ids]
            if t.type == "advisory":
                obj = stix2.Report(id=sid("report", t.threat_id), name=t.title, description=t.description, published=created,
                                   report_types=["vulnerability"], object_refs=vulns or [IDENTITY.id], external_references=refs or None, **common)
            else:  # campaign, ioc_batch
                obj = stix2.Campaign(id=sid("campaign", t.threat_id), name=t.title, description=t.description,
                                     external_references=refs or None, **common)
                for v in vulns:
                    rel(obj.id, "targets", v)
            main = objs.setdefault(obj.id, obj).id
        for tech in t.attack_techniques:
            ap = stix2.AttackPattern(id=sid("attack-pattern", tech), name=_attack_names().get(tech, tech), created_by_ref=IDENTITY.id,
                                     created=EPOCH, modified=EPOCH, external_references=[{
                                         "source_name": "mitre-attack", "external_id": tech,
                                         "url": f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/"}])
            objs.setdefault(ap.id, ap)
            for v in vulns:
                rel(ap.id, "targets", v)  # technique exploits / follows the vulnerability
            if main not in vulns:
                rel(main, "uses", ap.id)
        iocs = db.scalars(select(IOCRow).where(IOCRow.related_threat_id == t.threat_id).limit(MAX_INDICATORS + 1)).all()
        for i in iocs[:MAX_INDICATORS]:
            ind = stix2.Indicator(
                id=sid("indicator", f"{i.ioc_type}:{i.value}"), name=i.value, pattern_type="stix",
                pattern=f"[{PATTERN[i.ioc_type]} = '{_esc(i.value)}']", valid_from=i.first_seen or i.retrieved_at,
                indicator_types=["anomalous-activity"] if i.source == "tor_exit" else ["malicious-activity"],
                confidence=i.confidence, labels=[x for x in (i.source, i.malware_family) if x] or None,
                created_by_ref=IDENTITY.id, created=i.retrieved_at, modified=i.retrieved_at, object_marking_refs=[stix2.TLP_WHITE])
            objs.setdefault(ind.id, ind)
            # "indicates" is only valid towards campaigns/malware/etc.; a vulnerability or report gets "related-to".
            rel(ind.id, "indicates" if main.startswith("campaign--") else "related-to", main)
        if len(iocs) > MAX_INDICATORS:
            n = stix2.Note(id=sid("note", t.threat_id), content=f"Truncated: first {MAX_INDICATORS} indicators exported for {t.threat_id}.",
                           object_refs=[main], created_by_ref=IDENTITY.id, created=EPOCH, modified=EPOCH)
            objs.setdefault(n.id, n)
    return stix2.Bundle(objects=list(objs.values()), id=sid("bundle", ",".join(t.threat_id for t in threats)))


@router.get("/api/export/stix", tags=["export"], responses={200: {"content": {"application/stix+json": {}},
                                                                   "description": "STIX 2.1 bundle"},
                                                             400: {"description": "no / too many ids"}, 404: {"description": "unknown threat_id"}})
def export_stix(threat_id: str | None = Query(None, description="One threat_id"),
                ids: str | None = Query(None, description=f"Comma-separated threat_ids (max {MAX_IDS})"),
                db: Session = Depends(get_db)):
    """STIX 2.1 bundle: identity Vectra, vulnerability (CVE external ref) / campaign / report, ATT&CK attack-patterns,
    indicators for linked IOCs, and relationships. Deterministic IDs: re-exporting the same threat gives the same objects."""
    wanted = list(dict.fromkeys(([threat_id] if threat_id else []) + [i.strip() for i in (ids or "").split(",") if i.strip()]))
    if not wanted or len(wanted) > MAX_IDS:
        raise HTTPException(400, f"give threat_id or ids (1..{MAX_IDS} threat_ids)")
    rows = {t.threat_id: t for t in db.scalars(select(Threat).where(Threat.threat_id.in_(wanted)))}
    if missing := [w for w in wanted if w not in rows]:
        raise HTTPException(404, f"unknown threat_id(s): {missing}")
    bundle = build_bundle(db, [rows[w] for w in wanted])
    return Response(bundle.serialize(pretty=True), media_type="application/stix+json;version=2.1")


# =====================================================================================================
# Lead-time example timelines (3 CVEs from the backtest above)
# =====================================================================================================
@router.get("/api/insights/lead-time/examples", tags=["insights"])
def lead_time_examples(days: int = Query(90, ge=1, le=LEAD_TIME["max_window_days"]), db: Session = Depends(get_db)) -> dict:
    """Three CVEs from the backtest: largest lead, near-zero lead, and a miss, each with a dated signal timeline.
    Picks from the new-CVE cohort when possible (old CVEs with years-old exploits inflate leads)."""
    rep = lead_time(days=days, db=db)
    pool = [r for r in rep.rows if r.cohort == "new_cves"] or rep.rows
    flagged = [r for r in pool if r.lead_days is not None]
    picks = []
    if flagged:
        picks.append(("largest_lead", max(flagged, key=lambda r: (r.lead_days, r.cve_id))))
        near = min(flagged, key=lambda r: (r.lead_days, r.cve_id))
        if near.cve_id != picks[0][1].cve_id:
            picks.append(("near_zero_lead", near))
    miss = sorted((r for r in pool if r.lead_days is None), key=lambda r: (r.kev_date_added, r.cve_id), reverse=True)
    if miss:
        picks.append(("miss", miss[0]))
    epss_hist = load_cache("epss_history") or {}
    exploit = load_cache("exploit_signals") or {}
    poc = load_cache("github_poc_quality") or {}
    certin = _certin_dates(db)
    out = []
    for kind, r in picks:
        t = db.get(Threat, r.cve_id)
        kd = r.kev_date_added
        ev = []

        def add(d, what, detail=None, signal=None):
            if d:
                d = d.date() if isinstance(d, datetime) else d if isinstance(d, date) else date.fromisoformat(str(d)[:10])
                ev.append({"date": d.isoformat(), "event": what, "detail": detail, "signal": signal,
                           "before_kev": d < kd, "days_before_kev": (kd - d).days})
        add(t.nvd_published_at if t else None, "NVD publication")
        h = sorted((d, v) for d, v in (epss_hist.get(r.cve_id) or {}).items() if v is not None)
        for line in (LEAD_TIME["epss_threshold"], 0.5):  # first day EPSS crossed each line upwards
            first = next(((d, v) for d, v in h if v >= line), None)
            if first:
                add(first[0], f"EPSS crossed {line}", f"epss={first[1]:.3f}", "epss" if line == LEAD_TIME["epss_threshold"] else None)
        q = poc.get(r.cve_id) or {}
        if q.get("ok") and q.get("first_ok_created_at"):
            counted = r.signals.get("github_poc") is not None
            add(q["first_ok_created_at"], "First quality GitHub PoC", q.get("first_ok_repo")
                + ("" if counted else " (not counted: on/after KEV or before the publication grace window)"), "github_poc")
        if (exploit.get(r.cve_id) or {}).get("exploitdb_date"):
            add(exploit[r.cve_id]["exploitdb_date"], "Exploit-DB entry", None, "exploitdb")
        if r.cve_id in certin:
            add(certin[r.cve_id][0], "CERT-In advisory", certin[r.cve_id][1], "certin")
        add(kd, "Added to CISA KEV (exploitation confirmed)")
        ev.sort(key=lambda e: (e["date"], e["event"] != "NVD publication"))
        out.append({"example": kind, "cve_id": r.cve_id, "title": r.title, "cohort": r.cohort,
                    "kev_date_added": kd.isoformat(), "flagged_at": r.flagged_at.isoformat() if r.flagged_at else None,
                    "lead_days": r.lead_days, "first_signal": r.first_signal, "timeline": ev,
                    "explanation": (f"Flagged {r.lead_days} day(s) before KEV by {r.first_signal}." if r.lead_days is not None
                                    else "Missed: no early signal fired before the KEV listing.")})
    return {"window_days": days, "as_of": rep.as_of.isoformat(), "examples": out,
            "note": "Backtest on cached public data; signals are counted only strictly before the KEV date."}


# =====================================================================================================
# IP geolocation of malicious indicators (PLAN_ip_geolocation.md). Location = where the IP is REGISTERED.
# =====================================================================================================
GEO_NOTE = ("Location of the network an IP is registered to (DB-IP Lite), not of the person behind an attack: "
            "attackers mostly use rented cloud servers, VPNs, Tor exits and hijacked machines.")


@router.get("/api/geo/ip/{ip}", tags=["geo"])
def geo_ip(ip: str) -> dict:
    """Locate any IP (or CIDR). 422 if it is not an IP; geo=null when private/documentation/unlisted."""
    import ipaddress
    from collectors import geo
    try:
        ipaddress.ip_network(ip, strict=False) if "/" in ip else ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(422, "not an IP address or CIDR") from None
    g = geo.lookup(ip)
    reason = None
    if g is None:
        addr = ipaddress.ip_network(ip, strict=False).network_address if "/" in ip else ipaddress.ip_address(ip)
        reason = ("private/reserved/documentation address: has no real-world location" if not addr.is_global
                  else "geolocation database unavailable" if not geo.available() else "not in the geolocation database")
    return {"ip": ip, "geo": g, "reason": reason, "note": GEO_NOTE, "attribution": geo.ATTRIBUTION}


@router.get("/api/insights/ioc-geo", tags=["geo"])
def ioc_geo(points: int = Query(300, ge=0, le=2000, description="Max map points (grouped by ~10 km cell)"),
            db: Session = Depends(get_db)) -> dict:
    """Where the malicious IPs/networks in our feeds are registered: countries, network owners, hosting share and
    map points (lat/lon grouped, largest first). Real feed data (ThreatFox, Feodo, Tor exits, OTX, Spamhaus DROP)."""
    from collections import Counter, defaultdict
    from collectors import geo
    rows = db.execute(select(IOCRow.value, IOCRow.ioc_type, IOCRow.source, IOCRow.malware_family, IOCRow.geo)
                      .where(IOCRow.ioc_type.in_(("ip", "cidr")))).all()
    countries, codes, asns, sources = Counter(), {}, Counter(), Counter()
    cells: dict[tuple, dict] = defaultdict(lambda: {"count": 0, "sources": Counter(), "families": Counter(), "examples": []})
    hosting = hosted_known = 0
    for value, kind, source, family, g in rows:
        if not g:
            continue
        countries[g["country"]] += 1
        codes[g["country"]] = g["country_code"]
        sources[source] += 1
        if g.get("asn_org"):
            asns[(g["asn"], g["asn_org"])] += 1
        if g.get("hosting") is not None:
            hosted_known += 1
            hosting += bool(g["hosting"])
        if g.get("latitude") is not None:
            c = cells[(round(g["latitude"], 1), round(g["longitude"], 1))]
            c["count"] += 1
            c["sources"][source] += 1
            if family:
                c["families"][family] += 1
            c.setdefault("country", g["country"]); c.setdefault("city", g["city"])
            if len(c["examples"]) < 3:
                c["examples"].append(value)
    located = sum(countries.values())
    pts = sorted(cells.items(), key=lambda kv: (-kv[1]["count"], kv[0]))[:points]
    return {
        "total_ip_indicators": len(rows), "located": located, "unknown": len(rows) - located,
        "by_country": [{"country": k, "country_code": codes[k], "count": n} for k, n in countries.most_common(15)],
        "top_networks": [{"asn": a, "asn_org": o, "count": n} for (a, o), n in asns.most_common(10)],
        "hosting_share_pct": round(100 * hosting / hosted_known, 1) if hosted_known else None,
        "hosting_method": "network-owner name matches a cloud/hosting provider (heuristic)",
        "by_source": dict(sources.most_common()),
        "points": [{"lat": lat, "lon": lon, "count": c["count"], "country": c["country"], "city": c["city"],
                    "sources": dict(c["sources"]), "top_family": (c["families"].most_common(1) or [[None]])[0][0],
                    "examples": c["examples"]} for (lat, lon), c in pts],
        "geo_source": geo.SOURCE, "available": geo.available(), "attribution": geo.ATTRIBUTION, "note": GEO_NOTE,
    }
