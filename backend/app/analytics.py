"""Member 3 USPs: simulated sector exposure heatmap and the what-if patch impact simulator.

Both reuse the real matcher and scoring engine; nothing here has its own risk logic.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, get_args

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .asset_store import get_asset_store
from .contracts import Asset, Sector, ThreatRecord
from .correlator import AlertRow, CorrelationEngine, threat_from_row
from .database import get_db
from .matcher import match_asset, norm
from .models import Threat
from .scoring import score_incident

router = APIRouter()
DATA = Path(__file__).resolve().parents[2] / "data"

SECTOR_LABELS = {"power": "Power/Energy", "banking": "Banking", "govt": "Government", "health": "Healthcare",
                 "telecom": "Telecom", "water": "Water"}

SOURCE_LABELS = {"nvd": "NVD", "kev": "CISA KEV", "otx": "AlienVault OTX", "certin": "CERT-In",
                 "epss": "FIRST EPSS", "threatfox": "ThreatFox", "urlhaus": "URLhaus",
                 "malwarebazaar": "MalwareBazaar", "feodotracker": "Feodo Tracker",
                 "ransomware": "Ransomware leak sites", "openphish": "OpenPhish", "spamhaus_drop": "Spamhaus DROP",
                 "tor_exit": "Tor exit nodes", "netrax_synthetic": "Synthetic (demo)", "vectra_lab": "Vectra lab"}


def _source_label(source: str | None) -> str:
    if not source:
        return "unknown"
    if "+" in source:  # a record corroborated by several feeds, e.g. "nvd+kev"
        return " + ".join(_source_label(s) for s in source.split("+"))
    return SOURCE_LABELS.get(source, source.replace("_", " ").title())


def _active_alerts(db: Session) -> list[dict]:
    return [CorrelationEngine.to_alert(r) for r in db.scalars(select(AlertRow))
            if r.data["status"] != "resolved"]


# --- sector posture ----------------------------------------------------------------------------------

@router.get("/api/sectors/posture", tags=["analytics"])
def sector_posture(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Per-sector exposure from the synthetic asset inventory and the currently active (not resolved) alerts."""
    store = get_asset_store()
    active = _active_alerts(db)
    sectors = []
    for sector in get_args(Sector):
        assets = store.by_sector(sector)
        ids = {a.asset_id for a in assets}
        mine = [a for a in active if ids & set(a["asset_ids"])]
        vuln = [a for a in mine if a["kind"] == "vulnerability"]
        affected = {i for a in vuln if a["match_detail"] == "confirmed_affected" for i in a["asset_ids"]} & ids
        verify = {i for a in vuln if a["match_detail"] == "needs_verification" for i in a["asset_ids"]} & ids - affected

        # Each asset's priority score = its worst active alert. Sector risk = criticality-weighted mean over ALL
        # assets (unexposed ones count as 0), so one bad asset in a big sector isn't over- or under-stated.
        asset_score = {a.asset_id: 0.0 for a in assets}
        for a in mine:
            for i in set(a["asset_ids"]) & ids:
                asset_score[i] = max(asset_score[i], a["risk_score"] or 0.0)
        weight = {a.asset_id: a.criticality for a in assets}
        weighted = sum(weight[i] * s for i, s in asset_score.items()) / sum(weight.values()) if assets else 0.0

        threat_count: dict[str, int] = {}
        for a in vuln:
            for t in a["threat_ids"]:
                threat_count[t] = threat_count.get(t, 0) + 1
        top = sorted(threat_count, key=lambda t: (-threat_count[t], t))[:5]
        sectors.append({
            "sector": sector,
            "label": SECTOR_LABELS[sector],
            "total_assets": len(assets),
            "confirmed_affected_assets": len(affected),
            "needs_verification_assets": len(verify),
            "active_incidents": len(mine),
            "active_critical_high_incidents": sum(a["priority"] in ("critical", "high") for a in mine),
            "max_asset_priority_score": max(asset_score.values(), default=0.0),
            "weighted_sector_risk_score": round(weighted, 1),
            "top_threat_ids": top,
        })
    return {
        "data_classification": "Simulated Sector Exposure (Synthetic Asset Inventory)",
        "is_simulated": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "formula": "weighted_sector_risk_score = sum(criticality x worst active alert risk_score per asset) / "
                   "sum(criticality), over every asset in the sector (assets with no active alert count as 0)",
        "sectors": sorted(sectors, key=lambda s: -s["weighted_sector_risk_score"]),
    }


# --- what-if patch simulator -------------------------------------------------------------------------

class PatchImpactRequest(BaseModel):
    threat_id: str | None = None
    asset_ids: list[str] | None = None
    patched_version: str = Field(min_length=1)

    @model_validator(mode="after")
    def _need_target(self):
        if not self.threat_id and not self.asset_ids:
            raise ValueError("give threat_id, asset_ids, or both")
        return self


def _load_threat(db: Session, threat_id: str) -> ThreatRecord | None:
    """From Member 2's threats table, falling back to the demo fixture files (works before the DB is loaded)."""
    row = db.get(Threat, threat_id)
    if row is not None:
        return threat_from_row(row)
    for f in ("demo_cves.json", "threats_synthetic.json"):
        for t in json.loads((DATA / f).read_text(encoding="utf-8")):
            if t["threat_id"] == threat_id:
                return ThreatRecord.model_validate(t)
    return None


def _patched_copy(asset: Asset, threat: ThreatRecord, version: str) -> tuple[Asset, list[str]]:
    """Deep copy of the asset with every package the threat targets set to `version`. The live store is untouched."""
    products = {(norm(c.vendor), norm(c.product)) for c in threat.affected_configurations}
    clone = asset.model_copy(deep=True)
    changed = []
    for sw in clone.software:
        if (norm(sw.vendor), norm(sw.product)) in products:
            changed.append(f"{sw.vendor}/{sw.product} {sw.version} -> {version}")
            sw.version = version
    return clone, changed


def _state(asset: Asset, threat: ThreatRecord) -> dict:
    m = match_asset(asset, threat)
    s = score_incident(asset, threat, m)
    versions = [sw.version for sw in asset.software if m.software and sw.product == m.software["product"]]
    return {"match_detail": m.match_detail, "score": s.vulnerability_priority_score,
            "priority": s.priority if s.vulnerability_priority_score > 0 else None,
            "version": versions[0] if versions else None, "reason": m.reason}


@router.post("/api/simulation/patch-impact", tags=["analytics"],
             responses={404: {"description": "unknown threat or asset"}, 400: {"description": "nothing to simulate"}})
def patch_impact(body: PatchImpactRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """What if we upgraded to `patched_version`? Re-runs the real matcher + scorer on in-memory copies of the assets
    and compares before vs after. Nothing in the inventory or the alerts changes."""
    store = get_asset_store()
    for i in body.asset_ids or []:
        if store.get(i) is None:
            raise HTTPException(404, f"asset {i} not found")

    if body.threat_id:
        threat = _load_threat(db, body.threat_id)
        if threat is None:
            raise HTTPException(404, f"threat {body.threat_id} not found")
        threats = [threat]
    else:  # assets only: simulate against the threats behind their open vulnerability alerts
        ids = set(body.asset_ids)
        tids = sorted({t for a in _active_alerts(db) if a["kind"] == "vulnerability" and ids & set(a["asset_ids"])
                       for t in a["threat_ids"]})
        threats = [t for t in (_load_threat(db, x) for x in tids) if t]
        if not threats:
            raise HTTPException(400, "these assets have no open vulnerability alerts; pass a threat_id")

    pairs: list[tuple[Asset, ThreatRecord]] = []
    for t in threats:
        if body.asset_ids:
            targets = [store.get(i) for i in body.asset_ids]
        else:  # every asset currently exposed to this threat
            targets = [a for a in store.all() if match_asset(a, t).match_detail != "confirmed_unaffected"]
        pairs += [(a, t) for a in targets]

    transitions, notes = [], []
    for asset, t in pairs:
        before = _state(asset, t)
        clone, changed = _patched_copy(asset, t, body.patched_version)
        after = _state(clone, t)
        if not changed:
            notes.append(f"{asset.asset_id} doesn't run any product targeted by {t.threat_id}; nothing to patch")
        elif after["match_detail"] == "confirmed_affected":
            notes.append(f"{body.patched_version} is still inside a vulnerable range of {t.threat_id} on {asset.asset_id}")
        elif after["match_detail"] == "needs_verification":
            notes.append(f"{asset.asset_id}: can't confirm {body.patched_version} is safe ({after['reason']})")
        transitions.append({
            "asset_id": asset.asset_id, "threat_id": t.threat_id, "changed_software": changed,
            "before": before, "after": after,
            "summary": f"{asset.asset_id}: {before['match_detail']} (score {before['score']:g}) -> "
                       f"{after['match_detail']} (score {after['score']:g})",
        })

    def count(side: str, detail: str) -> int:
        return len({x["asset_id"] for x in transitions if x[side]["match_detail"] == detail})

    before_total = round(sum(x["before"]["score"] for x in transitions), 1)
    after_total = round(sum(x["after"]["score"] for x in transitions), 1)
    return {
        "data_classification": "Modelled what-if on synthetic asset copies (no live changes)",
        "is_simulated": True,
        "threat_ids": [t.threat_id for t in threats],
        "patched_version": body.patched_version,
        "assets_simulated": len({a.asset_id for a, _ in pairs}),
        "before_affected_count": count("before", "confirmed_affected"),
        "after_affected_count": count("after", "confirmed_affected"),
        "before_needs_verification_count": count("before", "needs_verification"),
        "after_needs_verification_count": count("after", "needs_verification"),
        "before_aggregate_exposure_score": before_total,
        "after_aggregate_exposure_score": after_total,
        "modelled_exposure_reduction_pct": round(100 * (before_total - after_total) / before_total, 1)
        if before_total else 0.0,
        "formula": "aggregate exposure = sum of vulnerability_priority_score over every (asset, threat) pair; "
                   "reduction % = (before - after) / before x 100",
        "transitions": transitions,
        "notes": notes,
    }


# --- CVE impact & spread graph -----------------------------------------------------------------------

@router.get("/api/impact/{threat_id}", tags=["analytics"],
            responses={404: {"description": "unknown threat"}})
def cve_impact(threat_id: str, db: Session = Depends(get_db), max_spread_per_org: int = 6) -> dict[str, Any]:
    """Detect -> match -> spread graph for ONE advisory, from whichever feed reported it.

    Reuses the real matcher and scorer on the synthetic inventory (no own risk logic, nothing persisted):
      1. did it reach us?       version-aware match across every asset
      2. what is affected?      tri-state verdict + vulnerability_priority_score per hit
      3. how could it spread?   MODELLED lateral movement to same-organisation assets from a foothold
    """
    threat = _load_threat(db, threat_id)
    if threat is None:
        raise HTTPException(404, f"threat {threat_id} not found")
    store = get_asset_store()
    assets = store.all()
    by_id = {a.asset_id: a for a in assets}

    source = getattr(threat, "source", None)
    source_id, cve_id = f"source:{source}", f"cve:{threat.threat_id}"
    nodes: list[dict[str, Any]] = [
        {"id": source_id, "type": "source", "tier": "source", "label": _source_label(source), "source": source},
        {"id": cve_id, "type": "cve", "tier": "cve", "label": threat.cve_id or threat.threat_id,
         "threat_id": threat.threat_id, "title": threat.title, "cvss": threat.cvss, "severity": threat.severity,
         "kev_listed": threat.kev_listed, "epss": threat.epss,
         "public_exploit": bool(getattr(threat, "public_exploit", False)), "is_simulated": bool(threat.is_simulated)},
    ]
    edges: list[dict[str, Any]] = [
        {"from": source_id, "to": cve_id, "kind": "reported_by", "label": f"detected from {_source_label(source)}"}]
    notes: list[str] = []

    # 1 + 2. Direct exposure. A threat with no structured affected-product data would otherwise make match_asset
    # mark every asset needs_verification (its conservative default) -> 40 false amber nodes, so guard it.
    if not threat.affected_configurations:
        notes.append("This advisory carries no structured affected-product data, so per-asset applicability cannot be "
                     "computed automatically; an analyst must verify it. No asset is auto-flagged.")
        direct = []
    else:
        direct = [m for m in (match_asset(a, threat) for a in assets) if m.match_detail != "confirmed_unaffected"]

    affected_ids = {m.asset_id for m in direct}
    orgs_with_hit: dict[str, list[str]] = {}
    exposure_total = 0.0
    for m in direct:
        asset = by_id[m.asset_id]
        score = score_incident(asset, threat, m)
        exposure_total += score.vulnerability_priority_score
        entry = asset.internet_facing and m.match_detail == "confirmed_affected"
        sw = m.software or {}
        nodes.append({
            "id": asset.asset_id, "type": "asset", "tier": "entry" if entry else "affected",
            "asset_id": asset.asset_id, "hostname": asset.hostname, "role": asset.role, "sector": asset.sector,
            "organisation": asset.organisation, "criticality": asset.criticality,
            "internet_facing": asset.internet_facing, "os": asset.os, "match_detail": m.match_detail,
            "score": round(score.vulnerability_priority_score, 1),
            "priority": score.priority if score.vulnerability_priority_score > 0 else None,
            "software": f"{sw.get('vendor')}/{sw.get('product')} {sw.get('version')}" if sw else None,
            "reason": m.reason})
        edges.append({"from": cve_id, "to": asset.asset_id, "kind": "affects", "match_detail": m.match_detail,
                      "score": round(score.vulnerability_priority_score, 1), "label": m.match_detail.replace("_", " ")})
        orgs_with_hit.setdefault(asset.organisation, []).append(asset.asset_id)

    # 3. Spread (modelled). From each organisation that has a foothold, lateral movement to its other assets.
    # Foothold = an internet-facing confirmed hit if the org has one (external entry), else its most critical hit.
    present = {n["id"] for n in nodes}
    spread_ids: set[str] = set()
    confirmed_entry = {m.asset_id for m in direct if m.match_detail == "confirmed_affected"}
    for org, hit_ids in orgs_with_hit.items():
        hits = [by_id[i] for i in hit_ids]
        external_footholds = [a for a in hits if a.internet_facing and a.asset_id in confirmed_entry]
        foothold = external_footholds[0] if external_footholds else max(hits, key=lambda a: a.criticality)
        external = bool(external_footholds)
        neighbours = sorted((a for a in assets if a.organisation == org and a.asset_id not in affected_ids),
                            key=lambda a: (-a.criticality, a.asset_id))
        shown = neighbours[:max_spread_per_org]
        if len(neighbours) > len(shown):
            notes.append(f"{org}: {len(neighbours) - len(shown)} more internal asset(s) in the same zone not drawn.")
        for n in shown:
            spread_ids.add(n.asset_id)
            if n.asset_id not in present:
                present.add(n.asset_id)
                nodes.append({"id": n.asset_id, "type": "asset", "tier": "blast", "asset_id": n.asset_id,
                              "hostname": n.hostname, "role": n.role, "sector": n.sector, "organisation": n.organisation,
                              "criticality": n.criticality, "internet_facing": n.internet_facing, "os": n.os,
                              "match_detail": None, "score": None, "priority": None})
            edges.append({"from": foothold.asset_id, "to": n.asset_id, "kind": "can_spread_to",
                          "requires_foothold": not external, "label": "could reach",
                          "basis": ("lateral movement from an internet-facing foothold" if external
                                    else "lateral movement once an attacker already has a foothold inside")})

    if not direct and threat.affected_configurations:
        notes.append("Checked every asset: none in our inventory runs an affected version, so we are not exposed to "
                     "this advisory right now. Absence of a match is re-checked whenever inventory changes.")
    sectors_touched = {by_id[i].sector for i in affected_ids | spread_ids}
    return {
        "data_classification": "Modelled CVE impact on the synthetic asset inventory (real matcher + scorer)",
        "is_simulated": True, "threat_id": threat.threat_id, "cve_id": threat.cve_id, "title": threat.title,
        "source": source, "source_label": _source_label(source), "cvss": threat.cvss, "severity": threat.severity,
        "kev_listed": threat.kev_listed, "epss": threat.epss,
        "public_exploit": bool(getattr(threat, "public_exploit", False)), "threat_is_simulated": bool(threat.is_simulated),
        "spread_model": ("Spread is a MODELLED lateral-movement path: from a compromised asset an attacker can reach "
                         "other assets in the SAME organisation / security zone. It is derived from shared organisation "
                         "and internet exposure, NOT from observed network topology or captured traffic."),
        "summary": {
            "checked_assets": len(assets),
            "confirmed_affected": sum(m.match_detail == "confirmed_affected" for m in direct),
            "needs_verification": sum(m.match_detail == "needs_verification" for m in direct),
            "entry_points": sum(1 for n in nodes if n.get("tier") == "entry"),
            "blast_radius_assets": len(spread_ids), "organisations_touched": len(orgs_with_hit),
            "sectors_touched": len(sectors_touched), "aggregate_exposure_score": round(exposure_total, 1)},
        "nodes": nodes, "edges": edges, "notes": notes,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
