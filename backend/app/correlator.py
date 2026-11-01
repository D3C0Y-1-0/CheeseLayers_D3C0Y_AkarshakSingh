"""Evidence correlation: turns threat matches and sensor events into deduplicated incident alerts.

Two kinds of incident:
  vulnerability  one alert per (threat, asset). Re-ingesting the same advisory updates it, never duplicates.
  behaviour      events on ONE asset that are within `window` of each other form one incident (chained, so
                 10:00, 10:12, 10:24 is one incident). Clusters are recomputed from every stored event of the asset on
                 each ingest, so out-of-order arrival gives the same incident, and a late event that bridges two
                 incidents merges them.
Events on different assets are never merged. They are only *linked* (related_alert_ids) when they share an explicit
indicator: the exact same outbound dest_ip.
Maintenance windows are applied by time coverage (not the 15-minute chain): an approved change from 02:00-04:00
covers a spike at 02:20. Scoring decides whether it explains the activity (see scoring.py).
"""
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import JSON, Integer, String, case, delete, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from .asset_store import get_asset_store
from .contracts import (LIFECYCLE_ORDER, LIFECYCLE_TO_STATUS, Asset, IncidentAlert, SecurityEvent, ThreatRecord,
                        TimelineEntry)
from .database import Base, UTCDateTime
from .matcher import match_threat
from .scoring import CONFIG, behavioural_suspicion, classify_event, evidence_confidence, level, score_incident

DEFAULT_WINDOW_MINUTES = 15
_LEVELS = ["low", "medium", "high", "critical"]


# --- tables (registered on Member 2's Base, so init_db() creates them) --------------------------------

class AlertRow(Base):
    __tablename__ = "incident_alerts"
    alert_id: Mapped[str] = mapped_column(String, primary_key=True)
    dedup_key: Mapped[str] = mapped_column(String, unique=True)
    kind: Mapped[str] = mapped_column(String, index=True)
    priority_rank: Mapped[int] = mapped_column(Integer, index=True)  # 0 low .. 3 critical, for sorting
    updated_at: Mapped[object] = mapped_column(UTCDateTime, index=True)
    data: Mapped[dict] = mapped_column(JSON)  # the full IncidentAlert (+ audit trail)


class EventRow(Base):
    __tablename__ = "security_events"
    event_id: Mapped[str] = mapped_column(String, primary_key=True)
    asset_id: Mapped[str | None] = mapped_column(String, index=True)
    timestamp: Mapped[object] = mapped_column(UTCDateTime, index=True)
    alert_id: Mapped[str | None] = mapped_column(String, index=True)
    data: Mapped[dict] = mapped_column(JSON)


def incident_evidence(db, ids, limit=100):
    """Keep recent detections in bounded investigations, then order their evidence chronologically."""
    flagged = EventRow.data["rule_id"].as_string().is_not(None)
    rows = list(db.scalars(select(EventRow).where(EventRow.event_id.in_(ids))
        .order_by(case((flagged, 0), else_=1), EventRow.timestamp.desc(), EventRow.event_id).limit(limit + 1)))
    return sorted(rows[:limit], key=lambda r: (r.timestamp, r.event_id)), len(rows) > limit


def _now() -> datetime:
    return datetime.now(timezone.utc)


def remediation(a: dict, now: datetime | None = None) -> dict:
    """Target date = detection + CONFIG days for the priority. Overdue = past target and not yet mitigated/closed."""
    days = CONFIG["remediation_targets_days"].get(a.get("priority"))
    if days is None or not a.get("created_at"):
        return {"remediation_target_at": None, "overdue": None, "remediation_policy": CONFIG["remediation_policy_label"]}
    target = datetime.fromisoformat(a["created_at"]) + timedelta(days=days)
    done = a.get("lifecycle_status") in ("mitigated", "closed")
    return {"remediation_target_at": target.isoformat(), "remediation_target_days": days,
            "overdue": (not done) and (now or _now()) > target,
            "remediation_policy": CONFIG["remediation_policy_label"]}


def _alert_id(dedup_key: str) -> str:
    return "ALR-" + hashlib.sha1(dedup_key.encode()).hexdigest()[:8].upper()


def _audit(at: datetime, text: str, ref: str | None = None) -> dict:
    return {"at": at.isoformat(), "event": text, "ref": ref}


class CorrelationEngine:
    def __init__(self, db: Session, window_minutes: int = DEFAULT_WINDOW_MINUTES):
        self.db = db
        self.window = timedelta(minutes=window_minutes)
        self.assets = get_asset_store()

    # --- storage helpers ---------------------------------------------------------------------------

    def _load(self, alert_id: str) -> AlertRow | None:
        return self.db.get(AlertRow, alert_id)

    def _save(self, alert: IncidentAlert, dedup_key: str, audit: list[dict], extra: dict) -> None:
        alert.status = LIFECYCLE_TO_STATUS[alert.lifecycle_status]
        entries = [TimelineEntry.model_validate(a) for a in audit] + list(alert.timeline)
        alert.timeline = sorted(entries, key=lambda t: t.at)  # always chronological, whatever order things arrived
        data = alert.model_dump(mode="json") | extra | {"audit": audit}
        row = self._load(alert.alert_id)
        if row is None:
            row = AlertRow(alert_id=alert.alert_id, dedup_key=dedup_key)
            self.db.add(row)
        row.kind, row.priority_rank, row.updated_at, row.data = alert.kind, _LEVELS.index(alert.priority), _now(), data

    @staticmethod
    def to_alert(row: AlertRow) -> dict:
        """API view: the alert without internal bookkeeping fields, plus its remediation target (computed on read)."""
        a = {k: v for k, v in row.data.items() if k not in ("audit", "event_timeline")}
        return a | remediation(a)

    # --- CVE-driven alerts ---------------------------------------------------------------------------

    def correlate_threat(self, threat: ThreatRecord, trigger: str = "correlate") -> dict:
        """Match one threat against every asset; create or update one alert per exposed asset."""
        now = _now()
        out = {"threat_id": threat.threat_id, "assets_checked": len(self.assets), "created": [], "updated": [],
               "matches": []}
        for m in match_threat(threat, self.assets.all()):
            key = f"vuln:{threat.threat_id}:{m.asset_id}"
            existing = self._load(_alert_id(key))
            if m.match_detail == "confirmed_unaffected":
                if existing and existing.data["match_detail"] != "confirmed_unaffected":
                    self._mark_no_longer_matches(existing, m.reason, now)
                    out["updated"].append(existing.alert_id)
                continue

            asset = self.assets.get(m.asset_id)
            s = score_incident(asset, threat, m)
            prefix = "[SIMULATED] " if threat.is_simulated else ""  # synthetic IDs must never pass as real CVEs
            alert = IncidentAlert(
                alert_id=_alert_id(key), kind="vulnerability", priority=s.priority, status="new",
                asset_ids=[m.asset_id], threat_ids=[threat.threat_id], evidence_ids=[],
                risk_score=s.risk_score, factors=s.factors, match_status=m.match_status,
                reasons=[m.reason] + s.escalation_reasons, limitations=s.limitations + s.warnings, timeline=[],
                created_at=now, title=f"{prefix}{threat.cve_id or threat.threat_id} on {asset.hostname} ({asset.asset_id})",
                match_detail=m.match_detail, vulnerability_priority_score=s.vulnerability_priority_score,
                behavioural_suspicion_score=s.behavioural_suspicion_score,
                evidence_confidence_score=s.evidence_confidence_score, score_factors=s.score_factors,
                escalation_reasons=s.escalation_reasons,
                is_simulated=asset.is_simulated or threat.is_simulated,
            )
            if existing:
                old = existing.data
                alert.created_at = datetime.fromisoformat(old["created_at"])
                alert.lifecycle_status = old["lifecycle_status"]  # an analyst's progress is never reset by a re-score
                audit = list(old["audit"])
                if old.get("match_detail") == "confirmed_unaffected" and m.match_detail != "confirmed_unaffected":
                    alert.lifecycle_status = "detected"
                    audit.append(_audit(now, "exposure reopened: the current inventory is affected or needs verification",
                                        threat.threat_id))
                if old["priority"] != alert.priority or old["risk_score"] != alert.risk_score:
                    audit.append(_audit(now, f"re-scored ({trigger}): {old['priority']} {old['risk_score']} -> "
                                             f"{alert.priority} {alert.risk_score}", threat.threat_id))
                else:
                    audit.append(_audit(now, f"duplicate advisory received ({trigger}); no change", threat.threat_id))
                out["updated"].append(alert.alert_id)
            else:
                audit = [_audit(now, f"detected ({trigger}): {m.reason}", threat.threat_id)]
                out["created"].append(alert.alert_id)
            self._save(alert, key, audit, {"related_alert_ids": []})
            out["matches"].append({"asset_id": m.asset_id, "match_detail": m.match_detail,
                                   "match_status": m.match_status, "reason": m.reason, "alert_id": alert.alert_id,
                                   "priority": alert.priority, "risk_score": alert.risk_score})
        self.db.commit()
        return out

    def _mark_no_longer_matches(self, row: AlertRow, reason: str, now: datetime) -> None:
        a = IncidentAlert.model_validate(self.to_alert(row))
        a.match_detail, a.match_status, a.priority = "confirmed_unaffected", None, "low"
        a.vulnerability_priority_score = a.risk_score = 0
        if LIFECYCLE_ORDER.index(a.lifecycle_status) < LIFECYCLE_ORDER.index("mitigated"):
            a.lifecycle_status = "mitigated"
        audit = row.data["audit"] + [_audit(now, f"re-check: asset no longer matches ({reason})")]
        a.timeline = [t for t in a.timeline if t.ref is not None and t.ref.startswith("EVT")]
        self._save(a, row.dedup_key, audit, {"related_alert_ids": row.data.get("related_alert_ids", [])})

    # --- behaviour incidents --------------------------------------------------------------------------

    def ingest_events(self, events: list[SecurityEvent]) -> dict:
        """Store events (dedup by event_id) and rebuild the incidents of every asset they touch."""
        out = {"received": len(events), "duplicates": [], "created": [], "updated": [], "merged": [],
               "unattributed": [], "incidents": []}
        touched: set[str] = set()
        for e in events:
            row = self.db.get(EventRow, e.event_id)
            data = e.model_dump(mode="json")
            if row is not None:
                out["duplicates"].append(e.event_id)
                if row.data == data:
                    continue  # exact replay: nothing to do
                if row.asset_id and row.asset_id != e.asset_id:
                    touched.add(row.asset_id)  # the corrected event left its old asset
                row.asset_id, row.timestamp, row.data = e.asset_id, e.timestamp, data
            else:
                self.db.add(EventRow(event_id=e.event_id, asset_id=e.asset_id, timestamp=e.timestamp, data=data))
            if e.asset_id is None:
                out["unattributed"].append(self._unattributed_alert(e))
            else:
                touched.add(e.asset_id)
        self.db.flush()

        for asset_id in sorted(touched):
            for kind, alert_id in self._rebuild_asset(asset_id):
                out[kind].append(alert_id)
        self._link_shared_indicators(touched)
        self.db.commit()
        ids = list(dict.fromkeys(out["created"] + out["updated"] + out["unattributed"]))
        out["incidents"] = [self.to_alert(self._load(i)) for i in ids if self._load(i)]
        return out

    def _clusters(self, rows: list[EventRow]) -> list[list[EventRow]]:
        clusters: list[list[EventRow]] = []
        for r in sorted(rows, key=lambda r: (r.timestamp, r.event_id)):
            if clusters and r.timestamp - clusters[-1][-1].timestamp <= self.window:
                clusters[-1].append(r)
            else:
                clusters.append([r])
        return clusters

    def _rebuild_asset(self, asset_id: str) -> list[tuple[str, str]]:
        asset = self.assets.get(asset_id)
        rows = list(self.db.scalars(select(EventRow).where(EventRow.asset_id == asset_id)))
        events = {r.event_id: SecurityEvent.model_validate(r.data) for r in rows}
        maintenance = [events[r.event_id] for r in rows if r.data["event_type"] == "maintenance"]
        results: list[tuple[str, str]] = []
        now = _now()

        for cluster in self._clusters(rows):
            cluster_events = [events[r.event_id] for r in cluster]
            if not any(classify_event(e).signal for e in cluster_events):
                for r in cluster:
                    r.alert_id = None
                continue
            # Alerts this cluster's events already belong to (more than one = a late event bridged two incidents).
            owners = sorted({r.alert_id for r in cluster if r.alert_id}, key=lambda a: self._load(a).data["created_at"])
            ids = {e.event_id for e in cluster_events}
            context = [m for m in maintenance if m.event_id not in ids and self._covers(m, cluster)]
            alert_id = owners[0] if owners else _alert_id(f"behav:{asset_id}:{cluster[0].event_id}")
            existing = self._load(alert_id)
            alert, extra = self._behaviour_alert(alert_id, asset, cluster_events + context, existing, now)
            audit = list(existing.data["audit"]) if existing else [
                _audit(now, f"incident opened from {len(cluster_events)} event(s) on {asset_id}")]
            for dup in owners[1:]:
                audit.append(_audit(now, f"merged incident {dup}: a late event linked the two time windows", dup))
                self.db.execute(delete(AlertRow).where(AlertRow.alert_id == dup))
                results.append(("merged", dup))
            if existing and existing.data["priority"] != alert.priority:
                audit.append(_audit(now, f"re-scored: {existing.data['priority']} -> {alert.priority}"))
            if extra["suppressed"] and not (existing and existing.data.get("suppressed")):
                audit.append(_audit(now, next((r for r in alert.escalation_reasons if r.startswith("suppressed")),
                                              "suppressed by maintenance context")))
            key = existing.dedup_key if existing else f"behav:{asset_id}:{cluster[0].event_id}"
            self._save(alert, key, audit, extra)
            for r in cluster:
                r.alert_id = alert_id
            results.append(("updated" if existing else "created", alert_id))
        return results

    @staticmethod
    def _covers(maint: SecurityEvent, cluster: list[EventRow]) -> bool:
        try:
            start = datetime.fromisoformat(maint.details["window_start"])
            end = datetime.fromisoformat(maint.details["window_end"])
        except (KeyError, TypeError, ValueError):
            return False
        return start <= cluster[-1].timestamp and cluster[0].timestamp <= end

    def _behaviour_alert(self, alert_id: str, asset: Asset, events: list[SecurityEvent], existing: AlertRow | None,
                         now: datetime) -> tuple[IncidentAlert, dict]:
        has_vuln = list(self.db.scalars(select(AlertRow.alert_id).where(AlertRow.kind == "vulnerability")))
        open_vuln = [a for a in has_vuln if asset.asset_id in self._load(a).data["asset_ids"]
                     and self._load(a).data["match_detail"] != "confirmed_unaffected"]
        s = score_incident(asset, events=events)
        b = s.score_factors["behaviour"]
        suppressed = bool(b.get("maintenance_damping_applied"))
        signals = sorted(s.signals, key=lambda x: x.at)
        timeline = [TimelineEntry(at=x.at, event=f"{x.signal or 'context'}: {x.reason}", ref=x.event_id) for x in signals]
        dest_ips = sorted({e.details.get("dest_ip") for e in events
                           if classify_event(e).signal == "outbound_connection" and e.details.get("dest_ip")})
        kinds = ", ".join(b.get("distinct_signal_types", []))
        attacks = list(dict.fromkeys(e.details["attack_label"] for e in sorted(events, key=lambda e: e.timestamp)
                                     if e.details.get("attack_label")))
        title = (f"Maintenance activity on {asset.hostname} ({asset.asset_id}): not escalated" if suppressed
                 else f"{' + '.join(attacks)} on {asset.hostname} ({asset.asset_id})" if attacks
                 else f"Suspicious activity on {asset.hostname} ({asset.asset_id}): {kinds}")
        reasons = [f"{x.event_id}: {x.reason}" for x in signals if x.signal] + s.escalation_reasons
        if open_vuln:
            reasons.append(f"asset also has open vulnerability alert(s): {', '.join(open_vuln)}")
        alert = IncidentAlert(
            alert_id=alert_id, kind="behaviour", priority=s.priority, status="new", asset_ids=[asset.asset_id],
            threat_ids=[], evidence_ids=[x.event_id for x in signals], risk_score=s.risk_score, factors=s.factors,
            match_status=None, reasons=reasons, limitations=s.limitations, timeline=timeline,
            created_at=datetime.fromisoformat(existing.data["created_at"]) if existing else now, title=title,
            lifecycle_status=existing.data["lifecycle_status"] if existing else "detected",
            match_detail=None if open_vuln else "no_cve_behavioural",
            vulnerability_priority_score=0, behavioural_suspicion_score=s.behavioural_suspicion_score,
            evidence_confidence_score=s.evidence_confidence_score, score_factors=s.score_factors,
            escalation_reasons=s.escalation_reasons, is_simulated=asset.is_simulated or any(e.is_simulated for e in events),
        )
        related = existing.data.get("related_alert_ids", []) if existing else []
        classification = [{"rule_id": e.rule_id, "attack_type": e.details["attack_type"], "label": e.details["attack_label"],
                           "stage": e.details.get("stage"), "mitre": e.details.get("mitre", []),
                           "src_ip": e.details.get("src_ip"), "event_id": e.event_id}
                          for e in events if e.details.get("attack_type")]
        src_ips = sorted({c["src_ip"] for c in classification if c["src_ip"]})
        return alert, {"related_alert_ids": related, "indicators": {"dest_ips": dest_ips, "src_ips": src_ips},
                       "suppressed": suppressed, "attack_classification": classification}

    def _unattributed_alert(self, e: SecurityEvent) -> str:
        """An event with no asset_id can't be correlated or fully scored, but must stay visible."""
        now = _now()
        key = f"behav:unattributed:{e.event_id}"
        alert_id = _alert_id(key)
        existing = self._load(alert_id)
        score, b, signals = behavioural_suspicion(None, [e])
        conf, conf_bd = evidence_confidence(None, None, signals)
        sig = signals[0]
        prio = min(level(score), "medium", key=_LEVELS.index)  # can't be urgent if we don't know which host
        alert = IncidentAlert(
            alert_id=alert_id, kind="behaviour", priority=prio, status="new", asset_ids=[], threat_ids=[],
            evidence_ids=[e.event_id], risk_score=score, factors={"confidence": conf / 100}, match_status=None,
            reasons=[f"{e.event_id}: {sig.reason}"],
            limitations=sig.limitations + ["not correlated with other events: asset unknown; priority capped at medium"],
            timeline=[TimelineEntry(at=e.timestamp, event=f"{sig.signal or 'context'}: {sig.reason}", ref=e.event_id)],
            created_at=datetime.fromisoformat(existing.data["created_at"]) if existing else now,
            title=f"Unattributed sensor event {e.event_id} ({e.source_sensor})",
            lifecycle_status=existing.data["lifecycle_status"] if existing else "detected",
            match_detail="no_cve_behavioural", behavioural_suspicion_score=score, evidence_confidence_score=conf,
            score_factors={"behaviour": b, "confidence": conf_bd, "vulnerability": {"score": 0.0},
                           "priority": {"driver": "behaviour", "cap": "medium (asset unknown)"}},
            escalation_reasons=[f"behavioural suspicion {score} capped at {prio}: asset unknown"],
            is_simulated=e.is_simulated,
        )
        audit = existing.data["audit"] if existing else [_audit(now, "recorded unattributed event", e.event_id)]
        self._save(alert, key, audit, {"related_alert_ids": [], "indicators": {"dest_ips": []}})
        return alert_id

    def _link_shared_indicators(self, touched: set[str]) -> None:
        """Link (never merge) behaviour incidents on different assets that talk to the exact same dest_ip."""
        from .models import IOCRow  # Member 2's IOC table: tells us if the IP is a known-bad indicator

        rows = [r for r in self.db.scalars(select(AlertRow).where(AlertRow.kind == "behaviour"))
                if r.data.get("indicators", {}).get("dest_ips")]
        now = _now()
        for r in rows:
            mine = set(r.data["indicators"]["dest_ips"])
            related = []
            for o in rows:
                shared = mine & set(o.data["indicators"]["dest_ips"])
                if o.alert_id != r.alert_id and shared and set(o.data["asset_ids"]) != set(r.data["asset_ids"]):
                    related.append((o.alert_id, sorted(shared)))
            new = [(a, ips) for a, ips in related if a not in r.data.get("related_alert_ids", [])]
            if not new:
                continue
            data = dict(r.data)
            data["related_alert_ids"] = sorted(set(data.get("related_alert_ids", [])) | {a for a, _ in new})
            for a, ips in new:
                known = [i for i in ips if self.db.scalar(select(IOCRow.source).where(IOCRow.value == i).limit(1))]
                note = f"linked to {a}: both assets connected to {', '.join(ips)}"
                note += f" (known IOC: {', '.join(known)})" if known else " (not in our IOC feeds)"
                data["reasons"] = data["reasons"] + [note]
                data["audit"] = data["audit"] + [_audit(now, note, a)]
                data["timeline"] = sorted(data["timeline"] + [_audit(now, note, a)], key=lambda t: t["at"])
            r.data = data

    # --- lifecycle ------------------------------------------------------------------------------------

    def acknowledge(self, alert_id: str, to: str | None, reason: str, by: str | None) -> dict:
        row = self._load(alert_id)
        if row is None:
            raise KeyError(alert_id)
        current = row.data["lifecycle_status"]
        i = LIFECYCLE_ORDER.index(current)
        target = to or (LIFECYCLE_ORDER[i + 1] if i + 1 < len(LIFECYCLE_ORDER) else None)
        if target is None:
            raise ValueError(f"{alert_id} is already closed")
        if LIFECYCLE_ORDER.index(target) <= i:
            raise ValueError(f"can't move {alert_id} from {current} back to {target}; lifecycle only moves forward")
        now = _now()
        data = dict(row.data)
        entry = _audit(now, f"status {current} -> {target}" + (f" by {by}" if by else "") + f": {reason}")
        data["lifecycle_status"], data["status"] = target, LIFECYCLE_TO_STATUS[target]
        data["audit"] = data["audit"] + [entry]
        data["timeline"] = sorted(data["timeline"] + [entry], key=lambda t: t["at"])
        row.data, row.updated_at = data, now
        self.db.commit()
        return self.to_alert(row)

    def reset(self) -> dict[str, int]:
        n_alerts = self.db.execute(delete(AlertRow)).rowcount
        n_events = self.db.execute(delete(EventRow)).rowcount
        self.db.commit()
        return {"alerts_deleted": n_alerts, "events_deleted": n_events}


def threat_from_row(row: Any) -> ThreatRecord:
    """Member 2's `threats` table row -> ThreatRecord."""
    return ThreatRecord.model_validate({c.name: getattr(row, c.name) for c in row.__table__.columns})


__all__ = ["AlertRow", "CONFIG", "CorrelationEngine", "EventRow", "threat_from_row"]
