"""A separate Isolation Forest trained only on this live portal's observed windows.

Stores feature vectors/provenance, never pickles. A frozen model never retrains on incoming
evaluation traffic. It does not reuse the historical SecRepo sensor's baseline.
"""
import hashlib
import json
import math
from bisect import bisect_right
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from threading import RLock
from uuid import uuid4
from statistics import median

from sqlalchemy import select

from app.contracts import SecurityEvent
from app.correlator import CorrelationEngine
from app.database import SessionLocal
from app.models import LabMLWindow, LabObservation, LabSetting

LOCK = RLock()
KEY = "live_ml"
ASSET_ID = "LAB-GOV-WEB-01"
WINDOW_SECONDS = 5
GRACE_SECONDS = 2  # Allow in-flight portal transactions to commit before finalising a window.
MINIMUM_WINDOWS = 30
MAXIMUM_WINDOWS = 600
FEATURES = ["requests_per_second", "http_4xx_ratio", "login_failure_ratio", "unique_peers", "unique_usernames"]
CONFIG = dict(n_estimators=200, contamination=0.05, random_state=42, n_jobs=1)
LIMITATIONS = ["Operator-declared baseline, not independently labelled benign ground truth.",
    "Five-second active windows from this portal only; no idle windows are fabricated.",
    "An anomaly percentile is relative unusualness, not attack probability or forecast accuracy.",
    "ML findings are low confidence and do not authorise automatic blocking."]


def utcnow():
    return datetime.now(timezone.utc)


def boundary(stamp, ceil=False):
    units = stamp.timestamp() / WINDOW_SECONDS
    return datetime.fromtimestamp((math.ceil(units) if ceil else math.floor(units)) * WINDOW_SECONDS, timezone.utc)


def vector(rows):
    n = len(rows)
    return [n / WINDOW_SECONDS, sum(400 <= r["status"] < 500 for r in rows) / n,
            sum(r["kind"] == "login" and r["status"] == 401 for r in rows) / n,
            len({r["peer_ip"] for r in rows}), len({r["username"] for r in rows if r.get("username")})]


@lru_cache(maxsize=4)
def fitted(serialized):
    import sklearn
    from sklearn.ensemble import IsolationForest
    payload = json.loads(serialized)
    if payload["sklearn_version"] != sklearn.__version__:
        raise ValueError("Lab model library changed; collect and freeze a new baseline")
    model = IsolationForest(**payload["config"]).fit(payload["training_vectors"])
    return model, sorted(float(s) for s in model.decision_function(payload["training_vectors"]))


def score(model_data, values):
    forest, reference = fitted(json.dumps(model_data, sort_keys=True))
    s = float(forest.decision_function([values])[0])
    return dict(flagged=s < 0, score=round(s, 6),
        unusual_percentile=round(100 * (len(reference) - bisect_right(reference, s)) / len(reference), 1),
        model_id=model_data["model_id"], features=dict(zip(FEATURES, values)))


def get_config(db):
    row = db.get(LabSetting, KEY)
    return dict(row.data) if row else {"state": "disabled"}


def save(db, config):
    row = db.get(LabSetting, KEY)
    if row:
        row.data = config
    else:
        db.add(LabSetting(key=KEY, data=config))


def start(reason, stamp=None):
    stamp = stamp or utcnow()
    with LOCK, SessionLocal() as db:
        previous = get_config(db).get("model")
        if previous and db.get(LabSetting, "lab_ml_model:" + previous["model_id"]) is None:
            db.add(LabSetting(key="lab_ml_model:" + previous["model_id"], data=previous))
        config = dict(state="collecting", session_id=uuid4().hex, reason=reason,
                      started_at=stamp.isoformat(), first_window_start=boundary(stamp, ceil=True).isoformat(),
                      last_end=boundary(stamp, ceil=True).isoformat(), window_seconds=WINDOW_SECONDS)
        save(db, config)
        db.commit()
    return status()


def disable():
    with LOCK, SessionLocal() as db:
        config = get_config(db)
        config["state"] = "disabled"
        save(db, config)
        db.commit()
    return status()


def tick(stamp=None):
    """Finalise only completed windows. One control-plane worker; portal only writes observations."""
    stamp = stamp or utcnow()
    with LOCK, SessionLocal() as db:
        config = get_config(db)
        if config["state"] not in ("collecting", "frozen"):
            return
        lower, upper = datetime.fromisoformat(config["last_end"]), boundary(stamp - timedelta(seconds=GRACE_SECONDS))
        if upper <= lower:
            return
        rows = list(db.scalars(select(LabObservation).where(LabObservation.at >= lower, LabObservation.at < upper)
                              .order_by(LabObservation.at, LabObservation.event_id)))
        bins = {}
        for row in rows:
            bins.setdefault(boundary(row.at), []).append(row.data)
        for begin, records in sorted(bins.items()):
            wid = "LAB-WIN-" + config["session_id"] + "-" + str(int(begin.timestamp()))
            if db.get(LabMLWindow, wid):
                continue
            end = begin + timedelta(seconds=WINDOW_SECONDS)
            data = dict(window_id=wid, start_at=begin.isoformat(), end_at=end.isoformat(),
                phase="baseline" if config["state"] == "collecting" else "evaluation",
                features=dict(zip(FEATURES, vector(records))), request_count=len(records),
                evidence_ids=[r["event_id"] for r in records],
                rule_ids=sorted({r["finding"]["rule_id"] for r in records if r.get("finding")}),
                score=None, excluded_reason=None)
            if config["state"] == "collecting":
                if data["rule_ids"] or any(r["status"] == 429 for r in records):
                    data["excluded_reason"] = "Known deterministic finding or enforcement response in baseline window"
            elif begin >= datetime.fromisoformat(config["evaluation_from"]):
                result = score(config["model"], [data["features"][f] for f in FEATURES])
                data["score"] = result
                if result["flagged"]:
                    reason = (f"Lab Isolation Forest: five-second window more unusual than {result['unusual_percentile']}% "
                              f"of its own training windows; score {result['score']}; statistical triage, not proof of attack")
                    event = SecurityEvent(event_id=wid, asset_id=ASSET_ID, timestamp=end, event_type="http",
                        source_sensor="vectra-live-portal-5s", is_simulated=True, rule_id="LIVE-ML-001", confidence="low",
                        source="vectra_live_lab_ml", retrieved_at=stamp.isoformat(),
                        raw_ref=f"/api/lab/ml/windows/{wid}", shadow_watch_evaluated=True,
                        details=dict(attack_signal="http_anomaly", attack_label="Lab statistical anomaly",
                                     detection_reason=reason, supporting_evidence_ids=data["evidence_ids"],
                                     model_id=result["model_id"], features=data["features"]))
                    db.add(LabMLWindow(window_id=wid, session_id=config["session_id"], start_at=begin, end_at=end, data=data))
                    CorrelationEngine(db).ingest_events([event])
                    continue
            else:
                data["excluded_reason"] = "Straddles freeze time; not a future evaluation window"
            db.add(LabMLWindow(window_id=wid, session_id=config["session_id"], start_at=begin, end_at=end, data=data))
        config["last_end"] = upper.isoformat()
        save(db, config)
        db.commit()


def freeze(stamp=None):
    import sklearn
    stamp = stamp or utcnow()
    with LOCK:
        tick(stamp)
        with SessionLocal() as db:
            config = get_config(db)
            if config["state"] != "collecting":
                raise ValueError("Start baseline collection before freezing")
            windows = list(db.scalars(select(LabMLWindow).where(LabMLWindow.session_id == config["session_id"])
                                      .order_by(LabMLWindow.start_at)))
            usable = [w for w in windows if not w.data["excluded_reason"]]
            if len(usable) < MINIMUM_WINDOWS:
                raise ValueError(f"Need {MINIMUM_WINDOWS} completed eligible active windows; have {len(usable)}")
            if len(usable) > MAXIMUM_WINDOWS:
                raise ValueError("Baseline exceeds 600 windows; start a focused new collection")
            cut = int(len(usable) * 0.8)
            train, holdout = usable[:cut], usable[cut:]
            vectors = [[w.data["features"][f] for f in FEATURES] for w in train]
            if len({tuple(v) for v in vectors}) < 4:
                raise ValueError("Need at least four distinct training vectors; collect varied ordinary traffic")
            model = dict(model_id="LAB-IF-" + uuid4().hex, training_vectors=vectors,
                training_window_ids=[w.window_id for w in train], holdout_window_ids=[w.window_id for w in holdout],
                training_until=train[-1].end_at.isoformat(), baseline_until=usable[-1].end_at.isoformat(),
                frozen_at=stamp.isoformat(), sklearn_version=sklearn.__version__, config=CONFIG, features=FEATURES)
            model["baseline_reason"] = config["reason"]
            model["feature_summary"] = {f: dict(min=min(col), median=median(col), max=max(col))
                for f, col in zip(FEATURES, zip(*vectors))}
            model["fingerprint"] = hashlib.sha256(json.dumps(model, sort_keys=True).encode()).hexdigest()
            checks = [score(model, [w.data["features"][f] for f in FEATURES]) for w in holdout]
            model["holdout_flagged"] = sum(s["flagged"] for s in checks)
            db.add(LabSetting(key="lab_ml_model:" + model["model_id"], data=model))
            config.update(state="frozen", model=model, evaluation_from=boundary(stamp, ceil=True).isoformat())
            save(db, config)
            db.commit()
    return status()


def status():
    with SessionLocal() as db:
        config = get_config(db)
        session = config.get("session_id")
        windows = list(db.scalars(select(LabMLWindow).where(LabMLWindow.session_id == session)
                                  .order_by(LabMLWindow.start_at))) if session else []
        model = dict(config.get("model", {}))
        # Show provenance and size, never send the full training matrix on every console poll.
        matrix = model.pop("training_vectors", [])
        model["training_windows"] = len(matrix)
        if matrix:
            model.setdefault("feature_summary", {f: dict(min=min(col), median=median(col), max=max(col))
                for f, col in zip(FEATURES, zip(*matrix))})
        return dict(state=config["state"], session_id=session, started_at=config.get("started_at"),
            minimum_baseline_windows=MINIMUM_WINDOWS, window_seconds=WINDOW_SECONDS,
            finalisation_grace_seconds=GRACE_SECONDS,
            eligible_baseline_windows=sum(w.data["phase"] == "baseline" and not w.data["excluded_reason"] for w in windows),
            model=model, windows=[w.data for w in windows[-30:]][::-1], limitations=LIMITATIONS)
