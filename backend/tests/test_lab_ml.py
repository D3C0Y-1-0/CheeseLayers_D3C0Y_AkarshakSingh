from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

from app import live_lab
from app.correlator import CorrelationEngine, EventRow
from app.database import SessionLocal, init_db
from app.models import InventoryOverride, LabMLWindow, LabObservation, LabSetting, Threat
from shadow_watch import lab_ml

START = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def isolated():
    init_db()
    with SessionLocal() as db:
        CorrelationEngine(db).reset()
        for table in (LabMLWindow, LabObservation, LabSetting, InventoryOverride):
            db.execute(delete(table))
        db.commit()
    live_lab.initialise()
    yield
    with SessionLocal() as db:
        CorrelationEngine(db).reset()
        for table in (LabMLWindow, LabObservation, LabSetting, InventoryOverride):
            db.execute(delete(table))
        db.execute(delete(Threat).where(Threat.threat_id == live_lab.THREAT_ID))
        db.commit()


def observation(stamp, eid, status=200, finding=None):
    return dict(event_id=eid, at=stamp.isoformat(), status=status, kind="document", peer_ip="192.0.2.1",
                name="notice.txt", finding=finding, is_simulated=True)


def add_window(index, count, status=200, finding=None):
    with SessionLocal() as db:
        for i in range(count):
            stamp = START + timedelta(seconds=index * 5 + 1, microseconds=i)
            eid = f"TEST-{index}-{i}"
            db.add(LabObservation(event_id=eid, at=stamp, data=observation(stamp, eid, status, finding)))
        db.commit()


def train():
    lab_ml.start("Operator-declared ordinary traffic", START)
    for i in range(30):
        add_window(i, 1 + i)
    lab_ml.tick(START + timedelta(seconds=152))
    return lab_ml.freeze(START + timedelta(seconds=152))


def test_no_fabricated_idle_or_incomplete_windows():
    lab_ml.start("Operator declared baseline", START)
    add_window(0, 2)
    lab_ml.tick(START + timedelta(seconds=4))
    assert lab_ml.status()["eligible_baseline_windows"] == 0
    lab_ml.tick(START + timedelta(seconds=20))
    status = lab_ml.status()
    assert status["eligible_baseline_windows"] == 1 and len(status["windows"]) == 1
    assert len(status["windows"][0]["evidence_ids"]) == 2
    lab_ml.tick(START + timedelta(seconds=20))
    assert len(lab_ml.status()["windows"]) == 1


def test_not_enough_data_or_constant_training_rejected():
    lab_ml.start("Operator declared baseline", START)
    with pytest.raises(ValueError, match="Need 30"):
        lab_ml.freeze(START + timedelta(seconds=4))
    for i in range(30):
        add_window(i, 1)
    with pytest.raises(ValueError, match="distinct"):
        lab_ml.freeze(START + timedelta(seconds=152))


def test_known_rule_and_enforcement_windows_excluded():
    lab_ml.start("Operator declared baseline", START)
    add_window(0, 2, finding={"rule_id": "LIVE-WEB-001"})
    add_window(1, 2, status=429)
    lab_ml.tick(START + timedelta(seconds=12))
    status = lab_ml.status()
    assert status["eligible_baseline_windows"] == 0
    assert all(w["excluded_reason"] for w in status["windows"])


def test_temporal_holdout_frozen_model_live_outlier_and_evidence():
    result = train()
    assert result["model"]["training_windows"] == 24
    assert len(result["model"]["holdout_window_ids"]) == 6
    assert result["model"]["training_until"] < result["model"]["baseline_until"]
    before = result["model"]["fingerprint"]
    add_window(31, 80)
    lab_ml.tick(START + timedelta(seconds=162))
    state = lab_ml.status()
    assert state["model"]["fingerprint"] == before
    latest = state["windows"][0]
    assert latest["phase"] == "evaluation" and latest["score"]["flagged"]
    with SessionLocal() as db:
        event = db.get(EventRow, latest["window_id"])
        assert event.data["rule_id"] == "LIVE-ML-001" and event.data["confidence"] == "low"
        assert event.data["details"]["supporting_evidence_ids"] == latest["evidence_ids"]
    model_id = state["model"]["model_id"]
    lab_ml.fitted.cache_clear()  # Process restart recreates the same model from stored vectors.
    with SessionLocal() as db:
        model = lab_ml.get_config(db)["model"]
    assert lab_ml.score(model, [16, 0, 0, 1, 0])["model_id"] == model_id


def test_post_freeze_partial_window_not_used_as_future_evaluation():
    train()
    # Simulate freezing midway through the next window: that window straddles the freeze time.
    with SessionLocal() as db:
        cfg = lab_ml.get_config(db)
        cfg["evaluation_from"] = (START + timedelta(seconds=155)).isoformat()
        lab_ml.save(db, cfg)
        db.commit()
    add_window(30, 20)
    lab_ml.tick(START + timedelta(seconds=157))
    w = lab_ml.status()["windows"][0]
    assert w["score"] is None and "Straddles" in w["excluded_reason"]
    lab_ml.disable()
    assert lab_ml.status()["state"] == "disabled"
