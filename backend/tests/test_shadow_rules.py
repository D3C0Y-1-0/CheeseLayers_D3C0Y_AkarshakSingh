import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from shadow_watch.engine import ShadowWatchEngine
from shadow_watch.normalize import adapt_shared_events, load_events, normalize_events
from shadow_watch.rules import RuleConfig
from shadow_watch.schemas import DetectionContext

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def events():
    return load_events(ROOT / "data/fixtures/events_shadow.json")


@pytest.fixture
def context():
    return DetectionContext(protected_asset_ids=frozenset({"HLT-WEB-01", "BNK-NET-01"}))


def one(events, kind):
    return next(e for e in events if e.event_type == kind)


def test_three_rules_stable_replay_and_order(events, context):
    chain = [e for e in events if e.event_id in {"SW-EV-0001", "SW-EV-0002", "SW-EV-0003"}]
    engine = ShadowWatchEngine()
    result = engine.evaluate(chain, context)
    assert [f.detector_id for f in result] == ["SW-HTTP-001", "SW-PROC-001", "SW-NET-001"]
    assert result == engine.evaluate(list(reversed(chain)) + chain, context)
    assert {eid for f in result for eid in f.evidence_ids} == {e.event_id for e in chain}
    assert all(f.raw_ref and f.source and f.retrieved_at for f in result)
    with pytest.raises(ValidationError):
        result[0].reason = "changed"


def test_normal_http_and_small_sample(events, context):
    event = one(events, "http_window").model_dump(mode="json")
    for counts in [(100, 90), (300, 5), (0, 0)]:
        event["details"].update(request_count=counts[0], http_4xx_count=counts[1], unique_client_count=0)
        assert not ShadowWatchEngine().evaluate(normalize_events([event]), context)


def test_expected_unrelated_and_approved_process(events, context):
    event = one(events, "process_start").model_dump(mode="json")
    for parent, child in [("systemd", "bash"), ("nginx", "worker"), ("nginx-malware", "sh")]:
        event["details"].update(parent_process=parent, process_name=child)
        assert not ShadowWatchEngine().evaluate(normalize_events([event]), context)
    event["details"].update(parent_process="/usr/sbin/nginx", process_name="/bin/sh")
    approved = DetectionContext(protected_asset_ids=context.protected_asset_ids,
                                approved_process_pairs=frozenset({("nginx", "sh")}))
    assert not ShadowWatchEngine().evaluate(normalize_events([event]), approved)


def test_network_new_is_weak_and_known_or_inbound_ignored(events, context):
    event = one(events, "network_connection").model_dump(mode="json")
    result = ShadowWatchEngine().evaluate(normalize_events([event]), context)
    assert result[0].confidence == result[0].severity_hint == "low"
    for field in ("outbound", "is_new_destination"):
        raw = json.loads(json.dumps(event))
        raw["details"][field] = False
        assert not ShadowWatchEngine().evaluate(normalize_events([raw]), context)
    assert not ShadowWatchEngine().evaluate(normalize_events([event]), DetectionContext(protected_asset_ids=frozenset()))


@pytest.mark.parametrize("mutation", [
    {"observed_at": "2026-10-31"}, {"observed_at": "garbage"}, {"asset_id": ""},
    {"observed_at": 1761900000}, {"observed_at": "1761900000"},
    {"details": {"request_count": -1}}, {"details": {"request_count": True}},
    {"details": {"http_4xx_count": 9999}}, {"details": {"window_seconds": 0}},
    {"details": {"failed_auth_count": None}}, {"ingested_at": "2025-01-01T00:00:00Z"},
])
def test_bad_http_rejected(events, mutation):
    raw = one(events, "http_window").model_dump(mode="json")
    for key, val in mutation.items():
        if key == "details":
            raw[key].update(val)
        else:
            raw[key] = val
    with pytest.raises(ValidationError):
        normalize_events([raw])


def test_process_requires_host_telemetry(events):
    raw = one(events, "process_start").model_dump(mode="json")
    raw["source_type"] = "network_sensor"
    with pytest.raises(ValidationError):
        normalize_events([raw])
    raw["source_type"] = "synthetic_host"
    del raw["details"]["process_name"]
    with pytest.raises(ValidationError):
        normalize_events([raw])


def test_maintenance_lowers_http_but_preserves_process(events, context):
    maintenance = one(events, "maintenance_window").model_dump(mode="json")
    http = next(e for e in events if e.event_id == "SW-EV-0001").model_dump(mode="json")
    process = next(e for e in events if e.event_id == "SW-EV-0002").model_dump(mode="json")
    for raw in (http, process):
        raw.update(asset_id=maintenance["asset_id"], observed_at="2026-10-30T21:00:00Z", ingested_at="2026-10-30T21:00:02Z")
    result = ShadowWatchEngine().evaluate(normalize_events([maintenance, http, process]), context)
    assert next(f for f in result if f.detector_id == "SW-HTTP-001").severity_hint == "low"
    assert next(f for f in result if f.detector_id == "SW-PROC-001").severity_hint == "high"
    assert all(f.maintenance_evidence_ids == (maintenance["event_id"],) for f in result)


def test_conflicting_ids_rejected(events):
    raw = one(events, "http_window").model_dump(mode="json")
    changed = dict(raw, asset_id="OTHER")
    with pytest.raises(ValueError, match="conflicting duplicate"):
        normalize_events([raw, changed])


def test_shared_adapter_preserves_unknown_fields_as_issues():
    original = json.loads((ROOT / "data/events.json").read_text(encoding="utf-8"))
    events, issues = adapt_shared_events(original, ingested_at="2026-11-01T00:00:00Z", raw_ref="data/events.json")
    assert {e.event_id for e in events} == {"EVT-0002", "EVT-0003", "EVT-0006"}
    assert {i["event_id"] for i in issues} == {"EVT-0001", "EVT-0004", "EVT-0005", "EVT-0007", "EVT-0008"}


def test_thresholds_configurable(events, context):
    http = next(e for e in events if e.event_id == "SW-EV-0001")
    assert ShadowWatchEngine().evaluate([http], context)
    assert not ShadowWatchEngine(RuleConfig(minimum_requests_per_minute=10000)).evaluate([http], context)
