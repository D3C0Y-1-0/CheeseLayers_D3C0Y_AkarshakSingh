import pytest
from pydantic import ValidationError

from ai.schemas import IncidentContext
from ai.tools import InvestigationScope, ReadOnlyTools
from test_shadow_investigation import setup


def test_tool_scope_and_hard_budget():
    _, ctx, tools = setup()
    with pytest.raises(PermissionError):
        tools.get_incident_context("OTHER-INCIDENT")
    with pytest.raises(PermissionError):
        tools.get_asset_evidence("OTHER-ASSET")
    assert tools.get_incident_context(ctx.incident_id)["incident_id"] == ctx.incident_id
    assert len(tools.get_asset_evidence(ctx.asset_ids[0])["items"]) <= 100
    assert tools.get_remediation_guidance(None)["patch_verified"] is False
    with pytest.raises(PermissionError, match="budget"):
        tools.get_incident_context(ctx.incident_id)
    assert not any(hasattr(tools, name) for name in ("shell", "scan", "execute", "update", "delete"))


def test_invalid_time_window_and_unverified_threat():
    _, ctx, tools = setup()
    with pytest.raises(ValueError):
        tools.get_asset_evidence(ctx.asset_ids[0], {"start_at": "garbage", "end_at": "2026-10-31T00:00:00Z"})
    with pytest.raises(PermissionError):
        tools.get_remediation_guidance("CVE-2024-4577")


def test_provider_cannot_escape_scope_or_mix_real_data():
    provider, ctx, _ = setup()
    tools = ReadOnlyTools(provider, InvestigationScope(ctx.incident_id, frozenset({"OTHER-ASSET"})))
    with pytest.raises(PermissionError):
        tools.get_incident_context(ctx.incident_id)
    raw = ctx.model_dump(mode="json")
    raw["evidence"][0]["asset_id"] = "OTHER-ASSET"
    with pytest.raises(ValidationError):
        IncidentContext.model_validate(raw)


def test_incident_rejects_invented_evidence():
    _, ctx, _ = setup()
    raw = ctx.model_dump(mode="json")
    raw["findings"][0]["evidence_ids"] = ["missing"]
    with pytest.raises(ValidationError):
        IncidentContext.model_validate(raw)


def test_invalid_destination_and_missing_counts_rejected():
    from shadow_watch.normalize import normalize_events
    _, ctx, _ = setup()
    raw = next(e.model_dump(mode="json") for e in ctx.evidence if e.event_type == "network_connection")
    for field, value in [("destination_port", 65536), ("destination_ip", "https://example.com"), ("outbound", "false")]:
        changed = {**raw, "details": {**raw["details"], field: value}}
        with pytest.raises(ValidationError):
            normalize_events([changed])
