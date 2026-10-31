# Member 4 integration handoff

**Connected implementation:** `shadow_watch/integration.py` implements both interfaces against
Member 3's existing event/alert tables. FastAPI installs them during startup. Persisted synthetic
incidents work in demo mode; real incidents require authenticated tools. The interfaces below
also allow replacing these adapters. See [current integration](INTEGRATION.md).

Shared `data/contracts.json` v1.1 and flat fixtures remain unchanged. `NormalizedEvent` is an
additive typed envelope; incomplete shared-record conversion returns explicit issues.
`DetectionFinding` is an additive DTO, not a replacement `alert`. Severity hints are not central
scores. Member 3 owns correlation, priority, central incident classification and persistence.

Machine-readable DTO schemas: [member4_schemas.json](member4_schemas.json). Regenerate with
`.venv/Scripts/python.exe -X utf8 scripts/export_shadow_schemas.py`.
Capture actual route mock responses with
`.venv/Scripts/python.exe -X utf8 scripts/export_shadow_samples.py`.
That route-only exporter intentionally uses the standalone preview adapter. To capture the fully
integrated responses, start the app and run `scripts/check_integrated_http.py` instead.

## Files

| Files | Responsibility |
|---|---|
| `backend/shadow_watch/schemas.py`, `normalize.py` | Immutable typed UTC events/findings; conservative shared-fixture adapter |
| `backend/shadow_watch/rules.py`, `engine.py` | Three rules, explicit protected inventory, approved process pairs, stable findings |
| `backend/shadow_watch/demo.py` | Predefined synthetic previews and finding sink interface |
| `backend/ai/schemas.py`, `fallback.py` | Scoped incident context and deterministic report |
| `backend/ai/tools.py` | Bounded read-only provider and authorisation scope |
| `backend/ai/llm.py`, `investigator.py` | Consent-gated generation, exact grounding checks and fallback |
| `backend/routes/` | Two POST routes, registered with a small `app/main.py` addition |
| `scripts/`, `backend/tests/test_shadow*` | Fixtures, replay, tests and synthetic ML experiment |

## Member 3: receive detections

```python
from shadow_watch.engine import ShadowWatchEngine
from shadow_watch.normalize import normalize_events
from shadow_watch.schemas import DetectionContext

events = normalize_events(authorised_records)
findings = ShadowWatchEngine().evaluate(events, DetectionContext(
    protected_asset_ids=frozenset(authorised_asset_ids),
    approved_process_pairs=frozenset(),  # normalized (parent basename, child basename)
))
```

Finding fields: `finding_id`, `asset_id`, `detector_id`, `detector_version`, `finding_type`,
`observed_at`, `severity_hint`, `evidence_ids`, `reason`, `confidence`, `is_simulated`, `source`,
`retrieved_at`, `raw_ref`, `maintenance_evidence_ids`, `limitations`. Tuples serialize as arrays.
`retrieved_at` is the source event's `ingested_at`. Stable IDs hash rule version, detector, asset
and evidence ID. Identical duplicates collapse; conflicting payloads sharing an ID are rejected.
Ordering uses observation time then event ID, never substituted ingestion time.

To receive demo API findings, implement `FindingSink.accept_findings(...)` and register:

```python
app.state.shadow_finding_sink = member3_sink
```

The sink accepts keyword arguments `run_id`, `scenario`, `events` (tuple of normalized events),
`findings` (tuple of findings) and returns a tuple of central alert ID strings. Atomically persist
evidence and deduplicate by event/finding ID, including after retries/restarts. With no findings,
an empty alert tuple is valid; retain maintenance evidence without forcing an alert. A failed
handoff returns HTTP 503 and permits retry with the same run ID. A sink registered after preview
creation receives that cached preview once on replay.

The integrated sink uses Member 3's engine with a five-minute window. Member 3 retains ownership
of separate-asset handling, maintenance triage and final priority. Full integration tests now
exercise actual SQLite persistence and correlation as well as the isolated mock. Same asset/time
does not establish process/network causality; the report explicitly discloses that limitation.

## Member 2/3: provide scoped incident context

Implement `EvidenceProvider.get_incident(incident_id) -> IncidentContext`. Raise `KeyError` if
missing and `PermissionError` if denied. Then configure this synchronous auth adapter:

```python
from ai.tools import InvestigationScope, ReadOnlyTools

def investigation_tools_factory(request, incident_id):
    # Use your existing authentication and incident/asset authorisation here.
    allowed_asset_ids = authorise_incident(request, incident_id)
    return ReadOnlyTools(member3_provider, InvestigationScope(
        incident_id, frozenset(allowed_asset_ids), demo_only=False,
    ))

app.state.investigation_tools_factory = investigation_tools_factory
```

The built-in provider permits persisted simulated incidents in `DEMO_MODE=true`. It denies real
incidents and use outside demo mode. A production caller must replace it with an authenticated
factory. Preview IDs use their separate demo-only scope.

Context fields: `incident_id`, `assessment`, `asset_ids`, `evidence`, `additional_evidence`, `findings`,
`verified_cve_ids`, `references`, `limitations`, `is_simulated`, `integration_status`.
Persisted contexts use `integration_status="persisted"`. Maximum 100 evidence items/findings
and 20 assets. Legacy `additional_evidence` citations preserve original IDs and unknown ingestion
times. An unattributed incident can have an empty asset list. Typed evidence/findings match asset scope and simulation status; finding
references must exist in the context. Provide only verified CVEs and actual source references;
unknown association is an empty array. For larger incidents select a relevant bounded subset
and disclose the selection limit.

```python
tools.get_incident_context(incident_id)
tools.get_asset_evidence(asset_id, {"start_at": "2026-10-31T09:00:00Z", "end_at": "2026-10-31T10:00:00Z"})
tools.get_remediation_guidance(threat_id=None)
```

Time windows are half-open and UTC aware. Maximum three retrieval calls per instance. The
investigator currently performs one context retrieval. No mutation, scan or shell tool exists.
Verified vulnerability exposure reports work even without behavioural logs.

## Member 1: consume responses

Use [API.md](API.md) and `samples/shadow_*.json`. Show assessment, `generated_by`, `is_simulated`,
`integration_status`, evidence links, limitations and analyst-review requirement. `raw_ref` is a
repository-relative provenance pointer, not a promised download endpoint. Render log text as
plain text. Injection returns the preview directly; no Member 3 alert list/detail route has been
invented. After integration use central `alert_ids` and the teammate's normal alert endpoints.
