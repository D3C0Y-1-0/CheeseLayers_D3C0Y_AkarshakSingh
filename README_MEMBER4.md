# NETRA-X Member 4: Shadow Watch and investigation

Three deterministic rules, immutable evidence-linked findings, offline investigation reports,
and a constrained optional Groq assistant, in the existing FastAPI app. No new database,
migrations, frontend, incident scoring formula or threat collector.

**Integration status:** `DatabaseFindingSink` and `StoredIncidentProvider` now connect to Member 3's
existing SQLite tables in the FastAPI lifespan. The frontend follows central `alert_ids` and
investigates persisted evidence. The standalone CLI still uses an in-memory preview for module
rehearsal. See [integration](docs/INTEGRATION.md) and [adapter interfaces](docs/MEMBER4_HANDOFF.md).

## Install (PowerShell, repository root)

```powershell
uv venv .venv
uv pip install --python .venv/Scripts/python.exe -r backend/requirements.txt
```

Standalone rules, fixture generation and CLI replay need only Python 3.11+ and `pydantic>=2,<3`.
Add `pytest` for rule tests. The API needs existing backend requirements; no LLM SDK is required.
Use `-X utf8` on Windows because the existing feed loader uses the platform default encoding.

```powershell
.venv/Scripts/python.exe -X utf8 scripts/generate_shadow_fixtures.py
.venv/Scripts/python.exe -X utf8 -m pytest backend/tests/test_shadow_rules.py -q -p no:cacheprovider
.venv/Scripts/python.exe -X utf8 -m pytest backend/tests/test_shadow_pipeline.py backend/tests/test_shadow_investigation.py backend/tests/test_shadow_security.py -q -p no:cacheprovider
```

`data/fixtures/` contains 8 complete synthetic events, a scenario manifest and maintenance records.
Generation is deterministic, checks inventory IDs and never rewrites shared contracts or fixtures.
`adapt_shared_events()` returns explicit issues for incomplete HTTP aggregates, missing assets and
unverifiable maintenance approval. It never invents missing counts or approval flags. The original
flat fixture remains the raw source for successfully adapted events.

## Replay and API

```powershell
.venv/Scripts/python.exe -X utf8 scripts/replay_shadow_demo.py no_cve_suspicious_chain
.venv/Scripts/python.exe -X utf8 scripts/replay_shadow_demo.py benign_maintenance
.venv/Scripts/python.exe -X utf8 scripts/replay_shadow_demo.py missing_telemetry
```

The CLI returns findings and template investigation without network, database or server.
Use `--run-id rehearsal-2` for another namespace or `--output artifacts/my_replay.json` to save it.

Run the existing API from cached threat feeds:

```powershell
$env:DEMO_MODE = 'true'
.venv/Scripts/python.exe -X utf8 -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

In a second PowerShell:

```powershell
$body = @{ scenario = 'no_cve_suspicious_chain'; run_id = 'demo-session-1' } | ConvertTo-Json
$result = Invoke-RestMethod http://127.0.0.1:8000/api/demo/inject-behaviour -Method Post -ContentType application/json -Body $body
Invoke-RestMethod "http://127.0.0.1:8000/api/alerts/$($result.incident_id)/investigate" -Method Post
```

| Scenario | Expected result |
|---|---|
| `no_cve_suspicious_chain` | HTTP anomaly, web-server shell child, new outbound destination; 3 findings; `suspected_activity`; no CVE claim |
| `benign_maintenance` | Approved change, high traffic with low error rate, expected package manager; 0 findings; `needs_verification` preview |
| `missing_telemetry` | 2 HTTP/network findings; explicit process visibility gap; `needs_verification` |

Use `incident_id` for preview investigation; use `alert_ids` for persisted central investigations.
The preview store holds at most 100 scenario/run pairs, evicts least recently replayed pairs,
and disappears on restart. Replaying a pair regenerates the same IDs and fixture timestamps.
Use one API worker for the demo. A new run ID changes IDs but keeps the original synthetic times.
No arbitrary event ingestion, URL fetch, shell command or scan endpoint exists.

API fields/errors: [docs/API.md](docs/API.md). Frontend samples:
[suspicious](docs/samples/shadow_no_cve_suspicious_chain.json),
[maintenance](docs/samples/shadow_benign_maintenance.json),
[missing telemetry](docs/samples/shadow_missing_telemetry.json).

## Configuration and optional LLM

Copy `backend/.env.example` to the repository root as `.env` if needed. Leave keys empty for the
demo. Environment variables override file values. Never commit `.env`.

| Variable | Default | Meaning |
|---|---|---|
| `DEMO_MODE` | `false` in existing backend | Set `true` for synthetic injection and zero cloud LLM requests |
| `LLM_PROVIDER` | `template` | `template` or `groq` |
| `LLM_MODEL` | empty | Operator-selected model supporting JSON output |
| `LLM_API_KEY` | empty | Provider key, kept server-side |
| `LLM_ALLOW_CLOUD` | `false` | Explicit consent to send bounded incident facts to Groq when demo mode is off |
| `LLM_TIMEOUT_SECONDS` | `5` | Generation deadline: greater than 0, at most 30 seconds |

Template-only mode makes no cloud requests. With consent, the assistant receives a bounded report
and permitted summaries. It may select a permitted summary and reorder existing analyst review
steps. Every other factual field must match exactly: evidence citations, CVEs, limitations, source
timestamps and references. It cannot invent free-form remediation or change scores. Raw advisory
bodies, command lines and original log text are excluded. No model-selected tools run; one scoped
retrieval precedes generation. Wrappers allow at most three calls and 100 evidence items.
Timeouts, provider errors, oversized or malformed output, unsupported claims and detected
instruction-like input return the template with `fallback_reason`. Error details are not exposed.

Transport follows Groq's [API reference](https://console.groq.com/docs/api-reference) and
[JSON output documentation](https://console.groq.com/docs/structured-outputs). It was tested with
mocked responses, **not a live provider credential**. Actions always require analyst review.

## Optional ML experiment

```powershell
uv pip install --python .venv/Scripts/python.exe -r backend/requirements-shadow-ml.txt
.venv/Scripts/python.exe -X utf8 scripts/evaluate_shadow.py
.venv/Scripts/python.exe -X utf8 -m pytest backend/tests/test_shadow_ml.py -q -p no:cacheprovider
```

Report: [artifacts/shadow_evaluation.json](artifacts/shadow_evaluation.json). The synthetic dataset
has 350 normal training rows and 150 held-out rows (142 normal, 8 suspicious). Test rows never
participate in fitting or threshold tuning. Feature order, dataset hash, seed, library version,
counts, false-positive denominator, raw scores and measured batch latency are recorded.

The recorded window-rule baseline found 8/8 suspicious rows and 0/142 false positives. Rules plus
Isolation Forest still found 8/8 but added 4/142 false positives (precision 0.667, recall 1.0,
FPR 0.0282). **ML is therefore not enabled or saved.** These are synthetic measurements;
pre-labelled process counts do not independently validate sensor ancestry or production accuracy.
No external dataset download was needed and incompatible schemas are not mixed.

## Validation limits and teammate work

Rules, replay, reports, evidence scoping, API gates, model-output rejection and optional evaluation
have executable tests. No-CVE detection requires neither feeds nor an LLM. Source authenticity is
the ingestion adapter's responsibility; this demo accepts only its predefined synthetic fixtures.
Durable storage, correlation, final priority and dashboard rendering are now connected. Access to
real incidents still requires a production authentication/scope factory. Suspicion or exposure
never proves a breach or zero-day.

The existing full backend suite expects ignored `backend/data/raw/` payloads absent here. Raw
reconstruction/provenance tests cannot be reproduced from caches alone. Current feed downloads
would not recreate historical raw files matching cached data, so none were fabricated.

Run `.venv/Scripts/python.exe -X utf8 scripts/smoke_shadow_api.py` for a complete offline
startup check that loads the cache into a disposable SQLite database and exercises all three
scenarios through the existing app lifespan. On restricted Windows shells the temporary SQLite
directory may require normal host permissions.
