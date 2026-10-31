# Vectra API: feeds, signals, assets, alerts, analytics, Shadow Watch and investigation

## Member 4 endpoints

### `POST /api/demo/inject-behaviour`

Available only with `DEMO_MODE=true`; otherwise 404. Request:

```json
{"scenario":"no_cve_suspicious_chain","run_id":"demo-session-1"}
```

`scenario` is required and must be `no_cve_suspicious_chain`, `benign_maintenance`, or
`missing_telemetry`. Optional `run_id` defaults as above; 1-128 characters from letters,
digits, `_`, `.`, `:`, `-`, beginning with a letter/digit. Extra fields and malformed input
return 422. Invalid/missing synthetic fixtures or unavailable Member 3 sink return 503.

Response fields: `scenario`, `run_id`, `incident_id`, `alert_ids`, `findings`, `evidence`,
`integration_status`, `handoff_status`, `is_simulated`, `note`. Evidence is the typed Member 4
envelope and references original fixture records via `raw_ref`. All demo records are simulated.
The normal app lifespan connects the SQLite handoff: `handoff_status="delivered"` and `alert_ids`
identify persisted central incidents. Benign maintenance has no escalated alert, so an empty
`alert_ids` is valid even when delivered. Standalone replay reports `pending_member3`.
`incident_id` remains the optional in-memory preview ID; the frontend follows central `alert_ids`.

Same scenario/run replays return stable IDs without duplicate findings. Preview retention is
100 runs per API process; restart resets it. Use one worker. Fixture observation times remain
historical on replay. See [handoff](MEMBER4_HANDOFF.md) for central alert sink registration.

Samples (each includes injection and investigation):
[suspicious](samples/shadow_no_cve_suspicious_chain.json),
[benign](samples/shadow_benign_maintenance.json),
[missing telemetry](samples/shadow_missing_telemetry.json).

### `POST /api/alerts/{id}/investigate`

No body. Use the injection's `incident_id` for a demo preview or an authorised persisted central
alert ID after Member 3 integration. Cloud LLM calls happen only with `LLM_ALLOW_CLOUD=true` AND
`LLM_API_KEY` set (also in demo mode); otherwise a cached LLM report or the template is returned.

Returns `incident_id`, `assessment` (`vulnerability_exposure`, `suspected_activity`,
`needs_verification`), `summary`, `asset_ids`, `verified_cve_ids`, `evidence_ids`, `evidence`,
`why_relevant`, `limitations`, `recommended_actions`, `references`, `generated_by` (`template`,
`llm` or `llm_cached`), `validation` (grounding check, see "AI narrative" below), `is_simulated`,
`integration_status`, `fallback_reason`, `analyst_review_required`.
Each evidence citation includes ID, asset, event type, observation time, sensor, source,
retrieval/ingestion time and raw provenance pointer. Unknown CVE association is an empty array.

Template reports always work offline. Optional consent-gated Groq generation may reword only
`summary`, `why_relevant` and `recommended_actions`; every other field must match trusted context
exactly, and the narrative passes the grounding check. Every action is a suggestion. `fallback_reason` is null or `offline_mode`,
`disabled`, `unconfigured`, `timeout`, `invalid_output`, `provider_error`. Model errors return
a normal 200 template report. Missing demo preview returns 404; scope denial returns 403;
invalid IDs return 422. The default persisted provider permits synthetic incidents in demo mode
and denies real incidents or access outside demo mode. Real deployments must supply an
authenticated scope factory. No evidence is inferred from missing telemetry or absent feeds.

### AI narrative: grounding, `generated_by`, cache (`backend/ai/grounded.py`)

Every AI text (investigation, threat summary, CERT-In draft, Hindi translation) starts from a
deterministic template built only from stored facts. The LLM may reword the narrative fields only.
Its output is rejected → template, `fallback_reason: "invalid_output"` if it:
contains a CVE/asset/evidence/alert ID, ATT&CK ID, version (x.y.z), IP or URL **not present in the
input**; changes any non-narrative field; claims compromise/exploitation/zero-day/attribution the
facts don't state; or contains a command. `generated_by`: `llm` (fresh, validated), `llm_cached`
(validated earlier, served from `backend/data/cache/ai_reports/<sha256 of normalised input>.json`,
works offline), `template`. `validation`: `{passed: true|false|null, checked_tokens,
rejected_tokens[], note}` (`null` = template, no model involved). `GET /health` → `llm:
{cloud_enabled, provider, reason, cached_reports}`. Pre-fill the cache for the demo with
`backend/.venv/bin/python scripts/pregenerate_ai.py` (needs the key; `--dry-run` lists what it would do).

### `POST /api/threats/{threat_id}/summary?lang=en|hi`

No body. Grounded summary of one threat. Narrative (LLM-wordable): `summary` (what it is),
`affected_summary` (who in our inventory), `exploit_summary` (KEV/EPSS/public exploit/signals),
`why_it_matters`, `recommended_actions[]`. Facts: `affected_assets[]` (Member 3's matcher run
read-only, `confirmed_affected` or `needs_verification`, with `installed` and `fixed_in`),
`alert_ids[]`, `exploit_signals` `{kev_listed, epss, public_exploit, evidence, signals[]}`,
`sources` `{references[], raw_refs[]}`, `is_simulated`, `language`, plus `generated_by`,
`validation`, `fallback_reason`, `analyst_review_required: true`. Synthetic threats say "synthetic
demo record, not a real CVE"; null CVSS/EPSS/KEV read "unknown". 404 unknown threat.
Sample: `docs/samples/threat_summary.json`.

### `GET /api/alerts/{id}/evidence`

Returns `{alert_id, items: [SecurityEvent], limit: 100, truncated: boolean}`. Original normalized
Shadow Watch envelopes and findings are preserved in event additions (`normalized_event`,
`shadow_findings`). Legacy event fields remain unchanged. Requires simulated incident scope in
demo mode or an authenticated tools factory outside it. Unknown alert: 404; scope denial: 403.
The frontend uses these stored events rather than matching IDs to bundled fixtures.

## Existing Member 2 endpoints

Base URL `http://localhost:8000` · interactive docs at `/docs` (OpenAPI at `/openapi.json`) · CORS allows `http://localhost:5173`.
Field names follow **`data/contracts.json`** (entity `threat`). Example responses (real output) are in `docs/samples/*.json`.

**Data honesty:** `null` means unknown or not checked. It never means 0 or false. `false` means "checked, and no".
All timestamps are ISO 8601 in UTC (`…Z`). `is_simulated: true` marks synthetic fixtures (`DEMO-VULN-*`).
Never show those as real CVEs.

```bash
cd backend
DEMO_MODE=true .venv/bin/python -m collectors.run_all   # offline: cache -> merge -> source_status -> SQLite (~7 s)
.venv/bin/python -m collectors.run_all --from-raw        # offline: re-parse backend/data/raw/* (after a schema change)
DEMO_MODE=true .venv/bin/uvicorn app.main:app --port 8000
.venv/bin/python -m ingestion.loader                     # (re)load DB only; idempotent
.venv/bin/python -m pytest tests -q
```
If the DB is empty, the server loads the cache on startup, so a fresh clone works with no network.
Without DEMO_MODE the server also runs the **feed scheduler** in-process (see *Scheduler* below). With `DEMO_MODE=true`
the scheduler is off: no network at all.

## Threat object (`ThreatItem`) — `data/contracts.json` v1.1 entity `threat`
`threat_id, cve_id, source, title, description, cvss, cvss_version, severity, epss, epss_percentile, kev_listed,
public_exploit, affected_configurations[] (+versions_text), references[], attack_techniques[], published_at,
nvd_published_at, kev_date_added, retrieved_at, raw_ref, raw_refs[], is_simulated, type, cve_ids[], tags[]`.
IOCs follow the contract entity `ioc`.

| Field | Meaning for the UI |
|---|---|
| `severity` | `critical/high/medium/low/none`, or `null` = not scored yet. Show "Unknown", not "None". |
| `kev_listed` | `true` = CISA says it's exploited in the wild (strongest "act now" badge). `null` = no CVE to check. |
| `epss` | 0–1 chance of exploitation in the next 30 days. Show as %. `null` = FIRST has no score. |
| `public_exploit` | Exploit code is public (Exploit-DB / GitHub PoC / Nuclei / CISA SSVC). `null` = not checkable. |
| `published_at` | Original publication: NVD's date for a CVE, the advisory / pulse / post date otherwise. |
| `kev_date_added` | `YYYY-MM-DD` CISA listed it in KEV. Not the publication date. `null` = not in KEV. |
| `raw_refs` | Every raw payload the record came from (KEV dump + NVD page...). `raw_ref` = `raw_refs[0]`. |
| `affected_configurations` | NVD version ranges. If all four bounds are `null`, the `cpe` version field is exact (`*` = all versions). |

---

### `GET /health`
Liveness check, whether we're running offline, and the scheduler's next runs (`null` in DEMO_MODE). Sample: `samples/health.json`
```json
{"status": "ok", "demo_mode": true, "threats": 19635, "time": "2026-10-31T11:54:32.883336Z", "scheduler": null}
// live mode: "scheduler": [{"id": "kev", "every_hours": 1.0, "next_run_time": "2026-10-31T14:02:00+00:00"}, ...]
```

### `GET /api/threats`
Paginated threat feed. **Newest arrival first** by default (`retrieved_at` desc, then `published_at` desc), so an
injected demo CVE shows at the top. Samples: `samples/threats.json`, `threats_filtered.json`,
`threats_simulated.json`, `threats_after_inject.json`.

| Param | Type | Example | Notes |
|---|---|---|---|
| `source` | csv | `kev,certin` | nvd, kev, nvd+kev, certin, otx, ransomware, threatfox, urlhaus, malwarebazaar, feodotracker, tor_exit, spamhaus_drop, openphish, vectra_synthetic |
| `severity` | csv | `critical,unknown` | `unknown` matches `severity = null`. Anything else → 422 |
| `kev` | bool | `true` | `false` = checked and not listed (`null` excluded) |
| `min_epss` | 0–1 | `0.5` | threats with `epss = null` are excluded |
| `q` | str ≥2 | `fortinet` | case-insensitive match on threat_id / title / description |
| `simulated` | bool | `false` | `true` = only `DEMO-VULN-*` fixtures |
| `sort` | `retrieved` \| `published` | `published` | `published` = newest publication first, nulls last |
| `page`, `page_size` | int | `1`, `50` | `page_size` ≤ 200 |

```json
{"items": [ThreatItem, ...], "total": 19643, "page": 1, "page_size": 50, "pages": 393}
```

### `GET /api/threats/{threat_id}`
Full record plus `raw_payloads[]`: one entry per `raw_refs` path, primary first (repo-relative path, sha256, size,
fetch time). IDs can contain `:` (e.g. `otx:…`, `ransomware:…`). Unknown ID → `404 {"detail": "..."}`.
Samples: `samples/threat_detail.json` (real KEV CVE), `threat_detail_simulated.json` (DEMO-VULN-003: nulls preserved).
```json
{ ...ThreatItem..., "raw_payloads": [
  {"id": 1, "source": "kev", "path": "backend/data/raw/kev/latest.json", "sha256": "72b7…", "size_bytes": 1472929, "fetched_at": "…"},
  {"id": 2, "source": "kev", "path": "backend/data/raw/nvd_kev/all_0.json", "sha256": "6e1d…", "size_bytes": 4096816, "fetched_at": "…"}]}
```

### `GET /api/source-status`
One row per collector, written by `collectors/run_all.py` on every run. Sample: `samples/source_status.json`
```json
[{"source": "kev", "status": "cache", "last_attempt": "…", "last_success": "…", "age_minutes": 6, "error": null, "record_count": 1766}]
```
`status`: `ok` (live fetch worked) · `cache` (DEMO_MODE, serving cached data) · `stale` (live fetch failed, using the old cache) ·
`failed` (no data) · `skipped` (e.g. no API key). `last_success` = when the data we hold was actually fetched.
`last_attempt` = the last live try. A failed run never clears `last_success`.

### `GET /api/overview`
Dashboard KPIs in one call. Sample: `samples/overview.json`
```json
{"threats_total": 19643, "threats_by_source": {"nvd": 17269, "kev": 1766, ...},
 "threats_by_severity": {"critical": 2109, "high": 7310, "medium": 6908, "low": 727, "none": 2, "unknown": 2587},
 "kev_count": 1846, "high_epss_count": 970, "high_epss_threshold": 0.5, "public_exploit_count": 1716,
 "simulated_count": 3, "ioc_count": 27406, "iocs_by_type": {"ip": 4770, "cidr": 1756, ...},
 "sources": [SourceStatus, ...], "newest_retrieved_at": "…",
 "matched_assets": 0, "open_alerts": 0, "trend": [], "notes": ["Counts reflect active incidents."]}
```
`kev_count` counts every threat with `kev_listed: true`, including CERT-In advisories that mention a KEV CVE, so it
is larger than `threats_by_source.kev`. `matched_assets` counts distinct assets with active
vulnerability alerts; `open_alerts` counts all active incidents. `trend` adds publication-date
counts (`{date,count}`), ordered by day for the last 14 days, excluding undated records.
The snippet illustrates the shape; `samples/overview.json` contains a captured response.
Threat listing also accepts `relevant=true` to filter to threats behind active asset alerts.

### `POST /api/demo/inject-cve`
Demo trigger for Scenario A ("a new advisory just arrived"). Body: `{"fixture_id": "CVE-2024-21762"}`.
- Only accepts IDs from **`data/demo_cves.json`** (real KEV CVEs: `CVE-2024-21762`, `CVE-2024-4577`, `CVE-2023-22515`) and
  **`data/threats_synthetic.json`** (`DEMO-VULN-001..003`). Anything else → **400**, with the allowed list. Missing body → 422.
- Upserts the fixture record (no duplicate) with `retrieved_at = now`, so it tops `GET /api/threats`.
  Real CVEs keep `is_simulated: false` and `source: "nvd+kev"`. Synthetic ones are always `is_simulated: true`.
- Records **one labelled early-warning signal** (`is_simulated: true`, `details.replay: true`), so the inject shows on
  *Early warnings*: `new_kev` if the record is KEV-listed (all three demo CVEs), else `new_critical_cve` if CVSS ≥ 9.0
  (`DEMO-VULN-001`). If neither fact is true (`DEMO-VULN-002/003`) no signal is invented: `signal: null` + `signal_note`.
  The id is deterministic, so injecting again refreshes `detected_at` instead of adding a second signal.
- Then calls `app/hooks.py:on_new_threat(threat_id, "demo_inject")`: Member 3 matches, scores and creates alerts.

Samples: `samples/inject_cve.json`, `inject_cve_synthetic.json`, `inject_cve_rejected.json`
```json
{"injected": ThreatItem, "fixture_file": "data/demo_cves.json", "hook_called": "on_new_threat",
 "signal": SignalOut | null, "signal_note": null | "why no signal"}
```
To reset the demo: `POST /api/demo/reset` (feed data + simulated signals) and `POST /api/demo/reset-alerts`.

---

## Early-warning signals (`ingestion/changes.py`)
Every ingest (scheduled job, manual `run_all`) diffs the new data against the DB as it was and stores a
**ThreatSignal** (contracts.json `threat_signal`) per change:

| `signal_type` | Fires when | `old_value → new_value` | `source` |
|---|---|---|---|
| `new_kev` | a CVE is newly KEV-listed | `false`/`null` → `true` | kev |
| `epss_jump` | EPSS rose by ≥ 0.2 (absolute), or crossed 0.5 upwards. `null` before or after never counts. | old → new score | epss |
| `new_public_exploit` | a new Exploit-DB entry, or a GitHub PoC that **passes the quality filter**, appears | `null` → `{source, date / repo}` | exploitdb · github_poc |
| `new_certin_advisory` | a new CERT-In advisory or vulnerability note. `details.cve_ids` = the CVEs it mentions, `details.kev_cves` = those in KEV | `null` → advisory id | certin |
| `new_critical_cve` | a CVE published in the last 14 days gets CVSS ≥ 9.0 (new, or newly scored) | old → new CVSS | nvd |

Thresholds are in one config (`changes.SIGNALS`), echoed by `/api/signals/summary`.
- **Idempotent:** `signal_id` = a hash of (threat_id, type, old, new). Re-running an ingest, or the same change happening
  again, never creates a second signal.
- **Baseline:** the very first load into an empty DB is a baseline with no signals (no flood of "new" KEV entries).
- Demo signals (`simulate-signal`, `inject-cve`, `seed`) are `is_simulated: true` with `details.simulated: true`.
  Inject/seed signals also carry `details.replay: true`: they replay a fact the record already has.

### `GET /api/signals?since=&type=&simulated=&limit=50`
Newest first. **The frontend polls this:** keep the response's `newest_detected_at`, then call
`?since=<that>` to get only newer signals. `type` = csv of the types above (anything else → 422). `limit` ≤ 500.
Sample: `samples/signals.json`
```json
{"items": [{"signal_id": "sig-…", "threat_id": "CVE-2024-21762", "signal_type": "epss_jump", "old_value": 0.49, "new_value": 0.84,
            "detected_at": "…", "source": "epss", "details": {"delta": 0.35, "crossed": true}, "is_simulated": false,
            "threat_title": "CVE-2024-21762: Fortinet FortiOS …", "severity": "critical", "kev_listed": true}],
 "count": 1, "newest_detected_at": "…"}
```

### `GET /api/signals/summary`
Counts by type for the last 24 h and 7 days (dashboard tiles). Sample: `samples/signals_summary.json`
```json
{"last_24h": {"new_kev": 1, "epss_jump": 3, "new_public_exploit": 0, "new_certin_advisory": 2, "new_critical_cve": 5},
 "last_7d": {...}, "total": 11, "simulated_last_24h": 0, "latest_detected_at": "…",
 "thresholds": {"epss_jump_abs": 0.2, "epss_cross": 0.5, "critical_cvss": 9.0, "critical_max_age_days": 14}}
```

### `POST /api/demo/simulate-signal`
Body: `{"fixture_id": "DEMO-VULN-001", "signal_type": "epss_jump"}`. Same allowlist as `inject-cve` (a non-allowlisted
fixture → 400; an unknown `signal_type` → 422). It creates a realistic signal, stores it, fires
`on_new_threat(threat_id, signal_type)`, and returns the signal (same shape as `/api/signals` items).
- **Real KEV fixtures are never altered.** The signal ends at their real current value (e.g. EPSS 0.49 → real 0.84).
- **Synthetic `DEMO-VULN-*` rows are updated to match the signal**, so the dashboard stays consistent: EPSS → 0.62,
  `kev_listed` → true, `public_exploit` → true, or CVSS → 9.1 for `new_critical_cve`.
- Every press creates a new signal (demo signals are salted with their time).
Samples: `samples/simulate_signal.json`, `samples/simulate_signal_real.json`.

### `POST /api/demo/seed` (prepare the demo)
Fills *Early warnings* on a cold start. **DEMO_MODE only** (403 otherwise). Idempotent: the same 5 `signal_id`s
every call (re-running refreshes `detected_at`). Re-seed after `/api/demo/reset`, which deletes simulated signals.
Every signal replays a fact the record really has, and nothing is invented (no made-up EPSS jump):
`new_kev` + `new_public_exploit` on CVE-2024-4577 and CVE-2023-22515, `new_critical_cve` on DEMO-VULN-001.
It does **not** fire `on_new_threat`, so no alerts are created and incidents still start empty.
CVE-2024-21762 is left out on purpose: the live inject provides it. Offline equivalent: `scripts/seed_demo.py`.
Sample: `samples/demo_seed.json`
```json
{"seeded": [SignalOut, ...], "skipped": [], "note": "Simulated replays of real record facts ..."}
```

### `POST /api/demo/reset`
Restores Member 2's data to the cached baseline. It deletes every simulated signal and reloads threats and IOCs from
the cache, which undoes `inject-cve` and `simulate-signal` edits. Real signals and **other members' tables are untouched**.
Sample: `samples/demo_reset.json`
```json
{"deleted_simulated_signals": 3, "before": {"threats": 19635, "threat_signals": 14, ...}, "after": {"threats": 19635, "threat_signals": 11, ...}}
```

## Scheduler (`ingestion/scheduler.py`)
APScheduler runs in-process, started by the FastAPI lifespan. It is **never started when `DEMO_MODE=true`**.
Each job fetches only its own sources, re-merges the rest from cache, reloads the DB and runs change detection.
Every run updates `source_status`.

| Job | Every | Fetches live |
|---|---|---|
| kev | 1 h | KEV catalogue + NVD records for newly added KEV CVEs + EPSS history / PoC quality for the backtest |
| nvd | 2 h | **incremental only**: `lastModStartDate` = last success − 1 h (NVD indexing lag). Never the full window |
| epss | 24 h | EPSS scores + exploit signals (Exploit-DB, PoC-in-GitHub, Nuclei, Vulnrichment) + PoC quality for new PoCs |
| certin | 6 h | CERT-In advisories + vulnerability notes |
| abusech | 1 h | ThreatFox / URLhaus / MalwareBazaar / Feodo |

- **First runs:** each job's first run is at its last success + interval, so a restart doesn't refetch fresh data.
  First runs are staggered by 2 minutes.
- **One run at a time:** a global lock stops jobs (and `/api/demo/reset`) from interleaving writes to the caches and the DB.
- **The full 30-day NVD fetch only happens on a manual** `python -m collectors.run_all`.

## For Member 3: `on_new_threat(threat_id, signal_type)`
`backend/app/hooks.py` is yours to implement:
```python
def on_new_threat(threat_id: str, signal_type: str) -> None: ...
```
- **When it fires:** once per **new** signal, **after** the signal and the threat are committed, so you can read both
  from the DB. A replayed change doesn't fire it again, because the signal already exists. It never fires on the
  baseline load or on `/api/demo/reset`.
- **`signal_type`:** one of the five types above, or `demo_inject` (from `POST /api/demo/inject-cve`, which also stores one labelled signal but fires the hook
  only once, as `demo_inject`).
- **`threat_id`:** a row in `threats`. For `new_certin_advisory` it's the advisory, and its CVEs are in `threats.cve_ids`
  and `signal.details.cve_ids`. Match each CVE's own record.
- **To read the signal:** `SELECT * FROM threat_signals WHERE threat_id=? AND signal_type=? ORDER BY detected_at DESC LIMIT 1`.
- **Where it runs:** in the scheduler thread (live ingest) or in the request thread (demo endpoints). Keep it fast
  (match, score, insert alert). Exceptions are logged and swallowed, so a hook bug never breaks ingestion. Still,
  don't rely on that.
- **Suggested handling:** `new_kev` / `epss_jump` / `new_public_exploit` → re-score existing alerts on matched assets.
  `new_critical_cve` / `demo_inject` / `new_certin_advisory` → match against assets and create alerts.

---

## Insights & export (`backend/app/insights.py`)

### `GET /api/insights/lead-time?days=90`
Backtest: of the CVEs CISA added to KEV in the last `days` days (1–180), how many did our signals flag **before**
the KEV date, and how early? Sample: `samples/lead_time.json`
- **Signals** (only those dated strictly before `kev_date_added` count, so there's no look-ahead):
  `epss` (historical EPSS ≥ threshold, sampled at fixed offsets before the KEV date) · `exploitdb` (earliest exploit
  `date_published`) · `github_poc` (earliest PoC repo `created_at` that passes the **PoC quality filter**: the repo has at least one
  non-README code file in its git tree, and was created no earlier than the CVE's NVD date minus 30 days. Older repos
  are reused or renamed, not early PoCs.) · `certin` (earliest CERT-In advisory mentioning the CVE).
- `flagged_at` = earliest signal. `lead_days = kev_date_added − flagged_at`. Median and p75 are over flagged CVEs.
- **Use `cohorts.new_cves` for the early-warning claim.** `old_cves` (CVEs published > 365 days before their KEV date)
  get huge lead days from years-old exploits. That's real, but it isn't an early warning.
- All thresholds are in one config (`collectors/history.py: LEAD_TIME`), echoed back as `config`.
  `methodology[]` and `limitations[]` are included in every response, so show them in the UI.
```json
{"window_days": 90, "as_of": "2026-10-31", "population": 110, "flagged_before_kev": 43, ...,
 "cohorts": {"new_cves": {"population": 97, "flagged_before_kev": 32, "pct_flagged_before_kev": 33.0, "median_lead_days": 13.0, "p75_lead_days": 64.0},
             "old_cves": {...}, "unknown_age": {...}},
 "per_signal": {"github_poc": {"fired_before_kev": 40, "earliest_signal": 37, "data_available": 84}, "epss": {...}, ...},
 "config": {"epss_threshold": 0.1, "epss_offsets_days": [1,3,7,14,30,60,90], ...}, "methodology": [...], "limitations": [...],
 "rows": [{"cve_id": "CVE-…", "title": "…", "kev_date_added": "2026-09-18", "published_at": "…", "flagged_at": "2025-11-13",
           "lead_days": 309, "first_signal": "github_poc", "cve_age_at_kev_days": 340, "cohort": "new_cves",
           "signals": {"epss": {"date": "…", "detail": "epss=0.231"} | null, "exploitdb": null, "github_poc": {"date": "…"}, "certin": null}}]}
```
The data comes from `epss_history.json` and `github_poc_quality.json` (collected by `collectors/history.py` during `run_all`,
incrementally) plus `exploit_signals.json` (`exploitdb_date`). Fully offline in DEMO_MODE. `days` > 180 → 422.

### `GET /api/insights/india?limit=10`
India-first panel. Sample: `samples/india.json`
- `certin_advisories[]`: latest CERT-In advisories and vulnerability notes (full ThreatItems, `references` = cert-in.org.in page).
- `ransomware_victims_total`, `ransomware_by_sector`, `ransomware_by_group`, and `ransomware_groups[]`, which groups
  victims by sector and gang (largest first). Each victim has `references` pointing to ransomware.live, **never the leak site**.
- `otx_pulses[]`: OTX campaigns whose tag or targeted country is exactly *India*, or whose title says India.
  "British Indian Ocean Territory" does not count.

### `GET /api/export/stix?threat_id=…` or `?ids=a,b,c`
A STIX 2.1 bundle (`application/stix+json;version=2.1`) built with the `stix2` library, for SIEMs, TAXII or other CERTs.
Samples: `samples/stix_cve.json`, `samples/stix_bundle.json`.
- `identity` **Vectra** is the `created_by_ref` of every object. Everything is marked TLP:WHITE.
- `vulnerability` gets an `external_references` entry `{"source_name": "cve", "external_id": "CVE-…"}`. Synthetic `DEMO-VULN-*`
  threats get **no** CVE ref and `labels: ["simulated"]`. Advisories become a `report` plus a `vulnerability` per CVE.
  Campaigns and IOC batches become a `campaign` that `targets` its vulnerabilities.
- `attack-pattern` per ATT&CK technique (mitre-attack ref) → `targets` the vulnerability / is `used` by the campaign.
- `indicator` per linked IOC (STIX pattern, `valid_from` = first_seen), with `indicates` a campaign or `related-to`
  otherwise. Capped at 1000 per threat, and a `note` says when output was truncated.
- IDs are deterministic (UUIDv5), so re-exporting gives the same objects and a SIEM dedupes them.
- No ID → 400. More than 50 IDs → 400. Any unknown ID → 404.
- Validated in tests with the official `stix2-validator` (pinned to 3.2.0: the 3.3.1 wheel ships without its schemas).

---

# Member 3 endpoints (assets, matching, scoring, alerts)
Models: `backend/app/contracts.py` (`Asset`, `ThreatRecord` = Member 2's `ThreatItem` + matcher hints, `SecurityEvent`, `IncidentAlert`).

### `GET /api/assets`
JSON array of assets (contract entity `asset`). Sample: `samples/assets.json`.

| Param | Type | Meaning |
|---|---|---|
| `sector` | `power` \| `banking` \| `govt` \| `health` \| `telecom` \| `water` | Only this sector |
| `criticality` | int 1–5 | Exact criticality |
| `min_criticality` | int 1–5 | Criticality ≥ this |
| `internet_facing` | bool | Only exposed / only internal |

Invalid values → 422. `software[].version: null` = version unknown (any match on it needs manual review).

### `GET /api/assets/{asset_id}`
One asset, or 404. Sample: `samples/asset_PWR-FW-01.json`.

### Alert object (`IncidentAlert`)
JSON Schema: `samples/incident_alert.schema.json`. Every contract `alert` field, plus these Member 3 additions:

| Field | Meaning |
|---|---|
| `title` | Human-readable headline |
| `lifecycle_status` | `detected → investigating → confirmed → action_required → mitigated → closed`. Contract `status` is derived from it: detected=`new`, the middle three=`ack`, mitigated/closed=`resolved`. |
| `match_detail` | `confirmed_affected` \| `confirmed_unaffected` \| `needs_verification` \| `no_cve_behavioural`. It is the detailed form of contract `match_status`. |
| `vulnerability_priority_score`, `behavioural_suspicion_score`, `evidence_confidence_score` | Three separate 0–100 scores, never merged into one |
| `score_factors` | Breakdown of each score's inputs and weights, for display |
| `escalation_reasons` | Audit trail explaining the priority |
| `is_simulated` | True when built on synthetic data |
| `related_alert_ids` | Behaviour incidents on OTHER assets that share an exact outbound `dest_ip` (linked, never merged) |
| `indicators.dest_ips` | Suspicious outbound destinations seen in a behaviour incident |
| `suppressed` | `true` = maintenance context kept this incident from escalating |

**`timeline`** is always chronological. It mixes sensor events (`ref` = event_id, sensor's own UTC offset) and audit
entries (detected, re-scored, duplicate received, suppressed, merged, status changes; `Z` times). Sort by parsed time, not by string.

### `GET /api/alerts`
Most urgent first (priority, then latest update). `{"items": [IncidentAlert, ...], "total": n}`. Sample: `samples/alerts.json`.

| Param | Values |
|---|---|
| `priority` | `low` \| `medium` \| `high` \| `critical` |
| `status` | contract `new`/`ack`/`resolved` **or** a `lifecycle_status` value |
| `sector` | any asset sector |
| `match_status` | contract `confirmed`/`uncertain`/`requires_manual_review` **or** a `match_detail` value (e.g. `no_cve_behavioural`) |
| `kind` | `vulnerability` \| `behaviour` |
| `asset_id` | alerts involving this asset |

### `GET /api/alerts/{alert_id}`
The alert, plus `assets[]` (full asset records) and `threats[]` (summary from the threats table, `in_database: false` if
it isn't loaded). 404 if unknown. Samples: `alert_detail_vulnerability.json` (Scenario A), `alert_detail_behaviour.json`
(Scenario B), `alert_detail_maintenance.json` (Scenario C).

### `POST /api/alerts/{alert_id}/acknowledge`
Body (all optional): `{"status": "<lifecycle_status>", "reason": "patch scheduled", "by": "soc-analyst"}`. No `status` =
advance one step. Lifecycle only moves forward: going backwards gives **409**, an unknown alert gives **404**. It adds a timeline entry
with who, when and why. Re-scores never reset an analyst's progress. Sample: `samples/acknowledge.json`.

### `POST /api/correlate/threat` (Member 2 → Member 3)
Body: one threat (contract `threat`). Matches it against all 40 assets, scores each exposed one, and creates or updates one
alert per (threat, asset). Sending it again updates the alert and never duplicates it. Sample: `samples/correlate_threat.json`.
```json
{"threat_id": "CVE-2024-21762", "assets_checked": 40, "created": ["ALR-…"], "updated": [],
 "matches": [{"asset_id": "PWR-FW-01", "match_detail": "confirmed_affected", "match_status": "confirmed",
              "reason": "installed 7.2.6 is inside the vulnerable range (>= 7.2.0, < 7.2.7)", "alert_id": "ALR-…",
              "priority": "critical", "risk_score": 99.4}]}
```
`on_new_threat` (hooks.py) does the same automatically for every new signal and for `POST /api/demo/inject-cve`.

### `POST /api/correlate/events` (Member 4 → Member 3)
Body: a JSON **array** of events (contract `event`; optional additions `rule_id`, `confidence`: low/medium/high).
- Events with the same `event_id` are deduplicated (`duplicates[]`).
- Events on one asset that are ≤15 min apart (chained) form one incident. Arrival order doesn't matter.
- Different assets are never merged.
- A maintenance window covering the activity suppresses noisy HTTP/auth signals. It never suppresses a shell or a new
  outbound connection.
- Events with `asset_id: null` become their own alert (`unattributed[]`), capped at medium.

Response: `{"received", "duplicates", "created", "updated", "merged", "unattributed", "incidents": [IncidentAlert]}`.
Sample: `samples/correlate_events.json`.

### `POST /api/demo/reset-alerts`
Deletes all alerts and ingested events. Member 2's `/api/demo/reset` leaves our tables alone, so a full demo reset
calls both.

### `GET /api/sectors/posture` (heatmap)
Per-sector exposure built from the synthetic inventory plus every **active** alert (`status != resolved`). Sorted by
`weighted_sector_risk_score`, highest first. **Always show the `data_classification` label in the UI.** Sample: `samples/sectors_posture.json`.
```json
{"data_classification": "Simulated Sector Exposure (Synthetic Asset Inventory)", "is_simulated": true, "formula": "…",
 "sectors": [{"sector": "power", "label": "Power/Energy", "total_assets": 7, "confirmed_affected_assets": 2,
   "needs_verification_assets": 0, "active_incidents": 2, "active_critical_high_incidents": 2,
   "max_asset_priority_score": 99.4, "weighted_sector_risk_score": 29.2, "top_threat_ids": ["CVE-2024-21762", "DEMO-VULN-001"]}]}
```
`weighted_sector_risk_score` = Σ(criticality × the asset's worst active `risk_score`) / Σ criticality, over all assets in the
sector. Assets with no active alert count as 0.

### `POST /api/simulation/patch-impact` (what-if)
Body: `{"threat_id": "CVE-2024-21762", "patched_version": "7.4.11"}`. Add `"asset_ids": [...]` to limit which assets
are simulated. If you send only `asset_ids`, it simulates the threats behind their open vulnerability alerts. It copies the assets
in memory, upgrades every package the threat targets, and re-runs the **real** matcher and scorer. **Nothing live
changes.** Sample: `samples/patch_impact.json`.
```json
{"before_affected_count": 2, "after_affected_count": 0, "before_aggregate_exposure_score": 198.8,
 "after_aggregate_exposure_score": 0.0, "modelled_exposure_reduction_pct": 100.0,
 "transitions": [{"asset_id": "PWR-FW-01", "summary": "PWR-FW-01: confirmed_affected (score 99.4) -> confirmed_unaffected (score 0)",
                  "before": {...}, "after": {...}, "changed_software": ["fortinet/fortios 7.2.6 -> 7.4.11"]}],
 "notes": []}
```
A version that is still vulnerable stays affected and gets a note. A non-standard version (`7.4.11-custombuild`) becomes
`needs_verification` and keeps a non-zero score: we never claim a patch is safe without proof. Errors: neither target given → 422,
unknown threat or asset → 404, assets with no open alerts and no `threat_id` → 400. Threats come from the DB, falling back to the
demo fixture files.

## Member 3: Attack Lab (attack simulation + detection)

Simulates simple attacks as the raw log lines a real server would write, detects them **from the text alone**
(the detector is never told which attack ran), names the attack type with MITRE ATT&CK, and feeds what fired into
the correlation engine as a normal behaviour incident. Dashboard: `/app/attack-lab`. Code: `backend/app/attack_lab.py`
(playbooks + API), `backend/app/detection.py` (parsers, rules, verdict).

| Method | Path | What |
|---|---|---|
| GET | `/api/attack-lab/playbooks` | Attacks we can simulate: `brute_force`, `sql_injection`, `port_scan`, `command_injection`, `normal_traffic` (control: must not fire) |
| GET | `/api/attack-lab/rules` | The rulebook: every rule's exact logic, threshold, reason it works, MITRE technique; SQLi/CMDi signature regexes |
| POST | `/api/attack-lab/run` | `{scenario, target_asset_id?, succeed?}` → steps, raw lines, detections, verdict, events sent, incident. **DEMO_MODE only** (403 otherwise) |
| POST | `/api/attack-lab/analyze` | `{lines: [...]}` → same detection on any pasted log lines / URLs. Stateless, nothing stored |

Pipeline: **parse** (web access, sshd auth, firewall, process audit, conntrack; anything else is checked as raw request
text) → **per-line signatures** (SQLi, command injection, traversal, XSS on the URL-decoded request) → **per-source
thresholds** (10+ failed logins / 60s, 15+ ports / 60s) → **sequence rules** (login success after failures; injected
request returning 5x a normal page; web server → shell; outbound to attacker-named IP) → **verdict** (attack type,
stage recon/attempt/compromise, confidence, decision path).

| Rule | Detects | Signal → score |
|---|---|---|
| AUTH-BF-001 | brute force / password spraying (T1110) | `brute_force` 0.6 |
| AUTH-BF-002 | success after brute force (T1078) | `credential_compromise` 0.95 |
| NET-SCAN-001 | port scan (T1046) | `port_scan` 0.45 |
| WEB-SQLI-001 | SQL injection (T1190) | `sql_injection` 0.75 |
| WEB-SQLI-002 | injected query returned data (T1213) | `data_exposure` 0.95 |
| WEB-CMDI-001 | command injection (T1190) | `command_injection` 0.85 |
| WEB-TRAV-001 / WEB-XSS-001 | path traversal / XSS | `http_anomaly` 0.5 |
| HOST-PROC-001 | web server spawned a shell (T1059.004) | `unexpected_process` 0.8 |
| NET-C2-001 | reverse-shell outbound (T1095) | `outbound_connection` 0.7 |

Each fired rule becomes one `SecurityEvent` (`rule_id`, `confidence`, `details.attack_signal/attack_label/
detection_reason/mitre/src_ip`). Behaviour alerts built from them get a title naming the attack
(e.g. `SQL injection + SQL injection: data extracted on netbanking-web (BNK-NET-01)`), plus
`attack_classification` and `indicators.src_ips`. Re-running on the same asset within 15 minutes joins the open
incident (`correlation.note` says so); `POST /api/demo/reset-alerts` starts clean.

Expected results: brute force → medium (blocked) / critical (password guessed); SQL injection → high / critical (data
extracted); port scan → medium; command injection → high / critical (shell + call-home); normal traffic → no incident.

# Emerging campaigns (`backend/app/campaigns.py`, contract v1.3 entity `campaign`)

Relationships between threats (PS objective 2). Scope: threats published in the last 30 days **of
the data** (anchored to the newest `published_at`, so an offline cache gives the same answer every
day) plus every KEV entry, OTX pulse, CERT-In advisory and ransomware record. Plain NVD CVEs count
only with activity (KEV, public exploit, EPSS ≥ 0.1) or when another in-scope item names them.

Links, applied strongest first: shared CVE > shared IOC value > shared vendor+product > shared
ATT&CK technique > TF-IDF cosine of title+description ≥ `tfidf_threshold`. Keys held by more than
`max_key_members` (techniques: `max_technique_members`) threats are generic (T1190, "microsoft
windows") and ignored (`meta.skipped_generic_keys`). Single-linkage with a size cap
(`max_campaign_size`): a link that would grow a group past it is not applied, so boilerplate text
can't chain thousands of advisories together. Campaigns = groups with ≥ `min_size` members.
`is_emerging`: ≥ `emerging_min_new` members in the last 7 days and ≥ `emerging_growth` × the
previous 7 days. Every threshold is in `CONFIG` (echoed as `config`). Deterministic; cached in
`backend/data/cache/campaigns.json` with a fingerprint of the in-scope data; recomputed at
startup (background) and after every ingest (`collectors/run_all.py`) only when that data changed.
Shared IOC links exist in the rule but the current cache has no IOC value in two threats.

### `GET /api/campaigns?emerging=true|false&limit=50`

`{as_of, config, meta: {threats_in_scope, links_by_type, skipped_generic_keys[], method},
total, emerging_total, items: [campaign]}`; campaign = `campaign_id`, `title`, `size`,
`threat_ids[]`, `sources{}`, `link_reasons[]` (`{type, key, count, text}` e.g. "17 share fortinet
fortios"), `first_seen`, `last_seen`, `growth_7d {last_7d, prev_7d, ratio}`, `is_emerging`,
`kev_listed_members`, `affected_asset_ids[]`/`affected_asset_count` (Member 3's matcher,
read-only), `top_recommended_action`, `is_simulated`. Emerging first, then most exposed assets.
Sample: `docs/samples/campaigns.json`.

### `GET /api/campaigns/{campaign_id}`

The campaign + `members[]`: `{threat_id, title, source, type, severity, cvss, kev_listed,
published_at, is_simulated, shared_keys[]}` (`shared_keys` = this member's keys among the
campaign's link reasons; empty = grouped by text similarity). 404 unknown.
Sample: `docs/samples/campaign_detail.json`. `GET /api/threats/{id}` now also returns
`campaign_ids[]` (additive).

# CERT-In Incident Report Assistant (`backend/app/certin_draft.py`)

### `POST /api/alerts/{alert_id}/certin-draft?format=json|markdown&lang=en|hi`

No body. A **draft for analyst review; never sent** (`sent: false`, `status:
"draft_for_analyst_review"`). Fields: `reportability_assessment` ("vulnerability exposure only —
not by itself a reportable incident" for vulnerability alerts; "potential security incident —
analyst must determine reportability" for behaviour alerts), `suggested_category` +
`category_candidates[]` (`{number, category, reason, status: "analyst to confirm"}`, from the CERT-In
Directions of 28 April 2022, Annexure I; `category_source`), `time_of_detection` (alert
`created_at`), `incident_description`, `affected_assets[]`, `observed_evidence[]` (stored event IDs),
`related_threats[]`, `actions_taken_so_far[]` (lifecycle changes from the alert timeline),
`recommended_next_actions[]`, `missing_information[]`, `contact` (placeholders), `disclaimer`
(the 6-hour obligation applies only to reportable incident types), `markdown`, `generated_at`, plus
`generated_by`/`validation`/`fallback_reason`. An LLM may reword only `incident_description` and
`recommended_next_actions` (grounding rules above). `format=markdown` returns `text/markdown` with
`Content-Disposition: attachment; filename="certin-draft-<id>.md"`. Demo mode: simulated alerts
only (403 otherwise); outside demo mode the authenticated incident factory must allow it.
404 unknown alert. Samples: `docs/samples/certin_draft_vulnerability.json`,
`docs/samples/certin_draft_behaviour.json`.

# Remediation targets (organisation policy)

Every alert (`GET /api/alerts`, `GET /api/alerts/{id}`) now also carries, computed on read
(additive, contract v1.3 `alert`): `remediation_target_at` (`created_at` + days for the priority),
`remediation_target_days`, `overdue` (past the target and lifecycle not `mitigated`/`closed`) and
`remediation_policy: "organisation-defined policy, not a regulatory deadline"`. Defaults in
`backend/app/scoring.py` `CONFIG.remediation_targets_days`: critical 7, high 14, medium 30, low 90.

### `GET /api/insights/lead-time/examples?days=90`

Three CVEs from the lead-time backtest (new-CVE cohort when possible): `largest_lead`,
`near_zero_lead` and `miss`. Each: `cve_id`, `title`, `cohort`, `kev_date_added`, `flagged_at`,
`lead_days`, `first_signal`, `explanation`, `timeline[]` = `{date, event, detail, signal,
before_kev, days_before_kev}` for NVD publication, EPSS crossing 0.1 and 0.5 (first day, from the
EPSS history cache), first quality GitHub PoC (flagged when not counted), Exploit-DB entry, CERT-In
advisory, and the KEV addition. Same numbers as the backtest row. Sample:
`docs/samples/lead_time_examples.json`.
