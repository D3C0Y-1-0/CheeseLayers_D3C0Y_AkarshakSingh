# NETRA-X API: Member 2 endpoints (feeds, health, demo, insights, STIX export)

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
Liveness check, plus whether we're running offline. Sample: `samples/health.json`
```json
{"status": "ok", "demo_mode": true, "threats": 19643, "time": "2026-10-31T11:54:32.883336Z"}
```

### `GET /api/threats`
Paginated threat feed. **Newest arrival first** by default (`retrieved_at` desc, then `published_at` desc), so an
injected demo CVE shows at the top. Samples: `samples/threats.json`, `threats_filtered.json`,
`threats_simulated.json`, `threats_after_inject.json`.

| Param | Type | Example | Notes |
|---|---|---|---|
| `source` | csv | `kev,certin` | nvd, kev, nvd+kev, certin, otx, ransomware, threatfox, urlhaus, malwarebazaar, feodotracker, tor_exit, spamhaus_drop, openphish, netrax_synthetic |
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
 "matched_assets": null, "open_alerts": null, "notes": ["… null until Member 3 …"]}
```
`kev_count` counts every threat with `kev_listed: true`, including CERT-In advisories that mention a KEV CVE, so it
is larger than `threats_by_source.kev`. **`matched_assets` / `open_alerts` are `null` (TODO Member 3).**

### `POST /api/demo/inject-cve`
Demo trigger for Scenario A ("a new advisory just arrived"). Body: `{"fixture_id": "CVE-2024-21762"}`.
- Only accepts IDs from **`data/demo_cves.json`** (real KEV CVEs: `CVE-2024-21762`, `CVE-2024-4577`, `CVE-2023-22515`) and
  **`data/threats_synthetic.json`** (`DEMO-VULN-001..003`). Anything else → **400**, with the allowed list. Missing body → 422.
- Upserts the fixture record (no duplicate) with `retrieved_at = now`, so it tops `GET /api/threats`.
  Real CVEs keep `is_simulated: false` and `source: "nvd+kev"`. Synthetic ones are always `is_simulated: true`.
- Then calls `app/hooks.py:on_new_threat(threat_id)`. It's a no-op for now; Member 3 adds matching, scoring and alerts there.

Samples: `samples/inject_cve.json`, `inject_cve_synthetic.json`, `inject_cve_rejected.json`
```json
{"injected": ThreatItem, "fixture_file": "data/demo_cves.json", "hook_called": "on_new_threat"}
```
To reset the demo, run `python -m ingestion.loader`. That restores the cached versions and timestamps.

---

## Insights & export (`backend/app/insights.py`)

### `GET /api/insights/lead-time?days=90`
Backtest: of the CVEs CISA added to KEV in the last `days` days (1–180), how many did our signals flag **before**
the KEV date, and how early? Sample: `samples/lead_time.json`
- **Signals** (only those dated strictly before `kev_date_added` count, so there's no look-ahead):
  `epss` (historical EPSS ≥ threshold, sampled at fixed offsets before the KEV date) · `exploitdb` (earliest exploit
  `date_published`) · `github_poc` (earliest PoC repo `created_at`. Repos older than the CVE's NVD date minus 30 days
  are ignored as reused repos) · `certin` (earliest CERT-In advisory mentioning the CVE).
- `flagged_at` = earliest signal. `lead_days = kev_date_added − flagged_at`. Median and p75 are over flagged CVEs.
- **Use `cohorts.new_cves` for the early-warning claim.** `old_cves` (CVEs published > 365 days before their KEV date)
  get huge lead days from years-old exploits. That's real, but it isn't an early warning.
- All thresholds are in one config (`collectors/history.py: LEAD_TIME`), echoed back as `config`.
  `methodology[]` and `limitations[]` are included in every response, so show them in the UI.
```json
{"window_days": 90, "as_of": "2026-10-31", "population": 110, "flagged_before_kev": 44, "pct_flagged_before_kev": 40.0,
 "median_lead_days": 32.5, "p75_lead_days": 309.0,
 "cohorts": {"new_cves": {"population": 97, "flagged_before_kev": 33, "pct_flagged_before_kev": 34.0, "median_lead_days": 9.0, "p75_lead_days": 55.0},
             "old_cves": {...}, "unknown_age": {...}},
 "per_signal": {"github_poc": {"fired_before_kev": 41, "earliest_signal": 39, "data_available": 84}, "epss": {...}, ...},
 "config": {"epss_threshold": 0.1, "epss_offsets_days": [1,3,7,14,30,60,90], ...}, "methodology": [...], "limitations": [...],
 "rows": [{"cve_id": "CVE-…", "title": "…", "kev_date_added": "2026-09-18", "published_at": "…", "flagged_at": "2025-11-13",
           "lead_days": 309, "first_signal": "github_poc", "cve_age_at_kev_days": 340, "cohort": "new_cves",
           "signals": {"epss": {"date": "…", "detail": "epss=0.231"} | null, "exploitdb": null, "github_poc": {"date": "…"}, "certin": null}}]}
```
The data comes from `epss_history.json` and `github_poc_dates.json` (collected by `collectors/history.py` during `run_all`,
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
- `identity` **NETRA-X** is the `created_by_ref` of every object. Everything is marked TLP:WHITE.
- `vulnerability` gets an `external_references` entry `{"source_name": "cve", "external_id": "CVE-…"}`. Synthetic `DEMO-VULN-*`
  threats get **no** CVE ref and `labels: ["simulated"]`. Advisories become a `report` plus a `vulnerability` per CVE.
  Campaigns and IOC batches become a `campaign` that `targets` its vulnerabilities.
- `attack-pattern` per ATT&CK technique (mitre-attack ref) → `targets` the vulnerability / is `used` by the campaign.
- `indicator` per linked IOC (STIX pattern, `valid_from` = first_seen), with `indicates` a campaign or `related-to`
  otherwise. Capped at 1000 per threat, and a `note` says when output was truncated.
- IDs are deterministic (UUIDv5), so re-exporting gives the same objects and a SIEM dedupes them.
- No ID → 400. More than 50 IDs → 400. Any unknown ID → 404.
- Validated in tests with the official `stix2-validator` (pinned to 3.2.0: the 3.3.1 wheel ships without its schemas).
