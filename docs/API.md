# NETRA-X API: Member 2 endpoints (feeds, health, demo)

Base URL `http://localhost:8000` · interactive docs at `/docs` (OpenAPI at `/openapi.json`) · CORS allows `http://localhost:5173`.
Field names follow **`data/contracts.json`** (entity `threat`). Example responses (real output) are in `docs/samples/*.json`.

**Data honesty:** `null` means unknown or not checked. It never means 0 or false. `false` means "checked, and no".
All timestamps are ISO 8601 in UTC (`…Z`). `is_simulated: true` marks synthetic fixtures (`DEMO-VULN-*`).
Never show those as real CVEs.

```bash
cd backend
DEMO_MODE=true .venv/bin/python -m collectors.run_all   # offline: cache -> merge -> source_status -> SQLite (~7 s)
DEMO_MODE=true .venv/bin/uvicorn app.main:app --port 8000
.venv/bin/python -m ingestion.loader                     # (re)load DB only; idempotent
.venv/bin/python -m pytest tests -q
```
If the DB is empty, the server loads the cache on startup, so a fresh clone works with no network.

## Threat object (`ThreatItem`)
Contract fields: `threat_id, cve_id, source, title, description, cvss, cvss_version, severity, epss, epss_percentile,
kev_listed, public_exploit, affected_configurations[], references[], attack_techniques[], published_at, retrieved_at,
raw_ref, is_simulated`.
Extras (ours, safe to ignore): `type` (`vulnerability|advisory|campaign|ioc_batch`), `cve_ids[]` (every CVE the threat
mentions; advisories have several and `cve_id: null`), `tags[]`, `affected_configurations[].versions_text`
(free-text range, CERT-In only).

| Field | Meaning for the UI |
|---|---|
| `severity` | `critical/high/medium/low/none`, or `null` = not scored yet. Show "Unknown", not "None". |
| `kev_listed` | `true` = CISA says it's exploited in the wild (strongest "act now" badge). `null` = no CVE to check. |
| `epss` | 0–1 chance of exploitation in the next 30 days. Show as %. `null` = FIRST has no score. |
| `public_exploit` | Exploit code is public (Exploit-DB / GitHub PoC / Nuclei / CISA SSVC). `null` = not checkable. |
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
Full record plus `raw_payload`, which references the raw file it was parsed from (repo-relative path, sha256, size,
fetch time). IDs can contain `:` (e.g. `otx:…`, `ransomware:…`). Unknown ID → `404 {"detail": "..."}`.
Samples: `samples/threat_detail.json` (real KEV CVE), `threat_detail_simulated.json` (DEMO-VULN-003: nulls preserved).
```json
{ ...ThreatItem..., "raw_payload": {"id": 1, "source": "kev", "path": "backend/data/raw/kev/latest.json",
  "sha256": "72b7…", "size_bytes": 1472929, "fetched_at": "2026-10-31T11:47:38Z"} }
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
