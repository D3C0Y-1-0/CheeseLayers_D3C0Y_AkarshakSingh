# Vectra

The integrated React dashboard and FastAPI backend: cached public intelligence, simulated asset
inventory, explainable scoring/correlation, Shadow Watch and grounded SOC investigation.

**Current status and explanation:** [docs/STATUS_REPORT.md](docs/STATUS_REPORT.md) covers what is
implemented, how each flow works, verification results and remaining work. Vectra is a local
prototype: public intelligence and historical attack traffic are real datasets; the organisation,
target assets and replayed incidents are simulated. A stopped local server does not serve the UI
until `scripts/start.ps1` is run.

## Run the complete demo (PowerShell, repository root)

For a double-click launch on Windows, open **Start Vectra.cmd**. It starts a background server,
waits for a successful health check, then opens the dashboard in your default browser. Errors keep
the launcher window open. Timestamped server logs and process metadata are stored in ignored `logs/`.

```powershell
uv venv .venv
uv pip install --python .venv/Scripts/python.exe -r backend/requirements.txt
Push-Location frontend
npm.cmd ci
Pop-Location
.\scripts\start.ps1
```

`start.ps1` uses `backend\.venv` if it works, else `.venv`. Open **http://127.0.0.1:8000/app**. The script builds React and serves it with the API from one
address in `DEMO_MODE=true`. Initial startup loads bundled caches into SQLite; wait for
"Application startup complete". Subsequent starts reuse the database. Use `-SkipBuild` for an
already built frontend or `-Port 8001` for another port. Your root `.env` stays private and ignored;
no key is needed. For frontend development run `npm.cmd run dev` in `frontend/` alongside the
backend, then open http://127.0.0.1:5173/app. Vite proxies API calls to port 8000.

The normal script runs in the foreground: leave that terminal open. To keep the server independent
of the terminal after an existing build:

```powershell
.\scripts\start.ps1 -SkipBuild -Background
# Stop this registered background server (including the Windows Python child process):
.\scripts\stop.ps1
```

Background mode reuses an already healthy Vectra server on the requested port. It waits up to
90 seconds for startup and reports the saved error log if the process exits. The stop helper
validates the recorded process identity before terminating its process tree; logs are retained.

Current persistence defaults to `backend/data/vectra.db` (`VECTRA_DB_URL` override). An older
`backend/data/netrax.db` is a different file: a new default database will load the cache but will
not automatically import its earlier incidents. Both database filenames and sidecars are ignored.

## Run the complete demo (macOS / Linux)

```bash
uv venv backend/.venv            # or: python3.12 -m venv backend/.venv
uv pip install --python backend/.venv/bin/python -r backend/requirements.txt
(cd frontend && npm ci)
./scripts/start.sh               # --skip-build to reuse frontend/dist, --port 8001 for another port
```

Open **http://127.0.0.1:8000/app**. Same behaviour as `start.ps1`: it uses `backend/.venv` (or
`.venv`), exports the scoring config, builds the frontend, sets `DEMO_MODE=true` and `PYTHONUTF8=1`
and binds 127.0.0.1 only. Cloud LLM text appears only if `.env` sets `LLM_ALLOW_CLOUD=true` and
`LLM_API_KEY`; otherwise the dashboard shows cached LLM reports or templates. Pre-fill the cache
before a demo with `backend/.venv/bin/python scripts/pregenerate_ai.py` (`--dry-run` to preview).
Verify on macOS: `backend/.venv/bin/python -m pytest backend/tests -q -p no:cacheprovider`.

## Connected features

- Command Center: real API counts, publication trend, source health, seven scenarios (three on real SecRepo logs),
  persisted incident links and a repeatable alert/event reset.
- Threat Intelligence: server pagination/search/filtering, asset relevance, source references,
  ATT&CK labels and STIX 2.1 export.
- Asset Inventory: simulated inventory and links to each asset's open incidents.
- Incidents: stored sensor evidence, three separate scores with inputs, lifecycle changes,
  investigation reports, visibility gaps and proposed actions.
- Early warnings: signal history, thresholds and explicitly synthetic signal simulation.
- Exposure & impact: sector posture, read-only patch what-if, lead-time analysis and cached
  CERT-In/India-related intelligence.
- Attack simulation: real attackers from SANS ISC honeypots/firewall sensors replayed against an asset; detection
  from log text, each exploited CVE linked to KEV/EPSS and our matcher, animated replay and threat-intel panel.
- Campaigns: TF-IDF + shared CVE/IOC grouping, patch batches separated, ranked by actionability.
- Security Operations: globe view of sector risk and attacker sources.
- AI assistance: grounded threat/incident narratives, cached model responses, best-effort Hindi
  translation and analyst-reviewed CERT-In draft generation. Drafts are never submitted.

The suspicious chain creates a persisted no-CVE incident. Benign maintenance retains all events
without escalation. Missing host telemetry remains a visibility gap. Replay/restart is idempotent;
demo alert reset also clears the preview cache so a scenario can be replayed after reset.

Shadow Watch stores normalized envelopes/findings in Member 3's existing event JSON. There is no
second database or score engine. Template reports work offline. The default scope permits
persisted simulated incidents in demo mode; real incidents require an authenticated scope factory.
Demo mode disables the feed scheduler. The cloud LLM (Groq) is used only when `.env` sets
`LLM_ALLOW_CLOUD=true` and a key (`LLM_API_KEY`, `GROQ_API_KEY` or `GROQ_API_KEY1..9`); otherwise cached
LLM reports or templates are shown. Investigation suggestions are read-only; explicitly approved
lab responses are executed and verified through the separate live controls.

The UI labels bundled fallback samples and never fakes successful mutations. Public intelligence
and synthetic activity remain distinct. Isolation Forest added false positives on the synthetic
fixture, so synthetic fixture scenarios stay rules-only; the historical model runs on the two SecRepo sensors as a
low-severity "needs review" signal (no ground-truth labels: outliers, not confirmed attacks). See [Member 4 runbook](README_MEMBER4.md),
[integration](docs/INTEGRATION.md), and [API contract](docs/API.md).

## Verify

Current full backend checkpoint: **347 passed, 10 skipped** (1 November 2026, 298.21 seconds).
Actual Apache and portal/ML HTTP rehearsals passed separately. See the latest
[status report](docs/STATUS_REPORT.md) for focused follow-up verification and remaining limits.

Initial review at `3c3f590` (1 November 2026): **315 backend tests passed, 10 skipped, no failures**.
TypeScript/Vite production build passed. Skips require missing historical raw payloads or optional
geolocation data; visual browser rehearsal and live cloud-provider verification are still separate.

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest backend/tests/test_full_integration.py -q -p no:cacheprovider
.venv/Scripts/python.exe -X utf8 -m pytest backend/tests -q -p no:cacheprovider
.venv/Scripts/python.exe -X utf8 data/validate.py
Push-Location frontend
npm.cmd run build
Pop-Location
```

Use `-X utf8` on Windows. Raw reconstruction/provenance checks need original files under the
ignored `backend/data/raw/`; the current tests skip unavailable raw payloads rather than inventing
them. A skipped reconstruction check is a validation gap, not proof of provenance.

## Optional setup and current limits

For the behaviour/Isolation Forest explanation and a five-minute presentation, use the
[Member 4 judge guide](docs/MEMBER4_JUDGE_GUIDE.md).

For actual request-driven detection and reversible responses, see [LIVE_LAB.md](docs/LIVE_LAB.md).
For the complete live Indian district-service CVE attack, real backend replacement, independent
collection and verification, use [INDIA_LIVE_DEMO.md](docs/INDIA_LIVE_DEMO.md).
Start Vectra with `scripts/start.ps1 -SkipBuild -Background -LiveLab` and open `/lab` locally.
The separate portal listener runs on port 8010; the control API stays on loopback. This opt-in
lab covers inventory reassessment against known intelligence, live request/auth patterns,
temporary peer restrictions, a working document boundary fix and verification by subsequent
requests. Its custom weakness has a DEMO ID, not a real CVE. Historical ML remains separate.
The separate Apache target uses actual CVE-2021-41773 and a CERT-In reference. The custom portal
now also supports its own real-traffic baseline, chronological holdout and frozen future-window
ML scoring. Both run in the fictional organisation; no real company's data is used.
The latest follow-up verification is recorded at the top of
[STATUS_REPORT.md](docs/STATUS_REPORT.md), separately from the earlier full-suite checkpoint.

- The startup script disables feed scheduling in demo mode. Public feeds are read from their
  bundled snapshots. Cache availability and collector freshness are separate states.
- Cloud text requires `LLM_ALLOW_CLOUD=true`, the Groq provider/model configuration and a valid
  key. This opt-in now also applies in demo mode. Leave it false for cached/template-only use.
- IP geolocation needs `maxminddb` and the local DB-IP Lite files described in
  [PLAN_ip_geolocation.md](PLAN_ip_geolocation.md). Missing files return unknown locations.
- Authentication/roles, real organisational telemetry onboarding and deployment hardening remain
  production work. The local script binds to `127.0.0.1`.
- Real-sensor Isolation Forest is an outlier triage aid; the historical logs have no ground-truth
  attack labels. Synthetic scenarios remain rules-only.
- The initial integration's 216-pass/9-failure record is historical. Use the current verification
  section in [STATUS_REPORT.md](docs/STATUS_REPORT.md) for this checkout.

## What belongs in Git

Commit source code, dependency manifests/lockfiles, tests, blank `.env.example` templates,
`data/` fixtures, public `backend/data/cache/` snapshots and reviewed evaluation JSON reports.
These caches make the demo reproducible without downloading feeds at startup.

The ignore rules exclude private `.env` variants, private key files, virtual environments,
`node_modules`, frontend builds, SQLite files and sidecars, raw collector payloads, large IP
geolocation databases, logs, editor caches and temporary artifacts. They do not erase files
already committed or remove secrets from Git history. Previously exposed credentials still
require rotation. Avoid committing confidential logs or new AI reports from real organisations.
