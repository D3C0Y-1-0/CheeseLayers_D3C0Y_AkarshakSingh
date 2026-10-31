# Vectra

The integrated React dashboard and FastAPI backend: cached public intelligence, simulated asset
inventory, explainable scoring/correlation, Shadow Watch and grounded SOC investigation.

## Run the complete demo (PowerShell, repository root)

```powershell
uv venv .venv
uv pip install --python .venv/Scripts/python.exe -r backend/requirements.txt
Push-Location frontend
npm.cmd ci
Pop-Location
.\scripts\start.ps1
```

Open **http://127.0.0.1:8000/app**. The script builds React and serves it with the API from one
address in `DEMO_MODE=true`. Initial startup loads bundled caches into SQLite; wait for
"Application startup complete". Subsequent starts reuse the database. Use `-SkipBuild` for an
already built frontend or `-Port 8001` for another port. Your root `.env` stays private and ignored;
no key is needed. For frontend development run `npm.cmd run dev` in `frontend/` alongside the
backend, then open http://127.0.0.1:5173/app. Vite proxies API calls to port 8000.

## Connected features

- Command Center: real API counts, publication trend, source health, four predefined scenarios,
  persisted incident links and a repeatable alert/event reset.
- Threat Intelligence: server pagination/search/filtering, asset relevance, source references,
  ATT&CK labels and STIX 2.1 export.
- Asset Inventory: simulated inventory and links to each asset's open incidents.
- Incidents: stored sensor evidence, three separate scores with inputs, lifecycle changes,
  investigation reports, visibility gaps and proposed actions.
- Early warnings: signal history, thresholds and explicitly synthetic signal simulation.
- Exposure & impact: sector posture, read-only patch what-if, lead-time analysis and cached
  CERT-In/India-related intelligence.

The suspicious chain creates a persisted no-CVE incident. Benign maintenance retains all events
without escalation. Missing host telemetry remains a visibility gap. Replay/restart is idempotent;
demo alert reset also clears the preview cache so a scenario can be replayed after reset.

Shadow Watch stores normalized envelopes/findings in Member 3's existing event JSON. There is no
second database or score engine. Template reports work offline. The default scope permits
persisted simulated incidents in demo mode; real incidents require an authenticated scope factory.
Demo mode disables the feed scheduler and cloud LLM. The optional provider remains explicitly
opt-in outside demo mode. No suggested remediation is executed.

The UI labels bundled fallback samples and never fakes successful mutations. Public intelligence
and synthetic activity remain distinct. Isolation Forest added false positives on the synthetic
fixture, so it is not enabled. See [Member 4 runbook](README_MEMBER4.md),
[integration](docs/INTEGRATION.md), and [API contract](docs/API.md).

## Verify

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest backend/tests/test_full_integration.py -q -p no:cacheprovider
.venv/Scripts/python.exe -X utf8 -m pytest backend/tests -q -p no:cacheprovider
.venv/Scripts/python.exe -X utf8 data/validate.py
Push-Location frontend
npm.cmd run build
Pop-Location
```

Full-suite raw reconstruction/provenance checks require ignored `backend/data/raw/` files absent
from this checkout; cached data cannot reproduce those original payloads. Use `-X utf8` on Windows.
