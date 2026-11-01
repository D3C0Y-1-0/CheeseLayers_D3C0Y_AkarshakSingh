# CLAUDE.md — Project context (read this first)

## Latest live activity / response / assistant handoff - 1 November 2026

This section supersedes the earlier frontend-only scope below: user additionally authorised
live automatic attack-type visualisation, a real portal login form, block bypass verification,
workspace NLP tasks, report grounding and a per-tab data audit. Existing teammate/UI work is
preserved; no .env edits, database resets, commit, push or deployment were performed.

Implemented:
- `backend/app/portal.html`: functional owned dummy login page, public notice, actual HTTP/event
  feedback. It POSTs real requests; it does not insert selected attack scenarios.
- Portal middleware observes all routed/unknown/validation-failed HTTP requests and enforces
  restrictions before routing/body parsing. It never reads credential bodies/cookies/headers.
  URL fields are bounded and sensitive query keys redacted before signature inspection/storage.
- Automatic SQLi/command-injection/traversal/XSS labels reuse strong replay signatures. Login
  burst/spray/success-sequence, 8-path discovery and 30-failure/3-peer distributed patterns are
  evidence-linked. No match stays no rule fired; no guessed CVE or successful compromise.
- `/lab` now animates actual portal + independent Apache observations and offers explicitly
  recorded playback. Initial retained history is not presented as a live replay. Pause affects
  animation only. Counts are bounded to retained view; large bursts sample 20 animation entries.
- Block covers paths/verbs/bad JSON/reconnections/spoofed forwarded headers for the exact TCP
  peer, normalising IPv4-mapped IPv6. Default TTL 300s; retries renew original-duration quiet
  period when enabled, tracked on the action. State polling does not renew. Release/expiry work.
  Compare-and-set updates prevent stale retry/verification writes undoing a concurrent release.
- Opt-in deterministic auto-block is OFF at handoff; renewal ON. ML never auto-blocks. Scope is
  custom portal :8010, NOT the OS firewall, Apache listener or arbitrary traffic to this PC.
  Distributed failure finding does not identify a botnet or automatically block every source.
- `app/assistant.py`: deterministic bounded intent queries over stored records. SOC Ask formerly
  offered literal search/CVE summaries; now recognises incident/inventory/provenance tasks.
  Local `/lab` adds exact-target block/release/custom-portal patch proposals; a separate Execute
  invokes existing token/loopback-protected action API. Queries never mutate, no arbitrary tools.
- Report controls default to `evidence_only=true`: model AND model cache bypassed. Optional
  LLM mode revalidates cached narratives and rejects factual-field overrides, new numbers,
  identifiers, commands and compromise/attribution overclaims. Filters do not prove semantics.
  Hindi in strict mode honestly returns English fallback. Clipboard failures display an error.
- `scripts/start-lab-portal.ps1 -Background` supports hidden persistent launch, logs and process
  metadata compatible with identity-checked `scripts/stop.ps1 -Port 8010`.

Validation:
- Full backend suite: **362 passed, 10 skipped** in 374.19s. A later focused live/AI run after
  final enforcement/distributed changes: **45 passed**. One Starlette/httpx deprecation warning.
- Final production TypeScript/Vite build passed. Lint has zero errors / five existing warnings.
  Inline portal/console and external activity JavaScript syntax checks passed; console ID/control
  contract tested. Native rendered browser/mobile/keyboard and a real second PC remain unverified.
- Actual running-service HTTP check on private 10.120.134.199:8010: home200; automatically labelled
  SQLi then XSS attempts on missing URL; block applied; changed URL + malformed body + spoofed XFF
  returned429, verified action and renewal1; release restored200. Evidence-only investigation
  returned200/template and cited the actual event; CERT-In draft200 with sent=false. Strict Hindi
  returned English with correct note. Details: ignored `logs/live-activity-verification.json`.
- Main and portal were restarted using verified process identities, preserving existing data.
  Main: `http://127.0.0.1:8000/lab`; portal: `http://10.120.134.199:8010/` on verified Wi-Fi IP.
  Both run in background. Refresh /lab and /app after deployment/build changes; tokens rotate
  on control restart. The Apache watcher retrieves the current token each collection cycle.

Read `docs/LIVE_ACTIVITY_AND_DATA.md` for the complete rule/scope table, run instructions,
block semantics, assistant commands and tab-by-tab actual versus predefined data. Rehearse
from the second PC before judges. Collect a NEW ordinary ML baseline after the expanded HTTP
coverage; an older baseline saw a different request mix. Do not silently tune for desired flags.
Production identity/tenant boundaries, retention, calibrated false-positive measurement,
additional authorised OS/network sensors and bundle-size improvement remain future work.

## Latest dashboard and presentation handoff - 1 November 2026

This section supersedes older checkout and UI status below. The earlier live-foundation work
has been committed/merged by the team. This task started on `main` at `512c825`; do not assume
the historical branch or dirty-file list below still describes this checkout. Read `git status`.

User explicitly requested a repo-wide presentation story and visual improvements across `/app`.
These changes are frontend/docs only; preserve `.env`, Docker configuration and backend contracts.

- `docs/PITCH_AND_DEMO.md` is the current complete 11-13 minute script, seven-minute cut,
  page/endpoint map, evidence requirements, judge questions and failure contingencies.
- Shared visual components live in `frontend/src/dashboard/Visuals.tsx` and `visuals.css`:
  metric cards, score gauges, distributions, breakdowns, workflow rails and expandable details.
- Dashboard pages now prioritise actual counts, charts and evidence timelines. Full reasons,
  raw evidence, source references, rulebooks and optional fixture controls remain expandable.
  Unknown values remain unknown; chart scopes distinguish current page from full inventory.
- All dashboard routes were reviewed, including SOC, Command Center, Threats, Assets,
  Incidents/detail, Signals, Campaigns, Analytics and Attack Replay. Existing graph/globe,
  investigation, SHAP/PDF and replay functionality is retained. `/lab` remains the live controller.
- AI investigation and CERT-In draft now expose the existing English/Hindi API option and show
  actual returned language/fallback. Neither drafting nor copying submits a regulatory report.
- Shared health uses existing polling and distinguishes cache-mode API connectivity from fresh
  intelligence. Live HTTP activity, cached intelligence, replay and baseline models stay labelled.
- Replay and live sensors use DIFFERENT detectors and common downstream correlation/scoring;
  do not describe them as one identical detection engine. A CVE signature is attempt evidence,
  not proof of successful exploitation. Incident state changes are not proof of remediation.

Verification for this UI task: final TypeScript/Vite production build passed; ESLint passed
with five existing warnings (no errors). HTTP returned 200 for landing and all checked app
routes, and the server references the current build's JavaScript/CSS (both return 200).
Native browser automation was unavailable, so visual browser/mobile/keyboard review remains.
The existing large JavaScript chunk warning also remains. Earlier backend test results below
are historical and were not rerun for this presentation-only change. No commit/push/deploy.

Next: rehearse `docs/PITCH_AND_DEMO.md` against current runtime data, check rendered layouts at
mobile/desktop widths, and exercise Hindi fallback with the actual configured provider. For
judges, prepare the live baseline before the anomaly test, release blocks before patch checks,
and verify the same Apache district URL after replacement. Hosted and local DBs are separate.

## Current operational handoff — 1 November 2026 (Asia/Kolkata)

**Read this section before the historical team plan below. It overrides outdated implementation/status claims.**

### Checkout and preservation

- Working branch: `codex/live-india-foundation`, based on `d8ee68e` (`shap`). The latest requested
  pull included Render deployment and SHAP/PDF explanation work. The `app/main.py` conflict was
  resolved by retaining BOTH upstream explainability routes and the new live-lab routes.
- There are substantial **uncommitted tracked and untracked changes**. Do not reset, clean,
  overwrite, drop recovery stashes or discard files before reviewing `git status`.
- Recovery stash retained: `codex: preserve live lab and deterministic foundation before user-requested pull`.
  An older Member 4 recovery stash may also exist. No push/deployment was performed by this work.
- User explicitly authorises an owned, codebase-only lab; no real company is to be attacked or
  its data collected. Keep all demonstrations confined to the fictional organisation/dummy records.
- `.env` is ignored and untracked. Never print credentials. Runtime databases, logs, collector
  checkpoints, environments, builds and `lab/apache/runtime/` stay out of Git.

### What the product now demonstrates

The organisation is **Fictional Indian District Citizen Services**. The original 40 synthetic
inventory assets remain. Initialising the custom portal and discovering Apache adds three lab
assets, making 43 in that setup. Counts come from inventory; do not assume 40/43 in application logic.

1. **Known-intelligence path:** stored CVE/KEV/vendor/CERT-In intelligence is matched against
   current product/version inventory. New threat signals already invoke `on_new_threat`; a new
   CERT-In advisory resolves its explicit CVE IDs to the corresponding structured range records.
   Persisted inventory overrides and operator reassessment now update exposure immediately.
2. **Behaviour path:** actual requests/authentication outcomes are recorded by the custom
   portal; independent Apache access logs are collected separately. Rules generate findings
   from those observations, and the existing correlator persists incidents/evidence.
3. **Response:** temporary custom-portal restrictions and a working document boundary fix;
   for the Apache district endpoint, verified blue/green replacement with a fixed binary.
   A subsequent actual HTTP request verifies effects. A status change alone is not mitigation.
4. **Early warning:** exposure can be raised BEFORE a controlled attack. Live statistical
   outliers supply triage. Neither is a validated forecast of attacker timing/probability.
   Do not claim zero-day discovery, real-world accuracy or automatic regulatory compliance.

### Known-vulnerability foundation changes

- `app/asset_store.py`: immutable fixture starting inventory plus fresh SQLite override snapshots,
  visible across the control and portal processes. Shared fixture JSON/contracts were not renamed.
- `app/live_lab.py`: audited simulated inventory changes, relevant intelligence reassessment,
  explicit CVE-linked CERT-In references and source retrieval/simulation fields.
- Reassessment uses the SAME vendor/product normalisation as the matcher (including hyphens).
  Conflicting product/version CPE observations return 422; update the CPE or set it to null.
  Instrumented live assets must use service-specific controls, not manually fabricated versions.
- Newly reported empty inventory is incomplete, not proof of removal/safety. Missing structured
  advisory applicability requires verification. Curated synthetic fixture inventory semantics
  are preserved. `assessment_status` distinguishes unknown inventory/no structured matches.
- `app/correlator.py`: a previously unaffected exposure reopens when it becomes affected or
  uncertain again. Version parsing is bounded/memoised without changing comparison rules.
- Inventory entry is an operator observation, not proof that a real host was patched. For the
  runnable Apache lab, registration checks actual Docker identity/image and `httpd -v`.

### Actual published-CVE lab — use this for the main live presentation

- `lab/apache/compose.yaml`: official digest-pinned Apache 2.4.49 and 2.4.51, plus a pinned Nginx
  relay. Targets are on an internal Docker network, read-only, UID 1000, capabilities dropped,
  resource limited, CGI/executable/proxy handlers disabled. Only dummy documents/configs mount.
- The public dummy notice is under `/srv/lab/public`; a dummy internal record is under
  `/srv/lab/internal`. The real CVE-2021-41773 traversal in 2.4.49 exposes that dummy record.
  2.4.51 rejects the same request. No host/private/real organisation data is required or used.
- Apache 2.4.51 is the historical comparison fixed for the demonstrated traversal CVEs, **not
  a current production security recommendation**. Other CVEs may still match those old versions.
- CERT-In reference: `CIAD-2021-0039`; vendor and CERT-In URLs are in
  `lab/apache/advisory_sources.json`. This file is reviewed reference metadata, not a fresh
  automated scrape/full raw advisory. Existing canonical cache metadata is preserved.
- `app/apache_lab.py`: local/token-protected discover, verified register, original-log ingestion,
  evidence/state, bounded live probe, patch/rollback and actual verification endpoints.
- `shadow_watch/apache.py`: parses original request lines, status, bytes, route identity, peer
  information, relay-generated request IDs and raw hashes. Original query values are discarded
  from normalised evidence. Malformed records are explicitly rejected; no guessed verdicts.
- The relay overwrites route/request-ID/observed-peer headers and strips untrusted X-Forwarded-For.
  Its generated request ID links the actual HTTP response to the independently collected log.
  Docker/host/proxy NAT may hide the original client; do not identify an attacker/person/country.
- `scripts/watch_apache_lab.py`: independent Docker-log collector, authenticated loopback
  ingestion, persisted timestamp checkpoints, duplicate-safe IDs and ignored raw log capture.
  Initial collection starts when the collector registers; it does not invent historical traffic.
- **Patch is real service replacement:** the SAME port 8011 district endpoint is routed from
  verified Apache 2.4.49 to verified 2.4.51 via generated Nginx config and a tested reload.
  Inventory/exposure is rechecked. Verification repeats actual public/traversal requests.
  The old backend stays isolated for rollback; this is not an OS package installer or proof of
  fleet-wide eradication. Replacement actions can be applied, verified and superseded.
- Container snapshots preserve version-at-observation, so late old logs are not misclassified
  using the service's newly patched inventory. Fixed-target attempts remain candidate CVE
  patterns; they are not recorded as verified affected/exploited targets.

### Custom portal behaviour and real sensor-specific ML

- `shadow_watch/live.py`: actual document traversal, 10 login failures/peer/60s, failures across
  5 usernames/peer/60s, and login success after at least 5 failures for the same username/peer.
  Passwords are never recorded. Success-after-failures is suspicious, not verified account theft.
- Existing typed Shadow Watch HTTP/process/network/auth rules remain; process findings require
  host telemetry. Auth aggregate thresholds now respect configured observation-window bounds.
- The custom portal weakness is `DEMO-VULN-LAB-TRAVERSAL`, **not a published CVE**. It uses a
  two-document virtual store and never opens host files. Its separate listener is port 8010.
- `shadow_watch/lab_ml.py`: separate Isolation Forest for this portal only. Five-second ACTIVE
  windows, two-second finalisation grace, at least 30 eligible windows and four distinct training
  vectors. No fake idle windows. Features: request rate, 4xx ratio, failed-login ratio, unique
  peers and unique usernames. Known rule-positive/429 windows are excluded from baseline use.
- Earlier 80% trains; later 20% is a chronological baseline holdout. 200 trees, contamination
  0.05, fixed seed. Explicit freeze prevents online retraining/attack contamination. Future
  evaluation excludes windows straddling freeze time. Baseline is operator-declared ordinary
  traffic, not independently labelled ground truth. Holdout flags must remain visible.
- Training vectors, provenance IDs, config, library version and fingerprint persist as JSON;
  no pickles. Frozen models can reconstruct after restart; earlier models are archived in
  `lab_settings`. A changed sklearn version requires a new baseline. Background processing runs
  only when the lab is enabled, with one control worker; portal only writes observations.
- `LIVE-ML-001` findings are low-confidence triage with original request-window references.
  They do not automatically block. The historical SecRepo model is NEVER reused for this sensor.
- Historical SecRepo ML remains separate: web/SSH, 200 trees, contamination 0.02, 70/30 temporal
  split, rules-first fallback; batched candidate scoring retains prior scores/decisions. Upstream
  SHAP/PDF explanations cover those historical models, not the new lab model.

### Evidence, investigation and India context

- Evidence and actions persist in SQLite; default DB is `backend/data/vectra.db` via
  `VECTRA_DB_URL`. The older `netrax.db` is separate. Do not silently delete/migrate/reset either.
- New durable tables: `inventory_overrides`, `lab_observations`, `lab_settings`, `lab_actions`,
  `lab_ml_windows`, `apache_lab_observations`; not part of the derived-feed drop/rebuild list.
- Bounded investigation/evidence selection prioritises recent detections before the 100-record
  cap, then orders the selected evidence chronologically. Truncation remains explicit.
- `ai/schemas.py`, `ai/fallback.py`, `shadow_watch/integration.py` preserve live detector reasons,
  ingestion timestamps, candidate versus verified CVE applicability and source references.
  CERT-In drafts now retain verified live CVE applicability, request IDs and recent detector reasons. Reports distinguish exposure, attempt patterns and actual success; HTTP 200/bytes alone do
  not prove data disclosure. The controlled probe separately verifies the dummy marker.
- India-specific context is service ownership/impact, IST timeline, actual CERT-In relevance,
  existing India intelligence/Hindi assistance and analyst-reviewed reporting drafts. These are
  not real government deployments or automatic submissions. Reporting duties are contextual;
  do not put an unconditional six-hour deadline on every anomaly.
- Detection/matching/scoring are deterministic/ML. Optional LLM is narrative assistance; current
  local rehearsal used template output. Cloud requires explicit opt-in/provider/key and can
  otherwise use cached/template reports. Never expose `.env` values to debug this.

### Start, demonstrate, stop

From the repository root (stop an already registered server before changing its launch flags):

```powershell
.\scripts\start.ps1 -SkipBuild -Background -LiveLab
.\scripts\start-apache-lab.ps1
.\scripts\start-apache-collector.ps1
# Optional separate custom portal; keep terminal open:
.\scripts\start-lab-portal.ps1
```

- Control console: `http://127.0.0.1:8000/lab`; dashboard: `/app`; API schema: `/docs`.
  Control API stays on loopback and requires the per-process local console token/Host/peer.
- District Apache endpoint: `http://127.0.0.1:8011/documents/notice.txt`; comparison: port 8012.
  For two PCs, explicitly pass a specific private LAN address to the Apache/portal launcher;
  leave the control plane local. No automatic Windows firewall changes were made.
- Console sequence: discover/warn → ordinary request → live dummy traversal → inspect independent
  evidence/incident → replace with fixed Apache → verify → repeat the SAME attacker request.
  Restore vulnerable backend only for a fresh owned-lab run. No fixture injection is needed.
- Current rehearsed state: Apache district endpoint routes to fixed 2.4.51; custom portal is
  patched; temporary custom restriction released; a real portal ML baseline remains frozen.
- Repeat actual checks: `python -X utf8 scripts/rehearse_apache_lab.py`;
  `scripts/rehearse_live_lab.py` for the custom flow; `scripts/train_lab_baseline.py` for roughly
  three minutes of actual baseline traffic plus a measured burst. These are loopback-only tools.
- Stop registered app: `scripts/stop.ps1 -Port 8000`; worker: `scripts/stop.ps1 -Worker apache-collector`;
  portal if registered in background: `scripts/stop.ps1 -Port 8010`; foreground portal: Ctrl+C.
  Owned Docker lab: `docker compose -f lab/apache/compose.yaml down`.
- Launchers retain stdout/stderr and identity metadata in ignored `logs/`. Read those records
  rather than hardcoding PIDs. Stop helpers verify PID/start-time/python identity before stopping.
- Do not casually use global reset-alert endpoints: they remove correlated evidence, while raw
  lab records/checkpoints/models persist. Prefer fresh requests and explicit rollback controls.

### Verification and next steps

- Actual Apache HTTP rehearsal passed: affected before traffic; dummy disclosure on 2.4.49;
  independent request-ID-matched finding; same endpoint replaced with 2.4.51; traversal 404;
  public notice 200; exposure confirmed unaffected for CVE-2021-41773; action verified and
  investigation cites that CVE. Evidence: ignored `logs/apache-live-rehearsal.json`.
- Actual lab ML rehearsal: 25 training windows, 7 later holdout windows, 1 holdout flagged;
  new 40-request burst flagged without a request-rule finding. These are tiny controlled
  measurements, not attack accuracy. Evidence: `logs/live-ml-rehearsal.json`.
- Earlier custom live flow: about 66 ms to persisted finding locally, 429 for the selected peer,
  another peer 200, real boundary fix 403, public notice 200, auth sequence linked 11 requests.
- Full backend checkpoint: **347 passed, 10 skipped** in 298.21 seconds; after the final CERT-In draft evidence integration, **27 focused tests passed**. The only pytest warning was the upstream Starlette/httpx deprecation. Actual HTTP rehearsals are separate from these tests.
- Frontend production build passed after pulling SHAP; new UI is the backend-served `/lab`
  console. Browser visual and two-PHYSICAL-PC rehearsal have not been verified here. Native
  computer/browser automation was unavailable earlier; do not claim visual testing from HTTP.
- Primary runbook: `docs/INDIA_LIVE_DEMO.md`; custom/ML details: `docs/LIVE_LAB.md`;
  API/contracts: `docs/API.md`; current audit: `docs/STATUS_REPORT.md`; coverage:
  `docs/DYNAMIC_FOUNDATION_ROADMAP.md`. Older standalone/replay guides are historical checkpoints.
- Next: (1) physical two-PC/browser rehearsal; (2) representative baseline/labelled evaluation,
  false alarms and sensor/context/seasonality calibration; (3) production authentication/tenant
  separation, independent real host/network sensors, retention/backups/load/deployment hardening; reconcile executed lab-action ledger entries with analyst reporting rather than assuming lifecycle entries list all actions;
  (4) only then validated forecasts with defined outcomes/horizons and untouched future data.
- Keep scheduled feeds off in DEMO_MODE; label cache freshness separately from live telemetry.
  Optional geolocation reader/data is still separate and its warning is not a server crash.
- Preserve generated scoring blocks below and in `docs/SCORING_AND_AI.md`. Do not change shared
  fixture field names. Prefer focused tests; run full regression when core integration changes.

---

## Historical team context (retain useful requirements; current status above takes precedence)

## 1. Situation
- **Event:** D3COY — 24-hour cybersecurity hackathon. Sponsor & PS author: **C-DAC** (MeitY's R&D arm).
- **Timeline:** starts ~2:00 PM Sat 31 Oct 2026 → ends ~2:00 PM Sun 1 Nov 2026.
- **Team:** 4 people. 1 frontend dev (hand-codes UI), 3 full-stack devs (vibe-coding with Claude Code).
- **Team knowledge:** little/no cybersecurity background. Keep code and explanations plain; add short comments explaining security concepts where they're used.
- **Priority:** a flawless, offline-safe demo beats feature count. Every feature must show up on the dashboard.
- **Scope right now: BACKEND ONLY.** Do not create or edit anything in `frontend/`. A teammate builds the UI later against our API. So every feature must be exposed through a documented REST endpoint, with the contract in `docs/API.md` and example responses saved in `docs/samples/*.json` (the frontend dev mocks from these).

## 1b. Team plan — Vectra (this OVERRIDES the folder ownership/phases below where they conflict)
- **Product name:** Vectra. Branches: `frontend`, `feeds`, `correlation`, `ai`.
- **Member 1:** React dashboard + demo. **Member 2:** FastAPI app, SQLite DB, threat-intel ingestion, source health. **Member 3:** asset inventory, version matching, risk scoring, incident correlation (integration lead). **Member 4:** Shadow Watch (behaviour rules + Isolation Forest), SOC investigation agent, LLM fallback.
- **API ownership:** M2 → `/health`, `/api/overview`, `/api/threats`, `/api/threats/{id}`, `/api/source-status`, `POST /api/demo/inject-cve`. M3 → `/api/assets`, `/api/alerts`, `/api/alerts/{id}`, `POST /api/alerts/{id}/acknowledge`. M4 → `POST /api/demo/inject-behaviour`, `POST /api/alerts/{id}/investigate`.
- **Shared fixtures (team starter ZIP):** `data/assets.json` (40 assets), `data/threats_synthetic.json`, `data/events.json`, `data/windows.csv`, `data/contracts.json`. **`data/contracts.json` is the source of truth for field names** — align our schemas to it; never rename shared fields unilaterally.
- **Data honesty rules:** `null` = unknown/unverified — never coerce missing CVSS/EPSS to 0 or false. Every record carries `source`, `retrieved_at`, `is_simulated`, and a link to its raw payload. Synthetic IDs (e.g. `DEMO-VULN-001`) must never be presented as real CVEs.
- **Three demo scenarios:** A) known CVE → matched asset → scored alert; B) no-CVE suspicious behaviour → investigation; C) benign maintenance spike → not escalated.
- **Milestones:** H2 contracts + basic API · H6 parts work separately · H10 PS demo end-to-end · H14 agent + Shadow Watch connected · H20 scenarios tested · H21 feature freeze.

## 2. Problem Statement — PS 01: AI-Based National Cyber Threat Early Warning System
Build an AI-powered system that **collects threat intelligence from multiple sources, finds emerging attack patterns and vulnerable systems, scores risk, and issues early warnings with explanations and mitigations** — proactive, not reactive.

**Key objectives (from PS):**
1. **Threat Intelligence Aggregation** — trusted feeds, public advisories, vulnerability databases, simulated security logs.
2. **AI-Based Threat Analysis** — ML/NLP to find suspicious indicators, recurring attack patterns, relationships between threats.
3. **Early Warning Generation** — timely alerts based on severity, confidence, relevance.
4. **Risk Prioritisation** — rank by exploitability, asset criticality, potential impact, available evidence.
5. **Actionable Recommendations** — patch, block indicators, investigate.
6. **Threat Intelligence Dashboard** — active threats, affected technologies.

**Judges' example use case (our core demo — must be perfect):**
A new vulnerability advisory is published → correlated with a simulated asset inventory showing the org uses the affected software → system identifies exposure, assigns a risk level, generates an alert recommending investigation + remediation.

**Deliverables:** functional prototype · dashboard (threats, risk levels, alerts) · demo on public or simulated data · explanation of AI model, scoring approach, mitigation workflow.

## 3. Domain glossary (minimum needed)
| Term | Meaning |
|---|---|
| CTI | Cyber threat intelligence — info about attacks/attackers. Our input. |
| CVE | ID of a public vulnerability, e.g. `CVE-2024-3400`. |
| CVSS | 0–10 severity of a CVE (how bad it *could* be). |
| CPE | Standard product/version string used to match CVEs to software: `cpe:2.3:a:vendor:product:version:...` |
| CISA KEV | US govt list of CVEs **actively exploited in the wild**. Strongest "act now" signal. |
| EPSS | Probability (0–1) a CVE is exploited in next 30 days (FIRST.org). |
| IOC | Indicator of Compromise — malicious IP / domain / URL / file hash. |
| MITRE ATT&CK | Catalogue of attacker techniques (e.g. T1190 Exploit Public-Facing App, T1566 Phishing). |
| SIEM / SOC | Log + alerting platform / the analyst team using it. Our end users. |
| CERT-In | India's national CERT; publishes advisories & vulnerability notes. |
| Honeypot | Decoy system; any interaction with it is suspicious. C-DAC runs a national honeynet. |
| STIX / TAXII | Standard JSON format / transport for sharing CTI. |

## 4. Architecture
```
 Feeds (NVD, KEV, EPSS, CERT-In, abuse.ch, OTX, ATT&CK) + Simulated logs/honeypot
        │  collectors/ (one module per source, scheduled)
        ▼
 Normaliser → SQLite (threat_items, iocs, assets, alerts, log_events)
        │
        ├─ Correlator: CVE ↔ asset inventory (vendor/product/version/CPE)
        ├─ IOC matcher: IOCs ↔ simulated firewall/auth logs
        ├─ Risk engine: explainable 0–100 score
        ├─ AI: LLM summary + mitigation · campaign clustering · log anomaly detection · ATT&CK mapping
        ▼
 FastAPI REST  →  React dashboard
```

## 5. Stack
- **Backend:** Python 3.11, FastAPI, SQLite via SQLAlchemy (swap to Postgres only if time), APScheduler, httpx, BeautifulSoup4, pandas, scikit-learn.
- **LLM:** provider-agnostic wrapper `backend/ai/llm.py` (env `LLM_PROVIDER` + `LLM_API_KEY`; Groq / Gemini free tier or Anthropic API). Must degrade gracefully: if no key, return a template-based summary.
- **Frontend:** React + Vite + Tailwind + Recharts (+ react-router). Dark SOC-style theme.
- **Secrets:** `.env` only, never committed. Provide `.env.example`.

## 6. Folder layout & ownership
```
backend/
  collectors/      # Full-stack 1 — one file per source + run_all.py
  data/raw/        # raw dumps (gitignored except samples)
  data/cache/      # normalised JSON snapshots used in DEMO_MODE
  data/sim/        # simulated assets, logs, honeypot events
  core/            # Full-stack 2 — db models, correlator, risk engine
  ai/              # Full-stack 3 — llm.py, clustering, anomaly, attack_mapping
  api/             # FastAPI routers
frontend/          # Frontend dev
docs/              # pitch notes, architecture diagram, scoring explanation
```

## 7. Data sources
| Source | Endpoint | Auth | Gives us |
|---|---|---|---|
| NVD API 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Optional `apiKey` header (5 req/30s without, 50 with). Date ranges ≤120 days. | CVE text, CVSS, CPE configurations, references |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | None | Actively-exploited flag, due dates, ransomware use |
| FIRST EPSS | `https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B` (batch) | None | Exploit probability + percentile |
| CERT-In | `https://www.cert-in.org.in/` (advisories + vulnerability notes listing pages; scrape HTML) | None | India-specific advisories (key for C-DAC jury) |
| abuse.ch URLhaus / ThreatFox / MalwareBazaar | APIs: `urlhaus-api.abuse.ch`, `threatfox-api.abuse.ch/api/v1/`, `mb-api.abuse.ch/api/v1/` — header `Auth-Key`. Fallback no-key exports: `https://urlhaus.abuse.ch/downloads/csv_recent/`, `https://threatfox.abuse.ch/export/json/recent/` | Free Auth-Key | Malicious URLs, IOCs (IP/domain/hash), malware family |
| AlienVault OTX | `https://otx.alienvault.com/api/v1/pulses/subscribed` (+ `/pulses/activity`) | `X-OTX-API-KEY` | Community "pulses" = campaigns with IOCs + ATT&CK tags |
| MITRE ATT&CK | `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json` | None | Technique IDs/names/tactics (large file — download once, cache) |
| Simulated (ours) | `backend/data/sim/` | — | Asset inventory, firewall/auth logs, honeypot events |

**Rules for every collector:** timeout + retry with backoff · respect rate limits · save raw response to `data/raw/` · write normalised output to `data/cache/<source>.json` · log counts · never crash the pipeline if one source fails. `DEMO_MODE=true` → read only from `data/cache/` (no network).

## 8. Normalised schemas → **`data/contracts.json` (v1.3) is the source of truth**
Field names, types and enums for `threat`, `ioc`, `threat_signal`, `asset`, `event`, `alert`, `window` live in `data/contracts.json`
(check fixtures with `.venv/bin/python data/validate.py`). Don't restate them here: change the contract first,
tell the team, then change code. Key rule: **`null` = unknown/unverified, never 0/false.**

Backend (Member 2): `backend/collectors/schema.py` → `ThreatItem` (= contract `threat`) and `IOC` (= contract `ioc`).
Every collector builds these directly (no post-conversion). After a schema change, rebuild the cache offline with
`python -m collectors.run_all --from-raw`: it re-parses `backend/data/raw/*` with each collector's own parser.
§9 below still says `in_kev`; read it as **`kev_listed`**.

v1.3 (31 Oct): added `campaign` (GET /api/campaigns); later v1.3 additions are listed in docs/API.md (AI summaries, CERT-In draft, remediation targets).
v1.2 (31 Oct): added `threat_signal` (early-warning changes, see docs/API.md; Member 3 hook = `on_new_threat(threat_id, signal_type)`).
v1.1 changes (31 Oct): added entity `ioc`; made `type`, `cve_ids[]`, `tags[]` and `affected_configurations[].versions_text`
official threat fields; split dates (`published_at` = original publication: NVD's date for CVEs, advisory/pulse date
otherwise · `nvd_published_at` · `kev_date_added` (YYYY-MM-DD) · `retrieved_at` = when we fetched it); added `raw_refs[]`
(every contributing raw payload; `raw_ref` = `raw_refs[0]`, the primary one).

**What still doesn't fit perfectly** (checked 31 Oct on the merged cache, 0 contract errors):
1. **Multi-CVE threats:** CERT-In advisories and OTX pulses have `cve_id: null`; their CVEs are in `cve_ids[]`.
   `kev_date_added`/`nvd_published_at` stay null on them (those are per-CVE facts; look up the CVE's own record).
2. **CERT-In version ranges are free text** → all four bounds null, text in `versions_text`. Vendor/product are guessed
   from the text, not CPE names; `cpe` is null.
3. **`kev_listed` / `public_exploit` are `null` for threats with no CVE** (ransomware victims, most pulses, IOC batches): not checkable.
4. **Not yet scored upstream:** many NVD CVEs have no `cvss`/`severity`/`epss` yet (null). `cvss_version` mixes 3.1/3.0/4.0.
5. **KEV CVEs that NVD hasn't published** keep `published_at`/`nvd_published_at` null (KEV's date is only in `kev_date_added`).
6. **`raw_refs` covers payloads we store:** KEV dump + NVD page. EPSS / exploit-signal / ATT&CK enrichment comes from
   caches with no per-record raw file, so it isn't listed there.
7. **`published_at` null** for the 3 reputation-list batches (Tor, Spamhaus DROP, OpenPhish publish no dates).
8. **`retrieved_at` is per source run**, not per record.

## 9. Risk scoring (explainable — show every factor in the UI)
Source of truth: `backend/app/scoring.py` `CONFIG`. The block below is generated from it
(`backend/.venv/bin/python scripts/gen_scoring_doc.py`); `backend/tests/test_scoring_doc.py` fails if it drifts.
Full explanation for judges: `docs/SCORING_AND_AI.md`.

<!-- BEGIN GENERATED: scoring formula (scripts/gen_scoring_doc.py, from backend/app/scoring.py CONFIG) -->
Three separate 0-100 scores, never merged into one number. Priority comes from the higher of the first two.

```text
vulnerability_priority_score = 100 × ( 0.25·severity + 0.3·exploitation + 0.25·criticality + 0.2·exposure )
  severity     = CVSS / 10                     (CVSS unknown -> 0.5 + a limitation note, never 0)
  exploitation = KEV-listed: 0.8 + 0.2·EPSS^0.5   (KEV = exploited somewhere; EPSS = how widely)
                 otherwise:  EPSS^0.5                  (EPSS unknown -> 0.25)
                 public exploit code -> at least 0.6
  criticality  = asset criticality (1-5) / 5
  exposure     = 1.0 internet-facing · 0.25 internal
  0 when the asset runs a version outside the vulnerable range (confirmed_unaffected)
  version match needs manual verification -> priority capped at high

behavioural_suspicion_score = 100 × min(1, 0.75·worst_signal × confidence_multiplier + 0.2·(distinct signal types − 1))
  confidence_multiplier (from the detector): low 0.6 · medium 0.8 · high 1.0
  × 0.3 only if EVERY signal is http_anomaly / auth_anomaly inside an approved maintenance window
  signal severities: credential_compromise 0.95, data_exposure 0.95, exploit_on_vulnerable_asset 0.9, command_injection 0.85, unexpected_process 0.8, sql_injection 0.75, outbound_connection 0.7, exploit_attempt 0.7, brute_force 0.6, http_anomaly 0.5, auth_anomaly 0.5, login_hammering 0.5, port_scan 0.45, inbound_ids_alert 0.4, recon_probe 0.35

evidence_confidence_score = provenance + match certainty + corroboration − missing-field penalty
  provenance: kev 30 · verified 25 · telemetry 20 · simulated 15 · other 10
  match certainty: confirmed_affected 40 · needs_verification 15
  corroboration: 10 per distinct signal type, max 30
  penalty: 5 per event with a missing key field

priority = critical >= 80 · high >= 55 · medium >= 30 · else low
remediation target (organisation-defined policy, not a regulatory deadline): critical 7d · high 14d · medium 30d · low 90d

worked example: CVE-2024-21762 (CVSS 9.8, EPSS 0.846, KEV) on PWR-FW-01 (criticality 5, internet-facing)
  severity 24.5 + exploitation 29.5 + criticality 25.0 + exposure 20.0 = 99.0 -> critical
```
<!-- END GENERATED: scoring formula -->

## 10. AI components
1. **LLM analyst summary** per alert: what it is, why it matters to *these* assets, recommended actions (patch version / block IOCs / investigate host), mapped ATT&CK techniques. Strict JSON output, validated.
2. **Campaign detection:** TF-IDF/embeddings + clustering (e.g. HDBSCAN/KMeans) over advisory/pulse text + shared CVEs/IOCs → group related threats into "emerging campaigns".
3. **Log anomaly detection (Shadow Watch):** five detectors: `SW-HTTP-001`, `SW-PROC-001`, `SW-NET-001`,
   `SW-AUTH-001` (10+ failed logins/min) and `SW-ML-001` (Isolation Forest).
   **Isolation Forest status:** enabled **only on the two real SecRepo sensors** (secrepo.com web server Dec 2016,
   AWS sshd Nov-Dec 2014), trained on the **first 70% of each sensor's minutes**, scoring only that sensor.
   **Not used on the synthetic scenarios**: there it added 4/142 false positives with no recall gain (rules alone
   8/8, 0 FP), so they stay rules-only. ML findings are **low severity, low confidence ("unusual, needs review")**
   and never escalate alone. SecRepo has **no ground-truth labels**, so ML flags are outliers, not confirmed attacks.
   Evidence: `artifacts/shadow_evaluation.json` (synthetic), `artifacts/shadow_evaluation_real.json` (real). See
   `README_MEMBER4.md`, `docs/SCORING_AND_AI.md`.
4. **ATT&CK mapping:** use OTX tags where present; else keyword/embedding match of CVE/advisory text against ATT&CK technique descriptions.
5. **Early warning rule:** threat becomes a warning when risk ≥ threshold OR (in_kev AND matches any asset) OR campaign volume spikes.

## 11. Dashboard pages
Overview (KPIs, risk trend, top alerts) · Live threat feed (filter by source/severity) · Alert detail (score breakdown, affected assets, AI summary, actions, ATT&CK) · Assets (inventory, per-asset risk) · Campaigns · ATT&CK heatmap · (stretch) "Ask the SOC" chat.

## 12. Simulated data requirements
- 30–50 assets across Indian critical sectors (power grid SCADA HMI, bank core server, govt web portal, hospital PACS, etc.).
- **Deliberately include software versions affected by real KEV CVEs** so the core demo always fires a Critical alert.
- Logs: ~5k auth/firewall events over 7 days, with a few injected hits on real abuse.ch/ThreatFox IOCs + a brute-force burst.
- Optional honeypot event stream (SSH login attempts/commands) — nods to C-DAC's honeynet work.

## 13. C-DAC alignment (for pitch)
C-DAC Mohali's **Cyber Threat Management System** = honeypot sensors → analysis → risk calc → integrated early warning → India-focused CTI → SIEM integration → single dashboard. Related: Honeynet Technologies, C-ADAR (MITRE mapping, IOC correlation), E-Samarthak (ML multistage attack prediction), CDAC webSIEM.
**Our pitch:** the AI analyst layer — asset-aware prioritisation + explainable scores + LLM-written warnings on top of national feeds like CERT-In and CTMS; India-first; exports to SIEM/STIX; on-prem capable.

## 14. Conventions
- Small, working increments; run it after each change.
- Type hints, Pydantic models for API I/O.
- No secrets in code or logs. Gitignore `.env`, `data/raw/`.
- `make demo` (or a script) must start everything from cache with zero network.
