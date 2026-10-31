# CLAUDE.md — Project context (read this first)

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