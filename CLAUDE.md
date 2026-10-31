# CLAUDE.md — Project context (read this first)

## 1. Situation
- **Event:** D3COY — 24-hour cybersecurity hackathon. Sponsor & PS author: **C-DAC** (MeitY's R&D arm).
- **Timeline:** starts ~2:00 PM Sat 31 Oct 2026 → ends ~2:00 PM Sun 1 Nov 2026.
- **Team:** 4 people. 1 frontend dev (hand-codes UI), 3 full-stack devs (vibe-coding with Claude Code).
- **Team knowledge:** little/no cybersecurity background. Keep code and explanations plain; add short comments explaining security concepts where they're used.
- **Priority:** a flawless, offline-safe demo beats feature count. Every feature must show up on the dashboard.

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

## 8. Normalised schemas (core contracts — don't change without telling the team)
```python
ThreatItem: id, source, type("vulnerability"|"advisory"|"campaign"|"ioc_batch"),
            title, description, published_at, url,
            cve_ids[], cvss: float|None, severity, epss: float|None, in_kev: bool,
            affected: [{vendor, product, versions, cpe}], attack_techniques[], tags[], raw_ref
IOC:        value, ioc_type("ip"|"domain"|"url"|"sha256"|"md5"), source, malware_family,
            first_seen, confidence, related_threat_id
Asset:      id, hostname, ip, role, os, software:[{vendor, product, version, cpe}],
            criticality(1-5), internet_facing: bool, sector("power"|"banking"|"govt"|"health"|...), owner
Alert:      id, threat_id, asset_ids[], risk_score(0-100), level("Low"|"Medium"|"High"|"Critical"),
            factors:{cvss, exploit, criticality, exposure, confidence}, ai_summary, why_it_matters,
            recommendations[], attack_techniques[], status("new"|"ack"|"resolved"), created_at
```

## 9. Risk scoring (explainable — show every factor in the UI)
```
exploit    = 1.0 if in_kev else max(epss, 0.05)
exposure   = 1.0 if internet_facing else 0.5
confidence = 1.0 exact version match · 0.7 product match, version unknown · 0.4 vendor-only/fuzzy
risk       = 100 × (cvss/10) × exploit^0.5 × (criticality/5) × exposure × confidence
level      = Critical ≥75 · High ≥50 · Medium ≥25 · Low <25
```
(Square root on exploit stops low-EPSS CVEs collapsing to ~0; tune weights if the demo ranking looks wrong.)

## 10. AI components
1. **LLM analyst summary** per alert: what it is, why it matters to *these* assets, recommended actions (patch version / block IOCs / investigate host), mapped ATT&CK techniques. Strict JSON output, validated.
2. **Campaign detection:** TF-IDF/embeddings + clustering (e.g. HDBSCAN/KMeans) over advisory/pulse text + shared CVEs/IOCs → group related threats into "emerging campaigns".
3. **Log anomaly detection:** Isolation Forest on simulated auth/firewall logs (failed logins, rare ports, IOC hits) → suspicious-activity alerts.
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
