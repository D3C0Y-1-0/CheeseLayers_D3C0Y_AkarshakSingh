# Vectra: how the scoring and the "AI" actually work

PS 01 asks for "an explanation of the AI model, threat scoring approach, and proposed mitigation workflow".
This is that explanation, including what is **not** AI. Every number in the scoring section is generated
from `backend/app/scoring.py` `CONFIG` (`scripts/gen_scoring_doc.py`), and a test fails if this page drifts.

## 1. Architecture

```text
 Public feeds (cached for an offline demo)          Simulated organisation
 NVD · CISA KEV · FIRST EPSS · CERT-In ·            40-asset inventory (6 sectors) ·
 abuse.ch · OTX · ransomware leak sites             sensor events · Attack Lab logs
        │ collectors/ → normalised `threat` / `ioc` records (data/contracts.json)
        ▼                                                    │
 SQLite ──► early-warning signals (feed diffs) ──► on_new_threat hook
        │                                            │
        │   ┌── version matcher (tri-state) ◄────────┘          Shadow Watch / Attack Lab
        │   ▼                                                    detection rules
        │   risk scoring (3 scores) ──► correlation engine ◄────────────┘
        │                                  │  one incident per asset + time window, lifecycle, audit trail
        ├─► campaign detection (TF-IDF)    ▼
        └─► AI summary / CERT-In draft ◄── incident alerts ──► FastAPI ──► React dashboard
```

## 2. What is ML, what is rules, what is the LLM

| Component | Technique | Kind | Status |
|---|---|---|---|
| **Campaign detection** (`app/campaigns.py`) | TF-IDF vectors (scikit-learn) of title + description, cosine similarity ≥ 0.6, plus shared CVE / IOC / product / ATT&CK keys, union-find grouping. Unsupervised, no training labels. | **ML / NLP** | On. Statistical grouping of public reports, not attribution. |
| Version matching (`app/matcher.py`) | CPE vendor/product + version ranges (`packaging.version`). Tri-state result: confirmed affected / confirmed unaffected / needs verification. | Rules | On |
| Risk scoring (`app/scoring.py`) | Transparent weighted formula (section 3). Not learned: every factor is shown in the UI. | Rules | On |
| Early-warning signals (`ingestion/changes.py`) | Diffs between feed runs: new KEV entry, EPSS +0.2 or crossing 0.5, quality-filtered public exploit, CERT-In advisory, CVSS ≥ 9 on a recent CVE. | Rules | On |
| Behaviour detection (Shadow Watch, Attack Lab `app/detection.py`) | Signatures (SQL injection, command injection...), thresholds (10+ failed logins / 60 s, 15+ ports / 60 s), sequences (login after brute force, web server → shell). MITRE ATT&CK mapping. | Rules | On |
| **Isolation Forest** (`shadow_watch/ml.py`) | Anomaly detection over one-minute windows of REAL logs, one model per real sensor, temporal split. | **ML** | **On as a triage signal** (SW-ML-001, low severity; never escalates alone) |
| **LLM narrative** (`ai/grounded.py`) | Groq `openai/gpt-oss-120b`. It may only **reword** a deterministic template built from stored facts. | **LLM** | On when `LLM_ALLOW_CLOUD=true`; validated answers cached for offline replay |

**Isolation Forest, two evaluations.**
1. *Synthetic benchmark* (`windows.csv`, Member 4): rules alone 8/8 with 0 false positives; rules + model 8/8 with
   **4 false positives** and no recall gain, so on that data the model added only noise (`artifacts/shadow_evaluation.json`).
2. *Real logs* (SecRepo, CC BY 4.0: secrepo.com's web server Dec 2016, 27,532 requests; an AWS sshd 30 Nov - 31 Dec
   2014, 14,798 failed logins). Trained on the first 70% of each sensor's minutes, tested on the rest
   (`scripts/evaluate_shadow_real.py` -> `artifacts/shadow_evaluation_real.json`). There is no ground truth for real
   logs, so we compare with what our rules flag on the same held-out minutes:
   - web (1,920 test minutes): rules flag 21 (attack payloads), the model 65; they overlap on 1. The model's extra
     finds are volume anomalies with no payload, e.g. an automated Java crawler guessing paths (46 of 51 requests 404).
   - ssh (759 test minutes): rules flag 226 bursts, the model 113, overlapping on 112. The model's one extra find is a
     **distributed spray**: 7 IPs, 7 attempts on admin/ubnt/support/test/user in one minute, under the rule threshold.
   So the two are complementary: rules catch payloads and bursts, the model catches what thresholds miss. It is
   enabled only as a low-severity "unusual, needs review" finding, only on the sensor it was trained on.

**LLM guard rails.** The template (always correct, works offline) is the source of truth. The model's rewording is
rejected and the template shown if it adds any CVE/asset ID, version, IP or URL that is not in the stored facts,
changes a fact field, claims a "confirmed breach" or "zero-day", or includes commands. Look-alike characters
(non-breaking hyphens, en dashes) are folded to ASCII first, so `GOV‑VPN‑01` cannot hide an invented ID from the
check. Each panel shows `generated_by` (template / llm / llm_cached) and the validation result. Validated answers are
cached (`scripts/pregenerate_ai.py`) so the offline demo shows real LLM text.

## 3. Risk scoring (generated from CONFIG)

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

Why these choices: KEV is the strongest "act now" signal, but KEV alone used to give every KEV CVE the same
exploitation value (11 alerts tied at 99.4). A KEV floor plus EPSS spread keeps KEV on top and still separates
them. Asset context (criticality + exposure) is 45% of the score so the same CVE ranks clearly lower on an internal
or less critical system. Unknown inputs never count as 0: they get a conservative value and a visible limitation.
Exposure or a version match never proves a breach; behaviour evidence is scored separately.

## 4. Mitigation workflow

1. **Detect:** a feed change or new advisory fires a signal → the matcher checks every asset → one alert per exposed
   asset; or sensor / Attack Lab events → one behaviour incident per asset and 15-minute window.
2. **Prioritise:** the three scores and priority, each with its inputs ("Why this priority").
3. **Act:** recommended action (patch to a fixed version / verify the version / block indicators / investigate the
   host) and a remediation target from organisation policy (not a legal deadline). The **what-if patch simulator**
   re-runs the real matcher and scorer on copies of the assets to show the exposure removed by a patch.
4. **Track:** lifecycle detected → investigating → confirmed → action_required → mitigated → closed, forward-only,
   with an audit trail. Campaign view shows related threats and which assets they reach.
5. **Report:** investigation report (cites evidence IDs, lists visibility gaps) and a CERT-In report draft for the
   analyst to verify. Nothing is sent or executed automatically.

## 5. Limits (say these if asked)

Simulated organisation and behaviour; real but cached public feeds. Scores are a transparent policy, not a learned
probability of compromise. Campaigns are statistical grouping, not attribution. The LLM rewords, it does not reason.
