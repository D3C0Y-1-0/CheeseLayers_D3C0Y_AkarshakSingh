# Vectra: the complete website story and judge demonstration

**Live automatic attack labels, response policy, assistant and per-tab data provenance:** [LIVE_ACTIVITY_AND_DATA.md](LIVE_ACTIVITY_AND_DATA.md).

Reviewed against the application routes, dashboard components, live controllers, startup,
intelligence/matching, scoring, investigations and evaluation code on 1 November 2026.
Starting checkout: `main` at `512c825`; frontend visual changes follow that checkpoint.

## The story in one sentence

**A fictional Indian district-service team turns scattered threat intelligence into an early
exposure warning, observes a real request against its owned lab, investigates the evidence,
changes the running service, and verifies that the same request can no longer disclose the dummy record.**

Everything you show should answer one of five questions:

1. What do we know about threats?
2. Which of our services does that knowledge apply to?
3. What has actually happened to those services?
4. What should an analyst do, and did it work?
5. What evidence supports our early-warning and AI claims?

Do not start by reciting tools, model names or the number of tabs. Introduce the organisation
and the consequence: citizen-service availability and protection of application records.
The organisation/records are fictional; no real government or company deployment is claimed.

## Preparation: distinguish the three environments

| Environment | What it contains | What to demonstrate |
|---|---|---|
| Hosted website / Render or app Dockerfile | Built React + FastAPI, its own configured DB/cache; startup can seed labelled warning examples | Dashboard breadth and cached intelligence |
| Defender's local website, port 8000 | `/app`, local `/lab`, local DB, optional window worker and Docker control | The live end-to-end demonstration |
| Second PC / private network | Requests to the defender's explicitly exposed owned portal | Independently visible requests and observed source host |

**Use the local `/app` for the live scene.** A separately hosted deployment has a different DB;
local requests do not automatically appear there. The regular app Dockerfile does not create
the Apache lab or give a hosted web service a Docker daemon. Do not expose the local control API.

Before judges arrive:

- Read [INDIA_LIVE_DEMO.md](INDIA_LIVE_DEMO.md) for the Apache setup and
  [TWO_PC_DEMO.md](TWO_PC_DEMO.md) / [SECOND_PC_HANDOFF.md](SECOND_PC_HANDOFF.md) for the second PC.
- Start the local app with the lab flag, owned Apache targets, independent collector and the
  custom portal if using the LAN behaviour scene. Build the frontend after UI changes.
- Prepare actual ordinary portal traffic and freeze the portal-specific model before the
  presentation if showing live ML. Never train on the attack being evaluated.
- Open `/app`, `/lab` and one incident tab. Keep the attacker terminal/browser visible beside
  the defender. Confirm one ordinary request succeeds and is observed before beginning.
- Release temporary restrictions before testing a patch: an active 429 block prevents a request
  reaching the patched document handler and therefore cannot verify that patch.
- If the lab was left fixed by rehearsal, explicitly restore the vulnerable OWNED backend for
  the next run, then reassess before sending the next controlled attack.
- Preserve case history. Avoid the global reset controls while collectors/models are active;
  those clear correlated events but leave raw lab records/checkpoints/models in place.
- Copy the values currently visible in the UI into speaker notes. Feed counts, cohort sizes,
  lead days, source states, asset counts and model scores are runtime values, not fixed claims.

## Full tour: approximately 11–13 minutes, covering the whole website

Assign one narrator/defender operator and one attacker operator. A third person should manage
time and be ready to open the requested evidence; the fourth handles technical questions.

### Scene 1 — “This is the service we are protecting” (30 seconds)

**Screen:** landing `/`, then Open dashboard.

**Say:** “Imagine a district IT team responsible for citizen services. They receive many
advisories, own different software versions, and have limited time to decide what matters.
Vectra connects that knowledge to their services and to what their sensors actually observe.”

**Show:** architecture flow briefly. If using the landing score controls, describe them as an
illustrative score explanation driven by configured factors, not an actual incident or patch.
Do not scroll through every landing animation. Its job is orientation; proof follows in `/app`.

**Bridge:** “First, let's look at the analyst's workspace.”

### Scene 2 — “From many sources to one work queue” (45 seconds)

**Screens:** `/app/soc`, then `/app` Command Center.

**Show:** SOC open-incidents arc, intelligence count, source/cache state; then the severity
distribution, priority queue and source cards in Command Center. Read current counts only.

**Say:** “This brings our intelligence and incident state together. The API-connected badge
means the application is connected. Feed freshness is separately visible. This demonstration
uses cached public intelligence, while the owned lab can produce new telemetry live.”

The globe is an orientation visual. Feed-origin arcs/sector nodes are not tracks of live
attackers. Optional geolocation represents IP registration data, not a person's location;
an unavailable database should stay unavailable. A source's country is not attack attribution.

**Bridge:** “But a large threat count is not yet a useful warning. We need relevance.”

### Scene 3 — “Known vulnerability × installed technology” (60 seconds)

**Screens:** `/app/threats`, `/app/assets`.

**Show:** search a relevant CVE, open its detail cards, original reference, CVSS/KEV/EPSS and
matched-asset linkage. Then show the corresponding inventory row and installed version.
The asset-sector tiles and internet-facing/criticality fields explain organisational context.

**Say:** “A CVE identifies a specific vulnerability. KEV says exploitation has been confirmed
somewhere; it does not say our target was attacked. We compare affected products and versions
with inventory, then prioritise the service's exposure.”

Use the lab Apache case for the main live thread. Other synthetic assets demonstrate broader
inventory/sector matching. Null means unknown. An uncertain version is not silently confirmed
affected, and an inventory edit is not an actual software installation.

**Optional:** open the summary and request Hindi. This is best-effort machine translation of
narrative fields; the UI shows the returned language and fallback. Rehearse it first. Do not
depend on a live cloud response or present English fallback as successful Hindi translation.

**Bridge:** “The warning must also change when the intelligence or the environment changes.”

### Scene 4 — “What changes the warning?” (30 seconds)

**Screen:** `/app/signals`.

**Show:** 24-hour cards, seven-day signal bars and one before/after source record.

**Say:** “A KEV addition, EPSS change, public exploit reference or relevant CERT-In advisory
can trigger reassessment. Inventory changes are another trigger. These source-change warnings
are different from requests observed by a sensor.”

If the record says simulated, call it a seeded/replayed example. `DEMO_MODE` disables scheduled
collection, and `prestart.py` can seed labelled warnings. Do not say an advisory was published
or freshly fetched during the demo unless the actual collector evidence establishes that.

**Bridge:** “Related records can also help the team find a larger pattern.”

### Scene 5 — “Find relationships without inventing an attacker” (30 seconds)

**Screen:** `/app/campaigns`.

**Show:** composition chart, one emerging association, sources and one shared key; contrast a
vendor patch batch with an attacker-campaign hypothesis.

**Say:** “Shared indicators, meaningful metadata and TF-IDF text similarity help us group
related intelligence. The group retains its linking evidence. Similar text or a same-day
vendor release is not proof of a common attacker.”

**Bridge:** “Now let's test whether an early warning connects to actual activity and action.”

### Scene 6 — “Warn, attack, change the service, prove the result” (3 minutes)

**Screens:** local `/lab` with the district Apache panel, plus the attacker request display.
Keep `/app/incidents` ready. Use original request IDs to connect the displays.

| Action | Show / say | Proof |
|---|---|---|
| Discover/reassess before this controlled attempt | “The verified Apache version matches CVE-2021-41773. Here is the CERT-In reference.” | Binary/image provenance and exposure assessment exist before the next request |
| Ordinary notice request | “Normal service remains usable.” | Actual HTTP 200 and a source record, not an inserted incident |
| Dummy traversal request | “The owned affected service exposes this synthetic internal record.” | Actual response marker/status; independent Apache log and matching relay-generated request ID |
| Open the central incident | “The source record produces a deterministic finding and a prioritised case.” | Event ID, original path, source timestamps, observed binary version and applicability |
| Replace with fixed Apache | “We change the backend behind the same district endpoint.” | Verified fixed binary, generated relay configuration/reload and reassessed inventory |
| Repeat identical traversal, then public notice | “The original path now fails while the public service still works.” | Traversal 404/403 with no dummy marker, public notice 200, action verified |

The actual code uses blue/green replacement to the 2.4.51 comparison binary, not an OS package
installer. That historical version is fixed for the demonstrated traversal CVEs, not every
later vulnerability. The old backend remains isolated for rollback; do not claim fleet-wide
eradication. Never change to the comparison URL and present that alone as patching the original
endpoint: the important proof is that the SAME district URL changes behaviour.

**If the venue needs a simpler two-PC scene:** use the direct custom portal on 8010 for
traversal/login bursts, observed LAN peer, temporary 429 block, release, actual boundary fix
and subsequent 403 while the notice stays 200. That custom weakness has a DEMO ID, not Apache's
CVE. Follow with the local Apache panel as the product-specific CVE proof.

The portal can show a source host on the network. Apache's Docker/relay path can hide the
original peer behind NAT. Neither identifies a person or locates the attacker geographically.

**Bridge:** “The detection is useful because an analyst can inspect why it happened.”

### Scene 7 — “An explainable case, not just a red number” (60 seconds)

**Screen:** `/app/incidents` → the new incident detail.

**Show:** queue/lifecycle view, three score gauges, recent evidence timeline, rule/source
details and investigation. Expand one source record instead of reading every timeline entry.

**Say:** “Vulnerability priority, behavioural suspicion and evidence confidence are separate.
They are triage measures, not interchangeable probabilities. The explanation cites stored
evidence and states what it cannot establish.”

The LLM is optional narrative assistance. The shown badge tells whether the wording is
template, cached LLM or live LLM; rules/matching and model decisions are not delegated to it.
Recommendations alone are not executed responses. The live action ledger/verification is the
proof of the response. Lifecycle acknowledgement records analyst progress, not a substitute
for technical verification. Preserve the incident after fixing current exposure.

### Scene 8 — “Where ML adds a different kind of warning” (45–60 seconds)

**Screen:** live portal ML panel in `/lab`; optionally a historical ML incident's SHAP panel.

**Show:** model ID, actual training window count, temporal split, holdout flags and the new
burst's feature vector/score. Keep the rules-versus-ML distinction explicit.

**Say:** “Rules catch known patterns. This model asks whether a completed window is unusual
relative to this sensor's own earlier traffic. It remains frozen during evaluation.”

The portal model uses five-second active windows with two seconds' finalisation grace; it is
not the SecRepo model. Historical SecRepo uses separate web/SSH history and supports SHAP/PDF
explanations. Do not attach those historical SHAP charts to the live portal model.
An unusualness percentile is not attack probability. Show holdout flags, including benign
operator-baseline flags, rather than claiming perfect detection. Do not call a model outlier
a discovered zero-day. The model does not automatically block.

### Scene 9 — “Broader traffic, same inspectable rules” (40 seconds)

**Screen:** `/app/attack-lab`.

**Show:** one captured traffic profile, its replay graph, one threshold/signature and original
line. Optionally paste a changed request into Analyse to show the parser computes its result.

**Say:** “This is historical public honeypot/firewall traffic analysed and replayed against
our simulated inventory. It gives us additional cases and controls beyond our local lab.”

Do not claim these replay animations are current live packets hitting the organisation. A
signature-associated CVE does not by itself prove successful exploitation. Keep “No rule fired”
controls available if asked about false positives. The rulebook/ATT&CK mapping is expandable.

### Scene 10 — “Measure decisions and examine early-warning evidence” (60 seconds)

**Screen:** `/app/analytics`.

**Show:** sector cards, one patch what-if before/after result, backtest coverage donut and the
largest/near-zero/missed dated examples. Read the NEW-CVE cohort values on screen.

**Say:** “The what-if models exposure changes on copies; it does not install a patch. We
already showed actual replacement separately. The backtest asks whether dated source signals
preceded a later KEV listing, with strengths and misses visible.”

Read `flagged_before_kev`, `population`, `pct_flagged_before_kev`, `median_lead_days` from the
displayed cohort. Never reuse fixed example numbers such as 32/97 without checking the current
cohort. A KEV listing is confirmation of exploitation somewhere, not the first attack date.
This retrospective source-date comparison does not prove when a production system could have
collected every signal. Explain the missing-source/sampling/cohort limits when asked.

**Prediction has three different meanings here:** preventive exposure before our controlled
request; statistical detection of observed unusual behaviour; retrospective warning lead time
relative to KEV. None is validated forecasting of a specific future organisational compromise.

### Scene 11 — “Make the evidence useful to an Indian analyst” (40 seconds)

**Screens:** Analytics India panel, then the incident's CERT-In draft.

**Show:** actual CERT-In advisory links, reported India-related intelligence by sector/group,
then prepare a draft, preview its evidence and optionally download Markdown.

**Say:** “India-first means relevant advisories connected to the organisation's technologies,
service/sector context, IST evidence and an analyst-reviewed reporting workflow. It does not
mean every global CVE uniquely targets India.”

Public ransomware reports are not compromises in our fictional organisation. A generated
draft is not sent to CERT-In and is not automatic compliance. Review missing fields and the
executed action ledger before filing. Hindi is best effort; use the actual returned-language
and generation badges. STIX export and SHAP PDF are useful optional take-away artifacts.

### Closing (20 seconds)

“We connected threat knowledge to a service, warned before a controlled attempt, observed
the request, explained the evidence, changed the running endpoint and verified the outcome.
Vectra makes that chain visible for an Indian organisation, while keeping uncertainty visible.”

## Seven-minute version

Landing 15s → SOC/Command Center 35s → Threats/Assets/CERT-In relevance 45s → live attack and
same-endpoint replacement 150s → incident evidence/three scores 55s → ML contrast 40s →
Analytics backtest/India/draft 50s → close 20s. Keep Campaigns, Signals, replay, exports,
Hindi and detailed model explanations ready for Q&A rather than rushing every interaction.

## Feature map: every page has a purpose

| Screen/component | What to mention | Observable source |
|---|---|---|
| Landing flow / score lab | Architecture and illustrative scoring inputs | Browser illustration/config, not a live incident |
| SOC globe / ask / incident arc | Navigation, situational overview and contextual search | Overview, alerts, inventory, threat search; optional generation/geo |
| Command Center | Incident priorities, publication trend, source health | `/api/overview`, `/api/alerts`; status distinct from collection freshness |
| Threat detail / AI summary / STIX | Specific vulnerability facts, references and asset relevance | `/api/threats`, summary endpoint, STIX export |
| Assets | Product/version, sector, criticality and declared exposure | `/api/assets`; lab registration supplies verified binary snapshots |
| Early warnings | Source changes and before/after values | `/api/signals`, summary; simulated seeds remain labelled |
| Campaigns | Relationships, emergence, patch-batch distinction | `/api/campaigns`, group reasons and member records |
| Exposure / patch what-if | Sector posture and modelled decision impact | Posture and patch-impact endpoints |
| Lead-time examples | Measured retrospective signal ordering and misses | Lead-time/cohort/example endpoints |
| Live console | Owned request-driven detection, response and verification | Actual portal/Apache services, independent logs and action ledger |
| Incident / AI / evidence | Three scores, lifecycle, original records, bounded citations | Alert/evidence/investigation endpoints |
| ML / SHAP / PDF | Sensor-specific outliers and explanation of historical model | Lab model windows; separate historical SHAP APIs |
| Attack simulation / analyser | Captured public traffic, graph, thresholds and controls | ISC cache replay and text analysis; not live external exploitation |
| CERT-In draft / Hindi | Analyst-facing preparation and language assistance | Draft/translation endpoints; nothing automatically submitted |

## Answers to predictable judge questions

| Question | Precise answer |
|---|---|
| “What is real?” | Public intelligence, historical captured traffic, owned lab service requests, source records and verified response effects. Targets/records are fictional/synthetic. |
| “Why preload CVEs?” | They are reference knowledge that enables exposure warning before an attack; telemetry is a separate incoming stream. |
| “Is everything AI?” | No. Matching, signatures and scoring are explicit; Isolation Forest supplies outliers, TF-IDF supplies text relationships, optional LLM supplies narrative. |
| “What does 99% mean?” | Relative unusualness against a specific training population, not 99% attack probability or detection accuracy. |
| “Did you predict an attack?” | We demonstrated preventive exposure warning and measured retrospective lead time; future attacker timing/compromise forecasting is not validated. |
| “Can you trace the attacker?” | We can preserve observed peers, request IDs and timestamps. NAT/proxies and identity attribution have limits. |
| “Did patching really happen?” | The original district URL changes from an affected to a verified fixed backend; repeated HTTP checks prove the tested effect. |
| “Are all vulnerabilities gone?” | No. The verified result concerns the demonstrated CVE/behaviour; other vulnerabilities and investigation work may remain. |
| “Why India?” | Service context, CERT-In relevance, sector/IST views and reviewable reporting/language assistance, not a claim of government adoption. |
| “Can it run nationally today?” | It is an integrated prototype. Production identity/tenant isolation, authorised sensors, calibration, retention, scale and operational validation remain. |

## Contingencies

- Venue Wi-Fi failure: run owned loopback requests on the defender and say it is a one-PC
  rehearsal. Do not call that a completed two-PC network demonstration.
- LLM/translation unavailable: use template/cached wording and the returned language badge.
- Geo unavailable: show the evidence path, not invented map locations.
- Collector not delivering: inspect worker logs/status and request ID. Do not substitute fixture
  injection while calling it live independent telemetry.
- Unexpected ML result: inspect features and holdout flags. Do not adjust a threshold silently
  to force the desired classification.
- Time overrun: complete the same-endpoint verification before optional breadth. One causal
  chain with evidence is more useful than unfinished clicks through every tab.

## UI changes made for this presentation

All `/app` routes retain their underlying APIs. The workspace now has workflow navigation,
source-aware connection state, metric cards, severity/group distributions, sector summaries,
three-score gauges, a lifecycle rail, compact recent evidence, warning-change inspectors,
before/after impact cards and dated backtest tracks. Full explanations/references/raw details
remain expandable. Counts are explicitly scoped to the whole dataset, current view or page.
The existing SOC globe, attack graph, SHAP bars, exports and live console are preserved.

TypeScript/build/lint validation and any unavailable browser checks are recorded in the
current handoff. Backend regression history belongs in [STATUS_REPORT.md](STATUS_REPORT.md);
a frontend-only change does not imply a newly repeated full backend suite.
