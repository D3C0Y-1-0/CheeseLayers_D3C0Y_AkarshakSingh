# Member 4: explanation and judge demonstration

Current live implementation/runbook: [INDIA_LIVE_DEMO.md](INDIA_LIVE_DEMO.md), including a real
owned Apache CVE target, actual backend replacement and a separate live portal ML baseline.
The historical SecRepo explanation below still applies to that separate model/replay path.

## The one-sentence story

Vectra joins known vulnerability exposure with suspicious behaviour, prioritises it for this
organisation, and gives an analyst the underlying evidence and next investigation steps.

Threat intelligence describes what could affect software. Behavioural telemetry describes what
was observed. Neither a matching CVE nor a statistical outlier proves a breach.

## The three jobs in Shadow Watch

1. **Rules recognise explicit patterns:** HTTP error bursts, an unexpected web-server shell child,
   first-seen outbound destinations, and failed-login bursts. Rule findings carry evidence IDs.
2. **Isolation Forest scores unusual windows:** only for the two SecRepo real sensors. It sees
   numeric one-minute aggregates, not URL payloads or an attacker's intentions. It runs as an
   additional low-confidence finding when an explicit rule did not fire.
3. **Correlation and scoring assemble an investigation:** same-asset/time findings are persisted
   and scored by the shared incident engine. A temporal relationship is not proof of causality.

The LLM does not make these detections. It can reword evidence-grounded report fields, with
templates/cached responses when the provider is unavailable. The three central scores are
vulnerability priority, behavioural suspicion and evidence confidence.

## What Isolation Forest actually does

A minute is a vector of measurements. Web features are request rate, 4xx ratio, client count
and failed authentication count. SSH features are failed logins, unique sources, unique users
and invalid-user ratio. The model uses random feature splits; points separated with unusually
short paths are potential outliers. Official implementation details:
https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html

Current configuration is 200 trees, seed 42 and contamination 0.02, independently for web and
SSH. Each sensor uses its earliest 70% of active minutes for fitting. This preserves chronological
separation from the held-out portion; it does not establish that every training minute is benign.
The contamination setting helps select an outlier threshold; it is not measured accuracy.

Synthetic scenarios deliberately stay rules-only: the synthetic evaluation had 8/8 positives and
0/142 false positives with rules, but adding ML produced 4/142 false positives with no recall gain.
Historical SecRepo logs have no ground-truth attack labels. Their evaluation shows which windows
rules and ML flag, not a validated precision/recall for attacks.

The distributed-spray example has 7 failures, 7 sources and 5 usernames. The explicit threshold
is 10 failures, so it does not fire. The selected historical window gets an ML outlier finding,
low confidence/priority, with score -0.074 and relative unusualness percentile 99.3 in the recorded
rehearsal. The percentile is relative to sensor history, not a probability of attack.

This is a chosen illustrative held-out case. Do not present a chosen successful demonstration
as a random blind evaluation or claim generalised detection accuracy.

## Preparation before judges

1. Start the app with `scripts/start.ps1 -SkipBuild -Background` or double-click `Start Vectra.cmd`.
2. Open http://127.0.0.1:8000/app and check the connected/demo labels.
3. Rehearse **Real distributed spray (ML)** and optionally **Real crawler anomaly (ML)** to warm
   model/case-selection caches. Keep the same backend process running afterward.
4. Press **Reset demo alerts** before the presentation. This clears incidents/events and preview
   state; the fitted model/case-selection caches remain warm in that process.
5. Keep the key incident/evidence screens ready. Record a short manual backup if the display
   machine/network is unreliable. The core demo needs no live feed or model-provider request.
6. Show template/cached/live model badges honestly. A missing provider key does not disable
   detection or investigation. Geolocation is optional and is not needed for the core story.

## A focused five-minute presentation

| Time | Action | Evidence to show | Message |
|---|---|---|---|
| 0:00–0:25 | Command Center | Dataset totals and simulated-inventory label | Public intelligence, historical traffic, simulated organisation |
| 0:25–1:05 | Inject known CVE; open its incident | Affected FortiOS version, patched twin, score inputs | Prioritise exposure before requiring evidence of exploitation |
| 1:05–1:50 | Inject suspicious behaviour; open incident and stored sensor evidence | SW-HTTP-001, SW-PROC-001, SW-NET-001 and three evidence IDs | Investigate a no-CVE behavioural chain; no zero-day claim |
| 1:50–2:10 | Inject benign maintenance | Zero findings/escalated incidents; retained observations | High traffic alone is insufficient |
| 2:10–3:10 | Real SSH brute force, then Real distributed spray (ML) | First: SW-AUTH-001; second: SW-ML-001, counts, outlier score and low confidence | Rules catch explicit bursts; ML adds an unusual combination below the threshold |
| 3:10–4:10 | Attack simulation; select a known-CVE profile and replay | Animated log flow, matched signatures, source lines and asset/CVE verdicts | Real captured requests replayed locally, not live exploit execution |
| 4:10–5:00 | Investigate an incident; show patch what-if | Evidence citations/limits and modelled exposure reduction | Analyst gets a reasoned next step; proposed remediation is not executed |

If time is short, keep the CVE, no-CVE, benign and ML contrast. Campaigns, SOC globe, Hindi and
CERT-In drafts are supporting screens or answers to follow-up questions, not prerequisites.

For Attack Lab, say **"requests match known-CVE exploit signatures"**, not "we proved those CVEs
were exploited." Source records can be date-only and replay timing/target mapping is synthetic.

## What you should say when challenged

- **Is this all AI?** No. Matching, signatures and scoring are explicit rules. Isolation Forest
  supplies statistical triage; TF-IDF helps campaign grouping; the optional LLM supplies narrative.
- **Does 99.3 mean 99.3% attack confidence?** No. It is relative unusualness against historical
  sensor minutes. Evidence confidence and incident priority are separate fields.
- **Did you discover a zero-day?** No. The behaviour path can flag suspicious activity without a
  known CVE; identification of a new vulnerability would require separate research/verification.
- **What if ML is wrong?** Model-only findings stay low severity, need review, and trigger no
  blocking or remediation. The crawler case is useful for explaining that unusual can be benign.
- **Is your model validated in production?** No. Real logs are historical and unlabeled; results
  require representative labelled evaluation before any production accuracy claim.

## Improvement order

Implemented and rehearsed locally: held-out candidate windows are now scored in a batch rather
than calling the forest twice for each window. Cold HTTP replay of the distributed-spray case
fell from 23.09 seconds to 6.65 seconds on this machine after restarting the server. It retained
the same selected minute, -0.074 score, 99.3 percentile and low-severity finding. These are local
measurements, not a general latency guarantee. The focused rules/ML/real-log/integration suite
passed 43 tests, including batch-versus-direct sklearn score and decision comparisons.

1. Keep the ML demonstration responsive: batch forest scoring, cache selected cases and rehearse
   cold startup. Preserve the same model, feature schema, scores and flag decisions.
2. Show rules and ML side by side in a dedicated comparison panel: counts, baseline, rule
   threshold/verdict, model verdict, raw score, confidence and source evidence.
3. Add contextual baselines for real deployments: per-asset roles, approved changes, known
   egress destinations, traffic seasonality and verified process/network identifiers.
4. Evaluate labelled benign and suspicious examples across time and independent sensors;
   compare rules versus rules+ML using false positives and recall. Calibrate on a validation
   portion and reserve a later untouched test portion.
5. Standardise correlation windows and improve provenance joins. Production authentication,
   authorised live sensors, versioned model monitoring and deployment hardening follow that.

References for temporal evaluation:
https://scikit-learn.org/stable/modules/cross_validation.html#time-series-split
