# Coverage and next work

Updated 1 November 2026, Asia/Kolkata, on `codex/live-india-foundation`, based on `d8ee68e`.

| Requirement | Implemented now | Remaining boundary / next work |
|---|---|---|
| Known vulnerability intelligence | Cached multi-source CVEs/KEV/advisories, normalisation, source status and existing change hooks | DEMO_MODE disables scheduled refresh. Authorised production refresh and source failure/retry operational monitoring need rehearsal |
| Exposure before an attack | Product/version matching and separate explainable scores; live lab can open exposure before requests | Reported inventory is not an independently verified software scan |
| Changing organisation inventory | Audited SQLite overrides; immediate reassessment of relevant stored intelligence; exposure reopens after rollback | Asset discovery/agent attestation, transactional workflow recovery, complete-inventory semantics and modelled CPE/platform coverage need production work |
| Indian organisation context | Fictional district-service target, government asset context, IST console, existing India intelligence, explicit CVE-linked CERT-In references and report drafts | No claim of actual Indian government deployment, CERT-In certification, unique Indian targeting or automatic compliance |
| Live requests and behaviour | Actual portal observations plus independent real Apache access-log collection; traversal/failure burst/multi-account/failure-to-success rules | Independent host/network collectors and production sensor authentication remain |
| Statistical behaviour | Frozen portal-specific Isolation Forest with actual baseline traffic, chronological holdout, provenance and future-window scoring; historical SecRepo/SHAP stays separate | Representative labelled evaluation, context and seasonality calibration remain; one ordinary holdout flag in the local small rehearsal |
| Correlated investigation | Central stored incidents, evidence citations and detector reasons in deterministic reports; optional guarded narrative generation | Temporal association is not a verified process/network causal chain; larger incidents have bounded investigation coverage |
| Response with effects | Temporary portal restriction/fix and actual blue/green district Apache replacement through a validated relay reload; rollback | Analyst approved, owned-lab scoped. No OS firewall, host isolation, package installer or external remediation |
| Response verification | Subsequent actual requests verify 429 restrictions, custom boundary 403, Apache traversal 404 and continued public 200; relay request ID joins source records | Verification proves the tested service effect, not fleet-wide eradication; old Apache remains isolated for rollback |
| Attack backtracking | Observed TCP peer/port, timestamps, original request IDs, supporting auth sequence and stored status | Does not identify a person, infer a country, trace through NAT/proxies or contact sources |
| Prediction | Preventive exposure warning can precede a controlled attempt; timestamps retained | No validated future-attack probability. Define outcomes/horizon, obtain labels, reserve future test data, compare a baseline and measure false alarms first |
| No fixture-selected verdicts | New console uses actual service requests, live rules and current inventory; rehearsal verifies runtime results | Existing dashboard demo injection/replay buttons remain labelled fixtures/replay; they are not the live-lab path |
| Two-PC demonstration | Private-address portal launcher, separate loopback control plane, one-worker shared database | Actual two-physical-PC networking/firewall/browser rehearsal has not been performed here |
| Published CVE exploitation | Actual owned Apache 2.4.49 CVE-2021-41773 dummy disclosure, 2.4.51 comparison, verified inventory and independent collector; CERT-In CIAD-2021-0039 reference | Both are historical versions; this is not a production upgrade recommendation. Custom portal still has its separate DEMO ID |
| Production service | Local opt-in control token, local Host/peer restriction, separate portal listener, persisted audit/evidence | User/tenant authentication, TLS/network policies, independent sensors, retention, backups, distributed workers, model governance and load evaluation remain |

## Recommended next implementation order

1. Rehearse `/lab` in the actual browser, then the two-PC private network. Demonstrate ordinary
   traffic, an exposure warning, an observed attempt, a verified response and recovery.
2. Improve the now-implemented lab baseline using representative non-attack traffic under
   different loads. Keep training fixed during demonstrations and reserve unseen future runs.
   Show rules-only versus rules+ML and explicit false positives; never reuse the SecRepo model.
3. Extend the independent Apache collector pattern to authorised host/network sensors. Retain
   pinned product identity, dummy-data-only lab access, original logs and verified applicability.
   Do not attach Apache's CVE to the custom portal because its vulnerability class looks similar.
4. Add an authenticated telemetry onboarding path and one constrained response adapter for
   that service. Preserve action approval, target scope, expiry, failure state and verification.
5. Only then evaluate a forecasting feature: choose a future outcome and horizon, establish
   labels and a chronological holdout, avoid looking ahead and compare a simple baseline.

Fixed rule definitions, version ranges and dummy service records are normal implementation
inputs. A fake demonstration would choose the verdict from a scenario name or return a
prewritten incident. This live path computes verdicts from incoming requests and current state.

Primary live runbook: [INDIA_LIVE_DEMO.md](INDIA_LIVE_DEMO.md). Custom portal details:
[LIVE_LAB.md](LIVE_LAB.md). Detailed current status: [STATUS_REPORT.md](STATUS_REPORT.md).
