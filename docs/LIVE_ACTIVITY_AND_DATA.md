# Live activity, response and data provenance

This update adds automatic request classification and visualisation; the operator never
selects an attack type. It is a bounded HTTP sensor, not whole-PC packet capture.

## Start and observe

1. Start the defender: `powershell -ExecutionPolicy Bypass -File scripts/start.ps1 -Background -LiveLab -SkipBuild`.
2. Open `http://127.0.0.1:8000/lab` to initialise the profile. Keep this control plane local.
3. Start the portal on this machine's actual private address:
   `powershell -ExecutionPolicy Bypass -File scripts/start-lab-portal.ps1 -BindAddress 10.120.134.199 -Background`.
   That address must still belong to the defender. This command does not add firewall rules.
4. Open `http://10.120.134.199:8010/` on the second PC. It has a functional dummy login form
   (`demo-user` / `lab-only-password`), public notice link, actual status and event reference.
5. Send owned-lab requests; the new /lab graph and feed follow actual stored observations.
   Ordinary requests, findings and 429 enforcement responses are distinct. Existing history
   is not replayed as live on page load. Replay retained events explicitly labels recorded playback.
6. The independent Apache collector continues to supply its own observations to the graph.
   The existing Apache controls, evidence, patch comparison and verification remain separate.

The visual polls every two seconds. Retention in this view is up to 100 portal and 30 Apache
records, not a lifetime counter. It animates at most the latest 20 new records per poll to
bound browser load and labels sampling. The full stored event references remain inspectable.
It cannot display attacks against uninstrumented ports, OS processes, SSH or another service.

## Automatic classifications and evidence

| Observed pattern | Rule | Meaning / limits |
|---|---|---|
| Document name crosses parent directories | LIVE-WEB-001 | Traversal attempt; status records the actual handler outcome |
| Strong SQLi / command injection / traversal / XSS URL signature | LIVE-HTTP-SIGNATURE | Reuses replay signature definitions; type(s) computed from request, not a scenario selector |
| Parent directory in another observed URL | LIVE-WEB-002 | Traversal attempt, not proof of host-file disclosure |
| 8 distinct missing paths from one peer in 60s | LIVE-WEB-003 | Possible discovery scan; ordinary missing pages below threshold stay unflagged |
| 10 login failures from one peer in 60s | LIVE-AUTH-001 | Possible guessing burst, not proof of compromise |
| Success after 5 failures for same username/peer in 60s | LIVE-AUTH-002 | Suspicious sequence; account ownership unverified |
| Failures against 5 usernames from one peer in 60s | LIVE-AUTH-003 | Possible password spraying |
| 30 failures for one username across at least 3 peers in 60s | LIVE-AUTH-004 | Possible distributed guessing; not botnet attribution |
| Apache collector's traversal signature | APACHE-TRAVERSAL-001 | Independent access log and verified product/version context |
| Frozen-baseline unusual portal window | LIVE-ML-001 | Separate statistical triage, never automatic block |

Normal traffic is observed too. Unsupported patterns remain no rule fired; this is not proof
of safety. SQL/XSS/command signatures do not execute a payload or create a CVE association.
The dummy portal has no SQL database, command executor or real personal records to exploit.
The detector ignores password bodies/cookies/authorization headers; bounded URL query fields
are inspected after redacting sensitive parameter names. Do not put personal data into lab URLs.

## Blocking and the reported zombie/bypass concern

Enforcement now runs before routing and body validation, across all portal paths and verbs.
Changing URL, sending malformed JSON, opening a new source port or supplying X-Forwarded-For
cannot escape an active restriction for the same observed TCP peer. IPv4-mapped IPv6 is
normalised. Control and evidence must refer to that exact peer.

The default manual duration is 300 seconds. With renew quiet period enabled, an observed
restricted retry extends expiry by the block's original duration, with retry count/time in
the action ledger. It does not manufacture another attack finding. After a full quiet period,
expiry is intentional; Release overrides enforcement. Repeated polling of state never renews it.
A genuinely different peer is a different scope. This cannot identify an attacker through NAT,
stop all distributed sources, or firewall the Apache listener/other applications.

Auto-block is OFF by default. Enable and save it in /lab to apply an audited restriction after
a deterministic finding. The triggering request is already completed; the next is restricted.
ML never auto-blocks. False positives remain possible, so keep evidence/release controls visible.
Release the peer before verifying a boundary patch: a 429 does not verify that patch.

## Assistant and reports

The SOC Ask widget previously searched literal keywords and generated CVE summaries; it did
not execute general NLP tasks. It now recognises bounded stored-data queries such as show open
incidents, high priority incidents, show assets, where does data come from and explain prediction.
CVE/vendor/hostname searches remain available. Newer answers cannot be overwritten by old requests.

The /lab assistant additionally understands block latest peer, block an explicit IP, release an
IP and patch portal. It returns an exact target/evidence/scope proposal. Only Execute reviewed
portal action invokes the existing local/token-protected action API, which revalidates evidence.
Queries do not mutate, arbitrary tools/commands are unsupported, and no task is claimed complete
when it only returned a link. No cloud model chooses executable actions.

Report controls default to Evidence only: deterministic templates and stored citations, bypassing
both the model and its cache (`?evidence_only=true`). This avoids generated narrative but does not
validate external source truth or eliminate errors in templates. Analyst review remains necessary.
Optional LLM mode rechecks cached outputs, rejects factual-key overrides, unknown identifiers,
new numeric claims, commands and compromise/attribution overclaims. These are filters, not a
mathematical guarantee of semantic correctness. Hindi requires optional model translation;
evidence-only mode returns honestly labelled English fallback. No report is sent to CERT-In.

## Is each tab hardcoded?

| Screen | Actual source | What is deliberately predefined |
|---|---|---|
| Landing | Browser illustration | Architecture visuals and interactive example scoring |
| SOC / Command Center | Overview/alerts/assets/posture APIs | Publisher map locations and layout; bundled samples if API unavailable |
| Threats | SQLite records loaded from public-feed cache/collectors | Labelled demo weaknesses and curated lab reference metadata |
| Assets | Inventory fixture plus SQLite overrides and verified lab registrations | Original 40 fictional organisational assets |
| Incidents/detail | Correlation/scoring of stored telemetry or explicit replay | Rule thresholds/scoring policy; replay targets are fictional |
| Signals | Stored source-change records | Labelled seeded demo changes when seeded; not freshly published advisories |
| Campaigns | Shared identifiers/metadata plus TF-IDF grouping of stored threats | Algorithm/threshold choices, not hand-entered membership counters |
| Analytics | Calculated posture, what-if and retrospective source-date cohorts | Method/policy and input datasets; what-if is not executed patching |
| Attack Replay | Historical SANS ISC traffic and parser/rule results | Recorded traffic is replayed; it is not new packets against the lab |
| /lab live view | Actual portal observations, independent Apache logs, real action ledger | Dummy targets/records, known detector definitions and UI layout |
| Investigations / drafts | Stored facts and citations; optional model rewording | Deterministic template text; generation/fallback explicitly labelled |

API-connected means connected to the backend, not fresh external feeds. DEMO_MODE disables
scheduled external collection but permits actual live portal requests. Hosted and local databases
are separate. Sample/error notices must remain visible when an API is unavailable.

## Verification scope

Regression cases exercise automatic signature types, benign controls, observation redaction,
threshold edges, distributed failures, route/method/body/header/connection block bypass attempts,
renewal/quiet expiry/release, action proposals without execution, console control IDs and strict
report/cache validation. Production build and lint verify dashboard integration. Test outcomes
are recorded in CLAUDE.md. Native rendered-browser review and a real second-PC rehearsal are
separate checks; do not describe API/test-client checks as those completed demonstrations.
