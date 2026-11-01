# Live lab: both detection paths

For the main actual Apache CVE attack/replacement/verification presentation, use
[INDIA_LIVE_DEMO.md](INDIA_LIVE_DEMO.md). This document describes the separate custom portal.

This lab generates actual requests, observes their actual results, stores evidence, correlates
incidents and enforces reversible responses. The organisation, records and assets are fictional.
The custom portal weakness is **DEMO-VULN-LAB-TRAVERSAL (CWE-22), not a published CVE**.
No real Apache/Fortinet exploitation is claimed by this lab. Real CVEs are assessed separately
against the reported inventory with the existing product/version matcher.

## Start on the defender PC

From the repository root, stop the registered server if already running, then enable the lab:

```powershell
.\scripts\stop.ps1 -Port 8000
.\scripts\start.ps1 -SkipBuild -Background -LiveLab
```

Open `http://127.0.0.1:8000/lab` on the defender. This initialises the additional lab asset,
dummy vulnerability and database tables. The original 40 fixture assets remain; inventory
updates are stored as SQLite overrides, not written into the fixtures. Restarting preserves
overrides, observations and actions when using the same database.

In another terminal start the portal:

```powershell
.\scripts\start-lab-portal.ps1
```

The default portal address is `http://127.0.0.1:8010`. For two PCs on your private lab network,
use the defender's specific private LAN address instead:

```powershell
.\scripts\start-lab-portal.ps1 -BindAddress 192.168.1.20
```

Replace the example address with the defender's assigned address. Allow that portal port on
the private network if Windows asks. Keep Vectra's port 8000 on loopback. Only the portal
listener is exposed to the second PC; it has no console, inventory or response endpoints.
Both processes must use the same `VECTRA_DB_URL` (or the default database). Use one worker
per listener. `--no-proxy-headers` preserves the actual TCP peer rather than trusting supplied
forwarding headers. Stop the portal with Ctrl+C; stop Vectra with `scripts/stop.ps1`.

## Path one: preventive exposure and changing inventory

In the local console, select `LAB-GOV-WEB-01` and reassess exposure **before sending traffic**.
The matcher discovers version 1.0.0 inside the lab advisory's affected range and persists an
exposure alert without any attack request. This is preventive warning, not attack prediction.

Also select a fixture asset such as `PWR-FW-01` and reassess. Its reported FortiOS version
matches the stored real `CVE-2024-21762` metadata. Change the reported version to `7.4.11`
(set a stale version-specific CPE to `null`), give an observation reason and record the change.
Exposure is rechecked and the old alert is retired when the matcher confirms it is outside
the affected range. This **records an inventory observation; it does not install FortiOS**.

Relevant stored CERT-In advisories are linked by explicit CVE membership, not by keyword
similarity. Their references and retrieval timestamps are returned. No matching advisory
means an empty list, not invented Indian provenance. Sources remain independently refreshed
by the existing ingestion pipeline; DEMO_MODE keeps scheduled collection disabled.

The existing `on_new_threat` hook handles new intelligence signals, including resolving a
CERT-In advisory's CVEs to their version-range records. The local reassessment endpoint
handles inventory change or an explicit operator recheck. These triggers share the matcher.
Newly reported empty software inventory is marked incomplete and returns needs-verification
for previously relevant intelligence; it is not treated as proof of complete removal.

## Path two: actual requests, behaviour and response

From the second PC (or another terminal on this PC), use your lab portal address:

```powershell
$portalBase = 'http://127.0.0.1:8010'
Invoke-WebRequest "$portalBase/document?name=notice.txt" -UseBasicParsing
Invoke-WebRequest "$portalBase/document?name=../internal/dummy-records.json" -UseBasicParsing
```

Vulnerable lab mode returns a dummy record for the second request. The custom document service
incorrectly permits escaping its `/public` namespace into `/internal`. Its outer virtual store
contains only two dummy documents: it never opens host files, credentials or real records.
The detector independently recognises parent-directory segments in the observed name. A
generic traversal attempt does not acquire a real CVE association.

In `/lab`, inspect the observation: request name, returned status, byte count, timestamp,
TCP peer/port, rule, evidence IDs and attribution limit. The observation and security event
are persisted and the existing correlator creates/updates an incident on the main dashboard.
The console polls every two seconds; this is polling, not WebSocket streaming.

Choose one response at a time:

1. **Temporary block:** select a finding, approve a 15–300 second restriction, then make another
   request from that same PC. It returns HTTP 429, verifying enforcement. Another peer remains
   unaffected. Release it or let it expire. The restriction is in this portal, not an OS firewall.
2. **Patch:** apply the document boundary fix. This changes actual service behaviour and its
   reported version to 1.1.0, then reassesses exposure. A subsequent traversal returns HTTP 403
   and verifies the action; the public notice still returns HTTP 200. Rollback restores 1.0.0,
   restores the lab flaw and reopens the exposure alert.

Do not demonstrate a block and patch simultaneously: an active 429 restriction prevents the
request from reaching the patched document handler, so it cannot verify the patch.

For authentication behaviour, POST real login requests:

```powershell
1..10 | ForEach-Object {
    try {
        Invoke-RestMethod "$portalBase/login" -Method Post -ContentType 'application/json' `
            -Body '{"username":"demo-user","password":"wrong"}'
    } catch { Write-Host 'Expected rejection; check Vectra for the observed result.' }
}
Invoke-RestMethod "$portalBase/login" -Method Post -ContentType 'application/json' `
    -Body '{"username":"demo-user","password":"lab-only-password"}'
```

Live rules: 10 failures from one peer in 60 seconds; failures against 5 distinct usernames
from one peer in 60 seconds; successful login after at least 5 failures for that username and
peer in 60 seconds. Supporting request IDs are retained. A success-after-failures sequence
needs investigation: it does not establish who owned the successful session. Passwords are
never stored in observations. The dummy account grants no access to host resources.

## India context, attribution and predictive claims

Use the India intelligence panel, real CERT-In references, an IST timeline and analyst-reviewed
incident draft. An India advisory is relevant because of installed technology, not because
every linked vulnerability uniquely targets India. Source index:
https://www.cert-in.org.in/s2cMainServlet?pageid=VLNLIST02

The TCP peer is an observed network source, not a verified attacker, physical location or
country. NAT/proxies can conceal the original source. Vectra does not trace through other
systems or contact the source. A spoofed X-Forwarded-For header cannot change this lab peer.

The historical SecRepo Isolation Forest is deliberately **not applied to this new sensor**.
The implemented lab-specific forest instead learns actual portal traffic in complete five-second
active windows, with two seconds' finalisation grace. Start collection and explicitly freeze it
after at least 30 eligible windows/four distinct training vectors. Earlier 80% trains; later 20%
is a chronological operator-baseline holdout. Known rule-positive/429 windows are excluded.
Future evaluation cannot retrain the frozen model or use a window straddling freeze time.
Vectors, original request IDs, model/config/library version and fingerprints persist as JSON.
Historical ML replay and SHAP explanations remain separate. See the primary runbook for the
actual three-minute preparation script and measured holdout flags.

No future-attack probability is computed. Show the timestamp of the exposure alert preceding
the first observed attempt as a controlled demonstration of preventive warning. Forecast
accuracy would require defined outcomes, labelled sequences, chronological evaluation and
comparison with a baseline; an anomaly percentile is not that accuracy.

## Operational limits

To repeat the real HTTP verification on one PC, with both listeners running:

```powershell
.\.venv\Scripts\python.exe -X utf8 scripts/rehearse_live_lab.py
```

This script changes only the dummy portal, generates actual requests, checks responses and
stored evidence, and saves `logs/live-lab-rehearsal.json`. It leaves the portal patched and
releases its temporary block. It does not reset existing incidents or insert fixture findings.
The recorded warning lead time is operator-controlled and not forecast accuracy.

This adds a bounded-functionality live lab, not production sensor onboarding. It currently
collects from its own request handlers rather than an independent network/host agent. Portal
traffic must reach the handler to be recorded; infrastructure-level failures and malformed
requests rejected before handler validation are outside this collector. Control is local,
opt-in and token protected. It does not add production user accounts or tenant isolation.
Observations/actions persist and database retention/archival remains operational work.
Inventory updates can persist before a reassessment failure; re-running reassessment is the
recovery path. SQLite is intended for this small, single-worker lab, not large live workloads.
