# Vectra: 5-minute demo script

For the current actual request → independent collection → real replacement → verification demo,
use [INDIA_LIVE_DEMO.md](INDIA_LIVE_DEMO.md). This broader script retains earlier fixture/replay paths.

**Before the jury (once, with internet):** `backend/.venv/bin/python scripts/pregenerate_ai.py` (Windows: `backend\.venv\Scripts\python scripts\pregenerate_ai.py`)
caches validated LLM text, so the offline demo shows **LLM-cached** badges. Without it every AI panel
shows **Template**, which is still complete and correct.
**Start:** `./scripts/start.sh` (Windows: `.\scripts\start.ps1`) → open http://127.0.0.1:8000/app.
On the Command Center, press **Reset demo alerts** so you start clean, then prepare the Early warnings feed:
`curl -X POST http://127.0.0.1:8000/api/demo/seed` (or offline: `backend/.venv/bin/python scripts/seed_demo.py`).
It adds 5 labelled replay signals (Simulated) and creates no alerts. Safe to repeat.

| Time | Click | Say |
|---|---|---|
| 0:00 | **Command Center** | "~19,600 real public threat records from NVD, CISA KEV, EPSS, CERT-In, abuse.ch and OTX, cached so the demo runs offline. Our 40-asset organisation is simulated; attack traffic is real (SANS ISC honeypots, SecRepo server logs)." The top banner says whether the cloud LLM is on. |
| 0:25 | **Inject known CVE** (CVE-2024-21762, FortiOS) → **Early warnings** | "A new advisory arrives: a labelled early-warning signal (new_kev) is recorded and the matcher checks every asset." |
| 0:45 | **Incidents** → *CVE-2024-21762 on nrldc-edge-fw01 (PWR-FW-01)* | "Critical: 7.2.6 is inside the vulnerable range; its patched twin PWR-FW-02 (7.4.11) did not alert." Open **Why this priority**: severity + KEV/EPSS exploitation + asset criticality + exposure, every input shown. |
| 1:15 | Same incident: **Generate AI summary**, **Investigate incident**, **Draft CERT-In report** | "The LLM only rewrites wording. Every ID, version and URL must exist in our stored facts, or we show the template; the badge says which." CERT-In: "a draft for the analyst; nothing is sent." |
| 1:50 | **Attack simulation** → filter *Known-CVE exploits* → **51.159.5.6** → **Replay attack** | "A REAL attacker's real requests from SANS honeypots (30 Oct). The detector reads only the log text." Let it play: exploit packets go to *Our threat intel*. "Requests match known-CVE exploit signatures; the linked CVEs are KEV-listed; our matcher says GOV-WEB-01 is **vulnerable to CVE-2024-4577**, so the CVE alert is raised and the incident is critical." Scroll to the intel table: KEV, EPSS, our verdict per CVE. |
| 2:50 | Same page: filter *Login hammering* or *Port scans* → replay one; then *No rule fired* | "Real port scans and login hammering from the firewall feed. And real traffic where no rule fires stays quiet: no false alarm." |
| 3:20 | **Command Center** → **Real SSH brute force** → open incident → **Investigate** | "Shadow Watch on a real server's sshd log: 74 failed logins a minute from one IP, rule SW-AUTH-001. Medium: failures only, no successful login seen." |
| 3:50 | **Real distributed spray (ML)** | "7 IPs, one attempt each: under the rule threshold. The Isolation Forest, trained on this server's own history, flags it as unusual: low severity, needs review. ML flags are outliers, not confirmed attacks." |
| 4:15 | **Campaigns** → top campaign *PEERSTITCH, a Stealthy FortiGate Implant* | "TF-IDF + shared CVEs group related threat reports; ranked by actionability: this one reaches our 2 FortiGate firewalls. Vendor patch days are labelled patch batches, not campaigns." |
| 4:40 | **Exposure & impact** → sector posture + **What if we patched?** (CVE-2024-21762 → 7.4.11) | "Banking and power carry the risk; patching removes 100% of this exposure, computed by the same matcher and scorer, on copies." Then **Reset demo alerts**: "repeatable, feed data untouched." |

Fallbacks: if the backend is down, every page shows labelled bundled samples. If an AI call fails,
the panel shows the template with the reason (`LLM not used: …`).

## Limitations (say these if asked)

- **Real data vs simulated.** Real: threat feeds (cached), SANS ISC attack traffic (Attack Lab), SecRepo server
  logs (real Shadow Watch scenarios). Simulated: our 40-asset organisation, so real attacks are REPLAYED onto it
  and labelled as replays. Three Shadow Watch scenarios use synthetic events. Feed records are
  real but cached; `DEMO_MODE` makes no live fetches.
- **AI text is reworded, not reasoned.** The LLM only rewords a deterministic template. The grounding
  check catches invented IDs/versions/IPs/URLs, overclaims and commands, but not subtle mis-emphasis.
  Cached LLM text is served only when the stored facts are unchanged. Hindi is best-effort machine translation; English is retained when translation is unavailable.
- **Campaigns are statistical, not attribution.** Generic keys (T1190, "microsoft windows") are
  ignored, and groups are capped at 50, so big vendor clusters split into several campaigns. The IOC
  rule exists, but the current cache has no IOC shared by two threats. "7 days" counts back from the
  newest record in the data, not today.
- **CERT-In draft is a template.** The categories come from the 28 April 2022 Directions (Annexure I)
  and the suggestion is a heuristic. Verify against the current official text; reportability and
  filing are the analyst's job.
- **Lead time is a backtest** on cached data with a 90-day KEV window that moves with the calendar.
  EPSS history is incomplete for some CVEs. PoC dates are GitHub repo creation dates, quality-filtered.
- **Remediation targets** are an organisation policy (7/14/30/90 days), not a legal deadline.
- **Not production-hardened.** No authentication (demo mode allows simulated incidents only), SQLite,
  a single process, and loopback-only binding.
- Raw feed payloads (`backend/data/raw/`) are not in the repo, so raw-reconstruction checks need a live
  collector run.
