# Vectra: 5-minute demo script

**Before the jury (once, with internet):** `backend/.venv/bin/python scripts/pregenerate_ai.py`
caches validated LLM text, so the offline demo shows **LLM-cached** badges. Without it every AI panel
shows **Template**, which is still complete and correct.
**Start:** `./scripts/start.sh` (Windows: `.\scripts\start.ps1`) → open http://127.0.0.1:8000/app.
On the Command Center, press **Reset demo alerts** so you start clean.

| Time | Click | Say |
|---|---|---|
| 0:00 | **Command Center** | "~19,600 real public threat records from NVD, CISA KEV, EPSS, CERT-In, abuse.ch and OTX, cached so the demo runs offline. Assets and behaviour are simulated." Point at the top banner: it says whether the cloud LLM is on. |
| 0:30 | **Inject known CVE** (CVE-2024-21762, FortiOS) | "A new advisory arrives. A change-detection signal fires, and the matcher checks our 40-asset inventory." |
| 0:50 | **Early warnings** | Show the signal. "Signals come from KEV additions, EPSS jumps, quality-checked public exploits, CERT-In advisories and new critical CVEs." Optional: **Simulate on DEMO-VULN-001** (labelled Simulated). |
| 1:10 | **Incidents** → open *CVE-2024-21762 on nrldc-edge-fw01 (PWR-FW-01)* | "Critical: the power-grid firewall runs 7.2.6, inside the vulnerable range. Its patched twin PWR-FW-02 (7.4.11) did not alert." Show **Why this priority** (three scores and their inputs) and the **Remediation target** tag: "organisation policy, not a regulatory deadline." |
| 1:40 | On the same incident: **AI summary** → *Generate AI summary* | Read the badge (LLM / LLM-cached / Template) and the validation note: "Every ID, version and URL in the AI text must exist in our stored facts, or we fall back to the template." |
| 2:05 | **Draft CERT-In report** → expand *Preview draft* → **Download .md** | "Vulnerability exposure only, so not by itself a reportable incident. The category is a suggestion for the analyst to confirm. Nothing is sent." |
| 2:30 | **Campaigns** → tick *Emerging only* → open the FortiOS campaign | "Related threats grouped by shared CVE, product, ATT&CK technique and text similarity. *Why grouped* lists the evidence. 2 of our assets are exposed." |
| 3:00 | **Command Center** → **Inject suspicious behaviour** → open the new incident | "Scenario B: no CVE at all. An odd HTTP window, an unexpected process and a new outbound connection on HLT-WEB-01." Click **Investigate incident** (cites evidence IDs, lists visibility gaps), then **Draft CERT-In report**: "potential security incident, analyst must determine reportability." |
| 3:40 | **Command Center** → **Inject benign maintenance** | "Scenario C: an approved change window explains the spike, so the events are kept but not escalated. No alert." Optional: **Missing telemetry** → "an absent sensor is a visibility gap, never proof of safety." |
| 4:10 | **Exposure & impact** → *Early-warning lead-time* + *Lead-time examples* | "Backtest: X of Y new CVEs were flagged before CISA KEV confirmed exploitation." Walk one timeline: NVD publish → first quality PoC → KEV add, plus the **Missed** example. |
| 4:40 | **Command Center** → **Reset demo alerts** | "Repeatable: alerts and sensor events reset, feed data retained." |

Fallbacks: if the backend is down, every page shows labelled bundled samples. If an AI call fails,
the panel shows the template with the reason (`LLM not used: …`).

## Limitations (say these if asked)

- **Simulated organisation.** Assets, behaviour events and incidents are synthetic. Feed records are
  real but cached; `DEMO_MODE` makes no live fetches.
- **AI text is reworded, not reasoned.** The LLM only rewords a deterministic template. The grounding
  check catches invented IDs/versions/IPs/URLs, overclaims and commands, but not subtle mis-emphasis.
  Cached LLM text is served only when the stored facts are unchanged. Hindi (Step 7) is not shipped.
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
