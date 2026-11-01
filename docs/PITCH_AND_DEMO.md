# Vectra — pitch & live demo playbook

How to present and demonstrate the whole system, end to end, with judge Q&A.
Target length: **6–7 minutes demo + Q&A**. Honesty is the winning move — every
number below is real and every limit is stated on purpose.

---

## 0. Before you start (2-minute checklist)

- **PC1 (defender, this laptop):** services up — main app `:8000`, portal on the
  LAN `:8010`, Apache lab `:8011/8012`, collector. Two browser windows open:
  **console** `http://127.0.0.1:8000/lab` and **dashboard** `http://127.0.0.1:8000/app`.
- **PC2 (attacker):** same Wi-Fi, `demo-attacker.ps1` copied over, connection to
  `http://<PC1-LAN-IP>:8010/` confirmed.
- **Clean start:** on the console click **Roll back fix** (portal → vulnerable)
  and **Restore vulnerable** (Apache). On the dashboard click **Reset demo alerts**.
- **Roles:** one person drives PC1 + narrates; one person runs PC2 on cue.
- **Fallback:** if Wi-Fi fails, the whole flow runs on PC1 alone (see
  `docs/INDIA_LIVE_DEMO.md`). Have it ready.

---

## 1. The hook (30 seconds)

> "India's critical services — power, banking, hospitals, government portals — are
> hit by the same attacks every day. The problem isn't a lack of threat data;
> it's that nobody connects *the flood of global threat intel* to *the specific
> systems an organisation runs*, early enough to act. Vectra is an AI early-warning
> SOC that does exactly that: it warns you **before** the attack, catches it
> **live**, and proves the fix — and we'll show all three on two laptops right now."

---

## 2. The product, in one view (1 minute)

Open the dashboard → **Security Operations**.

- **SAY:** "This is the live SOC. 19,000+ threats from 15 national feeds — NVD,
  CISA KEV, CERT-In, abuse.ch — refreshed continuously."
- **SHOW:** the threat globe, the open-incidents gauge, the 27,000 IOCs watched.
- **SAY:** "Everything is asset-aware — it only alerts on what *we actually run*."

Then open **Incidents** for one second: "a prioritised queue, most dangerous
first." You'll come back to it live.

---

## 3. The live demo — attack, detect, respond, verify (3 minutes)

Two screens visible: **PC1 console (left)**, **PC1 dashboard (right)**. PC2 attacks on cue.

| Step | DO (PC1 / PC2) | SAY | JUDGE SEES |
|---|---|---|---|
| **Warn first** | PC1 console §1: Reassess `LAB-GOV-WEB-01` | "Before anyone attacks, we already know this service is exposed." | an **EXPOSED** verdict card |
| **Attack** | PC2: `demo-attacker.ps1 -Target <IP> -Phase traversal` | "Now a real attack from a second machine." | console §2: a **red detection row** + the **attack-path diagram** with PC2's real IP |
| **Pile on** | PC2: `-Phase bruteforce` | "Shadow Watch catches it by behaviour, not a signature." | a second detection (login burst) from the same IP |
| **Correlate** | PC1 dashboard → Incidents → open the new one | "It becomes one scored incident with evidence and a recommendation." | 3-score breakdown + evidence timeline |
| **Block** | PC1 console §3: Inspect a red row → **Block selected peer**; PC2 re-runs traversal | "We block the source — and prove it with the attacker's own next request." | PC2 gets **429**; block → **verified** |
| **Patch** | PC1 console §3: **Apply boundary fix**; PC2 re-runs traversal | "Then we fix the weakness itself." | PC2 gets **403**; patch → **verified**; exposure re-scored |

**Strong finish — the real published CVE:** console Apache section → Restore
vulnerable → Discover → Traversal attack (real **CVE-2021-41773**, dummy record
disclosed on Apache 2.4.49) → Replace with fixed Apache → Verify (same request now
**404**). SAY: "Same loop, but this is a real CVE on real Apache, CERT-In
CIAD-2021-0039."

---

## 4. Breadth — it's not just our lab (1 minute)

Dashboard → **Attack simulation**.

- **SAY:** "These are 22 *real* attackers from SANS Internet Storm Center honeypots
  — real IPs, real requests, real dates. We replay them against our inventory."
- **SHOW the filters:** "Only 3 of 22 are known-CVE. The rest — injection,
  traversal, scanning, login hammering — are caught by **behaviour, no CVE needed**."
- **SHOW** the Detection rulebook: "13 rules, each mapped to MITRE ATT&CK, each with
  the plain-English reason it works."

---

## 5. The prediction story (1 minute)

Dashboard → **Exposure & impact**.

- **SAY:** "We don't claim to predict the future. We make two honest claims."
- **One:** "A preventive exposure warning — you just saw it fire before the attack."
- **Two — the backtest:** point at **32 / 97**. "Of 97 CVEs that CISA confirmed as
  actively exploited in the last 90 days, our early signals — EPSS rising, a public
  proof-of-concept appearing — flagged **32 of them before that confirmation, a
  median of 13 days early**. No look-ahead. And we show the ones we **missed**."

---

## 6. Close (30 seconds)

> "So: it warns before the attack, catches the unknown by behaviour and ML, scores
> and explains every alert, proves its own fixes, and measures its own early-warning
> lead time — honestly, misses included. It's India-first, offline-capable, and
> exports to CERT-In. That's a national early-warning system you can actually trust."

---

## 7. Judge Q&A — anticipated questions and honest answers

**"Is this real or is the data hardcoded?"**
Real. The attack-simulation attackers are live SANS Internet Storm Center honeypot
data (`collectors/isc.py`, CC BY-NC-SA 4.0), cached for offline reliability. CVE/KEV/
EPSS come from NVD, CISA and FIRST. The live 2-PC attack is real traffic over Wi-Fi.
The only synthetic parts, labelled as such, are the **target inventory** and the
**dummy documents** — because we're not attacking a real organisation.

**"How is this beyond just known CVEs?"**
Most real attacks aren't a single CVE. 19 of our 22 real attackers are caught by
**behaviour** — traversal, injection, brute force, scanning — with no CVE involved.
The Incidents tab has a "Behaviour, no CVE" filter. On top of that, the **Isolation
Forest** flags statistically unusual traffic with no rule and no signature at all.

**"How do you keep false positives down?"** *(expect this — it's a strong suit)*
Five ways: (1) thresholds model humans not tools — "a person mistypes 1–3 times;
hundreds a minute is a tool"; (2) built-in **"No rule fired" control** attackers —
real traffic, one of them in 7 threat feeds, that we deliberately don't alert on;
(3) **corroboration before escalation** — sequence rules need a second signal;
(4) **ML is low-confidence triage, never auto-block** — we even left it *off* the
synthetic sensors because there it added 4/142 false positives with no gain;
(5) **three separate scores**, and an asset on a fixed version scores **0**.

**"What exactly is the AI/ML?"**
An Isolation Forest anomaly detector, trained only on each sensor's own declared-
ordinary traffic, frozen to prevent attack contamination, with a chronological
holdout. Plus explainable risk scoring, TF-IDF campaign clustering, and an optional
LLM that writes the analyst summary (templates when no key — it degrades gracefully).

**"How do you validate the 'early warning'?"**
A backtest with no look-ahead: for CVEs CISA later confirmed exploited (KEV), we
check whether our signals fired strictly *before* that date. 32/97 flagged, median
13 days. We separate new vs old CVEs (old ones inflate the number) and we show the
misses. It's indicative on one window, not a benchmark — and we say so.

**"Can you identify the attacker / where they are?"**
Honestly, no, and we don't pretend to. We record the TCP source. In the live demo
that's a LAN host, which we locate on the **network path**, not a world map — a
private IP has no geographic location. For the internet attackers, we show the
registered location of the IP, with the caveat that NAT/proxies can hide the origin.
We never name a person or country.

**"Is any of this production-ready / does it scale?"**
It's a working prototype. Detection, scoring and correlation are deterministic and
tested (300+ tests). For production we'd add real host/network sensors, tenant
isolation, authentication, retention and load testing — we have a roadmap. We're
deliberately not overclaiming.

**"Why does it matter for India / C-DAC specifically?"**
It mirrors C-DAC's own direction — honeypot sensors → analysis → risk → early
warning → India-focused CTI → single dashboard. We add the asset-aware AI layer on
top of CERT-In and national feeds, with IST timelines, Hindi assistance, and
analyst-reviewed CERT-In report drafts. On-prem and offline-capable.

**"What's simulated vs real?"** *(have this crisp)*
Real: the attack traffic, the detection rules, the CVE/KEV/EPSS facts, the live
2-PC attack, the Apache CVE exploit, the ML model. Simulated: the asset inventory
(Indian critical-sector org), the dummy documents, and *which* asset an internet
attacker is replayed against.

**"What if the live demo breaks?"**
It runs on one laptop without the second PC or any network — same attack, detection,
block, patch, verify, driven from the console alone. We also have the recorded
evidence (rehearsal JSON, incident history) as backup.

**"The portal weakness isn't a published CVE — is that cheating?"**
No — it's labelled `DEMO-VULN-LAB-TRAVERSAL`, never presented as a real CVE. It
exists so we can show the *behavioural* detection loop live and safely. The
*published* CVE (CVE-2021-41773) is demonstrated separately on real Apache.

---

## 8. One-line cheat sheet (if you only remember this)

**Warn before → catch live (behaviour + ML) → score & explain → prove the fix →
measure the lead time, misses and all.** Real data, honest limits, India-first.
