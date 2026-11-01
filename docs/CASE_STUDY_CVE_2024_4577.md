# Case study: CVE-2024-4577 — a real PHP RCE against our citizen portal

A single-CVE walkthrough that leads from national threat intelligence to one of our
own assets, to a scored incident, to a real attacker who used it, to the fix — and
then hands off to the live 2-PC lab. Present it as one causal story, not a tour.

Written for: the team, to present to the D3COY judges.

---

## Why this CVE

- **CVE-2024-4577** is a real, widely-exploited (**CISA KEV**) argument-injection
  remote-code-execution bug in **PHP running as CGI on Windows**.
- Our **GOV-WEB-01** is a "Citizen services portal (PHP on Windows/IIS, CGI)" on
  **PHP 8.1.28** — exactly the affected configuration. The match is honest, not forced.
- **The bridge:** the real honeypot attacker **51.159.5.6** in our Attack-simulation
  data used *both* CVE-2024-4577 *and* CVE-2021-41773 — so the same attacker ties the
  website case study to the Apache CVE we exploit live in the lab.

Say "a real PHP RCE that matches our portal," never "the CVE behind [a specific
outage]" — we have not established that link, and we don't claim it.

---

## A-Z flow on the website (≈3 minutes)

| # | Screen | Do / Say | What it proves |
|---|---|---|---|
| 1 | **Threat Intelligence** `/app/threats` | Search `CVE-2024-4577`. Open it. | Real vulnerability facts: CVSS, **KEV-listed**, EPSS, references — from NVD/CISA, not us |
| 2 | **Early warnings** `/app/signals` | Show it was flagged when it became KEV / its EPSS rose. | "We were warned it was dangerous before it reached us" |
| 3 | **Asset Inventory** `/app/assets` | Open `GOV-WEB-01` — PHP 8.1.28, Windows/CGI, internet-facing, criticality. | "Our portal runs precisely the affected configuration" |
| 4 | **Incidents** `/app/incidents` | Open the **critical (≈94) CVE-2024-4577** incident on GOV-WEB-01. Show the three scores, evidence, recommendation. Click **Investigate** for AI review steps. | Knowledge → relevance → a scored, explained, prioritised case |
| 5 | **Attack simulation** `/app/attack-lab` | Select attacker **51.159.5.6**, Replay against GOV-WEB-01. | "A real internet attacker actually used this exact CVE" |
| 6 | **Bridge** | "That same attacker also used CVE-2021-41773 on Apache — which we'll now exploit and patch **live**." | Hands off to the 2-PC lab |

Read the on-screen numbers live; they are runtime values, not fixed claims.

---

## The remediation an analyst would carry out

1. **Confirm exposure.** GOV-WEB-01 runs PHP **8.1.28** as CGI on Windows → within
   the affected range (fixed in 8.1.29). The matcher already shows this.
2. **Immediate mitigation** (if an upgrade can't ship at once):
   - Move PHP off CGI to **Mod-PHP / FastCGI** — the bug only affects CGI mode; or
   - Add a web-server rule blocking the soft-hyphen `%AD` argument-injection pattern; and
   - Restrict the portal to required networks.
3. **Patch.** Upgrade PHP to **8.1.29 / 8.2.20 / 8.3.8 or later**.
4. **Verify.** Re-send the exploit request → it must fail; re-run the matcher →
   GOV-WEB-01 becomes **confirmed_unaffected** and the incident can close.

This is the same **detect → match → recommend → patch → verify** loop the live lab
demonstrates end to end — on the website it's the analysis; in the lab it's live.

---

## Hand-off to the live 2-PC lab

After the website story, run the live demo (see [TWO_PC_DEMO.md](TWO_PC_DEMO.md) and
the playbook [PITCH_AND_DEMO.md](PITCH_AND_DEMO.md)):

- The lab exploits **CVE-2021-41773** on real Apache 2.4.49 (safe to run on owned,
  dummy-data containers), then replaces it with fixed 2.4.51 and verifies.
- Narrate the continuity: *"On the website we analysed a real PHP CVE against our
  portal. Here we take the same attacker's Apache CVE and do it for real — attack,
  detect, block, patch, and prove the fix with the attacker's own next request."*

Why two CVEs: we demonstrate the PHP RCE through real intelligence and real attacker
data (we do not run a live PHP-CGI RCE against a production-shaped host), and we
demonstrate the full live exploit/patch loop on the Apache CVE in an isolated lab.
Both are real, published, KEV-adjacent CVEs. Be upfront about this split if asked.

---

## Case-specific judge questions

- **"Did this CVE cause [the outage you mentioned]?"** — We don't claim that. We show
  that it's real, actively exploited, and matches our portal's exact configuration.
- **"Why not exploit the PHP CVE live too?"** — Safely running a real PHP-CGI RCE
  needs a production-shaped Windows host; we keep live exploitation to the isolated
  Apache lab. The PHP case is proven through intelligence + real attacker traffic.
- **"How fast could you have known?"** — Early warnings flags KEV/EPSS changes; the
  Exposure & impact backtest shows our measured lead time on confirmed-exploited CVEs.
- **"Is the match real or forced?"** — GOV-WEB-01 is literally "PHP on Windows/CGI,"
  which is exactly what CVE-2024-4577 targets. The version 8.1.28 is below the 8.1.29 fix.
