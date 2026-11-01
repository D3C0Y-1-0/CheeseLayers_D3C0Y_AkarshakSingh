# Two-PC live demo — attacker view + defender view

A second laptop sends real traffic over Wi-Fi to the lab portal on the defender
laptop. The defender's Vectra console shows each request with the **real source
LAN IP** of the attacker laptop, detects the attack, and responds. Every value
is observed at runtime — no IPs, findings, or timestamps are hardcoded.

This drives only the team's **own isolated lab portal**, which serves dummy
records. It is not aimed at any real system.

## Roles

| | Defender PC (this laptop) | Attacker PC (2nd laptop) |
|---|---|---|
| Runs | Vectra console `/lab`, dashboard `/app`, lab portal, Apache lab, collector | A browser, or `scripts/demo-attacker.ps1` |
| Network | Wi-Fi LAN address, e.g. `10.120.134.199` | Same Wi-Fi |
| Shows the judges | Detection, source IP, block, patch, verify | The requests being sent |

## What is honest here, and the one limit

- **Honest:** the custom portal is a direct listener, so the TCP peer it records
  **is** the attacker laptop's real LAN IP. Detection, blocking, and the patch
  are all keyed to that real IP and verified by the attacker's next real request.
- **Limit worth stating to judges:** a LAN/Wi-Fi address identifies the device on
  this network, not a person, city, or country. Say "source host on our network,"
  not "we traced the attacker." The Apache CVE part stays on the defender's
  localhost because Docker NAT would hide the real source there — so the source-IP
  story uses the **portal**, and Apache is the "real published CVE" proof.

## One-time setup

### Defender (this laptop)

1. Find the Wi-Fi LAN address (looks like `10.x.x.x` or `192.168.x.x`):
   ```powershell
   Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -eq 'Wi-Fi' | Select IPAddress
   ```
2. Open the portal port to the local network **in an Administrator PowerShell**
   (this is a firewall change, so a human runs it):
   ```powershell
   New-NetFirewallRule -DisplayName "Vectra Lab Portal 8010" -Direction Inbound `
     -Action Allow -Protocol TCP -LocalPort 8010 -RemoteAddress LocalSubnet -Profile Private
   ```
   If the attacker PC still cannot connect, your Wi-Fi is on the **Public**
   profile — re-run with `-Profile Public` (venue networks are often Public).
3. Start the stack with the portal bound to the LAN address (control console and
   Apache lab stay on localhost):
   ```powershell
   .\scripts\start.ps1 -SkipBuild -Background -LiveLab
   .\scripts\start-apache-lab.ps1
   .\scripts\start-apache-collector.ps1
   .\scripts\start-lab-portal.ps1 -BindAddress <YOUR-LAN-IP>   # keep this window open
   ```
4. Open the console `http://127.0.0.1:8000/lab` and the dashboard
   `http://127.0.0.1:8000/app`.

### Attacker (2nd laptop)

- **Simplest:** a browser. Open `http://<DEFENDER-LAN-IP>:8010/` — if the lab
  page loads, the network path works.
- **Scripted:** copy `scripts/demo-attacker.ps1` to the 2nd laptop (no install, no
  repo needed) and run it with the defender's address.

## Demo flow (both screens visible)

Start state: portal **vulnerable**, no block on the attacker IP.

0. **Early warning (before any attack).** Defender: in section 1 of the console,
   reassess the portal asset `LAB-GOV-WEB-01`. The app already flags it as exposed
   to the known lab weakness — this is the *proactive* step: our own system warns
   about the exposure before anyone touches it.
1. **Baseline.** Attacker: `demo-attacker.ps1 -Target <IP> -Phase benign`
   (or browse `/document?name=notice.txt`). Defender: one row, *No finding*,
   showing the attacker's real IP.
2. **Attack → the architecture runs.** Attacker: `-Phase traversal`. Portal
   returns the dummy internal record (HTTP 200). On the defender the full chain
   fires at once: the sensor **detects** (**LIVE-WEB-001 Path traversal attempt**
   from that IP) → the **correlator** turns it into a scored **incident** →
   it appears on the **dashboard** `/app` with a priority, a score breakdown, the
   cited evidence, and a recommended action. Open the alert to show that chain.
3. **Brute force (optional).** Attacker: `-Phase bruteforce`. Defender:
   **LIVE-AUTH-001 Login failure burst** from the same IP.
4. **Respond — block.** Defender: select the detected row, **Temporarily block
   selected peer**. Attacker: re-run `-Phase traversal` → now **HTTP 429**.
   Defender: the block shows **verified**.
5. **Respond — patch.** Defender: **Apply document boundary fix**. Attacker:
   re-run `-Phase traversal` → now **HTTP 403**, no record disclosed. Defender:
   the patch shows **verified**, and exposure is re-evaluated.
6. **Real published CVE (defender localhost).** In the Apache section: Discover /
   warn → Send ordinary request → Send traversal (CVE-2021-41773, dummy record on
   2.4.49) → Replace with fixed Apache → Verify (same request now 404).

## How the live demo binds to the website (Attack simulation + Incidents)

The 2-PC demo and the website run the **same detection engine and incident
model** — the laptop just feeds it *live* traffic instead of replayed logs.

- **Website → Attack simulation tab** replays 22 real internet attackers (SANS
  Internet Storm Center honeypots) against the simulated inventory. It proves
  *breadth*: a 13-rule **Detection rulebook** (each with its MITRE ATT&CK ID),
  11 known CVEs including **CVE-2021-41773**, plus injection, traversal, scanning,
  login hammering, XSS and SQLi. "Try it yourself" lets a judge paste any log line.
- **2-PC laptop demo → the live portal** proves *depth and liveness*: a real
  second machine, a real source IP, detection and response in real time, verified
  by the attacker's next request.
- **They converge in the Incidents tab.** The live portal attack becomes one
  scored incident that correlates all your Shadow Watch signals — path traversal
  (**LIVE-WEB-001**), login burst (**LIVE-AUTH-001**) and the Isolation Forest
  anomaly (**LIVE-ML-001**, the ML) — with a 3-part score breakdown, an evidence
  timeline, an **Investigate incident** (AI) action and a **Draft CERT-In report**
  action. Benign requests show in the same timeline as *"no suspicious pattern."*

Demo line: *"On the website it catches 22 real internet attackers. On this laptop
you watch it catch a live one, in real time, and fix it — same engine."*

## Two judge questions — have these ready

**"These are just known exposures / CVEs. How is it beyond that?"**
- Only **3 of 22** real attackers are known-CVE; the rest are caught by
  **behaviour, no CVE needed**. The Incidents tab has a **"Behaviour, no CVE"**
  filter — show it.
- Shadow Watch flags patterns (traversal, brute force, spray, scanning, command
  injection) from the traffic itself, and the **Isolation Forest (LIVE-ML-001)**
  flags statistically unusual traffic with **no rule and no signature at all** —
  the "unknown unknown" the problem statement asks for.
- And it is **early**: exposure is warned *before* anyone attacks (known
  intelligence × your inventory), not after the breach.

**"How do you keep false positives down?"** (expect this one)
- **Thresholds model people, not tools:** "a person mistypes 1-3 times; hundreds a
  minute is a tool" — see the rulebook's **"Why it works"** column.
- **Built-in controls:** the Attack simulation includes **"No rule fired
  (control)"** attackers — real traffic (one sits in 7 threat feeds) we
  deliberately do *not* alert on. We never alert on reputation alone.
- **Corroboration before escalation:** sequence rules need a second signal (login
  *success after* failures; injection *plus* a large response). One weak signal
  does not escalate.
- **ML is triage, not a verdict:** every ML flag is low-confidence, labelled
  *"statistical triage, not proof of attack,"* and never auto-blocks. We measured
  it and left the Isolation Forest **off** the synthetic sensors because there it
  added 4/142 false positives with no recall gain — honesty about where ML helps.
- **Three separate scores, not one blended number:** evidence-confidence tempers
  thin alerts, and an asset on a fixed version scores **0** (confirmed unaffected).
- **Maintenance windows suppress benign spikes**, so planned bursts do not page.

## Teardown (after the demo)

1. Stop the portal window with **Ctrl+C** (or `Get-NetTCPConnection -LocalPort
   8010 -State Listen` then stop that PID's tree).
2. Remove the firewall rule (Administrator PowerShell):
   ```powershell
   Remove-NetFirewallRule -DisplayName "Vectra Lab Portal 8010"
   ```
3. For local-only work again, start the portal without `-BindAddress`
   (defaults to `127.0.0.1`).

## If the network fails at the venue

Fall back to the **single-laptop** demo in `docs/INDIA_LIVE_DEMO.md`: the same
attack, detection, block, patch, and verify, driven from the defender console
alone. It needs no second PC and no firewall change.
