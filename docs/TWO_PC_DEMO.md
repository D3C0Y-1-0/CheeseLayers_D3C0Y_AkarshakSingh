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

1. **Baseline.** Attacker: `demo-attacker.ps1 -Target <IP> -Phase benign`
   (or browse `/document?name=notice.txt`). Defender: one row, *No finding*,
   showing the attacker's real IP.
2. **Attack.** Attacker: `-Phase traversal`. Portal returns the dummy internal
   record (HTTP 200). Defender: new row **LIVE-WEB-001 Path traversal attempt**
   from that IP. Click **Inspect** to show the evidence.
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
