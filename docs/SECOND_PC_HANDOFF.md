# Second laptop — "attacker view" handoff

This laptop sends ordinary demonstration traffic to the team's **own** lab portal
running on the **defender laptop**. The portal serves only dummy records. This is
a rehearsal of our own lab, not an action against any real system.

You only need: this laptop on the **same Wi-Fi** as the defender, and the
defender's current LAN address.

---

## 1. Get the defender's LAN address

Ask the person on the defender laptop to run this and read you the number:

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -eq 'Wi-Fi' | Select IPAddress
```

It looks like `10.120.134.199` or `192.168.x.x`. **It changes on every network**,
so confirm it at the venue — do not reuse an old one. Below, replace
`<DEFENDER-IP>` with that number.

## 2. Check the connection

Open a browser on this laptop and go to:

```
http://<DEFENDER-IP>:8010/
```

- Page loads ("Fictional Indian district citizen portal — LAB ONLY") → you're in, go to step 3.
- It hangs or refuses → see Troubleshooting at the bottom.

## 3. Send the demo traffic

**Option A — one script (recommended).** Copy the single file `demo-attacker.ps1`
(from the defender's `scripts/` folder) onto this laptop, e.g. to the Desktop.
Open PowerShell in that folder and run:

```powershell
.\demo-attacker.ps1 -Target <DEFENDER-IP>              # full sequence
# or one phase at a time, to match the defender's narration:
.\demo-attacker.ps1 -Target <DEFENDER-IP> -Phase benign
.\demo-attacker.ps1 -Target <DEFENDER-IP> -Phase traversal
.\demo-attacker.ps1 -Target <DEFENDER-IP> -Phase bruteforce
.\demo-attacker.ps1 -Target <DEFENDER-IP> -Phase spray
```

If PowerShell blocks the script, run it this way instead:

```powershell
powershell -ExecutionPolicy Bypass -File .\demo-attacker.ps1 -Target <DEFENDER-IP>
```

**Option B — browser only (no script).** These two URLs are enough for the core
story (login bursts need the script):

```
http://<DEFENDER-IP>:8010/document?name=notice.txt                       (normal, HTTP 200)
http://<DEFENDER-IP>:8010/document?name=..%2Finternal%2Fdummy-records.json   (the attack)
```

## 4. What the defender screen shows

| You send | Defender console shows |
|---|---|
| `-Phase benign` | one row, **No finding**, with THIS laptop's real IP |
| `-Phase traversal` | **LIVE-WEB-001 Path traversal attempt** from your IP; dummy record returned (HTTP 200) while vulnerable |
| `-Phase bruteforce` | **LIVE-AUTH-001 Login failure burst** from your IP |
| `-Phase spray` | **LIVE-AUTH-003 Multi-account login failures** from your IP |

Then the defender **blocks** your IP (your next attack → **HTTP 429**) and
**applies the fix** (your next attack → **HTTP 403**, no record returned).

## 5. Talking point (keep it honest)

A Wi-Fi address identifies the **device on this network**, not a person, city, or
country. Say "the source host on our network," not "we traced the attacker."

---

## Troubleshooting

- **Can't connect / it hangs.**
  1. Both laptops on the **same Wi-Fi**? (Not one on hotspot, one on venue Wi-Fi.)
  2. Right IP? Re-check step 1 on the defender.
  3. Defender firewall: the defender must have added the inbound rule for port
     8010. If the venue Wi-Fi is a **Public** network, the rule needs the Public
     profile — tell the defender to re-add it with `-Profile Public`.
- **"running scripts is disabled"** → use the `-ExecutionPolicy Bypass` form in step 3.
- **Attack returns 403 right away** → the portal is already patched; the defender
  rolls it back ("Roll back lab fix") to start vulnerable.
- **Everything returns 429** → this IP is still blocked from a previous run; the
  defender releases it, or wait for it to expire.
