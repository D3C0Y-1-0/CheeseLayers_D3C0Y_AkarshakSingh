<#
  Vectra 2-PC demo driver -- run this on the SECOND laptop (the "attacker" view).

  It sends ordinary demonstration traffic to YOUR OWN isolated lab portal, which
  serves only dummy records. It is a rehearsal driver for the team's lab, not a
  tool against any real system. It touches only the host you pass with -Target.

  Nothing is hardcoded: pass the defender PC's Wi-Fi/LAN address with -Target.
  Both laptops must be on the same Wi-Fi, and the defender must have opened the
  portal port in Windows Firewall (see docs/TWO_PC_DEMO.md).

  Examples (run on the second laptop):
    .\demo-attacker.ps1 -Target 10.120.134.199            # full sequence
    .\demo-attacker.ps1 -Target 10.120.134.199 -Phase traversal
    .\demo-attacker.ps1 -Target 10.120.134.199 -Phase bruteforce
#>
param(
  [Parameter(Mandatory)][string]$Target,
  [ValidateRange(1024, 65535)][int]$Port = 8010,
  [ValidateSet('all', 'benign', 'traversal', 'bruteforce', 'spray')][string]$Phase = 'all',
  [int]$PauseSeconds = 3
)
$ErrorActionPreference = 'Stop'
$base = "http://${Target}:${Port}"

# One request; returns the real HTTP status even for 4xx/429 (which Invoke-WebRequest treats as errors).
function Send-LabRequest {
  param([string]$Method, [string]$Path, [hashtable]$Body)
  $url = "$base$Path"
  try {
    if ($Body) {
      $r = Invoke-WebRequest -Uri $url -Method $Method -Body ($Body | ConvertTo-Json) `
        -ContentType 'application/json' -UseBasicParsing -TimeoutSec 8
    } else {
      $r = Invoke-WebRequest -Uri $url -Method $Method -UseBasicParsing -TimeoutSec 8
    }
    return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$r.Content }
  } catch {
    $resp = $_.Exception.Response
    if ($resp) {
      $status = [int]$resp.StatusCode
      $text = ''
      if ($_.ErrorDetails) { $text = $_.ErrorDetails.Message }
      return [pscustomobject]@{ Status = $status; Body = $text }
    }
    throw "Cannot reach $url. Check the Wi-Fi, the -Target address, and the defender's firewall rule. ($($_.Exception.Message))"
  }
}

function Wait-Phase { if ($PauseSeconds -gt 0) { Start-Sleep -Seconds $PauseSeconds } }

Write-Host "Target lab portal: $base" -ForegroundColor Cyan
Write-Host "The defender console shows each request below with THIS PC's real LAN IP.`n"

if ($Phase -in 'all', 'benign') {
  Write-Host "[1] Ordinary citizen request (public notice)" -ForegroundColor Green
  $r = Send-LabRequest -Method GET -Path '/document?name=notice.txt'
  Write-Host ("    GET /document?name=notice.txt  ->  HTTP {0}" -f $r.Status)
  Write-Host "    Defender: one row, 'No finding'. This is the baseline.`n"
  if ($Phase -eq 'all') { Wait-Phase }
}

if ($Phase -in 'all', 'traversal') {
  Write-Host "[2] Document-boundary bypass attempt (the attack)" -ForegroundColor Yellow
  $r = Send-LabRequest -Method GET -Path '/document?name=..%2Finternal%2Fdummy-records.json'
  $disclosed = $r.Body -match 'FICTIONAL CITIZEN'
  Write-Host ("    GET /document?name=../internal/dummy-records.json  ->  HTTP {0}" -f $r.Status)
  if ($r.Status -eq 200 -and $disclosed) {
    Write-Host "    Dummy internal record returned -> portal is in the VULNERABLE state." -ForegroundColor Yellow
  } elseif ($r.Status -eq 403) {
    Write-Host "    Blocked by the document boundary -> portal is already PATCHED." -ForegroundColor Green
  } elseif ($r.Status -eq 429) {
    Write-Host "    Temporary restriction -> this peer is currently blocked." -ForegroundColor Green
  }
  Write-Host "    Defender: new row, 'LIVE-WEB-001 Path traversal attempt', with this PC's IP.`n"
  if ($Phase -eq 'all') { Wait-Phase }
}

if ($Phase -in 'all', 'bruteforce') {
  Write-Host "[3] Login failure burst (10 attempts, same account)" -ForegroundColor Yellow
  for ($i = 1; $i -le 10; $i++) {
    $r = Send-LabRequest -Method POST -Path '/login' -Body @{ username = 'attacker'; password = "wrong-$i" }
    Write-Host ("    attempt {0,2}  ->  HTTP {1}" -f $i, $r.Status)
  }
  Write-Host "    Defender: 'LIVE-AUTH-001 Login failure burst' once 10 failures land inside 60s.`n"
  if ($Phase -eq 'all') { Wait-Phase }
}

if ($Phase -eq 'spray') {
  Write-Host "[*] Password spray (one try each across several accounts)" -ForegroundColor Yellow
  foreach ($u in 'ravi', 'priya', 'amit', 'sunita', 'arjun', 'neha') {
    $r = Send-LabRequest -Method POST -Path '/login' -Body @{ username = $u; password = 'spray-123' }
    Write-Host ("    {0,-8}  ->  HTTP {1}" -f $u, $r.Status)
  }
  Write-Host "    Defender: 'LIVE-AUTH-003 Multi-account login failures' (>=5 usernames, one peer, 60s).`n"
}

Write-Host "Done. Switch to the defender screen to show the detections, then block/patch." -ForegroundColor Cyan
