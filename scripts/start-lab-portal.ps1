param([ValidateRange(1024, 65535)][int]$Port = 8010, [string]$BindAddress = '127.0.0.1', [switch]$Background)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
# Same as start.ps1: pick the first venv that can actually import the app (root .venv may be incomplete).
$pythonPath = $null
foreach ($candidate in @((Join-Path $projectRoot 'backend\.venv\Scripts\python.exe'), (Join-Path $projectRoot '.venv\Scripts\python.exe'))) {
    if (Test-Path -LiteralPath $candidate) {
        try { & $candidate -c "import fastapi, uvicorn" 2>$null; if ($LASTEXITCODE -eq 0) { $pythonPath = $candidate; break } } catch { continue }
    }
}
if (-not $pythonPath) { throw 'Install backend dependencies in backend\.venv (or .venv) first. See README.md.' }
$address = $null
if (-not [Net.IPAddress]::TryParse($BindAddress, [ref]$address)) { throw 'BindAddress must be a literal address assigned to this PC.' }
if (-not [Net.IPAddress]::IsLoopback($address)) {
    if ($address.Equals([Net.IPAddress]::Any) -or $address.Equals([Net.IPAddress]::IPv6Any)) {
        throw 'Choose this PC''s specific private LAN address instead of all interfaces.'
    }
    $bytes = $address.GetAddressBytes()
    $privateIPv4 = $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and `
        ($bytes[0] -eq 10 -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or ($bytes[0] -eq 192 -and $bytes[1] -eq 168))
    if (-not $privateIPv4) { throw 'Use loopback or a private IPv4 address for the lab listener.' }
}
$env:VECTRA_LAB_ENABLED = 'true'
$env:PYTHONUTF8 = '1'
Write-Host "Lab portal: http://${BindAddress}:$Port/ (dummy records only)"
if ($Background) {
    # Reuse only an identity-checked recorded process; never terminate an unrelated listener.
    $statePath = Join-Path $projectRoot "logs\vectra-$Port.json"
    if (Test-Path -LiteralPath $statePath) {
        $previous = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $existing = Get-Process -Id $previous.process_id -ErrorAction SilentlyContinue
        if ($existing -and [Math]::Abs(($existing.StartTime.ToUniversalTime() - [DateTime]::Parse($previous.start_time_utc).ToUniversalTime()).TotalSeconds) -lt 2) {
            throw "A recorded portal process is already running. Use scripts\stop.ps1 -Port $Port before restarting it."
        }
    }
    $logDirectory = Join-Path $projectRoot 'logs'
    New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $stdout = Join-Path $logDirectory "portal-$Port-$stamp.stdout.log"
    $stderr = Join-Path $logDirectory "portal-$Port-$stamp.stderr.log"
    $arguments = @('-X', 'utf8', '-u', '-m', 'uvicorn', 'app.live_lab:portal_app', '--app-dir',
        ('"' + (Join-Path $projectRoot 'backend') + '"'), '--host', $BindAddress, '--port', "$Port", '--no-proxy-headers', '--workers', '1')
    $server = Start-Process -FilePath $pythonPath -ArgumentList $arguments -WorkingDirectory $projectRoot `
        -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    [ordered]@{process_id=$server.Id; start_time_utc=$server.StartTime.ToUniversalTime().ToString('o');
        python_path=$pythonPath; port=$Port; url="http://${BindAddress}:$Port/";
        stdout_log=$stdout; stderr_log=$stderr} | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
    Start-Sleep -Seconds 2
    $server.Refresh()
    if ($server.HasExited) { throw "Portal exited. Inspect $stderr" }
    Write-Host "Portal running in background. PID $($server.Id). Stop with scripts\stop.ps1 -Port $Port"
    return
}
Write-Host 'Initialise the local Vectra /lab console first. Keep this terminal open; Ctrl+C stops the portal.'
& $pythonPath -X utf8 -m uvicorn app.live_lab:portal_app --app-dir (Join-Path $projectRoot 'backend') --host $BindAddress --port $Port --no-proxy-headers --workers 1
if ($LASTEXITCODE -ne 0) { throw "Lab portal stopped with exit code $LASTEXITCODE" }
