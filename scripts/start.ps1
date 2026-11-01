param([switch]$SkipBuild, [ValidateRange(1024, 65535)][int]$Port = 8000, [switch]$Background, [switch]$LiveLab)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$appUrl = "http://127.0.0.1:$Port/app"

function Test-VectraReady {
    try {
        $health = Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 2 -ErrorAction Stop
        $schema = Invoke-RestMethod "http://127.0.0.1:$Port/openapi.json" -TimeoutSec 2 -ErrorAction Stop
        return ($health.status -eq 'ok' -and $schema.info.title -in @('Vectra API', 'NETRA-X API'))
    } catch { return $false }
}

if ($Background -and (Test-VectraReady)) {
    if ($LiveLab) {
        try { $null = Invoke-WebRequest "http://127.0.0.1:$Port/lab" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop }
        catch { throw "The running server does not have the live lab enabled. Stop it with scripts\stop.ps1 -Port $Port, then restart with -LiveLab." }
    }
    Write-Host "Vectra is already running: $appUrl"
    return
}
# Same order as start.sh: backend\.venv, then .venv. Use the first one that can actually import the app's dependencies.
$pythonPath = $null
foreach ($candidate in @((Join-Path $projectRoot 'backend\.venv\Scripts\python.exe'), (Join-Path $projectRoot '.venv\Scripts\python.exe'))) {
    if (Test-Path -LiteralPath $candidate) {
        try {
            & $candidate -c "import fastapi, uvicorn, sklearn" 2>$null
            if ($LASTEXITCODE -eq 0) { $pythonPath = $candidate; break }
        } catch { continue }
    }
}
if (-not $pythonPath) { throw 'Create backend\.venv (or .venv) and install backend/requirements.txt first. See README.md.' }
Write-Host "Python: $pythonPath"
if (-not $SkipBuild) {
    & $pythonPath -X utf8 (Join-Path $PSScriptRoot 'export_scoring_config.py')
    if ($LASTEXITCODE -ne 0) { throw 'Could not export the central scoring configuration.' }
    Push-Location (Join-Path $projectRoot 'frontend')
    try {
        & npm.cmd run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
    } finally { Pop-Location }
}
if (-not (Test-Path -LiteralPath (Join-Path $projectRoot 'frontend\dist\index.html'))) {
    throw 'Frontend build missing. Run this script without -SkipBuild.'
}
$env:DEMO_MODE = 'true'
$env:PYTHONUTF8 = '1'
$env:VECTRA_LAB_ENABLED = if ($LiveLab) { 'true' } else { 'false' }
if ($Background) {
    $logDirectory = Join-Path $projectRoot 'logs'
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $stdout = Join-Path $logDirectory "vectra-$Port-$stamp.stdout.log"
    $stderr = Join-Path $logDirectory "vectra-$Port-$stamp.stderr.log"
    $statePath = Join-Path $logDirectory "vectra-$Port.json"
    $arguments = @('-X', 'utf8', '-u', '-m', 'uvicorn', 'app.main:app', '--app-dir',
                   ('"' + (Join-Path $projectRoot 'backend') + '"'), '--host', '127.0.0.1', '--port', "$Port", '--no-proxy-headers')
    $server = Start-Process -FilePath $pythonPath -ArgumentList $arguments -WorkingDirectory $projectRoot `
        -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    $state = [ordered]@{ process_id = $server.Id; start_time_utc = $server.StartTime.ToUniversalTime().ToString('o');
        python_path = $pythonPath; port = $Port; url = $appUrl; stdout_log = $stdout; stderr_log = $stderr }
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
    Write-Host "Starting background server (PID $($server.Id)). Startup log: $stderr"
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt 90) {
        $server.Refresh()
        if ($server.HasExited) {
            if (Test-Path -LiteralPath $stderr) { Get-Content -LiteralPath $stderr -Tail 35 | Write-Host }
            throw "Server exited with code $($server.ExitCode). See $stderr"
        }
        if (Test-VectraReady) {
            Write-Host "Ready: $appUrl"
            Write-Host "Background mode: closing this terminal will not send Ctrl+C to the server. Stop with .\scripts\stop.ps1 -Port $Port"
            return
        }
        Start-Sleep -Milliseconds 500
    }
    throw "Startup exceeded 90 seconds. Server PID $($server.Id) may still be loading; inspect $stderr"
}
Write-Host "Vectra demo: $appUrl"
Write-Host 'Foreground mode: keep this terminal open. Ctrl+C stops the server. Use -Background to detach it.'
Push-Location $projectRoot
try {
    & $pythonPath -X utf8 -m uvicorn app.main:app --app-dir (Join-Path $projectRoot 'backend') --host 127.0.0.1 --port $Port --no-proxy-headers
    $serverExitCode = $LASTEXITCODE
} finally { Pop-Location }
if ($serverExitCode -ne 0) { throw "Server exited with code $serverExitCode. Review the error above or start with -Background to save logs." }
Write-Host 'Vectra stopped normally. Start it again or use -Background to keep it independent of this terminal.'
