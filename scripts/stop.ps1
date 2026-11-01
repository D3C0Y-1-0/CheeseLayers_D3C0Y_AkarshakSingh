param([ValidateRange(1024, 65535)][int]$Port = 8000, [ValidateSet('apache-collector')][string]$Worker)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$statePath = if ($Worker) { Join-Path $projectRoot "logs\$Worker.json" } else { Join-Path $projectRoot "logs\vectra-$Port.json" }
if (-not (Test-Path -LiteralPath $statePath)) { throw "No background server record for port $Port. Foreground servers stop with Ctrl+C." }
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$server = Get-Process -Id $state.process_id -ErrorAction SilentlyContinue
if (-not $server) { Write-Host 'The recorded Vectra process has already stopped.'; return }
$recordedStart = [DateTime]::Parse($state.start_time_utc).ToUniversalTime()
if ([Math]::Abs(($server.StartTime.ToUniversalTime() - $recordedStart).TotalSeconds) -gt 2 `
    -or -not [String]::Equals($server.Path, $state.python_path, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Process identity changed since startup. Refusing to stop a potentially unrelated process.'
}
# Windows virtual-environment python.exe can launch the actual interpreter as a child.
# Stop only the identity-checked process tree, so that child cannot retain the port.
& taskkill.exe /PID $server.Id /T /F
if ($LASTEXITCODE -ne 0) { throw "Could not stop the registered Vectra process tree. PID: $($server.Id)" }
Write-Host "Stopped Vectra background process tree PID $($server.Id). Logs retained in logs\."
