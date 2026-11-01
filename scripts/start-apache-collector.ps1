$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { $pythonPath = Join-Path $projectRoot 'backend\.venv\Scripts\python.exe' }
$logs = Join-Path $projectRoot 'logs'
New-Item -ItemType Directory -Path $logs -Force | Out-Null
$statePath = Join-Path $logs 'apache-collector.json'
if (Test-Path -LiteralPath $statePath) {
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $existing = Get-Process -Id $state.process_id -ErrorAction SilentlyContinue
    if ($existing -and [Math]::Abs(($existing.StartTime.ToUniversalTime() - [DateTime]::Parse($state.start_time_utc).ToUniversalTime()).TotalSeconds) -lt 2 -and $existing.Path -eq $state.python_path) {
        Write-Host "Apache collector already running (PID $($existing.Id))."
        return
    }
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$stdout = Join-Path $logs "apache-collector-$stamp.stdout.log"
$stderr = Join-Path $logs "apache-collector-$stamp.stderr.log"
$arguments = @('-X','utf8','-u',('"' + (Join-Path $projectRoot 'scripts\watch_apache_lab.py') + '"'))
$worker = Start-Process -FilePath $pythonPath -ArgumentList $arguments -WorkingDirectory $projectRoot -WindowStyle Hidden `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
@{process_id=$worker.Id; start_time_utc=$worker.StartTime.ToUniversalTime().ToString('o'); python_path=$pythonPath;
  stdout_log=$stdout; stderr_log=$stderr} | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
Write-Host "Apache collector started (PID $($worker.Id)); log: $stdout"
Write-Host 'Stop with scripts\stop.ps1 -Worker apache-collector'
