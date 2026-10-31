param([switch]$SkipBuild, [int]$Port = 8000)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
# Same order as start.sh: backend\.venv, then .venv. Use the first one that can actually import the app's dependencies.
$pythonPath = $null
foreach ($candidate in @((Join-Path $projectRoot 'backend\.venv\Scripts\python.exe'), (Join-Path $projectRoot '.venv\Scripts\python.exe'))) {
    if (Test-Path -LiteralPath $candidate) {
        & $candidate -c "import fastapi, uvicorn, sklearn" 2>$null
        if ($LASTEXITCODE -eq 0) { $pythonPath = $candidate; break }
    }
}
if (-not $pythonPath) { throw 'Create backend\.venv (or .venv) and install backend/requirements.txt first. See README.md.' }
if (-not $SkipBuild) {
    & $pythonPath -X utf8 (Join-Path $PSScriptRoot 'export_scoring_config.py')
    if ($LASTEXITCODE -ne 0) { throw 'Could not export the central scoring configuration.' }
    Push-Location (Join-Path $projectRoot 'frontend')
    try {
        & npm.cmd run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
    } finally { Pop-Location }
}
$env:DEMO_MODE = 'true'
$env:PYTHONUTF8 = '1'
Write-Host "Vectra demo: http://127.0.0.1:$Port/app"
Write-Host 'Offline cache mode. Press Ctrl+C to stop.'
& $pythonPath -X utf8 -m uvicorn app.main:app --app-dir (Join-Path $projectRoot 'backend') --host 127.0.0.1 --port $Port
