param([switch]$SkipBuild, [int]$Port = 8000)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { throw 'Create .venv and install backend/requirements.txt first. See README.md.' }
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
Write-Host "Vectra / NETRA-X demo: http://127.0.0.1:$Port/app"
Write-Host 'Offline cache mode. Press Ctrl+C to stop.'
& $pythonPath -X utf8 -m uvicorn app.main:app --app-dir (Join-Path $projectRoot 'backend') --host 127.0.0.1 --port $Port
