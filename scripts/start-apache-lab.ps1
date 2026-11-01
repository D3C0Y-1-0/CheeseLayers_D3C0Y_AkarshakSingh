param([string]$BindAddress = '127.0.0.1')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$address = $null
if (-not [Net.IPAddress]::TryParse($BindAddress, [ref]$address)) { throw 'Use a literal loopback or private IPv4 address assigned to this PC.' }
if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'The Apache relay launcher currently supports IPv4 bindings; use 127.0.0.1 or a private LAN address.' }
if (-not [Net.IPAddress]::IsLoopback($address)) {
    $bytes = $address.GetAddressBytes()
    if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        -not ($bytes[0] -eq 10 -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or ($bytes[0] -eq 192 -and $bytes[1] -eq 168))) {
        throw 'Use loopback or a specific private LAN address; all-interface/public binding is not supported.'
    }
}
$labRoot = Join-Path $projectRoot 'lab\apache'
$runtimeRoot = Join-Path $labRoot 'runtime'
New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
$runtimeConfig = Join-Path $runtimeRoot 'nginx.conf'
if (-not (Test-Path -LiteralPath $runtimeConfig)) {
    Copy-Item -LiteralPath (Join-Path $labRoot 'nginx.conf') -Destination $runtimeConfig
}
$env:VECTRA_APACHE_BIND = $BindAddress
& docker compose -f (Join-Path $labRoot 'compose.yaml') up -d
if ($LASTEXITCODE -ne 0) { throw 'Could not start the owned Apache lab. Check Docker Desktop and lab logs.' }
& docker compose -f (Join-Path $labRoot 'compose.yaml') restart vulnerable patched
if ($LASTEXITCODE -ne 0) { throw 'Could not reload the owned Apache targets with the current access-log configuration.' }
Write-Host "District service: http://${BindAddress}:8011/documents/notice.txt"
Write-Host "Fixed comparison: http://${BindAddress}:8012/documents/notice.txt"
Write-Host 'Open the local Vectra /lab console and discover the owned containers. Start the independent collector.'
