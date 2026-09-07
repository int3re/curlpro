<#
  Captures a reference browser fingerprint from a local fingerproxy echo-server.

  The data comes NOT from the browser's stdout — headless Chrome does not give
  it on Windows — but from the echo-server log, which prints the full detail
  JSON with -verbose.

  Every run is a fresh process and a throwaway profile, to guarantee a new TLS
  connection: Chrome >=110 shuffles its extensions per connection, and a profile
  built from a single sample would freeze the noise.

  Usage: .\capture.ps1 -Samples 5
#>
param(
    [int]$Samples  = 5,
    [string]$Url   = 'https://localhost:8443/json',
    [int]$DwellSec = 5
)

$chrome = 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
if (-not (Test-Path $chrome)) { throw "Chrome not found: $chrome" }

$ver = (Get-Item $chrome).VersionInfo.ProductVersion
Write-Host "Chrome $ver -> $Url, $Samples runs" -ForegroundColor Cyan

for ($i = 1; $i -le $Samples; $i++) {
    $prof = Join-Path $env:TEMP "curlpro-cap-$i"
    if (Test-Path $prof) { Remove-Item -Recurse -Force $prof -ErrorAction SilentlyContinue }

    $p = Start-Process $chrome -PassThru -ArgumentList @(
        "--user-data-dir=$prof"
        '--no-first-run'
        '--no-default-browser-check'
        '--ignore-certificate-errors'
        '--new-window'
        $Url
    )
    Start-Sleep -Seconds $DwellSec

    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Get-Process chrome -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -eq $chrome } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800

    Remove-Item -Recurse -Force $prof -ErrorAction SilentlyContinue
    Write-Host "  run $i/$Samples done"
}

Write-Host "Done. Analyse with: python analyze.py {path-to-echo-server-log}" -ForegroundColor Green
