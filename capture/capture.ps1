<#
  Снятие эталонного отпечатка браузера с локального fingerproxy echo-server.

  Данные берутся НЕ из stdout браузера (на Windows headless Chrome его не отдаёт),
  а из лога echo-server, который при -verbose печатает полный detail-JSON.

  Каждый прогон — свежий процесс и одноразовый профиль, чтобы гарантировать
  новое TLS-соединение: Chrome ≥110 перемешивает расширения на каждом соединении,
  и профиль по одному сэмплу зафиксирует шум.

  Usage: .\capture.ps1 -Samples 5
#>
param(
    [int]$Samples  = 5,
    [string]$Url   = 'https://localhost:8443/json',
    [int]$DwellSec = 5
)

$chrome = 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
if (-not (Test-Path $chrome)) { throw "Chrome не найден: $chrome" }

$ver = (Get-Item $chrome).VersionInfo.ProductVersion
Write-Host "Chrome $ver -> $Url, $Samples прогонов" -ForegroundColor Cyan

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
    Write-Host "  прогон $i/$Samples готов"
}

Write-Host "Готово. Разбор: python analyze.py {путь-к-логу-echo-server}" -ForegroundColor Green
