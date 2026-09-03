<#
  Сборка нативной библиотеки curlpro.

  cgo требует C-компилятора. На Windows это MinGW-w64 (x86_64, posix threads):
  winget install BrechtSanders.WinLibs.POSIX.UCRT
  либо распакованный архив с winlibs.com.

  Usage: .\build.ps1 [-CC D:\mingw64\bin\gcc.exe]
#>
param(
    [string]$CC = "",
    [string]$Out = "dist"
)

$ErrorActionPreference = 'Stop'

if (-not $CC) {
    $found = @(
        "D:\mingw64\bin\gcc.exe",
        "C:\mingw64\bin\gcc.exe",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Links\gcc.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $found) {
        $found = (Get-Command gcc -ErrorAction SilentlyContinue).Source
    }
    if (-not $found) {
        throw "gcc не найден. Установите MinGW-w64 или укажите путь: .\build.ps1 -CC путь\к\gcc.exe"
    }
    $CC = $found
}

$env:PATH = (Split-Path $CC) + ";C:\Program Files\Go\bin;$env:PATH"
$env:CGO_ENABLED = "1"
$env:CC = $CC

Write-Host "CC: $CC" -ForegroundColor Cyan
New-Item -ItemType Directory -Force $Out | Out-Null

$ErrorActionPreference = 'Continue'
go build -buildmode=c-shared -o "$Out\curlpro.dll" ./lib
if ($LASTEXITCODE -ne 0) { throw "сборка не удалась" }

Get-ChildItem $Out | Select-Object Name, @{n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } }
Write-Host 'Готово. Проверка: cd python; $env:PYTHONPATH="."; python -m pytest tests' -ForegroundColor Green
