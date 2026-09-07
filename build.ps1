<#
  Builds the curlpro native library.

  cgo needs a C compiler. On Windows that is MinGW-w64 (x86_64, posix threads):
  winget install BrechtSanders.WinLibs.POSIX.UCRT
  or an unpacked archive from winlibs.com.

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
        throw "gcc not found. Install MinGW-w64 or give the path: .\build.ps1 -CC path\to\gcc.exe"
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
if ($LASTEXITCODE -ne 0) { throw "the build failed" }

Get-ChildItem $Out | Select-Object Name, @{n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } }
Write-Host 'Done. Check with: cd python; $env:PYTHONPATH="."; python -m pytest tests' -ForegroundColor Green
