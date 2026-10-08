@echo off
rem The environment every script here runs depot_tools in. One file, so that
rem the next thing learned the hard way is learned once.

set PATH=D:\depot_tools;%PATH%

rem Use the Visual Studio installed here, not Google's internal toolchain
rem package, which depot_tools would otherwise try to download.
set DEPOT_TOOLS_WIN_TOOLCHAIN=0
set DEPOT_TOOLS_METRICS=0

rem vs_toolchain.py looks for Visual Studio 2026 under %ProgramFiles%\...\18
rem and nowhere else; this machine's install is on D:.
set vs2026_install=D:\Program Files\Microsoft Visual Studio\18\Community

rem Short paths on D:, outside %LOCALAPPDATA%. Run from an MSIX-packaged app
rem (the Claude desktop app is one), writes to %LOCALAPPDATA% are redirected
rem into %LOCALAPPDATA%\Packages\<app>\LocalCache\Local\..., some fifty
rem characters longer: Chromium's Python venv then failed to install, pip
rem reporting a path past MAX_PATH ("google\cloud\bigquery_storage_v1alpha\
rem services\metastore_partition_service\transports\grpc_asyncio.py"). The
rem git mirror was moved off C: for room; vpython and CIPD for length.
set DEPOT_TOOLS_CACHE_DIR=D:/chromium/git-cache
set VPYTHON_VIRTUALENV_ROOT=D:\chromium\.vpython
set CIPD_CACHE_DIR=D:\chromium\.cipd-cache
