@echo off
rem Fetch or finish fetching the Chromium source, without taking the machine
rem over.
rem
rem   chromium\sync.cmd          :: two workers, below-normal priority
rem   chromium\sync.cmd 6        :: more workers, when nobody is using the box
rem
rem Why the default is two. gclient sizes its worker pool from the core count:
rem on sixteen threads that is ~20 python processes at once, each over 100 MB.
rem Measured here on 2026-10-02: every core pegged, 87% of memory in use, and
rem the sync itself died -- exit 1 after four minutes with no error message at
rem all, which is what a worker killed for want of memory looks like from the
rem outside. Two workers finish the same job in about an hour and leave the
rem machine usable.
rem
rem Interrupting this is safe. gclient resumes: every sub-repo it already
rem fetched is kept, and the shared mirror under D:\chromium\git-cache means a
rem second run re-downloads nothing.
setlocal
set JOBS=%1
if "%JOBS%"=="" set JOBS=2
set PATH=D:\depot_tools;%PATH%
set DEPOT_TOOLS_WIN_TOOLCHAIN=0
set DEPOT_TOOLS_METRICS=0
set DEPOT_TOOLS_CACHE_DIR=D:/chromium/git-cache
set vs2026_install=D:\Program Files\Microsoft Visual Studio\18\Community
cd /d D:\chromium || exit /b 1
echo [sync] %JOBS% workers, below-normal priority, start %DATE% %TIME%
start "" /belownormal /b /wait cmd /c "gclient sync --nohooks --with_branch_heads --with_tags --jobs %JOBS%"
set RC=%ERRORLEVEL%
echo [sync] exit %RC% at %DATE% %TIME%
if not %RC%==0 echo [sync] run it again -- it continues where it stopped
exit /b %RC%
