@echo off
rem Build chrome from one of chromium/args/*.gn.
rem
rem   chromium\build.cmd iterate      :: the development configuration
rem   chromium\build.cmd release      :: official, ThinLTO + PGO
rem   chromium\build.cmd iterate 14   :: all-out, when nobody needs the machine
rem
rem The target is `chrome` on purpose: building `all` adds every test binary
rem and takes far longer. Set NINJA_SUMMARIZE_BUILD=1 for per-step timings.
rem
rem Six workers at below-normal priority by default, not sixteen. siso sizes
rem its own concurrency from the core count and knows nothing about free
rem memory, and the compile tail reaches ~2.5 GB a job: on this machine that
rem means every core pegged for hours and the browser swapping. Six leaves the
rem box usable and costs perhaps half again as long. Give a number to go
rem faster when the machine is free.
setlocal
set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=iterate
set JOBS=%2
if "%JOBS%"=="" set JOBS=6
set ARGS=%~dp0args\%CONFIG%.gn
if not exist "%ARGS%" (
  echo no such configuration: %ARGS%
  exit /b 2
)
call "%~dp0env.cmd"
set OUT=out\%CONFIG%
cd /d D:\chromium\src || exit /b 1

if not exist "%OUT%" mkdir "%OUT%"
rem gn reads args.gn from the output directory, so the configuration is copied
rem in. Copying rather than symlinking keeps the tree free of links that
rem gclient's `git clean` would argue with.
copy /y "%ARGS%" "%OUT%\args.gn" >nul || exit /b 1
echo [build] %CONFIG% at %DATE% %TIME%
call gn gen "%OUT%" || exit /b 1
rem The MIDL output pinned in the tree must match this SDK's byte for byte;
rem on a revision other than the pinned one, three type libraries do not, and
rem only those are rebaselined, never committed (midl-baseline.py says why).
call python3 "%~dp0midl-baseline.py" "%OUT%" 2 || exit /b 1
echo [build] %JOBS% workers, below-normal priority
start "" /belownormal /b /wait cmd /c "autoninja -C %OUT% -j %JOBS% chrome"
set RC=%ERRORLEVEL%
echo [build] exit %RC% at %DATE% %TIME%
if %RC%==0 echo [build] %OUT%\chrome.exe
exit /b %RC%
