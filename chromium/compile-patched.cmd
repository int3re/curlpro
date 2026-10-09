@echo off
rem Compile the files the patches touch, and nothing else.
rem
rem   chromium\compile-patched.cmd            :: 2 workers, below-normal
rem   chromium\compile-patched.cmd iterate 8  :: a configuration and a count
rem
rem Minutes rather than the hours a full build takes, and it catches every
rem syntax and type error in our own C++ before a night is spent on one.
rem
rem The object paths, not `source.cc^`: that single-object syntax ninja
rem documents resolved to nothing under siso and reported "no work to do" --
rem a silent no-op that reads exactly like a successful compile, while no
rem object was written. These names come from the generated .ninja files
rem (obj/<dir>/<target>/<file>.obj) and a wrong one fails loudly.
rem
rem Two workers by default. Six put `MemoryError` in two Blink generators and
rem `LLVM ERROR: out of memory` in clang: the compile tail reaches ~2.5 GB a
rem job and this machine had 5 GB of RAM and 9 GB of commit free. Raise it
rem when the machine is empty.
setlocal
set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=iterate
set JOBS=%2
if "%JOBS%"=="" set JOBS=2
call "%~dp0env.cmd"
cd /d D:\chromium\src || exit /b 1
if not exist "out\%CONFIG%\args.gn" (
  echo [compile] no out\%CONFIG% -- run chromium\build.cmd %CONFIG% first
  exit /b 2
)
set OBJS=obj/third_party/blink/renderer/platform/platform/fingerprint.obj obj/third_party/blink/renderer/platform/platform/font_cache_skia_win.obj obj/third_party/blink/renderer/modules/webgl/webgl/webgl_rendering_context_base.obj obj/components/embedder_support/user_agent/user_agent_utils.obj
echo [compile] %CONFIG%, %JOBS% workers, below-normal, at %DATE% %TIME%
start "" /belownormal /b /wait cmd /c "autoninja -C out\%CONFIG% -j %JOBS% %OBJS%"
set RC=%ERRORLEVEL%
echo [compile] exit %RC% at %DATE% %TIME%
if %RC%==0 echo [compile] the patched files compile
exit /b %RC%
