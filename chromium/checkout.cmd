@echo off
rem Put the tree on the release this fork targets, and sync its DEPS.
rem
rem   chromium\checkout.cmd                    :: the release below, two workers
rem   chromium\checkout.cmd 154.0.8037.100     :: an exact release, by its tag
rem   chromium\checkout.cmd 8078               :: the head of a release branch
rem   chromium\checkout.cmd 154.0.8037.100 6   :: more workers, the machine free
rem
rem A tag, not a branch head, for anything that is shipped: the head of
rem branch-heads/8037 was 154.0.8037.152 on 2026-10-08, a version that never
rem reached the stable channel (.100 had, the day before) -- a browser that
rem names a Chrome no one runs. Stable versions are listed at
rem https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows
rem
rem A release branch pins its sub-repos to commits that live on branch-heads
rem refs, which a default sync does not fetch -- hence --with_branch_heads on
rem every sync here. Like sync.cmd it runs few workers at below-normal priority:
rem gclient's default pool pegged the machine and died for want of memory.
setlocal
set REF=%1
if "%REF%"=="" set REF=154.0.8037.100
set JOBS=%2
if "%JOBS%"=="" set JOBS=2
call "%~dp0env.cmd"
cd /d D:\chromium\src || exit /b 1

echo [checkout] %REF% at %DATE% %TIME%
rem gclient may rewrite origin when it hits trouble; the docs say to check it.
for /f "delims=" %%u in ('git remote get-url origin') do set ORIGIN=%%u
echo [checkout] origin is %ORIGIN%

rem The reset below discards whatever the tree holds. Our patches live in
rem chromium/patches/ and are applied by a script, so a clean tree loses
rem nothing -- but a dirty one may be work not yet written down there.
for /f "delims=" %%s in ('git status --porcelain --untracked-files=no') do (
  echo [checkout] the tree has uncommitted changes; save them as patches first:
  git status --short --untracked-files=no
  exit /b 3
)

rem /l: findstr reads "." as a regular expression otherwise, which any branch
rem number matches.
echo %REF%| findstr /l /c:"." >nul
if errorlevel 1 (
  set TARGET=refs/remotes/branch-heads/%REF%
  set LOCAL=b%REF%
  call git fetch origin +refs/branch-heads/%REF%:refs/remotes/branch-heads/%REF% || exit /b 1
) else (
  set TARGET=refs/tags/%REF%
  set LOCAL=v%REF%
  call git fetch origin +refs/tags/%REF%:refs/tags/%REF% || exit /b 1
)
rem A local branch, not a detached HEAD: our patches are committed onto it.
call git rev-parse --verify --quiet refs/heads/%LOCAL% >nul
if errorlevel 1 (
  call git checkout -b %LOCAL% %TARGET% || exit /b 1
) else (
  call git checkout %LOCAL% || exit /b 1
)
call git reset --hard %TARGET% || exit /b 1
for /f "delims=" %%v in ('python3 build\util\version.py -f chrome\VERSION -t "@MAJOR@.@MINOR@.@BUILD@.@PATCH@"') do echo [checkout] tree is %%v

echo [checkout] DEPS and hooks, %JOBS% workers, below-normal priority, at %TIME%
start "" /belownormal /b /wait cmd /c "gclient sync --with_branch_heads --with_tags -D --reset --jobs %JOBS%"
set RC=%ERRORLEVEL%
echo [checkout] exit %RC% at %DATE% %TIME%
if not %RC%==0 echo [checkout] run it again -- gclient continues where it stopped
exit /b %RC%
