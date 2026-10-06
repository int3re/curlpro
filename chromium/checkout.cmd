@echo off
rem Put the tree on the release branch this fork targets, and sync its DEPS.
rem
rem   chromium\checkout.cmd            :: the default branch below
rem   chromium\checkout.cmd 8078       :: another milestone, for a rebase
rem
rem The branch number is the third component of a Chrome version:
rem 154.0.8037.93 -> branch-heads/8037. A release branch pins its sub-repos to
rem commits that live on branch-heads refs, which a default sync does not
rem fetch -- hence --with_branch_heads on every sync here, not just the first.
setlocal
set BRANCH=%1
if "%BRANCH%"=="" set BRANCH=8037
set PATH=D:\depot_tools;%PATH%
set DEPOT_TOOLS_WIN_TOOLCHAIN=0
set DEPOT_TOOLS_METRICS=0
set DEPOT_TOOLS_CACHE_DIR=D:/chromium/git-cache
rem Visual Studio is on D: here, where vs_toolchain.py does not look.
set vs2026_install=D:\Program Files\Microsoft Visual Studio\18\Community
cd /d D:\chromium\src || exit /b 1

echo [checkout] branch-heads/%BRANCH% at %DATE% %TIME%
rem gclient may rewrite origin when it hits trouble; the docs say to check it.
for /f "delims=" %%u in ('git remote get-url origin') do set ORIGIN=%%u
echo [checkout] origin is %ORIGIN%

call git fetch --tags origin +refs/branch-heads/%BRANCH%:refs/remotes/branch-heads/%BRANCH% || exit /b 1
call git rev-parse --verify --quiet refs/heads/b%BRANCH% >nul
if errorlevel 1 (
  call git checkout -b b%BRANCH% refs/remotes/branch-heads/%BRANCH% || exit /b 1
) else (
  call git checkout b%BRANCH% || exit /b 1
)
rem A detached HEAD cannot be committed to and gclient would move it; a local
rem branch is what the release-branch instructions use.
call git reset --hard refs/remotes/branch-heads/%BRANCH% || exit /b 1
for /f "delims=" %%v in ('python build\util\version.py -f chrome\VERSION -t "@MAJOR@.@MINOR@.@BUILD@.@PATCH@"') do echo [checkout] tree is %%v

echo [checkout] sync with hooks at %TIME% -- toolchain, PGO profile and every DEPS
call gclient sync --with_branch_heads --with_tags -D --reset
set RC=%ERRORLEVEL%
echo [checkout] exit %RC% at %DATE% %TIME%
exit /b %RC%
