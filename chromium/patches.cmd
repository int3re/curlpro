@echo off
rem Apply chromium/patches/*.patch to the tree, in filename order, as commits
rem on the current local branch (checkout.cmd made it, at the release tag).
rem
rem   chromium\patches.cmd
rem
rem git am --3way: a patch whose context moved in a newer release is merged
rem when git can, and stops with the conflict named when it cannot -- reported,
rem never forced. After fixing it: git am --continue, then format-patch again.
rem
rem Writing a new patch: edit in D:\chromium\src, commit on the branch, then
rem   git -C D:\chromium\src format-patch -1 HEAD --no-signature -o D:\curlPro\chromium\patches
rem with the tree's local git identity set to the repository's own
rem (chromium/README.md, "Identity").
setlocal
call "%~dp0env.cmd"
cd /d D:\chromium\src || exit /b 1
rem Type libraries midl-baseline.py rebaselined for this machine's SDK are
rem not work to keep: the pinned ones go back before the tree is judged.
call git checkout -- "third_party/win_build_output/midl/*.tlb" 2>nul
for /f "delims=" %%s in ('git status --porcelain --untracked-files=no') do (
  echo [patches] the tree has uncommitted changes; apply onto a clean tree
  exit /b 3
)
set COUNT=0
for %%p in ("%~dp0patches\*.patch") do (
  echo [patches] %%~nxp
  call git am --3way --keep-cr "%%p" || (
    echo [patches] %%~nxp does not apply: resolve, git am --continue, re-export
    exit /b 1
  )
  set /a COUNT+=1
)
echo [patches] applied %COUNT%
for /f "delims=" %%l in ('git log --oneline -n %COUNT%') do echo [patches]   %%l
