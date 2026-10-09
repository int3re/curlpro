# chromium/

The fork: build configuration, patches and the scripts that apply them.
Stage 42 in [../ROADMAP.md](../ROADMAP.md) says why it exists and what was
decided; this file says how to run it.

The Chromium checkout itself is **not** in this repository — it is ~150 GB.
It lives at `D:\chromium` (`src` under it), with depot_tools at
`D:\depot_tools` and a shared git mirror at `D:\chromium\git-cache`.

| Here | What |
|---|---|
| `args/iterate.gn` | the build to develop against: component, no symbols, minutes per patch |
| `args/release.gn` | the build to ship: official, ThinLTO and PGO, as a real Chrome is built |
| `env.cmd` | the environment every script runs depot_tools in — one place for what was learned the hard way |
| `sync.cmd` | fetch or finish fetching the source, two workers, below-normal |
| `checkout.cmd` | put the tree on the release branch this fork targets and sync its DEPS |
| `build.cmd` | build `chrome` from one of the arg sets |
| `patches/` | our patches, `git format-patch` files, the one source of the fork's code |
| `patches.cmd` | apply them to the tree, in filename order, as commits (`git am --3way`) |
| `midl-baseline.py` | make the tree's pinned MIDL output agree with this SDK where only type libraries differ; `build.cmd` runs it |
| `DESIGN.md` | what each patch does and why it is where it is |

## What the tree requires

Measured against the 154 source, 2026-10-02 — the commonly-repeated advice is
out of date on every one of these:

- **Visual Studio 2026** (≥ 18.0), MSVC toolset `VC145`, with the
  "Desktop development with C++" workload **and the MFC/ATL sub-component**.
  VS 2022 is no longer the packaged toolchain.
- **Windows 11 SDK 10.0.28000**, enforced by `#error Windows 10.0.28000.0 SDK
  or higher required.` in `base/win/windows_version.cc`. Debugging Tools
  ≥ 10.0.26100.3323, for the large-page PDBs Chrome uses.
- `DEPOT_TOOLS_WIN_TOOLCHAIN=0`, or depot_tools tries to download Google's
  internal toolchain, which is not ours to have.
- Short cache paths off `%LOCALAPPDATA%` when the scripts are started from an
  MSIX-packaged app (the Claude desktop app is one): Windows redirects such a
  process's writes there into `%LOCALAPPDATA%\Packages\<app>\LocalCache\...`,
  some fifty characters longer, and Chromium's Python venv then failed to
  install past `MAX_PATH`. `env.cmd` puts vpython, CIPD and the git mirror
  under `D:\chromium`.
- `vs2026_install` pointing at the install, when Visual Studio is not on C:.
  `vs_toolchain.py` searches `%ProgramFiles%\...\18` and nowhere else, so an
  install on D: is simply not found; the scripts here set it.
- **Defender excluding `D:\chromium` and `D:\depot_tools`.** Not a nicety:
  reports of the same machine building in 30 min with exclusions and 90+
  without are in the chromium-dev archives, and the official "why is my build
  slow" answer leads with it.
- `enable_nacl` must **not** be set. NaCl and PPAPI are gone from the tree and
  the argument now fails `gn gen` as unused. Every third-party arg list on the
  web still carries it.
- There is **no remote build execution for external contributors on Windows**.
  Every build is local; plan in hours, not minutes.

## The SDK revision has to be the pinned one, not just the pinned version

The tree names an exact servicing revision — `docs/windows_build_instructions.md`
in 154.0.8037.100 asks for **10.0.28000.2270** — and it means it. Chromium
checks pre-generated MIDL output into `third_party/win_build_output/midl/`
because `midl.exe` is not reproducible across SDK revisions, and
`build/toolchain/win/midl.py` compares byte for byte with no flag and no
environment variable to skip it. Build with another revision and it stops:

```
midl.exe output different from files in gen/chrome/windows_services/...
To rebaseline: copy /y <tmp>\* ..\..\third_party\win_build_output\midl\...
```

The Visual Studio Installer's `Windows11SDK.28000` component gave
**10.0.28000.2114** here (May 2026) against the pinned .2270 (June 2026), and
every directory is still named `10.0.28000.0`, so only
`(Get-Item '...\bin\10.0.28000.0\x64\midl.exe').VersionInfo.ProductVersion`
tells them apart. And .2270 cannot be had any more: winget carries .1721,
.2114 and .2526, the downloads page offers the newest, and the archive page
lists no 28000 at all (checked 2026-10-09).

So what actually differs was measured, all nineteen MIDL actions at once:
every `.h`, `_i.c`, `_p.c` and `dlldata.c` is byte-identical on .2114, and
four **type libraries** are not — `updater_legacy_idl` with its `_user` and
`_system` variants, and `windows_services`' `tracing_service_idl`. Ten bytes
each, at the same size: a two-byte value and two four-byte words of the
library's internal tables swapped between `00000000` and `FFFFFFFF`. `chrome`
depends on two of them, both through `chrome/browser:core` (`gn path`): the
updater's header, to talk to GoogleUpdate, and the elevated tracing service's,
to start it. It uses neither `.tlb` as code.

`midl-baseline.py` does what `midl.py`'s own message says — "To rebaseline:
copy …" — but only for type libraries, and only when every text output of the
same action already matches; a difference in anything a compiler reads stops
it, with the files named, and then it is the pinned SDK that is needed.
`build.cmd` runs it before every build. The copied files are machine-specific
and never committed: `checkout.cmd` and `patches.cmd` put the pinned ones back
(`git checkout -- "third_party/win_build_output/midl/*.tlb"`) before they look
for a clean tree.

`compile-patched.cmd` builds only the files our patches touch and needs no
MIDL at all.

## Line endings

`C:\Program Files\Git\etc\gitconfig` sets `core.autocrlf=true` for the whole
machine, and the tree's files are LF. A file rewritten from Windows — or
merely checked out again under that setting — comes back CRLF: git normalises
it on commit, so the patch is clean, but the working copy no longer matches
what every other file is. The tree is set `core.autocrlf=false` locally, as
Chromium's own Windows instructions ask.

## Not taking the machine over

Both `sync.cmd` and `build.cmd` run at below-normal priority with a small
number of workers (two and six), because the tools do not do this themselves:
gclient and siso size their pools from the core count and know nothing about
free memory. On this machine the default pools pegged all sixteen threads and
put memory at 87%, and the sync then **died with exit 1 and no error message**
— which is what a worker killed for want of memory looks like from outside.
Both take a worker count as an argument for when the machine is free.

## Building

```cmd
chromium\checkout.cmd            :: once per milestone: branch + DEPS
chromium\build.cmd iterate       :: or: chromium\build.cmd release
```

`iterate` is a component build with `symbol_level=0`: a full build in 3–6 h on
twelve cores, and **1–3 minutes** for a changed `.cc` afterwards, because only
the one component DLL relinks. It is not what a shipped Chrome behaves like —
DCHECKs are off but there is no LTO and no PGO — so a fingerprint claim is
only ever *proven* on a `release` build.

`release` is `is_official_build=true`, which pulls in ThinLTO, PGO phase 2 and
full symbols by itself; it takes 2–3× as long and tens of minutes per
incremental edit. The PGO profile comes from `checkout_pgo_profiles: True` in
`D:\chromium\.gclient` — without it `gn gen` stops on a missing profile.

## Proving a build

```cmd
python scripts\fpcapture.py -name patched -chrome D:\chromium\src\out\iterate\chrome.exe
python scripts\fpcapture.py -compare capture\fp\this-machine.json capture\fp\patched.json
```

Every value the patch claims to serve must equal the target device's, and
every value it does not touch must equal this machine's. A baseline build with
no patches must differ from the installed Chrome in **nothing a page can read**
except the brand list, which an unbranded Chromium reports as `Chromium`
rather than `Google Chrome` — that difference is itself one of the things the
patches have to put right, out of the profile that already records it.

## Following upstream

A milestone every four weeks. `checkout.cmd` takes the branch as an argument,
the patches are applied in filename order and any that no longer applies is
reported rather than forced. The branch number is the third component of a
Chrome version: 154.0.**8037**.93 → `branch-heads/8037`. Current stable comes
from `https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows`.

## Identity

The tree's commits become the patches, and the patches are published with
this repository: the tree's **local** git identity must be the repository's
own (`int3re` and its GitHub noreply address), set once with
`git -C D:\chromium\src config --local user.name/user.email`. On the
measuring machine the global identity is another one, and the first patch
went out with it before this was caught. Before committing a patch, its
`From:` line is checked.

## Licence

Chromium is BSD-3; its `LICENSE` and the notices of its third-party code
travel with any binary we distribute. The Google branding, the Google API keys
and the `Google Chrome` name are not ours to ship — the build is Chromium with
our patches, and what it *reports* to a page is a separate question, answered
from a profile, which is the whole point of the stage.
