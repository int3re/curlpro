# Stage 24 — a Chromium that reports a measured device

ROADMAP Stage 42. Started 2026-10-02 at the owner's direction: patch Chromium
so that canvas, WebGL and the font list answer for a chosen machine. Decided
with him the same day: a local build, our own patches on stock Chromium 154,
and canvas pixels left alone (the reasoning is in the ROADMAP entry). This
file is what has been measured since.

## The harness

`scripts/fpcapture.py` reads, from a real browser started by the package's
own driver, what a page can read about the machine — every WebGL1 and WebGL2
parameter the context accepts (the enum names are taken from the context, not
from a list of ours), the extensions, the twelve shader precisions, a drawn
triangle read back, a fixed canvas drawing hashed three ways and read twice,
text metrics, the font inventory by three probes, WebGPU, an audio render, and
the usual navigator and screen values — 368 in all on Chrome 154. `-compare`
diffs two records. The records stay out of the repository (`capture/fp/` is
ignored): a font inventory and a GPU name describe somebody's computer.

It is also the acceptance test for the canvas decision: the four checks
CreepJS runs to call a canvas modified — the round trip, the blank canvas, the
2×2 anti-aliased arc against known Blink strings, integer metrics for
`measureText('')` — run on every capture. Stock Chrome 154: **clean**, arc
`000202000202000202000202`. A patched build must answer the same.

## What the light flags change: nothing, now across 340 values

The driver's light flags (Stage 41) had been measured on 22 values. Read with
and without them through the harness: 340 equal, the only difference the
record's own note of which flags were used.

## Two things the prior art gets wrong

- **`document.fonts.check()` is no presence oracle in Chromium.** It answered
  true for all 294 probed families, the three nonexistent controls included.
  Brave is described as leaving this path unhooked; there is nothing to hook.
- **`local()` sees fonts that measurement does not.** Eight families resolved
  through a `local()` source while a measured span could not tell them from
  the fallback (`Britannic Bold`, `OCR A Extended`, `Script MT Bold`, …). A
  font filter on family matching alone leaks through `FontUniqueNameLookup`.

## One machine, two GPUs: what a GPU decides

The measuring laptop has an Intel Iris Xe and an NVIDIA RTX 4050. Chrome uses
the Intel; `--force-high-performance-gpu` — a switch Chromium has, declared in
`gpu/config/gpu_switches.cc` and long thought macOS-only — moves it to the
NVIDIA on Windows too, and adds nothing a page sees (the window's chrome, the
flags-visible values: equal). So one browser, one OS, one machine, two GPUs,
read the same minute:

| | differs |
|---|---|
| `UNMASKED_VENDOR_WEBGL`, `UNMASKED_RENDERER_WEBGL`, WebGL1 and WebGL2 | 4 strings |
| `MAX_VERTEX_UNIFORM_VECTORS` 4096 → 4095, and in WebGL2 `MAX_VERTEX_UNIFORM_COMPONENTS` 16384 → 16380, `MAX_COMBINED_VERTEX_UNIFORM_COMPONENTS` 212992 → 212988 — ANGLE keeps one uniform vector back on NVIDIA | 4 numbers |
| the WebGL triangle read back, both contexts | 2 hashes |
| everything computed from canvas 2D pixels: `toDataURL`, `getImageData`, the offscreen canvas, their sizes | 7 values |
| the other 79 WebGL1 and 129 WebGL2 parameters, all 35 and 32 extensions, all 12 precisions, fonts, text metrics, audio, the 2×2 arc CreepJS checks | **nothing** |

Two consequences, and they reorder the stage.

**On Windows, ANGLE flattens the WebGL block.** Over Direct3D 11 the
parameters are ANGLE's, not the driver's: two GPUs of different vendors differ
in four strings and four numbers. A WebGL transplant between Windows GPUs is
therefore small — and its coherence problem is not in the parameters any more
but in the **pixels**: canvas 2D is rasterised on the GPU, so its hash follows
the physical card, as does anything WebGL draws. Claiming the NVIDIA while
drawing on the Intel puts an NVIDIA string beside Intel pixels. CreepJS's
arc check does not see it — the arc is the same on both — but a site that
keeps canvas hashes by GPU would.

**The cheapest true identity is a real GPU.** This laptop is two complete,
consistent identities without a patch: every value, pixels included, is what
that card produces. That belongs in the driver now, ahead of any build.

## The order, revised by the measurement

1. Toolchain and a baseline build (in progress: the source is syncing, two
   workers, below-normal priority; SDK 10.0.28000 and MFC/ATL still to be
   installed by the owner).
2. The profile plumbing — unchanged.
3. **Fonts first.** Independent of the GPU, the largest list of values, and
   the one change that moves canvas output *honestly*: text drawn with the
   fonts that are really available is a real rendering. All four layers,
   `local()` included.
4. **WebGL after it, and small:** the strings and the handful of limits ANGLE
   lets through, for the cases a real GPU cannot cover — a machine whose own
   GPU is rare or a virtual one — with the pixel caveat said where the option
   is.
5. Canvas: proof that the guards stay clean.
6. Distribution and the rebase.

## The patches, and what "written" means here

Two patches exist (`chromium/patches/`), both exported from commits on the
release tag and both round-tripping onto a clean tag byte for byte. **Neither
has been compiled**: `gn gen` stops before the first file, because Windows SDK
10.0.28000 is missing and `base/win/windows_version.cc` enforces it with an
`#error`. Read code is not working code, and nothing in them is proven.

What was done instead, since a typo would cost a build of hours: every API
they touch was read in the 154.0.8037.100 tree rather than recalled —
`AtomicString::empty()` and `GetString()`, `String::DeprecatedLower()`,
`Utf8()` and `FromUtf8(std::string_view)`, `base::flat_set`'s constructor from
a moved vector and its `contains()`, `base::as_byte_span`, and `IsWebGL2()`,
which is not in `webgl_rendering_context_base.h` at all but inherited from
`WebGLContextObjectSupport`. Two of those did not match what the first draft
assumed. Blink's own `Base64Decode` is used rather than `base/base64.h`, which
platform's DEPS do not allow.

## The build environment, as found

- The tree now **requires Visual Studio 2026** (`MSVC_TOOLSET_VERSION['2026'] =
  'VC145'`), Windows SDK **10.0.28000** (an `#error` in
  `base/win/windows_version.cc`), MFC/ATL, and Debugging Tools ≥
  10.0.26100.3323. There is no remote execution for external contributors on
  Windows.
- `vs_toolchain.py` looks for Visual Studio 2026 under `%ProgramFiles%` only;
  an install on D: needs `vs2026_install`.
- `fetch --git-cache` on Windows writes its cache path into `.gclient`
  unescaped (`"C:\Users\..."`, an invalid Python escape), and gclient then
  refuses to parse its own output. `.gclient` is written by hand.
- gclient's default worker pool (one per core) pegged all sixteen threads,
  took memory to 87%, and the sync died with exit 1 and no message — a worker
  killed for memory. Two workers at below-normal priority finish the same job
  and leave the machine usable; `chromium/sync.cmd` and `build.cmd` do that.
