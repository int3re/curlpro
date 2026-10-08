# The fork's design

What the patches do and why each one is where it is. Measurements behind the
decisions are in [docs/STAGE24-RESULTS.md](../docs/STAGE24-RESULTS.md); the
plan is ROADMAP Stage 42.

## The rule the rest follows

**Serve a measured device, never claim a capability the machine lacks.** A
profile is a transcript of a real browser on a real machine
(`scripts/fpcapture.py`). Values are only ever moved *down* to a target's:
a WebGL limit lower than the host's (the RTX 4050's 4095 uniform vectors
over the Iris Xe's 4096) is safe, because a page that trusts it asks for
less. A limit *higher* than the host's would be a lie the first texture that
uses it exposes — the page breaks, and the break is the mark. Such a value is
not served; the host's is, and the build logs that the profile asked for
more than this machine has.

Canvas pixels and anything WebGL draws are never touched (ROADMAP Stage 42:
the four CreepJS checks catch any interference, and Intel and NVIDIA pixels
differ anyway — they follow the card).

## How the profile reaches the page

```
the package's driver (curlpro.browser.Chrome)
  │  chrome.exe --curlpro-fingerprint=<base64 of the profile's compact JSON>
  ▼
browser process: forwards the switch, does not read it
  │  one entry in kSwitchNames, RenderProcessHostImpl::PropagateBrowserCommandLineToRenderer
  ▼
renderer: blink::curlpro::Fingerprint::Get(), parsed once per process
  ▼
WebGL getParameter(UNMASKED_*), the limit helpers, the font matching
```

- **The driver passes the data, the browser only forwards it.** A renderer
  is sandboxed and cannot open a file. The first design had the browser read
  a profile file and hand renderers its contents; but a blocking read on the
  browser's UI thread needs `ScopedAllowBlocking`, whose constructor is
  private to an allow-list of call sites. The browser is started by the
  package's own driver anyway, so the driver puts the data itself on the
  command line and the browser's patch shrinks to one name in the list of
  switches it already forwards to renderers. Base64, because a JSON value's
  quotes and spaces through Windows command-line quoting is a parser bug
  waiting to happen, and base64 has none to quote. The RTX 4050's profile —
  47 limits, two strings, 157 fonts — is 7,444 characters, against Windows'
  32,767 for a whole command line.
- **A switch of our own, not a known one.** Chrome raises its "unsupported
  command-line flag" infobar only for the flags listed in
  `bad_flags_prompt.cc`; an unlisted switch raises nothing. Stage 40 measured
  why that matters: the infobar is 56 px of window chrome a page can read.
- **Process-wide first, per tab later.** One profile per browser process is
  what the command line carries. One browser holding several identities —
  Stage 41's step 2 — needs the profile per `WebContents`, the way
  `WebPreferences` travels; that is a later patch on the same reader.
- **The reader lives in Blink's platform layer**
  (`third_party/blink/renderer/platform/curlpro/`). Every consumer — WebGL in
  `modules/webgl`, fonts in `platform/fonts` — can depend on platform, and
  platform may already include `base/command_line.h` and `base/json`; the
  one addition to its `DEPS` is `base/base64.h`. No new top-level directory,
  no dependency reaching across the tree.

## Where each value is served

| Value | Hook | Why there |
|---|---|---|
| `UNMASKED_VENDOR_WEBGL`, `UNMASKED_RENDERER_WEBGL` | the two cases in `WebGLRenderingContextBase::getParameter` (`webgl_rendering_context_base.cc`) | the only strings that moved between two real GPUs. Not `GLES2Implementation::GetStringHelper`: it serves every GL client in the renderer, and only WebGL is the page's |
| the WebGL limits | `WebGLRenderingContextBase::GetIntParameter` and its siblings, by enum | one place serves both WebGL1 and WebGL2; lowered only (the rule above) |
| the font inventory | the top of `FontCache::CreateFontPlatformData` (`font_cache_skia_win.cc`) | both paths meet there — a CSS family name and a `local()` source — so one filter serves both. Brave filters family matching alone, and measured here that leaks eight families `local()` still resolves. `AlternateFontName::kLastResort` is never filtered: it is Chromium's own fallback, and hiding it leaves glyphs unrendered, which is louder than any font list |
| `document.fonts.check()` | nothing | measured: it answers true for families that do not exist |

## The profile file

Written from an `fpcapture` record of the target device, by
`scripts/fpcapture.py -profile`:

```json
{
  "source": "rtx4050 — fpcapture, Chrome 154.0.8037.98, 2026-10-08",
  "webgl": {
    "unmasked_vendor": "Google Inc. (NVIDIA)",
    "unmasked_renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 4050 Laptop GPU (0x000028A1) Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "parameters": {"MAX_VERTEX_UNIFORM_VECTORS": 4095},
    "webgl2_parameters": {"MAX_VERTEX_UNIFORM_COMPONENTS": 16380,
                          "MAX_COMBINED_VERTEX_UNIFORM_COMPONENTS": 212988,
                          "MAX_VERTEX_UNIFORM_VECTORS": 4095}
  }
}
```

The parameter blocks carry the target's whole measured block, not only what
differed on one host: another host's ANGLE may differ elsewhere. `fonts.present`
is every family any of the three probes found on the target.

**A font list is a measured device's whole inventory, never a hand-made
subset.** It is served with its gaps — a page wanting a script font the target
genuinely lacks renders as it would render on the target, which is the point.
A subset invented by hand would take Chromium's own fallback fonts away and
leave glyphs unrendered, and boxes where text belongs are a louder signal than
the font list ever was.

## The first proof

The cleanest test available, because the measuring laptop has both cards:
build on the Intel (the default), serve the RTX 4050's record, and diff the
patched build's capture against the **real** RTX 4050 capture. What must
remain different is exactly the pixels — canvas 2D and the WebGL triangle,
which follow the card that drew them. Every string and limit must match.

The fonts have a proof of their own, and it needs no second machine: serve a
profile whose list leaves out a family this machine has, and read the three
probes. All three must lose it at once — the measured span, `local()`, and the
text metrics that draw with it. A profile with no font list must leave all 157
of them exactly as they are.

And the guards must stay clean through both: the four canvas checks that call
a canvas modified (`fpcapture` runs them on every capture) answer the same on
the patched build as on stock Chrome, because nothing here touches a pixel.

## Following upstream

The patches are commits on a local branch over the release tag
(`v154.0.8037.100`), exported with `git format-patch` into
`chromium/patches/` and applied in filename order. A new milestone is
`checkout.cmd <tag>` and the patches again; one that no longer applies is
reported, not forced.
