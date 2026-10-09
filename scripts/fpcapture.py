"""Record what a page can read about the machine's graphics and fonts, from a
real browser, and diff two such records.

Why this exists. Stage 42 patches Chromium so that canvas, WebGL and the font
list report a chosen device instead of the one the build runs on. A value can
only be served if it has been measured first: the WebGL parameter block, the
extension list, the shader precisions and the font inventory are *data*, and
this is the tool that collects them — the same relationship the HTTP profiles
have with ``cmd/hcapture``. Nothing here is invented; a record is a transcript
of one browser on one machine.

It is also the test. After the patch, the same page is read from the patched
build and the two records are diffed: every value the patch claims to serve
must equal the target's, and every value it does not touch must equal the
host's. ``-compare`` prints that diff.

Running it::

    python scripts/fpcapture.py -name this-machine        # the installed Chrome
    python scripts/fpcapture.py -name patched -chrome D:\\chromium\\src\\out\\Release\\chrome.exe
    python scripts/fpcapture.py -compare capture/fp/this-machine.json capture/fp/patched.json

The page is served over plain HTTP on 127.0.0.1, which Chromium counts as a
secure context, so ``crypto.subtle`` (the canvas hashes) and WebGPU work
without a certificate.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

#: Families probed for presence. The point is not to be exhaustive — it is to
#: cover what a fingerprinting script probes: the fonts a Windows edition
#: ships (and so the ones that identify an edition), the Office and Adobe
#: installs that identify a *machine*, the macOS and Linux sets whose absence
#: tells the platforms apart, and a few that exist nowhere, as controls.
FONTS = [
    # Windows, shipped with the OS
    "Arial", "Arial Black", "Arial Narrow", "Bahnschrift", "Calibri", "Cambria",
    "Cambria Math", "Candara", "Comic Sans MS", "Consolas", "Constantia", "Corbel",
    "Courier New", "Ebrima", "Franklin Gothic Medium", "Gabriola", "Gadugi", "Georgia",
    "HoloLens MDL2 Assets", "Impact", "Ink Free", "Javanese Text", "Leelawadee UI",
    "Lucida Console", "Lucida Sans Unicode", "Malgun Gothic", "Marlett",
    "Microsoft Himalaya", "Microsoft JhengHei", "Microsoft New Tai Lue",
    "Microsoft PhagsPa", "Microsoft Sans Serif", "Microsoft Tai Le",
    "Microsoft YaHei", "Microsoft Yi Baiti", "MingLiU-ExtB", "Mongolian Baiti",
    "MS Gothic", "MV Boli", "Myanmar Text", "Nirmala UI", "Palatino Linotype",
    "Segoe Fluent Icons", "Segoe MDL2 Assets", "Segoe Print", "Segoe Script",
    "Segoe UI", "Segoe UI Emoji", "Segoe UI Historic", "Segoe UI Symbol",
    "Segoe UI Variable", "SimSun", "Sitka", "Sylfaen", "Symbol", "Tahoma",
    "Times New Roman", "Trebuchet MS", "Verdana", "Webdings", "Wingdings",
    "Yu Gothic",
    # Windows, with an edition or a language pack
    "Aharoni", "Aldhabi", "Andalus", "Angsana New", "AngsanaUPC", "Aparajita",
    "Arabic Typesetting", "Batang", "BIZ UDGothic", "BIZ UDMincho", "Browallia New",
    "David", "DengXian", "DFKai-SB", "DilleniaUPC", "DokChampa", "Dotum",
    "Estrangelo Edessa", "EucrosiaUPC", "Euphemia", "FangSong", "Fixedsys",
    "FrankRuehl", "Gautami", "Gisha", "Gulim", "Gungsuh", "IrisUPC", "Iskoola Pota",
    "JasmineUPC", "KaiTi", "Kalinga", "Kartika", "Khmer UI", "KodchiangUPC", "Kokila",
    "Lao UI", "Latha", "Levenim MT", "LilyUPC", "Lucida Sans", "Mangal", "Meiryo",
    "Miriam", "MoolBoran", "MS Mincho", "MS PGothic", "MS PMincho", "MS UI Gothic",
    "Narkisim", "NSimSun", "Nyala", "Plantagenet Cherokee", "Raavi", "Rod",
    "Sakkal Majalla", "Shonar Bangla", "Shruti", "SimHei", "Simplified Arabic",
    "Traditional Arabic", "Tunga", "Urdu Typesetting", "Utsaah", "Vani", "Vijaya",
    "Vrinda", "Yu Mincho",
    # Office and Adobe: not the OS, so they identify the machine
    "Agency FB", "Algerian", "Bauhaus 93", "Bell MT", "Berlin Sans FB", "Bernard MT Condensed",
    "Bodoni MT", "Book Antiqua", "Bookman Old Style", "Bookshelf Symbol 7",
    "Bradley Hand ITC", "Britannic Bold", "Broadway", "Brush Script MT", "Californian FB",
    "Calisto MT", "Castellar", "Centaur", "Century", "Century Gothic", "Century Schoolbook",
    "Chiller", "Colonna MT", "Cooper Black", "Copperplate Gothic Bold", "Curlz MT",
    "Edwardian Script ITC", "Elephant", "Engravers MT", "Eras Bold ITC", "Felix Titling",
    "Footlight MT Light", "Forte", "Franklin Gothic Book", "Freestyle Script",
    "French Script MT", "Garamond", "Gigi", "Gill Sans MT", "Gloucester MT Extra Condensed",
    "Goudy Old Style", "Goudy Stout", "Haettenschweiler", "Harlow Solid Italic",
    "Harrington", "High Tower Text", "Imprint MT Shadow", "Informal Roman", "Jokerman",
    "Juice ITC", "Kristen ITC", "Kunstler Script", "Lucida Bright", "Lucida Calligraphy",
    "Lucida Fax", "Lucida Handwriting", "Magneto", "Maiandra GD", "Matura MT Script Capitals",
    "Mistral", "Modern No. 20", "Monotype Corsiva", "MT Extra", "Niagara Engraved",
    "Niagara Solid", "OCR A Extended", "Old English Text MT", "Onyx", "Palace Script MT",
    "Papyrus", "Parchment", "Perpetua", "Playbill", "Poor Richard", "Pristina",
    "Rage Italic", "Ravie", "Rockwell", "Script MT Bold", "Showcard Gothic", "Snap ITC",
    "Stencil", "Tempus Sans ITC", "Tw Cen MT", "Viner Hand ITC", "Vivaldi", "Vladimir Script",
    "Wide Latin", "Adobe Arabic", "Adobe Devanagari", "Adobe Fan Heiti Std",
    "Adobe Hebrew", "Adobe Ming Std", "Adobe Myungjo Std", "Adobe Naskh Medium",
    "Adobe Song Std", "Courier Std", "Minion Pro", "Myriad Pro", "Source Code Pro",
    # Developer and game installs, same reasoning
    "Cascadia Code", "Cascadia Mono", "Fira Code", "Inconsolata", "JetBrains Mono",
    "Roboto", "Roboto Mono", "Open Sans", "Noto Sans", "Noto Color Emoji",
    "Nimbus Sans", "DejaVu Sans", "DejaVu Serif", "DejaVu Sans Mono", "Liberation Sans",
    "Liberation Serif", "Liberation Mono", "Ubuntu", "Cantarell", "FreeSans",
    # macOS, to tell a lying platform from a true one
    "American Typewriter", "Andale Mono", "Apple Chancery", "Apple Color Emoji",
    "AppleGothic", "Avenir", "Avenir Next", "Baskerville", "Big Caslon", "Bodoni 72",
    "Chalkboard", "Chalkduster", "Charter", "Cochin", "Copperplate", "Didot",
    "Futura", "Geneva", "Gill Sans", "Helvetica", "Helvetica Neue", "Herculanum",
    "Hoefler Text", "Iowan Old Style", "Lucida Grande", "Luminari", "Marker Felt",
    "Menlo", "Monaco", "Noteworthy", "Optima", "Palatino", "Phosphate", "Rockwell Nova",
    "San Francisco", "SF Pro", "Skia", "Snell Roundhand", "Times", "Trattatello",
    "Zapfino",
    # Controls: no machine has these, and a build that claims them is lying badly
    "curlPro No Such Font", "ZZZZ Nonexistent Family 1", "\u0424\u043e\u043d\u0442 \u041a\u043e\u0442\u043e\u0440\u043e\u0433\u043e \u041d\u0435\u0442",
]

PAGE = r"""<!doctype html>
<meta charset="utf-8">
<title>fpcapture</title>
<body style="font:14px system-ui;padding:2em">
<h1>Reading the machine…</h1>
<pre id="log"></pre>
<div id="probe" style="position:absolute;left:-9999px;top:-9999px;visibility:hidden"></div>
<script>
const FONTS = __FONTS__;
const out = {errors: {}};
const log = (m) => { document.getElementById("log").textContent += m + "\n"; };

// Every step is guarded on its own: one surface that throws (a GPU that
// refuses a context, a codec that is absent) must not cost us the rest of the
// record, and the error itself is data — a real browser on a real machine
// fails in its own way.
async function step(name, fn) {
  try { out[name] = await fn(); } catch (e) { out.errors[name] = String(e && e.message || e); }
  log(name + (out.errors[name] ? " — " + out.errors[name] : " ok"));
}

// JSON cannot carry a typed array or a WebGL object; keep what identifies the
// value and name the rest by its type, so a diff never compares "[object]"
// against a number and calls it a change.
function plain(v) {
  if (v === null || v === undefined) return null;
  const t = typeof v;
  if (t === "number" || t === "string" || t === "boolean") return v;
  if (Array.isArray(v)) return v.map(plain);
  if (ArrayBuffer.isView(v)) return Array.from(v);
  if (v instanceof Array) return Array.from(v).map(plain);
  return "[" + (v.constructor ? v.constructor.name : t) + "]";
}

async function sha256(bytes) {
  const d = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(d)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// --- canvas ---------------------------------------------------------------
// One fixed drawing, so that two machines differ only because they render
// differently: text in three families (the text stack), a gradient (the
// rasteriser), arcs and a shadow (anti-aliasing), and a composite operation.
function draw(ctx, w, h) {
  ctx.clearRect(0, 0, w, h);
  const g = ctx.createLinearGradient(0, 0, w, h);
  g.addColorStop(0, "#f60"); g.addColorStop(0.5, "#0af"); g.addColorStop(1, "#093");
  ctx.fillStyle = g; ctx.fillRect(0, 0, w, h);
  ctx.fillStyle = "rgba(255,255,255,0.75)";
  ctx.font = "18px Arial";
  ctx.fillText("curlPro \u2014 fingerprint \ud83d\udd0e 0123456789", 4, 24);
  ctx.font = "16px Times New Roman";
  ctx.fillText("\u0413\u043b\u0438\u0444\u044b \u0438 \u043a\u0435\u0440\u043d\u0438\u043d\u0433 \u2014 WaVeAfF", 4, 46);
  ctx.font = "15px monospace";
  ctx.fillText("iIl1| oO0 \u2014 .,;:", 4, 66);
  ctx.shadowBlur = 6; ctx.shadowColor = "#000";
  ctx.beginPath(); ctx.arc(w - 40, h - 30, 22, 0, Math.PI * 1.5); ctx.closePath();
  ctx.fillStyle = "#fff"; ctx.fill();
  ctx.shadowBlur = 0;
  ctx.globalCompositeOperation = "multiply";
  ctx.beginPath(); ctx.moveTo(10, h - 10); ctx.bezierCurveTo(w / 3, 10, w / 2, h, w - 10, 20);
  ctx.lineWidth = 3; ctx.strokeStyle = "#206"; ctx.stroke();
  ctx.globalCompositeOperation = "source-over";
}

async function canvasRecord() {
  const w = 360, h = 90;
  const read = () => {
    const c = document.createElement("canvas");
    c.width = w; c.height = h;
    const ctx = c.getContext("2d", {willReadFrequently: false});
    draw(ctx, w, h);
    return {url: c.toDataURL(), data: ctx.getImageData(0, 0, w, h).data, canvas: c, ctx: ctx};
  };
  const a = read(), b = read();
  // Read the same canvas twice without redrawing: a patch that adds noise per
  // call rather than per content shows up here, and so does an unpatched
  // browser's perfect stability.
  const again = a.ctx.getImageData(0, 0, w, h).data;
  let differs = 0, maxDelta = 0, alphaTouched = 0;
  for (let i = 0; i < a.data.length; i++) {
    const d = Math.abs(a.data[i] - again[i]);
    if (d) { differs++; maxDelta = Math.max(maxDelta, d); if (i % 4 === 3) alphaTouched++; }
  }
  const rec = {
    size: [w, h],
    dataURL: await sha256(new TextEncoder().encode(a.url)),
    pixels: await sha256(a.data),
    pixelsRedrawn: await sha256(b.data),
    pixelsSameCanvasAgain: await sha256(again),
    bytesChangedOnSecondRead: differs,
    maxChannelDelta: maxDelta,
    alphaBytesChanged: alphaTouched,
    dataURLLength: a.url.length,
  };
  if (typeof OffscreenCanvas === "function") {
    const o = new OffscreenCanvas(w, h);
    draw(o.getContext("2d"), w, h);
    rec.offscreenPixels = await sha256(o.getContext("2d").getImageData(0, 0, w, h).data);
    const blob = await o.convertToBlob({type: "image/png"});
    rec.offscreenBlobSize = blob.size;
  }
  const bmp = a.canvas.transferToImageBitmap ? null : null;  // 2D canvases have none
  if (bmp) rec.transferred = true;
  // Text metrics: the other half of the canvas fingerprint, and the half a
  // font allow-list moves without touching a pixel.
  const m = {};
  for (const font of ["16px Arial", "16px Times New Roman", "16px monospace",
                      "16px 'Segoe UI'", "16px 'Not A Font At All'"]) {
    a.ctx.font = font;
    const t = a.ctx.measureText("Hamburgefonstiv \u2014 \u0428\u0440\u0438\u0444\u0442 123");
    m[font] = {
      width: t.width, actualLeft: t.actualBoundingBoxLeft, actualRight: t.actualBoundingBoxRight,
      ascent: t.actualBoundingBoxAscent, descent: t.actualBoundingBoxDescent,
      fontAscent: t.fontBoundingBoxAscent, fontDescent: t.fontBoundingBoxDescent,
      emAscent: t.emHeightAscent, emDescent: t.emHeightDescent,
      alphabetic: t.alphabeticBaseline, hanging: t.hangingBaseline, ideographic: t.ideographicBaseline,
    };
  }
  rec.textMetrics = m;
  return rec;
}

// --- WebGL ----------------------------------------------------------------
// The enum names are taken from the context itself rather than from a list of
// ours: every numeric property is tried, and the ones getParameter accepts are
// the ones that exist in this browser. A list would go stale with the next
// extension; the context cannot.
function glRecord(kind) {
  const c = document.createElement("canvas");
  c.width = c.height = 64;
  const gl = c.getContext(kind, {antialias: true, preserveDrawingBuffer: true});
  if (!gl) return null;
  // enums: the numeric value of every parameter recorded, as the context
  // itself defines it — what the patched build looks a parameter up by.
  const rec = {attributes: {}, parameters: {}, enums: {}, precision: {}, extensions: null, unmasked: {}};
  const attrs = gl.getContextAttributes() || {};
  for (const k of Object.keys(attrs)) rec.attributes[k] = plain(attrs[k]);
  const names = [];
  for (const k in gl) { if (typeof gl[k] === "number" && /^[A-Z][A-Z0-9_]*$/.test(k)) names.push(k); }
  names.sort();
  for (const name of names) {
    while (gl.getError() !== gl.NO_ERROR) { /* drain */ }
    let v;
    try { v = gl.getParameter(gl[name]); } catch (e) { continue; }
    if (gl.getError() !== gl.NO_ERROR) continue;   // not a getParameter enum here
    if (v === null || v === undefined) continue;
    rec.parameters[name] = plain(v);
    rec.enums[name] = gl[name];
  }
  rec.extensions = (gl.getSupportedExtensions() || []).slice().sort();
  const dbg = gl.getExtension("WEBGL_debug_renderer_info");
  if (dbg) {
    rec.unmasked.vendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
    rec.unmasked.renderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
  }
  for (const shader of ["VERTEX_SHADER", "FRAGMENT_SHADER"]) {
    for (const p of ["LOW_FLOAT", "MEDIUM_FLOAT", "HIGH_FLOAT", "LOW_INT", "MEDIUM_INT", "HIGH_INT"]) {
      const f = gl.getShaderPrecisionFormat(gl[shader], gl[p]);
      rec.precision[shader + "." + p] = f ? [f.rangeMin, f.rangeMax, f.precision] : null;
    }
  }
  // A drawn triangle, read back: the renderer's own arithmetic and its
  // anti-aliasing, which the strings above do not describe.
  const vs = gl.createShader(gl.VERTEX_SHADER);
  gl.shaderSource(vs, "attribute vec2 p;void main(){gl_Position=vec4(p,0.0,1.0);}");
  gl.compileShader(vs);
  const fs = gl.createShader(gl.FRAGMENT_SHADER);
  gl.shaderSource(fs, "precision mediump float;void main(){gl_FragColor=vec4(gl_FragCoord.x/64.0,gl_FragCoord.y/64.0,0.5,1.0);}");
  gl.compileShader(fs);
  const prog = gl.createProgram();
  gl.attachShader(prog, vs); gl.attachShader(prog, fs); gl.linkProgram(prog); gl.useProgram(prog);
  const buf = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-0.8, -0.8, 0.9, -0.7, 0.0, 0.85]), gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(prog, "p");
  gl.enableVertexAttribArray(loc);
  gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
  gl.clearColor(0.1, 0.2, 0.3, 1.0);
  gl.clear(gl.COLOR_BUFFER_BIT);
  gl.drawArrays(gl.TRIANGLES, 0, 3);
  const px = new Uint8Array(64 * 64 * 4);
  gl.readPixels(0, 0, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, px);
  rec.drawnPixels = px;           // hashed by the caller, which can await
  rec.shaderLog = {
    vertex: gl.getShaderInfoLog(vs) || "",
    fragment: gl.getShaderInfoLog(fs) || "",
    program: gl.getProgramInfoLog(prog) || "",
  };
  return rec;
}

async function gl(kind) {
  const rec = glRecord(kind);
  if (!rec) return null;
  rec.drawnPixels = await sha256(rec.drawnPixels);
  return rec;
}

// --- fonts ----------------------------------------------------------------
// Three ways, because a patch that moves one and not the others is caught by
// the disagreement: measuring a span (FontFallbackList), document.fonts.check
// (FontCache::IsPlatformFamilyMatchAvailable, the path Brave leaves open) and
// a local() source (FontUniqueNameLookup).
async function fontRecord() {
  const probe = document.getElementById("probe");
  const base = ["monospace", "sans-serif", "serif"];
  const text = "mmmmmmmmmmlli WAWAVAT \u0428\u0440\u0438\u0444\u0442 0123456789";
  const span = (family) => {
    const s = document.createElement("span");
    s.style.cssText = "position:absolute;left:0;top:0;white-space:nowrap;font-size:72px;line-height:normal";
    s.style.fontFamily = family;
    s.textContent = text;
    probe.appendChild(s);
    const r = [s.offsetWidth, s.offsetHeight];
    probe.removeChild(s);
    return r;
  };
  const baseline = {};
  for (const b of base) baseline[b] = span(b);
  const byMeasure = [], byCheck = [], byLocal = [], widths = {};
  for (const f of FONTS) {
    const q = JSON.stringify(f);
    let seen = false;
    for (const b of base) {
      const m = span(q + "," + b);
      if (m[0] !== baseline[b][0] || m[1] !== baseline[b][1]) { seen = true; widths[f] = m; break; }
    }
    if (seen) byMeasure.push(f);
    try { if (document.fonts.check("72px " + q)) byCheck.push(f); } catch (e) { /* bad name */ }
    try {
      const face = new FontFace("probe_" + byLocal.length, "local(" + q + ")");
      await face.load();
      byLocal.push(f);
    } catch (e) { /* absent */ }
  }
  return {
    probed: FONTS.length,
    baseline: baseline,
    byMeasure: byMeasure,
    byCheck: byCheck,
    byLocal: byLocal,
    widths: widths,
    disagreement: {
      measureNotCheck: byMeasure.filter(f => !byCheck.includes(f)),
      checkNotMeasure: byCheck.filter(f => !byMeasure.includes(f)),
      localNotMeasure: byLocal.filter(f => !byMeasure.includes(f)),
    },
  };
}

// --- the canvas guards --------------------------------------------------
// The four checks CreepJS runs to decide whether a canvas has been
// interfered with. Stage 42 leaves canvas alone precisely because these
// catch noise and fixed substitution alike, so they are the acceptance test
// for that decision: a patched build must answer exactly as a stock one.
async function guards() {
  const g = {};
  const n = 32;

  // 1. The round trip (arkenfox TZP, by way of CreepJS). Known values are
  // written, read back, written into a second canvas and read again: a read
  // path that perturbs anything fails, and the channels say what it touched.
  // Alpha is kept at 255 throughout — the canvas stores premultiplied, so a
  // partial alpha loses precision legitimately and would read as a lie.
  const known = (() => {
    let s = 123456789;
    const rnd = () => ((s = (s * 1103515245 + 12345) & 0x7fffffff) >> 7) % 256;
    const c = document.createElement("canvas");
    c.width = c.height = n;
    const x = c.getContext("2d", {willReadFrequently: true});
    const d = x.createImageData(n, n);
    for (let i = 0; i < d.data.length; i += 4) {
      d.data[i] = rnd(); d.data[i + 1] = rnd(); d.data[i + 2] = rnd(); d.data[i + 3] = 255;
    }
    x.putImageData(d, 0, 0);
    return {canvas: c, ctx: x, data: d.data};
  })();
  const channels = ["r", "g", "b", "a"];
  const count = (a, b) => {
    const bad = {r: 0, g: 0, b: 0, a: 0};
    let total = 0;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) { bad[channels[i % 4]]++; total++; }
    }
    return {total: total, byChannel: bad};
  };
  const back = known.ctx.getImageData(0, 0, n, n).data;
  g.roundTripWriteRead = count(known.data, back);
  const second = document.createElement("canvas");
  second.width = second.height = n;
  const sctx = second.getContext("2d", {willReadFrequently: true});
  sctx.putImageData(new ImageData(new Uint8ClampedArray(back), n, n), 0, 0);
  g.roundTripSecondCanvas = count(back, sctx.getImageData(0, 0, n, n).data);

  // The same thing by drawing rather than by putImageData: noise added at
  // draw time rather than at read time would show here and not above.
  const drawn = document.createElement("canvas");
  drawn.width = drawn.height = 8;
  const dctx = drawn.getContext("2d", {willReadFrequently: true});
  const want = [];
  for (let y = 0; y < 8; y++) {
    for (let x = 0; x < 8; x++) {
      const r = (x * 31) % 256, gg = (y * 37) % 256, b = ((x + y) * 41) % 256;
      dctx.fillStyle = `rgb(${r},${gg},${b})`;
      dctx.fillRect(x, y, 1, 1);
      want.push(r, gg, b, 255);
    }
  }
  g.roundTripDrawn = count(new Uint8ClampedArray(want), dctx.getImageData(0, 0, 8, 8).data);

  // 2. A cleared canvas must read as nothing at all.
  const blank = document.createElement("canvas");
  blank.width = blank.height = 8;
  const bctx = blank.getContext("2d");
  bctx.clearRect(0, 0, 8, 8);
  g.blankCanvasMax = Math.max(...bctx.getImageData(0, 0, 8, 8).data);

  // 3. CreepJS compares this 2x2 anti-aliased arc against eight hardcoded
  // real Blink pixel strings. We record ours: the test is that the patched
  // build's string equals the stock browser's on the same machine, which is
  // stricter than matching a published list.
  const arc = document.createElement("canvas");
  arc.width = arc.height = 2;
  const actx = arc.getContext("2d");
  actx.beginPath();
  actx.arc(1, 1, 1, 0, Math.PI * 2);
  actx.fill();
  g.knownArcPixels = Array.from(actx.getImageData(0, 0, 2, 2).data).join("");

  // 4. measureText('') must return integers; a fractional offset is how
  //    fingerprint-chromium's text-metric noise is spotted.
  const m = document.createElement("canvas").getContext("2d").measureText("");
  const fields = ["actualBoundingBoxAscent", "actualBoundingBoxDescent",
                  "actualBoundingBoxLeft", "actualBoundingBoxRight",
                  "fontBoundingBoxAscent", "fontBoundingBoxDescent", "width"];
  g.emptyMetrics = {};
  g.emptyMetricsAllIntegers = true;
  for (const f of fields) {
    const v = m[f];
    g.emptyMetrics[f] = v;
    if (typeof v === "number" && !Number.isInteger(v)) g.emptyMetricsAllIntegers = false;
  }

  g.verdict = (g.roundTripWriteRead.total === 0 && g.roundTripSecondCanvas.total === 0
               && g.roundTripDrawn.total === 0 && g.blankCanvasMax === 0
               && g.emptyMetricsAllIntegers) ? "clean" : "modified";
  return g;
}

// --- the rest -------------------------------------------------------------
async function webgpu() {
  if (!navigator.gpu) return null;
  const a = await navigator.gpu.requestAdapter();
  if (!a) return {adapter: null};
  const limits = {};
  for (const k in a.limits) limits[k] = plain(a.limits[k]);
  const info = {};
  if (a.info) for (const k of ["vendor", "architecture", "device", "description", "driver",
                               "backend", "type", "subgroupMinSize", "subgroupMaxSize",
                               "isFallbackAdapter", "d3dShaderModel"]) {
    if (k in a.info) info[k] = plain(a.info[k]);
  }
  return {
    info: info,
    features: Array.from(a.features || []).sort(),
    limits: limits,
    preferredCanvasFormat: navigator.gpu.getPreferredCanvasFormat ? navigator.gpu.getPreferredCanvasFormat() : null,
  };
}

async function audio() {
  const C = window.OfflineAudioContext || window.webkitOfflineAudioContext;
  if (!C) return null;
  const ctx = new C(1, 44100, 44100);
  const osc = ctx.createOscillator();
  osc.type = "triangle";
  osc.frequency.value = 10000;
  const comp = ctx.createDynamicsCompressor();
  comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12;
  comp.attack.value = 0; comp.release.value = 0.25;
  osc.connect(comp); comp.connect(ctx.destination);
  osc.start(0);
  const buf = await ctx.startRendering();
  const d = buf.getChannelData(0);
  let sum = 0;
  for (let i = 4500; i < 5000; i++) sum += Math.abs(d[i]);
  return {sum: sum, hash: await sha256(new Float32Array(d.slice(4000, 5000))),
          sampleRate: ctx.sampleRate, channels: buf.numberOfChannels};
}

async function misc() {
  const n = navigator, r = {};
  r.userAgent = n.userAgent;
  r.platform = n.platform;
  r.languages = (n.languages || []).join(",");
  r.hardwareConcurrency = n.hardwareConcurrency;
  r.deviceMemory = n.deviceMemory === undefined ? null : n.deviceMemory;
  r.maxTouchPoints = n.maxTouchPoints;
  r.webdriver = n.webdriver;
  r.pdfViewerEnabled = n.pdfViewerEnabled;
  r.plugins = Array.from(n.plugins || []).map(p => p.name + "|" + p.filename);
  r.mimeTypes = Array.from(n.mimeTypes || []).map(m => m.type);
  r.screen = [screen.width, screen.height, screen.availWidth, screen.availHeight,
              screen.colorDepth, screen.pixelDepth];
  r.devicePixelRatio = devicePixelRatio;
  r.windowChrome = [outerWidth - innerWidth, outerHeight - innerHeight];
  r.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  r.timezoneOffset = new Date().getTimezoneOffset();
  r.chromeKeys = window.chrome ? Object.keys(window.chrome).sort() : null;
  r.visibilityState = document.visibilityState;
  if (n.userAgentData) {
    r.brands = n.userAgentData.brands.map(b => b.brand + ";" + b.version);
    r.mobile = n.userAgentData.mobile;
    try {
      r.highEntropy = await n.userAgentData.getHighEntropyValues(
        ["architecture", "bitness", "model", "platformVersion", "fullVersionList", "wow64", "formFactors"]);
      r.highEntropy.fullVersionList = (r.highEntropy.fullVersionList || []).map(b => b.brand + ";" + b.version);
    } catch (e) { r.highEntropy = String(e); }
  }
  if (navigator.storage && navigator.storage.estimate) {
    const q = await navigator.storage.estimate();
    r.storageQuota = q.quota;
  }
  if (navigator.permissions) {
    r.permissions = {};
    for (const name of ["geolocation", "notifications", "camera", "microphone", "midi"]) {
      try { r.permissions[name] = (await navigator.permissions.query({name: name})).state; }
      catch (e) { r.permissions[name] = "unsupported"; }
    }
  }
  if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
    const d = await navigator.mediaDevices.enumerateDevices();
    r.mediaDevices = d.map(x => x.kind).sort();
  }
  r.speechVoices = (() => {
    try { return speechSynthesis.getVoices().length; } catch (e) { return null; }
  })();
  r.mathFingerprint = [Math.tan(-1e300), Math.sinh(1), Math.acosh(1e308),
                       Math.pow(Math.PI, -100), Math.exp(1)].map(String);
  return r;
}

(async () => {
  await document.fonts.ready;
  await step("misc", misc);
  await step("canvas", canvasRecord);
  await step("guards", guards);
  await step("webgl", () => gl("webgl"));
  await step("webgl2", () => gl("webgl2"));
  await step("webgpu", webgpu);
  await step("audio", audio);
  await step("fonts", fontRecord);
  document.querySelector("h1").textContent = "Done — the record is written.";
  await fetch("/report", {method: "POST", headers: {"content-type": "application/json"},
                          body: JSON.stringify(out)});
})();
</script>
"""


class Stand:
    """Serves the page and keeps the one report it gets."""

    def __init__(self) -> None:
        self.report: dict | None = None
        page = PAGE.replace("__FONTS__", json.dumps(FONTS))
        stand = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802
                body = page.encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(body)))
                self.send_header("cache-control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802
                n = int(self.headers.get("content-length", 0))
                stand.report = json.loads(self.rfile.read(n) or b"{}")
                self.send_response(204)
                self.send_header("content-length", "0")
                self.end_headers()

            def log_message(self, *a) -> None:  # keep the console for our own lines
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def capture(name: str, executable: str | None, timeout: float, headless: bool,
            light: bool = True, extra: tuple = ()) -> Path:
    from curlpro.browser import Chrome, find_chrome

    exe = executable or find_chrome()
    if not exe:
        raise SystemExit("no browser found: pass -chrome, or set CURLPRO_CHROME")
    stand = Stand()
    print(f"stand on {stand.base}")
    started = time.time()
    try:
        with Chrome(stand.base + "/", executable=exe, headless=headless, timeout=timeout,
                    light=light, extra_args=extra) as chrome:
            version = chrome.version()
            deadline = time.time() + timeout
            while stand.report is None and time.time() < deadline:
                if not chrome.alive:
                    raise SystemExit("the browser exited before it reported")
                time.sleep(0.1)
        if stand.report is None:
            raise SystemExit(f"no report within {timeout:g}s")
        record = {
            "name": name,
            "captured": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "seconds": round(time.time() - started, 1),
            "executable": str(exe),
            "browser": {k: version.get(k) for k in ("product", "revision", "jsVersion", "protocolVersion")},
            "headless": headless,
            "light": light,
            "extra_args": list(extra),
            **stand.report,
        }
    finally:
        stand.close()
    out = ROOT / "capture" / "fp" / f"{name}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=1, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    errors = record.get("errors") or {}
    print(f"wrote {out.relative_to(ROOT)} in {record['seconds']}s | {record['browser']['product']}"
          f"{' | errors: ' + ', '.join(errors) if errors else ''}")
    return out


def flatten(o, prefix: str = "") -> dict:
    """A record as one level of dotted keys, so a diff names what moved."""
    flat = {}
    if isinstance(o, dict):
        for k, v in o.items():
            flat.update(flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(o, list) and o and all(isinstance(x, (str, int, float, bool)) for x in o):
        flat[prefix] = json.dumps(o, ensure_ascii=False)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            flat.update(flatten(v, f"{prefix}[{i}]"))
    else:
        flat[prefix] = o
    return flat


#: Keys that differ between any two runs and say nothing about the machine.
NOISE = ("captured", "seconds", "name", "executable", "misc.speechVoices", "audio.sum",
         "canvas.textMetrics", "fonts.baseline", "fonts.widths")


def compare(a: Path, b: Path, show_all: bool) -> int:
    left = flatten(json.loads(a.read_text(encoding="utf-8")))
    right = flatten(json.loads(b.read_text(encoding="utf-8")))
    keys = sorted(set(left) | set(right))
    same = changed = 0
    lines = []
    for k in keys:
        if not show_all and k.startswith(NOISE):
            continue
        x, y = left.get(k, "<absent>"), right.get(k, "<absent>")
        if x == y:
            same += 1
            continue
        changed += 1
        lines.append(f"  {k}\n    {a.stem}: {json.dumps(x, ensure_ascii=False)[:160]}"
                     f"\n    {b.stem}: {json.dumps(y, ensure_ascii=False)[:160]}")
    print(f"{a.stem} vs {b.stem}: {same} equal, {changed} different")
    print("\n".join(lines))
    return changed


def to_profile(record_path: Path) -> Path:
    """The profile the patched build reads (chromium/DESIGN.md), from a record.

    The WebGL blocks are the record's whole numeric blocks, not only what
    differed from one host: another host's ANGLE may differ elsewhere, and the
    build serves only what is *lower* than the machine's own anyway. Strings
    other than the two unmasked ones are left out — they were the same on
    every GPU measured, and a version string is the browser's, not the card's.
    The fonts are every family any probe found: span measurement and local()
    disagree, and the build must answer both alike.
    """
    rec = json.loads(record_path.read_text(encoding="utf-8"))

    def numbers(block: dict) -> list:
        # Each with its enum, which the build looks it up by; the name is for
        # whoever reads the file. A record from before enums were kept has
        # none, and is refused rather than half-used.
        block = block or {}
        enums = block.get("enums") or {}
        if block.get("parameters") and not enums:
            raise SystemExit(f"{record_path}: no enum values in the record — capture it again")
        # Capabilities only: the integer MAX_* limits, which differ by device
        # and which the build may lower to the target's. The rest of the
        # block is state (ACTIVE_TEXTURE, BLEND_COLOR...) — the same in every
        # browser — and nothing to serve.
        return [{"name": k, "enum": enums[k], "value": v}
                for k, v in sorted(block.get("parameters", {}).items())
                if k.startswith("MAX_") and isinstance(v, int) and not isinstance(v, bool) and k in enums]

    gl1, gl2 = rec.get("webgl") or {}, rec.get("webgl2") or {}
    fonts = rec.get("fonts") or {}
    brand = vendor_brand((rec.get("misc") or {}).get("brands") or [])
    profile = {
        "source": f"{rec.get('name')} — fpcapture, {rec.get('browser', {}).get('product')}, "
                  f"{rec.get('captured', '')[:10]}",
        "webgl": {
            "unmasked_vendor": (gl1.get("unmasked") or {}).get("vendor", ""),
            "unmasked_renderer": (gl1.get("unmasked") or {}).get("renderer", ""),
            "parameters": numbers(gl1),
            "webgl2_parameters": numbers(gl2),
        },
        "fonts": {
            "present": sorted(set(fonts.get("byMeasure", [])) | set(fonts.get("byLocal", []))),
        },
    }
    if brand:
        # The build reports this beside "Chromium" and the GREASE entry, and
        # Chromium's own seeding by the major version reproduces the measured
        # list, order included (chromium/patches/0003, scripts/chromium_brands.py).
        profile["ua"] = {"brand": brand}
    out = record_path.with_name(record_path.stem + ".profile.json")
    out.write_text(json.dumps(profile, indent=1, ensure_ascii=False), encoding="utf-8")
    switch = switch_value(profile)
    print(f"wrote {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out}: "
          f"{len(profile['webgl']['parameters'])} + {len(profile['webgl']['webgl2_parameters'])} "
          f"WebGL limits, {len(profile['fonts']['present'])} fonts, "
          f"brand {brand or '(none: Chromium only)'}; "
          f"--curlpro-fingerprint is {len(switch)} characters")
    return out


def vendor_brand(brands: list) -> str:
    """The brand a Chromium-based browser adds to "Chromium" and the GREASE
    entry: "Google Chrome", "Microsoft Edge", "Opera". Empty for Chromium
    itself, or when the record holds no single such brand.

    The GREASE entry is recognised by Chromium's own grammar, "Not" + c + "A"
    + c + "Brand" over its eleven characters (scripts/chromium_brands.py),
    not by a guess at what looks odd."""
    from chromium_brands import CHARS
    grease = {f"Not{a}A{b}Brand" for a in CHARS for b in CHARS}
    names = [b.rsplit(";", 1)[0] for b in brands]
    own = [n for n in names if n != "Chromium" and n not in grease]
    return own[0] if len(own) == 1 else ""


def switch_value(profile: dict) -> str:
    """The profile as the build takes it: compact JSON in base64 on the
    browser's command line, which the browser forwards to every renderer.
    Base64 because a JSON value's quotes and spaces through Windows
    command-line quoting is a parser bug waiting to happen."""
    import base64
    compact = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(compact).decode("ascii")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-name", default="this-machine", help="the record's name under capture/fp/")
    p.add_argument("-chrome", default=None, help="the browser to read (default: the installed one)")
    p.add_argument("-headless", action="store_true", help="read a headless browser (its own fingerprint)")
    p.add_argument("-timeout", type=float, default=120.0)
    p.add_argument("-plain", action="store_true", help="start the browser without the driver's light flags")
    p.add_argument("-args", nargs="*", default=[], help="extra flags for the browser, as they are written")
    p.add_argument("-compare", nargs=2, metavar=("A", "B"), help="diff two records instead of capturing")
    p.add_argument("-all", action="store_true", help="with -compare: do not hide the per-run noise")
    p.add_argument("-profile", metavar="RECORD", help="write the patched build's profile from a record")
    a = p.parse_args()
    if a.profile:
        to_profile(Path(a.profile))
        return
    if a.compare:
        raise SystemExit(1 if compare(Path(a.compare[0]), Path(a.compare[1]), a.all) else 0)
    capture(a.name, a.chrome, a.timeout, a.headless, light=not a.plain, extra=tuple(a.args))


if __name__ == "__main__":
    main()
