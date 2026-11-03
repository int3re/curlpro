"""Captures from a Chromium that will not take the stand's certificate from
the command line.

Yandex Browser 26.10 shows its own "security threat" page in spite of
--ignore-certificate-errors, the SPKI list and DevTools'
Security.setIgnoreCertificateErrors (measured 2026-11-03). The page has a
proceed link ("make an exception for this site", #proceed-link); this script
clicks it over DevTools, once per host the stand's pages reach, in a
throwaway profile that is deleted afterwards. Nothing outside the profile is
touched — the machine's certificate store least of all. The browser runs
headed: headless Yandex ignores the URL it is given.

Two jobs:

    python scripts/capture-proceed.py headers BROWSER OUT.json [hcapture flags...]
        cmd/hcapture as the stand (built here), the browser driven to it —
        what hcapture -browser does for a browser that takes the flags.

    python scripts/capture-proceed.py open BROWSER URL [COUNT] [DWELL]
        URL opened in COUNT fresh profiles, DWELL seconds each: the samples
        `curlpro capture -manual` waits for (TLS and HTTP/2).

Needs the `websockets` package.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import websockets

REPO = Path(__file__).resolve().parents[1]
PORT = 9341
PROCEED = ("(() => { const a = document.getElementById('proceed-link');"
           " if (!a) return 'no warning'; a.click(); return 'proceeded'; })()")


async def call(ws, method, params=None, _id=[0]):
    _id[0] += 1
    await ws.send(json.dumps({"id": _id[0], "method": method, "params": params or {}}))
    while True:
        m = json.loads(await ws.recv())
        if m.get("id") == _id[0]:
            return m


async def blank_page() -> dict:
    """The DevTools target of the browser's first page."""
    pages = []
    for _ in range(60):
        try:
            pages = [t for t in json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/list", timeout=2))
                     if t["type"] == "page"]
            if pages:
                break
        except OSError:
            pass
        await asyncio.sleep(0.5)
    if not pages:
        raise SystemExit("no DevTools endpoint")
    return next((p for p in pages if p["url"].startswith("about:blank")), pages[0])


async def proceed(ws, url: str) -> str:
    await call(ws, "Page.navigate", {"url": url})
    await asyncio.sleep(2.5)
    r = await call(ws, "Runtime.evaluate", {"expression": PROCEED, "returnByValue": True})
    return r.get("result", {}).get("result", {}).get("value")


def start_browser(browser: str, extra: list[str]) -> tuple[subprocess.Popen, str]:
    profile = tempfile.mkdtemp(prefix="curlpro-proceed-")
    args = [browser, f"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check",
            "--ignore-certificate-errors", f"--remote-debugging-port={PORT}", "--new-window", *extra,
            "about:blank"]
    return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL), profile


def stop_browser(proc: subprocess.Popen, profile: str) -> None:
    subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
    time.sleep(1.5)
    shutil.rmtree(profile, ignore_errors=True)


def spki_of(certs: Path) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    c = x509.load_pem_x509_certificate((certs / "tls.crt").read_bytes())
    der = c.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


def headers(browser: str, out: str, flags: list[str]) -> int:
    timeout = 45
    if "-timeout" in flags:
        timeout = int(flags[flags.index("-timeout") + 1].rstrip("s"))
    else:
        flags += ["-timeout", f"{timeout}s"]
    certs = REPO / (flags[flags.index("-certs") + 1] if "-certs" in flags else "capture/certs")
    origin, extra_hosts, start = "localhost:8443", ["d.localhost", "e.localhost"], "/"
    multi = any(f in flags for f in ("-origins", "-subres", "-cache", "-chips"))
    if multi:
        origin = "www.a.localhost:8443"
        extra_hosts = ["a.localhost", "api.a.localhost", "b.localhost", "c.localhost", "d.localhost", "e.localhost"]
    for flag, path in (("-origins", "/app/index.html?tab=1"), ("-subres", "/sub/index.html"),
                       ("-cache", "/c/index.html"), ("-chips", "/k/index.html")):
        if flag in flags:
            start = path

    build = Path(tempfile.mkdtemp(prefix="curlpro-hcapture-"))
    hcap = build / "hcapture.exe"
    subprocess.run(["go", "build", "-o", str(hcap), "./cmd/hcapture"], cwd=REPO, check=True)
    log = open(out + ".log", "w", encoding="utf-8")
    stand = subprocess.Popen([str(hcap), "-json", out, *flags], cwd=REPO, stdout=log, stderr=subprocess.STDOUT)
    time.sleep(1.5)
    extra = [f"--ignore-certificate-errors-spki-list={spki_of(certs)}"]
    if multi:
        extra.append("--host-resolver-rules=MAP *.localhost 127.0.0.1")
    proc, profile = start_browser(browser, extra)

    async def drive():
        page = await blank_page()
        async with websockets.connect(page["webSocketDebuggerUrl"], max_size=None) as ws:
            for host in [origin] + [h + ":8443" for h in extra_hosts if h + ":8443" != origin]:
                print(host, await proceed(ws, f"https://{host}/__exception"))
                await asyncio.sleep(2)
            r = await call(ws, "Page.navigate", {"url": f"https://{origin}{start}"})
            print("navigate:", r.get("result", {}).get("errorText") or "ok")

    try:
        asyncio.run(drive())
        try:
            stand.wait(timeout=timeout + 30)
        except subprocess.TimeoutExpired:
            print("the stand did not finish")
    finally:
        stop_browser(proc, profile)
        if stand.poll() is None:
            stand.kill()
        log.close()
        shutil.rmtree(build, ignore_errors=True)
    lines = [ln for ln in open(out + ".log", encoding="utf-8", errors="replace").read().splitlines()
             if not ln.startswith("  ")]
    print("\n".join(lines[-12:]))
    return 0 if stand.returncode == 0 else 1


def open_samples(browser: str, url: str, count: int, dwell: float) -> int:
    for i in range(count):
        proc, profile = start_browser(browser, [])

        async def once():
            page = await blank_page()
            async with websockets.connect(page["webSocketDebuggerUrl"], max_size=None) as ws:
                print(await proceed(ws, url))
                await asyncio.sleep(dwell)

        try:
            asyncio.run(once())
        finally:
            stop_browser(proc, profile)
        print("sample", i + 1, "done")
    return 0


def main() -> int:
    if len(sys.argv) >= 4 and sys.argv[1] == "headers":
        return headers(sys.argv[2], sys.argv[3], sys.argv[4:])
    if len(sys.argv) >= 4 and sys.argv[1] == "open":
        count = int(sys.argv[4]) if len(sys.argv) > 4 else 5
        dwell = float(sys.argv[5]) if len(sys.argv) > 5 else 4
        return open_samples(sys.argv[2], sys.argv[3], count, dwell)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
