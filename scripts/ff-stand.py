"""Run cmd/hcapture's -subres or -cache page in the installed Firefox, headless.

    go build -o hcapture.exe ./cmd/hcapture
    python scripts/ff-stand.py subres|cache h2|h1 OUT.json [timeout_s]

hcapture launches Chrome itself; Firefox needs the stand's certificate trusted
in a throwaway profile (cert_override.txt, the five-field line, one per name)
and the stand's names kept local (network.dns.localDomains). Run from the repo
root: hcapture reads capture/certs-multi.
"""
from __future__ import annotations

import hashlib
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PAGE, PROTO, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
TIMEOUT = int(sys.argv[4]) if len(sys.argv) > 4 else 40
FIREFOX = r"C:\Program Files\Mozilla Firefox\firefox.exe"
HCAPTURE = str(Path("hcapture.exe").resolve())  # built at the repo root
CERT = Path("capture/certs-multi/tls.crt")
PORT = 8443
NAMES = ["localhost", "a.localhost", "www.a.localhost", "api.a.localhost"] + [f"{c}.localhost" for c in "bcdefgh"]
START = {"subres": "/sub/index.html", "cache": "/c/index.html"}[PAGE]

der = ssl.PEM_cert_to_DER_cert(CERT.read_text(encoding="ascii"))
fp = ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())
prof = Path(tempfile.mkdtemp(prefix="ffstand-"))
(prof / "cert_override.txt").write_text(
    "".join(f"{n}:{PORT}\tOID.2.16.840.1.101.3.4.2.1\t{fp}\tU\t\n" for n in NAMES), encoding="utf-8")
(prof / "user.js").write_text("\n".join([
    f'user_pref("network.dns.localDomains", "{",".join(NAMES)}");',
    'user_pref("browser.shell.checkDefaultBrowser", false);',
    'user_pref("app.update.auto", false);',
    'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
    'user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);',
    'user_pref("browser.aboutwelcome.enabled", false);',
]) + "\n", encoding="utf-8")

args = [HCAPTURE, f"-{PAGE}", "-certs", "capture/certs-multi", "-timeout", f"{TIMEOUT}s", "-json", OUT]
if PROTO == "h1":
    args.insert(2, "-h1")
stand = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                         errors="replace")
time.sleep(2)
ff = subprocess.Popen([FIREFOX, "-headless", "-no-remote", "-profile", str(prof),
                       f"https://www.a.localhost:{PORT}{START}"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    out, _ = stand.communicate(timeout=TIMEOUT + 60)
finally:
    subprocess.run(["taskkill", "/T", "/F", "/PID", str(ff.pid)], capture_output=True)
    time.sleep(1.5)
    shutil.rmtree(prof, ignore_errors=True)
print("\n".join(out.splitlines()[-3:]))
