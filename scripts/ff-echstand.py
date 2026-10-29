"""Point the installed Firefox at cmd/echstand and record the hello it sends.

    go build -o echstand.exe ./cmd/echstand
    python scripts/ff-echstand.py OUT.json [timeout_s] [extra echstand flags...]

echstand -auto launches Chrome with its own DNS-over-HTTPS setting; Firefox
asks DNS through TRR instead. The throwaway profile puts TRR in mode 3 on the
stand's DoH server, lets it hand out a loopback address (allow-rfc1918), skips
the confirmation query the stand does not answer, and trusts the stand's
certificate for every name it serves under (cert_override.txt, the five-field
line; MU: the certificate names localhost, not the stand's .test names). Run
from the repo root: echstand reads capture/certs.
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

OUT = sys.argv[1]
TIMEOUT = int(sys.argv[2]) if len(sys.argv) > 2 else 40
EXTRA = sys.argv[3:]
FIREFOX = r"C:\Program Files\Mozilla Firefox\firefox.exe"
ECHSTAND = str(Path("echstand.exe").resolve())  # built at the repo root
CERT = Path("capture/certs/tls.crt")
NAME, PUBLIC, PORT, DOH = "ech-stand.test", "public.ech-stand.test", 8444, "127.0.0.1:8053"

der = ssl.PEM_cert_to_DER_cert(CERT.read_text(encoding="ascii"))
fp = ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())
prof = Path(tempfile.mkdtemp(prefix="ffech-"))
(prof / "cert_override.txt").write_text(
    "".join(f"{h}\tOID.2.16.840.1.101.3.4.2.1\t{fp}\tMU\t\n"
            for h in (f"{NAME}:{PORT}", f"{PUBLIC}:{PORT}", DOH)), encoding="utf-8")
(prof / "user.js").write_text("\n".join([
    'user_pref("network.trr.mode", 3);',
    f'user_pref("network.trr.uri", "https://{DOH}/dns-query");',
    f'user_pref("network.trr.custom_uri", "https://{DOH}/dns-query");',
    'user_pref("network.trr.allow-rfc1918", true);',
    'user_pref("network.trr.confirmationNS", "skip");',
    'user_pref("network.trr.excluded-domains", "");',
    'user_pref("network.dns.echconfig.enabled", true);',
    'user_pref("network.dns.http3_echconfig.enabled", true);',
    'user_pref("network.dns.use_https_rr_as_altsvc", true);',
    'user_pref("browser.shell.checkDefaultBrowser", false);',
    'user_pref("app.update.auto", false);',
    'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
    'user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);',
    'user_pref("browser.aboutwelcome.enabled", false);',
]) + "\n", encoding="utf-8")

stand = subprocess.Popen([ECHSTAND, "-name", NAME, "-public", PUBLIC, "-listen", f"127.0.0.1:{PORT}",
                          "-doh", DOH, "-timeout", f"{TIMEOUT}s", "-json", OUT, *EXTRA],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                         errors="replace")
time.sleep(2)
ff = subprocess.Popen([FIREFOX, "-headless", "-no-remote", "-profile", str(prof), f"https://{NAME}:{PORT}/"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    out, _ = stand.communicate(timeout=TIMEOUT + 60)
finally:
    subprocess.run(["taskkill", "/T", "/F", "/PID", str(ff.pid)], capture_output=True)
    time.sleep(1.5)
    shutil.rmtree(prof, ignore_errors=True)
print(out)
