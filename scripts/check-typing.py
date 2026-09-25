"""The request methods are typed: mypy must accept correct calls and name a
misspelt or mistyped keyword argument, on the sync, async and one-off paths.

Run: ``python scripts/check-typing.py`` (needs mypy; CI installs it). Exit
status 0 when mypy says exactly what is expected below.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PROBE = '''
import curlpro

s = curlpro.Session("chrome-153-windows")
s.get("https://a.test/", timeout=5, retries=2, page="https://b.test/")   # line 5: fine
s.get("https://a.test/", timout=5)                                       # line 6: misspelt
s.post("https://a.test/", retries="three")                               # line 7: wrong type
curlpro.get("https://a.test/", impersonate="chrome-153-windows", http3=True)  # line 8: fine
curlpro.get("https://a.test/", impersonat="x")                           # line 9: misspelt
retry_after: list[str] | None = s.get("https://a.test/").headers.get("retry-after")  # line 10: fine


async def main() -> None:
    a = curlpro.AsyncSession("chrome-153-windows")
    await a.get("https://a.test/", timeout=5)                            # line 15: fine
    await a.get("https://a.test/", timout=5)                             # line 16: misspelt
    async with a.stream("GET", "https://a.test/", params={"q": 1}):      # line 17: fine
        pass
'''

# line -> error code mypy must report there; every other line must be clean.
EXPECTED = {6: "call-arg", 7: "arg-type", 9: "call-arg", 16: "call-arg"}


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "probe.py"
        # The leading newline stays: the line numbers below count it.
        probe.write_text(PROBE, encoding="utf-8")
        out = subprocess.run(
            [sys.executable, "-m", "mypy", "--python-version", "3.10", "--follow-imports=silent",
             "--no-error-summary", "--show-error-codes", "--no-incremental", str(probe)],
            capture_output=True, text=True, cwd=ROOT / "python")
    got: dict[int, str] = {}
    for line in out.stdout.splitlines():
        m = re.search(r"probe\.py:(\d+): error: .*\[([a-z-]+)\]$", line)
        if m:
            got[int(m.group(1))] = m.group(2)
    if got != EXPECTED:
        print("mypy did not report what the typed signatures promise")
        print("expected:", EXPECTED)
        print("got:     ", got)
        print(out.stdout, out.stderr)
        return 1
    print(f"typed signatures: {len(EXPECTED)} mistakes caught, correct calls clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
