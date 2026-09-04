#!/usr/bin/env python3
"""Comparing the overhead with curl_cffi, requests and httpx.

Measured against a local echo-server so that network latency stays out of the
result: what is of interest is the library's own cost per request.

    tools/echo-server_windows_amd64.exe -listen-addr localhost:8443 \
        -cert-filename capture/certs/tls.crt -certkey-filename capture/certs/tls.key -quiet

    cd python && PYTHONPATH=. python bench.py [-n 300]
"""

from __future__ import annotations

import argparse
import socket
import statistics
import sys
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

URL = "https://localhost:8443/json"
REPO = Path(__file__).resolve().parents[1]


def stand_is_up() -> bool:
    try:
        with socket.create_connection(("localhost", 8443), timeout=1):
            return True
    except OSError:
        return False


def measure(name: str, fetch, n: int, warmup: int = 20) -> tuple[str, float, float, float]:
    """Returns (name, requests/sec, median ms, p95 ms)."""
    for _ in range(warmup):
        fetch()

    samples = []
    start = time.perf_counter()
    for _ in range(n):
        t0 = time.perf_counter()
        fetch()
        samples.append((time.perf_counter() - t0) * 1000)
    total = time.perf_counter() - start

    samples.sort()
    p95 = samples[int(len(samples) * 0.95) - 1]
    return name, n / total, statistics.median(samples), p95


def bench_curlpro(n: int):
    import curlpro

    curlpro.load_profiles(REPO / "profiles")
    s = curlpro.Session("chrome-151-windows", verify=False)
    try:
        return measure("curlpro", lambda: s.get(URL).content, n)
    finally:
        s.close()


def bench_curl_cffi(n: int):
    from curl_cffi import requests as cr

    s = cr.Session(impersonate="chrome", verify=False)
    try:
        return measure("curl_cffi", lambda: s.get(URL).content, n)
    finally:
        s.close()


def bench_requests(n: int):
    import requests

    s = requests.Session()
    try:
        return measure("requests (no fingerprint)", lambda: s.get(URL, verify=False).content, n)
    finally:
        s.close()


def bench_httpx(n: int):
    import httpx

    with httpx.Client(verify=False, http2=True) as c:
        return measure("httpx h2 (no fingerprint)", lambda: c.get(URL).content, n)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=300, help="requests per library")
    args = ap.parse_args()

    if not stand_is_up():
        print("no echo-server on localhost:8443 — see the docstring", file=sys.stderr)
        return 1

    benches = [
        ("curlpro", bench_curlpro),
        ("curl_cffi", bench_curl_cffi),
        ("requests", bench_requests),
        ("httpx", bench_httpx),
    ]

    rows = []
    for label, fn in benches:
        try:
            rows.append(fn(args.n))
        except Exception as exc:  # the library may not be installed
            print(f"  {label}: skipped ({type(exc).__name__}: {exc})", file=sys.stderr)

    rows.sort(key=lambda r: -r[1])
    print(f"\n{args.n} requests, a reused connection, a local stand\n")
    print(f"{'library':30} {'req/s':>9} {'median':>10} {'p95':>9}")
    print("-" * 61)
    best = rows[0][1] if rows else 1
    for name, rps, med, p95 in rows:
        rel = f"{rps / best * 100:.0f}%"
        print(f"{name:30} {rps:9.0f} {med:9.2f}ms {p95:8.2f}ms  {rel:>5}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
