r"""How far fetching and parsing scale over threads, on this interpreter.

    python scripts/ft-scaling.py [THREADS]

Starts a local server, then fetches and parses a page with html.parser —
Python's own work — first in one thread, then in THREADS threads (the
machine's cores by default), the same total work each time. With the GIL
the parsing takes turns and the ratio stays near 1; on a free-threaded build
(3.14t) with the GIL off the parsers run in parallel, and the ratio grows
with the cores. Nothing is asserted: the number depends on the machine; CI
prints it beside the free-threaded test run.
"""
import os
import sys
import sysconfig
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python"))
import curlpro  # noqa: E402

BODY = (("<div class=row><a href=/x>" + "text " * 40 + "</a></div>") * 800).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("content-type", "text/html")
        self.send_header("content-length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *a) -> None:  # noqa: ANN002
        pass


class Count(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.n = 0

    def handle_starttag(self, tag, attrs) -> None:  # noqa: ANN001
        self.n += 1


def main(threads: int) -> None:
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer.request_queue_size = 128
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    curlpro.load_profiles(ROOT / "profiles")
    jobs = threads * 6

    with curlpro.Session("chrome-153-windows") as s:
        def job(_: int) -> int:
            p = Count()
            p.feed(s.get(url).text)
            return p.n

        job(0)  # the connection, warm
        timings = {}
        for n in (1, threads):
            start = time.perf_counter()
            with ThreadPoolExecutor(n) as pool:
                assert all(pool.map(job, range(jobs)))
            timings[n] = time.perf_counter() - start
    srv.shutdown()
    gil = getattr(sys, "_is_gil_enabled", lambda: True)()
    print(f"python {sys.version.split()[0]}, free-threaded build: "
          f"{bool(sysconfig.get_config_var('Py_GIL_DISABLED'))}, GIL enabled: {gil}")
    print(f"{jobs} fetch+parse jobs: 1 thread {timings[1]:.2f} s, {threads} threads "
          f"{timings[threads]:.2f} s, speedup x{timings[1] / timings[threads]:.1f}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else (os.cpu_count() or 4))
