"""Threads, with and without the GIL.

The package is ctypes over a Go library: every native call releases the GIL,
and nothing in it is an extension module that could switch the GIL back on,
so under a free-threaded build (3.14t, PYTHON_GIL=0) threads run Python in
parallel as well. What that asks of the Python side is that its own shared
state holds up — these tests put it under threads on any build, and CI runs
them on 3.14t with the GIL off.
"""
from __future__ import annotations

import subprocess
import sys
import sysconfig
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import curlpro
import pytest

from echo_stand import EchoStand

REPO = Path(__file__).resolve().parents[2]
FREE_THREADED = bool(sysconfig.get_config_var("Py_GIL_DISABLED"))


@pytest.fixture(scope="module", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def test_the_gil_stays_off_where_it_is_off():
    """Importing the package must not switch the GIL back on: an extension
    module without free-threading support would, and the parallelism with
    it."""
    if not FREE_THREADED:
        pytest.skip("not a free-threaded build")
    assert not sys._is_gil_enabled()  # type: ignore[attr-defined]


def test_one_session_many_threads():
    """Sixteen threads on one session: every response is the one its thread
    asked for, the pool and the jar are shared and survive it."""
    with EchoStand() as st:
        st.routes = {}

        def route(rec):  # the path back, and a cookie on the way
            return 200, [("Set-Cookie", f"t{rec['path'][2:].split('-')[0]}=1; Path=/")], rec["path"].encode()

        for t in range(16):
            for i in range(20):
                st.routes[f"/p{t}-{i}"] = route
        with curlpro.Session("chrome-153-windows") as s:
            def worker(t: int) -> None:
                for i in range(20):
                    r = s.get(f"{st.url}/p{t}-{i}")
                    assert r.status == 200
                    assert r.content == f"/p{t}-{i}".encode(), "a response went to the wrong thread"

            with ThreadPoolExecutor(16) as pool:
                for f in [pool.submit(worker, t) for t in range(16)]:
                    f.result()
            assert len(st.seen) == 16 * 20
            # The jar took every thread's cookie.
            assert {f"t{t}" for t in range(16)} <= {c["name"] for c in s.cookies.export()}


def test_a_session_per_thread():
    with EchoStand() as st:
        def worker(t: int) -> int:
            with curlpro.Session("firefox-156-windows") as s:
                return sum(s.get(f"{st.url}/s{t}-{i}").status for i in range(10))

        with ThreadPoolExecutor(8) as pool:
            assert list(pool.map(worker, range(8))) == [2000] * 8


def test_bundled_profiles_load_once_under_threads(tmp_path):
    """The first sessions of a process, opened together, all find their
    profile: the load of the bundled set is done once, and before anyone
    goes on."""
    code = f"""
import threading, curlpro, curlpro.profiles as p
from pathlib import Path
p._BUNDLED = Path({str(REPO / 'profiles')!r})
p._autoloaded = False
barrier = threading.Barrier(8)
errors = []
def open_one():
    barrier.wait()
    try:
        with curlpro.Session("chrome-153-windows"):
            pass
    except Exception as e:
        errors.append(repr(e))
threads = [threading.Thread(target=open_one) for _ in range(8)]
[t.start() for t in threads]
[t.join() for t in threads]
print("ERRORS", errors)
"""
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120,
                         cwd=str(REPO / "python"))
    assert "ERRORS []" in out.stdout, out.stdout + out.stderr


def test_threads_parse_while_requests_run():
    """Parsing a response is Python's own work; with the GIL off it runs in
    parallel with the requests and with other parsers. Here it only has to
    come out right from every thread."""
    body = ("<p>" + "x" * 200 + "</p>") * 500
    with EchoStand() as st:
        st.routes = {"/doc": (200, [("Content-Type", "text/html")], body.encode())}
        with curlpro.Session("chrome-153-windows") as s:
            def worker(_: int) -> int:
                from html.parser import HTMLParser

                class Count(HTMLParser):
                    n = 0

                    def handle_starttag(self, tag, attrs):  # noqa: ANN001
                        self.n += 1

                total = 0
                for _ in range(5):
                    p = Count()
                    p.feed(s.get(f"{st.url}/doc").text)
                    total += p.n
                return total

            with ThreadPoolExecutor(8) as pool:
                assert list(pool.map(worker, range(8))) == [2500] * 8


def test_free_threaded_build_reports_itself():
    """What the run was on, for the log: a free-threaded build with the GIL
    off is the configuration this file exists for."""
    gil = getattr(sys, "_is_gil_enabled", lambda: True)()
    print(f"free-threaded build: {FREE_THREADED}, GIL enabled: {gil}, threading: {threading.active_count()}")
