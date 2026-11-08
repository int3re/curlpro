"""Loads the repository profiles once for every test module, and keeps the
machine's proxy out of the tests.

Installed from a wheel the package carries its profiles and loads them on
first use; run from the repository there is no such directory, and each
test module used to carry this fixture of its own.
"""
import os
from pathlib import Path

import curlpro
import pytest

REPO = Path(__file__).resolve().parents[2]

PROXY_VARIABLES = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy",
                   "NO_PROXY", "no_proxy")


@pytest.fixture(scope="session", autouse=True)
def _repository_profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.fixture(autouse=True)
def _no_machine_proxy(monkeypatch):
    """A session trusts the environment by default, and a machine's proxy
    (HTTPS_PROXY=http://127.0.0.1:10809 on the one these were written on)
    took the tests' requests: HTTP/3 refused through an http:// proxy, stands
    on 127.0.0.1 reached through it or not at all. A test that wants a proxy
    in the environment sets it itself. CURLPRO_TESTS_KEEP_PROXY=1 keeps the
    machine's — for network tests behind a proxy there is no way around.
    Python reads the environment for every request (Session._route), so this
    holds on every system, Linux included."""
    if os.environ.get("CURLPRO_TESTS_KEEP_PROXY") == "1":
        return
    for name in PROXY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
