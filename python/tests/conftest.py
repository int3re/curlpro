"""Loads the repository profiles once for every test module.

Installed from a wheel the package carries its profiles and loads them on
first use; run from the repository there is no such directory, and each
test module used to carry this fixture of its own.
"""
from pathlib import Path

import curlpro
import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _repository_profiles():
    curlpro.load_profiles(REPO / "profiles")
