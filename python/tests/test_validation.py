"""Bad option values are refused by name, at the boundary, in Python.

Found by an edge-input probe run in subprocesses: nothing crashed, but several
values slipped through or failed three frames deep with a message that named
nothing the caller had typed. A NaN timeout raised a bare ValueError from an
int() call, infinity an OverflowError, a negative body limit meant "no limit",
2**63 came back as a Go JSON error, a corrupt profile raised JSONDecodeError,
a missing profile directory was reported as "open .", and Expect(status=...)
took any object and then failed every response quoting its repr.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import curlpro

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


@pytest.mark.parametrize("bad", [float("nan"), -1, -0.5, float("-inf")])
def test_timeout_is_refused_by_name(bad):
    with pytest.raises(ValueError, match="timeout"):
        curlpro.Session("chrome-151-windows", timeout=bad)


def test_infinite_timeout_means_no_limit():
    with curlpro.Session("chrome-151-windows", timeout=float("inf")) as s:
        assert s is not None


def test_bool_timeout_is_a_type_error():
    with pytest.raises(TypeError, match="timeout"):
        curlpro.Session("chrome-151-windows", timeout=True)


@pytest.mark.parametrize("bad", [-1, 2**63, 1.5, True])
def test_max_response_size_bounds(bad):
    with pytest.raises((ValueError, TypeError), match="max_response_size"):
        curlpro.Session("chrome-151-windows", max_response_size=bad)


def test_negative_max_redirects_is_refused():
    with pytest.raises(ValueError, match="max_redirects"):
        curlpro.Session("chrome-151-windows", max_redirects=-1)


def test_register_profile_bad_json_is_a_value_error():
    with pytest.raises(ValueError, match="not valid JSON"):
        curlpro.register_profile("{not json")


def test_load_profiles_missing_directory_names_it():
    with pytest.raises(FileNotFoundError, match="no/such/dir"):
        curlpro.load_profiles("/no/such/dir")


def test_expect_status_takes_ints_only():
    with pytest.raises(TypeError, match="status"):
        curlpro.Expect(status=object())
    with pytest.raises(TypeError, match="not_status"):
        curlpro.Expect(not_status=[200, "404"])
    assert curlpro.Expect(status=[200, 201]).status == [200, 201]
