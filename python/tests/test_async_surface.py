"""The async session must offer what the sync one does — and refuse what it
does not have.

A field report found `s.page = url` on an AsyncSession doing nothing: the class
is a wrapper, the property had not been proxied, and the assignment quietly
made an attribute on the wrapper instead. No error, the request went out with
no Referer and the wrong sec-fetch-site, and it took an echo server to see.
The wrapper had also never had fingerprint() or audit() at all.

So two tests: the surface is compared with Session's, and the wrapper refuses
unknown attributes. The first fails the next time a property is added to
Session and forgotten here; the second turns any that slips through into an
AttributeError at the assignment instead of silence on the wire.
"""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path

import curlpro
import pytest

from rawserver import RawHeaderServer

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _profiles():
    curlpro.load_profiles(REPO / "profiles")


def _public(cls) -> set[str]:
    return {n for n, v in inspect.getmembers(cls)
            if not n.startswith("_") and (inspect.isfunction(v) or isinstance(v, property))}


def test_the_async_surface_covers_the_sync_one():
    sync, async_ = _public(curlpro.Session), _public(curlpro.AsyncSession)
    # websocket and stream are there under the same names, returning openers.
    missing = sync - async_
    assert missing == set(), f"AsyncSession does not proxy: {sorted(missing)}"


def test_an_unknown_attribute_is_refused_rather_than_swallowed():
    s = curlpro.AsyncSession("chrome-151-windows")
    try:
        with pytest.raises(AttributeError):
            s.pge = "https://example.test/"          # a typo for page
        with pytest.raises(AttributeError):
            s.some_future_property = 1
    finally:
        s._session.close()


def test_page_on_the_async_session_reaches_the_wire():
    with RawHeaderServer(persistent=True) as srv:
        page = "https://www.example.test/app"

        async def main():
            async with curlpro.AsyncSession("chrome-151-windows", verify=False,
                                            force_http1=True) as s:
                s.page = page
                assert s.page == page
                r = await s.get(srv.url + "x", mode="fetch")
                sent = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip()
                        for l in r.json()["raw"] if ":" in l}
                assert sent["origin"] == "https://www.example.test"
                assert sent["referer"] == "https://www.example.test/"
                assert sent["sec-fetch-site"] == "cross-site"
                s.page = None
                assert s.page is None

        asyncio.run(main())


def test_fingerprint_and_audit_work_on_the_async_session():
    async def main():
        async with curlpro.AsyncSession("chrome-152-android") as s:
            fp = s.fingerprint()
            assert fp.ja4.startswith("t13")
            assert {f.code for f in s.audit()} == {"mobile_no_device"}
            h = s.headers_for("POST", "https://example.test/api", mode="fetch")
            assert h["accept"] == "*/*"

    asyncio.run(main())
