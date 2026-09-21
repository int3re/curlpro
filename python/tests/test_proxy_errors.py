"""A proxy failure arrives as ProxyError with its stage and status.

Four outcomes used to be one CurlProError with an empty code, and a pool
deciding "drop this address or rest it" parsed the message for the answer.
"""
import pytest

import curlpro
from echo_stand import EchoStand


def outcome(**kw):
    with curlpro.Session("chrome-151-windows", timeout=(2, 3), retries=0, **kw) as s:
        with pytest.raises(curlpro.CurlProError) as ei:
            s.get("https://127.0.0.1:1/")
    return ei.value


def test_proxy_unreachable_is_the_dial_stage():
    for proxy in ("http://127.0.0.1:1", "socks5://127.0.0.1:1"):
        e = outcome(proxy=proxy)
        assert isinstance(e, curlpro.ProxyError) and not isinstance(e, curlpro.PermanentError)
        assert e.code == "proxy" and e.stage == "dial" and e.status is None


def test_407_is_a_permanent_proxy_auth_error():
    with EchoStand() as st:
        st.routes["CONNECT"] = (407, [("Proxy-Authenticate", 'Basic realm="x"')], b"")
        e = outcome(proxy=st.url)
        assert isinstance(e, curlpro.ProxyAuthError) and isinstance(e, curlpro.PermanentError)
        assert e.code == "proxy_auth" and e.stage == "auth" and e.status == 407
        # With credentials the proxy keeps refusing: the same answer.
        e = outcome(proxy=st.url.replace("http://", "http://u:p@"))
        assert isinstance(e, curlpro.ProxyAuthError) and e.status == 407


def test_gateway_refusal_carries_its_status_and_is_not_permanent():
    with EchoStand() as st:
        st.routes["CONNECT"] = (502, [], b"")
        e = outcome(proxy=st.url)
        assert type(e) is curlpro.ProxyError and not isinstance(e, curlpro.PermanentError)
        assert e.code == "proxy" and e.stage == "connect" and e.status == 502


def test_target_unreachable_directly_is_not_a_proxy_error():
    e = outcome()
    assert not isinstance(e, curlpro.ProxyError)


def test_proxy_address_mistakes_are_configuration_errors():
    e = outcome(proxy="ftp://127.0.0.1:21")
    assert isinstance(e, curlpro.ConfigurationError)
