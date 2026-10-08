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


def test_a_masque_proxy_is_a_scheme_we_speak():
    """masque:// reaches the dial, not the scheme check.

    The distinction matters to a caller: a ConfigurationError means "you wrote
    something I do not understand" and is permanent, while a dial failure means
    "that proxy is down" and is worth another address. Before HTTP/3 proxies
    existed the first was the only answer a masque:// address could get.
    """
    e = outcome(proxy="masque://127.0.0.1:1")
    assert isinstance(e, curlpro.ProxyError) and not isinstance(e, curlpro.ConfigurationError)
    assert e.stage == "dial"


def test_http3_names_the_proxy_scheme_that_can_carry_it():
    """QUIC through a byte-stream tunnel is impossible, and saying so beats
    going direct: that would publish the address the proxy was hiding."""
    for proxy in ("http://127.0.0.1:8080", "https://127.0.0.1:443", "socks5://127.0.0.1:1080"):
        with pytest.raises(curlpro.ConfigurationError, match="masque://"):
            curlpro.Session("chrome-151-windows", http3=True, proxy=proxy)
    # A MASQUE proxy is accepted: the session is built, and only the request
    # that uses it can fail.
    curlpro.Session("chrome-151-windows", http3=True, proxy="masque://127.0.0.1:443").close()
