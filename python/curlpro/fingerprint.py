"""What a server sees, computed without sending anything.

Until this existed the only way to learn one's own fingerprint was to ask an
oracle — tls.browserleaks.com and the like. That made every check depend on
someone else's service being up, and it made "why am I being detected" a
question answerable only online.

The ClientHello is ours to build, so the same values are computed locally, from
the marshalled bytes rather than from the profile: key_share, ECH and padding
materialise only when the handshake is assembled, and their sizes are part of
the fingerprint. Checked against 48 captures in ``reference/baselines`` — JA4,
JA3N and the Akamai string all match what the oracle reported.
"""

from __future__ import annotations

from typing import Any


class Fingerprint:
    """The network identity of a session.

        with curlpro.Session("chrome-151-windows") as s:
            fp = s.fingerprint()
            print(fp.ja4)       # t13d1516h2_8daaf6152771_806a8c22fdea
            print(fp.akamai)    # 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
    """

    __slots__ = ("_d",)

    def __init__(self, data: dict[str, Any]):
        self._d = data

    # -- TLS ---------------------------------------------------------------

    @property
    def ja4(self) -> str:
        """JA4 — stable across connections and across domains.

        The one to compare against a reference: extensions are sorted, so
        Chrome's per-connection shuffling does not move it.
        """
        return self._d.get("ja4", "")

    @property
    def ja4_r(self) -> str:
        """JA4 with the lists spelled out instead of hashed — for reading a diff."""
        return self._d.get("ja4_r", "")

    @property
    def ja3n(self) -> str:
        """JA3 with the extensions sorted. Stable, unlike plain JA3."""
        return self._d.get("ja3n", "")

    @property
    def ja3(self) -> str:
        """JA3 in send order.

        For a profile that shuffles its extensions — every Chrome since 110 —
        this legitimately differs between connections: twelve builds give
        twelve values. That is not a defect to be fixed; a frozen order is
        itself an anomaly. Compare :attr:`ja3n` or :attr:`ja4` instead.
        """
        return self._d.get("ja3", "")

    @property
    def ja3_text(self) -> str:
        """The string JA3 is the MD5 of — where a mismatch becomes readable."""
        return self._d.get("ja3_text", "")

    @property
    def akamai(self) -> str:
        """The HTTP/2 fingerprint: SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-order."""
        return self._d.get("akamai", "")

    # -- the raw material --------------------------------------------------

    @property
    def ciphers(self) -> list[str]:
        return list(self._d.get("ciphers") or [])

    @property
    def extensions(self) -> list[str]:
        return list(self._d.get("extensions") or [])

    @property
    def curves(self) -> list[str]:
        return list(self._d.get("curves") or [])

    @property
    def sigalgs(self) -> list[str]:
        return list(self._d.get("sigalgs") or [])

    @property
    def alpn(self) -> list[str]:
        return list(self._d.get("alpn") or [])

    # -- HTTP --------------------------------------------------------------

    @property
    def headers(self) -> list[str]:
        """Header names in send order, as an ordinary GET would send them."""
        return list(self._d.get("headers") or [])

    @property
    def headers_http1(self) -> list[str]:
        """The same over HTTP/1.1, where the set differs.

        Chrome sends no ``priority`` there and Firefox no ``TE``, so this is a
        different list rather than the same one reordered.
        """
        return list(self._d.get("headers_http1") or [])

    @property
    def ja4h(self) -> str:
        """JA4H — the fingerprint of the request, for a plain GET.

        Licensed differently from everything else here. JA4 for TLS is BSD-3
        and free; JA4H falls under the FoxIO License 1.1 and is patent-pending:
        internal and academic use is free, commercial monetisation needs an OEM
        licence from FoxIO. Computing it in a product is therefore a decision,
        not a detail — which is why it is said here rather than buried.

        Two clients with identical TLS can still differ here, which is why the
        two are scored together.

        Empty in a library built with ``-tags nofoxio``, where none of the
        FoxIO-licensed code is compiled in — see :attr:`ja4h_available`.
        """
        return self._d.get("ja4h", "")

    @property
    def ja4h_http1(self) -> str:
        """The same over HTTP/1.1, where the header set and the version differ."""
        return self._d.get("ja4h_http1", "")

    @property
    def ja4h_available(self) -> bool:
        """Whether this build computes JA4H at all.

        False in a library built with ``-tags nofoxio``: a dependency review
        that objects to the FoxIO License 1.1 can drop JA4H without dropping
        the library, and everything else is computed as before. Reported rather
        than inferred from an empty string, which the real implementation never
        returns.
        """
        return bool(self._d.get("ja4h_available", True))

    @property
    def user_agent(self) -> str:
        return self._d.get("user_agent", "")

    @property
    def profile(self) -> str:
        return self._d.get("profile", "")

    def to_dict(self) -> dict[str, Any]:
        """Everything as plain data — serialisable, storable, comparable."""
        return dict(self._d)

    #: Fields whose order is drawn per connection rather than fixed.
    #:
    #: Only the extension list: Chrome ≥110 shuffles it on every handshake, so
    #: two sessions of the same profile legitimately send it in different
    #: orders. Comparing those lists as written reports noise on every call —
    #: which is exactly why JA4 sorts them. Everything else keeps its order,
    #: the header list above all: there the order *is* the fingerprint.
    _UNORDERED = ("extensions",)

    def diff(self, other: "Fingerprint") -> dict[str, tuple[Any, Any]]:
        """What differs between two fingerprints.

        Answers the question a profile edit actually raises: did this change
        anything a server can see, and what exactly.

            a = curlpro.Session("chrome-151-windows").fingerprint()
            b = curlpro.Session("chrome-152-windows").fingerprint()
            for field, (mine, theirs) in a.diff(b).items():
                print(field, mine, "->", theirs)

        Prints, among other things, that Chrome 152 added the extension
        ``ca34`` — trust_anchors — rather than merely that two hashes are
        unequal.
        """
        out: dict[str, tuple[Any, Any]] = {}
        for key in ("ja4", "ja3n", "akamai", "ja4h", "ja4h_http1", "user_agent",
                    "ciphers", "extensions", "curves", "sigalgs", "alpn",
                    "headers", "headers_http1"):
            mine, theirs = self._d.get(key), other._d.get(key)
            if key in self._UNORDERED and isinstance(mine, list) and isinstance(theirs, list):
                if sorted(mine) == sorted(theirs):
                    continue
            if mine != theirs:
                out[key] = (mine, theirs)
        return out

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Fingerprint):
            return NotImplemented
        # Plain JA3 is deliberately excluded: it moves between connections for
        # every shuffling profile, so comparing it would make two identical
        # sessions look different.
        return not self.diff(other)

    def __repr__(self) -> str:
        return f"<Fingerprint {self.profile or '?'} ja4={self.ja4}>"

    def __str__(self) -> str:
        lines = [
            f"profile  {self.profile}",
            f"JA4      {self.ja4}",
            f"JA3N     {self.ja3n}",
            f"Akamai   {self.akamai}",
            f"JA4H     {self.ja4h}",
            f"ALPN     {', '.join(self.alpn)}",
            f"headers  {' '.join(self.headers)}",
        ]
        return "\n".join(lines)
