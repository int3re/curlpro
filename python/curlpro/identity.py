"""Who the visitor is, beyond the browser: country, time zone, languages —
consistent with the address the requests come from.

A browser in Berlin behind a German address asks for German first and keeps
Berlin's time; the same browser reporting Moscow's time zone and Russian
through a German proxy is a contradiction a fingerprinting script reads in a
line (CreepJS and pixelscan compare exactly these with the IP's location).
:class:`Identity` holds the three, and a session with one sends its
``Accept-Language`` and gives its browser (:class:`~curlpro.solvers.BrowserSolver`,
:meth:`~curlpro.Session.browser`) the same languages and time zone.

The time zone reaches the browser through DevTools'
``Emulation.setTimezoneOverride`` on the tab, set before its page loads.
Measured on Chrome 154: the page, its ``Date`` offsets, a dedicated worker, a
shared worker and a service worker all report the zone given, through
navigations; the ``TZ`` environment variable does nothing to Chrome on
Windows. The languages go into the browser's profile, as a person sets them,
and every one of those contexts reports them too.

:meth:`Identity.lookup` asks a geolocation service, through the proxy, where
the exit address is — the only network call here, made when asked.
:meth:`Identity.for_country` needs none: the country's usual time zone and its
language before English, a convention rather than a measurement — the caller
who knows better passes ``timezone`` and ``languages`` themselves.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

#: Country → (its languages before English, its usual time zone). The zone is
#: the capital's, or the most populous one's where a country spans several;
#: :meth:`Identity.lookup` gives the address's own.
_COUNTRIES: dict[str, tuple[tuple[str, ...], str]] = {
    "US": (("en-US", "en"), "America/New_York"),
    "GB": (("en-GB", "en"), "Europe/London"),
    "CA": (("en-CA", "en"), "America/Toronto"),
    "AU": (("en-AU", "en"), "Australia/Sydney"),
    "IE": (("en-IE", "en"), "Europe/Dublin"),
    "NZ": (("en-NZ", "en"), "Pacific/Auckland"),
    "IN": (("en-IN", "en", "hi"), "Asia/Kolkata"),
    "SG": (("en-SG", "en"), "Asia/Singapore"),
    "DE": (("de-DE", "de"), "Europe/Berlin"),
    "AT": (("de-AT", "de"), "Europe/Vienna"),
    "CH": (("de-CH", "de"), "Europe/Zurich"),
    "FR": (("fr-FR", "fr"), "Europe/Paris"),
    "BE": (("nl-BE", "nl", "fr"), "Europe/Brussels"),
    "NL": (("nl-NL", "nl"), "Europe/Amsterdam"),
    "ES": (("es-ES", "es"), "Europe/Madrid"),
    "IT": (("it-IT", "it"), "Europe/Rome"),
    "PT": (("pt-PT", "pt"), "Europe/Lisbon"),
    "PL": (("pl-PL", "pl"), "Europe/Warsaw"),
    "CZ": (("cs-CZ", "cs"), "Europe/Prague"),
    "SE": (("sv-SE", "sv"), "Europe/Stockholm"),
    "NO": (("nb-NO", "nb", "no"), "Europe/Oslo"),
    "DK": (("da-DK", "da"), "Europe/Copenhagen"),
    "FI": (("fi-FI", "fi"), "Europe/Helsinki"),
    "RO": (("ro-RO", "ro"), "Europe/Bucharest"),
    "HU": (("hu-HU", "hu"), "Europe/Budapest"),
    "GR": (("el-GR", "el"), "Europe/Athens"),
    "TR": (("tr-TR", "tr"), "Europe/Istanbul"),
    "UA": (("uk-UA", "uk"), "Europe/Kyiv"),
    "RU": (("ru-RU", "ru"), "Europe/Moscow"),
    "KZ": (("ru-KZ", "ru", "kk"), "Asia/Almaty"),
    "BY": (("ru-BY", "ru", "be"), "Europe/Minsk"),
    "IL": (("he-IL", "he"), "Asia/Jerusalem"),
    "AE": (("ar-AE", "ar"), "Asia/Dubai"),
    "SA": (("ar-SA", "ar"), "Asia/Riyadh"),
    "BR": (("pt-BR", "pt"), "America/Sao_Paulo"),
    "MX": (("es-MX", "es"), "America/Mexico_City"),
    "AR": (("es-AR", "es"), "America/Argentina/Buenos_Aires"),
    "CO": (("es-CO", "es"), "America/Bogota"),
    "CL": (("es-CL", "es"), "America/Santiago"),
    "JP": (("ja-JP", "ja"), "Asia/Tokyo"),
    "KR": (("ko-KR", "ko"), "Asia/Seoul"),
    "CN": (("zh-CN", "zh"), "Asia/Shanghai"),
    "TW": (("zh-TW", "zh"), "Asia/Taipei"),
    "HK": (("zh-HK", "zh"), "Asia/Hong_Kong"),
    "VN": (("vi-VN", "vi"), "Asia/Ho_Chi_Minh"),
    "TH": (("th-TH", "th"), "Asia/Bangkok"),
    "ID": (("id-ID", "id"), "Asia/Jakarta"),
    "PH": (("en-PH", "en", "fil"), "Asia/Manila"),
    "MY": (("ms-MY", "ms"), "Asia/Kuala_Lumpur"),
    "ZA": (("en-ZA", "en"), "Africa/Johannesburg"),
    "EG": (("ar-EG", "ar"), "Africa/Cairo"),
    "NG": (("en-NG", "en"), "Africa/Lagos"),
}

#: The service :meth:`Identity.lookup` asks by default: answers over HTTPS,
#: with ``ip``, ``country`` (ISO 3166-1 alpha-2) and ``timezone`` (IANA).
LOOKUP_URL = "https://ipinfo.io/json"


def accept_language(languages: tuple[str, ...] | list[str]) -> str:
    """The header Chrome sends for a list of languages: the first without a
    weight, each next 0.1 lower — ``ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7``, as
    measured on this machine's Chrome 154."""
    out = []
    for i, lang in enumerate(languages):
        q = max(1.0 - i / 10, 0.1)
        out.append(lang if i == 0 else f"{lang};q={q:.1f}")
    return ",".join(out)


@dataclass(frozen=True)
class Identity:
    """A visitor's country, time zone and languages.

    ``languages`` in order of preference (``("de-DE", "de", "en-US", "en")``);
    ``timezone`` an IANA name (``"Europe/Berlin"``); ``country`` an ISO
    3166-1 alpha-2 code; ``ip`` the exit address a lookup found.
    """

    country: str = ""
    timezone: str = ""
    languages: tuple = field(default_factory=tuple)
    ip: str = ""

    @property
    def accept_language(self) -> str:
        return accept_language(self.languages)

    @classmethod
    def for_country(cls, country: str, *, timezone: str = "", languages: Any = None) -> "Identity":
        """A visitor of ``country``: its language before English and its
        usual time zone, unless given."""
        code = country.upper()
        if code not in _COUNTRIES and not (timezone and languages):
            raise ValueError(f"no defaults for country {country!r}: pass timezone= and languages=, "
                             f"or one of {', '.join(sorted(_COUNTRIES))}")
        own, zone = _COUNTRIES.get(code, ((), ""))
        if languages is None:
            langs = tuple(own) + tuple(x for x in ("en-US", "en") if x not in own)
        else:
            langs = tuple(languages)
        return cls(country=code, timezone=timezone or zone, languages=langs)

    @classmethod
    def lookup(cls, proxy: str = "", *, impersonate: str | None = None, url: str = LOOKUP_URL,
               timeout: float = 15.0) -> "Identity":
        """Where the requests come out: asks ``url`` through ``proxy`` (direct
        when empty) and builds the identity of that country, with the zone the
        service gives for the address. The service sees the exit address —
        that is the point — and nothing else of the caller."""
        from .session import Session

        kw: dict[str, Any] = {"timeout": timeout, "trust_env": False}
        if impersonate:
            kw["impersonate"] = impersonate
        with Session(proxy=proxy or None, **kw) as s:
            data = s.get(url, mode="fetch", credentials="omit").raise_for_status().json()
        country = str(data.get("country") or data.get("country_code") or "").upper()
        zone = str(data.get("timezone") or data.get("time_zone") or "")
        if not country:
            raise ValueError(f"{url} named no country: {str(data)[:200]}")
        base = cls.for_country(country, timezone=zone, languages=None if country in _COUNTRIES else ("en-US", "en"))
        return replace(base, ip=str(data.get("ip") or ""))
