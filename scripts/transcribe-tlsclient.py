"""Transcribes TLS and HTTP/2 profiles from bogdanfinn/tls-client into curlPro.

tls-client describes each client as a uTLS ClientHelloSpec in Go (cipher
suites, extensions with their parameters) plus its HTTP/2 SETTINGS, window
increment, pseudo-header order and stream priority. Some of its profiles have
no browser of this project's to stand on: OkHttp 4 on the Android platform's
TLS (Android 7 to 13) and the TLS stacks of a few mobile apps (Zalando, Nike,
Mesh, Confirmed, MMS). Those are written here field for field — the suites and
extensions as tls-client lists them, in its order — as deltas on the nearest
captured client of the same platform for everything tls-client does not
describe: OkHttp 5.5 on Conscrypt for Android, Safari on iOS for iOS. They are
marked transcribed, and the note says what is tls-client's and what is not.

What tls-client does not have, nor this transcription: the apps' own headers.
An app sends its own User-Agent and headers; the profile carries the
platform's (OkHttp's on Android, with the app's name nowhere), and the caller
sets the app's.

Usage:
    python scripts/transcribe-tlsclient.py --src DIR --sha COMMIT [--write]

DIR holds profiles/contributed_custom_profiles.go of tls-client at COMMIT.
Without --write the plan is printed and nothing is written.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PROFILES = REPO / "profiles"
UTLS = REPO / "vendor" / "github.com" / "refraction-networking" / "utls"
UTLS_FORK = REPO / "vendor" / "github.com" / "bogdanfinn" / "utls"
SOURCE = "github.com/bogdanfinn/tls-client"

# tls-client's name -> (our name, parent, User-Agent or None to inherit).
TARGETS = {
    "Okhttp4Android13": ("okhttp-4.10-android13", "okhttp-5.5-conscrypt", "okhttp/4.10.0"),
    "Okhttp4Android12": ("okhttp-4.10-android12", "okhttp-5.5-conscrypt", "okhttp/4.10.0"),
    "Okhttp4Android11": ("okhttp-4.10-android11", "okhttp-5.5-conscrypt", "okhttp/4.10.0"),
    "Okhttp4Android10": ("okhttp-4.10-android10", "okhttp-5.5-conscrypt", "okhttp/4.10.0"),
    "Okhttp4Android9": ("okhttp-4.10-android9", "okhttp-5.5-conscrypt", "okhttp/4.10.0"),
    "Okhttp4Android8": ("okhttp-4.10-android8", "okhttp-5.5-conscrypt", "okhttp/4.10.0"),
    "Okhttp4Android7": ("okhttp-4.10-android7", "okhttp-5.5-conscrypt", "okhttp/4.10.0"),
    "ZalandoAndroidMobile": ("zalando-app-android", "okhttp-5.5-conscrypt", None),
    "NikeAndroidMobile": ("nike-app-android", "okhttp-5.5-conscrypt", None),
    "MeshAndroid": ("mesh-app-android", "okhttp-5.5-conscrypt", None),
    "MeshAndroid2": ("mesh-app-android-2", "okhttp-5.5-conscrypt", None),
    "ConfirmedAndroid": ("confirmed-app-android", "okhttp-5.5-conscrypt", None),
    "ConfirmedAndroid2": ("confirmed-app-android-2", "okhttp-5.5-conscrypt", None),
    "ZalandoIosMobile": ("zalando-app-ios", "safari-26-ios", None),
    "NikeIosMobile": ("nike-app-ios", "safari-26-ios", None),
    "MMSIos": ("mms-app-ios", "safari-26-ios", None),
    "MeshIos": ("mesh-app-ios", "safari-26-ios", None),
    "MeshIos2": ("mesh-app-ios-2", "safari-26-ios", None),
    "ConfirmedIos": ("confirmed-app-ios", "safari-26-ios", None),
}

# ---------------------------------------------------------------------------
# uTLS's constants, read from the vendored source
# ---------------------------------------------------------------------------


def utls_constants() -> dict[str, int]:
    """Constants of uTLS and of the fork tls-client builds on (which exports
    CompressionNone and PointFormatUncompressed): typed values, uint16(...)
    and aliases of other constants."""
    out: dict[str, int] = {}
    aliases: dict[str, str] = {}
    value = re.compile(r"^\s*(\w+)\s*(?:\w+\s*)?=\s*(?:uint16|uint8|CurveID|SignatureScheme)?\(?\s*(0x[0-9a-fA-F]+|\d+)\s*\)?\s*(?://.*)?$", re.M)
    alias = re.compile(r"^\s*(\w+)\s*(?:(?:uint8|uint16)\s*)?=\s*([A-Za-z_]\w*)\s*(?://.*)?$", re.M)
    for root in (UTLS, UTLS_FORK):
        for f in root.glob("*.go"):
            if f.name.endswith("_test.go"):
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            for name, v in value.findall(text):
                out.setdefault(name, int(v, 0))
            for name, other in alias.findall(text):
                aliases.setdefault(name, other)
    for _ in range(3):
        for name, other in aliases.items():
            if name not in out and other in out:
                out[name] = out[other]
    out["GREASE_PLACEHOLDER"] = 0x0a0a
    return out


C = utls_constants()


def const(expr: str) -> int:
    expr = expr.strip().removeprefix("tls.")
    m = re.fullmatch(r"(?:uint16|tls\.CurveID|CurveID)\((.+)\)", expr)
    if m:
        expr = m.group(1).strip().removeprefix("tls.")
    if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", expr):
        return int(expr, 0)
    if expr not in C:
        raise KeyError(f"unknown constant {expr}")
    return C[expr]


def items(body: str) -> list[str]:
    return [x for x in (s.strip() for s in re.split(r",\s*", body)) if x and not x.startswith("//")]


# ---------------------------------------------------------------------------
# Parsing a ClientProfile literal
# ---------------------------------------------------------------------------


def blocks(src: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in re.finditer(r"^var (\w+) = ClientProfile\{(.*?)^\}", src, re.S | re.M)}


def strip_comments(text: str) -> str:
    return re.sub(r"//[^\n]*", "", text)


def balanced(text: str, start: int) -> str:
    """The text inside the braces opening at text[start]."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
    raise ValueError("unbalanced braces")


def b64(values: list[int]) -> str:
    return base64.b64encode(bytes(values)).decode()


def extension(kind: str, body: str) -> dict:
    """One uTLS extension literal as a curlPro extension."""
    def list_of(field: str) -> list[int]:
        m = re.search(field + r":\s*\[\][\w.]+\{(.*?)\}", body, re.S)
        return [const(x) for x in items(m.group(1))] if m else []

    if kind == "SNIExtension":
        return {"type": "server_name"}
    if kind == "ExtendedMasterSecretExtension":
        return {"type": "extended_master_secret"}
    if kind == "RenegotiationInfoExtension":
        return {"type": "renegotiation_info"}
    if kind == "SessionTicketExtension":
        return {"type": "session_ticket"}
    if kind == "StatusRequestExtension":
        return {"type": "status_request"}
    if kind == "SCTExtension":
        return {"type": "signed_certificate_timestamp"}
    if kind == "UtlsGREASEExtension":
        return {"type": "GREASE"}
    if kind == "UtlsPaddingExtension":
        if "BoringPaddingStyle" not in body:
            raise ValueError("padding other than BoringPaddingStyle")
        # WillPad: true keeps the extension, empty, where BoringSSL's rule
        # would leave it out.
        if re.search(r"WillPad:\s*true", body):
            return {"type": "padding", "always": True}
        return {"type": "padding"}
    if kind == "SupportedCurvesExtension":
        return {"type": "supported_groups", "groups": list_of("Curves")}
    if kind == "SupportedPointsExtension":
        return {"type": "ec_point_formats", "formats": b64(list_of("SupportedPoints"))}
    if kind == "SignatureAlgorithmsExtension":
        return {"type": "signature_algorithms", "algorithms": list_of("SupportedSignatureAlgorithms")}
    if kind == "SupportedVersionsExtension":
        return {"type": "supported_versions", "versions": list_of("Versions")}
    if kind == "PSKKeyExchangeModesExtension":
        return {"type": "psk_key_exchange_modes", "modes": b64(list_of("Modes"))}
    if kind == "UtlsCompressCertExtension":
        return {"type": "compress_certificate", "algorithms": list_of("Algorithms")}
    if kind == "ALPNExtension":
        m = re.search(r"AlpnProtocols:\s*\[\]string\{(.*?)\}", body, re.S)
        return {"type": "application_layer_protocol_negotiation",
                "alpn": [x.strip('"') for x in items(m.group(1))] if m else []}
    if kind == "ApplicationSettingsExtension":
        m = re.search(r"SupportedProtocols:\s*\[\]string\{(.*?)\}", body, re.S)
        return {"type": "application_settings", "alpn": [x.strip('"') for x in items(m.group(1))] if m else []}
    if kind == "KeyShareExtension":
        groups = [const(g) for g in re.findall(r"Group:\s*([\w.()]+)", body)]
        return {"type": "key_share", "groups": groups}
    raise ValueError(f"extension {kind} has no curlPro form")


def parse_spec(body: str) -> dict:
    body = strip_comments(body)
    m = re.search(r"CipherSuites:\s*\[\]uint16\{", body)
    suites = [const(x) for x in items(balanced(body, m.end() - 1))]
    m = re.search(r"CompressionMethods:\s*\[\]byte\{", body)
    comp = [const(x) for x in items(balanced(body, m.end() - 1))] if m else [0]
    m = re.search(r"Extensions:\s*\[\]tls\.TLSExtension\{", body)
    ext_text = balanced(body, m.end() - 1)
    exts = []
    for em in re.finditer(r"&tls\.(\w+)\{", ext_text):
        exts.append(extension(em.group(1), balanced(ext_text, em.end() - 1)))
    if "tls.BoringGREASEECH()" in ext_text:
        raise ValueError("ECH GREASE has no field form here")
    out = {"cipher_suites": suites, "compression_methods": b64(comp), "extensions": exts,
           "permute_extensions": "RandomExtensionOrder: true" in body}
    # The parents carry a signature_algorithms of their own, which overrides
    # the extension's list on every build: written here, it is this one.
    sig = [e["algorithms"] for e in exts if e["type"] == "signature_algorithms"]
    if sig:
        out["signature_algorithms"] = sig[0]
    return out


SETTING = {"SettingHeaderTableSize": 1, "SettingEnablePush": 2, "SettingMaxConcurrentStreams": 3,
           "SettingInitialWindowSize": 4, "SettingMaxFrameSize": 5, "SettingMaxHeaderListSize": 6}


def parse_http2(body: str) -> dict:
    body = strip_comments(body)
    out: dict = {}
    m = re.search(r"settings:\s*map\[http2\.SettingID\]uint32\{(.*?)\}", body, re.S)
    values = {}
    if m:
        for k, v in re.findall(r"http2\.(\w+):\s*(\d+|math\.MaxUint32)", m.group(1)):
            values[SETTING[k]] = 0xFFFFFFFF if v == "math.MaxUint32" else int(v)
    m = re.search(r"settingsOrder:\s*\[\]http2\.SettingID\{(.*?)\}", body, re.S)
    order = [SETTING[x.removeprefix("http2.")] for x in items(m.group(1))] if m else sorted(values)
    # fhttp writes every setting of the order, a missing one as 0.
    out["settings"] = [{"id": i, "value": values.get(i, 0)} for i in order]
    m = re.search(r"connectionFlow:\s*(\d+)", body)
    if m:
        out["connection_window_update"] = int(m.group(1))
    m = re.search(r"pseudoHeaderOrder:\s*\[\]string\{(.*?)\}", body, re.S)
    if m:
        out["pseudo_order"] = [x.strip('"') for x in items(m.group(1))]
    m = re.search(r"headerPriority:\s*&http2\.PriorityParam\{(.*?)\}", body, re.S)
    if m and m.group(1).strip():
        w = re.search(r"Weight:\s*(\d+)", m.group(1))
        e = re.search(r"Exclusive:\s*(true|false)", m.group(1))
        if w:
            out["stream_weight"] = int(w.group(1)) + 1
        if e:
            out["stream_exclusive"] = e.group(1) == "true"
    return out


# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args()
    src = (Path(a.src) / "contributed_custom_profiles.go").read_text(encoding="utf-8")
    profiles = blocks(src)
    date = dt.date.today().isoformat()
    failed = 0
    for tc, (name, parent, ua) in TARGETS.items():
        body = profiles[tc]
        spec_owner = tc
        alias = re.search(r"return (\w+)\.GetClientHelloSpec\(\)", body)
        try:
            tls = parse_spec(profiles[alias.group(1)] if alias else body)
            if alias:
                spec_owner = alias.group(1)
            http2 = parse_http2(body)
        except (KeyError, ValueError) as e:
            print(f"{tc}: left out — {e}")
            failed += 1
            continue
        note = (f"Transcribed, not captured: the TLS ClientHello (cipher suites and extensions with their "
                f"parameters, in tls-client's order) and the HTTP/2 SETTINGS, window increment, pseudo-header "
                f"order and priority are tls-client's {tc}"
                + (f" (its ClientHello is {spec_owner}'s)" if spec_owner != tc else "")
                + f". Everything else stands on the captured {parent}: ")
        if parent.startswith("okhttp"):
            note += ("OkHttp's header set (OkHttp, measured over HTTP/2 only, has no HTTP/1.1 set). " +
                     ("The User-Agent is OkHttp 4.10's, the version tls-client names."
                      if ua else "An app sends its own User-Agent and headers, which tls-client does not "
                                 "describe: set them on the session."))
        else:
            note += ("Safari's header sets. An app sends its own User-Agent and headers (CFNetwork's, not "
                     "Safari's), which tls-client does not describe: set them on the session.")
        quirks = []
        if any(e["type"] == "application_settings" and not e.get("alpn") for e in tls["extensions"]):
            quirks.append("its ALPS extension names no protocol (BoringSSL sends ALPS only with one)")
        if any(e.get("always") for e in tls["extensions"]):
            quirks.append("its padding extension is on every hello, empty below 256 bytes (WillPad: true)")
        if quirks:
            note += " Kept as tls-client has it: " + "; ".join(quirks) + "."
        want = {
            "name": name,
            "based_on": parent,
            "source": {"kind": "transcribed", "from": SOURCE, "ref": a.sha,
                       "path": "profiles/contributed_custom_profiles.go", "date": date, "note": note},
            "tls": tls,
            "http2": http2,
        }
        if ua:
            want["headers"] = {"user_agent": ua}
        if parent.startswith("safari"):
            # Safari's iOS-version pool varies Safari's User-Agent; an app
            # sends its own, so the delta declines it (gen-identities.py
            # writes the same).
            want["devices"] = []
        path = PROFILES / f"{name}.json"
        print(f"{tc:22s} -> {name:26s} on {parent}: {len(tls['cipher_suites'])} suites, "
              f"{len(tls['extensions'])} extensions, h2 {http2.get('settings')}")
        if a.write:
            path.write_text(json.dumps(want, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return 1 if failed and a.write else 0


if __name__ == "__main__":
    sys.exit(main())
