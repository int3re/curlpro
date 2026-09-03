#!/usr/bin/env python3
"""Сведение N сырых сэмплов в один нормализованный эталон.

Chrome >=110 перемешивает расширения и рандомизирует значения GREASE на каждом
соединении. Поэтому эталон строится по пересечению сэмплов, а GREASE
вырезается: сохраняются только его ПОЗИЦИИ (первая/последняя), но не значения.

Usage: python normalize.py samples/chrome-151-windows [-o reference/chrome-151-windows.json]
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

EXT_NAMES = {
    0: "server_name", 5: "status_request", 10: "supported_groups",
    11: "ec_point_formats", 13: "signature_algorithms", 16: "alpn",
    17: "status_request_v2", 18: "signed_certificate_timestamp",
    21: "padding", 23: "extended_master_secret", 27: "compress_certificate",
    28: "record_size_limit", 34: "delegated_credentials", 35: "session_ticket",
    43: "supported_versions", 45: "psk_key_exchange_modes", 49: "post_handshake_auth",
    50: "signature_algorithms_cert", 51: "key_share",
    17513: "application_settings", 17613: "application_settings_new",
    51914: "trust_anchors", 65037: "encrypted_client_hello",
    65281: "renegotiation_info",
}


def is_grease(v: int) -> bool:
    """RFC 8701: GREASE значения имеют вид 0x?A?A."""
    return (v & 0x0F0F) == 0x0A0A


def build(sample_dir: Path) -> dict:
    paths = sorted(sample_dir.glob("sample-*.json"))
    if not paths:
        raise SystemExit(f"нет сэмплов в {sample_dir}")

    samples = [json.loads(p.read_text(encoding="utf-8")) for p in paths]

    ja4 = {s.get("_ja4") for s in samples} - {None}
    ext_sets = {tuple(sorted(e for e in s["ja3"]["AllExtensions"] if not is_grease(e)))
                for s in samples}
    if len(ext_sets) != 1:
        raise SystemExit(f"наборы расширений расходятся ({len(ext_sets)} вариантов) — "
                         "сэмплы сняты с разных клиентов или версий")

    first = samples[0]
    exts = sorted(ext_sets)[0]

    # позиции GREASE в исходном порядке — устойчивы, в отличие от значений
    positions = Counter()
    for s in samples:
        order = s["ja3"]["AllExtensions"]
        for idx, e in enumerate(order):
            if is_grease(e):
                positions["first" if idx == 0 else
                          "last" if idx == len(order) - 1 else f"pos{idx}"] += 1

    ciphers = [c for c in first["ja3"]["CipherSuites"] if not is_grease(c)]

    return {
        "captured": {
            "user_agent": first["user_agent"],
            "samples": len(samples),
            "ja4": sorted(ja4),
            "ja3_hashes": sorted({s["_ja3_hash"] for s in samples if s.get("_ja3_hash")}),
        },
        "tls": {
            "extensions_normalized": list(exts),
            "extensions_readable": [f"{EXT_NAMES.get(e, 'unknown')} (0x{e:04x})" for e in exts],
            "grease_positions": dict(positions),
            "cipher_suites": ciphers,
            "signature_algorithms": first["ja4"]["SignatureAlgorithms"],
            "supported_groups_readable": first["ja3"]["ReadableSupportedGroups"],
        },
        "raw_client_hello_b64": first["metadata"]["ClientHelloRecord"],
    }


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 64
    src = Path(sys.argv[1])
    ref = build(src)

    out = None
    if "-o" in sys.argv:
        out = Path(sys.argv[sys.argv.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(ref, indent=2, ensure_ascii=False), encoding="utf-8")

    c = ref["captured"]
    t = ref["tls"]
    print(f"Сэмплов: {c['samples']}   JA4: {', '.join(c['ja4'])}")
    print(f"Шифров: {len(t['cipher_suites'])}   Расширений: {len(t['extensions_normalized'])}")
    print(f"GREASE-позиции: {t['grease_positions']}")
    print("\nРасширения (нормализовано):")
    for r in t["extensions_readable"]:
        print(f"   {r}")
    if out:
        print(f"\nЭталон сохранён: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
