#!/usr/bin/env python3
"""Сборка профиля из нормализованного эталона и сырых сэмплов.

На выходе — JSON в схеме docs/PROFILE-SCHEMA.md: базовый профиль несёт
захваченные байты ClientHello, а заголовки и настройки HTTP/2 записываются
декларативно, чтобы следующая версия браузера описывалась дельтой.

Usage: python make_profile.py samples/chrome-151-windows reference/chrome-151-windows.json \
                             -o ../profiles/chrome-151-windows.json --name chrome-151-windows
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def build(sample_dir: Path, ref_path: Path, name: str) -> dict:
    ref = json.loads(ref_path.read_text(encoding="utf-8"))
    samples = [json.loads(p.read_text(encoding="utf-8"))
               for p in sorted(sample_dir.glob("sample-*.json"))]
    if not samples:
        raise SystemExit(f"нет сэмплов в {sample_dir}")

    frames = samples[0]["metadata"]["HTTP2Frames"]

    settings = [{"id": s["Id"], "value": s["Val"]} for s in frames["Settings"]]

    headers = frames.get("Headers") or []
    pseudo = [h["Name"] for h in headers if h["Name"].startswith(":")]
    ua = samples[0]["user_agent"]

    order = []
    for h in headers:
        if h["Name"].startswith(":"):
            continue
        # user-agent хранится один раз в headers.user_agent, здесь — только позиция
        order.append({"key": h["Name"], "value": "" if h["Name"] == "user-agent" else h["Value"]})

    # Chrome ставит priority на HEADERS-кадре; на проводе вес на единицу меньше (RFC 7540).
    prio = (frames.get("Priorities") or [{}])[0]

    profile = {
        "name": name,
        "tls": {
            "raw_client_hello": ref["raw_client_hello_b64"],
            "signature_algorithms": ref["tls"]["signature_algorithms"],
            "permute_extensions": True,
        },
        "http2": {
            "settings": settings,
            "connection_window_update": frames["WindowUpdateIncrement"],
            "pseudo_order": pseudo,
        },
        "headers": {"user_agent": ua, "order": order},
    }
    if prio:
        profile["http2"]["stream_weight"] = prio["Weight"] + 1
        profile["http2"]["stream_exclusive"] = prio["Exclusive"]
    return profile


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 64
    sample_dir, ref_path = Path(sys.argv[1]), Path(sys.argv[2])
    name = sys.argv[sys.argv.index("--name") + 1] if "--name" in sys.argv else sample_dir.name

    prof = build(sample_dir, ref_path, name)

    if "-o" in sys.argv:
        out = Path(sys.argv[sys.argv.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(prof, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"профиль записан: {out}")

    h2 = prof["http2"]
    print(f"name:     {prof['name']}")
    print(f"settings: {';'.join(f'{s['id']}:{s['value']}' for s in h2['settings'])}")
    print(f"window:   {h2['connection_window_update']}")
    print(f"pseudo:   {','.join(x[1] for x in h2['pseudo_order'])}")
    print(f"headers:  {len(prof['headers']['order'])} шт.")
    for h in prof["headers"]["order"]:
        print(f"   {h['key']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
