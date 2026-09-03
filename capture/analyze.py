#!/usr/bin/env python3
"""Разбор лога fingerproxy echo-server (-verbose) в набор эталонных сэмплов.

Проверяет ключевую гипотезу этапа 0: Chrome >=110 перемешивает TLS-расширения
на каждом соединении, поэтому JA3 нестабилен, а JA4 (сортирующий расширения) --
стабилен. Если это подтверждается, стенд снимает настоящий браузер, а не артефакт.

Usage: python analyze.py <server.log> [--out samples/]
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

LINE = re.compile(r"\[client (?P<client>[\d.:]+)\] (?P<key>ja3|ja4|detail): (?P<val>.*)")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def request_path(detail: dict) -> str:
    frames = detail.get("metadata", {}).get("HTTP2Frames") or {}
    for h in frames.get("Headers") or []:
        if h["Name"] == ":path":
            return h["Value"]
    return ""


def parse(log_path: Path, want_path: str = "") -> dict[str, dict]:
    """Собирает записи по client-адресу. Один адрес = одно TLS-соединение.

    По одному h2-соединению браузер шлёт несколько запросов (навигация, затем
    /favicon.ico), и каждый даёт свою detail-запись. Заголовки у них разные:
    у favicon нет upgrade-insecure-requests и другие sec-fetch-*. Поэтому
    detail накапливаются, а нужный выбирается по :path.
    """
    conns: dict[str, dict] = {}
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = LINE.search(line)
        if not m:
            continue
        conn = conns.setdefault(m["client"], {})
        val = m["val"].strip()
        if m["key"] == "detail":
            try:
                conn.setdefault("details", []).append(json.loads(val))
            except json.JSONDecodeError:
                pass
        else:
            conn[m["key"]] = val

    for conn in conns.values():
        details = conn.get("details") or []
        chosen = next((d for d in details if request_path(d) == want_path), None) if want_path else None
        conn["detail"] = chosen or (details[0] if details else {})
    return conns


def summarize(conns: dict[str, dict]) -> int:
    browser = {
        c: d for c, d in conns.items()
        if (ua := d.get("detail", {}).get("user_agent", "")) and "curl" not in ua.lower()
    }
    if not browser:
        print("Браузерных соединений в логе нет.", file=sys.stderr)
        return 1

    ja3s = [d["ja3"] for d in browser.values() if "ja3" in d]
    ja4s = [d["ja4"] for d in browser.values() if "ja4" in d]

    print(f"Браузерных соединений: {len(browser)}")
    ua = next(iter(browser.values())).get("detail", {}).get("user_agent", "?")
    print(f"User-Agent: {ua}\n")

    print(f"Уникальных JA3: {len(set(ja3s))} из {len(ja3s)}")
    for h, n in Counter(ja3s).most_common():
        print(f"   {h}  x{n}")
    print(f"\nУникальных JA4: {len(set(ja4s))} из {len(ja4s)}")
    for h, n in Counter(ja4s).most_common():
        print(f"   {h}  x{n}")

    ok = len(set(ja3s)) > 1 and len(set(ja4s)) == 1
    print()
    if ok:
        print("OK: JA3 нестабилен, JA4 стабилен - перемешивание расширений подтверждено.")
    elif len(set(ja4s)) > 1:
        print("ВНИМАНИЕ: JA4 нестабилен. Смешаны разные клиенты или версии.")
    else:
        print("ВНИМАНИЕ: JA3 стабилен. Мало сэмплов, либо соединение переиспользовалось.")

    akamai = Counter()
    for d in browser.values():
        fp = akamai_fingerprint(d.get("detail", {}))
        if fp:
            akamai[fp] += 1
    if akamai:
        print("\nAkamai HTTP/2:")
        for fp, n in akamai.most_common():
            print(f"   {fp}  x{n}")

    return 0 if ok else 2


def akamai_fingerprint(detail: dict) -> str | None:
    """SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER.

    Две ловушки, на которых сыпались другие реализации:
    вес PRIORITY на проводе на единицу меньше настоящего (RFC 7540), а пустой
    WINDOW_UPDATE сериализуется как "00", а не "0".
    """
    frames = detail.get("metadata", {}).get("HTTP2Frames") or {}
    settings = frames.get("Settings")
    if not settings:
        return None

    s = ";".join(f"{x['Id']}:{x['Val']}" for x in settings)
    wu = frames.get("WindowUpdateIncrement") or 0
    wu_s = f"{wu:02d}"

    prio = frames.get("Priorities") or []
    p_s = ",".join(
        f"{p['StreamId']}:{int(p['Exclusive'])}:{p['StreamDep']}:{p['Weight'] + 1}"
        for p in prio
    ) or "0"

    pseudo = ",".join(
        h["Name"][1] for h in (frames.get("Headers") or []) if h["Name"].startswith(":")
    )
    return f"{s}|{wu_s}|{p_s}|{pseudo}"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 64
    log = Path(sys.argv[1])
    want = sys.argv[sys.argv.index("--path") + 1] if "--path" in sys.argv else ""
    conns = parse(log, want)

    if "--out" in sys.argv:
        out = Path(sys.argv[sys.argv.index("--out") + 1])
        out.mkdir(parents=True, exist_ok=True)
        n = 0
        for d in conns.values():
            ua = d.get("detail", {}).get("user_agent", "")
            if not ua or "curl" in ua.lower():
                continue
            n += 1
            # строки ja3/ja4 приходят отдельными строками лога, а не внутри detail
            payload = dict(d["detail"], _ja3_hash=d.get("ja3"), _ja4=d.get("ja4"))
            (out / f"sample-{n:02d}.json").write_text(
                json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        print(f"Сохранено сэмплов: {n} -> {out}\n")

    return summarize(conns)


if __name__ == "__main__":
    sys.exit(main())
