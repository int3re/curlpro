"""Transcribes browser profiles from 0x676e67/wreq-util into curlPro profiles.

wreq-util describes every browser version as a tuple of BoringSSL options
(a TLS option set, a curve list, a signature-algorithm list), an HTTP/2 option
set, a header initializer and, per platform, a User-Agent and a brand list.
Versions are declared with ``mod_generator!`` and inherit each other's TLS and
HTTP/2 through ``vNNN::build_emulation``. There is no ClientHello, no HTTP/2
frame capture and no fingerprint hash in it: the data is a transcription of
what its author believes each version sends.

This script does not turn those options into a ClientHello of its own. It
reads wreq-util's own equivalence claims — "version N carries the same TLS and
HTTP/2 tuple as version M" — and, wherever M is a version this project has
captured, writes N as a delta on that captured profile: the captured
ClientHello, HTTP/2 frames and header sets, wreq-util's User-Agent, brand list
and accept-language, and a ``source`` block that says exactly that. Versions
whose tuple matches nothing captured are left out and listed, except the few
in CONSTRUCTED, where the difference is one HTTP/2 setting. Profiles that
already exist are never touched.

Usage:
    python scripts/transcribe-wreq.py --src DIR --sha COMMIT [--write]
    python scripts/gen-identities.py        # afterwards: the identity pools
                                            # live on some transcribed profiles

DIR holds the raw files of src/emulate/profile/ from wreq-util at COMMIT,
named chrome.rs, chrome_tls.rs, firefox.rs, ... (slashes as underscores).
Without --write the plan is printed and nothing is written.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PROFILES = REPO / "profiles"
SOURCE = "github.com/0x676e67/wreq-util"

# ---------------------------------------------------------------------------
# Parsing wreq-util's Rust
# ---------------------------------------------------------------------------

BLOCK = re.compile(r"mod_generator!\(\s*(.*?)\n\);", re.S)


def parse_blocks(text: str) -> list[dict]:
    """Every mod_generator! block as {name, tls, http2, parent, header, platforms}."""
    out = []
    for m in BLOCK.finditer(text):
        lines = [ln.strip() for ln in m.group(1).split("\n") if ln.strip()]
        rec = {"name": lines[0].rstrip(","), "tls": None, "http2": None, "parent": None,
               "header": None, "platforms": []}
        if "::build_emulation" in lines[1]:
            rec["parent"] = lines[1].split("::")[0]
            rec["header"] = lines[2].rstrip(",")
            tail = "\n".join(lines[3:])
        else:
            joined, i = lines[1], 2
            while not re.search(r"\),?$", joined):
                joined += " " + lines[i]
                i += 1
            rec["tls"] = tuple(a.strip() for a in re.match(r"tls_options!\((.*)\),?$", joined).group(1).split(","))
            rec["http2"] = re.match(r"http2_options!\((.*)\),?$", lines[i]).group(1).strip() or "()"
            rec["header"] = lines[i + 1].rstrip(",")
            tail = "\n".join(lines[i + 2:])
        for pm in re.finditer(r"\(\s*(MacOS|Linux|Windows|Android|IOS)\s*,\s*(?:r#\"(.*?)\"#\s*,\s*)?\"(.*?)\"\s*\)", tail, re.S):
            rec["platforms"].append({"os": pm.group(1), "sec_ch_ua": pm.group(2), "ua": pm.group(3)})
        if not rec["platforms"]:
            um = re.search(r"^\"(.*)\"$", tail.strip(), re.S)
            if um:
                rec["platforms"].append({"os": "*", "sec_ch_ua": None, "ua": um.group(1)})
        out.append(rec)
    return out


def resolve(blocks: list[dict]) -> dict[str, dict]:
    by = {b["name"]: b for b in blocks}
    for b in blocks:
        p = b
        while p["parent"]:
            p = by[p["parent"]]
        b["tls"], b["http2"], b["root"] = p["tls"], p["http2"], p["name"]
    return by


FAMILY_FILES = {"chrome": "chrome.rs", "firefox": "firefox.rs", "safari": "safari.rs", "opera": "opera.rs"}


def load(src: Path) -> dict[str, dict[str, dict]]:
    return {fam: resolve(parse_blocks((src / f).read_text(encoding="utf-8"))) for fam, f in FAMILY_FILES.items()}


def our_name(fam: str, name: str) -> tuple[str, str, str]:
    """(family, version, variant) in our naming; variant "", "private", "android", "ios", "ipados"."""
    if fam == "chrome":
        return ("edge", name[4:], "") if name.startswith("edge") else ("chrome", name[1:], "")
    if fam == "firefox":
        m = re.match(r"ff(?:_(private|android))?_?(\d+)", name)
        return "firefox", m.group(2), m.group(1) or ""
    if fam == "safari":
        m = re.match(r"safari(?:_(ios|ipad))?_?([\d_]+)", name)
        return "safari", m.group(2).replace("_", "."), {"ios": "ios", "ipad": "ipados", None: ""}[m.group(1)]
    if fam == "opera":
        return "opera", name[5:], ""
    raise ValueError(name)


# ---------------------------------------------------------------------------
# What we have, and what wreq-util says about it
# ---------------------------------------------------------------------------

def vkey(v: str) -> tuple:
    """A version as a tuple with trailing zeros dropped: our "safari-18.0" and
    wreq-util's "safari18" are one version, as are "17" and "17.0"."""
    parts = [int(x) for x in v.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def variant_class(variant: str) -> str:
    """iPadOS Safari stands on the captured iOS one: one WebKit, one OS line."""
    return "ios" if variant in ("ios", "ipados") else variant


def profile_family_version(name: str) -> tuple[str, str, str]:
    """(family, version, os) of one of our profile names."""
    fam, rest = name.split("-", 1)
    ver, os_ = rest.rsplit("-", 1)
    return fam, ver, os_


def load_profile(name: str) -> dict:
    return json.loads((PROFILES / f"{name}.json").read_text(encoding="utf-8"))


def resolved(name: str, key: str):
    """A section of a profile as the chain resolves it (delta profiles omit it)."""
    seen = set()
    while name and name not in seen:
        seen.add(name)
        d = load_profile(name)
        if key in d and d[key]:
            return d[key]
        name = d.get("based_on")
    return None


# wreq-util has no entry for these captured versions; their tuple is stated
# here so they can serve as a base. Each is justified in the note it carries.
ASSUMED_TUPLE = {
    # Safari 18.4 (curl-impersonate capture): SETTINGS 2:0,3:100,4:2097152,9:1 and
    # window 10420225 — wreq-util's http2_options!(6) exactly; the sigalgs are
    # the ten of SIGALGS_LIST_2 (inherited from the captured 18.0, which already
    # lacks ecdsa_sha1). wreq-util's 18.5 and 26.1–26.4 point at this tuple.
    "safari-18.4-macos": (("2", "CIPHER_LIST_2", "SIGALGS_LIST_2"), "6"),
    # safari-17-ios is the curl-impersonate capture safari_17.2_iOS: 21 ciphers,
    # SETTINGS 2:0,4:2097152,3:100, window 10485760 — wreq-util's tuple for its
    # own "safari_ios_17_2", which the name "17" hides from the version match.
    "safari-17-ios": (("1", "CIPHER_LIST_2"), "2"),
}

# wreq-util versions that are one of our profiles under another name.
SAME_AS_OURS = {("safari", (17, 2), "ios")}

# Versions whose tuple matches nothing captured but differ from a captured
# version by one HTTP/2 setting: (base, http2 settings override, note).
CONSTRUCTED = {
    # wreq-util's http2_options!(4): push not disabled, window 4194304 — the
    # captured Safari 17.0 (http2_options!(5)) minus SETTINGS_ENABLE_PUSH.
    ("safari", "15.6.1", ""): ("safari-17-macos", "drop_push", "wreq-util declares Safari 15.6.1, 16, 16.5 and 17.4.1 to share one TLS tuple with 17.0 and an HTTP/2 tuple that differs from 17.0's only by not sending SETTINGS_ENABLE_PUSH=0; taken as claimed"),
    ("safari", "16", ""): ("safari-17-macos", "drop_push", None),
    ("safari", "16.5", ""): ("safari-17-macos", "drop_push", None),
    ("safari", "17.4.1", ""): ("safari-17-macos", "drop_push", None),
    # http2_options!(1) on iOS: the captured iOS 17.2 (http2_options!(2)) minus the same setting.
    ("safari", "16.5", "ios"): ("safari-17-ios", "drop_push", "wreq-util declares iOS 16.5 to share the TLS tuple of iOS 17.2 and an HTTP/2 tuple that differs only by not sending SETTINGS_ENABLE_PUSH=0; taken as claimed"),
}

# Opera: wreq-util gives every Opera one tuple — permuted, ECH GREASE,
# X25519MLKEM768, the OLD ALPS codepoint — which is its Chrome 131 tuple.
OPERA_BASE = "chrome-131-macos"

SKIP_REASONS = {
    ("chrome", "105"): "wreq-util's tuple 2 (ECH GREASE without extension permutation) matches no captured version, and the curl-impersonate captures of Chrome 107 and 116 carry no ECH GREASE at all",
    ("firefox", "109"): "wreq-util's http2_options!(2) sends six PRIORITY frames on stream ids 3–13, which the profile schema does not express",
    ("firefox", "117"): "same tuple as Firefox 109: PRIORITY frames the schema does not express",
    ("firefox", "128"): "wreq-util's tuple 3 (15 ciphers, no session ticket, no psk_dhe_ke) matches no captured version",
}

DESKTOP = {"chrome": ["windows", "macos", "linux"], "edge": ["windows", "macos"],
           "firefox": ["windows", "macos", "linux"], "opera": ["windows", "macos"]}
OS_NAME = {"Windows": "windows", "MacOS": "macos", "Linux": "linux", "Android": "android", "IOS": "ios"}
PLATFORM_HINT = {"windows": '"Windows"', "macos": '"macOS"', "linux": '"Linux"'}

CHROME_UA = {
    "windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36",
    "macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36",
    "linux": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36",
}
FIREFOX_UA = {
    "windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0",
    "macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{v}.0) Gecko/20100101 Firefox/{v}.0",
    "linux": "Mozilla/5.0 (X11; Linux x86_64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0",
}
OS_TOKEN = {"windows": "Windows NT 10.0; Win64; x64", "macos": "Macintosh; Intel Mac OS X 10", "linux": "X11; "}


def user_agent(fam: str, ver: str, os_: str, wreq_ua: str | None) -> tuple[str, bool]:
    """wreq-util's User-Agent when it is well-formed, else the family's known
    shape. Returns (ua, synthesized)."""
    if fam == "safari":
        # One string per version, kept when it names this version and this
        # platform: wreq-util's 17.2.1 carries "Version/16.0" and its
        # "safari_ios_17_4_1" an iPad string.
        shown = ver if "." in ver else ver + ".0"
        token = {"macos": "Macintosh; Intel Mac OS X 10_15_7", "ios": "iPhone; CPU iPhone OS ", "ipados": "iPad; CPU OS "}[os_]
        if wreq_ua and f"Version/{shown} " in wreq_ua and token in wreq_ua:
            return wreq_ua, False
        under = shown.replace(".", "_")
        if os_ == "macos":
            return f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{shown} Safari/605.1.15", True
        device = "iPhone; CPU iPhone OS" if os_ == "ios" else "iPad; CPU OS"
        return f"Mozilla/5.0 ({device} {under} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{shown} Mobile/15E148 Safari/604.1", True
    ok = bool(wreq_ua) and OS_TOKEN[os_] in wreq_ua and "; U;" not in wreq_ua
    if fam in ("chrome", "edge"):
        # Every version transcribed is past the User-Agent reduction, so the
        # string is the family's fixed shape with the major version — the
        # same shape every captured profile of the family carries. wreq-util's
        # own strings are not used: some are malformed ("X11; U; Windows"),
        # some carry a full Edg/ build number the reduced UA does not.
        ua = CHROME_UA[os_].format(v=ver)
        return (ua + f" Edg/{ver}.0.0.0", True) if fam == "edge" else (ua, True)
    if fam == "opera":
        # wreq-util's string carries the Chromium version the Opera build sits
        # on, which nothing else here knows; kept when well-formed.
        ok = ok and re.search(rf"Chrome/\d+\.0\.0\.0 Safari/537\.36 OPR/{ver}\.0\.0\.0$", wreq_ua or "") is not None
        return (wreq_ua, False) if ok else ("", False)  # no usable UA: the caller skips
    if fam == "firefox":
        ok = ok and re.search(rf"rv:{ver}\.0\) Gecko/20100101 Firefox/{ver}\.0$", wreq_ua or "") is not None
        return (wreq_ua, False) if ok else (FIREFOX_UA[os_].format(v=ver), True)
    return wreq_ua or "", False


# ---------------------------------------------------------------------------
# Choosing the captured base for a wreq-util version
# ---------------------------------------------------------------------------

# A tuple that matches no captured version but is, by measurement, the same
# hello as another tuple's: (tuple) -> (tuple it stands on, why).
TUPLE_ALIAS = {
    # wreq-util's Safari 18.2/18.3/18.3.1: tls_options!(2) = 18.0's cipher
    # list with SIGALGS_LIST_2 (ecdsa_sha1 dropped). The captured Safari 18.0
    # already sends exactly that ten-entry list, so the two tuples are one hello.
    (("2", "CIPHER_LIST_2", "SIGALGS_LIST_2"), "3"):
        ((("1", "CIPHER_LIST_2"), "3"),
         "wreq-util declares these to differ from 18.0 by dropping ecdsa_sha1 from the signature "
         "algorithms; the captured 18.0 already sends the list without it, so the hello is 18.0's"),
}


def measured_profiles(data: dict) -> dict[str, tuple]:
    """Our captured profiles (no source block) with the wreq-util tuple of
    their version, where wreq-util has an entry for it or ASSUMED_TUPLE does."""
    tuples: dict[tuple[str, tuple, str], tuple] = {}
    for fam, mods in data.items():
        for name, b in mods.items():
            ofam, ver, variant = our_name(fam, name)
            tuples[(ofam, vkey(ver), variant_class(variant))] = (b["tls"], b["http2"])
    out = {}
    for p in sorted(PROFILES.glob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        # A capture whose SETTINGS alone are transcribed (source.covers) is a
        # capture: it stays a base to stand on.
        if d.get("source") and not d["source"].get("covers"):
            continue
        fam, ver, os_ = profile_family_version(p.stem)
        if fam not in ("chrome", "edge", "firefox", "safari"):
            continue
        variant = os_ if fam == "safari" and os_ in ("ios", "ipados") else ""
        t = ASSUMED_TUPLE.get(p.stem) or tuples.get((fam, vkey(ver), variant_class(variant)))
        if t:
            out[p.stem] = t
    return out


OS_PREF = ["macos", "windows", "linux", "android", "ios", "ipados"]


def pick_base(fam: str, ver: str, variant: str, tup: tuple, os_: str, measured: dict[str, tuple]) -> str | None:
    """The nearest captured version of the same family (Chrome for Edge) with
    the same tuple; among its OS variants the same OS, else macOS first."""
    fams = {"chrome": ("chrome", "edge"), "edge": ("chrome", "edge"), "firefox": ("firefox",), "safari": ("safari",)}[fam]
    want = TUPLE_ALIAS.get(tup, (tup, None))[0]
    cands = []
    for name, t in measured.items():
        bf, bv, bos = profile_family_version(name)
        bvariant = bos if bf == "safari" and bos in ("ios", "ipados") else ""
        if bf in fams and t == want and variant_class(bvariant) == variant_class(variant):
            cands.append((abs(vkey(bv)[0] - vkey(ver)[0]), 0 if vkey(bv) <= vkey(ver) else 1,
                          0 if bos == os_ else OS_PREF.index(bos) + 1, name))
    if not cands:
        return None
    return sorted(cands)[0][3]


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def header_order(base: str, ua_key: str, values: dict[str, str]) -> list[dict]:
    order = resolved(base, "headers")["order"]
    out = []
    for h in order:
        h = dict(h)
        k = h["key"].lower()
        if k in values:
            h["value"] = values[k]
        out.append(h)
    return out


def write_profile(name: str, base: str, fam: str, ver: str, os_: str, ua: str, sec_ch_ua: str | None,
                  accept_language: str, http2_override: dict | None, note: str, sha: str, today: str) -> None:
    values = {"accept-language": accept_language}
    if sec_ch_ua:
        values["sec-ch-ua"] = sec_ch_ua
        values["sec-ch-ua-mobile"] = "?0"
        values["sec-ch-ua-platform"] = PLATFORM_HINT[os_]
    prof = {
        "name": name,
        "based_on": base,
        "source": {
            "kind": "transcribed",
            "from": SOURCE,
            "ref": sha,
            "path": f"src/emulate/profile/{ {'edge': 'chrome'}.get(fam, fam) }.rs",
            "date": today,
            "note": note,
        },
        "headers": {"user_agent": ua, "order": header_order(base, "user-agent", values)},
    }
    if http2_override:
        prof["http2"] = http2_override
    (PROFILES / f"{name}.json").write_text(json.dumps(prof, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


def fixed_brands(fam: str, ver: str, ua: str | None, sec: str) -> str:
    """wreq-util's sec-ch-ua, or the right one where it is wrong."""
    from chromium_brands import sec_ch_ua
    m = re.search(r"Chrome/(\d+)\.", ua or "")
    chromium = int(m.group(1)) if m else int(ver.split(".")[0])
    if chromium >= 105:
        product = {"chrome": "Google Chrome", "edge": "Microsoft Edge", "opera": "Opera"}[fam]
        return sec_ch_ua(chromium, product, int(ver.split(".")[0]))
    twin = f"{fam}-{int(ver.split('.')[0])}-windows"
    if (PROFILES / f"{twin}.json").exists():
        for h in (resolved(twin, "headers") or {}).get("order", []):
            if h["key"].lower() == "sec-ch-ua" and h.get("value"):
                return h["value"]
    return sec


def plan(data: dict, sha: str) -> tuple[list[dict], list[tuple[str, str]]]:
    measured = measured_profiles(data)
    # Existing profiles by (family, normalised version, os): "safari-18.0-macos"
    # already is wreq-util's "safari18", "safari-17-ios" its "safari_ios_17_2"'s
    # sibling only by tuple, not by name — names are matched, tuples decide bases.
    have = set(SAME_AS_OURS)
    for p in PROFILES.glob("*.json"):
        f, v, o = profile_family_version(p.stem)
        have.add((f, vkey(v), o))
    jobs, skipped = [], []
    today = dt.date.today().isoformat()
    for fam, mods in data.items():
        for mname, b in mods.items():
            ofam, ver, variant = our_name(fam, mname)
            tup = (b["tls"], b["http2"])
            if variant in ("private", "android"):
                skipped.append((f"{ofam}-{ver}/{variant}", "no captured Firefox of that kind to stand on; wreq-util's tuple matches nothing captured"))
                continue
            if (ofam, ver) in SKIP_REASONS:
                skipped.append((f"{ofam}-{ver}", SKIP_REASONS[(ofam, ver)]))
                continue
            targets = []
            if ofam == "safari":
                targets = [variant or "macos"]
            else:
                targets = DESKTOP[ofam]
            for os_ in targets:
                name = f"{ofam}-{ver}-{os_}"
                if (ofam, vkey(ver), os_) in have:
                    continue
                plat = next((p for p in b["platforms"] if OS_NAME.get(p["os"]) == os_), None) \
                    or next((p for p in b["platforms"] if p["os"] == "*"), None)
                if ofam != "safari" and plat is None and ofam != "opera":
                    plat = b["platforms"][0] if b["platforms"] else None
                wua = plat["ua"] if plat else None
                sec = plat["sec_ch_ua"] if plat else None
                # wreq-util copies brand lists between versions and leaves some
                # unterminated; from Chromium 105 the list is computed as the
                # browser computes it (chromium_brands.py), and the note below
                # says so. Before 105 the captured twin of the version decides.
                if sec and ofam in ("chrome", "edge", "opera"):
                    sec = fixed_brands(ofam, ver, wua, sec)
                base, http2, cnote = None, None, None
                constructed = CONSTRUCTED.get((ofam, ver, variant))
                if constructed:
                    base, how, cnote = constructed
                    settings = [s for s in resolved(base, "http2")["settings"] if not (how == "drop_push" and s["id"] == 2)]
                    http2 = {"settings": settings}
                elif ofam == "opera":
                    base = OPERA_BASE
                else:
                    base = pick_base(ofam, ver, variant, tup, os_, measured)
                if base is None:
                    skipped.append((name, f"wreq-util's tuple {tup} matches no captured version"))
                    continue
                ua, synthesized = user_agent(ofam, ver, os_, wua)
                if not ua:
                    skipped.append((name, "no usable User-Agent in wreq-util"))
                    continue
                lang = "en-US,en;q=0.5" if ofam == "firefox" else "en-US,en;q=0.9"
                note = (f"ClientHello, HTTP/2 frames and header sets are those captured for {base}; "
                        f"wreq-util declares {ofam} {ver}{' ' + variant if variant else ''} to use the same TLS and HTTP/2 "
                        f"configuration ({mname}: tls_options!{tup[0]}, http2_options!({tup[1]})). "
                        + ("The User-Agent is the family's reduced shape with this version" if synthesized
                           else "The User-Agent is wreq-util's")
                        + f"; {'sec-ch-ua and accept-language are' if sec else 'accept-language is'} wreq-util's. "
                        f"Nothing was seen on the wire for this version here.")
                if cnote:
                    note += " " + cnote
                if tup in TUPLE_ALIAS:
                    note += " " + TUPLE_ALIAS[tup][1] + "."
                if ofam == "opera":
                    note += (" wreq-util gives every Opera version one tuple — the ALPS codepoint of Chromium 131 — "
                             "although the User-Agent names Chromium up to 147; taken as claimed.")
                if ofam == "firefox" and vkey(ver) >= (136,):
                    note += (" wreq-util declares Firefox 136 to 151 equal to 135; the Firefox 155 and 156 captured "
                             "here differ (15 ciphers, no FFDHE groups), so where the change happened is unknown.")
                if ofam == "safari" and vkey(ver) >= (26, 1) and variant == "":
                    note += (" wreq-util declares Safari 26.1 to 26.4 equal to 18.5 — without the X25519MLKEM768 "
                             "key share that the captured 26.0 and 26.0.1 carry; taken as claimed.")
                jobs.append({"name": name, "base": base, "fam": ofam, "ver": ver, "os": os_, "ua": ua, "sec": sec,
                             "lang": lang, "http2": http2, "note": note, "sha": sha, "today": today, "tuple": tup})
    return jobs, skipped


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    data = load(Path(args.src))
    jobs, skipped = plan(data, args.sha)
    for j in jobs:
        print(f"  {j['name']:26} <- {j['base']:22} {'h2 override' if j['http2'] else '':12} UA ...{j['ua'][-38:]}")
    print(f"\n{len(jobs)} profiles to write")
    for name, why in skipped:
        print(f"  skip {name:26} {why}")
    if args.write:
        for j in jobs:
            write_profile(j["name"], j["base"], j["fam"], j["ver"], j["os"], j["ua"], j["sec"], j["lang"],
                          j["http2"], j["note"], j["sha"], j["today"])
        print(f"\nwritten: {len(jobs)}")


if __name__ == "__main__":
    main()
