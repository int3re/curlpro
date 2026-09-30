r"""Writes a profile's resources section from hcapture -subres captures.

    python scripts/gen-resources.py PROFILE H2.json H1.json
    python scripts/gen-resources.py            # every pair in capture/subres
    python scripts/gen-resources.py --check    # exits 1 when a profile drifted

PROFILE is the profile file the section goes into (a delta: the section is
inherited down its chain). H2.json and H1.json are the stand's captures of
the same browser over HTTP/2 and over HTTP/1.1 (hcapture -subres, and
hcapture -subres -h1). Every value in the section is read off the captures:

- the kinds: sec-fetch-dest, sec-fetch-mode, Accept, priority and
  sec-purpose of each resource on the stand's page, by its path, and
  Accept-Encoding where it differs from the navigation's;
- the orders: the header sequences of every request of a group — no-cors
  resources, CORS resources, a frame's document — merged into one order
  each (a topological sort of what each request puts before what); a kind
  whose sequence contradicts its group gets an order of its own;
- storage_access: the value of sec-fetch-storage-access, and cors_origin:
  whether a same-origin CORS resource carried Origin.

The fetch order is carried over from the profile's chain with
sec-fetch-storage-access inserted where the credentialed cross-site fetches
put it. When capture/cache holds the same browser's hcapture -cache run, every
order of the profile — navigation, fetch, client hints, the resources, over
both transports — gains the cache's slots where the browser put them:
if-none-match and if-modified-since on a revalidation, and cache-control on a
reload where the browser sends one. The file is rewritten in the corpus
format (two spaces, LF).
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The stand's page (cmd/hcapture -subres): path -> kind.
KINDS = {
    "/sub/style.css": "style",
    "/sub/cs-style.css": "style",
    "/sub/preload.css": "style-preload",
    "/sub/head.js": "script",
    "/sub/cs.js": "script-body",
    "/sub/async.js": "script-async",
    "/sub/dyn.js": "script-async",
    "/sub/dyn-same.js": "script-async",
    "/sub/defer.js": "script-defer",
    "/sub/preload.js": "script-preload",
    "/sub/mod.js": "module",
    "/sub/modpre.js": "module-preload",
    "/sub/img.png": "image",
    "/sub/ss-img.png": "image",
    "/sub/cs-img.png": "image",
    "/sub/js-img.png": "image",
    "/sub/d-img.png": "image",
    "/sub/cs-img-cors.png": "image",
    "/sub/d-img-cred.png": "image",
    "/sub/d-img-anon.png": "image",
    "/sub/bg.png": "image-css",
    "/sub/favicon.ico": "icon",
    "/favicon.ico": "icon",
    "/sub/css-font.woff2": "font",
    "/sub/preload.woff2": "font-preload",
    "/sub/frame.html": "iframe",
    "/sub/frame2.html": "iframe",
    "/sub/prefetch.js": "prefetch",
    "/sub/beacon": "beacon",
    "/beacon-cs": "beacon",
}
# Kinds that are CORS without a crossorigin attribute.
ALWAYS_CORS = {"font", "font-preload", "module", "module-preload"}


def load(path):
    out = []
    for r in json.loads(Path(path).read_text(encoding="utf-8")):
        names, values = [], {}
        for h in r["headers"]:
            k, _, v = h.partition(": ")
            if k.startswith(":"):
                continue
            names.append(k)
            values.setdefault(k.lower(), v)
        out.append({"path": r["path"], "names": names, "h": values, "method": r["method"]})
    return out


def group_of(rec):
    dest, mode = rec["h"].get("sec-fetch-dest"), rec["h"].get("sec-fetch-mode")
    if dest == "iframe":
        return "navigate"
    if mode == "cors" and dest != "empty":
        return "cors"
    if mode == "no-cors":
        return "no-cors"
    return None  # fetch, documents


def merge(seqs):
    """One order consistent with every sequence, or None on a contradiction.
    Ties go to the name seen first."""
    first = {}
    for s in seqs:
        for n in s:
            first.setdefault(n, len(first))
    after = {n: set() for n in first}
    incoming = {n: 0 for n in first}
    for s in seqs:
        for i, a in enumerate(s):
            for b in s[i + 1:]:
                if b not in after[a]:
                    after[a].add(b)
                    incoming[b] += 1
    out = []
    ready = sorted((n for n in first if incoming[n] == 0), key=first.get)
    while ready:
        n = ready.pop(0)
        out.append(n)
        for b in after[n]:
            incoming[b] -= 1
            if incoming[b] == 0:
                ready.append(b)
        ready.sort(key=first.get)
    return out if len(out) == len(first) else None


def orders(recs):
    """The group orders, and the kinds that need one of their own."""
    groups, own = {}, {}
    by_group = {}
    for r in recs:
        g, kind = group_of(r), KINDS.get(r["path"])
        if g and kind:
            by_group.setdefault(g, []).append((kind, r["names"]))
    for g, items in by_group.items():
        seqs = []
        for kind, names in items:
            if merge(seqs + [names]) is None:
                own.setdefault(kind, []).append(names)
                continue
            seqs.append(names)
        groups[g] = merge(seqs)
    for kind, seqs in own.items():
        m = merge(seqs)
        if m is None:
            raise SystemExit(f"{kind}: its own requests contradict each other")
        groups[kind] = m
    return groups, set(own)


def kinds(recs, nav):
    out = {}
    for r in recs:
        kind = KINDS.get(r["path"])
        if not kind:
            continue
        h = r["h"]
        k = {"dest": h["sec-fetch-dest"]}
        if kind in ALWAYS_CORS:
            k["mode"] = "cors"
        elif kind == "iframe":
            k["mode"] = "navigate"
        accept = h.get("accept", "")
        if accept and accept != nav["accept"]:
            k["accept"] = accept
        ae = h.get("accept-encoding", "")
        if ae and ae != nav["accept-encoding"]:
            k["accept_encoding"] = ae
        if h.get("priority"):
            k["priority"] = h["priority"]
        if h.get("sec-purpose"):
            k["purpose"] = h["sec-purpose"]
        if kind in out and out[kind] != k:
            raise SystemExit(f"{kind}: {r['path']} says {k}, another request {out[kind]}")
        out[kind] = k
    return out


def chain_fetch(profile):
    """The fetch section the profile inherits, nearest first."""
    p = profile
    while True:
        f = p.get("fetch") or {}
        if f.get("order"):
            return f
        if not p.get("based_on"):
            raise SystemExit("no fetch section in the chain")
        p = json.loads((ROOT / "profiles" / f"{p['based_on']}.json").read_text(encoding="utf-8"))


def with_slot(order, seqs, slot, key=lambda n: n):
    """order with slot inserted after the name that precedes it in seqs, or
    first when nothing precedes it."""
    if any(key(n) == key(slot) for n in order):
        return order
    for s in seqs:
        names = [key(n) for n in s]
        if key(slot) not in names:
            continue
        i = names.index(key(slot))
        for prev in reversed(s[:i]):
            if key(prev) in [key(n) for n in order]:
                j = [key(n) for n in order].index(key(prev))
                return order[: j + 1] + [slot] + order[j + 1:]
        if i == 0:
            return [slot] + order
    raise SystemExit(f"no request places {slot}")


CACHE_SLOTS = ("cache-control", "if-none-match", "if-modified-since")


def cache_groups(h2, h1):
    """The revalidating requests of a -cache capture by the order they belong
    to: documents, fetches, subresources; each over HTTP/2 and HTTP/1.1."""
    def pick(recs, test):
        return [r["names"] for r in recs if ("if-none-match" in r["h"] or "if-modified-since" in r["h"]) and test(r["h"])]
    doc = lambda h: h.get("sec-fetch-dest") == "document"
    fetch = lambda h: h.get("sec-fetch-dest") == "empty" and h.get("sec-fetch-mode") == "cors"
    sub = lambda h: h.get("sec-fetch-dest") not in ("document", "empty", "iframe", None)
    return {name: ([[n.lower() for n in s] for s in pick(h2, test)], pick(h1, test))
            for name, test in (("navigate", doc), ("fetch", fetch), ("resource", sub))}


def pair_order(*seq_lists):
    """The order the browser writes the two validators in, from any request
    that carried both: ("if-none-match", "if-modified-since") or the reverse."""
    for seqs in seq_lists:
        for s in seqs:
            low = [n.lower() for n in s]
            if "if-none-match" in low and "if-modified-since" in low:
                return tuple(sorted(("if-none-match", "if-modified-since"), key=low.index))
    return ("if-none-match", "if-modified-since")


def slotted(order, seqs, h1=False, pair=("if-none-match", "if-modified-since")):
    """order with every cache slot the sequences carry, in the browser's places.
    Where a group saw one validator only, the other goes beside it in the
    browser's pair order. Order entries are names, or header pairs whose key
    is the name."""
    pairs = order and isinstance(order[0], dict)
    names = [h["key"] for h in order] if pairs else list(order)
    key = str.lower if h1 else (lambda n: n)
    seen = {key(n) for s in seqs for n in s}
    for slot in CACHE_SLOTS:
        if key(slot) not in seen:
            continue
        spelled = next(n for s in seqs for n in s if key(n) == key(slot)) if h1 else slot
        names = with_slot(names, seqs, spelled, key=key)
    low = [n.lower() for n in names]
    first, second = pair
    spell = (lambda n: "-".join(w.capitalize() for w in n.split("-"))) if h1 else (lambda n: n)
    if first in low and second not in low:
        names.insert(low.index(first) + 1, spell(second))
    elif second in low and first not in low:
        names.insert(low.index(second), spell(first))
    if not pairs:
        return names
    have = {h["key"]: h for h in order}
    return [have.get(n, {"key": n, "value": ""}) for n in names]


def chain_section(profile, section, field):
    """A field of a section as the profile inherits it, nearest first."""
    p = profile
    while True:
        v = (p.get(section) or {}).get(field)
        if v:
            return v
        if not p.get("based_on"):
            return None
        p = json.loads((ROOT / "profiles" / f"{p['based_on']}.json").read_text(encoding="utf-8"))


# The captures in the repository and the profiles they write.
# The profile, its -subres captures, its -cache captures. The cache run of
# Chrome was taken after the stand's Chrome updated itself to 154; the network
# stack's places for the validators are older than both versions.
PAIRS = [
    ("chrome-153-windows", "chrome-153", "chrome-154"),
    ("firefox-156-windows", "firefox-156", "firefox-156"),
]

# The -cache page's resources, by path, for the revalidation priorities.
CACHE_KINDS = {"/c/revalidate.js": "script", "/c/nostore.js": "script", "/c/stale.png": "image",
               "/c/heuristic.png": "image", "/c/immutable.png": "image", "/c/fresh.css": "style"}


def revalidation_priorities(recs, ks):
    """A kind whose conditional request carries another priority than its
    first request — Firefox drops the incremental flag from an image's."""
    for r in recs:
        kind = CACHE_KINDS.get(r["path"])
        if not kind or kind not in ks or not ("if-none-match" in r["h"] or "if-modified-since" in r["h"]):
            continue
        p = r["h"].get("priority", "")
        if p and p != ks[kind].get("priority", ""):
            ks[kind]["revalidate_priority"] = p


def descendants_slotted(name, nav2, f2, nav1):
    """Every profile below name, other than a derived preset, that lists an
    order of its own: the file with the cache slots put into those orders."""
    files = {}
    for f in sorted((ROOT / "profiles").glob("*.json")):
        files[json.loads(f.read_text(encoding="utf-8"))["name"]] = f
    parents = {n: json.loads(f.read_text(encoding="utf-8")).get("based_on") for n, f in files.items()}

    def below(n):
        n = parents.get(n)
        while n:
            if n == name:
                return True
            n = parents.get(n)
        return False

    pair = pair_order(nav2, f2)
    for n, f in files.items():
        if not below(n):
            continue
        d = json.loads(f.read_text(encoding="utf-8"))
        if (d.get("source") or {}).get("kind") == "derived":
            continue
        before = json.dumps(d, indent=2, ensure_ascii=False) + "\n"
        if (d.get("headers") or {}).get("order"):
            d["headers"]["order"] = slotted(d["headers"]["order"], nav2, pair=pair)
        if (d.get("http1") or {}).get("order"):
            d["http1"]["order"] = slotted(d["http1"]["order"], nav1, h1=True, pair=pair)
        for field, seqs in (("order", nav2), ("fetch_order", f2)):
            if (d.get("client_hints") or {}).get(field):
                d["client_hints"][field] = slotted(d["client_hints"][field], seqs, pair=pair)
        after = json.dumps(d, indent=2, ensure_ascii=False) + "\n"
        if after != before:
            yield f, after


def observed_first(observed, base, key=str.lower):
    """The order a browser was seen sending, with the names only the base knows
    placed after their nearest preceding base neighbour: where the two
    disagree, the observation wins."""
    out = list(observed)
    have = {key(n) for n in out}
    for i, name in enumerate(base):
        if key(name) in have:
            continue
        at = 0
        for prev in reversed(base[:i]):
            if key(prev) in have:
                at = [key(n) for n in out].index(key(prev)) + 1
                break
        out.insert(at, name)
        have.add(key(name))
    return out


def main(profile_path, h2_path, h1_path, check=False, cache=None):
    path = Path(profile_path)
    profile = json.loads(path.read_text(encoding="utf-8"))
    h2, h1 = load(h2_path), load(h1_path)

    nav = next(r for r in h2 if r["path"] == "/sub/index.html")
    section = {}
    o2, own2 = orders(h2)
    o1, own1 = orders(h1)
    section["orders"] = {k: [n.lower() for n in v] for k, v in sorted(o2.items())}
    section["http1_orders"] = dict(sorted(o1.items()))
    ks = kinds(h2, nav["h"])
    for kind in sorted(own2):
        ks[kind]["order"] = kind
    for kind in sorted(own1):
        ks[kind]["http1_order"] = kind
    section["kinds"] = dict(sorted(ks.items()))
    sa = {r["h"]["sec-fetch-storage-access"] for r in h2 if "sec-fetch-storage-access" in r["h"]}
    if len(sa) != 1:
        raise SystemExit(f"sec-fetch-storage-access values: {sa}")
    section["storage_access"] = sa.pop()
    same_cors = [r for r in h2 if group_of(r) == "cors" and r["h"].get("sec-fetch-site") == "same-origin"]
    if not same_cors:
        raise SystemExit("no same-origin CORS resource on the capture")
    section["cors_origin"] = "always" if all("origin" in r["h"] for r in same_cors) else "cross-origin"

    # The fetch order gains the storage-access slot where credentialed
    # cross-site fetches put it; the rest of the fetch section is inherited.
    base = chain_fetch(profile)
    cred2 = [r["names"] for r in h2 if r["h"].get("sec-fetch-dest") == "empty"
             and r["h"].get("sec-fetch-mode") == "cors" and "sec-fetch-storage-access" in r["h"]]
    cred1 = [r["names"] for r in h1 if r["h"].get("sec-fetch-dest") == "empty"
             and r["h"].get("sec-fetch-mode") == "cors" and "sec-fetch-storage-access" in r["h"]]
    names = with_slot([h["key"] for h in base["order"]], [[n.lower() for n in s] for s in cred2],
                      "sec-fetch-storage-access")
    have = {h["key"]: h for h in base["order"]}
    fetch = dict(profile.get("fetch") or {})
    fetch["order"] = [have.get(n, {"key": n, "value": ""}) for n in names]
    fetch["http1_order"] = with_slot(list(base["http1_order"]), cred1, "Sec-Fetch-Storage-Access",
                                     key=str.lower)

    out = {}
    for k, v in profile.items():
        if k == "fetch":
            out[k] = fetch
        elif k != "resources":
            out[k] = v
    if "fetch" not in out:
        out["fetch"] = fetch
    out["resources"] = section

    # The cache's slots, where the -cache run saw the browser put them.
    if cache is not None:
        g = cache_groups(load(cache[0]), load(cache[1]))
        nav2, nav1 = g["navigate"]
        f2, f1 = g["fetch"]
        r2, r1 = g["resource"]
        pair = pair_order(nav2, r2, f2)

        def place(order, seqs, h1=False):
            return slotted(order, seqs, h1=h1, pair=pair)
        headers = dict(out.get("headers") or {})
        headers["order"] = place(chain_section(profile, "headers", "order"), nav2)
        out["headers"] = headers
        # The navigation over HTTP/1.1 as the stand saw a link navigation
        # write it (/sub/next.html) — Firefox 156 put Connection before
        # Referer and Cookie before Upgrade-Insecure-Requests, where the order
        # inherited from a Firefox 154 capture had them the other way — with
        # the names only the inherited order knows kept in their places.
        link = next((r["names"] for r in h1 if r["path"] == "/sub/next.html"), None)
        base_h1 = chain_section(profile, "http1", "order")
        if link:
            base_h1 = observed_first(link, base_h1)
        http1 = dict(out.get("http1") or {})
        http1["order"] = place(base_h1, nav1, h1=True)
        out["http1"] = http1
        revalidation_priorities(load(cache[0]), section["kinds"])
        fetch["order"] = place(fetch["order"], f2)
        fetch["http1_order"] = place(fetch["http1_order"], f1, h1=True)
        hints = chain_section(profile, "client_hints", "order")
        if hints:
            ch = dict(out.get("client_hints") or {})
            ch["order"] = place(hints, nav2)
            fetch_hints = chain_section(profile, "client_hints", "fetch_order")
            if fetch_hints:
                ch["fetch_order"] = place(fetch_hints, f2)
            out["client_hints"] = ch
        for name, order in section["orders"].items():
            section["orders"][name] = place(order, nav2 if name == "navigate" else r2)
        for name, order in section["http1_orders"].items():
            section["http1_orders"][name] = place(order, nav1 if name == "navigate" else r1, h1=True)
    text = json.dumps(out, indent=2, ensure_ascii=False) + "\n"
    ok = True
    if cache is not None:
        # A delta that re-lists an order — a captured twin on another OS, an
        # Edge, a transcribed build — would drop the slots its parent gained.
        # The derived presets are left to derive-current.py, which copies the
        # parent's order whole.
        for child_path, child_text in descendants_slotted(profile["name"], nav2, f2, nav1):
            if check:
                same = child_path.read_text(encoding="utf-8") == child_text
                ok = ok and same
                if not same:
                    print(f"{child_path.name}: DRIFTED from capture/cache")
            else:
                child_path.write_text(child_text, encoding="utf-8", newline="\n")
    if check:
        same = path.read_text(encoding="utf-8") == text
        print(f"{path.name}: {'in sync' if same else 'DRIFTED from capture/subres'}")
        return same and ok
    path.write_text(text, encoding="utf-8", newline="\n")
    print(f"{path.name}: {len(section['kinds'])} kinds, orders {sorted(section['orders'])}, "
          f"http1 {sorted(section['http1_orders'])}")
    return True


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--check"]
    check = "--check" in sys.argv
    if len(args) == 3:
        ok = main(*args, check=check)
    elif not args:
        subres, cached = ROOT / "capture" / "subres", ROOT / "capture" / "cache"
        ok = all([main(ROOT / "profiles" / f"{name}.json", subres / f"{cap}-h2.json",
                       subres / f"{cap}-h1.json", check=check,
                       cache=(cached / f"{ccap}-h2.json", cached / f"{ccap}-h1.json")
                       if (cached / f"{ccap}-h2.json").exists() else None)
                  for name, cap, ccap in PAIRS])
    else:
        raise SystemExit(__doc__)
    sys.exit(0 if ok else 1)
