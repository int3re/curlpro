"""Write a derived fetch header set into the Safari profiles.

**This is the one derived thing in the corpus.** Everything else in a profile
was seen on the wire from a real browser; this was not, and says so: each set
it writes carries ``"derived": true``, ``curlpro.capabilities()`` reports it,
and ``session.audit()`` raises a finding when such a set is used. Replace it
with a capture the day a Mac or an iPhone is at hand — that is what
``docs/CAPTURE.md`` is for, and the run is twenty minutes.

Why it exists. Eleven Safari profiles had no fetch set at all, so
``mode="fetch"`` on them was refused outright and they could not make an XHR —
and a user reported Safari passing their anti-bot roughly twice as often as
any Chrome while being unusable for exactly that reason. A derived set is
worse than a measured one and much better than nothing.

What is derived, and how confident each part is:

* **The set** — high confidence. The Fetch standard says what a ``fetch()``
  carries: ``accept: */*``, no ``upgrade-insecure-requests``, no
  ``sec-fetch-user``, ``sec-fetch-mode: cors``, ``sec-fetch-dest: empty``,
  ``Origin`` and ``Referer`` by the page. Chrome and Firefox were measured
  doing exactly that (docs/STAGE15-RESULTS.md, docs/STAGE17-RESULTS.md).
* **Fetch metadata per version** — high confidence, and the reason this is a
  generator rather than one shared block: WebKit shipped Fetch Metadata in
  Safari 16.4. The 15.x profiles carry no ``sec-fetch-*`` in their navigation
  set and must carry none in their fetch set either; inventing them would be
  a worse tell than the missing set was.
* **The order** — a guess, and the weak part. The names Safari already sends
  keep the relative order its navigation capture shows; the four new ones
  (``content-type``, ``content-length``, ``origin``, ``referer``) are inserted
  at the profile's own ``custom_anchor``, which is by definition where the
  browser's service tail begins. Order is part of the fingerprint, so this is
  precisely what a capture must correct.

Run: ``python scripts/gen-safari-fetch.py`` (``--check`` exits 1 on drift).
"""
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROFILES = ROOT / "profiles"

# The names a navigation carries and a fetch never does.
NAVIGATION_ONLY = ("upgrade-insecure-requests", "sec-fetch-user")
# The slots a fetch needs: a body's headers, and the page's two.
ADDED = ("content-type", "content-length", "origin", "referer")
# What the Fetch standard fixes for a fetch(), where the profile has the name.
FETCH_VALUES = {
    "accept": "*/*",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    # The default for a request with no page named; with one it is computed.
    "sec-fetch-site": "same-origin",
}


def load(path):
    raw = path.read_bytes()
    return json.loads(raw.decode("utf-8")), ("\r\n" if b"\r\n" in raw else "\n")


def save(path, data, nl):
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    io.open(path, "wb").write(text.replace("\n", nl).encode("utf-8"))


def resolve(profiles, name, section, key):
    """The value a profile ends up with after inheritance."""
    while name:
        got = (profiles[name].get(section) or {}).get(key)
        if got:
            return got
        name = profiles[name].get("based_on")
    return None


def fetch_order(nav, anchor):
    """The fetch set, from the navigation set: values fixed, slots inserted.

    Every name the standard does not fix becomes a slot — an empty value the
    library fills from the navigation set. That is how the measured Chrome and
    Firefox sets are written, and it means an edit to a navigation value (a new
    Accept-Language, a new Accept-Encoding) reaches the fetch set for free
    instead of drifting from it.
    """
    out = []
    for h in nav:
        key = h["key"].lower()
        if key in NAVIGATION_ONLY:
            continue
        if key == anchor:
            out.extend({"key": a, "value": ""} for a in ADDED)
        out.append({"key": h["key"], "value": FETCH_VALUES.get(key, "")})
    if not any(h["key"] == "origin" for h in out):
        # No anchor in the set: the four go before the tail, which is the end.
        out.extend({"key": a, "value": ""} for a in ADDED)
    return out


def fetch_http1(order, anchor):
    """The same transformation on the HTTP/1.1 order, which carries the case."""
    out = []
    for name in order:
        low = name.lower()
        if low in NAVIGATION_ONLY:
            continue
        if low == anchor:
            out.extend(["Content-Type", "Content-Length", "Origin", "Referer"])
        out.append(name)
    return out


def main() -> int:
    check = "--check" in sys.argv
    files = sorted(PROFILES.glob("safari-*.json"))
    profiles = {p.stem: load(p)[0] for p in files}
    changed = []
    for path in files:
        name = path.stem
        data, nl = load(path)
        nav = resolve(profiles, name, "headers", "order")
        h1 = resolve(profiles, name, "http1", "order")
        anchor = (resolve(profiles, name, "headers", "custom_anchor") or "").split(",")[0].strip().lower()
        if not nav:
            continue
        want = {
            "order": fetch_order(nav, anchor),
            "custom_anchor": anchor,
            "derived": True,
        }
        if h1:
            want["http1_order"] = fetch_http1(h1, anchor)
            want = {"order": want["order"], "http1_order": want["http1_order"],
                    "custom_anchor": anchor, "derived": True}
        if data.get("fetch") == want:
            continue
        changed.append(name)
        if check:
            continue
        data["fetch"] = want
        save(path, data, nl)
        print(f"{name}: wrote a derived fetch set of {len(want['order'])} headers")
    if check and changed:
        print("safari fetch sets differ from the generator: " + ", ".join(changed), file=sys.stderr)
        return 1
    if not check:
        print(f"{len(files)} Safari profiles, {len(changed)} rewritten")
    return 0


if __name__ == "__main__":
    sys.exit(main())
