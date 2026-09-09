"""Replace the runner's locale with the one the parent profile declares.

Run as: python3 lang_fix.py <profile.json> <profiles-dir>

The runner's Chrome speaks en-US. The language tags in these profiles are a
decision rather than a measurement — the library is built for Russian sites —
so keeping the captured value would revert that one version at a time.

The first attempt deleted the header instead of replacing it, and the delta's
order replaces the parent's wholesale, so the profile went out with no
Accept-Language at all: JA4H fell from ge20nn13ruru to ge20nn120000. A browser
that sends no Accept-Language is a louder anomaly than the wrong language.

So the entry stays where the browser put it and only its value is taken from
the based_on chain.
"""
import json
import os
import sys

SECTIONS = ("headers", "fetch", "http1")
KEY = "accept-language"


def inherited_value(name, dirpath, seen=None):
    """The accept-language the based_on chain declares, or None."""
    seen = seen or set()
    while name and name not in seen:
        seen.add(name)
        path = os.path.join(dirpath, name + ".json")
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as f:
            p = json.load(f)
        for section in SECTIONS:
            for item in (p.get(section) or {}).get("order") or []:
                if isinstance(item, dict) and item.get("key") == KEY:
                    value = item.get("value")
                    if value:
                        return value
        name = p.get("based_on")
    return None


def main():
    path, dirpath = sys.argv[1], sys.argv[2]
    with open(path, encoding="utf-8") as f:
        profile = json.load(f)

    want = inherited_value(profile.get("based_on"), dirpath)
    if not want:
        print("the parent declares no accept-language — leaving the captured value")
        return 0

    touched = []
    for section in SECTIONS:
        for item in (profile.get(section) or {}).get("order") or []:
            if isinstance(item, dict) and item.get("key") == KEY:
                if item.get("value") != want:
                    touched.append("%s: %r -> %r" % (section, item.get("value"), want))
                    item["value"] = want

    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(profile, f, ensure_ascii=False, indent=2)
        f.write("\n")

    print("\n".join(touched) if touched else "accept-language already matched the parent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
