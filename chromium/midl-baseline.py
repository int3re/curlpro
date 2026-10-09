"""Make the tree's pinned MIDL output agree with this machine's SDK, where it
safely can, and say so where it cannot.

    python3 chromium\\midl-baseline.py out\\iterate [workers]

Chromium checks pre-generated MIDL output into third_party/win_build_output
and build/toolchain/win/midl.py compares the fresh output with it byte for
byte, so a build on any SDK revision but the pinned one stops there. Measured
on SDK 10.0.28000.2114 against the pinned .2270 (154.0.8037.100): of the
nineteen MIDL actions in the tree, every .h, _i.c, _p.c and dlldata.c is
identical, and three files differ -- the type libraries of
//chrome/updater/app/server/win:updater_legacy_idl and its _user and _system
variants, 10 bytes each, at the same size: a two-byte value and two four-byte
words in the library's internal tables. `chrome` depends on the plain one, for
the header that chrome/browser uses to talk to GoogleUpdate; the .tlb itself is
not part of chrome.dll.

So this does what midl.py's own message says ("To rebaseline: copy ..."), but
only for type libraries, and only when every text output of the same action
already matches. A difference in anything a compiler reads is a real one and
stops here, with the files named: then it is the pinned SDK that is needed.

The copied files are machine-specific and never committed. checkout.cmd and
patches.cmd put the pinned ones back before they look for a clean tree, so the
patches never carry them; build.cmd runs this again on every build.
"""
import filecmp
import os
import re
import shutil
import subprocess
import sys

SRC = r"D:\chromium\src"
BELOW_NORMAL = 0x00004000  # BELOW_NORMAL_PRIORITY_CLASS


def midl_outputs(out):
    """The first output of every MIDL action in the build graph."""
    outs = []
    pattern = re.compile(r"^build ([^ :]+)[^:]*: __\S*idl\S*_action")
    with open(os.path.join(SRC, out, "toolchain.ninja"), encoding="utf-8") as f:
        for line in f:
            m = pattern.match(line)
            if m:
                outs.append(m.group(1))
    return outs


def build(out, targets, jobs):
    """Run the MIDL actions, all of them, past failures; return rc and output."""
    cmd = f'autoninja -C {out} -j {jobs} -k 0 ' + " ".join(targets)
    p = subprocess.run(["cmd", "/c", cmd], cwd=SRC, capture_output=True,
                       text=True, errors="replace", creationflags=BELOW_NORMAL)
    return p.returncode, p.stdout + p.stderr


def rebaseline_pairs(output, out):
    """(fresh dir, pinned dir) for every action midl.py refused."""
    pairs = []
    for m in re.finditer(r"copy /y (\S+)\\\* (\S+)", output):
        fresh = m.group(1)
        pinned = os.path.normpath(os.path.join(SRC, out, m.group(2)))
        pairs.append((fresh, pinned))
    return pairs


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    out = sys.argv[1]
    jobs = sys.argv[2] if len(sys.argv) > 2 else "2"
    targets = midl_outputs(out)
    if not targets:
        sys.exit(f"[midl] no MIDL actions found in {out}\\toolchain.ninja -- run gn gen first")

    rc, output = build(out, targets, jobs)
    if rc == 0:
        print(f"[midl] all {len(targets)} MIDL actions match the tree")
        return 0

    pairs = rebaseline_pairs(output, out)
    if not pairs:
        print(output[-4000:])
        sys.exit("[midl] the MIDL actions failed, and not on a mismatch -- see above")

    copies = []
    for fresh, pinned in pairs:
        names = sorted(os.listdir(fresh))
        _, mismatch, errors = filecmp.cmpfiles(fresh, pinned, names, shallow=False)
        text = [n for n in mismatch + errors if not n.endswith(".tlb")]
        if text:
            sys.exit(
                f"[midl] {pinned} differs in what a compiler reads: {', '.join(text)}.\n"
                "[midl] That is not a type library's internal layout; it needs the SDK\n"
                "[midl] revision docs/windows_build_instructions.md names (chromium/README.md).")
        copies += [(os.path.join(fresh, n), os.path.join(pinned, n)) for n in mismatch]

    for src, dst in copies:
        shutil.copyfile(src, dst)
        print(f"[midl] type library rebaselined for this SDK: {os.path.relpath(dst, SRC)}")

    rc, output = build(out, targets, jobs)
    if rc != 0:
        print(output[-4000:])
        sys.exit("[midl] still failing after the type libraries were rebaselined")
    print(f"[midl] all {len(targets)} MIDL actions match, {len(copies)} type "
          "librar{} rebaselined (not committed; checkout.cmd and patches.cmd "
          "restore them)".format("y" if len(copies) == 1 else "ies"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
