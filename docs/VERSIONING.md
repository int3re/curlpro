# Versioning

Written on 2026-09-09, after six releases in five days. That pace was fine while
nobody depended on the library; it stops being fine the moment somebody does.
This file says what a version number promises, so the promise exists before the
users rather than after them.

## Before 1.0

The project is on `0.x`. Under semantic versioning that means the API may change
in a minor release, and formally nothing is guaranteed. Formally is not enough
to plan against, so the rules below are what is actually done.

**`0.x.Y` — a patch.** Nothing that exists changes meaning. Fixes, new optional
arguments with a default that reproduces the old behaviour, new profiles, new
fields in a returned object, documentation. Upgrading is safe without reading
anything.

**`0.X.0` — a minor.** May remove or rename something, may change a default. Not
done without a reason written down in the release notes, and never silently:
anything removed is named there together with what replaces it.

**No `1.0` yet, and the reason is stated rather than deferred.** 1.0 means the
API is worth freezing. Two things stand in the way. The fingerprint corpus is
still updated by hand — the library's whole claim is that profiles are data, and
until a new Chrome reaches the profiles without a human, the claim is a promise
rather than a property. And the library has had no users other than its author,
so nothing has yet pushed back on the shape of the API. Freezing an interface
nobody has argued with is how a bad interface becomes permanent.

## What is covered, and what is not

Covered by the rules above — the Python API: `Session`, `AsyncSession`,
`Persona`, `Fingerprint`, `Expect`, the module-level functions, the exception
types, and the `curlpro.requests` compatibility layer.

Not covered:

- **`internal/` in the Go module.** It is `internal` in the Go sense: not
  importable from outside, and changed whenever it needs changing.
- **The exact text of an error message.** The type and the code are part of the
  API; the wording is written to be read by a person and is improved freely.
  Matching on message text will break.
- **The value of a fingerprint.** `fingerprint().ja4` changes when a profile
  changes, which is the point. Profiles are data, and data is expected to move.
- **Which profiles exist.** New ones are added in a patch. One is removed only
  when it turns out not to describe a real browser — that has happened twice —
  and the removal is named in the notes.

## One number for the package and the library

Since 0.34.0 the package, the native library (`Version` in
[lib/curlpro.go](../lib/curlpro.go), what `curlpro_version` returns), the
header's `CURLPRO_ABI_VERSION_*` and the bindings' packages carry the same
version. Until 0.22.1 they were numbered apart — package 0.22.x carried ABI
0.33 — and a release with two numbers only confused whoever read them; the
package jumped to the ABI's number, since an ABI version cannot go back (a
profile bundle names the oldest library that reads it, and 0.22's library is
0.33).

[scripts/version.py](../scripts/version.py) lists every place the number is
written, `set X.Y.Z` writes it everywhere, and the tag of a release is checked
against all of them before anything is built. A test fails while they differ.

What keeps one number honest is a rule about the ABI: **a patch adds nothing to
it**. A new export or a new configuration field comes in a minor. So
`major.minor` is all a caller has to compare, and a profile bundle asks for
`X.Y.0` — an installed 0.34.0 reads what 0.34.3 publishes.

`REQUIRED_VERSION` in `python/curlpro/_ffi.py` and the bindings' `REQUIRED` are
not the version but its floor: the oldest library that side works with. It is
raised by hand when the side starts depending on a new export or field, and
never above the version itself.

The check exists because the failure it prevents is silent. Both sides tolerate
unknown JSON fields, so an old library given a new option ignores it and the
request goes out without it — which looks like a logic error rather than a stale
build. An hour of runs against the wrong code was lost to that before the check
existed.

A wheel always carries a matching pair. The mismatch is only reachable when
building from source or pointing `CURLPRO_LIBRARY` at an older file.

## The C ABI is covered too

Since 2026-11-04 the exports of `libcurlpro` are a public interface, not an
implementation detail of the Python package: [include/curlpro.h](../include/curlpro.h)
declares them, [C-ABI.md](C-ABI.md) describes them, and the bindings in
[bindings/](../bindings/README.md) — .NET, Node, Java, Rust, PHP, C — are built
on them. The version above is their version too, with these rules:

- **A patch** (`0.34.x`) adds nothing to the ABI.
- **A minor** may add exports and JSON fields. An existing signature, a field's
  meaning and an error code stay; a binding written for `0.34` works with
  `0.35`. Bindings refuse a library older than their floor's `major.minor`.
- **Changing or removing an export** would break every binding at once and is
  not done before 1.0; if it ever is, it is named in the release notes like any
  other removal.
- The header's `CURLPRO_ABI_VERSION_*` macros move together with `Version` in
  lib/curlpro.go, and `const Version` in the root Go package with both —
  `scripts/version.py` writes and checks them all.

## Deprecation

Anything on its way out keeps working for at least one minor release and warns
with `DeprecationWarning` naming the replacement. Removal happens in the next
minor, not the same one. Nothing has been deprecated so far.

## Build tags are part of the contract too

`-tags nofoxio` leaves out the FoxIO-licensed JA4H code. It is built and tested
in CI on every push, so it cannot rot into an option that no longer compiles.
The tag will not be removed without a minor release, and `ja4h_available` on a
`Fingerprint` says which build is in use.

## The release procedure

In [RELEASE.md](RELEASE.md): the dry run, the tag, the environment approval, and
the rakes stepped on so far.
