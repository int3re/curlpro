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

## The ABI version is a separate number

The native library carries its own version (`Version` in
[lib/curlpro.go](../lib/curlpro.go), `REQUIRED_VERSION` in
`python/curlpro/_ffi.py`). It has nothing to do with the package version and
moves on its own schedule: it is raised when the Python side starts depending on
a new export or a new configuration field.

The check exists because the failure it prevents is silent. Both sides tolerate
unknown JSON fields, so an old library given a new option ignores it and the
request goes out without it — which looks like a logic error rather than a stale
build. An hour of runs against the wrong code was lost to that before the check
existed.

A wheel always carries a matching pair. The mismatch is only reachable when
building from source or pointing `CURLPRO_LIBRARY` at an older file.

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
