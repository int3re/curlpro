# Releasing a version

The package is built and published by the
[.github/workflows/wheels.yml](../.github/workflows/wheels.yml) workflow, on a
`v*` tag.

The first release was **0.2.0, 5 September 2026**:
[pypi.org/project/curlpro](https://pypi.org/project/curlpro/). The current one is
**0.4.3**: a proxy address without a scheme is accepted, and `HTTP_PROXY` is
read for cleartext requests — which 0.4.2 had quietly left going out direct.

## What happens on a tag

1. **version** — compares the tag with `version` in `python/pyproject.toml`. It
   runs first and everything waits on it: a `v0.3.0` tag while `version` still
   said `0.2.0` would build and publish a `0.2.0` wheel silently, and a number
   taken on PyPI is not freed by deleting it.
2. **build** — wheels on five platforms: Linux x86-64 and arm64, macOS Intel and
   Apple Silicon, Windows x86-64. Each is built on its own machine: cgo does not
   cross-compile without the target platform's toolchain.
3. Every wheel is checked where it was built: it installs, finds the profiles
   inside the package and opens a session. The check **does not depend on anyone
   else's service** — a release has to pass on a day when browserleaks is down;
   the fingerprint is asked for in a separate step with `continue-on-error`, for
   information only.
4. **sdist** — the source archive for platforms outside the list. The Go module
   and the profiles are put into it, and the contents are checked: there was a
   time when the archive came out empty (0 Go files) and the promise that it
   "builds the native part itself" was not kept.
5. **publish** — the upload to PyPI, the trusted way.

## What is configured once

Publishing goes the **trusted way** (trusted publishing): PyPI verifies the
signature of the run itself in GitHub, and no token needs to be kept in the
repository's secrets at all — there is nothing to steal.

1. A publisher is registered in the project's settings on PyPI:

   | Field | Value |
   |---|---|
   | Owner | `int3re` |
   | Repository | `curlpro` |
   | Workflow | `wheels.yml` |
   | Environment | `pypi` |

2. A `pypi` environment with a required approval (*Required reviewers* →
   `int3re`) is created in the repository. A push to the public index cannot be
   taken back: an occupied version is never freed, and without the approval one
   wrong tag would cost that number for good. The approval is the last place an
   error can still be stopped.

## How to release

```bash
# 1. Raise the version in python/pyproject.toml
# 2. Make sure everything is green
go test -race ./internal/... && cd python && python -m pytest tests -q -m "not network"

# 3. A dry run: builds everything but publishes nothing — publish only fires on a tag
gh workflow run wheels.yml --ref main

# 4. Tag and push — the same version as in pyproject, or the version job stops it
git tag -a vX.Y.Z -m "curlpro X.Y.Z"
git push origin vX.Y.Z
```

The workflow then builds the wheels and stops at the environment approval.

**The dry run before the tag is not a formality.** The very first one found two
defects, either of which would have wrecked the release: the `macos-13` runner no
longer exists (GitHub keeps the two latest versions of an OS), and a job asking
for it does not fail but queues for ever — while `publish` waits for all five
wheels. And the macOS platform tags promised `10.15` and `11.0` while Go 1.27
requires macOS 13: on 11 and 12 pip would have installed a wheel that cannot
load.

## After the release

The wheels and the archive are attached to the
[GitHub release](https://github.com/int3re/curlpro/releases), so that installing
without reaching the index is possible:

```bash
gh release create vX.Y.Z --title "curlpro X.Y.Z" --notes-file NOTES.md dist/*
```

The files are taken from the artefacts of the same run that was published: then
the checksums agree with the index byte for byte, and that is worth verifying —
`SHA256SUMS.txt` sits next to them for exactly that.

## The native part's version

The library has an ABI version of its own (`Version` in
[lib/curlpro.go](../lib/curlpro.go) and `REQUIRED_VERSION` in
`python/curlpro/_ffi.py`). It is **not** the package version, and it is raised
when Python starts depending on a new export or a new configuration field.
Without that an old library ignores unknown fields silently: an option is passed
and does not take effect — which looks like a logic error rather than a stale
build. An hour of runs against the wrong code was once lost to that trap.
