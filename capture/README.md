# capture/

Capturing a reference browser fingerprint.

## The ordinary way — one command

```powershell
curlpro capture -name chrome-152-windows -samples 5
```

The command raises the stand itself, brings the browser, collects the samples,
normalises them and writes a profile into `profiles/`. Then:

```powershell
curlpro validate -only chrome-152-windows -oracle https://localhost:8443/json -insecure
```

It needs `tools/echo-server*` (from the
[wi1dcard/fingerproxy](https://github.com/wi1dcard/fingerproxy) releases) and a
certificate in `certs/` — how to generate one is in
[docs/CAPTURE.md](../docs/CAPTURE.md).

## What lives here

The scripts are left over from the manual cycle that captured the first
reference (stage 0). `curlpro capture` covers all of it, but they are useful when
an existing log needs taking apart, or when the intermediate data is worth
looking at:

| File | Purpose |
|---|---|
| `analyze.py` | turns an echo-server log into a set of samples, choosing by `:path` |
| `normalize.py` | reduces the samples to a reference: cuts GREASE out, checks the extension sets agree |
| `make_profile.py` | builds a profile from the reference and the samples |
| `capture.ps1` | runs the browser N times with throwaway profiles |

## Why several samples are needed

Chrome ≥110 shuffles its TLS extensions on every connection, and the GREASE
values are random. A single capture would freeze one arbitrary permutation, and a
profile built from it would describe a particular connection rather than a
browser.

The check that the stand is working: five samples must give **different JA3**
values and **one JA4**.

## Manual mode

If the browser does not start on its own — or if another one is wanted, Firefox
or Safari:

```powershell
curlpro capture -name firefox-145-windows -manual -wait 3m
```

The command prints an address; open it as many times as `-samples` asks for, each
time in a new window.
