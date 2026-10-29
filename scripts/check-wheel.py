"""The installed wheel works: the native library loads, the profiles are inside
the package, a session starts. Run by the release workflow inside the target
system (python:alpine for the musllinux wheels), where a one-line `python -c`
would need three layers of quoting."""
import pathlib

import curlpro

names = curlpro.load_profiles(pathlib.Path(curlpro.__file__).parent / "profiles")
assert "chrome-151-windows" in names, names
assert len(names) > 40, names
with curlpro.Session("chrome-151-windows") as s:
    assert s.impersonate == "chrome-151-windows"
print("profiles:", len(names), "library:", curlpro.library_version())
