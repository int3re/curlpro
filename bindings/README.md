# Bindings

Every language reaches the same Go core. All of them except Go go through the C
ABI — 45 functions in [include/curlpro.h](../include/curlpro.h), described in
[docs/C-ABI.md](../docs/C-ABI.md). Go uses the core directly: a Go program
cannot load a second Go runtime.

| Language | Folder | Built on | Blocking | Async | Stream | WebSocket | Checked |
|---|---|---|---|---|---|---|---|
| Python | [python/](../python) | ctypes | ✓ | asyncio | ✓ | ✓ | the project's test suite |
| C / C++ | [c/](c) | the header | ✓ | `*_start` + `result_wait` | ✓ | ✓ | gcc/g++ 14 (MinGW), Windows |
| Go | [go/](go) | the core, no ABI | ✓ | goroutines | ✓ | ✓ | `go test`, Windows |
| .NET | [dotnet/](dotnet) | `LibraryImport` | ✓ | `Task`, cancellation | ✓ | ✓ | .NET 10, Windows |
| Node.js | [node/](node) | koffi | ✓ | `Promise`, `AbortSignal` | ✓ | ✓ | Node 22 + koffi 3.3, Windows |
| Java | [java/](java) | FFM (`java.lang.foreign`) | ✓ | `CompletableFuture`, `cancel` | ✓ | ✓ | JDK 22, Windows |
| Rust | [rust/](rust) | libloading | ✓ | `spawn_blocking` | ✓ | ✓ | **not compiled yet** — CI will be the first build |
| PHP | [php/](php) | FFI | ✓ | — | — | — | **not run yet** — CI will be the first run |

"Checked" means the example in the folder ran against `dist/curlpro.dll` on
2026-11-04: the JA4 the session computes offline matched the one
`tls.peet.ws` saw, five parallel requests went out over HTTP/3, a cancelled
request was aborted, a streamed body was read to the end, a WebSocket echoed
text and binary messages, an unknown profile raised `configuration`, and
`curlpro_debug_counts` showed nothing left open.

## The same in every language

- **Finding the library:** `CURLPRO_LIBRARY` (a full path), else next to the
  package, else the system loader's search path.
- **Finding profiles:** the registry starts empty. A session loads profiles once
  if none are registered: `CURLPRO_PROFILES` (a directory), else `profiles/`
  next to the package or the working directory; then the signed bundle the
  Python package keeps in `CURLPRO_CACHE_DIR` (`%LOCALAPPDATA%\curlpro`,
  `~/Library/Caches/curlpro`, `~/.cache/curlpro`). Or load them yourself
  (`loadDir`, `loadBundle`, `register`).
- **The version check:** a binding refuses a library older than the ABI it was
  written for (0.30): an older library silently ignores options it does not know.
- **Session defaults are the browser's:** profile headers on, redirects followed
  (20), cookies, TLS resumption, the environment's proxy, 30 s. The ABI's own
  zero values are not — a missing boolean is `false` there — so every binding
  sends them explicitly.
- **Errors carry a code** (`timeout`, `proxy`, `proxy_auth`, `configuration`,
  `profile_capability`, `cors`, `too_large`, `ws_closed`…) and say whether they
  are permanent. Branch on the code, never on the message.
- **Anything not wrapped** is still reachable: every options object has an
  `extra`/`set` escape hatch that sends a field of docs/C-ABI.md as is.

## Packages

Each binding ships with the library inside, so a user installs one package and
sets nothing. [scripts/package-bindings.py](../scripts/package-bindings.py)
builds them from the libraries of all six platforms (win32, linux and darwin,
x64 and arm64); [bindings-release.yml](../.github/workflows/bindings-release.yml)
runs it on every `v*` tag, next to the wheels.

| Ecosystem | Package | Where the library goes | Profiles |
|---|---|---|---|
| npm | `curlpro` + `@curlpro/<platform>` | an optional dependency per platform; npm installs the one for the machine | `profiles/` in the main package |
| NuGet | `Curlpro` (assembly `Curlpro.Net.dll`) | `runtimes/<rid>/native/` | content copied to the app's `profiles/` |
| Maven | `io.curlpro:curlpro` jar | `io/curlpro/native/<platform>/`, extracted to a temporary file | the signed bundle when the release can sign, the plain profiles always |
| Composer | `curlpro-php-<v>.zip` | `lib/<platform>/` | `profiles/` |
| crates.io | `curlpro` (source only) | `CURLPRO_LIBRARY`, or next to the executable from the native archive | `CURLPRO_PROFILES` |
| anything else | `curlpro-<v>-<platform>.zip` | the library, `include/curlpro.h`, the licence | — |

Checked on 2026-11-04 with the Windows x64 library: each package installed into a
clean project ran without `CURLPRO_LIBRARY` or `CURLPRO_PROFILES` (npm,
NuGet, the jar with and without the signed bundle). The .NET assembly is called
`Curlpro.Net`, not `Curlpro`: on Windows `Curlpro.dll` and the native
`curlpro.dll` are the same file name, and the runtime loaded the managed one.

Publishing is opt-in per registry — `NPM_TOKEN`, `NUGET_API_KEY`,
`CARGO_REGISTRY_TOKEN` in the repository's secrets; the jar, the PHP archive
and the native archives are attached to the GitHub release.

## CI

[bindings.yml](../.github/workflows/bindings.yml) runs on Linux, macOS and
Windows whenever the library, the core, the header or a binding changes. It
builds every binding and runs [scripts/bindings-agree.sh](../scripts/bindings-agree.sh):
each language prints the offline JA4 of `chrome-156-windows`, and all of them
must equal the Go package's. A missing toolchain fails the job there, so a
runner image that loses PHP cannot quietly drop the PHP binding.

```bash
CURLPRO_LIBRARY=$PWD/dist/libcurlpro.so scripts/bindings-agree.sh   # locally: missing toolchains are skipped
```

## Building the library

```powershell
./build.ps1                       # Windows → dist/curlpro.dll
```

```bash
CGO_ENABLED=1 go build -buildmode=c-shared -o dist/libcurlpro.so ./lib      # Linux
CGO_ENABLED=1 go build -buildmode=c-shared -o dist/libcurlpro.dylib ./lib   # macOS
```

Add `-tags nofoxio` to leave out the FoxIO-licensed JA4H code.
