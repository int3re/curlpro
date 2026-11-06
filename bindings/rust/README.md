# Rust

`curlpro` — the library is loaded at run time with
[libloading](https://crates.io/crates/libloading), like every other binding: a
Go `c-shared` DLL has no import library for the MSVC linker, and one
`CURLPRO_LIBRARY` steers all languages alike. Rust 1.74+.

> **Not compiled yet.** There was no Rust toolchain on the machine these
> bindings were written on. The code follows docs/C-ABI.md and the bindings that
> were run (.NET, Node, Java), but expect `cargo check` to need a touch.

```rust
let s = curlpro::Session::new("chrome-156-windows")?;
println!("{}", s.fingerprint("https://example.com/")?["ja4"]);   // offline

let r = s.send(&curlpro::Request::get("https://example.com/").header("accept-language", "en"))?;
println!("{} {} {} bytes", r.status, r.proto, r.body.len());

match s.get("https://slow.example/") {
    Err(e) if e.code.as_deref() == Some("timeout") => { /* retry */ }
    Err(e) if e.permanent() => return Err(e.into()),
    other => { other?; }
}
```

- `Session` is `Send + Sync`; calls block. In async code use
  `tokio::task::spawn_blocking` — requests on one session run in parallel.
- `ResponseStream` implements `std::io::Read`; `WebSocket` has `send_text`,
  `send_binary`, `receive`, `close`.
- `SessionOptions::extra` and `Request::set` send any other field of the ABI.
- The library is never unloaded: a Go runtime cannot be.
- crates.io carries source only: put the library from the release archive
  `curlpro-<v>-<platform>.zip` next to the executable, or point
  `CURLPRO_LIBRARY` at it.

```bash
CURLPRO_LIBRARY=../../dist/curlpro.dll CURLPRO_PROFILES=../../profiles cargo run --example basic
```
