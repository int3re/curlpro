# The C ABI

`libcurlpro` (`curlpro.dll`, `libcurlpro.so`, `libcurlpro.dylib`) is a Go
library built with `-buildmode=c-shared`. Every language other than Go talks to
it through the 62 functions declared in [include/curlpro.h](../include/curlpro.h).
This file is the contract those functions keep: what goes in, what comes out,
who frees what, which errors exist, and what is safe from several threads.

The Python package was the first binding and still is the reference one
([python/curlpro/_ffi.py](../python/curlpro/_ffi.py)). The others live in
[bindings/](../bindings/README.md).

`dist/curlpro.h`, which `go build` writes next to the library, declares the same
functions with Go's typedefs (`GoInt`, `GoString`…). It is a build by-product.
Include `include/curlpro.h`.

## Loading the library

| Platform | File | Build |
|---|---|---|
| Windows | `curlpro.dll` | `./build.ps1` (MinGW gcc for cgo) |
| Linux | `libcurlpro.so` | `CGO_ENABLED=1 go build -buildmode=c-shared -o dist/libcurlpro.so ./lib` |
| macOS | `libcurlpro.dylib` | the same with `-o dist/libcurlpro.dylib` |

`-tags nofoxio` leaves out the FoxIO-licensed JA4H code; see
[VERSIONING.md](VERSIONING.md).

Every binding looks for the library in the same order, so one environment
variable steers all of them:

1. `CURLPRO_LIBRARY` — a full path to the file;
2. next to the binding's own package (where a package manager puts it);
3. the system loader's search path.

A Go c-shared library brings its own Go runtime. One process can hold one such
library; loading it into a Go program is not supported, which is why Go uses
the core directly ([bindings/go](../bindings/go/README.md)) rather than the ABI.

## The version check

```c
char *v = curlpro_version();   /* {"ok":true,"data":{"version":"0.34.0"}} */
```

The library's version is the ABI version (`CURLPRO_ABI_VERSION_*` in the
header), and since 0.34.0 the release's version as well — the Python package and
the bindings carry the same number. Its minor is raised when a function or a
configuration field is added; a patch adds neither. Both
sides ignore JSON fields they do not know, so an old library handed a new option
drops it silently and the request leaves without it. **A binding refuses a
library whose `major.minor` is lower than the one it was written against.** A
newer library is fine.

## Strings: the envelope

Every function that returns `char *` without an `out_len` returns a
NUL-terminated UTF-8 JSON object:

```json
{"ok": true,  "data": {…}}
{"ok": false, "error": "human-readable text", "code": "timeout", "details": {…}}
```

- `data` is absent when the call has nothing to report (`session_close`).
- `code` is absent for errors that have no class yet; treat absence as
  "unknown, maybe transient".
- `details` carries an error's machine-readable fields beside its code — a
  proxy's stage, an alert's number, `phase` (below) — and is absent when it
  has none.
- The text of `error` is for people and changes between releases. Branch on
  `code`.

The result is allocated by the library. **Free it with `curlpro_free`**, never
with the host's `free`: on Windows the DLL and the program may use different C
runtimes. `curlpro_free(NULL)` is a no-op.

Arguments are borrowed: the library copies what it needs before returning, so a
string may be freed or reused as soon as the call returns. That holds for the
`*_start` functions too.

## Bytes: frames

Bodies are bytes, not text, so calls that carry one use a frame:

```
offset 0      4                4 + n
       [ n: uint32 LE ][ JSON, n bytes ][ body, the rest ]
```

- **In** (`frame`, `frame_len`): the JSON is the request description, the rest
  is the request body.
- **Out** (returns `char *`, total length in `*out_len`): the JSON is the
  envelope above, the rest is the response body or message. A frame may contain
  NUL bytes; use `*out_len`, never `strlen`. Free it with `curlpro_free`.

The largest frame is 2 GiB − 1. A larger response comes back as an error with
`code: "too_large"`; read such a body with a stream.

## Handles

Sessions, streams, WebSockets and asynchronous calls are `curlpro_handle`
(`long long`). Each kind is numbered separately; `0` is never valid. A closed or
unknown handle gives an error envelope (`"session 7 not found"`), not a crash.

Close what you open: a session holds its connection pool, a stream or a socket
holds a connection. `curlpro_debug_counts()` shows what is still registered and
is the tool for leak tests.

## Profiles come first

The profile registry starts **empty**. Before the first session, load profiles:

| Call | Loads |
|---|---|
| `curlpro_profiles_load_dir(dir)` | every `*.json` under `dir` — the repository's `profiles/` |
| `curlpro_profiles_load_bundle(path, keys)` | a signed `profiles.json.gz` (+ `path.sig`); all or nothing |
| `curlpro_profile_register(json)` | one profile; may use `based_on` an already registered one |

All three answer `{"profiles": [names…]}`; the bundle adds `loaded`,
`package`, `commit`, `built`, `min_abi`. `keys` is a comma-separated list of
extra base64 Ed25519 public keys (the format of `CURLPRO_BUNDLE_KEYS`), or `""`.
A bundle loads only if the signature verifies and no profile in it asks for a
newer library.

Where a binding finds profiles: `CURLPRO_PROFILES` (a directory) if set, then
`profiles/` next to its package, then the signed bundle the Python package caches
in `CURLPRO_CACHE_DIR` or `%LOCALAPPDATA%\curlpro` / `~/.cache/curlpro`. A binding
does this once, while the registry is still empty: before the first session, and
before registering a profile of the caller's — which may be `based_on` a stock one.

`curlpro_profiles_list()`, `curlpro_profile_get(name)` (inheritance resolved)
and `curlpro_profile_capabilities(name)` (what it can do — fetch headers, HTTP/3,
devices — without opening a session) read the registry.

## Sessions

```c
char *r = curlpro_session_new("{\"profile\":\"chrome-157-windows\"}");
/* {"ok":true,"data":{"session":1}} */
```

A session is one browser: its TLS and HTTP/2/3 fingerprint, its connection
pool, cookie jar, header set and cache. Requests on one session may run in
parallel.

### Configuration

Only `profile` is required. **The zero values are not the browser defaults** —
the Go side reads a missing boolean as `false` and a missing number as `0`. A
binding must send the defaults below explicitly, the way the Python `Session`
does; each row says what an absent field means where that differs. The fields
marked "absent = `true`" are the exceptions, read as on when missing.

| Field | Type | Binding default | Meaning |
|---|---|---|---|
| `profile` | string or object | `chrome-157-windows` | registered profile name, or a profile given whole (`{"based_on": …, "tls": …}`) used for this session and never registered (0.32) |
| `timeout_ms` | int | `30000` (absent: no limit) | whole request, redirects, retries and the body included; 0 = none (until 0.31 a 0 became 30 s) |
| `connect_timeout_ms` | int | 0 | connection setup; 0 = only `timeout_ms` |
| `response_timeout_ms` | int | 0 | waiting for response headers |
| `decompress` | bool | absent = `true` | `false` hands bodies over as they came: compressed, `Content-Encoding` and `Content-Length` kept; such responses bypass the cache (0.32) |
| `ticket_cache` | string | `""` | a group name: sessions with the same one share their TLS tickets and resume each other's connections (one identity over several sessions); needs `resume` (0.32) |
| `expect_continue_ms` | int | absent = 1000 | how long a body announced with `Expect: 100-continue` waits for the server's `100` (a final answer first leaves it unsent; silence sends it when the time is up); `0` sends it at once, as before 0.33 (0.33) |
| `idle_timeout_ms` | int | 0 | a body that stops arriving: no byte for this long while a read waits; 0 = none. The bound for a stream with no total limit (0.31) |
| `default_headers` | bool | **`true`** (absent: `false`) | send the profile's headers in its order |
| `follow_redirects` | bool | **`true`** (absent: `false`) | |
| `max_redirects` | int | **`20`** (absent or `0`: 20) | |
| `cookies` | bool | **`true`** (absent: `false`) | keep a cookie jar |
| `resume` | bool | **`true`** (absent: `false`) | TLS session resumption, as browsers do; `ticket_cache` needs it on |
| `trust_env` | bool | **`true`** (absent: `false`) | `HTTPS_PROXY`/`NO_PROXY` from the environment |
| `post_quantum` | bool | absent = `true` | the X25519MLKEM768 key share |
| `alt_svc` | bool | absent = `true` | follow `Alt-Svc` to HTTP/3 |
| `keep_alive` | bool | absent = `true` | reuse connections |
| `samesite` | bool | absent = `true` | apply SameSite rules to cookies |
| `preflight` | bool | absent = `true` | send the CORS preflight a browser would |
| `http3` | bool | false | start with HTTP/3 where the profile can |
| `force_http1` | bool | false | |
| `proxy` | string | `""` | `http://`, `https://`, `socks5://`, `socks5h://`, with `user:pass@` |
| `insecure_skip_verify` | bool | false | skip certificate checks (the hello is unchanged) |
| `ca_cert` | string | | PEM file added to the trusted roots |
| `client_cert`, `client_key` | string | | PEM files for mutual TLS |
| `header_order` | [string] | | override the profile's header order |
| `max_response_size` | int | 0 | bytes; 0 = no limit; past it → `too_large` |
| `resolve` | {host: ip} | | fixed DNS answers |
| `resolve_via_proxy` | string | absent = `"name"` | what `resolve` does behind a proxy: `"name"` nothing — the tunnel names the host and the proxy resolves it, as curl's `--resolve`; `"ip"` the tunnel goes to the table's address (`CONNECT ip:port`, SOCKS5's address form, MASQUE's target), SNI and `Host` keeping the name. `conn.resolved_by` says which happened (0.34) |
| `ip_version` | string | `""` | `"4"`, `"6"` or `""` |
| `dns` | string | `""` | HTTPS-record lookups: `""` system, `"off"`, servers, or a DoH URL |
| `max_idle_conns`, `idle_conn_timeout_ms` | int | | pool limits |
| `retry` | object | | `{attempts, statuses, methods, backoff_ms, max_backoff_ms, respect_retry_after}` |
| `mode` | string | `""` | `"navigate"`, `"fetch"` or `""` (auto) — which header set |
| `page`, `top_level` | string | | the initiator page and the address-bar page (Referer, Origin, Sec-Fetch-Site) |
| `credentials` | string | | fetch credentials mode: `omit`, `same-origin`, `include` |
| `cache` | object | null | `{max_bytes, dir}` switches the HTTP cache on |
| `device`, `devices` | string, [object] | | a device from the profile (`"random"` picks one) |

### Session calls

| Call | `data` |
|---|---|
| `curlpro_session_close(s)` | — |
| `curlpro_session_fingerprint(s, url)` | `profile`, `ja3`, `ja3n`, `ja4`, `ja4_r`, `akamai`, `ciphers`, `extensions`, `alpn`, … — computed, nothing is sent |
| `curlpro_session_preview(s, spec)` | `{names, headers}`; with `"preflight":true` also `needed`. `spec` takes the request fields below except the body |
| `curlpro_session_set_header(s, name, value)` | `{headers}` |
| `curlpro_session_remove_header(s, name)` | `{removed, headers}` |
| `curlpro_session_suppress_header(s, name)` | `{headers, suppressed}` — never sent, even by the profile |
| `curlpro_session_reset_headers(s)` | `{removed}` |
| `curlpro_session_headers(s)` | `{headers, suppressed}` |
| `curlpro_session_set_page(s, url)` / `set_top_level(s, url)` | `{page}` / `{top_level}` |
| `curlpro_session_cookies(s)` | `{cookies: [{name, value, domain, path, expires, secure, http_only, same_site, …}]}` |
| `curlpro_session_set_cookies(s, json_array)` | `{cookies}` |
| `curlpro_session_clear_cookies(s)` | — |
| `curlpro_session_undo_cookies(s, changes)` | — (reverts a response's `cookie_changes`) |
| `curlpro_session_cache_info(s)` / `clear_cache(s)` | cache statistics / `{cleared}` |

## Requests

```c
char *frame = /* [len]{"method":"GET","url":"https://example.com/"} */;
int out_len;
char *resp = curlpro_request(session, frame, frame_len, &out_len);
/* resp: [len]{"ok":true,"data":{"status":200,…}}<body bytes> */
curlpro_free(resp);
```

### Request JSON

| Field | Type | Meaning |
|---|---|---|
| `method`, `url` | string | required. The path and query go on the wire as Chromium writes them, from the URL as given: what is percent-encoded stays as it is (`%xx` in its case), `\| ^ [ ] '` raw; a space, a control or non-ASCII byte, `" < >` (and in the path `` ` { } ``) are encoded (0.33; before, the path was re-escaped Go's way and a space in the query went raw) |
| `headers` | {name: value} | added to (or replacing) the profile's; order comes from the profile |
| `headers_raw` | [[name, value], …] | the whole header set, sent as given: order, case on HTTP/1.1 (lowercase on HTTP/2 and HTTP/3), a name twice sent twice — repeats of one name go out together, where its first stands; nothing of the profile's, the session's or the jar's is added; pseudo-headers in the list are skipped. Exclusive with `headers` and `header_order` (0.32). A value that is not UTF-8 goes as `[name, base64, "base64"]`; on HTTP/1.1 `Content-Length` and `Transfer-Encoding` in the list mark where the transport writes its own, from the body (0.33; they went out twice) |
| `h2_priority` | {weight, exclusive, depends_on} | this request's HTTP/2 priority (weight 1–256) in place of the profile's (0.32) |
| `target_raw` | string | the request-target — path and query — sent exactly as given, in place of the URL's (which still names the host, the scheme and the cookies' path): the bytes a relayed client sent, an app's own encoding, a path a signature was computed over. In origin form (`/…`) or `*`; CR, LF and NUL are refused, and so is a target starting with `//`; on HTTP/1.1 a space too, since it would split the request line. The first hop only (0.34) |
| `interim_events` | bool | on a `*_start` call, each 1xx response becomes a result of the call's own handle the moment it is read — `{"interim": {status, headers}}` — before the final one (Asynchronous calls); a 103's preloads or the 100 a client waits on reach it in time (0.34) |
| `connection` | `"new"` or an id | `"new"`: a connection of its own, opened for this request and pooled after; an id (a response's `conn.id`): that open connection — a proxy keeps each client connection to one server connection so. Either covers the first hop, takes the request past HTTP/3 and past the silent resend on a fresh connection; a named connection that is gone fails with `conn_closed`, one to another origin (not coalescable) or a busy HTTP/1.1 one with `configuration` (0.33) |
| `decompress` | bool or absent | per-request `decompress` (0.32) |
| `suppress_headers` | [string] | leave these out whatever set them |
| `header_order` | [string] | this request's order |
| `default_headers`, `session_headers`, `cookies` | bool or absent | switch the profile headers / session headers / jar off for this request |
| `protocol` | string | `"http1"`, `"h2"`, `"h3"` — force one |
| `timeout_ms`, `connect_timeout_ms`, `response_timeout_ms`, `idle_timeout_ms` | int or absent | per-request overrides; `0` = no limit for this request (0.31; it was refused) |
| `follow_redirects`, `max_redirects`, `retry` | | per-request overrides |
| `proxy` | string or absent | absent = the session's, `""` = direct |
| `mode`, `page`, `top_level`, `credentials` | | per-request; for `page`/`top_level` absent = the session's, `""` = none |
| `cache_mode` | string | fetch's `cache` option |
| `resource`, `crossorigin` | string | a subresource load (`"image"`, `"script"`…) and its `crossorigin` |
| `preflight` | bool | `false` skips the OPTIONS |
| `body_file` | string | stream the body from this file instead of the frame |
| `body_stream`, `body_size` | bool, int | the body is written while the request is in flight (below); `body_size` is its Content-Length when known, 0 = unknown (chunked on HTTP/1.1) |
| `multipart` | object | `{fields, order, files: [{field, filename, content_type}], file_sizes}`; file contents follow each other in the frame body, lengths in `file_sizes` |
| `track_cookies` | bool | log the jar changes into `cookie_changes` |

### Response JSON (`data`)

| Field | Meaning |
|---|---|
| `status`, `proto` | `200`, `"HTTP/2.0"` / `"HTTP/3.0"` / `"HTTP/1.1"` |
| `headers` | {name: [values]} — repeated headers stay separate |
| `url` | the final URL after redirects |
| `body_len` | the length of the body that follows the JSON |
| `history` | redirects: `[{status, url, location, headers}]` |
| `preflights` | CORS preflights sent before the request |
| `cookie_changes` | with `track_cookies` |
| `cache` | `"hit"`, `"revalidated"`, `"miss"`, or absent |
| `trailers` | {name: [values]} — the fields sent after the body (gRPC's `grpc-status`, `grpc-message`); absent when none came (0.31) |
| `trailers_raw` | [[name, value], …] — the trailer block as it came, as `headers_raw` is the header block: the server's case and order, a repeated field once per line, a value that is not UTF-8 as `[name, base64, "base64"]`; absent when none came (0.35) |
| `headers_raw` | [[name, value], …] — the header block as it came off the wire: the server's order and case, a repeated field once per line; absent for a cached response (0.32). A value that is not UTF-8 (obs-text, a `Set-Cookie` in cp1251) comes as `[name, base64, "base64"]`: JSON would turn its bytes into U+FFFD, as it does in `headers` (0.33) |
| `interim` | [{status, headers}] — the 1xx responses before the final one (103 Early Hints, 100 Continue), in order (0.32). Since 0.33 a body announced with `Expect: 100-continue` waits for the `100` (`expect_continue_ms`) |
| `conn` | the connection: `id` (same id, same connection), `reused`, `remote`, `local`, `proto`, `proxy`, `tls_version`, `cipher`, `resumed`, `ech`, `verified`, `ja4`/`ja4_r` of the ClientHello actually sent, and on a connection's first response `resolved_by` (`local`, or `proxy` when a proxy got the name, 0.34), `peer_certs` (DER, base64, leaf first), `connect_ms` (name resolution, TCP and a proxy's tunnel together; `dns_ms` the address lookup within it, 0.33) and `tls_ms` (0.32) |
| `timing` | `{wait_ms, body_ms}` — from the request leaving to its headers (0.32); from the headers to the body's last byte, on a buffered response (0.33) |

The body is already decompressed (gzip, br, zstd, deflate).

## Streaming a response

`curlpro_stream_open` takes the same frame as `curlpro_request` and returns as
soon as the headers arrive; `data` holds the response fields plus
`"stream": <handle>`. Then:

```c
char buf[65536];
int n;
while ((n = curlpro_stream_read(stream, buf, sizeof buf)) > 0) { /* use n bytes */ }
if (n < 0) { char *e = curlpro_stream_error(stream); /* envelope */ curlpro_free(e); }
curlpro_free(curlpro_stream_close(stream));
```

`curlpro_stream_read` returns the byte count, `0` at the end of the body, `-1`
on an error (or an unknown handle). Close the stream in every case.

`curlpro_stream_trailers(stream)` gives the response's trailers once a read has
returned `0`: `{"trailers": {name: [values]}, "trailers_raw": [[name, value], …]}`
(the block as it came, 0.35), empty before the end and when the server sent
none. A buffered response carries them as `trailers` (0.31) and `trailers_raw`.

`curlpro_decode(frame, len, &out_len)` (0.33) undoes a `Content-Encoding` on
bytes you hold — the copy to show of a body relayed as it came (`decompress:
false`). The frame's JSON is `{"encoding": "gzip, br", "limit": n}` (`0` is no
limit), its body the bytes; the answer is `{"complete": bool, "error"?: text}`
and the decoded bytes, at most `limit`. A cut input — the first megabyte of a
stream — gives what decoded before the cut with `complete: false` and the
reason; an encoding the library does not know is `configuration`.

## Streaming a request body

A request with `"body_stream": true` carries no body in its frame. Start it with
`curlpro_request_start` (the whole response comes back as the result) or
`curlpro_stream_open_start` (the head comes back, the body is read with
`curlpro_stream_read`), then write the body to the request's handle — it is
registered before the start returns:

```c
long long rid = /* curlpro_stream_open_start(s, [len]{"method":"POST","url":…,"body_stream":true}) */;
curlpro_free(curlpro_request_body_write(rid, chunk, chunk_len));  /* {"written": n}; blocks on flow control */
/* … more writes; on HTTP/2 and HTTP/3 the head may already be ready — a bidirectional stream … */
curlpro_free(curlpro_request_body_end(rid, "{\"grpc-status\": \"0\"}"));   /* or "" for no trailers */
```

- The length is unknown unless `body_size` gives it: chunked on HTTP/1.1, DATA
  frames until END_STREAM on HTTP/2 and HTTP/3. On HTTP/1.1 the response arrives
  after the body.
- A write blocks until the transport has taken the bytes: the server's flow
  control reaches the writer, nothing piles up in memory.
- The body cannot be sent twice, so such a request is never replayed: no
  retries, no resend on a fresh connection, no HTTP/3 guessed from Alt-Svc, and a
  307 or 308 comes back as the response instead of being followed.
- Trailers given to `body_end` go after the body. No `Trailer` header announces
  them, as no browser announces any; a client relayed through a proxy that
  announces its own sends that header in `headers`.
- The body stays registered until `body_end`, until the request fails or its
  response is complete, or until the stream it opened is closed. After that a
  write or an end answers `conn_closed` — also when the server answered before
  the body was done, instead of blocking.
- The blocking `curlpro_request`, `curlpro_stream_open` and
  `curlpro_upgrade_open` refuse `body_stream` with `configuration`: the thread
  that would write the body is the one waiting.

## Upgrade and raw connections

`curlpro_upgrade_open(session, frame, len, &out_len)` sends a request asking to
switch protocols — a WebSocket handshake relayed from a client, h2c, anything
with `Upgrade` — and on `101` hands back the connection. The request is an
ordinary one (the profile's headers when `default_headers` is on, the jar's
cookies, your `headers`, `header_order`, `proxy`, timeouts) on a connection of
its own negotiated as `http/1.1`, with the profile's ClientHello. Nothing is added
for the upgrade and nothing is checked in the answer: `Connection`, `Upgrade` and
`Sec-WebSocket-*` are whatever you send, and `Sec-WebSocket-Accept` is your
client's to check.

With `"connect_protocol": "websocket"` (0.33) the request is extended CONNECT
on HTTP/2 instead (RFC 8441) — WebSocket over HTTP/2, as Chrome opens it where
the server allows it: a stream on the origin's HTTP/2 connection (pooled, or
new with `"connection": "new"`), `:method CONNECT` and `:protocol` after
`:authority`, `:scheme` and `:path`. The server must have sent
`SETTINGS_ENABLE_CONNECT_PROTOCOL`, or the call fails without sending; a `2xx`
takes the place of the `101`, and `conn` is the stream: its DATA frames carry
your bytes both ways, `curlpro_conn_close_write` ends your side with
END_STREAM, `curlpro_conn_close` resets the stream and leaves the connection to
its other streams. `headers_raw` sends the client's `sec-websocket-*` as they
came. The URL is `wss://` or `https://`.

With `"connect_authority": "host:port"` (0.35) the request is a plain CONNECT on
HTTP/2 instead (RFC 9113 8.5): the URL's origin is the proxy, the stream
carries `:method CONNECT` and `:authority` set to the target — no `:scheme`,
`:path` or `:protocol` — and your `headers_raw` as given (a browser's proxy
credentials, Chrome's `chrome-tunnel` to googlezip.net); without
`headers_raw`, the profile's `User-Agent` and your `headers`, none of a page's
set and no cookies, as the session's own proxy tunnel. It goes on the
proxy's HTTP/2 connection beside its other streams, with the profile's
ClientHello, SETTINGS, pseudo-header order and HPACK, as a browser tunnels
through an HTTPS proxy; the proxy need not send
`SETTINGS_ENABLE_CONNECT_PROTOCOL`. A `2xx` hands back `conn` as above; a
proxy that negotiates HTTP/1.1 fails the call. Not together with
`connect_protocol`; an authority without a port is `configuration`.

The out frame is `{status, proto, headers, url, body_len, conn, info}` and,
for an answer other than `101`, its body (up to 1 MiB); `conn` is a handle,
present after `101` only. `info` is the connection the answer came over — the
object a response has as `conn` and `curlpro_tls_dial` as `info`: id, `reused`,
addresses, TLS, the JA4 of the hello actually sent, the chain, the setup times —
on every answer, a refusal's too; for a CONNECT through a proxy it is the
connection to the proxy (0.35). From there the bytes are yours, both ways — frames pass as
your client wrote them, with its extensions, masking, fragmentation, pings and
close codes:

| Call | Does |
|---|---|
| `curlpro_conn_read(conn, buf, len)` | bytes read, `0` when the peer closed its side, `-1` on an error; the bytes the server sent right behind the `101` come first |
| `curlpro_conn_write(conn, buf, len)` | writes `buf` whole: the byte count or `-1` |
| `curlpro_conn_error(conn)` | the stored error of a failed read or write, as an envelope |
| `curlpro_conn_read_start(conn, len)`, `curlpro_conn_write_start(conn, buf, len)` | asynchronous: `{"eof": bool}` + bytes, `{"written": n}` (the buffer is copied) |
| `curlpro_conn_close_write(conn)` | ends your direction (TLS close_notify), reading stays open |
| `curlpro_tls_dial(session, config)` | no HTTP at all: a TLS connection with the profile's ClientHello to `{host, port}`, `alpn` replacing its list (`[]` none, absent the profile's), through `proxy` or the session's; `{conn, info}`, `info` as a response's `conn` (0.32) |
| `curlpro_conn_close(conn)` | closes; a read blocked on it returns `-1` |

`curlpro_ws_*` is the other choice, where the library speaks WebSocket itself.

## WebSocket

| Call | In | Out |
|---|---|---|
| `curlpro_ws_connect(s, cfg)` | `{url, headers, subprotocols, timeout_ms, connect_timeout_ms, max_message_size, proxy}` | `{socket}` |
| `curlpro_ws_send(ws, frame, len, &out_len)` | frame: `{"binary": bool, "ping": bool}` + payload | frame with an empty envelope |
| `curlpro_ws_recv(ws, &out_len)` | — | frame: `{"binary": bool}` + message |
| `curlpro_ws_close(ws, code, reason)` | close code (1000) and reason | — |

The upgrade request carries the profile's fingerprint like any other.
`curlpro_ws_recv` blocks until a message arrives; `code: "ws_closed"` means the
peer (or `ws_close`) closed the socket, `"timeout"` that `timeout_ms` passed
without one. Control frames are answered by the library.

## Asynchronous calls

A blocking call holds a thread for the whole request. For thousands of requests
in flight use the `*_start` variants: each returns at once with
`{"request": <handle>}` (or an error envelope, when the arguments are wrong), and
the work runs inside the library.

```c
curlpro_free(curlpro_request_start(session, frame, frame_len));   /* → request id */
for (;;) {
    long long done = curlpro_result_wait(1000);   /* 0: nothing finished within 1 s */
    if (!done) continue;
    int len;
    char *res = curlpro_result_take(done, &len); /* exactly what curlpro_request would return */
    /* … */ curlpro_free(res);
}
```

| Start | Result frame (as the blocking variant) |
|---|---|
| `curlpro_request_start(s, frame, len)` | response envelope + body |
| `curlpro_stream_open_start(s, frame, len)` | head with `stream` |
| `curlpro_stream_read_start(stream, buf_len)` | `{"eof": bool}` + up to `buf_len` bytes |
| `curlpro_ws_connect_start(s, cfg)` | `{socket}` |
| `curlpro_ws_send_start(ws, frame, len)` | empty envelope |
| `curlpro_ws_recv_start(ws)` | `{"binary"}` + message |
| `curlpro_upgrade_open_start(s, frame, len)` | the upgrade's head (+ `conn` after `101`) and a refusal's body |
| `curlpro_conn_read_start(conn, len)`, `curlpro_conn_write_start(conn, buf, len)` | `{"eof"}` + bytes, `{"written"}` |

- `curlpro_result_wait(timeout_ms)` returns the handle of one finished call, or
  `0`. `timeout_ms <= 0` polls without waiting. The ready queue is
  process-wide: one thread per process should wait on it and route results by
  handle. That is what the bindings do.
- `curlpro_result_event()` (0.33) gives the queue as a handle for a loop that
  already waits on sockets — `{"handle", "kind": "event"}` on Windows, a
  manual-reset event for `WaitForMultipleObjects`; `"fd"` elsewhere, a pipe's
  read end for epoll or kqueue. It is up while finished calls wait: take them
  with `curlpro_result_wait(0)` until `0`, which lowers it, and wait again.
  The handle lives as long as the process and is not closed by the caller.
- `curlpro_result_take` may be called once per handle; the frame is the same as
  the blocking call's. A request started with `"interim_events": true`
  (`curlpro_request_start`, `curlpro_stream_open_start`) is the exception
  (0.34): each 1xx it reads — a 103 Early Hints, the 100 a body waits on, a
  102 — comes to the ready queue under the request's handle as a result of
  its own, `{"interim": {status, headers}}`, the moment it arrives, and the
  final result follows under the same handle. Take until a frame is not an
  interim one. A cancelled request's events are dropped with it.
- `curlpro_request_cancel(id)` aborts a request or a connect. A read or a receive
  cannot be un-read: after cancelling one, close the stream or socket.
- `curlpro_async_pending()` counts calls started and not taken.

## Error codes

| `code` | Meaning | Retry? |
|---|---|---|
| `timeout` | a deadline passed: the request's, the connection's, a message's, or the idle limit (`idle_timeout`) | yes |
| `proxy` | the proxy failed: unreachable, or refused the tunnel. `details: {stage: "dial"\|"connect", status}` | depends on `stage`/`status` |
| `proxy_auth` | the proxy wants credentials or rejected them (407, SOCKS auth). `details: {stage: "auth", status}` | **no** |
| `proxy_closed` | the proxy hung up without answering CONNECT (often: wants credentials) | maybe |
| `configuration` | the arguments make no sense: unknown profile or device, a bad URL, a header twice, a negative timeout | **no** |
| `profile_capability` | the profile cannot do it: no fetch header set, no HTTP/3, no devices | **no** |
| `cors` | the preflight was refused, the request was not sent. `details: {method, url, reason, status, headers}` | no |
| `too_large` | the body outgrew `max_response_size` or the 2 GiB frame | no |
| `session_closed` | the session was closed under the call | no |
| `ws_closed` | the WebSocket is closed | no |
| `ws_too_big` | a message exceeded `max_message_size` | no |
| `ws_protocol` | the server broke RFC 6455/7692 | no |
| `conn_closed` | a raw connection, or a streamed request body, is closed — by you, or because its request ended (0.31) | no |
| `dns` | the name did not resolve | maybe |
| `connect_refused` | the TCP connection was refused | maybe |
| `tls_alert` | the server ended the handshake with an alert. `details: {alert, name}` | depends |
| `tls_verify` | the server's certificate did not verify. `details: {reason, chain}` (0.33) | **no** |
| `reset` | the peer reset the connection, or the HTTP/2 stream. `details: {h2_code, stream_id}` for a stream | maybe |
| `goaway` | the HTTP/2 server sent GOAWAY. `details: {h2_code, last_stream_id}` | maybe |
| `h2_protocol` | the HTTP/2 connection failed on a protocol error. `details: {h2_code}` | no |
| `eof_before_headers` | the connection ended before the response's headers did | maybe |
| `eof_in_body` | the connection ended inside the body | maybe |
| `quic_protocol` | HTTP/3's QUIC connection failed on a transport error other than TLS. `details: {quic_code, remote}` (0.34) | no |
| *(absent)* | not classified (until 0.32 that was DNS, TCP, TLS and HTTP/2 failures too) | maybe |

`details.phase` (0.33) says where a request failed, whatever the code:
`connect` (name resolution, TCP, a proxy's tunnel), `tls` (the handshake),
`response` (the request on its way, the wait for the headers), `body` — not
on `proxy` and `proxy_auth`, whose `stage` says it. A
timeout keeps its code `timeout`; `phase: "connect"` or `"tls"` makes it a
connect timeout. `tls_verify` carries `details: {reason, chain}` — the
verifier's words and the chain the server showed (DER, base64, leaf first).
HTTP/3's failures have a phase too (0.34) — `connect` for the address,
`tls` for the QUIC handshake (QUIC has no connection before it), `response`,
`body` — and TCP's codes: a QUIC crypto error is `tls_alert` with the alert's
number, a stream reset, an HTTP/3 error or an application close `reset` with
`details: {h3_code, stream_id, remote}`, any other transport error
`quic_protocol`.

`configuration`, `profile_capability` and `proxy_auth` are permanent: retrying
the same call cannot change the outcome. A panic inside the library becomes
`{"ok": false, "error": "internal library error: …"}` rather than a crash.

## Threads and lifetime

- Every function may be called from any thread, concurrently. Requests on one
  session run in parallel and share its pool, jar and header set.
- No callbacks: the library never calls into the host, so no thread of the host
  is ever entered from Go.
- Nothing has to be initialised or shut down. Unclosed handles are released with
  the process.
- Do not unload the library (`dlclose`, `FreeLibrary`): a Go runtime cannot be
  unloaded.

## Compatibility

The header follows the library version. Within `0.x`:

- a patch (`0.30.x`) adds nothing to the ABI;
- a minor (`0.31.0`) may add functions and JSON fields; existing signatures and
  meanings stay. A binding written for `0.30` works with `0.31`.
- A change to an existing signature would be a major change and is not planned
  before 1.0; it would be named in [VERSIONING.md](VERSIONING.md).

## Bindings

| Language | Where | Built on | Tested on this ABI |
|---|---|---|---|
| Python | [python/](../python) | ctypes | the project's test suite |
| C, C++ | [bindings/c](../bindings/c) | the header | MinGW gcc/g++ 14, Windows |
| Go | [bindings/go](../bindings/go) | the core itself, no ABI | `go test` |
| .NET (C#, F#) | [bindings/dotnet](../bindings/dotnet) | `LibraryImport` | .NET 10, Windows |
| Node.js | [bindings/node](../bindings/node) | koffi | Node 22, Windows |
| Java | [bindings/java](../bindings/java) | FFM (`java.lang.foreign`) | JDK 22, Windows |
| Rust | [bindings/rust](../bindings/rust) | libloading | not yet compiled locally; CI builds it |
| PHP | [bindings/php](../bindings/php) | FFI | not yet run locally; CI runs it |

Every binding must produce the same fingerprint for the same profile:
[scripts/bindings-agree.sh](../scripts/bindings-agree.sh) compares their
offline JA4 with the Go package's, on three systems, in
[bindings.yml](../.github/workflows/bindings.yml). The packages that carry the
library are described in [bindings/README.md](../bindings/README.md#packages).
