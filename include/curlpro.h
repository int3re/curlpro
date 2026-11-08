/*
 * curlpro.h — the public C ABI of libcurlpro.
 *
 * This header is written by hand and is the contract for every language
 * binding (C, C++, Rust, Go via cgo, Node via FFI, .NET P/Invoke, Java FFM,
 * PHP FFI, Python ctypes). dist/curlpro.h is what `go build -buildmode=c-shared`
 * generates; it declares the same functions with Go's internal typedefs and is
 * not meant to be included by applications.
 *
 * The full description of every call, the JSON it takes and returns, the error
 * codes and the threading rules is in docs/C-ABI.md.
 *
 * Conventions, in short:
 *
 *   - Every function that returns `char *` returns a UTF-8 JSON envelope
 *       {"ok": true,  "data": …}
 *       {"ok": false, "error": "…", "code": "…", "details": {…}}
 *     allocated by the library. Release it with curlpro_free(). It is never
 *     NULL unless the process is out of memory.
 *
 *   - Functions that carry a body use a binary frame instead of a plain string:
 *       [uint32 little-endian JSON length][JSON][raw body bytes]
 *     The `frame`/`frame_len` arguments take such a frame; the returned frame's
 *     total length is written to `*out_len`. The JSON part of a returned frame
 *     is the envelope above; the body follows it.
 *
 *   - Sessions, streams, sockets and async requests are identified by 64-bit
 *     integers (curlpro_handle). 0 is never a valid handle.
 *
 *   - All functions are safe to call from any thread. A handle may be used from
 *     several threads at once; requests on one session run concurrently.
 */
#ifndef CURLPRO_H
#define CURLPRO_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The ABI version this header describes. curlpro_version() reports the
 * library's version in its envelope ({"version": "0.30.0"}); a binding should
 * refuse a library whose major.minor is lower than the one it was written
 * against, because an older library silently ignores options it does not know. */
#define CURLPRO_ABI_VERSION_MAJOR 0
#define CURLPRO_ABI_VERSION_MINOR 38
#define CURLPRO_ABI_VERSION_PATCH 0
#define CURLPRO_ABI_VERSION_STRING "0.38.0"

/* Frame header size in bytes: a uint32 little-endian length of the JSON part. */
#define CURLPRO_FRAME_HEADER 4

#if defined(_WIN32) && !defined(CURLPRO_STATIC)
#  ifdef CURLPRO_BUILDING
#    define CURLPRO_API __declspec(dllexport)
#  else
#    define CURLPRO_API __declspec(dllimport)
#  endif
#else
#  define CURLPRO_API
#endif

typedef long long curlpro_handle;

/* ---- Memory ------------------------------------------------------------- */

/* Releases a string or frame returned by any curlpro_* function. NULL is ignored. */
CURLPRO_API void curlpro_free(char *s);

/* ---- Library and profiles ------------------------------------------------ */

/* data: {"version": "0.30.0"} */
CURLPRO_API char *curlpro_version(void);

/* Loads every *.json profile in a directory into the process-wide registry.
 * Must be called (or curlpro_profiles_load_bundle) before the first session:
 * the registry starts empty. data: {"profiles": [names…]} */
CURLPRO_API char *curlpro_profiles_load_dir(const char *dir);

/* Loads a signed profile bundle (profiles.json.gz, signature in path + ".sig").
 * keys: comma-separated extra Ed25519 public keys trusted besides the built-in
 * ones (the format of CURLPRO_BUNDLE_KEYS), or "" for the built-in keys only. */
CURLPRO_API char *curlpro_profiles_load_bundle(const char *path, const char *keys);

/* Registers one profile given as JSON (may use "based_on"). */
CURLPRO_API char *curlpro_profile_register(const char *profile_json);

/* Removes a registered profile; one another profile stands on is refused.
 * Sessions made with it keep their copy. data: {"profiles": [names…]}. Since
 * 0.32. A profile used once can instead be given whole to curlpro_session_new
 * ("profile": {…}) and never registered. */
CURLPRO_API char *curlpro_profile_unregister(const char *name);

/* Forgets a named ticket group (ticket_cache): sessions holding it keep it.
 * data: {"dropped": bool}. Since 0.32. */
CURLPRO_API char *curlpro_ticket_cache_drop(const char *name);

/* data: list of registered profile names. */
CURLPRO_API char *curlpro_profiles_list(void);

/* data: what the named profile supports (http3, websocket, ech, …). */
CURLPRO_API char *curlpro_profile_capabilities(const char *name);

/* data: the named profile as JSON, inheritance resolved. */
CURLPRO_API char *curlpro_profile_get(const char *name);

/* ---- Sessions ------------------------------------------------------------ */

/* Creates a session. config: JSON, see docs/C-ABI.md ("profile" is required).
 * data: {"session": <handle>} */
CURLPRO_API char *curlpro_session_new(const char *config_json);

CURLPRO_API char *curlpro_session_close(curlpro_handle session);

/* Offline fingerprint for a URL: ja3, ja3n, ja4, akamai, headers, client_hello… */
CURLPRO_API char *curlpro_session_fingerprint(curlpro_handle session, const char *url);

/* The request the session would send, without sending it. spec: JSON. */
CURLPRO_API char *curlpro_session_preview(curlpro_handle session, const char *spec_json);

CURLPRO_API char *curlpro_session_set_header(curlpro_handle session, const char *name, const char *value);
CURLPRO_API char *curlpro_session_remove_header(curlpro_handle session, const char *name);
CURLPRO_API char *curlpro_session_suppress_header(curlpro_handle session, const char *name);
CURLPRO_API char *curlpro_session_reset_headers(curlpro_handle session);
CURLPRO_API char *curlpro_session_headers(curlpro_handle session);
CURLPRO_API char *curlpro_session_set_page(curlpro_handle session, const char *page_url);
CURLPRO_API char *curlpro_session_set_top_level(curlpro_handle session, const char *top_level_url);

CURLPRO_API char *curlpro_session_cookies(curlpro_handle session);
CURLPRO_API char *curlpro_session_set_cookies(curlpro_handle session, const char *cookies_json);
CURLPRO_API char *curlpro_session_clear_cookies(curlpro_handle session);
CURLPRO_API char *curlpro_session_undo_cookies(curlpro_handle session, const char *changes_json);

CURLPRO_API char *curlpro_session_cache_info(curlpro_handle session);
CURLPRO_API char *curlpro_session_clear_cache(curlpro_handle session);

/* ---- Requests (blocking) --------------------------------------------------- */

/* Sends a request and returns the whole response as a frame.
 * frame in:  JSON request (method, url, headers, …) + raw request body.
 * frame out: envelope with data {status, proto, headers, url, body_len, history, …}
 *            + raw response body. *out_len receives the frame's total length. */
CURLPRO_API char *curlpro_request(curlpro_handle session, const char *frame, int frame_len, int *out_len);

/* ---- Streaming responses --------------------------------------------------- */

/* Like curlpro_request, but returns only the head; data includes {"stream": <handle>}. */
CURLPRO_API char *curlpro_stream_open(curlpro_handle session, const char *frame, int frame_len, int *out_len);

/* Reads up to buf_len body bytes into buf. Returns the byte count, 0 at the end
 * of the body, or a negative value on error (then call curlpro_stream_error). */
CURLPRO_API int curlpro_stream_read(curlpro_handle stream, char *buf, int buf_len);

/* The stored error of a failed curlpro_stream_read, as an envelope. */
CURLPRO_API char *curlpro_stream_error(curlpro_handle stream);

CURLPRO_API char *curlpro_stream_close(curlpro_handle stream);

/* The trailers of the stream's response (gRPC's grpc-status, grpc-message):
 * data {"trailers": {name: [values]}}, empty until curlpro_stream_read has
 * returned 0 and when the server sent none. Since 0.31. */
CURLPRO_API char *curlpro_stream_trailers(curlpro_handle stream);

/* Undoes a Content-Encoding on bytes the caller holds — the copy to show of
 * a body relayed as it came (decompress false). The frame's JSON is
 * {"encoding": "gzip, br", "limit": n} (0: no limit), its body the bytes; the
 * result frame is {"complete": bool, "error"?: text} + the decoded bytes, at
 * most limit of them. A cut input gives what decoded before the cut. Since
 * 0.33. */
CURLPRO_API char *curlpro_decode(const char *frame, int frame_len, int *out_len);

/* ---- Streamed request bodies (0.31) --------------------------------------- */
/*
 * A request with "body_stream": true carries no body in its frame. Start it
 * with curlpro_request_start or curlpro_stream_open_start and write the body to
 * the request's handle while it is in flight; on HTTP/2 and HTTP/3 the response
 * may be read while the body is still being written (full duplex).
 */

/* Writes the next part of the body; blocks until the transport has taken the
 * bytes. data: {"written": n}. "conn_closed" once the request no longer reads. */
CURLPRO_API char *curlpro_request_body_write(curlpro_handle request, const char *buf, int buf_len);

/* Ends the body. trailers_json: {name: value or [values]}, or "" / NULL. */
CURLPRO_API char *curlpro_request_body_end(curlpro_handle request, const char *trailers_json);

/* ---- Upgrade and raw connections (0.31) ----------------------------------- */

/* Sends a request asking to switch protocols (Upgrade) on a connection of its
 * own, with the profile's TLS and HTTP/1.1. frame out: envelope with data
 * {status, proto, headers, url, body_len, conn} + the body of a refusal; conn
 * (a handle) only after 101. Nothing is added to or checked in the exchange:
 * after 101 the bytes are the caller's, both ways. */
CURLPRO_API char *curlpro_upgrade_open(curlpro_handle session, const char *frame, int frame_len, int *out_len);
CURLPRO_API char *curlpro_upgrade_open_start(curlpro_handle session, const char *frame, int frame_len);

/* Reads into buf: the byte count, 0 when the peer closed its side, -1 on an
 * error (curlpro_conn_error has it). Blocks until bytes arrive. */
CURLPRO_API int curlpro_conn_read(curlpro_handle conn, char *buf, int buf_len);

/* Writes buf whole: the byte count, or -1 on an error. */
CURLPRO_API int curlpro_conn_write(curlpro_handle conn, const char *buf, int buf_len);

/* The stored error of a failed read or write, as an envelope. */
CURLPRO_API char *curlpro_conn_error(curlpro_handle conn);

/* Asynchronous read ({"eof": bool} + bytes) and write ({"written": n}; buf is
 * copied before the call returns). */
CURLPRO_API char *curlpro_conn_read_start(curlpro_handle conn, int buf_len);
CURLPRO_API char *curlpro_conn_write_start(curlpro_handle conn, const char *buf, int buf_len);

/* A TLS connection with the profile's ClientHello for a protocol that is not
 * HTTP (MQTT, XMPP, an app's own), handed over raw like an upgraded one.
 * config: {host, port, alpn ([] none, absent the profile's), proxy,
 * connect_timeout_ms}. data: {"conn": <handle>, "info": {…}}. Since 0.32. */
CURLPRO_API char *curlpro_tls_dial(curlpro_handle session, const char *config_json);

/* Opens the connection a first request to the URL would open — ClientHello,
 * ALPN, the HTTP/2 preface — without a request, and leaves it in the pool.
 * request: a request's JSON (curlpro_request's meta: url, connection "new",
 * proxy, protocol, timeouts). data: {"info": {…}}, a response's conn with the
 * server's peer_settings and peer_window_update; "connection": info.id sends a
 * request on it. TCP only. The _start form answers on the ready queue.
 * Since 0.36. */
CURLPRO_API char *curlpro_preconnect(curlpro_handle session, const char *request_json);
CURLPRO_API char *curlpro_preconnect_start(curlpro_handle session, const char *request_json);

/* A profile from what a client sent — its ClientHello, its HTTP/2 preface,
 * frames and header blocks, its QUIC Initial, its HTTP/3 control stream —
 * as the profile object session_new takes. wire: {name, based_on,
 * client_hello, h2 (one connection's bytes or a list), quic_initial [],
 * h3_control}, all base64. data: {"profile": {…}, "notes": […]}: only what
 * the bytes show is set, based_on supplies the rest. Since 0.36. */
CURLPRO_API char *curlpro_profile_from_wire(const char *wire_json);

/* A session with "dial": "caller" asks for every connection it would open,
 * TCP and (since 0.38) QUIC's UDP: the ready queue carries {"dial": {conn,
 * session, host, port, request, local_address, udp}} under a number of its
 * own. conn is the caller's end of a pipe: curlpro_conn_read what curlpro
 * sends and put it on the caller's transport, curlpro_conn_write what comes
 * back — on a "udp" ask one datagram per call. result: "" when the connection is up,
 * {"error": text, "code": connect_refused | connect_unreachable | dns |
 * timeout | reset} when it failed. Closing conn first fails the dial too.
 * Since 0.37. */
CURLPRO_API char *curlpro_dial_result(curlpro_handle conn, const char *result_json);

/* Ends the caller's direction (TLS close_notify / FIN), reading stays open. */
CURLPRO_API char *curlpro_conn_close_write(curlpro_handle conn);

CURLPRO_API char *curlpro_conn_close(curlpro_handle conn);

/* ---- WebSocket ------------------------------------------------------------- */

/* config: JSON {url, headers, subprotocols, timeout_ms, connect_timeout_ms,
 * max_message_size, proxy}. data: {"socket": <handle>} */
CURLPRO_API char *curlpro_ws_connect(curlpro_handle session, const char *config_json);

/* frame in: JSON {"binary": bool, "ping": bool} + message bytes. */
CURLPRO_API char *curlpro_ws_send(curlpro_handle socket, const char *frame, int frame_len, int *out_len);

/* frame out: envelope with data {"binary": bool} + message bytes. Blocks until a
 * message arrives; the code "ws_closed" means the peer closed the socket. */
CURLPRO_API char *curlpro_ws_recv(curlpro_handle socket, int *out_len);

CURLPRO_API char *curlpro_ws_close(curlpro_handle socket, int code, const char *reason);

/* ---- Asynchronous calls ------------------------------------------------------ */
/*
 * The *_start functions return at once with data {"request": <handle>}. The
 * result is collected later:
 *   curlpro_result_wait(timeout_ms) -> the handle of a finished call, or 0 when
 *       none finished within the timeout (timeout_ms <= 0 polls without waiting);
 *   curlpro_result_take(handle, &len) -> the call's result as a frame, exactly
 *       what the blocking variant would have returned.
 */
CURLPRO_API char *curlpro_request_start(curlpro_handle session, const char *frame, int frame_len);
CURLPRO_API char *curlpro_stream_open_start(curlpro_handle session, const char *frame, int frame_len);
CURLPRO_API char *curlpro_stream_read_start(curlpro_handle stream, int buf_len);
CURLPRO_API char *curlpro_ws_connect_start(curlpro_handle session, const char *config_json);
CURLPRO_API char *curlpro_ws_send_start(curlpro_handle socket, const char *frame, int frame_len);
CURLPRO_API char *curlpro_ws_recv_start(curlpro_handle socket);

CURLPRO_API long long curlpro_result_wait(int timeout_ms);
/* A request started with "interim_events": true also yields a result per 1xx
 * response, {"interim": {status, headers}}, under its own handle before the
 * final one: take until the frame is not an interim one (0.34). */
CURLPRO_API char *curlpro_result_take(curlpro_handle request, int *out_len);
CURLPRO_API char *curlpro_request_cancel(curlpro_handle request);

/* A handle an event loop waits on beside its sockets instead of a thread in
 * curlpro_result_wait: data {"handle": n, "kind": "event"} on Windows (a
 * manual-reset event), {"handle": n, "kind": "fd"} elsewhere (a pipe's read
 * end). Signalled while finished calls wait: take them with
 * curlpro_result_wait(0) until it returns 0, which lowers it. The same handle
 * for the life of the process; do not close it. Since 0.33. */
CURLPRO_API char *curlpro_result_event(void);

/* Number of async calls started and not yet taken. */
CURLPRO_API long long curlpro_async_pending(void);

/* ---- Diagnostics ------------------------------------------------------------- */

/* data: counts of live sessions, streams, sockets, raw connections, streamed
 * bodies and pending calls. */
CURLPRO_API char *curlpro_debug_counts(void);

#ifdef __cplusplus
}
#endif

#endif /* CURLPRO_H */
