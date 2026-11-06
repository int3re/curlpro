package io.curlpro;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * One browser: its TLS and HTTP/2/3 fingerprint, connection pool, cookies and
 * headers. Thread-safe; requests run in parallel. Close it.
 */
public final class Session implements AutoCloseable {
    public static final String DEFAULT_PROFILE = "chrome-156-windows";

    /**
     * Session settings. The defaults are the browser's, as in the Python Session;
     * the ABI's own zero values are not (a missing boolean is false there).
     */
    public static final class Options {
        final Map<String, Object> json = new LinkedHashMap<>();

        public Options() {
            json.put("profile", DEFAULT_PROFILE);
            json.put("timeout_ms", 30_000);
            json.put("default_headers", true);
            json.put("follow_redirects", true);
            json.put("max_redirects", 20);
            json.put("cookies", true);
            json.put("resume", true);
            json.put("trust_env", true);
        }

        public Options profile(String name) { return set("profile", name); }
        public Options timeout(Duration d) { return set("timeout_ms", d.toMillis()); }
        public Options proxy(String url) { return set("proxy", url); }
        public Options http3(boolean on) { return set("http3", on); }
        public Options forceHttp1(boolean on) { return set("force_http1", on); }
        public Options followRedirects(boolean on) { return set("follow_redirects", on); }
        public Options cookies(boolean on) { return set("cookies", on); }
        public Options insecureSkipVerify(boolean on) { return set("insecure_skip_verify", on); }
        /** "navigate", "fetch" or null (auto). */
        public Options mode(String mode) { return set("mode", mode); }
        /** The initiator page: Referer, Origin and Sec-Fetch-Site follow from it. */
        public Options page(String url) { return set("page", url); }

        /** Any other session field of docs/C-ABI.md, sent as is. */
        public Options set(String field, Object value) {
            json.put(field, value);
            return this;
        }
    }

    private volatile long id;
    private final String profile;

    public Session() { this(new Options()); }

    public Session(String profile) { this(new Options().profile(profile)); }

    @SuppressWarnings("unchecked")
    public Session(Options options) {
        Curlpro.ensureProfiles();
        this.profile = (String) options.json.get("profile");
        var data = (Map<String, Object>) Native.call(Native.session_new, Json.stringify(options.json));
        this.id = ((Number) data.get("session")).longValue();
    }

    public String profile() { return profile; }

    long id() {
        long v = id;
        if (v == 0) throw new CurlproException("the session is closed", "session_closed", null);
        return v;
    }

    // ---- requests -------------------------------------------------------------------

    /** Sends a request and blocks until the whole response is in. */
    @SuppressWarnings("unchecked")
    public Response send(Request request) {
        var f = Native.callFramed(Native.request, id(), request.toFrame());
        return new Response((Map<String, Object>) f.data(), f.body());
    }

    /** Sends a request without holding a thread; cancel() on the future aborts it. */
    @SuppressWarnings("unchecked")
    public CompletableFuture<Response> sendAsync(Request request) {
        byte[] frame = request.toFrame();
        long sid = id();
        return Completions.run(() -> {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment in = arena.allocate(Math.max(frame.length, 1));
                MemorySegment.copy(frame, 0, in, java.lang.foreign.ValueLayout.JAVA_BYTE, 0, frame.length);
                return (MemorySegment) Native.request_start.invoke(sid, in, frame.length);
            } catch (Throwable t) {
                throw new CurlproException("native call failed: " + t, null, null);
            }
        }).thenApply(f -> new Response((Map<String, Object>) f.data(), f.body()));
    }

    public Response get(String url) { return send(Request.get(url)); }

    public CompletableFuture<Response> getAsync(String url) { return sendAsync(Request.get(url)); }

    public Response post(String url, String contentType, byte[] body) {
        return send(Request.post(url).header("content-type", contentType).body(body));
    }

    public Response post(String url, String contentType, String body) {
        return post(url, contentType, body.getBytes(StandardCharsets.UTF_8));
    }

    /** Opens a response as a stream: returns once the headers are in. */
    @SuppressWarnings("unchecked")
    public ResponseStream stream(Request request) {
        var f = Native.callFramed(Native.stream_open, id(), request.toFrame());
        return new ResponseStream((Map<String, Object>) f.data());
    }

    /** A WebSocket whose upgrade carries the profile's fingerprint. */
    @SuppressWarnings("unchecked")
    public WebSocket websocket(String url, Map<String, String> headers, List<String> subprotocols, Duration timeout) {
        var cfg = new LinkedHashMap<String, Object>();
        cfg.put("url", url);
        if (headers != null) cfg.put("headers", headers);
        if (subprotocols != null) cfg.put("subprotocols", subprotocols);
        if (timeout != null) cfg.put("timeout_ms", timeout.toMillis());
        var data = (Map<String, Object>) Native.call(Native.ws_connect, id(), Json.stringify(cfg));
        return new WebSocket(((Number) data.get("socket")).longValue());
    }

    public WebSocket websocket(String url) { return websocket(url, null, null, null); }

    // ---- what a server would see -------------------------------------------------------

    /** ja3, ja3n, ja4, akamai… for this URL, computed without sending anything. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> fingerprint(String url) {
        return (Map<String, Object>) Native.call(Native.session_fingerprint, id(), url);
    }

    /** The headers a request would carry, in order, without sending it. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> preview(String method, String url, Map<String, String> headers) {
        var spec = new LinkedHashMap<String, Object>();
        spec.put("method", method);
        spec.put("url", url);
        if (headers != null) spec.put("headers", headers);
        return (Map<String, Object>) Native.call(Native.session_preview, id(), Json.stringify(spec));
    }

    // ---- headers, page, cookies -------------------------------------------------------------

    public void setHeader(String name, String value) { Native.call(Native.session_set_header, id(), name, value); }

    @SuppressWarnings("unchecked")
    public boolean removeHeader(String name) {
        return Boolean.TRUE.equals(((Map<String, Object>) Native.call(Native.session_remove_header, id(), name)).get("removed"));
    }

    /** Never send this header, even when the profile would. */
    public void suppressHeader(String name) { Native.call(Native.session_suppress_header, id(), name); }

    public void resetHeaders() { Native.call(Native.session_reset_headers, id()); }

    public void setPage(String url) { Native.call(Native.session_set_page, id(), url); }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> cookies() {
        var data = (Map<String, Object>) Native.call(Native.session_cookies, id());
        Object list = data == null ? null : data.get("cookies");
        return list == null ? List.of() : (List<Map<String, Object>>) list;
    }

    public void setCookies(List<Map<String, Object>> cookies) { Native.call(Native.session_set_cookies, id(), Json.stringify(cookies)); }

    public void clearCookies() { Native.call(Native.session_clear_cookies, id()); }

    @SuppressWarnings("unchecked")
    public Map<String, Object> cacheInfo() { return (Map<String, Object>) Native.call(Native.session_cache_info, id()); }

    @Override
    public synchronized void close() {
        long v = id;
        id = 0;
        if (v != 0) Native.call(Native.session_close, v);
    }
}
