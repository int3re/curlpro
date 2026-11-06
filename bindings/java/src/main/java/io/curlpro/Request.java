package io.curlpro;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/** One request. Headers are merged into the profile's and sent in the profile's order. */
public final class Request {
    private final Map<String, Object> json = new LinkedHashMap<>();
    private final Map<String, String> headers = new LinkedHashMap<>();
    private byte[] body = new byte[0];

    public Request(String method, String url) {
        json.put("method", method);
        json.put("url", url);
    }

    public static Request get(String url) { return new Request("GET", url); }

    public static Request post(String url) { return new Request("POST", url); }

    public Request header(String name, String value) {
        headers.put(name, value);
        return this;
    }

    public Request body(byte[] body) {
        this.body = body == null ? new byte[0] : body;
        return this;
    }

    public Request body(String body) { return body(body.getBytes(StandardCharsets.UTF_8)); }

    public Request timeout(Duration d) { return set("timeout_ms", d.toMillis()); }

    /** "http1", "h2" or "h3" to force one. */
    public Request protocol(String protocol) { return set("protocol", protocol); }

    /** Any other request field of docs/C-ABI.md ("proxy", "mode", "page", "suppress_headers"…), sent as is. */
    public Request set(String field, Object value) {
        json.put(field, value);
        return this;
    }

    byte[] toFrame() {
        var meta = new LinkedHashMap<>(json);
        if (!headers.isEmpty()) meta.put("headers", headers);
        return Native.makeFrame(meta, body);
    }
}
