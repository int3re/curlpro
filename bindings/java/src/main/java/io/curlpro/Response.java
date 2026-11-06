package io.curlpro;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** A response with its body read whole (already decompressed). */
public final class Response {
    private final int status;
    private final String proto;
    private final String url;
    private final Map<String, List<String>> headers;
    private final byte[] body;
    private final Map<String, Object> raw;

    @SuppressWarnings("unchecked")
    Response(Map<String, Object> data, byte[] body) {
        this.raw = data;
        this.status = ((Number) data.getOrDefault("status", 0)).intValue();
        this.proto = (String) data.getOrDefault("proto", "");
        this.url = (String) data.getOrDefault("url", "");
        var h = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
        var src = (Map<String, Object>) data.get("headers");
        if (src != null) src.forEach((k, v) -> h.put(k, (List<String>) (List<?>) v));
        this.headers = h;
        this.body = body;
    }

    public int status() { return status; }

    /** "HTTP/1.1", "HTTP/2.0" or "HTTP/3.0". */
    public String proto() { return proto; }

    /** The final URL, after redirects. */
    public String url() { return url; }

    /** Case-insensitive; repeated headers keep every value. */
    public Map<String, List<String>> headers() { return headers; }

    public String header(String name) {
        var v = headers.get(name);
        return v == null || v.isEmpty() ? null : v.get(0);
    }

    public byte[] body() { return body; }

    public String text() { return new String(body, StandardCharsets.UTF_8); }

    /** The body parsed with the binding's small JSON reader (Map, List, String, Long, Double…). */
    public Object json() { return Json.parse(text()); }

    /** history, preflights, cache, cookie_changes: everything the library reported. */
    public Map<String, Object> raw() { return raw; }

    @Override
    public String toString() { return "<Response [" + status + "] " + proto + " " + url + ">"; }
}
