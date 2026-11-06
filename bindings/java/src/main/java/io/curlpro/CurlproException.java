package io.curlpro;

import java.util.Map;

/** An error the library reported. Branch on {@link #code()}, not on the message. */
public class CurlproException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String code;
    private final transient Map<String, Object> details;

    public CurlproException(String message, String code, Map<String, Object> details) {
        super(message);
        this.code = code;
        this.details = details;
    }

    /**
     * timeout, proxy, proxy_auth, proxy_closed, configuration, profile_capability, cors,
     * too_large, session_closed, ws_closed, ws_too_big, ws_protocol — or null.
     */
    public String code() { return code; }

    /** proxy/proxy_auth: {stage, status}; cors: {method, url, reason, status, headers}; else null. */
    public Map<String, Object> details() { return details; }

    /** Retrying the same call cannot change the outcome. */
    public boolean permanent() {
        return "configuration".equals(code) || "profile_capability".equals(code) || "proxy_auth".equals(code);
    }
}
