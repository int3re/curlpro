package io.curlpro;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static java.lang.foreign.ValueLayout.JAVA_INT;

/** A WebSocket whose upgrade carried the profile's fingerprint. Close it. */
public final class WebSocket implements AutoCloseable {
    /** One received message. */
    public record Message(boolean binary, byte[] data) {
        public String text() { return new String(data, StandardCharsets.UTF_8); }
    }

    private volatile long id;

    WebSocket(long id) { this.id = id; }

    private long id() {
        long v = id;
        if (v == 0) throw new CurlproException("the socket is closed", "ws_closed", null);
        return v;
    }

    public void send(String text) { send(false, false, text.getBytes(StandardCharsets.UTF_8)); }

    public void send(byte[] data) { send(true, false, data); }

    public void ping(byte[] data) { send(false, true, data == null ? new byte[0] : data); }

    /** Blocks for the next message; throws CurlproException with code "ws_closed" once closed. */
    public Message receive() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment outLen = arena.allocate(JAVA_INT);
            var p = (MemorySegment) Native.ws_recv.invoke(id(), outLen);
            var f = Native.frame(p, outLen.get(JAVA_INT, 0));
            var data = (Map<?, ?>) f.data();
            return new Message(data != null && Boolean.TRUE.equals(data.get("binary")), f.body());
        } catch (CurlproException e) {
            throw e;
        } catch (Throwable t) {
            throw new CurlproException("native call failed: " + t, null, null);
        }
    }

    private void send(boolean binary, boolean ping, byte[] payload) {
        Native.callFramed(Native.ws_send, id(), Native.makeFrame(Map.of("binary", binary, "ping", ping), payload));
    }

    public void close(int code, String reason) {
        long v = id;
        id = 0;
        if (v != 0) Native.call(Native.ws_close, v, code, reason);
    }

    @Override
    public void close() { close(1000, ""); }
}
