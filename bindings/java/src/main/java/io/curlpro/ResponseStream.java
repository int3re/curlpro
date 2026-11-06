package io.curlpro;

import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Map;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/** A response whose body is read in pieces, as an InputStream. Close it. */
public final class ResponseStream extends InputStream {
    private volatile long id;
    private final int status;
    private final String proto;
    private final String url;
    private final Map<String, Object> raw;

    ResponseStream(Map<String, Object> data) {
        this.id = ((Number) data.get("stream")).longValue();
        this.status = ((Number) data.getOrDefault("status", 0)).intValue();
        this.proto = (String) data.getOrDefault("proto", "");
        this.url = (String) data.getOrDefault("url", "");
        this.raw = data;
    }

    public int status() { return status; }
    public String proto() { return proto; }
    public String url() { return url; }
    public Map<String, Object> raw() { return raw; }

    @Override
    public int read() {
        byte[] one = new byte[1];
        int n = read(one, 0, 1);
        return n <= 0 ? -1 : one[0] & 0xff;
    }

    @Override
    public int read(byte[] b, int off, int len) {
        if (len == 0) return 0;
        long v = id;
        if (v == 0) return -1;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buf = arena.allocate(len);
            int n = (int) Native.stream_read.invoke(v, buf, len);
            if (n < 0) Native.envelope((MemorySegment) Native.stream_error.invoke(v)); // throws the stored error
            if (n <= 0) return -1;
            MemorySegment.copy(buf, JAVA_BYTE, 0, b, off, n);
            return n;
        } catch (CurlproException e) {
            throw e;
        } catch (Throwable t) {
            throw new CurlproException("native call failed: " + t, null, null);
        }
    }

    @Override
    public synchronized void close() {
        long v = id;
        id = 0;
        if (v != 0) Native.call(Native.stream_close, v);
    }
}
