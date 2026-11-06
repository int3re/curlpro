package io.curlpro;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/** The exports of include/curlpro.h through the Foreign Function and Memory API (JDK 22+). */
final class Native {
    private Native() {}

    static final int FRAME_HEADER = 4;

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LIB = SymbolLookup.libraryLookup(find(), Arena.global());

    /**
     * CURLPRO_LIBRARY, the curlpro.library system property, the working directory,
     * the library packed into the jar (io/curlpro/native/&lt;platform&gt;/), then the
     * loader's search path.
     */
    private static Path find() {
        String env = System.getenv("CURLPRO_LIBRARY");
        if (env != null && !env.isEmpty()) return Path.of(env);
        String prop = System.getProperty("curlpro.library");
        if (prop != null && !prop.isEmpty()) return Path.of(prop);
        String file = libraryFile();
        Path local = Path.of(file).toAbsolutePath();
        if (Files.exists(local)) return local;
        Path packed = extract("native/" + platform() + "/" + file, file);
        return packed != null ? packed : Path.of(System.mapLibraryName("curlpro"));
    }

    static String libraryFile() {
        String os = System.getProperty("os.name").toLowerCase();
        return os.contains("win") ? "curlpro.dll" : os.contains("mac") ? "libcurlpro.dylib" : "libcurlpro.so";
    }

    /** The platform name the packages use: win32-x64, linux-arm64, darwin-arm64… */
    static String platform() {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();
        String o = os.contains("win") ? "win32" : os.contains("mac") ? "darwin" : "linux";
        String a = arch.equals("aarch64") || arch.equals("arm64") ? "arm64" : "x64";
        return o + "-" + a;
    }

    /**
     * Copies a resource of the jar (under io/curlpro/) to a private temporary
     * directory: a native library has to be a file to be loaded. Null when the
     * jar does not carry it.
     */
    static Path extract(String resource, String name) {
        try (var in = Native.class.getResourceAsStream(resource)) {
            if (in == null) return null;
            Path dir = Files.createTempDirectory("curlpro-");
            Path out = dir.resolve(name);
            // deleteOnExit runs in reverse order: the directory goes last, once empty.
            dir.toFile().deleteOnExit();
            Files.copy(in, out);
            out.toFile().deleteOnExit();
            return out;
        } catch (java.io.IOException e) {
            return null;
        }
    }

    private static MethodHandle fn(String name, MemoryLayout ret, MemoryLayout... args) {
        var addr = LIB.find(name).orElseThrow(() -> new UnsatisfiedLinkError("libcurlpro has no " + name));
        var desc = ret == null ? FunctionDescriptor.ofVoid(args) : FunctionDescriptor.of(ret, args);
        return LINKER.downcallHandle(addr, desc);
    }

    static final MethodHandle free = fn("curlpro_free", null, ADDRESS);
    static final MethodHandle version = fn("curlpro_version", ADDRESS);
    static final MethodHandle profiles_load_dir = fn("curlpro_profiles_load_dir", ADDRESS, ADDRESS);
    static final MethodHandle profiles_load_bundle = fn("curlpro_profiles_load_bundle", ADDRESS, ADDRESS, ADDRESS);
    static final MethodHandle profile_register = fn("curlpro_profile_register", ADDRESS, ADDRESS);
    static final MethodHandle profiles_list = fn("curlpro_profiles_list", ADDRESS);
    static final MethodHandle profile_capabilities = fn("curlpro_profile_capabilities", ADDRESS, ADDRESS);
    static final MethodHandle profile_get = fn("curlpro_profile_get", ADDRESS, ADDRESS);
    static final MethodHandle session_new = fn("curlpro_session_new", ADDRESS, ADDRESS);
    static final MethodHandle session_close = fn("curlpro_session_close", ADDRESS, JAVA_LONG);
    static final MethodHandle session_fingerprint = fn("curlpro_session_fingerprint", ADDRESS, JAVA_LONG, ADDRESS);
    static final MethodHandle session_preview = fn("curlpro_session_preview", ADDRESS, JAVA_LONG, ADDRESS);
    static final MethodHandle session_set_header = fn("curlpro_session_set_header", ADDRESS, JAVA_LONG, ADDRESS, ADDRESS);
    static final MethodHandle session_remove_header = fn("curlpro_session_remove_header", ADDRESS, JAVA_LONG, ADDRESS);
    static final MethodHandle session_suppress_header = fn("curlpro_session_suppress_header", ADDRESS, JAVA_LONG, ADDRESS);
    static final MethodHandle session_reset_headers = fn("curlpro_session_reset_headers", ADDRESS, JAVA_LONG);
    static final MethodHandle session_set_page = fn("curlpro_session_set_page", ADDRESS, JAVA_LONG, ADDRESS);
    static final MethodHandle session_cookies = fn("curlpro_session_cookies", ADDRESS, JAVA_LONG);
    static final MethodHandle session_set_cookies = fn("curlpro_session_set_cookies", ADDRESS, JAVA_LONG, ADDRESS);
    static final MethodHandle session_clear_cookies = fn("curlpro_session_clear_cookies", ADDRESS, JAVA_LONG);
    static final MethodHandle session_cache_info = fn("curlpro_session_cache_info", ADDRESS, JAVA_LONG);
    static final MethodHandle request = fn("curlpro_request", ADDRESS, JAVA_LONG, ADDRESS, JAVA_INT, ADDRESS);
    static final MethodHandle stream_open = fn("curlpro_stream_open", ADDRESS, JAVA_LONG, ADDRESS, JAVA_INT, ADDRESS);
    static final MethodHandle stream_read = fn("curlpro_stream_read", JAVA_INT, JAVA_LONG, ADDRESS, JAVA_INT);
    static final MethodHandle stream_error = fn("curlpro_stream_error", ADDRESS, JAVA_LONG);
    static final MethodHandle stream_close = fn("curlpro_stream_close", ADDRESS, JAVA_LONG);
    static final MethodHandle ws_connect = fn("curlpro_ws_connect", ADDRESS, JAVA_LONG, ADDRESS);
    static final MethodHandle ws_send = fn("curlpro_ws_send", ADDRESS, JAVA_LONG, ADDRESS, JAVA_INT, ADDRESS);
    static final MethodHandle ws_recv = fn("curlpro_ws_recv", ADDRESS, JAVA_LONG, ADDRESS);
    static final MethodHandle ws_close = fn("curlpro_ws_close", ADDRESS, JAVA_LONG, JAVA_INT, ADDRESS);
    static final MethodHandle request_start = fn("curlpro_request_start", ADDRESS, JAVA_LONG, ADDRESS, JAVA_INT);
    static final MethodHandle result_wait = fn("curlpro_result_wait", JAVA_LONG, JAVA_INT);
    static final MethodHandle result_take = fn("curlpro_result_take", ADDRESS, JAVA_LONG, ADDRESS);
    static final MethodHandle request_cancel = fn("curlpro_request_cancel", ADDRESS, JAVA_LONG);
    static final MethodHandle async_pending = fn("curlpro_async_pending", JAVA_LONG);
    static final MethodHandle debug_counts = fn("curlpro_debug_counts", ADDRESS);

    // ---- calls ------------------------------------------------------------------

    /** Invokes a function returning an envelope; args that are Strings become C strings. */
    static Object call(MethodHandle h, Object... args) {
        try (Arena arena = Arena.ofConfined()) {
            Object[] a = new Object[args.length];
            for (int i = 0; i < args.length; i++) a[i] = args[i] instanceof String s ? arena.allocateFrom(s) : args[i];
            return envelope((MemorySegment) h.invokeWithArguments(a));
        } catch (CurlproException e) {
            throw e;
        } catch (Throwable t) {
            throw new CurlproException("native call failed: " + t, null, null);
        }
    }

    /** Invokes a function taking a frame and returning one; the last argument is *out_len. */
    static Frame callFramed(MethodHandle h, long handle, byte[] frame) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment in = arena.allocate(Math.max(frame.length, 1));
            MemorySegment.copy(frame, 0, in, JAVA_BYTE, 0, frame.length);
            MemorySegment outLen = arena.allocate(JAVA_INT);
            var p = (MemorySegment) h.invoke(handle, in, frame.length, outLen);
            return frame(p, outLen.get(JAVA_INT, 0));
        } catch (CurlproException e) {
            throw e;
        } catch (Throwable t) {
            throw new CurlproException("native call failed: " + t, null, null);
        }
    }

    static void freeQuietly(MemorySegment p) {
        try { free.invoke(p); } catch (Throwable ignored) { /* nothing to recover */ }
    }

    // ---- envelopes and frames -------------------------------------------------------

    record Frame(Object data, byte[] body) {}

    /** Takes ownership of an envelope, frees it and returns data or throws. */
    static Object envelope(MemorySegment p) {
        if (p.address() == 0) throw new CurlproException("the library returned nothing (out of memory?)", null, null);
        String json;
        try { json = p.reinterpret(Long.MAX_VALUE).getString(0); } finally { freeQuietly(p); }
        return unwrap(Json.parse(json));
    }

    /** Takes ownership of a frame, frees it and splits it. */
    static Frame frame(MemorySegment p, int len) {
        if (p.address() == 0) throw new CurlproException("the library returned nothing (out of memory?)", null, null);
        try {
            byte[] all = p.reinterpret(len).toArray(JAVA_BYTE);
            int metaLen = ByteBuffer.wrap(all, 0, FRAME_HEADER).order(ByteOrder.LITTLE_ENDIAN).getInt();
            String json = new String(all, FRAME_HEADER, metaLen, StandardCharsets.UTF_8);
            byte[] body = java.util.Arrays.copyOfRange(all, FRAME_HEADER + metaLen, all.length);
            return new Frame(unwrap(Json.parse(json)), body);
        } finally {
            freeQuietly(p);
        }
    }

    @SuppressWarnings("unchecked")
    static Object unwrap(Object parsed) {
        var env = (Map<String, Object>) parsed;
        if (Boolean.TRUE.equals(env.get("ok"))) return env.get("data");
        throw new CurlproException(
                env.getOrDefault("error", "unknown error").toString(),
                (String) env.get("code"),
                (Map<String, Object>) env.get("details"));
    }

    static byte[] makeFrame(Object meta, byte[] body) {
        byte[] json = Json.stringify(meta).getBytes(StandardCharsets.UTF_8);
        byte[] b = body == null ? new byte[0] : body;
        var buf = ByteBuffer.allocate(FRAME_HEADER + json.length + b.length).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(json.length).put(json).put(b);
        return buf.array();
    }
}
