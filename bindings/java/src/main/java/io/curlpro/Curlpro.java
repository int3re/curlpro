package io.curlpro;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** The native library and its process-wide profile registry (which starts empty). */
public final class Curlpro {
    private Curlpro() {}

    /** The ABI this binding was written against; an older library is refused. */
    public static final int REQUIRED_MAJOR = 0, REQUIRED_MINOR = 30;

    private static volatile String version;
    private static boolean autoloaded;

    /** The library's version, checked against the required one on first use. */
    @SuppressWarnings("unchecked")
    public static String version() {
        if (version != null) return version;
        synchronized (Curlpro.class) {
            if (version == null) {
                var data = (Map<String, Object>) Native.call(Native.version);
                String v = (String) data.get("version");
                String[] p = v.split("\\.");
                int maj = Integer.parseInt(p[0]), min = Integer.parseInt(p[1]);
                if (maj < REQUIRED_MAJOR || (maj == REQUIRED_MAJOR && min < REQUIRED_MINOR))
                    throw new CurlproException("libcurlpro " + v + " is older than the required "
                            + REQUIRED_MAJOR + "." + REQUIRED_MINOR + ".x: it would silently ignore options", null, null);
                version = v;
            }
            return version;
        }
    }

    /** Loads every *.json profile under a directory. */
    public static List<String> loadProfiles(Path dir) { return names(Native.call(Native.profiles_load_dir, dir.toString())); }

    /** Loads a signed bundle (profiles.json.gz + .sig); keys: extra base64 Ed25519 keys, comma-separated, or null. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> loadBundle(Path file, String keys) {
        if (keys == null) keys = System.getenv().getOrDefault("CURLPRO_BUNDLE_KEYS", "");
        return (Map<String, Object>) Native.call(Native.profiles_load_bundle, file.toString(), keys);
    }

    /** Registers one profile from JSON; it may be based_on a registered one (stock profiles load first). */
    public static List<String> registerProfile(String json) {
        ensureProfiles();
        return names(Native.call(Native.profile_register, json));
    }

    public static List<String> profiles() { return names(Native.call(Native.profiles_list)); }

    /** The profile with inheritance resolved. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> profile(String name) {
        ensureProfiles();
        return (Map<String, Object>) Native.call(Native.profile_get, name);
    }

    /** What the profile can do, without opening a session. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> capabilities(String name) {
        ensureProfiles();
        return (Map<String, Object>) Native.call(Native.profile_capabilities, name);
    }

    /** Sessions, streams, sockets and pending calls still registered: for leak tests. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> debugCounts() { return (Map<String, Object>) Native.call(Native.debug_counts); }

    /**
     * Loads profiles once when the registry is empty: CURLPRO_PROFILES, else ./profiles;
     * then the signed bundle the Python package caches.
     */
    public static synchronized void ensureProfiles() {
        version();
        if (autoloaded) return;
        autoloaded = true;
        if (!profiles().isEmpty()) return;
        String env = System.getenv("CURLPRO_PROFILES");
        Path dir = env != null && !env.isEmpty() ? Path.of(env) : Path.of("profiles");
        if (Files.isDirectory(dir)) loadProfiles(dir);
        else if (!loadPackedBundle()) loadPackedProfiles();
        Path bundle = cacheDir().resolve("profiles.json.gz");
        if (Files.exists(bundle) && Files.exists(Path.of(bundle + ".sig"))) {
            try { loadBundle(bundle, null); } catch (CurlproException ignored) { /* the directory is enough */ }
        }
    }

    /** The published jar carries the signed bundle when the release had the signing key. */
    private static boolean loadPackedBundle() {
        Path packed = Native.extract("profiles.json.gz", "profiles.json.gz");
        Path sig = packed == null ? null : Native.extract("profiles.json.gz.sig", "profiles.json.gz.sig");
        if (packed == null || sig == null) return false;
        try {
            Path next = Path.of(packed + ".sig");
            Files.move(sig, next);
            next.toFile().deleteOnExit();
            loadBundle(packed, null);
            return true;
        } catch (java.io.IOException | CurlproException e) {
            return false;
        }
    }

    /** And always the profiles themselves, listed in profiles/index.txt (scripts/package-bindings.py). */
    private static void loadPackedProfiles() {
        try (var index = Curlpro.class.getResourceAsStream("profiles/index.txt")) {
            if (index == null) return;
            Path dir = Files.createTempDirectory("curlpro-profiles-");
            dir.toFile().deleteOnExit();
            for (String name : new String(index.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).split("\n")) {
                if (name.isBlank()) continue;
                try (var in = Curlpro.class.getResourceAsStream("profiles/" + name.strip())) {
                    if (in == null) continue;
                    Path out = dir.resolve(name.strip());
                    Files.copy(in, out);
                    out.toFile().deleteOnExit();
                }
            }
            loadProfiles(dir);
        } catch (java.io.IOException ignored) {
            // nothing packed: CURLPRO_PROFILES then
        }
    }

    private static Path cacheDir() {
        String env = System.getenv("CURLPRO_CACHE_DIR");
        if (env != null && !env.isEmpty()) return Path.of(env);
        String os = System.getProperty("os.name").toLowerCase(), home = System.getProperty("user.home");
        if (os.contains("win")) {
            String local = System.getenv("LOCALAPPDATA");
            return Path.of(local != null ? local : home + "/AppData/Local", "curlpro");
        }
        if (os.contains("mac")) return Path.of(home, "Library", "Caches", "curlpro");
        String xdg = System.getenv("XDG_CACHE_HOME");
        return Path.of(xdg != null ? xdg : home + "/.cache", "curlpro");
    }

    @SuppressWarnings("unchecked")
    private static List<String> names(Object data) {
        var m = (Map<String, Object>) data;
        return m == null || m.get("profiles") == null ? List.of() : (List<String>) (List<?>) m.get("profiles");
    }
}
