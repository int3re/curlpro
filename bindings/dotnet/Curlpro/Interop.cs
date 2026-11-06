using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;

namespace Curlpro;

/// <summary>An error the library reported. Branch on <see cref="Code"/>, not on the message.</summary>
public class CurlproException : Exception
{
    /// <summary>timeout, proxy, proxy_auth, proxy_closed, configuration, profile_capability,
    /// cors, too_large, session_closed, ws_closed, ws_too_big, ws_protocol — or null.</summary>
    public string? Code { get; }

    /// <summary>For proxy/proxy_auth: {stage, status}; for cors: {method, url, reason, status, headers}.</summary>
    public JsonObject? Details { get; }

    /// <summary>Retrying the same call cannot change the outcome.</summary>
    public bool Permanent => Code is "configuration" or "profile_capability" or "proxy_auth";

    public CurlproException(string message, string? code = null, JsonObject? details = null) : base(message)
    {
        Code = code;
        Details = details;
    }
}

/// <summary>Envelopes and frames: the two shapes everything crosses the boundary in.</summary>
internal static unsafe class Interop
{
    public const int FrameHeader = 4;

    /// <summary>Takes ownership of a returned envelope, frees it and returns <c>data</c>.</summary>
    public static JsonNode? Envelope(IntPtr p)
    {
        if (p == IntPtr.Zero) throw new CurlproException("the library returned nothing (out of memory?)");
        string json;
        try { json = Marshal.PtrToStringUTF8(p) ?? ""; }
        finally { Native.curlpro_free(p); }
        return Unwrap(JsonNode.Parse(json)!.AsObject());
    }

    public static JsonNode? Unwrap(JsonObject env)
    {
        if (env["ok"]?.GetValue<bool>() == true) return env["data"];
        throw new CurlproException(
            env["error"]?.GetValue<string>() ?? "unknown error",
            env["code"]?.GetValue<string>(),
            env["details"] as JsonObject);
    }

    /// <summary>Takes ownership of a returned frame, frees it and splits it into data and body.</summary>
    public static (JsonNode? Data, byte[] Body) Frame(IntPtr p, int len)
    {
        if (p == IntPtr.Zero) throw new CurlproException("the library returned nothing (out of memory?)");
        try
        {
            var span = new ReadOnlySpan<byte>((void*)p, len);
            if (len < FrameHeader) throw new CurlproException($"frame shorter than its header: {len} bytes");
            int metaLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(span);
            var env = JsonNode.Parse(span.Slice(FrameHeader, metaLen))!.AsObject();
            var body = span[(FrameHeader + metaLen)..].ToArray();
            return (Unwrap(env), body);
        }
        finally { Native.curlpro_free(p); }
    }

    /// <summary>[uint32 LE JSON length][JSON][body].</summary>
    public static byte[] MakeFrame(JsonNode meta, ReadOnlySpan<byte> body)
    {
        var json = Encoding.UTF8.GetBytes(meta.ToJsonString());
        var frame = new byte[FrameHeader + json.Length + body.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(frame, (uint)json.Length);
        json.CopyTo(frame, FrameHeader);
        body.CopyTo(frame.AsSpan(FrameHeader + json.Length));
        return frame;
    }
}

/// <summary>The native library as a whole.</summary>
public static class Library
{
    /// <summary>The ABI this binding was written against; an older library is refused.</summary>
    public static readonly Version Required = new(0, 30);

    private static readonly Lazy<string> _version = new(() =>
    {
        var v = Interop.Envelope(Native.curlpro_version())!["version"]!.GetValue<string>();
        var parts = v.Split('.');
        var got = new Version(int.Parse(parts[0]), int.Parse(parts[1]));
        if (got < Required)
            throw new CurlproException(
                $"libcurlpro {v} is older than the required {Required}.x: it would silently ignore options");
        return v;
    });

    /// <summary>The library's version; loading and checking it on first use.</summary>
    public static string Version => _version.Value;

    /// <summary>Sessions, streams, sockets and pending calls still registered — for leak tests.</summary>
    public static JsonObject DebugCounts() => Interop.Envelope(Native.curlpro_debug_counts())!.AsObject();

    /// <summary>Asynchronous calls started and not yet collected.</summary>
    public static long AsyncPending => Native.curlpro_async_pending();
}

/// <summary>The process-wide profile registry. It starts empty.</summary>
public static class Profiles
{
    private static readonly object Gate = new();
    private static bool _autoloaded;

    /// <summary>Loads every *.json profile under a directory.</summary>
    public static IReadOnlyList<string> LoadDir(string dir) =>
        Names(Interop.Envelope(Native.curlpro_profiles_load_dir(dir)));

    /// <summary>Loads a signed bundle (profiles.json.gz + .sig). keys: extra base64 Ed25519 keys, comma-separated.</summary>
    public static IReadOnlyList<string> LoadBundle(string path, string? keys = null) =>
        Names(Interop.Envelope(Native.curlpro_profiles_load_bundle(path,
            keys ?? Environment.GetEnvironmentVariable("CURLPRO_BUNDLE_KEYS") ?? "")));

    /// <summary>Registers one profile from JSON; it may be <c>based_on</c> a registered one
    /// (the stock profiles are loaded first, as for a session).</summary>
    public static IReadOnlyList<string> Register(string profileJson)
    {
        EnsureLoaded();
        return Names(Interop.Envelope(Native.curlpro_profile_register(profileJson)));
    }

    public static IReadOnlyList<string> List() => Names(Interop.Envelope(Native.curlpro_profiles_list()));

    /// <summary>The profile with inheritance resolved.</summary>
    public static JsonObject Get(string name)
    {
        EnsureLoaded();
        return Interop.Envelope(Native.curlpro_profile_get(name))!.AsObject();
    }

    /// <summary>What the profile can do (fetch headers, HTTP/3, devices…) without opening a session.</summary>
    public static JsonObject Capabilities(string name)
    {
        EnsureLoaded();
        return Interop.Envelope(Native.curlpro_profile_capabilities(name))!.AsObject();
    }

    /// <summary>
    /// Loads profiles once when the registry is empty: CURLPRO_PROFILES, else a <c>profiles</c>
    /// directory next to the application; then the signed bundle the Python package caches.
    /// </summary>
    public static void EnsureLoaded()
    {
        _ = Library.Version;
        lock (Gate)
        {
            if (_autoloaded) return;
            _autoloaded = true;
            if (List().Count > 0) return;
            var dir = Environment.GetEnvironmentVariable("CURLPRO_PROFILES");
            if (string.IsNullOrEmpty(dir)) dir = Path.Combine(AppContext.BaseDirectory, "profiles");
            if (Directory.Exists(dir)) LoadDir(dir);
            var bundle = Path.Combine(CacheDir(), "profiles.json.gz");
            if (File.Exists(bundle) && File.Exists(bundle + ".sig"))
            {
                try { LoadBundle(bundle); }
                catch (CurlproException) { /* a stale or foreign bundle: the directory is enough */ }
            }
        }
    }

    private static string CacheDir()
    {
        var env = Environment.GetEnvironmentVariable("CURLPRO_CACHE_DIR");
        if (!string.IsNullOrEmpty(env)) return env;
        if (OperatingSystem.IsWindows())
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "curlpro");
        if (OperatingSystem.IsMacOS())
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Library", "Caches", "curlpro");
        var xdg = Environment.GetEnvironmentVariable("XDG_CACHE_HOME");
        return Path.Combine(string.IsNullOrEmpty(xdg)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cache") : xdg, "curlpro");
    }

    private static IReadOnlyList<string> Names(JsonNode? data) =>
        data?["profiles"]?.AsArray().Select(n => n!.GetValue<string>()).ToList() ?? [];
}
