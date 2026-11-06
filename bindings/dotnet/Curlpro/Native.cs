using System.Reflection;
using System.Runtime.InteropServices;

namespace Curlpro;

/// <summary>The exports of include/curlpro.h, one to one.</summary>
/// <remarks>
/// Every <c>char *</c> the library returns is taken as <see cref="IntPtr"/> and
/// released with <see cref="curlpro_free"/> by <see cref="Interop"/>, never by
/// the marshaller: the string belongs to the library's C runtime.
/// </remarks>
internal static unsafe partial class Native
{
    private const string Lib = "curlpro";

    static Native() => NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, Resolve);

    /// <summary>CURLPRO_LIBRARY, then next to the assembly, then the system search.</summary>
    private static IntPtr Resolve(string name, Assembly assembly, DllImportSearchPath? path)
    {
        if (name != Lib) return IntPtr.Zero;
        var env = Environment.GetEnvironmentVariable("CURLPRO_LIBRARY");
        if (!string.IsNullOrEmpty(env)) return NativeLibrary.Load(env);

        foreach (var file in FileNames())
        {
            // Next to the app, then where the NuGet package puts it for this platform.
            var local = Path.Combine(AppContext.BaseDirectory, file);
            if (File.Exists(local)) return NativeLibrary.Load(local);
            var packaged = Path.Combine(AppContext.BaseDirectory, "runtimes", RuntimeInformation.RuntimeIdentifier, "native", file);
            if (File.Exists(packaged)) return NativeLibrary.Load(packaged);
        }
        foreach (var file in FileNames())
            if (NativeLibrary.TryLoad(file, assembly, path, out var h)) return h;
        throw new DllNotFoundException(
            "libcurlpro was not found: put it next to the application or point CURLPRO_LIBRARY at it");
    }

    private static string[] FileNames() =>
        OperatingSystem.IsWindows() ? ["curlpro.dll"]
        : OperatingSystem.IsMacOS() ? ["libcurlpro.dylib"]
        : ["libcurlpro.so"];

    [LibraryImport(Lib)] internal static partial void curlpro_free(IntPtr s);

    [LibraryImport(Lib)] internal static partial IntPtr curlpro_version();

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_profiles_load_dir(string dir);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_profiles_load_bundle(string path, string keys);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_profile_register(string json);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_profiles_list();
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_profile_capabilities(string name);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_profile_get(string name);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_session_new(string config);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_session_close(long session);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_session_fingerprint(long session, string url);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_session_preview(long session, string spec);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_session_set_header(long session, string name, string value);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_session_remove_header(long session, string name);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_session_suppress_header(long session, string name);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_session_reset_headers(long session);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_session_headers(long session);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_session_set_page(long session, string url);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_session_set_top_level(long session, string url);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_session_cookies(long session);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_session_set_cookies(long session, string json);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_session_clear_cookies(long session);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_session_undo_cookies(long session, string json);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_session_cache_info(long session);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_session_clear_cache(long session);

    [LibraryImport(Lib)]
    internal static partial IntPtr curlpro_request(long session, byte* frame, int frameLen, out int outLen);

    [LibraryImport(Lib)]
    internal static partial IntPtr curlpro_stream_open(long session, byte* frame, int frameLen, out int outLen);
    [LibraryImport(Lib)] internal static partial int curlpro_stream_read(long stream, byte* buf, int bufLen);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_stream_error(long stream);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_stream_close(long stream);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_ws_connect(long session, string config);
    [LibraryImport(Lib)]
    internal static partial IntPtr curlpro_ws_send(long socket, byte* frame, int frameLen, out int outLen);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_ws_recv(long socket, out int outLen);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_ws_close(long socket, int code, string reason);

    [LibraryImport(Lib)] internal static partial IntPtr curlpro_request_start(long session, byte* frame, int frameLen);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_stream_open_start(long session, byte* frame, int frameLen);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_stream_read_start(long stream, int bufLen);
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr curlpro_ws_connect_start(long session, string config);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_ws_send_start(long socket, byte* frame, int frameLen);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_ws_recv_start(long socket);
    [LibraryImport(Lib)] internal static partial long curlpro_result_wait(int timeoutMs);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_result_take(long request, out int outLen);
    [LibraryImport(Lib)] internal static partial IntPtr curlpro_request_cancel(long request);
    [LibraryImport(Lib)] internal static partial long curlpro_async_pending();

    [LibraryImport(Lib)] internal static partial IntPtr curlpro_debug_counts();
}
