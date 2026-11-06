using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Curlpro;

/// <summary>
/// Session settings. Defaults are the browser's, as in the Python <c>Session</c>;
/// the ABI's own zero values are not (a missing boolean is false there).
/// </summary>
public sealed class SessionOptions
{
    public string Profile { get; set; } = "chrome-156-windows";
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
    public TimeSpan? ConnectTimeout { get; set; }
    public TimeSpan? ResponseTimeout { get; set; }
    public string? Proxy { get; set; }
    public bool DefaultHeaders { get; set; } = true;
    public bool FollowRedirects { get; set; } = true;
    public int MaxRedirects { get; set; } = 20;
    public bool Cookies { get; set; } = true;
    public bool Resume { get; set; } = true;
    public bool TrustEnv { get; set; } = true;
    public bool Http3 { get; set; }
    public bool ForceHttp1 { get; set; }
    public bool InsecureSkipVerify { get; set; }
    /// <summary>"navigate", "fetch" or null (auto).</summary>
    public string? Mode { get; set; }
    /// <summary>The initiator page: Referer, Origin and Sec-Fetch-Site follow from it.</summary>
    public string? Page { get; set; }
    /// <summary>Any other field of docs/C-ABI.md ("retry", "cache", "resolve", "device"…), sent as is.</summary>
    public JsonObject Extra { get; } = new();

    internal string ToJson()
    {
        var o = new JsonObject
        {
            ["profile"] = Profile,
            ["timeout_ms"] = (long)Timeout.TotalMilliseconds,
            ["default_headers"] = DefaultHeaders,
            ["follow_redirects"] = FollowRedirects,
            ["max_redirects"] = MaxRedirects,
            ["cookies"] = Cookies,
            ["resume"] = Resume,
            ["trust_env"] = TrustEnv,
            ["http3"] = Http3,
            ["force_http1"] = ForceHttp1,
            ["insecure_skip_verify"] = InsecureSkipVerify,
        };
        if (ConnectTimeout is { } ct) o["connect_timeout_ms"] = (long)ct.TotalMilliseconds;
        if (ResponseTimeout is { } rt) o["response_timeout_ms"] = (long)rt.TotalMilliseconds;
        if (Proxy is not null) o["proxy"] = Proxy;
        if (Mode is not null) o["mode"] = Mode;
        if (Page is not null) o["page"] = Page;
        foreach (var (k, v) in Extra) o[k] = v?.DeepClone();
        return o.ToJsonString();
    }
}

/// <summary>One request. Headers are merged into the profile's, in the profile's order.</summary>
public sealed class Request
{
    public Request(string method, string url)
    {
        Method = method;
        Url = url;
    }

    public string Method { get; set; }
    public string Url { get; set; }
    public Dictionary<string, string> Headers { get; } = new(StringComparer.OrdinalIgnoreCase);
    public byte[] Body { get; set; } = [];
    public TimeSpan? Timeout { get; set; }
    /// <summary>"http1", "h2" or "h3" to force one.</summary>
    public string? Protocol { get; set; }
    /// <summary>Any other request field of docs/C-ABI.md ("proxy", "mode", "page", "suppress_headers"…).</summary>
    public JsonObject Extra { get; } = new();

    internal byte[] ToFrame()
    {
        var o = new JsonObject { ["method"] = Method, ["url"] = Url };
        if (Headers.Count > 0)
        {
            var h = new JsonObject();
            foreach (var (k, v) in Headers) h[k] = v;
            o["headers"] = h;
        }
        if (Timeout is { } t) o["timeout_ms"] = (long)t.TotalMilliseconds;
        if (Protocol is not null) o["protocol"] = Protocol;
        foreach (var (k, v) in Extra) o[k] = v?.DeepClone();
        return Interop.MakeFrame(o, Body);
    }
}

/// <summary>A response with its body read whole.</summary>
public sealed class Response
{
    internal Response(JsonObject data, byte[] body)
    {
        Raw = data;
        Status = data["status"]?.GetValue<int>() ?? 0;
        Proto = data["proto"]?.GetValue<string>() ?? "";
        Url = data["url"]?.GetValue<string>() ?? "";
        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        if (data["headers"] is JsonObject h)
            foreach (var (k, v) in h)
                headers[k] = v?.AsArray().Select(x => x!.GetValue<string>()).ToArray() ?? [];
        Headers = headers;
        Body = body;
    }

    public int Status { get; }
    /// <summary>"HTTP/1.1", "HTTP/2.0" or "HTTP/3.0".</summary>
    public string Proto { get; }
    /// <summary>The final URL, after redirects.</summary>
    public string Url { get; }
    public IReadOnlyDictionary<string, string[]> Headers { get; }
    /// <summary>The body, already decompressed.</summary>
    public byte[] Body { get; }
    /// <summary>The whole response description: history, preflights, cache, cookie_changes.</summary>
    public JsonObject Raw { get; }

    public string? Header(string name) => Headers.TryGetValue(name, out var v) && v.Length > 0 ? v[0] : null;
    public string Text => Encoding.UTF8.GetString(Body);
    [RequiresUnreferencedCode("Reflection-based JSON; parse Body yourself under trimming")]
    [RequiresDynamicCode("Reflection-based JSON; parse Body yourself under AOT")]
    public T? Json<T>() => JsonSerializer.Deserialize<T>(Body);
    public override string ToString() => $"<Response [{Status}] {Proto} {Url}>";
}

/// <summary>
/// One browser: its TLS/HTTP fingerprint, connection pool, cookies and headers.
/// Thread-safe; requests run in parallel.
/// </summary>
public sealed class Session : IDisposable
{
    private long _id;

    public Session(string profile = "chrome-156-windows") : this(new SessionOptions { Profile = profile }) { }

    public Session(SessionOptions options)
    {
        Profiles.EnsureLoaded();
        Profile = options.Profile;
        _id = Interop.Envelope(Native.curlpro_session_new(options.ToJson()))!["session"]!.GetValue<long>();
    }

    public string Profile { get; }

    private long Id => _id != 0 ? _id : throw new CurlproException("the session is closed", "session_closed");

    // ---- requests -----------------------------------------------------------

    public Response Send(Request request)
    {
        var frame = request.ToFrame();
        var (data, body) = Call(frame, (f, n) => { unsafe { fixed (byte* p = f) return (Native.curlpro_request(Id, p, n, out var len), len); } });
        return new Response(data!.AsObject(), body);
    }

    public async Task<Response> SendAsync(Request request, CancellationToken ct = default)
    {
        var frame = request.ToFrame();
        long id = Id;
        var (data, body) = await Completions.Run(() => { unsafe { fixed (byte* p = frame) return Native.curlpro_request_start(id, p, frame.Length); } }, ct)
            .ConfigureAwait(false);
        return new Response(data!.AsObject(), body);
    }

    public Response Get(string url, IDictionary<string, string>? headers = null) => Send(Build("GET", url, headers, null));

    public Task<Response> GetAsync(string url, IDictionary<string, string>? headers = null, CancellationToken ct = default) =>
        SendAsync(Build("GET", url, headers, null), ct);

    public Response Post(string url, byte[] body, string contentType, IDictionary<string, string>? headers = null)
    {
        var r = Build("POST", url, headers, body);
        r.Headers["content-type"] = contentType;
        return Send(r);
    }

    [RequiresUnreferencedCode("Reflection-based JSON; use Post with your own bytes under trimming")]
    [RequiresDynamicCode("Reflection-based JSON; use Post with your own bytes under AOT")]
    public Response PostJson(string url, object value, IDictionary<string, string>? headers = null) =>
        Post(url, JsonSerializer.SerializeToUtf8Bytes(value), "application/json", headers);

    /// <summary>Opens a response as a stream: returns once the headers are in.</summary>
    public ResponseStream OpenStream(Request request)
    {
        var frame = request.ToFrame();
        var (data, _) = Call(frame, (f, n) => { unsafe { fixed (byte* p = f) return (Native.curlpro_stream_open(Id, p, n, out var len), len); } });
        return new ResponseStream(data!.AsObject());
    }

    public WebSocket ConnectWebSocket(string url, IDictionary<string, string>? headers = null,
        IEnumerable<string>? subprotocols = null, TimeSpan? timeout = null)
    {
        var cfg = new JsonObject { ["url"] = url };
        if (headers is not null)
        {
            var h = new JsonObject();
            foreach (var (k, v) in headers) h[k] = v;
            cfg["headers"] = h;
        }
        if (subprotocols is not null) cfg["subprotocols"] = new JsonArray(subprotocols.Select(s => (JsonNode)s).ToArray());
        if (timeout is { } t) cfg["timeout_ms"] = (long)t.TotalMilliseconds;
        var data = Interop.Envelope(Native.curlpro_ws_connect(Id, cfg.ToJsonString()));
        return new WebSocket(data!["socket"]!.GetValue<long>());
    }

    // ---- what the server would see ------------------------------------------------

    /// <summary>ja3, ja3n, ja4, akamai… for this URL, computed without sending anything.</summary>
    public JsonObject Fingerprint(string url) => Interop.Envelope(Native.curlpro_session_fingerprint(Id, url))!.AsObject();

    /// <summary>The headers a request would carry, in order, without sending it.</summary>
    public JsonObject Preview(string method, string url, IDictionary<string, string>? headers = null)
    {
        var spec = new JsonObject { ["method"] = method, ["url"] = url };
        if (headers is not null)
        {
            var h = new JsonObject();
            foreach (var (k, v) in headers) h[k] = v;
            spec["headers"] = h;
        }
        return Interop.Envelope(Native.curlpro_session_preview(Id, spec.ToJsonString()))!.AsObject();
    }

    // ---- session headers, page, cookies, cache -----------------------------------

    public void SetHeader(string name, string value) => Interop.Envelope(Native.curlpro_session_set_header(Id, name, value));
    public bool RemoveHeader(string name) =>
        Interop.Envelope(Native.curlpro_session_remove_header(Id, name))!["removed"]!.GetValue<bool>();
    /// <summary>Never send this header, even when the profile would.</summary>
    public void SuppressHeader(string name) => Interop.Envelope(Native.curlpro_session_suppress_header(Id, name));
    public void ResetHeaders() => Interop.Envelope(Native.curlpro_session_reset_headers(Id));
    public void SetPage(string url) => Interop.Envelope(Native.curlpro_session_set_page(Id, url));

    public JsonArray Cookies() => Interop.Envelope(Native.curlpro_session_cookies(Id))!["cookies"]?.AsArray() ?? [];
    public void SetCookies(JsonArray cookies) => Interop.Envelope(Native.curlpro_session_set_cookies(Id, cookies.ToJsonString()));
    public void ClearCookies() => Interop.Envelope(Native.curlpro_session_clear_cookies(Id));
    public JsonObject CacheInfo() => Interop.Envelope(Native.curlpro_session_cache_info(Id))!.AsObject();

    public void Dispose()
    {
        var id = Interlocked.Exchange(ref _id, 0);
        if (id != 0) Interop.Envelope(Native.curlpro_session_close(id));
    }

    private static Request Build(string method, string url, IDictionary<string, string>? headers, byte[]? body)
    {
        var r = new Request(method, url) { Body = body ?? [] };
        if (headers is not null) foreach (var (k, v) in headers) r.Headers[k] = v;
        return r;
    }

    private static (JsonNode? Data, byte[] Body) Call(byte[] frame, Func<byte[], int, (IntPtr, int)> f)
    {
        var (p, len) = f(frame, frame.Length);
        return Interop.Frame(p, len);
    }
}

/// <summary>A response whose body is read in pieces. Dispose it.</summary>
public sealed class ResponseStream : Stream
{
    private long _id;

    internal ResponseStream(JsonObject data)
    {
        _id = data["stream"]!.GetValue<long>();
        Status = data["status"]?.GetValue<int>() ?? 0;
        Proto = data["proto"]?.GetValue<string>() ?? "";
        Url = data["url"]?.GetValue<string>() ?? "";
        Raw = data;
    }

    public int Status { get; }
    public string Proto { get; }
    public string Url { get; }
    public JsonObject Raw { get; }

    public override unsafe int Read(byte[] buffer, int offset, int count)
    {
        if (count == 0) return 0;
        if (_id == 0) throw new ObjectDisposedException(nameof(ResponseStream));
        int n;
        fixed (byte* p = &buffer[offset]) n = Native.curlpro_stream_read(_id, p, count);
        if (n < 0) Interop.Envelope(Native.curlpro_stream_error(_id)); // throws the stored error
        return Math.Max(n, 0);
    }

    protected override void Dispose(bool disposing)
    {
        var id = Interlocked.Exchange(ref _id, 0);
        if (id != 0) Native.curlpro_free(Native.curlpro_stream_close(id));
        base.Dispose(disposing);
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>A WebSocket whose upgrade carried the profile's fingerprint.</summary>
public sealed class WebSocket : IDisposable
{
    private long _id;

    internal WebSocket(long id) => _id = id;

    private long Id => _id != 0 ? _id : throw new CurlproException("the socket is closed", "ws_closed");

    public void Send(string text) => SendFrame(false, false, Encoding.UTF8.GetBytes(text));
    public void Send(byte[] data) => SendFrame(true, false, data);
    public void Ping(byte[]? data = null) => SendFrame(false, true, data ?? []);

    /// <summary>Blocks for the next message. Throws CurlproException with Code "ws_closed" once closed.</summary>
    public (bool Binary, byte[] Data) Receive()
    {
        var p = Native.curlpro_ws_recv(Id, out var len);
        var (data, body) = Interop.Frame(p, len);
        return (data?["binary"]?.GetValue<bool>() ?? false, body);
    }

    public string ReceiveText() => Encoding.UTF8.GetString(Receive().Data);

    public void Close(int code = 1000, string reason = "")
    {
        var id = Interlocked.Exchange(ref _id, 0);
        if (id != 0) Native.curlpro_free(Native.curlpro_ws_close(id, code, reason));
    }

    public void Dispose() => Close();

    private unsafe void SendFrame(bool binary, bool ping, byte[] payload)
    {
        var frame = Interop.MakeFrame(new JsonObject { ["binary"] = binary, ["ping"] = ping }, payload);
        IntPtr p;
        int len;
        fixed (byte* f = frame) p = Native.curlpro_ws_send(Id, f, frame.Length, out len);
        Interop.Frame(p, len);
    }
}
