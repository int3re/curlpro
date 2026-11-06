// The .NET binding end to end: offline fingerprint, a request, the same
// fingerprint as a server saw it, parallel async requests, a stream.
//
//   set CURLPRO_LIBRARY=..\..\..\dist\curlpro.dll
//   set CURLPRO_PROFILES=..\..\..\profiles
//   dotnet run
using Curlpro;

// --ja4: only the offline JA4 of chrome-156-windows, for scripts/bindings-agree.sh.
if (args.Contains("--ja4"))
{
    using var ja4 = new Session("chrome-156-windows");
    Console.WriteLine(ja4.Fingerprint("https://example.com/")["ja4"]);
    return;
}

Console.WriteLine($"libcurlpro {Library.Version}");

using var session = new Session("chrome-156-windows");
var offline = session.Fingerprint("https://tls.peet.ws/");
Console.WriteLine($"ja4 offline:   {offline["ja4"]}");

var r = session.Get("https://tls.peet.ws/api/clean");
Console.WriteLine($"{r}  ({r.Body.Length} bytes)");
var seen = System.Text.Json.Nodes.JsonNode.Parse(r.Text)!;
Console.WriteLine($"ja4 by server: {seen["ja4"]}");
Console.WriteLine($"akamai:        {seen["akamai_hash"]}");

var tasks = Enumerable.Range(0, 5).Select(_ => session.GetAsync("https://example.com/")).ToArray();
var all = await Task.WhenAll(tasks);
Console.WriteLine($"async x5: {string.Join(", ", all.Select(x => $"{x.Status} {x.Proto}"))}");

using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(1)))
{
    try { await session.GetAsync("https://httpbin.org/delay/5", ct: cts.Token); Console.WriteLine("cancel: not cancelled?"); }
    catch (OperationCanceledException) { Console.WriteLine("cancel: ok"); }
}

using (var stream = session.OpenStream(new Request("GET", "https://example.com/")))
{
    var total = 0;
    var buf = new byte[1024];
    int n;
    while ((n = stream.Read(buf, 0, buf.Length)) > 0) total += n;
    Console.WriteLine($"stream: {stream.Status} {stream.Proto}, {total} bytes");
}

try { using var bad = new Session("no-such-browser"); }
catch (CurlproException e) { Console.WriteLine($"error code: {e.Code}, permanent: {e.Permanent}"); }

session.Dispose();
Console.WriteLine($"left open: {Library.DebugCounts().ToJsonString()}");
