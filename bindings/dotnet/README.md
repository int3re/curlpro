# .NET

`Curlpro` — P/Invoke through `LibraryImport` (source-generated marshalling,
trimming- and AOT-friendly), .NET 8+. No dependencies.

```csharp
using Curlpro;

using var s = new Session("chrome-156-windows");
Console.WriteLine(s.Fingerprint("https://example.com/")["ja4"]);   // offline

var r = await s.GetAsync("https://example.com/");
Console.WriteLine($"{r.Status} {r.Proto} {r.Body.Length} bytes");

try { await s.GetAsync("https://slow.example/", ct: cts.Token); }
catch (CurlproException e) when (e.Code == "timeout") { /* retry */ }
```

| | |
|---|---|
| `Session(profile)` / `Session(SessionOptions)` | browser defaults; `options.Extra["retry"] = …` for any other field |
| `Send` / `SendAsync(Request, ct)` | `Request` has `Headers`, `Body`, `Timeout`, `Protocol`, `Extra` |
| `Get`, `GetAsync`, `Post`, `PostJson` | |
| `OpenStream(Request)` | a `System.IO.Stream` over the body |
| `ConnectWebSocket(url)` | `Send(string/byte[])`, `Receive()`, `Close()` |
| `Fingerprint(url)`, `Preview(...)` | what the server would see, without sending |
| `SetHeader`, `SuppressHeader`, `Cookies`, `SetCookies`, `ClearCookies` | |
| `Profiles.LoadDir/LoadBundle/Register/List/Get/Capabilities` | |
| `CurlproException.Code`, `.Details`, `.Permanent` | |

Async calls use the ABI's own completion queue: one background thread waits on
`curlpro_result_wait` for every call in the process, so thousands of requests in
flight hold no thread each. Cancelling the token aborts the request.

## Run the example

```powershell
$env:CURLPRO_LIBRARY = "$PWD\..\..\dist\curlpro.dll"
$env:CURLPRO_PROFILES = "$PWD\..\..\profiles"
cd Example
dotnet run                          # net8.0
dotnet run -p:CurlproTfm=net10.0    # when only a newer targeting pack is installed
```

The NuGet package (`Curlpro`, built by scripts/package-bindings.py) carries the
library for six platforms in `runtimes/<rid>/native/` and the profiles as
content, so an app needs nothing else. The assembly is `Curlpro.Net.dll`: on
Windows `Curlpro.dll` would be the same file name as the native `curlpro.dll`.
