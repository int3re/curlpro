# Go

Go does not use the C ABI. A `c-shared` library carries its own Go runtime and a
Go program cannot load one, so the module exports the core itself as the root
package — [curlpro.go](../../curlpro.go):

```go
import "github.com/curlpro/curlpro"

if _, err := curlpro.LoadProfiles("profiles"); err != nil { log.Fatal(err) }
s, err := curlpro.NewSession("chrome-156-windows", curlpro.DefaultOptions())
if err != nil { log.Fatal(err) }
defer s.Close()

resp, err := s.Do(&curlpro.Request{Method: "GET", URL: "https://example.com/"})
if err != nil {
	log.Fatal(curlpro.Code(err), err) // timeout, proxy, configuration, …
}
fmt.Println(resp.Status, resp.Proto, len(resp.Body))
```

- `curlpro.Session`, `Options`, `Request`, `Response`, `Stream`, `WebSocket`,
  `Fingerprint`, `Cookie`… are aliases of the core types: their methods are the
  core's (`Do`, `DoStream`, `DialWebSocket`, `Fingerprint`, `PreviewHeaders`,
  `Cookies`, `SetHeader`…).
- `DefaultOptions()` are a browser's; the zero `Options` switch profile headers,
  redirects and cookies off.
- `LoadProfilesFS` takes an `embed.FS`, so a binary can carry its profiles.
- No cgo: `CGO_ENABLED=0` builds work, and cross-compilation is plain `GOOS=…`.

Until the module path (`github.com/curlpro/curlpro`) resolves to this
repository, use a `replace` directive or a `go.work` pointing at a checkout.

`go test -run 'Version|Offline|Unknown' .` checks the package offline;
[example_test.go](../../example_test.go) is a live request.
