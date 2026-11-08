package client

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

// connectH1 is a plain CONNECT (ConnectAuthority) through a proxy that
// negotiated HTTP/1.1: the request line `CONNECT host:port HTTP/1.1` on the
// proxy's TLS connection, which becomes the caller's after a 2xx — as Chrome
// tunnels through an HTTPS proxy that offers no h2. The connection leaves the
// pool at once: a tunnel takes it whole, and a refusal ends it.
//
// The request is written and its answer read here, as the session's own
// tunnel does (connectProxy): a 2xx to a CONNECT has no body, and the bytes
// after it are the tunnel's.
func (s *Session) connectH1(ctx context.Context, current *Request, u *url.URL, c *conn, reused bool) (*Upgraded, error) {
	s.mu.Lock()
	s.removeLocked(c)
	c.pooled = false
	s.mu.Unlock()

	target := current.ConnectAuthority
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if len(current.HeadersRaw) > 0 {
		req.Header[http.HeaderOrderKey] = rawHeaderSet(req.Header, current.HeadersRaw, target, true)
	} else {
		connectH1Headers(req, s.profile.Headers.UserAgent, current.Headers)
	}
	if d, ok := ctx.Deadline(); ok {
		_ = c.raw.SetDeadline(d)
	}
	stop := context.AfterFunc(ctx, func() { _ = c.raw.SetDeadline(time.Unix(1, 0)) })
	fail := func(err error) (*Upgraded, error) {
		stop()
		c.close()
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return nil, fmt.Errorf("upgrade: %w", err)
	}
	if err := req.Write(c.raw); err != nil {
		return fail(err)
	}
	resp, err := http.ReadResponse(c.br, req)
	if err != nil {
		return fail(err)
	}
	if s.useCookies(current) && s.includesCredentials(current, u) {
		s.storeCookies(current, u, s.acceptCookies(resp.Cookies()))
	}
	out := &Upgraded{Status: resp.StatusCode, Proto: resp.Proto, Headers: resp.Header, URL: current.URL,
		Info: c.describe(reused)}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, upgradeBodyLimit))
		resp.Body.Close()
		stop()
		c.close()
		if rerr != nil {
			return nil, fmt.Errorf("reading the refusal's body: %w", rerr)
		}
		out.Body = data
		return out, nil
	}
	if !stop() {
		c.close()
		return nil, fmt.Errorf("upgrade: %w", ctx.Err())
	}
	// From here the connection is the caller's, with whatever the proxy
	// relayed after its answer already in the reader's buffer.
	_ = c.raw.SetDeadline(time.Time{})
	out.Conn = &RawConn{raw: c.raw, br: c.br}
	return out, nil
}

// connectH1Headers is an HTTP/1.1 CONNECT's header set without headers_raw:
// Chrome's — Host, Proxy-Connection: keep-alive, the User-Agent — as the
// session's own tunnel writes it, then the caller's headers (credentials).
func connectH1Headers(req *http.Request, userAgent string, extra map[string]string) {
	req.Header["Host"] = []string{req.Host}
	req.Header["Proxy-Connection"] = []string{"keep-alive"}
	// An empty slice stops fhttp from writing its own User-Agent.
	req.Header["User-Agent"] = []string{}
	if userAgent != "" {
		req.Header["User-Agent"] = []string{userAgent}
	}
	order := []string{"host", "proxy-connection", "user-agent"}
	names := make([]string, 0, len(extra))
	for k := range extra {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		key := http.CanonicalHeaderKey(k)
		if _, seen := req.Header[key]; !seen {
			order = append(order, strings.ToLower(k))
		}
		req.Header[key] = []string{extra[k]}
	}
	req.Header[http.HeaderOrderKey] = order
}
