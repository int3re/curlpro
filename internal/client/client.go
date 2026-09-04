// Package client performs HTTP requests with a browser fingerprint from a profile.
//
// The TLS handshake is driven by uTLS from the profile's ClientHelloSpec; the
// protocol is chosen by the server through ALPN, and the offer list comes from
// the profile too. Connections are reused by host:port key, but the spec is
// rebuilt for every new connection: Chrome >= 110 shuffles extensions, and a
// constant order would set us apart from a browser on its own.
package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	"github.com/bogdanfinn/fhttp/http2"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/profile"
)

// DefaultMaxRedirects repeats the limit browsers use.
const DefaultMaxRedirects = 20

// Options configure a session.
type Options struct {
	// InsecureSkipVerify turns certificate verification off.
	InsecureSkipVerify bool
	// Timeout caps every request as a whole, redirects included.
	Timeout time.Duration
	// Proxy is http://, https:// or socks5:// with optional user:pass.
	Proxy string

	// DefaultHeaders enables the profile's headers.
	// With it off the caller controls the set and the order completely —
	// anti-bot systems look at the order too, so that control belongs outside.
	DefaultHeaders bool
	// HeaderOrder overrides the send order. Headers not listed here follow the
	// listed ones, keeping their relative order.
	HeaderOrder []string

	// FollowRedirects enables following 3xx responses.
	FollowRedirects bool
	// MaxRedirects caps the chain length. 0 means DefaultMaxRedirects.
	MaxRedirects int

	// Cookies enables the cookie jar shared by every request of the session.
	Cookies bool

	// MaxIdleConns caps the number of pooled connections. 0 means 64.
	//
	// The limit is not hypothetical: a rotating proxy with a session id in the
	// login yields a new connection for every request.
	MaxIdleConns int
	// IdleConnTimeout is how long an unused connection is kept. 0 means 300 s,
	// as long as Chrome keeps it.
	IdleConnTimeout time.Duration
	// ConnectTimeout caps establishing a connection separately from Timeout:
	// name resolution, TCP and the TLS handshake. 0 means the total limit only.
	//
	// Needed where a host goes silent: without a separate limit the request waits
	// out its whole budget on a dead address, though everything is clear in a second.
	// Reading the response is not bounded by it — Timeout covers that.
	ConnectTimeout time.Duration

	// CACert is the path to a root certificate (PEM) of your own, instead of the system ones.
	//
	// Needed for test stands, corporate networks and intercepting proxies:
	// without it the only option was switching verification off entirely.
	CACert string
	// ClientCert and ClientKey enable mutual authentication (mTLS).
	ClientCert string
	ClientKey  string

	// TrustEnv allows taking the proxy from the HTTPS_PROXY, HTTP_PROXY and
	// NO_PROXY environment variables, the way curl and requests do.
	// An explicitly set Proxy always wins.
	TrustEnv bool

	// MaxResponseSize caps the response body. 0 means no limit.
	//
	// Without one, a hostile or broken server with an endless body eats the
	// process memory whole: for a scraper that is not theory.
	MaxResponseSize int64

	// DisableAltSvc turns off the automatic HTTP/3 upgrade driven by Alt-Svc.
	//
	// The upgrade is on by default: that is what a browser does — the first
	// request to a site always goes over TCP, and the client moves to HTTP/3 only
	// after seeing the advertisement. Worth turning off where UDP is known to be
	// blocked and the extra attempt only wastes time.
	DisableAltSvc bool

	// Resolve overrides a host's address without touching the name in SNI or Host.
	//
	// The key is "host:port" or just "host" (then the rule applies to any port),
	// the value is "ip" or "ip:port". The equivalent of curl's --resolve: it is how
	// you reach one specific server behind a balancer, or test a stand under a real
	// name. The fingerprint does not change: the name stays the same, only the
	// socket destination moves.
	Resolve map[string]string

	// IPVersion restricts the address family: "4", "6" or empty.
	//
	// Needed where a name has an AAAA record but there is no IPv6 route:
	// without the restriction the connection first runs into a timeout.
	IPVersion string

	// DisableKeepAlive turns reuse off: every request gets its own connection,
	// which closes right after the response.
	//
	// The polarity matches net/http.Transport.DisableKeepAlives — the zero value
	// keeps the usual behaviour. No "Connection: close" header is sent: a browser
	// does not send one, and it would give the client away.
	// The client simply closes the socket, as a browser closes an idle one.
	DisableKeepAlive bool

	// ForceHTTP1 forbids h2 even when the server offers it.
	ForceHTTP1 bool

	// HTTP3 sends requests over QUIC instead of TCP.
	//
	// This is a separate transport, not an ALPN variant, so it is chosen explicitly.
	// The profile must describe an http3 section or the session will not be created.
	HTTP3 bool

	// Retry configures retries. nil means no retries.
	Retry *RetryPolicy

	// Mode selects the header set: "navigate" for a page load, "fetch" for
	// fetch/XHR, "" or "auto" to decide from the request (see modeFor).
	Mode string

	// Device is a device name from the profile's devices section; "random" picks
	// one at random. Empty means no device is chosen, and the high-entropy hints
	// keep the profile's values.
	//
	// The device is held for the session: a real client does not swap phones
	// between requests, and swapping mid-session would be a tell in itself.
	Device string
	// Devices overrides the profile's device list.
	Devices []profile.Device
}

// Request is a request in the library's terms.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte

	// Multipart, when set, is encoded into the body with a boundary in the
	// profile's style. Mutually exclusive with Body.
	Multipart *MultipartForm

	// BodyFile is the path to a file sent as the request body.
	//
	// The file is streamed rather than read into memory: sending a gigabyte
	// archive must not need a gigabyte of RAM. Mutually exclusive with Body.
	BodyFile string
	// BodySize is the body size for Content-Length. Zero together with BodyFile
	// means "take it from the file".
	BodySize int64

	// HeaderOrder overrides the order for a single request.
	HeaderOrder []string
	// DefaultHeaders switches the profile headers on or off for a single
	// request. nil means whatever the session says.
	//
	// A pointer rather than a bool: the session may switch them off entirely, and
	// then a single request needs a way to bring them back.
	DefaultHeaders *bool

	// Cookies switches the session cookie jar off for a single request.
	//
	// nil keeps the session behaviour. false isolates the request from the jar
	// in both directions: stored cookies are not sent and Set-Cookie from the
	// response is not remembered. One-way isolation would be surprising —
	// "do not use the memory" is easily read as "do not touch it at all".
	Cookies *bool

	// SessionHeaders switches the headers added to the session off for a single
	// request. nil keeps them. The profile headers are unaffected: they are
	// controlled by DefaultHeaders.
	SessionHeaders *bool

	// Protocol forces the transport for a single request: ProtoHTTP1, ProtoH2 or
	// ProtoH3. Empty means whatever the session decides: its options, and on
	// direct connections Alt-Svc as well.
	//
	// The instruction beats both: the caller is asking for a protocol, not for
	// advice.
	Protocol string

	// Per-request overrides of session settings.
	// nil means "take the session's" — that tells "not set" from "set to zero",
	// which for a timeout and for redirects are entirely different things.

	// Timeout caps this request as a whole, redirects and retries included.
	Timeout *time.Duration
	// ConnectTimeout overrides the limit on establishing the connection.
	ConnectTimeout *time.Duration
	// FollowRedirects overrides whether 3xx are followed.
	FollowRedirects *bool
	// MaxRedirects overrides the chain length limit.
	MaxRedirects *int
	// Retry overrides the retry policy for this request.
	Retry *RetryPolicy

	// Proxy overrides the session proxy.
	//
	// nil means "take the session's", an empty string means going directly,
	// bypassing it. Those differ, hence a pointer rather than a string.
	Proxy *string

	// SuppressHeaders removes headers by name after they were built from the profile.
	//
	// Needed for cases such as sec-fetch-user: it comes from the profile, and
	// deleting it from Headers would not touch it.
	SuppressHeaders []string

	// RedirectHop marks the request as a redirect hop. On such a hop Chromium
	// places the client hints (sec-ch-ua*) not at the front but after
	// Sec-Fetch-Dest — see buildHeaders.
	RedirectHop bool

	// Mode overrides Options.Mode for a single request.
	Mode string

	// Ctx is the request's parent context. nil means context.Background.
	//
	// Needed for cancellation from outside: an async call from Python is cancelled
	// when the asyncio task is, and without a context the request would live on
	// until its own timeout, holding a connection.
	Ctx context.Context
}

// context returns the request's parent context.
func (r *Request) context() context.Context {
	if r != nil && r.Ctx != nil {
		return r.Ctx
	}
	return context.Background()
}

// Values for Request.Protocol.
//
// h2 does not trim the ALPN list to a single entry: no browser sends a list of
// h2 alone, and the fingerprint forgery would end right there.
// So h2 means "do not go to QUIC and do not settle for HTTP/1.1": when the
// server negotiates http/1.1 the request fails with a clear error.
const (
	ProtoHTTP1 = "http1"
	ProtoH2    = "h2"
	ProtoH3    = "h3"
)

// protocol returns the transport the request asked for.
func (r *Request) protocol() string {
	if r == nil {
		return ""
	}
	return r.Protocol
}

// useCookies decides whether the jar takes part in this request.
func (s *Session) useCookies(r *Request) bool {
	if s.jar == nil {
		return false
	}
	if r != nil && r.Cookies != nil {
		return *r.Cookies
	}
	return true
}

// useSessionHeaders decides whether the session headers are added.
func (s *Session) useSessionHeaders(r *Request) bool {
	if r != nil && r.SessionHeaders != nil {
		return *r.SessionHeaders
	}
	return true
}

// useDefaultHeaders decides whether to add the profile headers.
func (s *Session) useDefaultHeaders(r *Request) bool {
	if r != nil && r.DefaultHeaders != nil {
		return *r.DefaultHeaders
	}
	return s.opts.DefaultHeaders
}

// proxyFor returns the proxy address for a request.
func (s *Session) proxyFor(r *Request) string {
	if r != nil && r.Proxy != nil {
		return *r.Proxy
	}
	return s.opts.Proxy
}

// proxyForHost returns the proxy, taking the environment into account.
//
// An explicitly set proxy always wins: the environment is a default, not an
// order. An empty string in the request means "go directly", and the
// environment does not override that either.
func (s *Session) proxyForHost(r *Request, host string) string {
	if r != nil && r.Proxy != nil {
		return *r.Proxy
	}
	if s.opts.Proxy != "" {
		return s.opts.Proxy
	}
	if s.opts.TrustEnv {
		return proxyFromEnv(host)
	}
	return ""
}

// connectLimitKey marks the connect limit inside a context.
type connectLimitKey struct{}

// withConnectLimit puts the request's override into the context.
//
// As a context value rather than an argument: three paths lead to dial — the
// connection pool, the HTTP/3 upgrade and the WebSocket — and an extra
// parameter would have to be threaded through each of them.
func withConnectLimit(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, connectLimitKey{}, d)
}

// connectContext bounds the connection-establishing phase.
//
// Returns the original context when there is no separate limit: an extra layer
// with a cancel per connection would cost more than it saves.
func (s *Session) connectContext(ctx context.Context) (context.Context, context.CancelFunc) {
	limit := s.opts.ConnectTimeout
	if d, ok := ctx.Value(connectLimitKey{}).(time.Duration); ok && d > 0 {
		limit = d
	}
	if limit <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, limit)
}

// timeout returns the limit for a request, honouring its override.
//
// Zero is rejected at the entry points (New and validate), so it cannot mean
// anything here: zero in the options used to substitute 30 seconds while zero
// in a request meant an instant timeout — one number with opposite meanings.
func (s *Session) timeout(r *Request) time.Duration {
	if r != nil && r.Timeout != nil {
		return *r.Timeout
	}
	return s.opts.Timeout
}

// validate checks the request overrides before sending. hasJar says whether the
// session has a cookie jar: without one, asking for cookies is a mistake worth
// reporting rather than a silently ignored option.
func (r *Request) validate(hasJar bool) error {
	if r == nil {
		return nil
	}
	if r.Timeout != nil && *r.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive, got %s "+
			"(leave it unset for no limit)", *r.Timeout)
	}
	if r.ConnectTimeout != nil && *r.ConnectTimeout <= 0 {
		return fmt.Errorf("connect timeout must be positive, got %s "+
			"(leave it unset for no limit)", *r.ConnectTimeout)
	}
	if r.Cookies != nil && *r.Cookies && !hasJar {
		return fmt.Errorf("cookies=true: the session has no cookie jar " +
			"(create the session with cookies enabled)")
	}
	switch r.Protocol {
	case "", ProtoHTTP1, ProtoH2, ProtoH3:
	default:
		return fmt.Errorf("unknown protocol %q: use %q, %q or %q",
			r.Protocol, ProtoHTTP1, ProtoH2, ProtoH3)
	}
	if r.MaxRedirects != nil && *r.MaxRedirects < 0 {
		return fmt.Errorf("max_redirects cannot be negative, got %d",
			*r.MaxRedirects)
	}
	return nil
}

// followRedirects reports whether to follow 3xx for this request.
func (s *Session) followRedirects(r *Request) bool {
	if r != nil && r.FollowRedirects != nil {
		return *r.FollowRedirects
	}
	return s.opts.FollowRedirects
}

// maxRedirects returns the chain length limit for this request.
func (s *Session) maxRedirects(r *Request) int {
	if r != nil && r.MaxRedirects != nil && *r.MaxRedirects > 0 {
		return *r.MaxRedirects
	}
	return s.opts.MaxRedirects
}

// Response is a response.
type Response struct {
	Status  int
	Headers map[string][]string
	Body    []byte
	Proto   string
	URL     string // the final URL after redirects
	// History holds the redirects that were followed, first to last.
	History []Redirect
}

// Session performs requests with a single profile.
type Session struct {
	profile *profile.Profile
	opts    Options
	alpn    []string
	jar     *cookiejar.Jar

	mu    sync.Mutex
	conns map[dialSpec][]*conn

	// orphans are HTTP/2 connections taken out of the pool but still finishing
	// their streams. Untracked they would leak along with the read goroutine.
	orphans map[*conn]struct{}

	// closed lives under the same mutex as the pool: otherwise a request started
	// at the same moment as Close would leave a connection without an owner.
	closed bool

	// headers are the headers the user added to the session. Kept apart from the
	// profile's so that ResetHeaders restores the plain fingerprint.
	headers *sessionHeaders

	// device is the phone this session's requests pretend to come from.
	device profile.Device
	// acceptCH are the hints the site asked for, per origin. Under the same
	// mutex as the pool: filled from responses, read while building headers.
	acceptCH map[string]map[string]bool

	// cookies is our own cookie record for export: the jar yields only the
	// name-value pair for an address, and that is not enough to save a session.
	cookies map[string]Cookie

	// altSvc holds the HTTP/3 advertisements per origin along with the "broken" mark.
	altSvc map[string]altSvcEntry

	// roots and clientCerts are prepared once when the session is created:
	// reading files per connection is wasted I/O on the hot path.
	roots       *x509.CertPool
	clientCerts []utls.Certificate

	h3 h3Transport
}

// New creates a session. The profile spec is checked right away so that a data
// error surfaces at creation rather than on the first request.
func New(p *profile.Profile, opts Options) (*Session, error) {
	if p == nil {
		return nil, fmt.Errorf("no profile given: a session needs one to build its fingerprint")
	}
	if _, err := profile.BuildSpec(p); err != nil {
		return nil, err
	}
	if opts.Timeout < 0 {
		return nil, fmt.Errorf("timeout cannot be negative, got %s", opts.Timeout)
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxRedirects == 0 {
		opts.MaxRedirects = DefaultMaxRedirects
	}

	// The device is chosen once per session. A list from the options overrides
	// the profile's: your own phones can be set without touching the profile.
	if len(opts.Devices) > 0 {
		clone := *p
		clone.Devices = opts.Devices
		p = &clone
	}
	var dev profile.Device
	if opts.Device != "" {
		var err error
		if dev, err = p.PickDevice(opts.Device); err != nil {
			return nil, err
		}
		// For profiles where the device sits inside the User-Agent, the string is
		// rebuilt: otherwise the hint would say one thing and the string next to
		// it another — a mismatch more visible than everyone sharing one phone.
		if ua := p.UserAgentFor(dev); ua != p.Headers.UserAgent {
			clone := *p
			clone.Headers.UserAgent = ua
			p = &clone
		}
	}

	s := &Session{
		profile: p,
		opts:    opts,
		alpn:    alpnFromProfile(p),
		conns:   make(map[dialSpec][]*conn),
		orphans: make(map[*conn]struct{}),
		headers: newSessionHeaders(),
		device:  dev,
	}
	if opts.ForceHTTP1 {
		s.alpn = []string{"http/1.1"}
	}
	// The files are read before the first request: a bad path must surface when
	// the session is created, not halfway through a scraping run.
	roots, err := loadRoots(opts.CACert)
	if err != nil {
		return nil, err
	}
	certs, err := loadClientCert(opts.ClientCert, opts.ClientKey)
	if err != nil {
		return nil, err
	}
	s.roots, s.clientCerts = roots, certs

	if opts.Cookies {
		jar, err := newCookieJar()
		if err != nil {
			return nil, err
		}
		s.jar = jar
	}
	// A missing http3 section in the profile must surface when the session is
	// created, not on the first request.
	if opts.HTTP3 && !p.HTTP3.Enabled() {
		return nil, fmt.Errorf("profile %q has no http3 section, so it cannot speak HTTP/3", p.Name)
	}
	// A proxy for QUIC is not implemented. Silently going direct is not an
	// option: that would reveal the very address the proxy was meant to hide.
	if opts.HTTP3 && opts.Proxy != "" {
		return nil, fmt.Errorf("HTTP/3 through a proxy is not supported: QUIC needs " +
			"CONNECT-UDP (RFC 9298), which no available library implements. " +
			"Drop either http3 or the proxy")
	}
	return s, nil
}

// Close closes every connection of the session and forbids further use.
//
// Without the ban a parallel request managed to create a connection after the
// pool was drained — and there would be nobody left to close it.
func (s *Session) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conns := s.conns
	orphans := s.orphans
	s.conns = map[dialSpec][]*conn{}
	s.orphans = map[*conn]struct{}{}
	s.mu.Unlock()

	s.closeH3()
	for _, list := range conns {
		closeAll(list)
	}
	// The orphans were finishing their streams; when the session closes there is no point waiting.
	for c := range orphans {
		c.close()
	}
}

// ensureOpen rejects work on a closed session.
func (s *Session) ensureOpen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSessionClosed
	}
	return nil
}

var errSessionClosed = errors.New("session is closed")

// Do performs a request, walking the redirect chain when needed, and returns
// the body whole.
func (s *Session) Do(r *Request) (*Response, error) {
	stream, err := s.DoStream(r)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	// The body limit: without it a server with an endless response eats the
	// process memory whole. One byte more is read to tell "exactly the limit"
	// from "over the limit".
	var reader io.Reader = stream
	if limit := s.opts.MaxResponseSize; limit > 0 {
		reader = io.LimitReader(stream, limit+1)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if limit := s.opts.MaxResponseSize; limit > 0 && int64(len(data)) > limit {
		return nil, withCode(CodeTooLarge, fmt.Errorf(
			"response body is larger than the max_response_size limit of %d bytes; "+
				"read it as a stream to handle a body this large without collecting it in memory",
			limit))
	}
	return &Response{
		History: stream.History,
		Status:  stream.Status,
		Headers: stream.Headers,
		Body:    data,
		Proto:   stream.Proto,
		URL:     stream.URL,
	}, nil
}

// prepare expands a multipart form into the request body.
//
// The header map is always copied: on a retry the same *Request passes through
// here twice, and writing content-type into the caller's map would distort
// their request, and the fingerprint with it.
func (s *Session) prepare(r *Request) (Request, error) {
	out := *r
	out.Headers = make(map[string]string, len(r.Headers))
	for k, v := range r.Headers {
		out.Headers[k] = v
	}
	if out.Multipart == nil {
		return out, nil
	}
	if len(out.Body) > 0 {
		return out, fmt.Errorf("request has both Body and Multipart set: pass exactly one")
	}
	body, contentType, err := encodeMultipart(out.Multipart, s.profile.FormBoundaryStyle())
	if err != nil {
		return out, err
	}
	out.Body = body
	// The boundary cannot be set from outside: it was generated here and must
	// match the body.
	out.Headers["content-type"] = contentType
	out.Multipart = nil
	return out, nil
}

// send performs one request, ignoring redirects.
//
// The response body stays open, and the context cancel is returned with it:
// whoever closes the body must call it, or the timeout keeps ticking on a
// request that has already finished.
// The connection is returned as well: the caller must release it through
// Session.release once the body has been read.
func (s *Session) send(r *Request, deadline time.Time) (*http.Response, context.CancelFunc, *conn, error) {
	u, err := url.Parse(r.URL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, nil, nil, fmt.Errorf("only https is supported, got scheme %q", u.Scheme)
	}

	method := r.Method
	if method == "" {
		method = http.MethodGet
	}

	body, size, err := requestBody(r)
	if err != nil {
		return nil, nil, nil, err
	}
	req, err := http.NewRequest(method, r.URL, body)
	if err != nil {
		if c, ok := body.(io.Closer); ok {
			c.Close()
		}
		return nil, nil, nil, err
	}
	// The limit lives in the request context: HTTP/2 reads it itself, while
	// HTTP/1.1 moves it onto the socket deadline (see conn.roundTrip).
	//
	// One deadline covers the whole chain rather than each step: otherwise twenty
	// redirects would stretch into twenty timeouts instead of one.
	// The cancel is returned to the caller and invoked when the body is closed:
	// until then reading must stay under the same limit.
	var cancel context.CancelFunc
	if !deadline.IsZero() {
		var ctx context.Context
		ctx, cancel = context.WithDeadline(r.context(), deadline)
		req = req.WithContext(ctx)
	} else if parent := r.context(); parent != context.Background() {
		var ctx context.Context
		ctx, cancel = context.WithCancel(parent)
		req = req.WithContext(ctx)
	}
	if r != nil && r.ConnectTimeout != nil {
		req = req.WithContext(withConnectLimit(req.Context(), *r.ConnectTimeout))
	}
	// Without an explicit size the transport would switch to chunked encoding,
	// which a browser does not use when uploading a file.
	if size >= 0 {
		req.ContentLength = size
	}

	fail := func(err error) (*http.Response, context.CancelFunc, *conn, error) {
		// The body may still be an open file: without closing it the descriptor
		// leaks, and with retries it multiplies by the number of attempts.
		if c, ok := body.(io.Closer); ok {
			c.Close()
		}
		if cancel != nil {
			cancel()
		}
		return nil, nil, nil, err
	}

	// The HTTP/3 branch sits here rather than earlier: before the context existed
	// it went out with no timeout at all, and a stuck request hung forever.
	// sendH3 builds its own headers: it needs no fhttp request.
	// The Alt-Svc upgrade applies to direct connections only: QUIC does not pass
	// through a proxy, and there is nothing to offer there.
	forced := r.protocol()
	viaAltSvc := forced == "" && !s.opts.HTTP3 &&
		s.proxyForHost(r, u.Host) == "" && s.altSvcH3(u)
	if forced == ProtoH3 || (forced == "" && s.opts.HTTP3) || viaAltSvc {
		// The session option was checked when it was created; a request's demand
		// only here: before it the profile might never have been needed.
		if !s.profile.HTTP3.Enabled() {
			return fail(&fatalError{fmt.Errorf(
				"protocol=%s: profile %q has no http3 section",
				ProtoH3, s.profile.Name)})
		}
		if s.proxyForHost(r, u.Host) != "" {
			return fail(&fatalError{fmt.Errorf("HTTP/3 through a proxy is not supported " +
				"(QUIC needs CONNECT-UDP, RFC 9298)")})
		}
		resp, err := s.sendH3(req.Context(), r, u)
		if err == nil {
			// HTTP/3 keeps its own connection inside the transport, nothing to release.
			return fromStdResponse(resp), cancel, nil, nil
		}
		if !viaAltSvc {
			return fail(err)
		}
		// The upgrade was our guess from the site's advertisement — fall back to
		// TCP and stop trying for a while, as a browser does.
		s.markAltSvcBroken(u)
	}

	forceH1 := s.opts.ForceHTTP1
	if forced != "" {
		forceH1 = forced == ProtoHTTP1
	}
	spec := s.newDialSpec(u, s.proxyForHost(r, u.Host), forceH1)
	c, err := s.conn(req.Context(), u, spec)
	if err != nil {
		// No connection — the request never reached the server, a retry is safe.
		return fail(&unprocessedError{err})
	}
	// The connection is alive, just of the wrong protocol: return it to the pool
	// and fail. A retry is pointless — the server would negotiate the same.
	if forced == ProtoH2 && c.proto != "h2" {
		s.release(c)
		return fail(&fatalError{fmt.Errorf(
			"protocol=%s: server negotiated %s. The ALPN list is left intact on purpose: "+
				"no browser offers h2 alone", ProtoH2, c.proto)})
	}
	// The headers are built after the connection is chosen: HTTP/1.1 order and
	// case depend on what the server negotiated, not on an option.
	s.applyHeaders(req, r, u, c.proto == "http/1.1")

	resp, err := c.roundTrip(req.Context(), req)
	if err != nil {
		// The connection is no longer usable. For HTTP/2 close it gently: a hard
		// close would cut the streams of neighbouring requests.
		s.release(c)
		s.evict(c, c.h2 == nil)
		err = fmt.Errorf("request failed: %w", err)
		if c.h2 != nil && h2Unprocessed(err) {
			return fail(&unprocessedError{err})
		}
		return fail(err)
	}

	if s.useCookies(r) {
		if cookies := resp.Cookies(); len(cookies) > 0 {
			s.jar.SetCookies(u, cookies)
			s.recordCookies(u, cookies)
		}
	}
	return resp, cancel, c, nil
}

func (s *Session) dial(ctx context.Context, u *url.URL, ds dialSpec) (*conn, error) {
	// The connect limit covers both TCP and the TLS handshake: for the caller
	// this is one phase, "no connection yet", and splitting it serves nobody.
	dialCtx, done := s.connectContext(ctx)
	defer done()

	raw, err := s.dialRaw(dialCtx, ds.addr, ds.proxy)
	if err != nil {
		return nil, err
	}

	// The spec is built per connection: ShuffleChromeTLSExtensions mutates the
	// slice in place, so reusing it would freeze the order.
	spec, err := profile.BuildSpec(s.profile)
	if err != nil {
		raw.Close()
		return nil, err
	}

	// ALPN lives inside the spec, and ApplyPreset overrides Config.NextProtos.
	// So restricting the protocol means editing the extension, not the config.
	// The fingerprint changes legitimately: a browser without h2 looks like this.
	//
	// The flag comes from dialSpec rather than from the session options: it is
	// part of the pool key, so a WebSocket h1 connection cannot replace the h2 one.
	if ds.forceHTTP1 {
		if !setALPN(spec, []string{"http/1.1"}) {
			raw.Close()
			return nil, fmt.Errorf("force_http1: profile %q has no ALPN extension to restrict", s.profile.Name)
		}
	}

	cfg := &utls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: s.opts.InsecureSkipVerify,
		RootCAs:            s.roots,
		Certificates:       s.clientCerts,
		// Profiles captured on a resumed connection contain pre_shared_key.
		// On a first connection there is no ticket yet, and uTLS refuses by
		// default to send an empty extension. A browser in that situation simply
		// does not send it — OmitEmptyPsk reproduces exactly that.
		OmitEmptyPsk: true,
	}
	if len(s.alpn) > 0 {
		cfg.NextProtos = s.alpn
	}

	uconn := utls.UClient(raw, cfg, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		raw.Close()
		return nil, fmt.Errorf("ApplyPreset: %w", err)
	}
	// The handshake runs under the same limit as TCP: a host that accepted the
	// connection and went silent would otherwise eat the whole request budget.
	if err := uconn.HandshakeContext(dialCtx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	// The protocol was chosen by the server. An empty ALPN means HTTP/1.1 — that
	// is how browser profiles that do not offer h2 behave.
	switch proto := uconn.ConnectionState().NegotiatedProtocol; proto {
	case "h2":
		cc, err := s.transport().NewClientConn(uconn)
		if err != nil {
			uconn.Close()
			return nil, fmt.Errorf("h2: %w", err)
		}
		return newH2Conn(cc, ds), nil
	case "http/1.1", "":
		return newH1Conn(uconn, ds), nil
	default:
		uconn.Close()
		return nil, fmt.Errorf("server negotiated %q, which is not supported", proto)
	}
}

// transport builds the HTTP/2 transport from the profile.
func (s *Session) transport() *http2.Transport {
	h2 := s.profile.HTTP2

	settings := make(map[http2.SettingID]uint32, len(h2.Settings))
	order := make([]http2.SettingID, 0, len(h2.Settings))
	for _, st := range h2.Settings {
		id := http2.SettingID(st.ID)
		settings[id] = st.Value
		order = append(order, id)
	}

	// TLSClientConfig is not set: the handshake is done by uTLS, and
	// NewClientConn receives an already established connection.
	tr := &http2.Transport{
		Settings:          settings,
		SettingsOrder:     order,
		ConnectionFlow:    h2.ConnectionWindowUpdate,
		PseudoHeaderOrder: h2.PseudoOrder,
	}
	// Priority on the HEADERS frame.
	//
	// A value of 0 means "do not send": that is how Safari behaves. A zero
	// PriorityParam does not set the PRIORITY flag, whereas nil would make
	// fhttp substitute its own default (weight 255, exclusive) — which happens
	// to be right for Chrome and wrong for everyone else.
	if h2.StreamWeight != nil {
		if *h2.StreamWeight == 0 {
			tr.HeaderPriority = &http2.PriorityParam{}
		} else {
			excl := h2.StreamExclusive != nil && *h2.StreamExclusive
			// On the wire the weight is one less than declared (RFC 7540).
			tr.HeaderPriority = &http2.PriorityParam{
				StreamDep: 0,
				Exclusive: excl,
				Weight:    uint8(*h2.StreamWeight - 1),
			}
		}
	}
	return tr
}
