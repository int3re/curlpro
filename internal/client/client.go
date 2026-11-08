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
	"golang.org/x/net/idna"
	"io"
	"net"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/fhttp/http2/hpack"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/profile"
)

// DefaultMaxRedirects repeats the limit browsers use.
const DefaultMaxRedirects = 20

// Options configure a session.
type Options struct {
	// InsecureSkipVerify turns certificate verification off.
	InsecureSkipVerify bool
	// Timeout caps every request as a whole, redirects included. 0 means no
	// limit: a video, a download, a server-sent event stream or a long poll
	// is read for as long as it lasts (until 0.31 a zero became 30 seconds,
	// while the C ABI and the Python docs promised none).
	Timeout time.Duration
	// IdleTimeout aborts a response whose body stops arriving: no byte for
	// this long while a read waits for one. 0 means no idle limit. It is the
	// bound a stream without a total limit wants — a dead peer is noticed,
	// and a live one is read however long it takes.
	IdleTimeout time.Duration
	// Proxy is http://, https:// or socks5:// with optional user:pass.
	Proxy string

	// DefaultHeaders enables the profile's headers.
	// With it off the caller controls the set and the order completely —
	// anti-bot systems look at the order too, so that control belongs outside.
	DefaultHeaders bool
	// HeaderOrder edits the send order: names, with "..." (OrderEllipsis) for
	// the profile's own order — see expandOrder. A list without "..." is the
	// list followed by the rest of the profile.
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
	// ResponseTimeout caps waiting for the response headers: from the request
	// going out to the status line arriving. 0 means the total limit only.
	//
	// The gap the other two leave: a server that accepts the connection and
	// then thinks for a minute before answering is past ConnectTimeout and
	// still inside Timeout. This is the limit for that silence. The body is
	// not bounded by it — once the headers are in, only Timeout applies.
	ResponseTimeout time.Duration

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

	// TicketCache names a group of sessions that share their TLS tickets, so
	// one resumes a connection another opened (tickets.go): sessions of one
	// identity, as a proxy opening a session per client connection runs
	// them. Empty, the session keeps its own. Needs Resume.
	TicketCache string

	// DisableDecompression hands bodies over as they came: compressed, with
	// their Content-Encoding and Content-Length, the way a transparent proxy
	// relays them (a 206 of a compressed resource stays a valid range, and
	// the size is the size on the wire). Off, the body is decoded — gzip, br,
	// zstd, deflate — as the profile's Accept-Encoding promises.
	DisableDecompression bool

	// ExpectContinueTimeout is how long a request with Expect: 100-continue
	// holds its body for the server's 100 (or its final answer, which leaves
	// the body unsent). 0 means a second, as curl and net/http wait;
	// negative, the body goes at once (the behaviour until 0.33).
	ExpectContinueTimeout time.Duration

	// Resolve overrides a host's address without touching the name in SNI or Host.
	//
	// The key is "host:port" or just "host" (then the rule applies to any port),
	// the value is "ip" or "ip:port". The equivalent of curl's --resolve: it is how
	// you reach one specific server behind a balancer, or test a stand under a real
	// name. The fingerprint does not change: the name stays the same, only the
	// socket destination moves.
	Resolve map[string]string

	// ResolveViaProxy says what Resolve does behind a proxy. "name" (or
	// empty): nothing — the tunnel names the host and the proxy resolves it,
	// as curl's --resolve. "ip": the tunnel goes to the table's address —
	// CONNECT ip:port, SOCKS5's IPv4/IPv6 form, MASQUE's target — while SNI
	// and Host keep the name; a proxy pinned to the address a client chose
	// keeps it. Response.Conn.ResolvedBy says which happened.
	ResolveViaProxy string

	// LocalAddress is the address connections leave from — an IP of this
	// machine, the port chosen by the system: a route past a VPN, one
	// interface of several (0.36). TCP, the proxy's connection included,
	// and QUIC's UDP. Empty: the system's choice.
	LocalAddress string

	// DNS chooses what resolves names and whether HTTPS records are asked for
	// first, as the browser asks (dns.go): "" the system's servers, "off" none,
	// "1.1.1.1,8.8.8.8" those servers, "https://..." DNS over HTTPS.
	DNS string

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

	// DisablePostQuantum drops the post-quantum hybrid group from the
	// ClientHello: X25519MLKEM768 leaves supported_groups and its 1216-byte
	// key share leaves key_share. That is the hello of Chrome under the
	// PostQuantumKeyAgreementEnabled=false policy and of Firefox with
	// security.tls.enable_kyber off — a client that exists. Nothing else
	// moves, so JA4 is unchanged; JA3 (which hashes the groups) and the size
	// change: a ~1.9 KB hello that spans two TCP segments becomes one that
	// fits in one. Off by default, because the browser sends the share.
	DisablePostQuantum bool

	// Resume turns on TLS session resumption.
	//
	// A browser talking to one host resumes constantly: it keeps the ticket the
	// server issued and the next connection is abbreviated. A client that never
	// resumes is an observable anomaly — and one that no fingerprint here
	// measures, because JA3, JA4, JA4H and the Akamai string are all computed
	// from the *first* handshake. The tell lives in the second.
	//
	// Off by default. Resuming changes the ClientHello: pre_shared_key appears,
	// last, carrying the ticket. That is what a browser does too, but the shape
	// of the resumed hello has not been measured against the oracles here, and
	// this project does not turn on what it has not measured.
	Resume bool

	// HTTP3 sends requests over QUIC instead of TCP.
	//
	// This is a separate transport, not an ALPN variant, so it is chosen explicitly.
	// The profile must describe an http3 section or the session will not be created.
	HTTP3 bool

	// Retry configures retries. nil means no retries.
	Retry *RetryPolicy

	// Cache switches the HTTP cache on (cache.go): fresh responses come back
	// without a request, stale ones are revalidated the way the browser
	// revalidates them. nil — the default — keeps every request on the network.
	Cache *CacheOptions

	// Mode selects the header set: "navigate" for a page load, "fetch" for
	// fetch/XHR, "" or "auto" to decide from the request (see modeFor).
	Mode string

	// Page is the URL of the page the session's requests are made from — the
	// initiator. With it set, three headers are derived the way a browser
	// derives them (measured on Chrome 153 and Firefox 156, identical):
	// Referer is the page's URL to its own origin and the page's origin
	// elsewhere (strict-origin-when-cross-origin, the default policy); Origin
	// is the page's origin, on every cross-origin fetch and on any request
	// with a body; sec-fetch-site is the relation between the page and the
	// URL — same-origin, same-site or cross-site — and degrades along a
	// redirect chain. Without a page the profile's own values go out: a
	// navigation typed into the bar (sec-fetch-site: none, no Referer) and a
	// fetch from the request's own origin.
	Page string

	// TopLevel is the URL of the page in the address bar when Page is a
	// frame's document: a captcha's or a widget's frame, whose requests
	// are made from the frame and under the page that embeds it. The
	// cache, the connections and the partitioned cookies are keyed by its
	// site (partition.go). Empty takes the Page itself for the top level;
	// a top-level navigation is always under its own URL.
	TopLevel string

	// Credentials is the credentials mode of fetch-mode requests, in the
	// words of fetch(): "same-origin" — cookies only to the page's own
	// origin, which is the default of fetch() and of XMLHttpRequest;
	// "include" — cookies to any origin the SameSite rules allow; "omit" —
	// none. Empty means same-origin. Measured on Chrome 153 and Firefox
	// 156: a plain fetch() to another origin of the same site carries no
	// cookie at all, and with include to another site only those marked
	// SameSite=None. Without a Page there is nothing to be same-origin
	// with and every cookie goes; a navigation has no credentials mode.
	Credentials string

	// DisableSameSite sends every cookie the jar matches whatever the
	// initiator — the behaviour before 0.10. Off, a request made from a
	// Page carries across sites only what the browser family would send:
	// the SameSite attribute, Chromium's Lax-by-default with its two-minute
	// POST window, the third-party rule of Firefox and Safari, and the
	// refusal of SameSite=None without Secure. See profile.CookiePolicy.
	DisableSameSite bool

	// DisablePreflight sends a cross-origin fetch straight out, without the
	// OPTIONS a browser sends first when the request is not "simple" — the
	// behaviour before 0.10. Off, the preflight goes when the Fetch
	// standard says it must, its answer is checked and cached for its
	// Access-Control-Max-Age, and a refusal is a *CORSError: the request
	// itself is not sent, because a browser would not send it.
	DisablePreflight bool

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

	// H2Priority, when set, is this request's priority in its HTTP/2
	// HEADERS frame, in place of the profile's stream_weight and
	// stream_exclusive: Chrome gives every resource type its own weight (256
	// a document, 220 a stylesheet, 110 an image…), and a proxy relays the
	// client's. Weight is 1–256 as RFC 7540 counts it.
	H2Priority *H2Priority

	// NewConnection sends the request on a connection of its own, opened
	// for it and pooled after; ConnectionID on the open connection with
	// that ID (Response.Conn.ID) — a proxy keeps each client connection to
	// one server connection that way. Either covers the request's first hop
	// and takes it past HTTP/3 and past the resend on another connection:
	// a connection named and gone is an error (conn_closed), not a detour.
	NewConnection bool
	ConnectionID  uint64

	// ConnectProtocol makes an Upgrade an extended CONNECT on HTTP/2 (RFC
	// 8441) with this :protocol — "websocket" for WebSocket over HTTP/2, as
	// Chrome opens it where the server allows it. Upgrade only.
	ConnectProtocol string

	// ConnectAuthority makes an Upgrade a plain CONNECT on HTTP/2 (RFC 9113
	// 8.5) to this host:port, sent to the URL's origin as to a proxy:
	// :method and :authority only, the headers as given (a browser's proxy
	// credentials — Chrome's chrome-tunnel to googlezip.net), on the
	// origin's connection beside its other streams, as a browser tunnels
	// through an HTTPS proxy. No SETTINGS_ENABLE_CONNECT_PROTOCOL is needed.
	// Upgrade only; not with ConnectProtocol.
	ConnectAuthority string

	// TargetRaw is the request-target — path and query — sent exactly as
	// given in place of the URL's, which still names the host, the scheme
	// and the cookies' path: the bytes a client relayed through a proxy sent
	// (an app's own encoding, a path a signature was computed over). On
	// HTTP/1.1 a space would split the request line and is refused. The
	// first hop only.
	TargetRaw string

	// LocalAddress overrides the session's for this request's connection
	// (TCP; HTTP/3 keeps the session's, its transport being one per
	// session). Part of the pool key: a connection from another address is
	// not taken.
	LocalAddress string

	// OnInterim hears of each 1xx response the moment it is read, before the
	// final one: a proxy relays a 103 Early Hints or a 100 Continue as it
	// comes. It runs on the transport's goroutine and must not block.
	OnInterim func(Interim)

	// HeadersRaw, when set, is the request's whole header set, sent as
	// given: in this order, in this case on HTTP/1.1 (HTTP/2 and HTTP/3 write
	// names lowercase, as they must), a name given twice sent twice. Nothing
	// is added — not the profile's headers, not the session's, not the jar's
	// cookies — beyond what the protocol needs: Host on HTTP/1.1 when the
	// list has none, the body's length. It is what a proxy relaying a
	// client's request wants: the client's headers, on the profile's TLS and
	// frames. Repeats of one name go out together, where its first one
	// stands. Exclusive with Headers and HeaderOrder.
	HeadersRaw [][2]string

	// Multipart, when set, is encoded into the body with a boundary in the
	// profile's style. Mutually exclusive with Body.
	Multipart *MultipartForm

	// BodyFile is the path to a file sent as the request body.
	//
	// The file is streamed rather than read into memory: sending a gigabyte
	// archive must not need a gigabyte of RAM. Mutually exclusive with Body.
	BodyFile string
	// BodySize is the body size for Content-Length. Zero together with BodyFile
	// means "take it from the file"; with BodyStream, an unknown length.
	BodySize int64

	// BodyStream is a body written while the request is in flight — an
	// io.Pipe's reader the caller feeds: a gRPC client or bidirectional
	// stream, an upload relayed as it arrives rather than after it ended.
	// Without BodySize its length is unknown: chunked on HTTP/1.1, DATA
	// frames until END_STREAM on HTTP/2 and HTTP/3, where the response may
	// come back while the body is still being written (full duplex).
	//
	// It cannot be read twice, so a request with one is never replayed: no
	// retries, no resend on a fresh connection after a reused one died, no
	// HTTP/3 guessed from Alt-Svc or DNS (a lost race would have eaten part
	// of it), and a 307 or 308 is handed back rather than followed. The
	// transport closes it when it is done with it — early, too, when the
	// server answers before the body ended — which fails the writer's next
	// write instead of leaving it blocked.
	BodyStream io.ReadCloser
	// BodyTrailer, with BodyStream, holds the trailers sent after the body.
	// The map is filled before the stream's writer closes it; empty, the
	// body ends with no trailers. Only names it holds at the end go out, and
	// no Trailer header announces them, as no browser announces any.
	BodyTrailer http.Header

	// freshConn sends the request on a new connection, past the pool: the
	// resend after a reused connection died under it.
	freshConn bool

	// interim logs the 1xx responses that came before this hop's final one;
	// made by attempt, shared by the copies the cache makes of the request.
	interim *interimLog
	// hop is the connection and the wait this hop's response came with.
	hop *hopRecord

	// TrackCookies logs the records the request changes in the jar, so a
	// failure can be undone exactly (rollback_cookies): the log comes back on
	// the response, and a failed request is undone before it returns.
	TrackCookies bool
	cookieLog    *cookieLog

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
	// ResponseTimeout overrides the limit on waiting for the response headers.
	ResponseTimeout *time.Duration
	// IdleTimeout overrides the limit on a body that stops arriving.
	// For all four a zero is no limit for this request.
	IdleTimeout *time.Duration
	// Decompress overrides DisableDecompression for this request: false
	// hands the body over as it came, true decodes it; nil takes the session's.
	Decompress *bool
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

	// Page overrides the session's page for a single request: nil takes the
	// session's, an empty string means no page — a request with no initiator.
	Page *string
	// TopLevel overrides the session's TopLevel for a single request: nil
	// takes the session's, an empty string takes the page for the top level.
	TopLevel *string

	// CacheMode is how the request uses the session's cache, as fetch()'s
	// cache option: "default", "no-store", "no-cache" (revalidate whatever is
	// stored — a reload), "force-cache", "only-if-cached". Empty is "default".
	CacheMode string
	// condETag, condLastModified and reloadCacheControl are what the cache
	// puts into a conditional request, each into the profile's slot for it.
	condETag, condLastModified, reloadCacheControl string

	// Resource names the kind of resource the request loads — "image",
	// "script", "style", "font", "iframe" and the rest the profile's
	// resources section lists — and takes that kind's header set: its
	// Accept, sec-fetch-dest, sec-fetch-mode, priority and order. Empty for
	// a navigation or a fetch (Mode).
	Resource string
	// CrossOrigin is the crossorigin attribute of the element: "anonymous"
	// or "use-credentials" make the resource CORS; empty leaves it as its
	// kind is (a font and a module script are CORS on their own).
	CrossOrigin string

	// Credentials overrides the session's credentials mode for a single
	// fetch-mode request: "same-origin", "include" or "omit"; empty takes
	// the session's.
	Credentials string

	// chainOrigin and originTainted are set by nextRequest on the hops of a
	// redirect chain. chainOrigin is the origin the chain started from,
	// which is what Origin names once a hop has moved the request elsewhere
	// — not the new host's own origin. originTainted says a hop made the
	// request's origin opaque under the Fetch standard's redirect rule (or
	// Chromium's stricter one for navigations), and Origin goes out as
	// "null": measured on Chrome 153 and Firefox 156.
	chainOrigin   string
	originTainted bool

	// Preflight overrides the session's DisablePreflight for one request:
	// nil takes the session's, false sends without the OPTIONS, true sends
	// it when the Fetch standard requires one.
	Preflight *bool
	// preflight marks the OPTIONS itself, so it is never preflighted in
	// turn and takes the preflight header set.
	preflight bool

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

// noteMode remembers the header set a request is going out with.
func (s *Session) noteMode(r *Request) {
	mode := s.modeFor(r)
	s.mu.Lock()
	if s.modesUsed == nil {
		s.modesUsed = make(map[string]bool, 2)
	}
	s.modesUsed[mode] = true
	s.mu.Unlock()
}

// ModesUsed lists the header sets requests have gone out with so far, sorted.
func (s *Session) ModesUsed() []string {
	s.mu.Lock()
	out := make([]string, 0, len(s.modesUsed))
	for m := range s.modesUsed {
		out = append(out, m)
	}
	s.mu.Unlock()
	sort.Strings(out)
	return out
}

// useCookies decides whether the jar takes part in this request.
func (s *Session) useCookies(r *Request) bool {
	if s.cookieJar() == nil {
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

// pageFor returns the page the request is made from: the request's own, else
// the session's; empty means no initiator.
func (s *Session) pageFor(r *Request) string {
	if r != nil && r.Page != nil {
		return *r.Page
	}
	s.pageMu.RLock()
	defer s.pageMu.RUnlock()
	return s.opts.Page
}

// SetPage changes the session's page; an empty string means no initiator.
func (s *Session) SetPage(page string) error {
	if page != "" {
		if err := validatePage(page); err != nil {
			return err
		}
	}
	s.pageMu.Lock()
	s.opts.Page = page
	s.pageMu.Unlock()
	return nil
}

// hasTicket reports whether the session holds a TLS ticket for a host — that
// is, whether the next connection to it will try to resume. uTLS keys its
// cache by the ServerName, which is the host the dial sets.
func (s *Session) hasTicket(host string) bool {
	if s.tlsSessions == nil {
		return false
	}
	_, ok := s.tlsSessions.Get(host)
	return ok
}

// Page returns the session's page.
func (s *Session) Page() string {
	s.pageMu.RLock()
	defer s.pageMu.RUnlock()
	return s.opts.Page
}

// validatePage refuses a page that is not an absolute http(s) URL: the
// headers derived from it would be derived from nothing.
func validatePage(page string) error {
	u, err := url.Parse(page)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return configErr("page must be an absolute http(s) URL, got %q", page)
	}
	return nil
}

// validateTopLevel refuses a top level that is not an absolute http(s) URL.
func validateTopLevel(top string) error {
	if validatePage(top) != nil {
		return configErr("top_level must be an absolute http(s) URL, got %q", top)
	}
	return nil
}

// SetTopLevel changes the session's top-level page; an empty string takes
// the page for it.
func (s *Session) SetTopLevel(top string) error {
	if top != "" {
		if err := validateTopLevel(top); err != nil {
			return err
		}
	}
	s.pageMu.Lock()
	s.opts.TopLevel = top
	s.pageMu.Unlock()
	return nil
}

// TopLevel returns the session's top-level page.
func (s *Session) TopLevel() string {
	s.pageMu.RLock()
	defer s.pageMu.RUnlock()
	return s.opts.TopLevel
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
func (s *Session) proxyForHost(r *Request, scheme, host string) string {
	if r != nil && r.Proxy != nil {
		return *r.Proxy
	}
	if s.opts.Proxy != "" {
		return s.opts.Proxy
	}
	if s.opts.TrustEnv {
		return proxyFromEnv(scheme, host)
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
	// A request's own limit wins, a zero one too: no separate connect limit.
	if d, ok := ctx.Value(connectLimitKey{}).(time.Duration); ok {
		limit = d
	}
	if limit <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, limit)
}

// timeout returns the limit for a request, honouring its override; 0 is no
// limit.
//
// Zero means the same at both levels now. It used to mean 30 seconds in the
// options and an error in a request, while the C ABI documented "0 = none":
// a stream of video or server-sent events was cut off at 30 seconds unless
// the caller set a day.
func (s *Session) timeout(r *Request) time.Duration {
	if r != nil && r.Timeout != nil {
		return *r.Timeout
	}
	return s.opts.Timeout
}

// decompress reports whether this request's body is decoded.
func (s *Session) decompress(r *Request) bool {
	if r != nil && r.Decompress != nil {
		return *r.Decompress
	}
	return !s.opts.DisableDecompression
}

// rawBodyKey marks, in a request's context, a body to be handed over as it
// came: conn.roundTrip reads it on HTTP/1.1 and HTTP/2.
type rawBodyKey struct{}

func wantsDecoded(ctx context.Context) bool {
	raw, _ := ctx.Value(rawBodyKey{}).(bool)
	return !raw
}

// expectContinue is the session's wait for a 100, 0 for none.
func (s *Session) expectContinue() time.Duration {
	switch t := s.opts.ExpectContinueTimeout; {
	case t < 0:
		return 0
	case t == 0:
		return time.Second
	default:
		return t
	}
}

// expectKey carries the session's wait for a 100 Continue to the HTTP/1.1
// path, which has no transport to hold it (HTTP/2's does).
type expectKey struct{}

func expectWait(ctx context.Context) time.Duration {
	d, _ := ctx.Value(expectKey{}).(time.Duration)
	return d
}

// idleTimeout returns the limit on a body that stops arriving; 0 is none.
func (s *Session) idleTimeout(r *Request) time.Duration {
	if r != nil && r.IdleTimeout != nil {
		return *r.IdleTimeout
	}
	return s.opts.IdleTimeout
}

// responseTimeout returns the limit on waiting for the response headers,
// honouring the request's override.
func (s *Session) responseTimeout(r *Request) time.Duration {
	if r != nil && r.ResponseTimeout != nil {
		return *r.ResponseTimeout
	}
	return s.opts.ResponseTimeout
}

// validate checks the request overrides before sending. hasJar says whether the
// session has a cookie jar: without one, asking for cookies is a mistake worth
// reporting rather than a silently ignored option.
func (r *Request) validate(hasJar bool) error {
	if r == nil {
		return nil
	}
	// Zero is no limit for this request; leaving a field unset takes the
	// session's.
	for _, t := range []struct {
		name string
		d    *time.Duration
	}{{"timeout", r.Timeout}, {"connect timeout", r.ConnectTimeout},
		{"response timeout", r.ResponseTimeout}, {"idle timeout", r.IdleTimeout}} {
		if t.d != nil && *t.d < 0 {
			return configErr("%s cannot be negative, got %s (0 is no limit)", t.name, *t.d)
		}
	}
	if err := checkLocalAddress(r.LocalAddress); err != nil {
		return err
	}
	if r.TargetRaw != "" {
		if err := checkTarget(r.TargetRaw); err != nil {
			return err
		}
	}
	if r.NewConnection && r.ConnectionID != 0 {
		return configErr("a request takes a new connection or a named one, not both")
	}
	if p := r.H2Priority; p != nil && (p.Weight < 1 || p.Weight > 256) {
		return configErr("h2_priority weight %d: RFC 7540 weights are 1 to 256", p.Weight)
	}
	if len(r.HeadersRaw) > 0 && (len(r.Headers) > 0 || len(r.HeaderOrder) > 0) {
		return configErr("headers_raw is the whole header set: it takes no headers or header_order beside it")
	}
	for _, kv := range r.HeadersRaw {
		// A pseudo-header relayed from an HTTP/2 or HTTP/3 request is left out:
		// :method, :scheme, :authority and :path come from the request itself.
		if strings.HasPrefix(kv[0], ":") {
			continue
		}
		if kv[0] == "" || strings.ContainsAny(kv[0], " \t\r\n:") || strings.ContainsAny(kv[1], "\r\n") {
			return configErr("headers_raw: not a header field: %q: %q", kv[0], kv[1])
		}
	}
	if r.Cookies != nil && *r.Cookies && !hasJar {
		return configErr("cookies=true: the session has no cookie jar " +
			"(create the session with cookies enabled)")
	}
	if err := validateOrder(r.HeaderOrder); err != nil {
		return err
	}
	if r.Page != nil && *r.Page != "" {
		if err := validatePage(*r.Page); err != nil {
			return err
		}
	}
	if r.TopLevel != nil && *r.TopLevel != "" {
		if err := validateTopLevel(*r.TopLevel); err != nil {
			return err
		}
	}
	if err := validateCredentials(r.Credentials); err != nil {
		return err
	}
	if err := validateCacheMode(r.CacheMode); err != nil {
		return err
	}
	switch r.Protocol {
	case "", ProtoHTTP1, ProtoH2, ProtoH3:
	default:
		return configErr("unknown protocol %q: use %q, %q or %q",
			r.Protocol, ProtoHTTP1, ProtoH2, ProtoH3)
	}
	if r.MaxRedirects != nil && *r.MaxRedirects < 0 {
		return configErr("max_redirects cannot be negative, got %d",
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
	// RawHeaders is the header block as it came (Stream.RawHeaders).
	RawHeaders [][2]string
	Body       []byte
	Proto      string
	URL        string // the final URL after redirects
	// History holds the redirects that were followed, first to last.
	History []Redirect
	// Preflights are the CORS preflights sent (or found cached) before the
	// request and its redirect hops, in order. Empty when none was needed.
	Preflights []Preflight
	// CookieChanges are the jar records the request changed, when it was
	// asked to track them (Request.TrackCookies).
	CookieChanges []CookieChange
	// Cache is how the session's cache served the final response: "hit",
	// "revalidated", "miss", or "" without a cache or for a request it
	// does not take (a POST, a no-store).
	Cache string
	// Interim are the 1xx responses that came before the final one.
	Interim []Interim
	// Conn is the connection the response came over; Timing its wait.
	Conn   *ConnInfo
	Timing *Timing
	// Trailers are the fields the server sent after the body (gRPC's
	// grpc-status, grpc-message); nil when it sent none.
	Trailers map[string][]string
	// TrailersRaw is the trailer block as it came, as RawHeaders is the
	// header block: names in the server's case and order (0.35).
	TrailersRaw [][2]string
}

// Session performs requests with a single profile.
type Session struct {
	profile *profile.Profile
	opts    Options
	alpn    []string
	// jar is swapped by ClearCookies while requests read it: atomic.
	jar atomic.Pointer[cookiejar.Jar]

	// tlsSessions holds the tickets servers issued to this session, so a second
	// connection to the same host can be abbreviated the way a browser's is.
	// Nil unless Options.Resume is set.
	tlsSessions utls.ClientSessionCache

	// pageMu guards opts.Page and opts.TopLevel: a scraper moves the page
	// between requests while async requests may be in flight.
	pageMu sync.RWMutex

	mu    sync.Mutex
	conns map[dialSpec][]*conn
	// dialing holds the attempts a burst is waiting on, per key; aliases
	// the connections other names took on by address (ConnPolicy). Under mu.
	dialing map[dialSpec]*dialGroup
	aliases map[dialSpec]*conn
	// connPolicy is the family's way of spending connections, and offersH2
	// says the ClientHello offers HTTP/2 at all: without it every
	// connection is HTTP/1.1 and a burst has nothing to wait for.
	connPolicy profile.ConnPolicy
	offersH2   bool
	// lastSweep is when the pool was last swept for expired and dead
	// connections. Under mu.
	lastSweep time.Time

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

	// chPolicy is the ch-* part of the Permissions-Policy of each origin's
	// last top-level page: which origins its hints may go to. Under mu.
	chPolicy map[string]map[string]allowlist

	// salts are the random numbers of the network hints' noise, the
	// browser's and the renderer's (hintSalt), drawn on first use.
	saltOnce sync.Once
	salts    [2]uint32

	// blinkMap says the profile is a Chromium whose pages' requests lay
	// their headers out through Blink's rapidhash map (pageOrder): 129 and
	// later. Set once in New.
	blinkMap bool

	// cookies is our own cookie record for export: the jar yields only the
	// name-value pair for an address, and that is not enough to save a session.
	cookies map[string]Cookie
	// cookieSeq numbers the records in the order they were created, which
	// is how cookies of two jars interleave in one header.
	cookieSeq uint64
	// parts are the partitioned jars, by top-level site (cookies.go).
	// Under mu; partsUsed says there is one, without the mutex.
	parts     map[string]*cookiejar.Jar
	partsUsed atomic.Bool

	// modesUsed are the header sets requests actually went out with. The
	// audit judges what was sent, not what the constructor was told: a
	// session built without a mode whose every request says mode="fetch"
	// is a fetch session, and a warning keyed on the constructor never fired.
	modesUsed map[string]bool

	// preflights caches allowing CORS preflight answers by origin, URL and
	// credentials mode, for their Access-Control-Max-Age. Under mu.
	preflights map[string]*preflightEntry

	// altSvc holds the HTTP/3 advertisements per origin along with the "broken" mark.
	altSvc map[string]altSvcEntry
	// quicWorks: a QUIC handshake has completed in this session, which is
	// what lets a race hold its TCP job back; h3rtt is the handshake time per
	// origin, the RTT the hold is measured by (race.go). h3rtt under mu.
	quicWorks atomic.Bool
	h3rtt     map[string]time.Duration

	// tpl holds the header sets resolved once from the profile.
	tpl templates

	// cache is the HTTP cache, nil when the session has none.
	cache *httpCache

	// roots and clientCerts are prepared once when the session is created:
	// reading files per connection is wasted I/O on the hot path.
	roots       *x509.CertPool
	clientCerts []utls.Certificate

	h3 h3Transport
	// masque holds what is open towards MASQUE proxies: one HTTP/3 connection
	// per proxy and the tunnels on it (proxyh3.go).
	masque masqueProxies
	// h2proxies are the HTTP/2 connections to https:// proxies that agreed
	// to h2, shared by the tunnels on them (proxyh2.go).
	h2proxies h2Proxies

	// dns resolves names and asks for HTTPS records (dns.go).
	dns dnsState
	// echCapable: a Chromium or Firefox profile whose hello carries ECH, which
	// uses an origin's ECH configuration when DNS publishes one; echInner is
	// how that browser builds the inner hello (scripts/patch-utls.py).
	echCapable bool
	echInner   utls.ECHInnerStyle
}

// New creates a session. The profile spec is checked right away so that a data
// error surfaces at creation rather than on the first request.
func New(p *profile.Profile, opts Options) (*Session, error) {
	if p == nil {
		return nil, configErr("no profile given: a session needs one to build its fingerprint")
	}
	helloSpec, err := profile.BuildSpec(p)
	if err != nil {
		return nil, err
	}
	if opts.Timeout < 0 {
		return nil, configErr("timeout cannot be negative, got %s", opts.Timeout)
	}
	if opts.ResponseTimeout < 0 {
		return nil, configErr("response timeout cannot be negative, got %s", opts.ResponseTimeout)
	}
	if opts.IdleTimeout < 0 {
		return nil, configErr("idle timeout cannot be negative, got %s", opts.IdleTimeout)
	}
	if err := checkLocalAddress(opts.LocalAddress); err != nil {
		return nil, err
	}
	switch opts.ResolveViaProxy {
	case "", "name", "ip":
	default:
		return nil, configErr("resolve_via_proxy %q: \"name\" (the proxy resolves) or \"ip\" "+
			"(the tunnel goes to the resolve table's address)", opts.ResolveViaProxy)
	}
	if opts.TicketCache != "" && !opts.Resume {
		return nil, configErr("ticket_cache %q shares tickets, and the session has resumption off", opts.TicketCache)
	}
	// A session-wide fetch on a profile without a fetch set is refused here,
	// once, rather than on every request.
	if err := modeError(p, opts.Mode); err != nil {
		return nil, err
	}
	if err := validateOrder(opts.HeaderOrder); err != nil {
		return nil, err
	}
	if opts.Page != "" {
		if err := validatePage(opts.Page); err != nil {
			return nil, err
		}
	}
	if opts.TopLevel != "" {
		if err := validateTopLevel(opts.TopLevel); err != nil {
			return nil, err
		}
	}
	if err := validateCredentials(opts.Credentials); err != nil {
		return nil, err
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
			// "this profile has no devices" is the profile's limit, "that
			// device is not in the list" is the caller's typo: a retry helps
			// with neither, and the codes say which to fix.
			if !p.HasDevices() {
				return nil, capabilityErr("%w", err)
			}
			return nil, asConfig(err)
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

	// Chrome 152 and 153 drew their trust_anchors order once per process.
	p = p.ForSession()

	s := &Session{
		echCapable: (profile.Chromium(p.Family()) || p.Family() == "firefox") && sendsECH(helloSpec),
		echInner:   echInnerStyle(p.Family()),
		profile:    p,
		opts:       opts,
		alpn:       alpnFromProfile(p),
		conns:      make(map[dialSpec][]*conn),
		dialing:    make(map[dialSpec]*dialGroup),
		aliases:    make(map[dialSpec]*conn),
		orphans:    make(map[*conn]struct{}),
		headers:    newSessionHeaders(),
		device:     dev,
		connPolicy: profile.ConnPolicyFor(p.Family()),
		offersH2:   offersH2(helloSpec),
		blinkMap:   blinkMapFor(p),
	}
	s.buildTemplates()
	if opts.Resume {
		// Thirty-two hosts is generous for one identity and small enough that
		// an abandoned session costs nothing. A named group is shared.
		s.tlsSessions = utls.NewLRUClientSessionCache(32)
		if opts.TicketCache != "" {
			s.tlsSessions = sharedTickets(opts.TicketCache)
		}
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
	if opts.Cache != nil {
		c, err := newHTTPCache(opts.Cache)
		if err != nil {
			return nil, err
		}
		s.cache = c
	}

	if opts.Cookies {
		jar, err := newCookieJar()
		if err != nil {
			return nil, err
		}
		s.jar.Store(jar)
	}
	// A missing http3 section in the profile must surface when the session is
	// created, not on the first request.
	if opts.HTTP3 && !p.HTTP3.Enabled() {
		return nil, capabilityErr("profile %q has no http3 section, so it cannot speak HTTP/3", p.Name)
	}
	// QUIC is UDP, and an ordinary proxy's CONNECT gives a byte stream: a
	// MASQUE proxy carries it (CONNECT-UDP, RFC 9298 — proxyh3.go), and a SOCKS5
	// one over UDP ASSOCIATE (socks5udp.go). Going direct instead is not an
	// option, silently or otherwise: that would reveal the very address the
	// proxy was meant to hide.
	if opts.HTTP3 && opts.Proxy != "" {
		if err := proxyCarriesH3(opts.Proxy); err != nil {
			return nil, err
		}
	}
	if err := s.setupDNS(); err != nil {
		return nil, err
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
	s.aliases = map[dialSpec]*conn{}
	// Attempts still dialing are abandoned; one that finishes anyway sees
	// the session closed and closes what it opened.
	for _, g := range s.dialing {
		g.cancel()
	}
	s.mu.Unlock()

	s.closeH3()
	s.closeMASQUE()
	s.closeH2Proxies()
	// Once with nothing to do waits out a DoH session being made right now.
	s.dns.dohOnce.Do(func() {})
	if s.dns.doh != nil {
		s.dns.doh.Close()
	}
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
	headersAt := time.Now()

	// The body limit: without it a server with an endless response eats the
	// process memory whole. One byte more is read to tell "exactly the limit"
	// from "over the limit".
	var reader io.Reader = stream
	if limit := s.opts.MaxResponseSize; limit > 0 {
		reader = io.LimitReader(stream, limit+1)
	}
	data, err := readAllSized(reader, bodySizeHint(stream.Headers, s.opts.MaxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if limit := s.opts.MaxResponseSize; limit > 0 && int64(len(data)) > limit {
		return nil, withCode(CodeTooLarge, fmt.Errorf(
			"response body is larger than the max_response_size limit of %d bytes; "+
				"read it as a stream to handle a body this large without collecting it in memory, "+
				"or raise max_response_size (0 means no limit)",
			limit))
	}
	return &Response{
		History:       stream.History,
		Preflights:    stream.Preflights,
		Status:        stream.Status,
		Headers:       stream.Headers,
		RawHeaders:    stream.RawHeaders,
		Body:          data,
		Proto:         stream.Proto,
		URL:           stream.URL,
		CookieChanges: stream.CookieChanges,
		Cache:         stream.Cache,
		Trailers:      stream.Trailers(),
		TrailersRaw:   stream.RawTrailers(),
		Interim:       stream.Interim,
		Conn:          stream.Conn,
		Timing:        bodyTiming(stream.Timing, time.Since(headersAt)),
	}, nil
}

// bodyTiming is the hop's timing with the body's read time added; a copy,
// since the hop's record is shared with the cache's copies.
func bodyTiming(t *Timing, body time.Duration) *Timing {
	if t == nil {
		return nil
	}
	out := *t
	ms := millis(body)
	out.BodyMS = &ms
	return &out
}

// bodySizeHint is the size to read a body into at first: its Content-Length
// — exact for an identity body, a floor for a compressed one — within the
// response limit and never past 8 MiB, since the header is the server's word
// and a false one must not reserve memory. 0 when there is none.
func bodySizeHint(h map[string][]string, limit int64) int64 {
	vs := h["Content-Length"]
	if len(vs) == 0 {
		return 0
	}
	n, err := strconv.ParseInt(vs[0], 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	if limit > 0 && n > limit {
		n = limit
	}
	return min(n, 8<<20)
}

// readAllSized is io.ReadAll starting from a buffer of the size expected.
// io.ReadAll starts at 512 bytes and doubles, which for a 5 KB page made
// nine allocations and copies of the body on every request.
func readAllSized(r io.Reader, hint int64) ([]byte, error) {
	if hint <= 0 {
		return io.ReadAll(r)
	}
	// One byte more: the read that finds EOF must not need a larger buffer.
	b := make([]byte, 0, hint+1)
	for {
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return b, err
		}
		if len(b) == cap(b) {
			b = append(b, 0)[:len(b)]
		}
	}
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
		return out, configErr("request has both Body and Multipart set: pass exactly one")
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
// parseURL is the one parser for every URL the client is given, and the place
// where a non-ASCII host becomes what actually goes on the wire.
//
// Go's net/url and net do no IDNA: "https://пример.рф/" parsed and dialled as
// written sends the raw Cyrillic name to the resolver and into SNI, and a
// library built for Russian sites was timing out on exactly the hosts it is
// for. Browsers send punycode — xn--e1afmkfd.xn--p1ai — and so does this,
// through the same table (x/net/idna, already used on the HTTP/3 path). The
// port and an IPv6 literal pass through untouched; a name IDNA rejects is an
// error here rather than a DNS failure three layers down.
// cookieJar is the session's jar, nil when cookies are off.
func (s *Session) cookieJar() *cookiejar.Jar { return s.jar.Load() }

func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}
	host := u.Hostname()
	// Browsers lower-case the host and drop the scheme's default port (the
	// URL standard does both), and Host, Origin and the cookie domain follow.
	if strings.EqualFold(u.Scheme, "https") && u.Port() == "443" || strings.EqualFold(u.Scheme, "http") && u.Port() == "80" {
		u.Host = strings.TrimSuffix(u.Host, ":"+u.Port())
	}
	if host == "" || strings.HasPrefix(u.Host, "[") {
		return u, nil
	}
	if isASCII(host) {
		if lower := strings.ToLower(u.Host); lower != u.Host {
			u.Host = lower
		}
		return u, nil
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return nil, fmt.Errorf("invalid host %q: %w", host, err)
	}
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(ascii, port)
	} else {
		u.Host = ascii
	}
	return u, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// request that has already finished.
// The connection is returned as well: the caller must release it through
// Session.release once the body has been read.
func (s *Session) send(r *Request, deadline time.Time) (*http.Response, context.CancelFunc, *conn, error) {
	u, err := parseURL(r.URL)
	if err != nil {
		return nil, nil, nil, err
	}
	switch u.Scheme {
	case "https", "http":
	default:
		return nil, nil, nil, fmt.Errorf(
			"only http and https are supported, got scheme %q", u.Scheme)
	}

	method := r.Method
	if method == "" {
		method = http.MethodGet
	}

	body, size, err := requestBody(r)
	if err != nil {
		return nil, nil, nil, err
	}
	// The parsed URL, not the caller's string: its host is punycode, lower
	// case and without a default port, which is what a browser puts in Host.
	// An internationalised name used to go out as raw UTF-8.
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		if c, ok := body.(io.Closer); ok {
			c.Close()
		}
		return nil, nil, nil, err
	}
	if r.TargetRaw != "" {
		rawTarget(req.URL, r.TargetRaw)
	} else {
		setTarget(req.URL, u)
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
	if !s.decompress(r) {
		req = req.WithContext(context.WithValue(req.Context(), rawBodyKey{}, true))
	}
	if d := s.expectContinue(); d > 0 {
		req = req.WithContext(context.WithValue(req.Context(), expectKey{}, d))
	}
	// A header set given whole goes as given on HTTP/2 too: Cookie crumbs as
	// they came, a joined Cookie as one field.
	if len(r.HeadersRaw) > 0 {
		req = req.WithContext(context.WithValue(req.Context(), http2.WholeCookie{}, true))
	}
	if p := r.H2Priority; p != nil {
		param := http2.PriorityParam{StreamDep: p.DependsOn, Exclusive: p.Exclusive, Weight: uint8(p.Weight - 1)}
		req = req.WithContext(http2.WithHeaderPriority(req.Context(), func(uint32) http2.PriorityParam { return param }))
	}
	if r.interim == nil {
		r.interim = &interimLog{notify: r.OnInterim}
	}
	req = req.WithContext(withInterim(req.Context(), r.interim))

	// ResponseTimeout bounds the wait for the response headers only. It is a
	// timer that cancels the request if nothing has arrived by then, and is
	// stopped the moment the headers are in; the body then reads under the
	// total limit alone. A second context would not do: for HTTP/2 the body
	// is bound to the request context, so cancelling a headers-only context
	// after the headers would kill the read that follows.
	//
	// Armed right before a transport call and disarmed right after it, so no
	// early failure leaves a timer pending, and an HTTP/3 attempt that falls
	// back to TCP arms it afresh for the second try.
	var headersLate atomic.Bool
	var headersTimer *time.Timer
	responseLimit := s.responseTimeout(r)
	// The idle limit aborts a stalled body through the same cancel, so a
	// request with only that limit needs one too.
	if (responseLimit > 0 || s.idleTimeout(r) > 0) && cancel == nil {
		var ctx context.Context
		ctx, cancel = context.WithCancel(req.Context())
		req = req.WithContext(ctx)
	}
	armHeaders := func() {
		if responseLimit <= 0 {
			return
		}
		stop := cancel
		headersTimer = time.AfterFunc(responseLimit, func() {
			headersLate.Store(true)
			stop()
		})
	}
	headersDone := func(err error) error {
		if headersTimer != nil {
			headersTimer.Stop()
			headersTimer = nil
		}
		if err != nil && headersLate.Load() {
			return withCode(CodeTimeout, fmt.Errorf(
				"no response headers within %s (response_timeout)", responseLimit))
		}
		return err
	}
	// Without an explicit size the transport would switch to chunked encoding,
	// which a browser does not use when uploading a file.
	if size >= 0 {
		req.ContentLength = size
	}
	// A streamed body may end with trailers. The map has to exist before the
	// body is written — the HTTP/2 transport decides then whether to end the
	// stream with a HEADERS frame — and is read when the body ends.
	if r.BodyStream != nil {
		if r.BodyTrailer == nil {
			r.BodyTrailer = http.Header{}
		}
		req.Trailer = r.BodyTrailer
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
	// Over cleartext there is no ALPN and no Alt-Svc to act on: h2c is not what
	// a browser does, and QUIC is TLS by definition. Rather than negotiate down
	// silently, an explicit demand for h2 or h3 is refused here — a request that
	// went out as HTTP/1.1 while the caller asked for h3 is worse than an error.
	plain := u.Scheme == "http"
	if plain {
		switch {
		case forced == ProtoH3 || s.opts.HTTP3:
			return fail(&fatalError{fmt.Errorf(
				"HTTP/3 needs TLS: %s cannot be requested for an http:// URL", ProtoH3)})
		case forced == ProtoH2:
			return fail(&fatalError{fmt.Errorf(
				"protocol=%s over http:// would be h2c, which no browser speaks; "+
					"use https:// or let it be HTTP/1.1", ProtoH2)})
		}
	}
	// An Alt-Svc upgrade is our own guess, so it is only taken when the path to
	// the target can carry QUIC: directly, or through a MASQUE proxy. Behind
	// any other proxy the advertisement is left alone — guessing wrong there
	// would cost a request to tell us what the scheme already says.
	viaAltSvc := !plain && forced == "" && !s.opts.HTTP3 && s.altSvcH3(u) &&
		masqueCarriesH3(s.proxyForHost(r, u.Scheme, u.Host)) == nil
	// An HTTPS record naming h3 sends the browser to HTTP/3 on the first
	// request, Alt-Svc or not: Chrome's DNS ALPN job, Firefox's
	// network.dns.use_https_rr_as_altsvc. Only on a direct connection — behind
	// a proxy nothing is resolved here at all.
	viaDNS := false
	if !plain && forced == "" && !s.opts.HTTP3 && !viaAltSvc && s.profile.HTTP3.Enabled() && !s.h3Broken(u) {
		if px := s.proxyForHost(r, u.Scheme, u.Host); px == "" {
			rec := s.httpsRecord(req.Context(), u, px, dnsRecordWait)
			// An ECH configuration in the record goes with it into QUIC (h3ECH).
			viaDNS = rec.ALPN("h3")
		}
	}
	// A guess races QUIC against TCP and may fall back: a streamed body read
	// by the losing attempt would be gone for the winning one.
	if r.BodyStream != nil || r.NewConnection || r.ConnectionID != 0 {
		viaAltSvc, viaDNS = false, false
	}
	tcpSpec := func() dialSpec {
		forceH1 := s.opts.ForceHTTP1
		if forced != "" {
			forceH1 = forced == ProtoHTTP1
		}
		spec := s.newDialSpec(u, s.proxyForHost(r, u.Scheme, u.Host), forceH1)
		if plain {
			spec.plain = true
		}
		return s.partition(spec, r, u)
	}
	// raced is the TCP connection a race with a guessed QUIC one left the
	// request with (race.go).
	var raced *conn
	if forced == ProtoH3 || (forced == "" && s.opts.HTTP3) || viaAltSvc || viaDNS {
		// The session option was checked when it was created; a request's demand
		// only here: before it the profile might never have been needed.
		if !s.profile.HTTP3.Enabled() {
			return fail(&fatalError{fmt.Errorf(
				"protocol=%s: profile %q has no http3 section",
				ProtoH3, s.profile.Name)})
		}
		proxy := s.proxyForHost(r, u.Scheme, u.Host)
		if proxy != "" {
			if err := proxyCarriesH3(proxy); err != nil {
				return fail(&fatalError{err})
			}
		}
		useH3 := true
		if viaAltSvc || viaDNS {
			// A guess is raced against TCP, as Chrome races it: whichever
			// connection is up first carries the request.
			var err error
			useH3, raced, err = s.raceH3(req.Context(), u, proxy, tcpSpec(), r.freshConn, viaDNS)
			if err != nil {
				return fail(&unprocessedError{err})
			}
		}
		if useH3 {
			armHeaders()
			sent := time.Now()
			resp, err := s.sendH3(req.Context(), r, u, proxy)
			err = headersDone(err)
			if err == nil {
				info := &ConnInfo{Proto: "h3", ResolvedBy: s.resolvedBy(u.Host, proxy),
					PeerSettings: takePeerSettings(resp.Header)}
				if proxy != "" {
					info.Proxy = redactProxy(proxy)
				}
				r.hop.set(info, time.Since(sent))
				// sendH3 opened its own copy of the body; this one would stay
				// open (and a file locked on Windows) until collected. A
				// streamed body is the same reader, still being sent.
				if closer, ok := body.(io.Closer); ok && r.BodyStream == nil {
					closer.Close()
				}
				// HTTP/3 keeps its own connection inside the transport, nothing to release.
				return fromStdResponse(resp), cancel, nil, nil
			}
			if !viaAltSvc && !viaDNS {
				return fail(err)
			}
			// The upgrade was our guess from the site's advertisement — fall back to
			// TCP and stop trying for a while, as a browser does.
			s.markAltSvcBroken(u)
		}
	}

	c, reused, err := raced, false, error(nil)
	switch {
	case c != nil:
	case r.ConnectionID != 0:
		c, reused, err = s.pinnedConn(r.ConnectionID, tcpSpec(), u.Hostname())
		if err != nil {
			return fail(&fatalError{err})
		}
	default:
		c, reused, err = s.conn(req.Context(), u, tcpSpec(), r.freshConn || r.NewConnection)
	}
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
	if c.h2 == nil && strings.ContainsRune(r.TargetRaw, ' ') {
		s.release(c)
		return fail(&fatalError{configErr("target_raw %q has a space, which splits an HTTP/1.1 request line "+
			"(the server negotiated http/1.1)", r.TargetRaw)})
	}
	// The headers are built after the connection is chosen: HTTP/1.1 order and
	// case depend on what the server negotiated, not on an option.
	s.applyHeaders(req, r, u, c.proto == "http/1.1")
	s.noteMode(r)

	armHeaders()
	sent := time.Now()
	resp, err := c.roundTrip(req.Context(), req)
	err = headersDone(err)
	if err == nil {
		r.hop.set(c.describe(reused), time.Since(sent))
	}
	if err != nil {
		// The connection is no longer usable. For HTTP/2 close it gently: a hard
		// close would cut the streams of neighbouring requests.
		s.release(c)
		// HTTP/1.1 is dead after any failure. An HTTP/2 connection is retired
		// only when it failed as a whole: a cancelled request, a
		// response_timeout or one stream's reset leave it serving the rest,
		// as in a browser — every such error used to cost a new handshake.
		if c.h2 == nil || !c.usable() || connectionDropped(err) || h2Unprocessed(err) {
			s.evict(c, c.h2 == nil)
		}
		// A kept-alive connection can die under a request: the server closed it
		// as the request went out, or a middlebox dropped it while it idled. No
		// response header arrived, so the request goes once more on a new
		// connection — whatever the method, as Chromium does
		// (HttpNetworkTransaction::ShouldResendRequest: the connection was
		// reused and no headers were received). A new connection that fails is
		// not resent: that is a real failure, and retries= decides about it.
		if reused && r.BodyStream == nil && r.ConnectionID == 0 &&
			(connectionDropped(err) || (c.h2 != nil && h2Unprocessed(err))) &&
			req.Context().Err() == nil && (deadline.IsZero() || time.Now().Before(deadline)) {
			if closer, ok := body.(io.Closer); ok {
				closer.Close()
			}
			if cancel != nil {
				cancel()
			}
			again := *r
			again.freshConn = true
			return s.send(&again, deadline)
		}
		err = fmt.Errorf("request failed: %w", inPhase(PhaseResponse, err))
		if c.h2 != nil && h2Unprocessed(err) {
			return fail(&unprocessedError{err})
		}
		return fail(err)
	}

	if s.useCookies(r) && s.includesCredentials(r, u) {
		s.storeCookies(r, u, s.acceptCookies(resp.Cookies()))
	}
	return resp, cancel, c, nil
}

func (s *Session) dial(ctx context.Context, u *url.URL, ds dialSpec) (*conn, error) {
	return s.dialWith(ctx, u, ds, nil)
}

// dialWith is dial with a question put to a burst's spare: asked once the
// server has chosen HTTP/2 and before the preface, a true answer closes the
// connection there — the way Chrome closes the spares of a race it lost.
func (s *Session) dialWith(ctx context.Context, u *url.URL, ds dialSpec, spare func() bool) (*conn, error) {
	// The connect limit covers both TCP and the TLS handshake: for the caller
	// this is one phase, "no connection yet", and splitting it serves nobody.
	dialCtx, done := s.connectContext(ctx)
	defer done()

	// Real ECH where the origin publishes a configuration and the browser
	// would use it (dns.go): asked before the TCP connection, as Chrome asks
	// for the record beside the address and reads it at the TLS handshake.
	ech := s.echConfig(dialCtx, u, ds)
	var raw net.Conn
	var uconn *utls.UConn
	var connectTook, tlsTook time.Duration
	// The address lookup inside the dial, timed by net's own hooks (with a
	// proxy, the lookup of the proxy's name).
	var dnsMu sync.Mutex
	var dnsAt time.Time
	var dnsTook time.Duration
	traced := httptrace.WithClientTrace(dialCtx, &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsMu.Lock(); dnsAt = time.Now(); dnsMu.Unlock() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			dnsMu.Lock()
			dnsTook += time.Since(dnsAt)
			dnsMu.Unlock()
		},
	})
	for attempt := 0; ; attempt++ {
		var err error
		dialed := time.Now()
		raw, err = s.dialRaw(traced, ds.addr, ds.proxy, ds.local)
		if err != nil {
			return nil, inPhase(PhaseConnect, err)
		}
		connectTook = time.Since(dialed)

		// Cleartext: no ClientHello, so no TLS fingerprint — but the HTTP/1.1 half
		// of the profile still applies, and that is the half a plain-HTTP server
		// can see. The header order and case come from the profile exactly as they
		// do over TLS, because the connection is an ordinary h1 connection from
		// here on.
		if ds.plain {
			c := newH1Conn(raw, ds)
			c.noteDial(raw, nil, false, connectTook, 0, nil)
			c.info.DNSMS = millis(dnsTook)
			c.info.ResolvedBy = s.resolvedBy(ds.addr, ds.proxy)
			return c, nil
		}
		hsCtx, hsDone := dialCtx, context.CancelFunc(func() {})
		if ech != nil {
			hsCtx, hsDone = context.WithTimeout(dialCtx, echHandshakeWait)
		}
		shaking := time.Now()
		notePhase(dialCtx, PhaseTLS)
		uconn, err = s.handshakeTLS(hsCtx, raw, u, ds, ech)
		tlsTook = time.Since(shaking)
		hsDone()
		if err == nil {
			break
		}
		raw.Close()
		// The server could not decrypt the hello and answered as its public
		// name with retry configurations: Chrome connects once more with them,
		// or with ECH off when there are none (tls_stream_attempt.cc).
		var rej *utls.ECHRejectionError
		if ech != nil && attempt == 0 && errors.As(err, &rej) {
			ech = nil
			if len(rej.RetryConfigList) > 0 {
				ech = rej.RetryConfigList
			}
			continue
		}
		// The network dropped the hello with ECH — as Russia's does to every
		// Cloudflare site — and Chrome would fail here. The connection is made
		// once more without ECH, as 0.17 made it, and the public name is
		// marked so the process's next connections do not try again (dns.go).
		if ech != nil && attempt == 0 && echDropped(err, dialCtx) {
			markECHBroken(ech)
			ech = nil
			continue
		}
		return nil, inPhase(PhaseTLS, err)
	}

	// The protocol was chosen by the server. An empty ALPN means HTTP/1.1 — that
	// is how browser profiles that do not offer h2 behave.
	state := uconn.ConnectionState()
	verified := !s.opts.InsecureSkipVerify
	switch proto := state.NegotiatedProtocol; proto {
	case "h2":
		if spare != nil && spare() {
			uconn.Close()
			return nil, errSpare
		}
		cc, err := s.transport().NewClientConn(uconn)
		if err != nil {
			uconn.Close()
			return nil, inPhase(PhaseConnect, fmt.Errorf("h2: %w", err))
		}
		c := newH2Conn(cc, ds)
		c.notePeer(raw, state, ds.proxy == "" && !s.opts.InsecureSkipVerify)
		c.noteDial(raw, &state, verified, connectTook, tlsTook, sentHello(uconn))
		c.info.DNSMS = millis(dnsTook)
		c.info.ResolvedBy = s.resolvedBy(ds.addr, ds.proxy)
		return c, nil
	case "http/1.1", "":
		c := newH1Conn(uconn, ds)
		c.noteDial(raw, &state, verified, connectTook, tlsTook, sentHello(uconn))
		c.info.DNSMS = millis(dnsTook)
		c.info.ResolvedBy = s.resolvedBy(ds.addr, ds.proxy)
		return c, nil
	default:
		uconn.Close()
		return nil, fmt.Errorf("server negotiated %q, which is not supported", proto)
	}
}

// handshakeTLS runs the profile's TLS handshake on a fresh connection, with
// real ECH when ech holds a configuration list.
func (s *Session) handshakeTLS(dialCtx context.Context, raw net.Conn, u *url.URL, ds dialSpec, ech []byte) (*utls.UConn, error) {
	// The spec is built per connection: ShuffleChromeTLSExtensions mutates the
	// slice in place, so reusing it would freeze the order.
	spec, err := profile.BuildSpec(s.profile)
	if err != nil {
		return nil, err
	}
	// The resuming ClientHello is a different message from the first one, and
	// no profile describes it: a browser's very first hello has nothing to
	// resume with, so a capture never contains pre_shared_key. The extension is
	// appended here, last, exactly where a browser puts it. With OmitEmptyPsk
	// it stays off the wire until a ticket exists, so the first handshake is
	// byte-for-byte what it was.
	// With ECH Chrome carries the PSK inside the inner hello alone, its binder
	// over the inner hello; the patched uTLS does the same for the BoringSSL
	// style (u_ech_curlpro.go). NSS puts a stand-in PSK in the outer hello,
	// which is not reproduced, so a Firefox connection with ECH does not resume.
	resume := s.opts.Resume && (ech == nil || s.echInner == utls.ECHInnerBoringSSL)
	if resume {
		spec.Extensions = append(spec.Extensions, &utls.UtlsPreSharedKeyExtension{})
		// Firefox's resuming hello has no session_ticket extension: NSS offers
		// the TLS 1.2 ticket slot only when it holds no TLS 1.3 ticket. Chrome
		// keeps it. The profile says which, and the cache says whether this
		// connection will resume at all — the first hello must stay as captured.
		if s.profile.TLS.ResumeOmitsSessionTicket != nil && *s.profile.TLS.ResumeOmitsSessionTicket && s.hasTicket(u.Hostname()) {
			dropSessionTicket(spec)
		}
	}

	// ALPN lives inside the spec, and ApplyPreset overrides Config.NextProtos.
	// So restricting the protocol means editing the extension, not the config.
	// The fingerprint changes legitimately: a browser without h2 looks like this.
	//
	// The flag comes from dialSpec rather than from the session options: it is
	// part of the pool key, so a WebSocket h1 connection cannot replace the h2 one.
	if ds.forceHTTP1 {
		if !setALPN(spec, []string{"http/1.1"}) {
			return nil, capabilityErr("force_http1: profile %q has no ALPN extension to restrict", s.profile.Name)
		}
	}
	switch ds.alpn {
	case "":
	case "-":
		dropALPN(spec)
	default:
		if !setALPN(spec, strings.Split(ds.alpn, ",")) {
			return nil, capabilityErr("alpn: profile %q has no ALPN extension to set", s.profile.Name)
		}
	}
	if s.opts.DisablePostQuantum {
		dropPostQuantum(spec)
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
	if resume {
		// One cache per session: tickets belong to the identity, and sharing
		// them between sessions would let two identities be linked by the very
		// mechanism meant to make each look like a returning browser — unless
		// the caller names one identity's group (Options.TicketCache).
		cfg.ClientSessionCache = s.tlsSessions
	} else {
		cfg.SessionTicketsDisabled = true
	}
	if len(s.alpn) > 0 {
		cfg.NextProtos = s.alpn
	}
	if ech != nil {
		// uTLS refuses a configuration list on a client that would accept
		// TLS 1.2; the outer hello still offers 1.2, as the spec says.
		cfg.EncryptedClientHelloConfigList = ech
		cfg.MinVersion = utls.VersionTLS13
		// Once ECH is accepted uTLS checks the server's answer against its own
		// record of the inner hello, which takes ALPN from the config: the
		// spec's list goes there, or a negotiated h2 reads as unrequested.
		for _, e := range spec.Extensions {
			if a, ok := e.(*utls.ALPNExtension); ok {
				cfg.NextProtos = append([]string(nil), a.AlpnProtocols...)
			}
		}
	}

	uconn := utls.UClient(raw, cfg, utls.HelloCustom)
	if ech != nil {
		uconn.ECHInner = s.echInner // the inner hello the browser builds (scripts/patch-utls.py)
	}
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("ApplyPreset: %w", err)
	}
	// The handshake runs under the same limit as TCP: a host that accepted the
	// connection and went silent would otherwise eat the whole request budget.
	if err := uconn.HandshakeContext(dialCtx); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	return uconn, nil
}

// hpackMode is one entry of the profile's HPACK policy: a mode, or never
// indexed below a value length (below > 0) and the default above it.
type hpackMode struct {
	mode  hpack.IndexMode
	below int
}

// hpackPolicy is the profile's HPACK representation by field name and
// value, nil when it names none (the encoder indexes whatever fits).
func hpackPolicy(h2 profile.HTTP2Spec) func(name, value string) hpack.IndexMode {
	pol := h2.HPACKIndexingPolicy
	if len(pol) == 0 {
		return nil
	}
	modes := make(map[string]hpackMode, len(pol))
	def := hpack.IndexDefault
	for name, m := range pol {
		var hm hpackMode
		if n, ok := profile.HPACKNeverBelow(m); ok {
			hm.below = n
		} else {
			hm.mode = map[string]hpack.IndexMode{"incremental": hpack.IndexIncremental,
				"without": hpack.IndexWithout, "literal": hpack.IndexLiteral, "never": hpack.IndexNever}[m]
		}
		if name == "default" {
			def = hm.mode
		} else {
			modes[name] = hm
		}
	}
	return func(name, value string) hpack.IndexMode {
		m, ok := modes[name]
		switch {
		case !ok:
			return def
		case m.below > 0 && len(value) < m.below:
			return hpack.IndexNever
		case m.below > 0:
			return def
		}
		return m.mode
	}
}

// hpackNameRef is the profile's choice of a literal's name entry.
func hpackNameRef(h2 profile.HTTP2Spec) hpack.NameRef {
	switch h2.HPACKNameIndex {
	case "first":
		return hpack.NameFirstStatic
	case "scan":
		return hpack.NameScan
	}
	return hpack.NameGo
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
		// The body is decoded by conn.roundTrip, as on HTTP/1.1: fhttp's own
		// decoder took zstd with a 512 MB window allocated up front, and knew
		// no stacked encodings.
		DisableCompression: true,
		// Expect: 100-continue holds the body (patch edit l).
		ExpectContinueTimeout: s.expectContinue(),
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
	// The header block field by field as the profile's browser writes it, and
	// its bodies' frames no larger than the browser's (patch edits m, n, o).
	tr.HPACKIndexPolicy = hpackPolicy(h2)
	tr.HPACKNameRef = hpackNameRef(h2)
	tr.HPACKHuffmanAlways = h2.HPACKHuffman == "always"
	tr.DisableCookieSplit = h2.DisableCookieSplit != nil && *h2.DisableCookieSplit
	tr.DataFrameMaxSize = h2.DataFrameMaxSize
	// fhttp writes them after the WINDOW_UPDATE and moves the first request's
	// stream past the last of them.
	for _, f := range h2.PriorityFrames {
		tr.Priorities = append(tr.Priorities, http2.Priority{
			StreamID: f.StreamID,
			PriorityParam: http2.PriorityParam{
				StreamDep: f.DependsOn,
				Exclusive: f.Exclusive,
				Weight:    uint8(f.Weight - 1),
			},
		})
	}
	return tr
}
