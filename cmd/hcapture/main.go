// Command hcapture is the stand that records the header order of a live
// browser over HTTP/2 and HTTP/3.
//
// Why a server of our own. Public oracles normalise the names, and not one of
// them shows the HTTP/3 order: before this stand the header order in HTTP/3 was
// observable by nothing, and the profile was taken on trust. Here the HEADERS
// frame is parsed as it arrived: HPACK for HTTP/2, our own QPACK decoder for HTTP/3.
//
// Running it (the browser starts itself, headless):
//
//	go run ./cmd/hcapture -auto               # HTTP/2
//	go run ./cmd/hcapture -auto -h3           # HTTP/3, Chrome is forced onto QUIC
//	go run ./cmd/hcapture -h3                 # no browser: open the address yourself
//
// The page itself performs a fetch, an XHR and a link navigation, so one run
// captures both header sets — the navigational one and the fetch one.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/qpack"
	quic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/quicvarint"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	cqpack "github.com/curlpro/curlpro/internal/qpack"
)

func main() {
	listen := flag.String("listen", "localhost:8443", "stand address")
	h3 := flag.Bool("h3", false, "bring up QUIC and move the browser onto HTTP/3")
	browser := flag.String("browser", "", "path to Chrome; empty means do not launch, wait instead")
	auto := flag.Bool("auto", false, "launch the browser found in the usual places")
	timeout := flag.Duration("timeout", 25*time.Second, "how long to wait for requests")
	out := flag.String("json", "", "file to write the capture to")
	certs := flag.String("certs", "capture/certs", "directory holding tls.crt and tls.key")
	flag.BoolVar(&origins, "origins", false, "serve the three-origin page: what a page sends to its own origin, its site and another site")
	flag.BoolVar(&closeAfter, "close", false, "close every connection after its first response, so later requests resume TLS on new ones")
	flag.Parse()

	certFile = *certs + "/tls.crt"
	keyFile = *certs + "/tls.key"
	if _, port, err := net.SplitHostPort(*listen); err == nil {
		listenPort = port
	}
	// Alt-Svc is the only way to move a browser onto QUIC when
	// --origin-to-force-quic-on cannot be passed: on Android there are no launch
	// flags. The browser switches to HTTP/3 from the request after this header.
	if *h3 {
		if _, port, err := net.SplitHostPort(*listen); err == nil {
			altSvc = `h3=":` + port + `"; ma=86400`
		}
	}

	s := &srv{}
	var wg sync.WaitGroup

	if *h3 {
		if err := s.listenQUIC(*listen, &wg); err != nil {
			fmt.Fprintln(os.Stderr, "QUIC:", err)
			os.Exit(1)
		}
	}
	// TCP is always listened on: the browser goes over TCP first and only moves
	// to QUIC on Alt-Svc or a forcing flag.
	if err := s.listenTCP(*listen, &wg); err != nil {
		fmt.Fprintln(os.Stderr, "TCP:", err)
		os.Exit(1)
	}

	path := *browser
	if path == "" && *auto {
		path = defaultBrowser()
	}
	var stop func()
	if path != "" {
		stop = launch(path, *listen, *h3)
	} else {
		fmt.Fprintf(os.Stderr, "open https://%s/ in a browser\n", *listen)
		stop = func() {}
	}

	// The stand lives until the timeout: the page manages all its requests, and
	// the final link navigation arrives towards the end.
	time.Sleep(*timeout)
	stop()
	s.closeAll()
	wg.Wait()

	s.report(*out)
}

// record is one request in wire order.
type record struct {
	Proto   string   `json:"proto"`
	Method  string   `json:"method"`
	Host    string   `json:"host,omitempty"`
	Path    string   `json:"path"`
	Headers []string `json:"headers"`
	// Resumed says the TLS session was resumed with a ticket; ClientHello is
	// the first record of the connection, base64, on the connection's first
	// request only.
	Resumed     bool   `json:"resumed,omitempty"`
	ClientHello string `json:"client_hello,omitempty"`
}

type srv struct {
	mu      sync.Mutex
	records []record
	notes   []string
	closers []io.Closer
}

// note records an observation not tied to a particular request.
func (s *srv) note(text string) {
	s.mu.Lock()
	for _, n := range s.notes {
		if n == text {
			s.mu.Unlock()
			return // the same thing repeats on every connection
		}
	}
	s.notes = append(s.notes, text)
	s.mu.Unlock()
	fmt.Fprintln(os.Stderr, text)
}

func (s *srv) add(r record) {
	s.mu.Lock()
	s.records = append(s.records, r)
	s.mu.Unlock()
	fmt.Fprintf(os.Stderr, "%s %s %s%s (%d headers)\n", r.Proto, r.Method, r.Host, r.Path, len(r.Headers))
}

func (s *srv) track(c io.Closer) {
	s.mu.Lock()
	s.closers = append(s.closers, c)
	s.mu.Unlock()
}

func (s *srv) closeAll() {
	s.mu.Lock()
	for _, c := range s.closers {
		_ = c.Close()
	}
	s.closers = nil
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// The content: the page itself calls fetch, XHR and follows a link.
// ---------------------------------------------------------------------------

const page = `<!doctype html><meta charset=utf-8><title>hcapture</title>
<body><h1>hcapture</h1><pre id=out></pre>
<script>
const log = m => { document.getElementById('out').textContent += m + "\n"; };
(async () => {
  try {
    await fetch('/fetch-get', {headers: {'X-Api-Key': 'v1'}});
    log('fetch-get');
    await fetch('/fetch-post', {method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Api-Key': 'v1'},
      body: JSON.stringify({a: 1})});
    log('fetch-post');
    await new Promise(r => {
      const x = new XMLHttpRequest();
      x.open('POST', '/xhr-post');
      x.setRequestHeader('X-Api-Key', 'v1');
      x.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      x.onloadend = r;
      x.send('a=1&b=2');
    });
    log('xhr-post');
    setTimeout(() => { location.href = '/second'; }, 300);
		} catch (e) { log('error ' + e); }
})();
</script>`

const second = `<!doctype html><meta charset=utf-8><title>second</title><body>ok`

// The origins run: what a browser sends when a page on one origin talks to
// its own origin, to a sibling of the same site and to another site — and
// what a navigation and a form post from a page carry. Three names on the
// same stand: the page lives on www.a.localhost, api.a.localhost is the same
// site, b.localhost is another site (the public suffix list has no entry for
// localhost, so a.localhost and b.localhost are two registrable domains, in
// Chromium and in our own siteRelation alike).
//
// Every fetch is wrapped: a CORS failure must not stop the chain, and the
// request has reached the stand by then anyway.
const (
	originsPage   = "www.a.localhost"
	originsSite   = "api.a.localhost"
	originsOther  = "b.localhost"
	originsScript = `<!doctype html><meta charset=utf-8><title>origins</title>
<body><h1>origins</h1><pre id=out></pre>
<script>
const log = m => { document.getElementById('out').textContent += m + "\n"; };
const port = location.port;
const targets = {so: location.origin, ss: 'https://api.a.localhost:' + port, cs: 'https://b.localhost:' + port};
const quiet = async f => { try { await f(); } catch (e) { log('x ' + e); } };
const xhr = (url, cred) => new Promise(r => { const x = new XMLHttpRequest();
  x.open('GET', url); x.withCredentials = cred; x.onloadend = r; x.onerror = r; x.send(); });
(async () => {
  // Cookies first: every name gets its five cookies in a first-party context,
  // by top-level navigations, before the page starts asking. sessionStorage
  // survives the round trip and stops it from repeating.
  if (!sessionStorage.primed) {
    sessionStorage.primed = '1';
    location.href = targets.cs + '/prime';
    return;
  }
  for (const [k, o] of Object.entries(targets)) {
    await quiet(() => fetch(o + '/' + k + '-get'));
    await quiet(() => fetch(o + '/' + k + '-post', {method: 'POST', body: 'a=1'}));
    await quiet(() => fetch(o + '/' + k + '-json', {method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Api-Key': 'v1'}, body: '{"a":1}'}));
    await quiet(() => xhr(o + '/' + k + '-xhr', false));
    // The credentials modes: fetch's default (same-origin), include, omit,
    // XHR withCredentials; a preflight without headers (DELETE) and a
    // preflight followed by a credentialed request.
    await quiet(() => fetch(o + '/' + k + '-cred', {credentials: 'include'}));
    await quiet(() => fetch(o + '/' + k + '-omit', {credentials: 'omit'}));
    await quiet(() => xhr(o + '/' + k + '-xhrcred', true));
    await quiet(() => fetch(o + '/' + k + '-del', {method: 'DELETE'}));
    await quiet(() => fetch(o + '/' + k + '-jsoncred', {method: 'POST', credentials: 'include',
      headers: {'Content-Type': 'application/json', 'X-Api-Key': 'v1'}, body: '{"a":1}'}));
    log(k);
  }
  // Redirects: where the Origin header goes when a hop changes the origin.
  await quiet(() => fetch(targets.ss + '/r1'));           // cross-origin first hop, then another site
  await quiet(() => fetch('/r2'));                         // same-origin first hop, then another site
  await quiet(() => fetch('/r2b'));                        // same-origin, then two cross-origin hops
  await quiet(() => fetch('/r4', {method: 'POST', body: 'a=1'}));  // same-origin POST, 307 to another site
  await new Promise(r => { const i = new Image(); i.onload = i.onerror = r;
    i.src = 'https://b.localhost:' + port + '/cs-img'; });
  await new Promise(r => { const s = document.createElement('script'); s.onload = s.onerror = r;
    s.src = 'https://b.localhost:' + port + '/cs-script'; document.head.appendChild(s); });
  setTimeout(() => { location.href = 'https://b.localhost:' + port + '/cs-nav'; }, 300);
})();
</script>`
	// The priming page: its response set the cookies; it moves on to the next name.
	originsPrime = `<!doctype html><meta charset=utf-8><title>prime</title><body>prime
<script>setTimeout(() => { location.href = 'NEXT'; }, 200);</script>`
	// The cross-site page: a form post back to the first origin, script-submitted.
	originsNav = `<!doctype html><meta charset=utf-8><title>nav</title><body>nav
<form id=f method=post action="https://www.a.localhost:PORT/form-post"><input name=a value=1></form>
<script>setTimeout(() => document.getElementById('f').submit(), 300);</script>`
	// The form target: a same-origin form post that is redirected with 307 to
	// another site — a navigation POST whose origin changes on the way.
	originsForm = `<!doctype html><meta charset=utf-8><title>form</title><body>form
<form id=f method=post action="/r3"><input name=a value=1></form>
<script>setTimeout(() => document.getElementById('f').submit(), 300);</script>`
	// Where the 307 lands, on the other site: it waits out the two-minute
	// window of Chromium's Lax+POST exception, then posts back to the first
	// origin once more, so the same cross-site POST is seen with young cookies
	// (the first form post) and with old ones (this one).
	originsLate = `<!doctype html><meta charset=utf-8><title>late</title><body>late
<form id=f method=post action="https://www.a.localhost:PORT/form-post-late"><input name=a value=1></form>
<script>setTimeout(() => document.getElementById('f').submit(), 125000);</script>`
	// The late form target: a same-origin script navigation to finish.
	originsDone = `<!doctype html><meta charset=utf-8><title>done</title><body>done
<script>setTimeout(() => { location.href = '/so-nav'; }, 300);</script>`
)

// primeCookies are set on every name by its priming page (and on the page's
// own origin by the start page): one of each SameSite kind, one None without
// Secure — which Chromium refuses at set time — and one with no attribute.
var primeCookies = []string{
	"strict=1; Path=/; SameSite=Strict",
	"lax=1; Path=/; SameSite=Lax",
	"none=1; Path=/; SameSite=None; Secure",
	"nonens=1; Path=/; SameSite=None",
	"plain=1; Path=/",
}

// origins is set by -origins: the stand serves the three-name page instead.
var origins bool

// originsStart is the page's path (query included), as the browser opens it.
const originsStart = "/app/index.html?tab=1"

// reply is what the stand answers with.
type reply struct {
	status   int
	body     string
	ctype    string
	location string
	cookies  []string
}

// route returns the response for a path; host tells the priming pages apart,
// which are the same path on every name.
func route(path, host string) reply {
	const html = "text/html; charset=utf-8"
	if origins {
		other := "https://" + originsOther + ":" + listenPort
		site := "https://" + originsSite + ":" + listenPort
		start := "https://" + originsPage + ":" + listenPort + originsStart
		switch path {
		case originsStart:
			// A page at a deep path with a query: it separates a full-URL
			// Referer from an origin-only one, which the root page could not.
			// The cookies are set on the first page so that later requests
			// show their position: in the profile cookie is a slot placed on a guess.
			return reply{200, originsScript, html, "", append([]string{"hc=1; path=/"}, primeCookies...)}
		case "/prime":
			// b.localhost first, then api.a.localhost, then back to the page.
			next := site + "/prime"
			if strings.HasPrefix(host, originsSite) {
				next = start
			}
			return reply{200, strings.ReplaceAll(originsPrime, "NEXT", next), html, "", primeCookies}
		case "/r1", "/r2":
			return reply{302, "", "", other + path + "-landed", nil}
		case "/r2b":
			return reply{302, "", "", site + "/r2b-mid", nil}
		case "/r2b-mid":
			return reply{302, "", "", other + "/r2b-landed", nil}
		case "/r3", "/r4":
			return reply{307, "", "", other + path + "-landed", nil}
		case "/r3-landed":
			return reply{200, strings.ReplaceAll(originsLate, "PORT", listenPort), html, "", nil}
		case "/cs-nav":
			return reply{200, strings.ReplaceAll(originsNav, "PORT", listenPort), html, "", nil}
		case "/form-post":
			return reply{200, originsForm, html, "", nil}
		case "/form-post-late":
			return reply{200, originsDone, html, "", nil}
		case "/so-nav":
			return reply{200, second, html, "", nil}
		case "/cs-script":
			return reply{200, "void 0;", "text/javascript", "", nil}
		}
	}
	switch path {
	case "/":
		return reply{200, page, html, "", []string{"hc=1; path=/"}}
	case "/second":
		return reply{200, second, html, "", nil}
	default:
		return reply{200, `{"ok":true}`, "application/json", "", nil}
	}
}

// header returns a request header's value, or "".
func (r record) header(name string) string {
	for _, h := range r.Headers {
		if n, v, ok := strings.Cut(h, ": "); ok && strings.EqualFold(n, name) {
			return v
		}
	}
	return ""
}

// listenPort is the stand's port, for the pages that name another host.
var listenPort = "8443"

// ---------------------------------------------------------------------------
// HTTP/2
// ---------------------------------------------------------------------------

// acceptCH are the high-entropy hints the stand asks for.
// Critical-CH makes the browser repeat the request at once instead of the next one.
const acceptCH = "sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-full-version-list, sec-ch-ua-model, sec-ch-ua-platform-version, sec-ch-ua-wow64, sec-ch-ua-form-factors, sec-ch-ua-full-version"

var (
	certFile = "capture/certs/tls.crt"
	keyFile  = "capture/certs/tls.key"
	// altSvc is non-empty when QUIC is up: it advertises HTTP/3 support.
	altSvc string
)

func serverTLSConfig(next []string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: next}, nil
}

func (s *srv) listenTCP(addr string, wg *sync.WaitGroup) error {
	cfg, err := serverTLSConfig([]string{"h2", "http/1.1"})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.track(ln)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			rc := &recordingConn{Conn: c}
			go s.serveConn(tls.Server(rc, cfg), rc)
		}
	}()
	return nil
}

func (s *srv) serveConn(c *tls.Conn, rc *recordingConn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	if err := c.Handshake(); err != nil {
		return
	}
	if c.ConnectionState().NegotiatedProtocol == "h2" {
		s.serveH2(c, c.ConnectionState().DidResume, rc.clientHello())
	}
}

// recordingConn keeps the first TLS record a client sends — its ClientHello —
// so that a resumed hello can be compared with a first one byte for byte.
// Recording stops once the record is complete; the rest is passed through.
type recordingConn struct {
	net.Conn
	mu    sync.Mutex
	hello []byte
	done  bool
}

func (r *recordingConn) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	r.mu.Lock()
	if !r.done && n > 0 {
		r.hello = append(r.hello, b[:n]...)
		if len(r.hello) >= 5 {
			want := 5 + int(binary.BigEndian.Uint16(r.hello[3:5]))
			if len(r.hello) >= want {
				r.hello = r.hello[:want]
				r.done = true
			}
		}
	}
	r.mu.Unlock()
	return n, err
}

func (r *recordingConn) clientHello() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.hello...)
}

// closeAfter is set by -close: every connection is closed after its first
// response, so the page's next request has to open a new one — and a client
// holding a session ticket resumes on it. That is how the resumed ClientHello
// of a browser is captured: on a kept-alive connection there is no second
// handshake to see.
var closeAfter bool

// serveH2 parses the frames by hand: net/http loses the header order, and that
// is exactly what is being captured here.
func (s *srv) serveH2(c net.Conn, resumed bool, hello []byte) {
	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	answered := 0
	// finish is what -close does after a response: a GOAWAY, then the socket.
	finish := func(fr *http2.Framer) bool {
		answered++
		if !closeAfter {
			return false
		}
		_ = fr.WriteGoAway(0, http2.ErrCodeNo, nil)
		return true
	}
	buf := make([]byte, len(preface))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != preface {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	// One encoder for the connection: HPACK's dynamic table is shared
	// state with the browser's decoder, and an encoder created per
	// response numbered its entries from an empty table while the browser
	// counted from everything it had already seen. With one set-cookie a
	// response it went unnoticed; with five, the names came out scrambled.
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	if err := fr.WriteSettings(
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20},
	); err != nil {
		return
	}

	pending := map[uint32]record{}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			_ = fr.WritePing(true, f.Data)
		case *http2.MetaHeadersFrame:
			r := record{Proto: "h2", Resumed: resumed}
			if answered == 0 && len(hello) > 0 {
				r.ClientHello = base64.StdEncoding.EncodeToString(hello)
			}
			for _, hf := range f.Fields {
				switch hf.Name {
				case ":method":
					r.Method = hf.Value
				case ":path":
					r.Path = hf.Value
				case ":authority":
					r.Host = hf.Value
				}
				r.Headers = append(r.Headers, hf.Name+": "+hf.Value)
			}
			if f.StreamEnded() {
				s.add(r)
				s.respondH2(fr, enc, &hbuf, f.StreamID, r)
				if finish(fr) {
					return
				}
			} else {
				pending[f.StreamID] = r
			}
		case *http2.DataFrame:
			if len(f.Data()) > 0 {
				_ = fr.WriteWindowUpdate(0, uint32(len(f.Data())))
				_ = fr.WriteWindowUpdate(f.StreamID, uint32(len(f.Data())))
			}
			if f.StreamEnded() {
				if r, ok := pending[f.StreamID]; ok {
					delete(pending, f.StreamID)
					s.add(r)
					s.respondH2(fr, enc, &hbuf, f.StreamID, r)
					if finish(fr) {
						return
					}
				}
			}
		case *http2.GoAwayFrame:
			return
		}
	}
}

func (s *srv) respondH2(fr *http2.Framer, enc *hpack.Encoder, buf *bytes.Buffer, id uint32, r record) {
	rep := route(r.Path, r.Host)
	buf.Reset()
	_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: fmt.Sprint(rep.status)})
	if rep.location != "" {
		_ = enc.WriteField(hpack.HeaderField{Name: "location", Value: rep.location})
	}
	if rep.ctype != "" {
		_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: rep.ctype})
	}
	_ = enc.WriteField(hpack.HeaderField{Name: "content-length", Value: fmt.Sprint(len(rep.body))})
	_ = enc.WriteField(hpack.HeaderField{Name: "cache-control", Value: "no-store"})
	_ = enc.WriteField(hpack.HeaderField{Name: "accept-ch", Value: acceptCH})
	_ = enc.WriteField(hpack.HeaderField{Name: "critical-ch", Value: acceptCH})
	if altSvc != "" {
		_ = enc.WriteField(hpack.HeaderField{Name: "alt-svc", Value: altSvc})
	}
	if origins {
		// CORS answers, so the cross-origin fetches on the page complete and the
		// chain moves on; the preflight itself is recorded like any request.
		// The origin is echoed and credentials allowed: a credentialed request
		// refuses a wildcard, and its preflight would stop the chain.
		acao := "*"
		if o := r.header("origin"); o != "" {
			acao = o
		}
		_ = enc.WriteField(hpack.HeaderField{Name: "access-control-allow-origin", Value: acao})
		_ = enc.WriteField(hpack.HeaderField{Name: "access-control-allow-credentials", Value: "true"})
		_ = enc.WriteField(hpack.HeaderField{Name: "access-control-allow-headers", Value: "content-type, x-api-key"})
		_ = enc.WriteField(hpack.HeaderField{Name: "access-control-allow-methods", Value: "GET, POST, DELETE, OPTIONS"})
	}
	for _, c := range rep.cookies {
		_ = enc.WriteField(hpack.HeaderField{Name: "set-cookie", Value: c})
	}
	_ = fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: buf.Bytes(), EndHeaders: true,
	})
	_ = fr.WriteData(id, true, []byte(rep.body))
}

// ---------------------------------------------------------------------------
// HTTP/3
// ---------------------------------------------------------------------------

const (
	h3FrameData     = 0x00
	h3FrameHeaders  = 0x01
	h3FrameSettings = 0x04

	h3StreamControl = 0x00
	h3StreamEncoder = 0x02
	h3StreamDecoder = 0x03

	qpackMaxTableCapacity = 4096
	qpackBlockedStreams   = 16
)

// listenQUIC brings up a listener on every address the host resolves to.
//
// One address is not enough: Chrome reaches localhost over ::1, and a listener
// bound only to 127.0.0.1 receives no datagram at all — one run was already
// lost that way while capturing the QUIC ClientHello.
func (s *srv) listenQUIC(addr string, wg *sync.WaitGroup) error {
	cert, err := utls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	cfg := &utls.Config{
		Certificates: []utls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
	var started int
	for _, a := range resolveAll(host, port) {
		udp, err := net.ListenUDP("udp", a)
		if err != nil {
			continue
		}
		pc := &countingPC{UDPConn: udp}
		ln, err := quic.Listen(pc, cfg, &quic.Config{MaxIdleTimeout: 2 * time.Minute})
		if err != nil {
			pc.Close()
			continue
		}
		started++
		s.track(ln)
		wg.Add(1)
		go func(ln *quic.Listener) {
			defer wg.Done()
			for {
				conn, err := ln.Accept(context.Background())
				if err != nil {
					fmt.Fprintf(os.Stderr, "QUIC %s: %v\n", ln.Addr(), err)
					return
				}
				fmt.Fprintf(os.Stderr, "QUIC connection from %s\n", conn.RemoteAddr())
				go s.serveH3Conn(conn)
			}
		}(ln)
	}
	if started == 0 {
		return fmt.Errorf("could not bind %s on any address", addr)
	}
	return nil
}

// countingPC counts the datagrams received: without it "the browser never came"
// and "it came but the handshake failed" are indistinguishable.
type countingPC struct {
	*net.UDPConn
	n  atomic.Int64
	wr atomic.Int64
}

func (c *countingPC) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.UDPConn.WriteTo(b, addr)
	if k := c.wr.Add(1); k <= 12 {
		fmt.Fprintf(os.Stderr, "QUIC -> %d: %d bytes, %s\n", k, len(b), describePacket(b))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "QUIC: send error to %s: %v\n", addr, err)
	}
	return n, err
}

func (c *countingPC) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	if err == nil {
		if k := c.n.Add(1); k <= 12 {
			fmt.Fprintf(os.Stderr, "QUIC <- %d: %d bytes from %s, %s\n", k, n, addr, describePacket(b[:n]))
		}
	}
	return n, addr, err
}

// describePacket reads the cleartext part of a QUIC header.
//
// The version and the packet type are not encrypted, and they show the main
// things: whether the sides agreed on a version and how far the handshake got.
func describePacket(b []byte) string {
	if len(b) < 1 {
		return "empty"
	}
	if b[0]&0x80 == 0 {
		return "short header (1-RTT)"
	}
	if len(b) < 7 {
		return "long header, truncated"
	}
	ver := binary.BigEndian.Uint32(b[1:5])
	kinds := map[byte]string{0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
	kind := kinds[(b[0]&0x30)>>4]
	name := fmt.Sprintf("version 0x%08x", ver)
	switch ver {
	case 0:
		return "Version Negotiation"
	case 0x00000001:
		name = "QUIC v1"
	case 0x6b3343cf:
		name = "QUIC v2"
	}
	if kind == "" {
		kind = "?"
	}
	// Connection identifiers are not encrypted. The server reply must carry a
	// DCID equal to the client's SCID: a mismatch here would mean the client
	// simply does not recognise our packet as its own.
	cids := ""
	if len(b) > 5 {
		dl := int(b[5])
		if len(b) >= 6+dl+1 {
			dcid := b[6 : 6+dl]
			sl := int(b[6+dl])
			if len(b) >= 7+dl+sl {
				scid := b[7+dl : 7+dl+sl]
				cids = fmt.Sprintf(", dcid=%x scid=%x", dcid, scid)
			}
		}
	}
	return name + ", " + kind + cids
}

// resolveAll expands a host into all of its addresses.
func resolveAll(host, port string) []*net.UDPAddr {
	var ips []net.IP
	if host == "localhost" {
		ips = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	} else {
		var err error
		if ips, err = net.LookupIP(host); err != nil {
			return nil
		}
	}
	var out []*net.UDPAddr
	for _, ip := range ips {
		a, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			out = append(out, a)
		}
	}
	return out
}

func (s *srv) serveH3Conn(conn *quic.Conn) {
	dec := cqpack.NewDecoder(qpackMaxTableCapacity)
	defer dec.Close(errors.New("connection closed"))

	// The control stream with SETTINGS: without it Chrome closes the connection.
	if ctl, err := conn.OpenUniStream(); err == nil {
		var b []byte
		b = quicvarint.Append(b, h3StreamControl)
		var payload []byte
		payload = quicvarint.Append(payload, 0x01) // QPACK_MAX_TABLE_CAPACITY
		payload = quicvarint.Append(payload, qpackMaxTableCapacity)
		payload = quicvarint.Append(payload, 0x07) // QPACK_BLOCKED_STREAMS
		payload = quicvarint.Append(payload, qpackBlockedStreams)
		b = quicvarint.Append(b, h3FrameSettings)
		b = quicvarint.Append(b, uint64(len(payload)))
		b = append(b, payload...)
		_, _ = ctl.Write(b)
	}
	if enc, err := conn.OpenUniStream(); err == nil {
		_, _ = enc.Write(quicvarint.Append(nil, h3StreamEncoder))
	}
	if d, err := conn.OpenUniStream(); err == nil {
		if _, err := d.Write(quicvarint.Append(nil, h3StreamDecoder)); err == nil {
			dec.SetDecoderStream(d)
		}
	}

	go func() {
		for {
			str, err := conn.AcceptUniStream(context.Background())
			if err != nil {
				return
			}
			go s.serveH3Uni(str, dec)
		}
	}()

	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go s.serveH3Stream(str, dec)
	}
}

func (s *srv) serveH3Uni(str *quic.ReceiveStream, dec *cqpack.Decoder) {
	r := quicvarint.NewReader(str)
	t, err := quicvarint.Read(r)
	if err != nil {
		return
	}
	switch t {
	case h3StreamEncoder:
		// The encoder stream feeds the dynamic table: without it the references
		// to it inside HEADERS do not expand.
		_ = dec.ReadEncoderStream(str)
	case h3StreamControl:
		s.readControlStream(r)
	default:
		_, _ = io.Copy(io.Discard, str)
	}
}

// readControlStream records the frames of the client's control stream.
//
// The HTTP/3-layer fingerprint lives here: the SETTINGS order, the GREASE frame
// and PRIORITY_UPDATE. Public oracles report it as a perk string, but your own
// browser on a phone cannot be checked against it — here it arrives as it is.
func (s *srv) readControlStream(r quicvarint.Reader) {
	for {
		t, err := quicvarint.Read(r)
		if err != nil {
			return
		}
		n, err := quicvarint.Read(r)
		if err != nil {
			return
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return
		}
		if t != h3FrameSettings {
			// GREASE frames and PRIORITY_UPDATE differ only by type: the payload is
			// not needed for the fingerprint, the type is.
			s.note(fmt.Sprintf("control stream frame: type %d (0x%x), length %d", t, t, n))
			continue
		}
		var pairs []string
		br := bytes.NewReader(payload)
		vr := quicvarint.NewReader(br)
		for {
			id, err := quicvarint.Read(vr)
			if err != nil {
				break
			}
			val, err := quicvarint.Read(vr)
			if err != nil {
				break
			}
			pairs = append(pairs, fmt.Sprintf("%d:%d", id, val))
		}
		s.note("client SETTINGS: " + strings.Join(pairs, ";"))
	}
}

func (s *srv) serveH3Stream(str *quic.Stream, dec *cqpack.Decoder) {
	defer str.Close()
	r := quicvarint.NewReader(str)
	var rec *record
	for {
		t, err := quicvarint.Read(r)
		if err != nil {
			break
		}
		n, err := quicvarint.Read(r)
		if err != nil {
			break
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(str, payload); err != nil {
			break
		}
		if t != h3FrameHeaders {
			continue // DATA and everything else is irrelevant to the header order
		}
		out := record{Proto: "h3"}
		next := dec.Decode(uint64(str.StreamID()), payload)
		for {
			hf, err := next()
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "QPACK:", err)
				return
			}
			switch hf.Name {
			case ":method":
				out.Method = hf.Value
			case ":path":
				out.Path = hf.Value
			case ":authority":
				out.Host = hf.Value
			}
			out.Headers = append(out.Headers, hf.Name+": "+hf.Value)
		}
		rec = &out
		s.add(out)
		break
	}
	if rec == nil {
		return
	}
	rep := route(rec.Path, rec.Host)
	body := rep.body

	var block bytes.Buffer
	enc := qpack.NewEncoder(&block)
	_ = enc.WriteField(qpack.HeaderField{Name: ":status", Value: fmt.Sprint(rep.status)})
	if rep.location != "" {
		_ = enc.WriteField(qpack.HeaderField{Name: "location", Value: rep.location})
	}
	if rep.ctype != "" {
		_ = enc.WriteField(qpack.HeaderField{Name: "content-type", Value: rep.ctype})
	}
	_ = enc.WriteField(qpack.HeaderField{Name: "content-length", Value: fmt.Sprint(len(body))})
	_ = enc.WriteField(qpack.HeaderField{Name: "accept-ch", Value: acceptCH})
	_ = enc.WriteField(qpack.HeaderField{Name: "critical-ch", Value: acceptCH})
	for _, c := range rep.cookies {
		_ = enc.WriteField(qpack.HeaderField{Name: "set-cookie", Value: c})
	}
	_ = enc.Close()

	var b []byte
	b = quicvarint.Append(b, h3FrameHeaders)
	b = quicvarint.Append(b, uint64(block.Len()))
	b = append(b, block.Bytes()...)
	b = quicvarint.Append(b, h3FrameData)
	b = quicvarint.Append(b, uint64(len(body)))
	b = append(b, body...)
	_, _ = str.Write(b)
}

// ---------------------------------------------------------------------------
// The browser and the report
// ---------------------------------------------------------------------------

// spkiHash is the base64 SHA-256 of the certificate's SubjectPublicKeyInfo,
// in the form --ignore-certificate-errors-spki-list expects.
func spkiHash(path string) (string, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", errors.New("the certificate did not parse")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

func defaultBrowser() string {
	for _, c := range []string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/usr/bin/google-chrome", "/usr/bin/chromium",
	} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// launch starts the browser in a fresh profile and returns a stop function.
//
// headless: the network layer of headless Chrome is the same, while a window
// with a certificate error would have to be dismissed by hand.
func launch(browser, origin string, h3 bool) func() {
	dir, err := os.MkdirTemp("", "curlpro-hcap-")
	if err != nil {
		return func() {}
	}
	args := []string{
		"--headless=new",
		"--user-data-dir=" + dir,
		"--no-first-run",
		"--no-default-browser-check",
		"--ignore-certificate-errors",
	}
	if origins {
		// Chromium resolves *.localhost to loopback on its own; the rule makes
		// that explicit rather than relied upon. The page is on www.a.localhost.
		args = append(args, "--host-resolver-rules=MAP *.localhost 127.0.0.1")
		origin = originsPage + ":" + listenPort
	}
	// --ignore-certificate-errors does not extend to the QUIC path — Chrome
	// sends the datagrams but silently abandons the handshake — nor does it
	// make the origin secure enough for the high-entropy client hints: three
	// runs got sec-ch-ua, -mobile and -platform and nothing else (STAGE19).
	// The stand's public key fingerprint lifts both checks, so every Chrome
	// run gets it.
	if h, err := spkiHash(certFile); err == nil {
		args = append(args, "--ignore-certificate-errors-spki-list="+h)
	} else {
		fmt.Fprintln(os.Stderr, "key fingerprint:", err)
	}
	if h3 {
		args = append(args, "--enable-quic", "--origin-to-force-quic-on="+origin)
	}
	start := "https://" + origin + "/"
	if origins {
		start = "https://" + origin + originsStart
	}
	args = append(args, start)
	cmd := exec.Command(browser, args...)
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "launching the browser:", err)
		os.RemoveAll(dir)
		return func() {}
	}
	return func() {
		if runtime.GOOS == "windows" {
			_ = exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprint(cmd.Process.Pid)).Run()
		}
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		time.Sleep(time.Second)
		os.RemoveAll(dir)
	}
}

func (s *srv) report(out string) {
	s.mu.Lock()
	recs := append([]record(nil), s.records...)
	s.mu.Unlock()

	s.mu.Lock()
	notes := append([]string(nil), s.notes...)
	s.mu.Unlock()
	for _, n := range notes {
		fmt.Println(n)
	}
	if len(recs) == 0 {
		fmt.Println("no request was captured")
		return
	}
	if !origins {
		sort.SliceStable(recs, func(i, j int) bool { return recs[i].Path < recs[j].Path })
	}
	for _, r := range recs {
		mark := ""
		if r.Resumed {
			mark = "  [resumed TLS]"
		}
		fmt.Printf("\n=== %s %s %s%s%s\n", r.Proto, r.Method, r.Host, r.Path, mark)
		for _, h := range r.Headers {
			name, value, _ := strings.Cut(h, ": ")
			if len(value) > 60 {
				value = value[:57] + "..."
			}
			fmt.Printf("  %-24s %s\n", name, value)
		}
	}
	if out != "" {
		b, _ := json.MarshalIndent(recs, "", "  ")
		if err := os.WriteFile(out, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "writing:", err)
		} else {
			fmt.Printf("\nwritten to %s\n", out)
		}
	}
}
