package client

// Тесты на поведение, введённое по итогам аудита (docs/STAGE14-RESULTS.md):
// метаданные Fetch на редиректах, permessage-deflate, ленивая распаковка,
// несколько HTTP/1.1-соединений на хост, слоты Content-Length/Content-Type/Origin.

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"

	"github.com/curlpro/curlpro/internal/profile"
)

// ---------------------------------------------------------------------------
// Редиректы
// ---------------------------------------------------------------------------

func navigationLike() profile.HeadersSpec {
	return profile.HeadersSpec{
		UserAgent: "Mozilla/5.0",
		Order: []profile.HeaderPair{
			{Key: "user-agent"},
			{Key: "sec-fetch-site", Value: "none"},
			{Key: "sec-fetch-mode", Value: "navigate"},
			{Key: "sec-fetch-user", Value: "?1"},
			{Key: "sec-fetch-dest", Value: "document"},
		},
	}
}

func headerOf(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// Навигация, начатая браузером, инициатора не имеет: Chromium оставляет
// sec-fetch-site: none и sec-fetch-user на каждом хопе, даже при смене хоста.
func TestRedirectKeepsNoneAndUserForNavigation(t *testing.T) {
	s := testSession(t, navigationLike(), profile.HTTP1Spec{})
	prev := &Request{Method: "GET", URL: "https://a.example.com/x"}

	next := s.nextRequest(prev, "https://b.other.org/y", 302, prev.URL)

	if v, ok := headerOf(next.Headers, "sec-fetch-site"); ok {
		t.Errorf("sec-fetch-site: none переписан в %q", v)
	}
	for _, name := range next.SuppressHeaders {
		if strings.EqualFold(name, "sec-fetch-user") {
			t.Error("sec-fetch-user погашен, а браузер его оставляет")
		}
	}
	built := names(s.buildHeaders(&next, mustURL(t, next.URL), "b.other.org", nil))
	if indexOf(built, "sec-fetch-user") < 0 {
		t.Errorf("sec-fetch-user пропал из запроса после редиректа: %v", built)
	}
}

// Явно заданное значение считается от инициатора всей цепочки и только
// ухудшается: same-origin → same-site → cross-site.
func TestRedirectEscalatesExplicitSite(t *testing.T) {
	s := testSession(t, navigationLike(), profile.HTTP1Spec{})
	const initiator = "https://a.example.com/start"
	cases := []struct{ from, to, prev, want string }{
		{initiator, "https://a.example.com/next", "same-origin", "same-origin"},
		{initiator, "https://b.example.com/next", "same-origin", "same-site"},
		{initiator, "https://a.example.co.uk/next", "same-origin", "cross-site"},
		{initiator, "https://other.org/next", "same-origin", "cross-site"},
		// Обратно не возвращается: цепочка уже была cross-site.
		{"https://other.org/mid", "https://a.example.com/back", "cross-site", "cross-site"},
		{initiator, "https://b.example.com/next", "same-site", "same-site"},
	}
	for _, tc := range cases {
		prev := &Request{Method: "GET", URL: tc.from, Headers: map[string]string{"Sec-Fetch-Site": tc.prev}}
		next := s.nextRequest(prev, tc.to, 302, initiator)
		got, _ := headerOf(next.Headers, "sec-fetch-site")
		if got != tc.want {
			t.Errorf("%s → %s при %s: получено %q, ожидалось %q", tc.from, tc.to, tc.prev, got, tc.want)
		}
		if n := len(next.Headers); n != 1 {
			t.Errorf("в карте %d ключей, ожидался один: %v", n, next.Headers)
		}
	}
}

// Редирект на http:// не ошибка клиента: ответ 3xx отдаётся как есть.
func TestRedirectToHTTPReturnsResponse(t *testing.T) {
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Location", "http://example.com/plain")
		w.WriteHeader(302)
	})
	srv, _ := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true, FollowRedirects: true})
	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
	if err != nil {
		t.Fatalf("ожидался ответ 302, получена ошибка: %v", err)
	}
	if resp.Status != 302 || resp.Headers["Location"] == nil {
		t.Errorf("ответ %d %v", resp.Status, resp.Headers)
	}
}

// ---------------------------------------------------------------------------
// Слоты: Content-Length, Content-Type, Origin
// ---------------------------------------------------------------------------

func postLike() (profile.HeadersSpec, profile.HTTP1Spec) {
	headers := profile.HeadersSpec{
		UserAgent:    "Mozilla/5.0",
		CustomAnchor: "accept",
		Order: []profile.HeaderPair{
			{Key: "content-length"},
			{Key: "sec-ch-ua", Value: `"Chromium";v="151"`},
			{Key: "upgrade-insecure-requests", Value: "1"},
			{Key: "content-type"},
			{Key: "user-agent"},
			{Key: "origin"},
			{Key: "accept", Value: "text/html"},
			{Key: "accept-encoding", Value: "gzip"},
		},
	}
	h1 := profile.HTTP1Spec{
		Connection: "keep-alive",
		Order: []string{"Host", "Connection", "Content-Length", "sec-ch-ua", "Upgrade-Insecure-Requests",
			"Content-Type", "User-Agent", "Origin", "Accept", "Accept-Encoding"},
	}
	return headers, h1
}

// Замер Chromium 148, навигационный POST: Host, Connection, Content-Length,
// …, Content-Type, User-Agent, Origin, Accept, …
func TestPostSlotsOnWire(t *testing.T) {
	headers, h1 := postLike()
	s := testSession(t, headers, h1)
	r := &Request{Method: "POST", URL: "https://example.com/form",
		Headers: map[string]string{"content-type": "application/x-www-form-urlencoded", "X-Api-Key": "v1"}}

	got := wireNames(t, s, r, "a=1")

	want := []string{"host", "connection", "content-length", "sec-ch-ua", "upgrade-insecure-requests",
		"content-type", "user-agent", "origin", "x-api-key", "accept", "accept-encoding"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("порядок на проводе\n получен: %v\n ожидался: %v", got, want)
	}
}

// GET без тела: пустые слоты не оставляют следа, Origin не добавляется.
func TestGetLeavesSlotsEmpty(t *testing.T) {
	headers, h1 := postLike()
	s := testSession(t, headers, h1)

	got := wireNames(t, s, &Request{Method: "GET", URL: "https://example.com/"}, "")

	for _, n := range got {
		switch n {
		case "content-length", "content-type", "origin":
			t.Errorf("пустой слот %s превратился в заголовок: %v", n, got)
		}
	}
}

func TestOriginValueIsRequestOrigin(t *testing.T) {
	headers, _ := postLike()
	s := testSession(t, headers, profile.HTTP1Spec{})
	built := s.buildHeaders(&Request{Method: "POST"}, mustURL(t, "https://shop.example.com:8443/cart"), "shop.example.com:8443", nil)
	for _, h := range built {
		if strings.EqualFold(h.Key, "origin") {
			if h.Value != "https://shop.example.com:8443" {
				t.Errorf("origin = %q", h.Value)
			}
			return
		}
	}
	t.Errorf("origin не добавлен: %v", names(built))
}

// ---------------------------------------------------------------------------
// Распаковка
// ---------------------------------------------------------------------------

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(data)
	zw.Close()
	return buf.Bytes()
}

func TestDecompressChainsAndSniffs(t *testing.T) {
	plain := []byte("plain text body")
	var brBuf bytes.Buffer
	bw := brotli.NewWriter(&brBuf)
	bw.Write(gzipped(t, plain))
	bw.Close()

	var raw bytes.Buffer
	fw, _ := flate.NewWriter(&raw, flate.DefaultCompression)
	fw.Write(plain)
	fw.Close()

	cases := []struct {
		name, encoding string
		body           []byte
	}{
		{"gzip", "gzip", gzipped(t, plain)},
		{"x-gzip с пробелами", " x-gzip ", gzipped(t, plain)},
		{"цепочка gzip, br", "gzip, br", brBuf.Bytes()},
		{"deflate сырой", "deflate", raw.Bytes()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc, err := decompress(io.NopCloser(bytes.NewReader(tc.body)), tc.encoding)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(rc)
			if err != nil || string(got) != string(plain) {
				t.Errorf("получено %q, %v", got, err)
			}
		})
	}
}

// Пустое тело с Content-Encoding (HEAD, 204, 304) — это отсутствие данных,
// а не сбой распаковки.
func TestDecompressEmptyBodyIsEOF(t *testing.T) {
	for _, enc := range []string{"gzip", "deflate", "zstd"} {
		rc, err := decompress(io.NopCloser(bytes.NewReader(nil)), enc)
		if err != nil {
			t.Fatalf("%s: %v", enc, err)
		}
		got, err := io.ReadAll(rc)
		if err != nil || len(got) != 0 {
			t.Errorf("%s: %q, %v", enc, got, err)
		}
	}
}

func TestDecompressRejectsUnknown(t *testing.T) {
	if _, err := decompress(io.NopCloser(bytes.NewReader(nil)), "compress"); err == nil {
		t.Error("неизвестная кодировка принята молча")
	}
}

// ---------------------------------------------------------------------------
// Пул HTTP/1.1: параллельные запросы на нескольких соединениях
// ---------------------------------------------------------------------------

func TestHTTP1PoolKeepsSeveralConnections(t *testing.T) {
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		time.Sleep(80 * time.Millisecond)
		io.WriteString(w, "ok")
	})
	srv, conns := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})

	wave := func() {
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
	}
	wave()
	first := conns.Load()
	wave()
	second := conns.Load() - first

	s.mu.Lock()
	pooled := 0
	for _, list := range s.conns {
		pooled += len(list)
	}
	s.mu.Unlock()
	t.Logf("первая волна: %d соединений, вторая: +%d, в пуле: %d", first, second, pooled)
	if pooled != maxConnsPerHost {
		t.Errorf("в пуле %d соединений, ожидалось %d", pooled, maxConnsPerHost)
	}
	if second > 12-maxConnsPerHost {
		t.Errorf("вторая волна открыла %d новых соединений, а %d простаивали в пуле",
			second, maxConnsPerHost)
	}
}

// ---------------------------------------------------------------------------
// WebSocket: permessage-deflate и заголовки рукопожатия
// ---------------------------------------------------------------------------

// deflateServer — компрессор серверной стороны с context takeover.
type deflateServer struct {
	buf bytes.Buffer
	w   *flate.Writer
}

func (d *deflateServer) frame(t *testing.T, msg string) []byte {
	t.Helper()
	if d.w == nil {
		d.w, _ = flate.NewWriter(&d.buf, flate.DefaultCompression)
	}
	d.buf.Reset()
	d.w.Write([]byte(msg))
	d.w.Flush()
	payload := bytes.TrimSuffix(d.buf.Bytes(), deflateTail)
	head := []byte{0x80 | 0x40 | opText} // FIN, RSV1, text
	switch n := len(payload); {
	case n < 126:
		head = append(head, byte(n))
	default:
		head = append(head, 126)
		head = binary.BigEndian.AppendUint16(head, uint16(n))
	}
	return append(head, payload...)
}

// readClientFrame разбирает маскированный кадр клиента.
func readClientFrame(t *testing.T, br *bufio.Reader) (rsv1 bool, payload []byte) {
	t.Helper()
	var head [2]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		t.Fatal(err)
	}
	rsv1 = head[0]&0x40 != 0
	n := uint64(head[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		io.ReadFull(br, ext[:])
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		io.ReadFull(br, ext[:])
		n = binary.BigEndian.Uint64(ext[:])
	}
	var mask [4]byte
	io.ReadFull(br, mask[:])
	payload = make([]byte, n)
	io.ReadFull(br, payload)
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return rsv1, payload
}

func inflateForTest(t *testing.T, payload []byte) string {
	t.Helper()
	r := flate.NewReader(io.MultiReader(bytes.NewReader(payload), bytes.NewReader(deflateTail), bytes.NewReader(deflateFinal)))
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// wsServerWith — как wsServer, но с дополнительными заголовками ответа 101.
func wsServerWith(t *testing.T, extra string, after func(c net.Conn, br *bufio.Reader)) string {
	t.Helper()
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		c, rw, err := w.(stdhttp.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"+
			"Connection: Upgrade\r\nSec-WebSocket-Accept: "+acceptKey(r.Header.Get("Sec-WebSocket-Key"))+
			"\r\n"+extra+"\r\n")
		after(c, rw.Reader)
	})
	srv, _ := auditServer(t, false, h)
	return wsURL(srv)
}

func TestWebSocketPermessageDeflate(t *testing.T) {
	got := make(chan string, 1)
	url := wsServerWith(t, "Sec-WebSocket-Extensions: permessage-deflate\r\n",
		func(c net.Conn, br *bufio.Reader) {
			var d deflateServer
			// Два сообщения подряд: второе ссылается на окно первого.
			c.Write(d.frame(t, "hello, websocket deflate"))
			c.Write(d.frame(t, "hello, websocket deflate again"))
			rsv1, payload := readClientFrame(t, br)
			if !rsv1 {
				got <- "клиент не сжал сообщение"
				return
			}
			got <- inflateForTest(t, payload)
			time.Sleep(200 * time.Millisecond)
			c.Close()
		})
	s := auditSession(t, Options{DefaultHeaders: true})
	ws, err := s.DialWebSocket(url, WebSocketOptions{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close(1000, "")

	for _, want := range []string{"hello, websocket deflate", "hello, websocket deflate again"} {
		msg, err := ws.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if string(msg.Data) != want {
			t.Errorf("получено %q, ожидалось %q", msg.Data, want)
		}
	}
	if err := ws.Send(false, []byte("from client, compressed")); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if s != "from client, compressed" {
			t.Errorf("сервер прочитал %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("сервер не получил сообщение")
	}
}

func TestWebSocketRejectsCompressedWithoutNegotiation(t *testing.T) {
	url := wsServerWith(t, "", func(c net.Conn, br *bufio.Reader) {
		var d deflateServer
		c.Write(d.frame(t, "surprise"))
		time.Sleep(200 * time.Millisecond)
		c.Close()
	})
	s := auditSession(t, Options{DefaultHeaders: true})
	ws, err := s.DialWebSocket(url, WebSocketOptions{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close(1000, "")
	_, err = ws.Recv()
	if Code(err) != CodeWSProtocol {
		t.Errorf("ожидалась ошибка протокола, получено %v (код %q)", err, Code(err))
	}
}

func TestWebSocketMessageLimit(t *testing.T) {
	url := wsServerWith(t, "", func(c net.Conn, br *bufio.Reader) {
		head := []byte{0x82, 126}
		head = binary.BigEndian.AppendUint16(head, 2048)
		c.Write(append(head, bytes.Repeat([]byte("x"), 2048)...))
		time.Sleep(200 * time.Millisecond)
		c.Close()
	})
	s := auditSession(t, Options{DefaultHeaders: true})
	ws, err := s.DialWebSocket(url, WebSocketOptions{Timeout: 2 * time.Second, MaxMessageSize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close(1000, "")
	_, err = ws.Recv()
	if Code(err) != CodeWSTooBig {
		t.Errorf("ожидался код %s, получено %v (код %q)", CodeWSTooBig, err, Code(err))
	}
}

// Рукопожатие собирается по шаблону профиля: Host первым, ключ после
// Accept-Language, навигационных заголовков нет (замер Chromium 148).
func TestWebSocketHandshakeFollowsTemplate(t *testing.T) {
	var lines atomic.Value
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		c, rw, _ := w.(stdhttp.Hijacker).Hijack()
		defer c.Close()
		_ = rw
		io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
	})
	// Сырые строки нужны для регистра и порядка: берём их с сокета до Hijack
	// нельзя, поэтому сервер-обёртка читает запрос сам.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv, _ := auditServer(t, false, h)
	_ = srv
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := tlsServerConn(t, c)
				if tc == nil {
					return
				}
				br := bufio.NewReader(tc)
				var head []string
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
					head = append(head, strings.TrimRight(line, "\r\n"))
				}
				lines.Store(head)
				io.WriteString(tc, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s := auditSession(t, Options{DefaultHeaders: true, Cookies: true})
	s.profile.WebSocket.Order = chromeWebSocketOrder()
	_, err = s.DialWebSocket("wss://localhost:"+port+"/ws", WebSocketOptions{Timeout: 2 * time.Second, Subprotocols: []string{"chat"}})
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("ожидался отказ 400, получено %v", err)
	}
	head, _ := lines.Load().([]string)
	var got []string
	for _, l := range head[1:] {
		got = append(got, strings.SplitN(l, ":", 2)[0])
	}
	want := []string{"Host", "Connection", "Pragma", "Cache-Control", "User-Agent", "Upgrade", "Origin",
		"Sec-WebSocket-Version", "Accept-Encoding", "Accept-Language", "Sec-WebSocket-Key",
		"Sec-WebSocket-Extensions", "Sec-WebSocket-Protocol"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("рукопожатие\n получено: %v\n ожидалось: %v", got, want)
	}
	for _, l := range head {
		if strings.HasPrefix(l, "Connection:") && l != "Connection: Upgrade" {
			t.Errorf("Connection: %q", l)
		}
	}
}

func chromeWebSocketOrder() []profile.HeaderPair {
	return []profile.HeaderPair{
		{Key: "Host"}, {Key: "Connection", Value: "Upgrade"}, {Key: "Pragma", Value: "no-cache"},
		{Key: "Cache-Control", Value: "no-cache"}, {Key: "User-Agent"}, {Key: "Upgrade", Value: "websocket"},
		{Key: "Origin"}, {Key: "Sec-WebSocket-Version", Value: "13"}, {Key: "Accept-Encoding"},
		{Key: "Accept-Language"}, {Key: "Cookie"}, {Key: "Sec-WebSocket-Key"},
		{Key: "Sec-WebSocket-Extensions", Value: "permessage-deflate; client_max_window_bits"},
		{Key: "Sec-WebSocket-Protocol"},
	}
}

// ---------------------------------------------------------------------------
// STAGE15: набор HTTP/1.1, список якорей, порядок на хопе редиректа
// ---------------------------------------------------------------------------

// http1.order задаёт и набор: Chrome не шлёт priority на HTTP/1.1, хотя
// в HTTP/2 он есть (замер Chrome 152).
func TestHTTP1OrderDefinesHeaderSet(t *testing.T) {
	headers := chromeLike() // содержит priority
	h1 := profile.HTTP1Spec{Connection: "keep-alive",
		Order: []string{"Host", "Connection", "User-Agent", "Accept", "Accept-Encoding", "Accept-Language", "Cookie"}}
	s := testSession(t, headers, h1)
	u := mustURL(t, "https://example.com/")

	onH1 := names(s.buildHeaders(&Request{}, u, "example.com", h1.Order))
	onH2 := names(s.buildHeaders(&Request{}, u, "example.com", nil))
	if indexOf(onH1, "priority") >= 0 {
		t.Errorf("priority ушёл на HTTP/1.1, хотя в http1.order его нет: %v", onH1)
	}
	if indexOf(onH2, "priority") < 0 {
		t.Errorf("priority пропал в HTTP/2: %v", onH2)
	}
}

// Список якорей: берётся первый присутствующий. У Firefox кастомные заголовки
// идут перед Connection, которого в HTTP/2 нет, — там перед
// Upgrade-Insecure-Requests (замер Firefox 154).
func TestAnchorListPicksPresentName(t *testing.T) {
	headers := profile.HeadersSpec{
		UserAgent:    "Mozilla/5.0",
		CustomAnchor: "connection, upgrade-insecure-requests",
		Order: []profile.HeaderPair{
			{Key: "user-agent"}, {Key: "accept", Value: "*/*"}, {Key: "accept-encoding", Value: "gzip"},
			{Key: "upgrade-insecure-requests", Value: "1"}, {Key: "sec-fetch-dest", Value: "document"},
		},
	}
	h1 := profile.HTTP1Spec{Connection: "keep-alive",
		Order: []string{"Host", "User-Agent", "Accept", "Accept-Encoding", "Connection", "Upgrade-Insecure-Requests", "Sec-Fetch-Dest"}}
	s := testSession(t, headers, h1)
	s.headers.Set("X-Api-Key", "v1")
	u := mustURL(t, "https://example.com/")

	onH1 := names(s.buildHeaders(&Request{}, u, "example.com", h1.Order))
	if at, anchor := indexOf(onH1, "x-api-key"), indexOf(onH1, "connection"); at != anchor-1 {
		t.Errorf("HTTP/1.1: кастомный заголовок не перед Connection: %v", onH1)
	}
	onH2 := names(s.buildHeaders(&Request{}, u, "example.com", nil))
	if at, anchor := indexOf(onH2, "x-api-key"), indexOf(onH2, "upgrade-insecure-requests"); at != anchor-1 {
		t.Errorf("HTTP/2: кастомный заголовок не перед Upgrade-Insecure-Requests: %v", onH2)
	}
	// И на проводе HTTP/1.1 — через настоящий Request.Write.
	got := wireNames(t, s, &Request{Method: "GET", URL: "https://example.com/"}, "")
	if at, anchor := indexOf(got, "x-api-key"), indexOf(got, "connection"); at != anchor-1 {
		t.Errorf("провод HTTP/1.1: %v", got)
	}
}

// На хопе редиректа Chromium переставляет sec-ch-ua* после Sec-Fetch-Dest,
// а Referer следует за ними (замер Chrome 152: оба хопа).
func TestRedirectHopMovesClientHints(t *testing.T) {
	headers := profile.HeadersSpec{
		UserAgent:    "Mozilla/5.0",
		CustomAnchor: "accept",
		Order: []profile.HeaderPair{
			{Key: "sec-ch-ua", Value: `"Chromium";v="152"`}, {Key: "sec-ch-ua-mobile", Value: "?0"},
			{Key: "sec-ch-ua-platform", Value: `"Windows"`}, {Key: "upgrade-insecure-requests", Value: "1"},
			{Key: "user-agent"}, {Key: "accept", Value: "text/html"}, {Key: "sec-fetch-site", Value: "none"},
			{Key: "sec-fetch-mode", Value: "navigate"}, {Key: "sec-fetch-dest", Value: "document"},
			{Key: "accept-encoding", Value: "gzip"}, {Key: "accept-language", Value: "ru"},
		},
	}
	h1 := profile.HTTP1Spec{Connection: "keep-alive", Order: []string{"Host", "Connection", "sec-ch-ua",
		"sec-ch-ua-mobile", "sec-ch-ua-platform", "Upgrade-Insecure-Requests", "User-Agent", "Accept",
		"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"}}
	s := testSession(t, headers, h1)
	r := &Request{Method: "GET", URL: "https://example.com/next", RedirectHop: true,
		Headers: map[string]string{"Referer": "https://example.com/start"}}

	got := wireNames(t, s, r, "")
	want := []string{"host", "connection", "upgrade-insecure-requests", "user-agent", "accept",
		"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-ch-ua", "sec-ch-ua-mobile",
		"sec-ch-ua-platform", "referer", "accept-encoding", "accept-language"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("хоп редиректа\n получен: %v\n ожидался: %v", got, want)
	}
	// В HTTP/2 то же самое, без Host и Connection.
	onH2 := names(s.buildHeaders(r, mustURL(t, r.URL), "example.com", nil))
	if indexOf(onH2, "sec-ch-ua") < indexOf(onH2, "sec-fetch-dest") {
		t.Errorf("HTTP/2 хоп: client hints не переставлены: %v", onH2)
	}
}

// ---------------------------------------------------------------------------
// STAGE15: режим fetch
// ---------------------------------------------------------------------------

func chromeWithFetch() (profile.HeadersSpec, profile.HTTP1Spec, profile.FetchSpec) {
	nav := profile.HeadersSpec{
		UserAgent:    "Mozilla/5.0",
		CustomAnchor: "accept",
		Order: []profile.HeaderPair{
			{Key: "sec-ch-ua", Value: `"Chromium";v="152"`}, {Key: "sec-ch-ua-mobile", Value: "?0"},
			{Key: "sec-ch-ua-platform", Value: `"Windows"`}, {Key: "upgrade-insecure-requests", Value: "1"},
			{Key: "content-type"}, {Key: "user-agent"}, {Key: "origin"}, {Key: "accept", Value: "text/html"},
			{Key: "sec-fetch-site", Value: "none"}, {Key: "sec-fetch-mode", Value: "navigate"},
			{Key: "sec-fetch-user", Value: "?1"}, {Key: "sec-fetch-dest", Value: "document"},
			{Key: "accept-encoding", Value: "gzip"}, {Key: "accept-language", Value: "ru"}, {Key: "cookie"},
		},
	}
	h1 := profile.HTTP1Spec{Connection: "keep-alive", Order: []string{"Host", "Connection", "sec-ch-ua",
		"sec-ch-ua-mobile", "sec-ch-ua-platform", "Upgrade-Insecure-Requests", "Content-Type", "User-Agent",
		"Origin", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
		"Accept-Encoding", "Accept-Language", "Cookie"}}
	fetch := profile.FetchSpec{
		CustomAnchor: "sec-ch-ua-mobile",
		Order: []profile.HeaderPair{
			{Key: "content-length"}, {Key: "sec-ch-ua-platform"}, {Key: "user-agent"}, {Key: "sec-ch-ua"},
			{Key: "content-type"}, {Key: "sec-ch-ua-mobile"}, {Key: "accept", Value: "*/*"}, {Key: "origin"},
			{Key: "sec-fetch-site", Value: "same-origin"}, {Key: "sec-fetch-mode", Value: "cors"},
			{Key: "sec-fetch-dest", Value: "empty"}, {Key: "referer"}, {Key: "accept-encoding"},
			{Key: "accept-language"}, {Key: "cookie"},
		},
		HTTP1Order: []string{"Host", "Connection", "Content-Length", "sec-ch-ua-platform", "User-Agent",
			"sec-ch-ua", "Content-Type", "sec-ch-ua-mobile", "Accept", "Origin", "Sec-Fetch-Site",
			"Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Accept-Language", "Cookie"},
	}
	return nav, h1, fetch
}

func fetchSession(t *testing.T) *Session {
	t.Helper()
	nav, h1, fetch := chromeWithFetch()
	s := testSession(t, nav, h1)
	s.profile.Fetch = fetch
	return s
}

// Замер Chrome 152, fetch POST JSON с кастомным заголовком по HTTP/1.1.
func TestFetchModeOnWire(t *testing.T) {
	s := fetchSession(t)
	r := &Request{Method: "POST", URL: "https://example.com/api",
		Headers: map[string]string{"content-type": "application/json", "X-Api-Key": "v1"}}
	if got := s.modeFor(r); got != ModeFetch {
		t.Fatalf("режим %q, ожидался fetch (JSON и кастомный заголовок)", got)
	}
	got := wireNames(t, s, r, `{"a":1}`)
	want := []string{"host", "connection", "content-length", "sec-ch-ua-platform", "user-agent", "sec-ch-ua",
		"content-type", "x-api-key", "sec-ch-ua-mobile", "accept", "origin", "sec-fetch-site",
		"sec-fetch-mode", "sec-fetch-dest", "accept-encoding", "accept-language"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("fetch POST\n получен: %v\n ожидался: %v", got, want)
	}
}

// Слоты fetch берут значения из навигационного набора: дельта на новую
// версию Chrome правит sec-ch-ua один раз.
func TestFetchSlotsFilledFromNavigation(t *testing.T) {
	s := fetchSession(t)
	built := s.buildHeaders(&Request{Method: "GET", Headers: map[string]string{"X-Api-Key": "v1"}},
		mustURL(t, "https://example.com/api"), "example.com", nil)
	for _, h := range built {
		switch strings.ToLower(h.Key) {
		case "sec-ch-ua":
			if h.Value != `"Chromium";v="152"` {
				t.Errorf("sec-ch-ua = %q", h.Value)
			}
		case "accept":
			if h.Value != "*/*" {
				t.Errorf("accept = %q, у fetch должен быть */*", h.Value)
			}
		case "upgrade-insecure-requests", "sec-fetch-user":
			t.Errorf("навигационный заголовок %s в fetch-наборе", h.Key)
		}
	}
}

// Автовыбор: форма — навигация, JSON — fetch, PUT — fetch, явный режим важнее.
func TestModeAutoDetection(t *testing.T) {
	s := fetchSession(t)
	cases := []struct {
		name string
		r    *Request
		want string
	}{
		{"GET без кастомных", &Request{Method: "GET"}, ModeNavigate},
		{"POST форма", &Request{Method: "POST", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}}, ModeNavigate},
		{"POST JSON", &Request{Method: "POST", Headers: map[string]string{"content-type": "application/json"}}, ModeFetch},
		{"PUT", &Request{Method: "PUT"}, ModeFetch},
		{"кастомный заголовок", &Request{Method: "GET", Headers: map[string]string{"Authorization": "Bearer x"}}, ModeFetch},
		{"referer не признак", &Request{Method: "GET", Headers: map[string]string{"Referer": "https://example.com/"}}, ModeNavigate},
		{"явная навигация", &Request{Method: "PUT", Mode: ModeNavigate}, ModeNavigate},
		{"явный fetch", &Request{Method: "GET", Mode: ModeFetch}, ModeFetch},
	}
	for _, tc := range cases {
		if got := s.modeFor(tc.r); got != tc.want {
			t.Errorf("%s: %q, ожидалось %q", tc.name, got, tc.want)
		}
	}
	// Профиль без секции fetch всегда навигация.
	s.profile.Fetch = profile.FetchSpec{}
	if got := s.modeFor(&Request{Method: "PUT", Mode: ModeFetch}); got != ModeNavigate {
		t.Errorf("без секции fetch режим %q", got)
	}
}
