package client

// Регрессионные тесты по находкам аудита 2026-09-02 (docs/STAGE14-RESULTS.md).
//
// Каждый тест воспроизводил конкретное расхождение между задокументированным
// и фактическим поведением на локальном стенде: TLS-сервер httptest (HTTP/1.1
// и HTTP/2), сервер HTTP/3 на uquic, WebSocket поверх Hijack, прокси-заглушки.
// Стенды поднимаются внутри теста, сеть не нужна.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	uh3 "github.com/refraction-networking/uquic/http3"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/profile"
)

func auditProfile(t *testing.T, name string) *profile.Profile {
	t.Helper()
	reg := profile.NewRegistry()
	if err := reg.LoadFS(os.DirFS("../../profiles"), "."); err != nil {
		t.Fatal(err)
	}
	p, err := reg.Resolve(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// auditServer поднимает TLS-сервер httptest. h2=false ограничивает ALPN
// до http/1.1 (так устроен httptest: EnableHTTP2 даёт только "h2").
// Второе значение — счётчик TCP-соединений, которые увидел сервер.
func auditServer(t *testing.T, h2 bool, h stdhttp.Handler) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = h2
	srv.Config.ConnState = func(c net.Conn, st stdhttp.ConnState) {
		if st == stdhttp.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &conns
}

// auditURL переводит адрес httptest на localhost: подключение по голому IP
// меняет SNI и JA4, а здесь нужна обычная форма.
func auditURL(srv *httptest.Server, path string) string {
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return "https://localhost:" + port + path
}

func auditSession(t *testing.T, opts Options) *Session {
	t.Helper()
	opts.InsecureSkipVerify = true
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	s, err := New(auditProfile(t, "chrome-151-windows"), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// ---------------------------------------------------------------------------
// 1. Путь HTTP/1.1 не распаковывает тело: DecompressBody у fhttp живёт
//    в Transport и в h2-транспорте, а conn.roundTrip ходит мимо обоих.
// ---------------------------------------------------------------------------

func TestAudit_HTTP1BodyNotDecompressed(t *testing.T) {
	const plain = "plain text over gzip"
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		zw := gzip.NewWriter(w)
		io.WriteString(zw, plain)
		zw.Close()
	})
	for _, tc := range []struct {
		name      string
		h2, force bool
	}{{"http1", false, true}, {"http2", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := auditServer(t, tc.h2, h)
			s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: tc.force})
			resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
			if err != nil {
				t.Fatal(err)
			}
			if string(resp.Body) != plain {
				t.Errorf("%s: тело не распаковано: proto=%s, %d байт, начало % x",
					tc.name, resp.Proto, len(resp.Body), resp.Body[:min(len(resp.Body), 8)])
			} else {
				t.Logf("%s: тело распаковано (proto=%s)", tc.name, resp.Proto)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. Повтор по коду ответа не закрывает удержанный ответ предыдущей попытки:
//    DoStream в цикле теряет outcome.stream вместе с телом, conn и cancel.
// ---------------------------------------------------------------------------

func TestAudit_RetryLeaksHeldResponse(t *testing.T) {
	var hits atomic.Int32
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if hits.Add(1) <= 2 {
			w.WriteHeader(503)
			io.WriteString(w, "busy")
			return
		}
		io.WriteString(w, "ok")
	})
	for _, tc := range []struct {
		name      string
		h2, force bool
	}{{"http1", false, true}, {"http2", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			hits.Store(0)
			srv, conns := auditServer(t, tc.h2, h)
			s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: tc.force,
				Retry: &RetryPolicy{Attempts: 2, Backoff: 10 * time.Millisecond}})
			resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
			if err != nil {
				t.Fatal(err)
			}
			if resp.Status != 200 {
				t.Fatalf("статус %d", resp.Status)
			}
			s.mu.Lock()
			var busy []int32
			for _, list := range s.conns {
				for _, c := range list {
					busy = append(busy, c.busy.Load())
				}
			}
			s.mu.Unlock()
			t.Logf("%s: сервер увидел %d соединений; busy соединений в пуле после ответа: %v",
				tc.name, conns.Load(), busy)
			for _, b := range busy {
				if b != 0 {
					t.Errorf("%s: соединение в пуле осталось занятым (busy=%d) после завершённого "+
						"запроса — удержанные ответы 503 не закрыты", tc.name, b)
				}
			}
			if !tc.h2 && conns.Load() != 1 {
				t.Errorf("http1: ожидалось одно keep-alive соединение, сервер увидел %d", conns.Load())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. Stream.Close на HTTP/1.1 дочитывает тело целиком: fhttp body.Close
//    (ветка default в transfer.go) делает io.Copy(io.Discard) до EOF.
//    А при истечении таймаута посреди дренажа соединение возвращается в пул
//    с недочитанными байтами в сокете.
// ---------------------------------------------------------------------------

func slowBodyHandler(chunks, chunk int, delay time.Duration, written *atomic.Int32) stdhttp.Handler {
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("/big", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(chunks*chunk))
		buf := bytes.Repeat([]byte("x"), chunk)
		for i := 0; i < chunks; i++ {
			if _, err := w.Write(buf); err != nil {
				return
			}
			written.Add(1)
			w.(stdhttp.Flusher).Flush()
			time.Sleep(delay)
		}
	})
	mux.HandleFunc("/small", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "ok")
	})
	return mux
}

func TestAudit_StreamCloseDrainsWholeBodyOnHTTP1(t *testing.T) {
	var written atomic.Int32
	const chunks = 100
	srv, _ := auditServer(t, false, slowBodyHandler(chunks, 64<<10, 20*time.Millisecond, &written))
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})

	st, err := s.DoStream(&Request{Method: "GET", URL: auditURL(srv, "/big")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(st, make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	cerr := st.Close()
	el := time.Since(start)
	t.Logf("Close после 1 КБ занял %s (err=%v); сервер успел отдать %d/%d кусков по 64 КБ",
		el, cerr, written.Load(), chunks)
	if el > 500*time.Millisecond {
		t.Errorf("Close дочитал ~%d МБ вместо того, чтобы сбросить соединение", chunks*64/1024)
	}
}

func TestAudit_StreamCloseTimeoutPoisonsConnection(t *testing.T) {
	var written atomic.Int32
	srv, conns := auditServer(t, false, slowBodyHandler(100, 64<<10, 20*time.Millisecond, &written))
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true, Timeout: 700 * time.Millisecond})

	st, err := s.DoStream(&Request{Method: "GET", URL: auditURL(srv, "/big")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(st, make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	t.Logf("Close (тело не дочитано, таймаут 700 мс): %v", st.Close())

	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/small")})
	if err != nil {
		t.Errorf("следующий запрос по той же сессии сломан: %v (соединений на сервере: %d)",
			err, conns.Load())
	} else {
		t.Logf("следующий запрос: %d %q (соединений на сервере: %d)", resp.Status, resp.Body, conns.Load())
	}
}

// ---------------------------------------------------------------------------
// 4. WebSocket.
// ---------------------------------------------------------------------------

// wsServer отвечает 101 на любое рукопожатие и отдаёт сокет в after.
func wsServer(t *testing.T, after func(c net.Conn, br *bufio.Reader)) *httptest.Server {
	t.Helper()
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		hj, ok := w.(stdhttp.Hijacker)
		if !ok {
			t.Error("нет Hijacker")
			return
		}
		c, rw, err := hj.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"+
			"Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			acceptKey(r.Header.Get("Sec-WebSocket-Key")))
		after(c, rw.Reader)
	})
	srv, _ := auditServer(t, false, h)
	return srv
}

func wsURL(srv *httptest.Server) string {
	return strings.Replace(auditURL(srv, "/ws"), "https://", "wss://", 1)
}

// Сервер прислал кадр Close: markClosed выставлен, и последующий Close()
// клиента становится no-op — TCP-сокет остаётся открытым.
func TestAudit_WebSocketServerCloseLeaksSocket(t *testing.T) {
	srv := wsServer(t, func(c net.Conn, _ *bufio.Reader) {
		c.Write([]byte{0x88, 0x02, 0x03, 0xE8}) // Close 1000 без маски
		time.Sleep(2 * time.Second)
		c.Close()
	})
	s := auditSession(t, Options{DefaultHeaders: true})
	ws, err := s.DialWebSocket(wsURL(srv), WebSocketOptions{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ws.Recv()
	t.Logf("Recv после Close сервера: %v", err)
	t.Logf("Close клиента: %v", ws.Close(1000, ""))

	if err := ws.conn.SetDeadline(time.Now()); err == nil {
		t.Errorf("после ws.Close() сокет остался открытым: Close вернулся по isClosed(), " +
			"не закрыв net.Conn и не ответив кадром Close")
		ws.conn.Close()
	} else {
		t.Logf("сокет закрыт: %v", err)
	}
}

// Длина кадра берётся из сети без предела: make([]byte, 2^62) паникует,
// а паника в c-shared библиотеке — это смерть процесса Python.
func TestAudit_WebSocketHugeFrameLengthPanics(t *testing.T) {
	srv := wsServer(t, func(c net.Conn, _ *bufio.Reader) {
		head := []byte{0x82, 0x7F}
		head = binary.BigEndian.AppendUint64(head, 1<<62)
		c.Write(head)
		time.Sleep(time.Second)
		c.Close()
	})
	s := auditSession(t, Options{DefaultHeaders: true})
	ws, err := s.DialWebSocket(wsURL(srv), WebSocketOptions{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close(1000, "")
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Recv паникует на заявленной длине кадра 2^62: %v", r)
			}
		}()
		_, err := ws.Recv()
		t.Logf("Recv: %v", err)
	}()
}

// ---------------------------------------------------------------------------
// 5. Прокси.
// ---------------------------------------------------------------------------

// Прокси принял TCP и молчит: CONNECT уходит без дедлайна, и таймаут
// запроса не действует.
func TestAudit_ProxyConnectIgnoresTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	})

	s := auditSession(t, Options{DefaultHeaders: true, Proxy: "http://" + ln.Addr().String(), Timeout: time.Second})
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := s.Do(&Request{Method: "GET", URL: "https://example.com/"})
		done <- err
	}()
	select {
	case err := <-done:
		t.Logf("запрос завершился за %s: %v", time.Since(start), err)
	case <-time.After(4 * time.Second):
		t.Errorf("timeout=1s, а запрос через молчащий прокси не завершился за 4 с: " +
			"connectProxy пишет и читает без дедлайна")
	}
}

// CONNECT к прокси уходит с заголовками по умолчанию fhttp.
func TestAudit_ProxyConnectCarriesGoUserAgent(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan *stdhttp.Request, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, err := stdhttp.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		got <- req
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
	}()

	s := auditSession(t, Options{DefaultHeaders: true, Proxy: "http://user:pw@" + ln.Addr().String(), Timeout: 3 * time.Second})
	_, err = s.Do(&Request{Method: "GET", URL: "https://example.com/"})
	t.Logf("ответ клиенту: %v", err)
	select {
	case req := <-got:
		t.Logf("CONNECT %s %s; Host=%q; заголовки: %v", req.Method, req.RequestURI, req.Host, req.Header)
		if ua := req.Header.Get("User-Agent"); !strings.Contains(ua, "Chrome/151") {
			t.Errorf("CONNECT к прокси уходит с User-Agent %q, а не браузера — прокси видит не браузер", ua)
		}
		if pc := req.Header.Get("Proxy-Connection"); pc != "keep-alive" {
			t.Errorf("Proxy-Connection = %q, Chrome шлёт keep-alive", pc)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("прокси не получил CONNECT")
	}
}

// ---------------------------------------------------------------------------
// 6. Session.Close ждёт чужой запрос: close() у h1 берёт c.mu, который
//    roundTrip удерживает на время ReadResponse.
// ---------------------------------------------------------------------------

func TestAudit_SessionCloseWaitsForInflightHTTP1(t *testing.T) {
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		time.Sleep(2 * time.Second)
		io.WriteString(w, "late")
	})
	srv, _ := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})

	done := make(chan error, 1)
	go func() {
		_, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	s.Close()
	el := time.Since(start)
	t.Logf("Close занял %s; запрос завершился: %v", el, <-done)
	if el > 500*time.Millisecond {
		t.Errorf("Close ждал завершения чужого запроса %s вместо того, чтобы оборвать его", el)
	}
}

// ---------------------------------------------------------------------------
// 7. Без заголовков профиля транспорты подставляют User-Agent Go.
// ---------------------------------------------------------------------------

func TestAudit_NoDefaultHeadersLeaksGoUserAgent(t *testing.T) {
	var ua atomic.Value
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		ua.Store(fmt.Sprintf("%q", r.Header.Get("User-Agent")))
		io.WriteString(w, "ok")
	})
	for _, tc := range []struct {
		name      string
		h2, force bool
	}{{"http1", false, true}, {"http2", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := auditServer(t, tc.h2, h)
			s := auditSession(t, Options{DefaultHeaders: false, ForceHTTP1: tc.force})
			if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
				t.Fatal(err)
			}
			got := ua.Load().(string)
			t.Logf("%s: User-Agent на сервере = %s", tc.name, got)
			if got != `""` {
				t.Errorf("%s: default_headers=false, UA не задан, а на провод ушёл %s", tc.name, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 8. HTTP/3: дубль accept-encoding, HEAD с Content-Encoding, утечка UDP.
// ---------------------------------------------------------------------------

func auditH3Server(t *testing.T, h stdhttp.Handler) string {
	t.Helper()
	cert, err := utls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Fatal(err)
	}
	ua, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp", ua)
	if err != nil {
		t.Fatal(err)
	}
	srv := &uh3.Server{
		Handler:   h,
		TLSConfig: &utls.Config{Certificates: []utls.Certificate{cert}},
	}
	go srv.Serve(udp)
	t.Cleanup(func() {
		srv.Close()
		udp.Close()
	})
	// Ждём, пока сервер запустит свой приёмный цикл: иначе он попадает
	// в счётчик горутин уже после замера «до» и выглядит утечкой клиента.
	for i := 0; i < 50 && countGoroutinesWith(h3ListenFn) == 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Sprintf("https://localhost:%d", udp.LocalAddr().(*net.UDPAddr).Port)
}

const h3ListenFn = "uquic.(*Transport).listen"

func countGoroutinesWith(substr string) int {
	buf := make([]byte, 4<<20)
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), substr)
}

func TestAudit_HTTP3(t *testing.T) {
	var accept atomic.Value
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("/ae", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		accept.Store(append([]string{}, r.Header.Values("Accept-Encoding")...))
		io.WriteString(w, "ok")
	})
	mux.HandleFunc("/head", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(200)
	})
	base := auditH3Server(t, mux)

	const listenFn = h3ListenFn
	before := countGoroutinesWith(listenFn)

	s := auditSession(t, Options{DefaultHeaders: true, HTTP3: true})
	resp, err := s.Do(&Request{Method: "GET", URL: base + "/ae"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("GET /ae: %d %s %q", resp.Status, resp.Proto, resp.Body)
	if got, _ := accept.Load().([]string); len(got) != 1 {
		t.Errorf("сервер получил accept-encoding %d раз: %q — транспорт h3 добавил свой "+
			"«gzip», не увидев строчного ключа профиля через Header.Get", len(got), got)
	} else {
		t.Logf("accept-encoding на сервере: %q", got)
	}

	if resp, err := s.Do(&Request{Method: "HEAD", URL: base + "/head"}); err != nil {
		t.Errorf("HEAD с Content-Encoding: gzip и пустым телом: %v", err)
	} else {
		t.Logf("HEAD: %d, тело %d байт", resp.Status, len(resp.Body))
	}

	s.Close()
	time.Sleep(300 * time.Millisecond)
	after := countGoroutinesWith(listenFn)
	t.Logf("горутин %s: до сессии %d, после Close %d", listenFn, before, after)
	if after > before {
		t.Errorf("UDP-транспорт из Dial не закрыт вместе с сессией: +%d слушающих горутин, "+
			"UDP-сокет утёк", after-before)
	}
}

// ---------------------------------------------------------------------------
// 9. Параллельные запросы под -race: пул, потоки, закрытие под нагрузкой.
//    Это не воспроизведение бага, а недостающее покрытие (AUDIT-QUESTIONS 2.2).
// ---------------------------------------------------------------------------

func TestAudit_ConcurrentRequests(t *testing.T) {
	body := bytes.Repeat([]byte("z"), 4096)
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Write(body)
	})
	for _, tc := range []struct {
		name      string
		h2, force bool
		closeMid  bool
	}{
		{"http1", false, true, false},
		{"http2", true, false, false},
		{"http1-close", false, true, true},
		{"http2-close", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, conns := auditServer(t, tc.h2, h)
			s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: tc.force})
			var wg sync.WaitGroup
			var okN, errN atomic.Int32
			for g := 0; g < 8; g++ {
				wg.Add(1)
				go func(g int) {
					defer wg.Done()
					for i := 0; i < 12; i++ {
						if i%3 == 0 {
							st, err := s.DoStream(&Request{Method: "GET", URL: auditURL(srv, "/")})
							if err != nil {
								errN.Add(1)
								continue
							}
							io.ReadFull(st, make([]byte, 100))
							st.Close()
							okN.Add(1)
							continue
						}
						resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
						if err != nil || len(resp.Body) != len(body) {
							errN.Add(1)
							continue
						}
						okN.Add(1)
					}
				}(g)
			}
			if tc.closeMid {
				go func() {
					time.Sleep(200 * time.Millisecond)
					s.Close()
				}()
			}
			wg.Wait()
			t.Logf("%s: ok=%d err=%d, соединений на сервере %d", tc.name, okN.Load(), errN.Load(), conns.Load())
			if !tc.closeMid && errN.Load() != 0 {
				t.Errorf("%s: %d ошибок без закрытия сессии", tc.name, errN.Load())
			}
		})
	}
}
