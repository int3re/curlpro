package client

import (
	"bufio"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// authProxy — прокси, требующий Basic-авторизацию.
//
// keepAlive выбирает поведение после 407: держать соединение (как делает
// большинство) или закрыть его — тогда клиент обязан переоткрыть сокет.
type authProxy struct {
	ln        net.Listener
	keepAlive bool
	target    string // куда вести туннель

	mu       sync.Mutex
	connects []*stdhttp.Request // все полученные CONNECT
	accepted atomic.Int32
}

func newAuthProxy(t *testing.T, target string, keepAlive bool) *authProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &authProxy{ln: ln, keepAlive: keepAlive, target: target}
	t.Cleanup(func() { ln.Close() })
	go p.serve()
	return p
}

func (p *authProxy) addr() string { return p.ln.Addr().String() }

func (p *authProxy) requests() []*stdhttp.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*stdhttp.Request(nil), p.connects...)
}

func (p *authProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.accepted.Add(1)
		go p.handle(c)
	}
}

func (p *authProxy) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		req, err := stdhttp.ReadRequest(br)
		if err != nil {
			return
		}
		p.mu.Lock()
		p.connects = append(p.connects, req)
		p.mu.Unlock()

		if req.Header.Get("Proxy-Authorization") == "" {
			body := "нужна авторизация"
			hdr := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
				"Proxy-Authenticate: Basic realm=\"test\"\r\n" +
				"Content-Length: " + itoa(len(body)) + "\r\n"
			if p.keepAlive {
				hdr += "Proxy-Connection: keep-alive\r\n\r\n"
			} else {
				hdr += "Proxy-Connection: close\r\nConnection: close\r\n\r\n"
			}
			io.WriteString(c, hdr+body)
			if !p.keepAlive {
				return
			}
			continue
		}

		up, err := net.Dial("tcp", p.target)
		if err != nil {
			io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { _, _ = io.Copy(up, br); up.Close() }()
		_, _ = io.Copy(c, up)
		return
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// Chrome шлёт CONNECT без учётных данных и добавляет их только после 407.
// Прокси, ведущий журнал, видит у нас ту же пару запросов.
func TestConnectSendsCredentialsOnlyAfterChallenge(t *testing.T) {
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	target := strings.TrimPrefix(srv.URL, "https://")

	for _, tc := range []struct {
		name      string
		keepAlive bool
		wantConns int32
	}{
		{"прокси держит соединение", true, 1},
		{"прокси закрывает после 407", false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newAuthProxy(t, target, tc.keepAlive)
			s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true,
				Proxy: "http://user:pw@" + p.addr(), Timeout: 10 * time.Second})

			resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
			if err != nil {
				t.Fatalf("запрос через прокси: %v", err)
			}
			if resp.Status != 200 {
				t.Fatalf("статус %d", resp.Status)
			}

			reqs := p.requests()
			if len(reqs) != 2 {
				t.Fatalf("прокси получил %d CONNECT, ожидалось 2", len(reqs))
			}
			if got := reqs[0].Header.Get("Proxy-Authorization"); got != "" {
				t.Errorf("первый CONNECT ушёл с Proxy-Authorization %q — браузер так не делает", got)
			}
			if got := reqs[1].Header.Get("Proxy-Authorization"); !strings.HasPrefix(got, "Basic ") {
				t.Errorf("второй CONNECT без учётных данных: %q", got)
			}
			if n := p.accepted.Load(); n != tc.wantConns {
				t.Errorf("прокси принял %d соединений, ожидалось %d", n, tc.wantConns)
			}
		})
	}
}

// Прокси требует авторизацию, а её нет: ошибка должна называть причину,
// а не «прокси вернул 407 Proxy Authentication Required».
func TestConnectWithoutCredentialsReportsChallenge(t *testing.T) {
	p := newAuthProxy(t, "127.0.0.1:1", true)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true,
		Proxy: "http://" + p.addr(), Timeout: 5 * time.Second})

	_, err := s.Do(&Request{Method: "GET", URL: "https://example.com/"})
	if err == nil {
		t.Fatal("ожидалась ошибка авторизации")
	}
	if !strings.Contains(err.Error(), "requires authentication") {
		t.Errorf("ошибка не называет причину: %v", err)
	}
}
