package client

import (
	"io"
	stdhttp "net/http"
	"strings"
	"testing"
)

// Соединение между запросами не пересоздаётся: пять последовательных запросов
// должны уложиться в одно TCP-соединение — и по HTTP/1.1, и по HTTP/2.
func TestConnectionReusedBetweenRequests(t *testing.T) {
	for _, tc := range []struct {
		name      string
		h2, force bool
	}{
		{"http1", false, true},
		{"http2", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				io.WriteString(w, "ok")
			})
			srv, conns := auditServer(t, tc.h2, h)
			s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: tc.force})
			for i := 0; i < 5; i++ {
				if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
					t.Fatalf("запрос %d: %v", i, err)
				}
			}
			if got := conns.Load(); got != 1 {
				t.Errorf("сервер принял %d соединений на 5 запросов, ожидалось 1", got)
			}
		})
	}
}

// keep_alive=False: соединение не переиспользуется, каждый запрос начинается
// с рукопожатия. Проверяется на обоих транспортах — для HTTP/2 «не
// переиспользовать» означает не мультиплексировать в уже открытое.
func TestKeepAliveDisabledOpensConnectionPerRequest(t *testing.T) {
	for _, tc := range []struct {
		name      string
		h2, force bool
	}{
		{"http1", false, true},
		{"http2", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				io.WriteString(w, "ok")
			})
			srv, conns := auditServer(t, tc.h2, h)
			s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: tc.force,
				DisableKeepAlive: true})
			for i := 0; i < 3; i++ {
				if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
					t.Fatalf("запрос %d: %v", i, err)
				}
			}
			if got := conns.Load(); got != 3 {
				t.Errorf("сервер принял %d соединений на 3 запроса, ожидалось 3", got)
			}
			// Пул при этом остаётся пустым: выключенный keep-alive не должен
			// копить сокеты, которые всё равно никому не достанутся.
			s.mu.Lock()
			n := s.totalLocked()
			s.mu.Unlock()
			if n != 0 {
				t.Errorf("в пуле осталось %d соединений, ожидалось 0", n)
			}
		})
	}
}

// Заголовок Connection берётся из профиля и при выключенном keep-alive:
// «Connection: close» браузер не шлёт, и он выдал бы клиента.
func TestKeepAliveDisabledKeepsProfileConnectionHeader(t *testing.T) {
	got := make(chan string, 1)
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		select {
		case got <- r.Header.Get("Connection"):
		default:
		}
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true, DisableKeepAlive: true})
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
		t.Fatal(err)
	}
	if v := <-got; !strings.EqualFold(v, "keep-alive") {
		t.Errorf("Connection: %q, ожидалось keep-alive из профиля", v)
	}
}
