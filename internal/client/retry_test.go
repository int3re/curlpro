package client

import (
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bogdanfinn/fhttp/http2"
)

// Классификация «запрос заведомо не обрабатывался» повторяет canRetryError
// из net/http: непригодное соединение, GOAWAY для необработанного потока,
// REFUSED_STREAM. Остальные сетевые ошибки после отправки не различают
// «сервер не получил» и «обработал и не ответил».
func TestH2UnprocessedClassification(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{errors.New("http2: client conn not usable"), true},
		{errors.New("http2: Transport received Server's graceful shutdown GOAWAY"), true},
		{http2.StreamError{StreamID: 1, Code: http2.ErrCodeRefusedStream}, true},
		{http2.StreamError{StreamID: 1, Code: http2.ErrCodeProtocol}, false},
		{io.ErrUnexpectedEOF, false},
		{errors.New("read tcp: connection reset by peer"), false},
	}
	for _, tc := range cases {
		if got := h2Unprocessed(tc.err); got != tc.want {
			t.Errorf("%v: получено %v, ожидалось %v", tc.err, got, tc.want)
		}
	}
}

// POST, разрешённый в Methods, всё равно не повторяется после сетевого сбоя,
// если запрос мог дойти до сервера: соединение оборвано после отправки.
func TestPostNotRetriedAfterAmbiguousNetworkError(t *testing.T) {
	var hits atomic.Int32
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		n := hits.Add(1)
		io.ReadAll(r.Body)
		if n == 1 {
			// Обрыв без ответа: сервер «обработал», но клиент этого не знает.
			hj, _ := w.(stdhttp.Hijacker)
			c, _, _ := hj.Hijack()
			c.Close()
			return
		}
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true,
		Retry: &RetryPolicy{Attempts: 2, Backoff: 10 * time.Millisecond, Methods: []string{"POST", "GET"}}})

	_, err := s.Do(&Request{Method: "POST", URL: auditURL(srv, "/"), Body: []byte("order=1")})
	if err == nil {
		t.Fatal("ожидалась ошибка: POST после обрыва повторять нельзя")
	}
	if hits.Load() != 1 {
		t.Errorf("сервер получил POST %d раз — повтор мог создать второй заказ", hits.Load())
	}

	// GET при тех же условиях повторяется: метод идемпотентен.
	hits.Store(0)
	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
	if err != nil || resp.Status != 200 {
		t.Fatalf("GET: %v %v", resp, err)
	}
	if hits.Load() != 2 {
		t.Errorf("GET дошёл %d раз, ожидалось 2", hits.Load())
	}
}

// Отказ в соединении — запрос заведомо не обрабатывался: POST повторяется,
// если это разрешено.
func TestPostRetriedWhenConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // порт свободен: первая попытка получит отказ

	var hits atomic.Int32
	go func() {
		time.Sleep(150 * time.Millisecond)
		ln2, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		defer ln2.Close()
		srv := &stdhttp.Server{Handler: stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			hits.Add(1)
			io.WriteString(w, "ok")
		})}
		tl := tlsListener(t, ln2)
		_ = srv.Serve(tl)
	}()

	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true,
		Retry: &RetryPolicy{Attempts: 3, Backoff: 100 * time.Millisecond, Methods: []string{"POST"}}})
	_, port, _ := net.SplitHostPort(addr)
	resp, err := s.Do(&Request{Method: "POST", URL: "https://localhost:" + port + "/", Body: []byte("x")})
	if err != nil {
		t.Fatalf("POST после отказа в соединении не повторён: %v", err)
	}
	if resp.Status != 200 || hits.Load() != 1 {
		t.Errorf("статус %d, попаданий %d", resp.Status, hits.Load())
	}
}
