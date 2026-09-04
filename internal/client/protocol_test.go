package client

import (
	"io"
	stdhttp "net/http"
	"strings"
	"testing"
)

// Протокол на запрос.
//
// Стенд httptest даёт ровно два варианта ALPN: с EnableHTTP2 сервер
// объявляет h2, без него — только http/1.1. Этого хватает, чтобы проверить
// и принуждение, и отказ, когда сервер согласовал не то.

func okHandler() stdhttp.Handler {
	return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "ok")
	})
}

// Запрос обязан уйти по HTTP/1.1, хотя сервер предлагает h2 и сессия
// его не запрещает.
func TestRequestProtocolForcesHTTP1(t *testing.T) {
	srv, _ := auditServer(t, true, okHandler())
	s := auditSession(t, Options{DefaultHeaders: true})

	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/"), Protocol: ProtoHTTP1})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Proto != "HTTP/1.1" {
		t.Errorf("согласован %s, ожидался HTTP/1.1", resp.Proto)
	}
}

// Обратное направление: сессия просит HTTP/1.1, запрос — h2.
func TestRequestProtocolOverridesSessionForceHTTP1(t *testing.T) {
	srv, _ := auditServer(t, true, okHandler())
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})

	plain, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Proto != "HTTP/1.1" {
		t.Fatalf("без указания согласован %s, ожидался HTTP/1.1", plain.Proto)
	}

	forced, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/"), Protocol: ProtoH2})
	if err != nil {
		t.Fatal(err)
	}
	if forced.Proto != "HTTP/2.0" {
		t.Errorf("с protocol=h2 согласован %s, ожидался HTTP/2.0", forced.Proto)
	}
}

// Два протокола в одной сессии живут на разных соединениях: признак входит
// в ключ пула, иначе запрос по h2 достался бы соединению http/1.1.
func TestBothProtocolsInOneSession(t *testing.T) {
	srv, conns := auditServer(t, true, okHandler())
	s := auditSession(t, Options{DefaultHeaders: true})

	for _, tc := range []struct{ proto, want string }{
		{ProtoHTTP1, "HTTP/1.1"},
		{ProtoH2, "HTTP/2.0"},
		{ProtoHTTP1, "HTTP/1.1"},
		{ProtoH2, "HTTP/2.0"},
	} {
		resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/"), Protocol: tc.proto})
		if err != nil {
			t.Fatalf("protocol=%s: %v", tc.proto, err)
		}
		if resp.Proto != tc.want {
			t.Fatalf("protocol=%s: согласован %s, ожидался %s", tc.proto, resp.Proto, tc.want)
		}
	}
	// По одному соединению на протокол, а не по одному на запрос.
	if got := conns.Load(); got != 2 {
		t.Errorf("сервер принял %d соединений, ожидалось 2", got)
	}
}

// Сервер без h2: запрос, потребовавший h2, обязан упасть внятно, а не
// молча уехать по HTTP/1.1.
func TestRequestProtocolH2FailsOnHTTP1Server(t *testing.T) {
	srv, _ := auditServer(t, false, okHandler())
	s := auditSession(t, Options{DefaultHeaders: true})

	_, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/"), Protocol: ProtoH2})
	if err == nil {
		t.Fatal("ошибки нет, а h2 сервер не предлагает")
	}
	if !strings.Contains(err.Error(), "http/1.1") {
		t.Errorf("ошибка не называет согласованный протокол: %v", err)
	}
}

// Такую ошибку повторять нечего: со второй попытки сервер согласует то же.
// Считаем соединения — три лишних рукопожатия были бы видны здесь.
func TestForcedProtocolErrorIsNotRetried(t *testing.T) {
	srv, conns := auditServer(t, false, okHandler())
	s := auditSession(t, Options{
		DefaultHeaders: true,
		Retry:          &RetryPolicy{Attempts: 3},
	})

	if _, err := s.Do(&Request{
		Method: "GET", URL: auditURL(srv, "/"), Protocol: ProtoH2,
	}); err == nil {
		t.Fatal("ошибки нет")
	}
	if got := conns.Load(); got != 1 {
		t.Errorf("сервер принял %d соединений, ожидалось одно: повторов быть не должно", got)
	}
}

// Профиль без секции http3: требование h3 обязано вскрыться ошибкой,
// а не тихим уходом по TCP.
func TestRequestProtocolH3NeedsProfileSection(t *testing.T) {
	srv, conns := auditServer(t, true, okHandler())
	s, err := New(auditProfile(t, "chrome-150-macos"), Options{
		DefaultHeaders: true, InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, err = s.Do(&Request{Method: "GET", URL: auditURL(srv, "/"), Protocol: ProtoH3})
	if err == nil {
		t.Fatal("ошибки нет, а профиль не описывает http3")
	}
	if !strings.Contains(err.Error(), "http3") {
		t.Errorf("ошибка не объясняет причину: %v", err)
	}
	if got := conns.Load(); got != 0 {
		t.Errorf("сервер принял %d соединений: до сети дело доходить не должно", got)
	}
}

// Неизвестное значение отвергается до сети.
func TestUnknownProtocolIsRejected(t *testing.T) {
	s := auditSession(t, Options{DefaultHeaders: true})
	_, err := s.Do(&Request{Method: "GET", URL: "https://localhost/", Protocol: "spdy"})
	if err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("ожидалась ошибка про protocol, получено: %v", err)
	}
}

// Заголовки профиля включаются и выключаются на запрос — в обе стороны.
func TestRequestDefaultHeadersBothWays(t *testing.T) {
	seen := make(chan stdhttp.Header, 4)
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		seen <- r.Header.Clone()
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, true, h)

	// Сессия без заголовков профиля: запрос возвращает их обратно.
	off := auditSession(t, Options{DefaultHeaders: false})
	if _, err := off.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
		t.Fatal(err)
	}
	if got := (<-seen).Get("sec-fetch-site"); got != "" {
		t.Errorf("сессия отключила заголовки профиля, а sec-fetch-site пришёл: %q", got)
	}

	on := true
	if _, err := off.Do(&Request{
		Method: "GET", URL: auditURL(srv, "/"), DefaultHeaders: &on,
	}); err != nil {
		t.Fatal(err)
	}
	if got := (<-seen).Get("sec-fetch-site"); got == "" {
		t.Error("запрос вернул заголовки профиля, а sec-fetch-site не пришёл")
	}

	// И наоборот: сессия с заголовками, запрос без них.
	no := false
	with := auditSession(t, Options{DefaultHeaders: true})
	if _, err := with.Do(&Request{
		Method: "GET", URL: auditURL(srv, "/"), DefaultHeaders: &no,
	}); err != nil {
		t.Fatal(err)
	}
	if got := (<-seen).Get("sec-fetch-site"); got != "" {
		t.Errorf("запрос отключил заголовки профиля, а sec-fetch-site пришёл: %q", got)
	}
}
