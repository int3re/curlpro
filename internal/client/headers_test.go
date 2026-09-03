package client

import (
	"net/url"
	"strings"
	"testing"

	"github.com/curlpro/curlpro/internal/profile"
)

// Порядок и регистр заголовков — часть отпечатка наравне с набором, но до сих
// пор проверялись только через сеть, на живом стенде. Здесь проверяется сама
// сборка: она общая для HTTP/1.1, HTTP/2 и HTTP/3, и расхождение между путями
// уже приводило к тому, что HTTP/3 молча терял SuppressHeaders и слот cookie.

// testSession собирает сессию в обход New: тому нужна валидная TLS-спека,
// а здесь проверяются только заголовки.
func testSession(t *testing.T, headers profile.HeadersSpec, h1 profile.HTTP1Spec) *Session {
	t.Helper()
	return &Session{
		profile: &profile.Profile{Name: "test", Headers: headers, HTTP1: h1},
		opts:    Options{DefaultHeaders: true},
		headers: newSessionHeaders(),
	}
}

func chromeLike() profile.HeadersSpec {
	return profile.HeadersSpec{
		UserAgent:    "Mozilla/5.0",
		CustomAnchor: "accept-encoding",
		Order: []profile.HeaderPair{
			{Key: "sec-ch-ua", Value: `"Chromium";v="141"`},
			// Пустое значение — подстановка из UserAgent с сохранением позиции.
			{Key: "user-agent"},
			{Key: "accept", Value: "text/html"},
			{Key: "accept-encoding", Value: "gzip, deflate, br, zstd"},
			{Key: "accept-language", Value: "en-US,en;q=0.9"},
			// Пустой слот: задаёт позицию, значение приходит из jar.
			{Key: "cookie"},
			{Key: "priority", Value: "u=0, i"},
		},
	}
}

// profileHTTP1 — порядок HTTP/1.1 с местом под Content-Length там, где его
// шлёт Chrome: сразу за Connection.
func profileHTTP1() profile.HTTP1Spec {
	return profile.HTTP1Spec{
		Connection: "keep-alive",
		Order: []string{
			"Host", "Connection", "Content-Length", "sec-ch-ua", "User-Agent",
			"Accept", "Accept-Encoding", "Accept-Language", "Cookie", "priority",
		},
	}
}

func names(built []headerKV) []string {
	out := make([]string, len(built))
	for i, h := range built {
		out[i] = strings.ToLower(h.Key)
	}
	return out
}

func indexOf(list []string, name string) int {
	for i, n := range list {
		if n == name {
			return i
		}
	}
	return -1
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("разбор %q: %v", raw, err)
	}
	return u
}

func TestCustomHeaderGoesBeforeAnchor(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})
	s.headers.Set("X-Api-Key", "secret")

	got := names(s.buildHeaders(&Request{}, mustURL(t, "https://example.com/"), "example.com", nil))

	at := indexOf(got, "x-api-key")
	if at < 0 {
		t.Fatalf("заголовок сессии потерян: %v", got)
	}
	// Служебный хвост браузер дописывает последним, поэтому заголовок после
	// него — заметная аномалия.
	if at > indexOf(got, "accept-encoding") {
		t.Errorf("кастомный заголовок после якоря: %v", got)
	}
}

func TestProfileOverrideKeepsPosition(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})
	u := mustURL(t, "https://example.com/")

	before := names(s.buildHeaders(&Request{}, u, "example.com", nil))
	s.headers.Set("User-Agent", "custom/1.0")
	built := s.buildHeaders(&Request{}, u, "example.com", nil)

	if got := names(built); indexOf(got, "user-agent") != indexOf(before, "user-agent") {
		t.Errorf("переопределение сдвинуло заголовок: %v -> %v", before, got)
	}
	for _, h := range built {
		if strings.EqualFold(h.Key, "user-agent") && h.Value != "custom/1.0" {
			t.Errorf("значение не применилось: %q", h.Value)
		}
	}
}

// Профиль пишет user-agent, пользователь — User-Agent. Пока ключи хранились
// в map, получалось два заголовка при одном имени в порядке.
func TestDifferentCaseIsOneHeader(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})
	s.headers.Set("USER-AGENT", "custom/1.0")

	got := names(s.buildHeaders(&Request{}, mustURL(t, "https://example.com/"), "example.com", nil))

	n := 0
	for _, name := range got {
		if name == "user-agent" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("user-agent встречается %d раз: %v", n, got)
	}
}

func TestSuppressedHeaderIsRemoved(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})
	r := &Request{SuppressHeaders: []string{"Accept-Language"}}

	got := names(s.buildHeaders(r, mustURL(t, "https://example.com/"), "example.com", nil))

	if indexOf(got, "accept-language") >= 0 {
		t.Errorf("погашенный заголовок остался: %v", got)
	}
}

// Пустой слот cookie в профиле задаёт позицию, а не значение: без jar он
// обязан исчезнуть, иначе на провод уйдёт пустой заголовок.
func TestEmptyCookieSlotDisappears(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})

	got := names(s.buildHeaders(&Request{}, mustURL(t, "https://example.com/"), "example.com", nil))

	if indexOf(got, "cookie") >= 0 {
		t.Errorf("пустой слот попал в запрос: %v", got)
	}
}

func TestHTTP1AddsHostAndConnection(t *testing.T) {
	h1 := profile.HTTP1Spec{
		Order:      []string{"Host", "Connection", "User-Agent", "Accept"},
		Connection: "keep-alive",
	}
	s := testSession(t, chromeLike(), h1)

	built := s.buildHeaders(&Request{}, mustURL(t, "https://example.com/"), "example.com", h1.Order)
	got := names(built)

	if got[0] != "host" {
		t.Errorf("Host обязан идти первым: %v", got)
	}
	if indexOf(got, "connection") != 1 {
		t.Errorf("Connection обязан идти вторым: %v", got)
	}
	// Регистр в HTTP/1.1 произволен, и браузеры им пользуются: профиль задаёт
	// его явно, поэтому на провод должен уйти Host, а не host.
	for _, h := range built {
		if strings.EqualFold(h.Key, "host") && h.Key != "Host" {
			t.Errorf("регистр профиля потерян: %q", h.Key)
		}
	}
}

// В HTTP/3 нет ни Host, ни Connection: они запрещены, а авторитет передаётся
// псевдо-заголовком :authority.
func TestHTTP3OmitsHostAndConnection(t *testing.T) {
	h1 := profile.HTTP1Spec{Order: []string{"Host", "Connection"}, Connection: "keep-alive"}
	s := testSession(t, chromeLike(), h1)

	got := names(s.buildHeaders(&Request{}, mustURL(t, "https://example.com/"), "example.com", nil))

	if indexOf(got, "host") >= 0 || indexOf(got, "connection") >= 0 {
		t.Errorf("HTTP/3 получил заголовки HTTP/1.1: %v", got)
	}
}

// Content-Length транспорт добавляет сам, уже после сборки. Место под него
// занимается заранее, иначе он уходит в хвост, а браузер шлёт его сразу
// за Connection.
func TestWireOrderKeepsSlotForAbsentHeader(t *testing.T) {
	built := []headerKV{{Key: "Host", Value: "example.com"},
		{Key: "Connection", Value: "keep-alive"}, {Key: "Accept", Value: "*/*"}}
	want := []string{"Host", "Connection", "Content-Length", "Accept"}

	got := wireOrder(built, want, "accept-encoding")

	if indexOf(got, "content-length") != 2 {
		t.Errorf("место под Content-Length не занято: %v", got)
	}
}

func TestWireOrderPlacesCustomAtAnchor(t *testing.T) {
	built := []headerKV{{Key: "Accept", Value: "*/*"},
		{Key: "X-Api-Key", Value: "secret"}, {Key: "Accept-Encoding", Value: "gzip"}}
	want := []string{"accept", "accept-encoding", "priority"}

	got := wireOrder(built, want, "accept-encoding")

	if indexOf(got, "x-api-key") != indexOf(got, "accept-encoding")-1 {
		t.Errorf("кастомный заголовок не встал перед якорем: %v", got)
	}
}

func TestRequestHeadersWinOverSession(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})
	s.headers.Set("X-Trace", "session")
	r := &Request{Headers: map[string]string{"X-Trace": "request"}}

	built := s.buildHeaders(r, mustURL(t, "https://example.com/"), "example.com", nil)

	for _, h := range built {
		if strings.EqualFold(h.Key, "x-trace") && h.Value != "request" {
			t.Errorf("заголовок запроса не перебил сессионный: %q", h.Value)
		}
	}
}

func TestNoDefaultHeadersDropsProfile(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})
	s.headers.Set("X-Only", "1")

	got := names(s.buildHeaders(&Request{NoDefaultHeaders: true},
		mustURL(t, "https://example.com/"), "example.com", nil))

	if len(got) != 1 || got[0] != "x-only" {
		t.Errorf("профильные заголовки не отключились: %v", got)
	}
}

// Значение заголовка может зависеть от метода.
//
// Замер Яндекс.Браузера 26.8 на Pixel 7: sdch в Accept-Encoding уходит на GET,
// HEAD, DELETE и PUT, но не на POST — даже с пустым телом. Правило описано
// в профиле данными; код о самом sdch ничего не знает.
func TestHeaderValueDependsOnMethod(t *testing.T) {
	h := chromeLike()
	for i := range h.Order {
		if h.Order[i].Key == "accept-encoding" {
			h.Order[i].Value = "gzip, deflate, br, zstd, sdch"
			h.Order[i].ValueByMethod = map[string]string{"post": "gzip, deflate, br, zstd"}
		}
	}
	s := testSession(t, h, profile.HTTP1Spec{})
	u, _ := url.Parse("https://example.com/")

	for _, tc := range []struct{ method, want string }{
		{"GET", "gzip, deflate, br, zstd, sdch"},
		{"DELETE", "gzip, deflate, br, zstd, sdch"},
		{"PUT", "gzip, deflate, br, zstd, sdch"},
		// Регистр метода в профиле произвольный: сверка идёт без учёта регистра.
		{"POST", "gzip, deflate, br, zstd"},
	} {
		got := ""
		for _, kv := range s.buildHeaders(&Request{Method: tc.method, URL: u.String()}, u, u.Host, nil) {
			if strings.EqualFold(kv.Key, "accept-encoding") {
				got = kv.Value
			}
		}
		if got != tc.want {
			t.Errorf("%s: accept-encoding = %q, ожидалось %q", tc.method, got, tc.want)
		}
	}
}
