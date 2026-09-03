package client

import (
	"bytes"
	"strings"
	"testing"

	http "github.com/bogdanfinn/fhttp"
)

// Сборка заголовков может быть верной, а на провод уйти другое: часть
// заголовков добавляет сам транспорт, уже после applyHeaders. Здесь
// проверяется результат целиком — через настоящий Request.Write.
func wireNames(t *testing.T, s *Session, r *Request, body string) []string {
	t.Helper()

	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	var req *http.Request
	var err error
	if rdr != nil {
		req, err = http.NewRequest(r.Method, r.URL, rdr)
	} else {
		req, err = http.NewRequest(r.Method, r.URL, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	s.applyHeaders(req, r, req.URL, true)

	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, line := range strings.Split(buf.String(), "\r\n")[1:] {
		if line == "" {
			break
		}
		names = append(names, strings.ToLower(strings.SplitN(line, ":", 2)[0]))
	}
	return names
}

func wireSession(t *testing.T) *Session {
	t.Helper()
	h1 := profileHTTP1()
	return testSession(t, chromeLike(), h1)
}

// Content-Length добавляет транспорт, уже после сборки. Место под него
// занимается заранее: иначе он уходит в самый хвост, тогда как браузер шлёт
// его сразу за Connection.
func TestContentLengthTakesItsSlot(t *testing.T) {
	s := wireSession(t)
	r := &Request{Method: "POST", URL: "https://example.com/x"}

	got := wireNames(t, s, r, `{"a":1}`)

	if len(got) < 3 || got[2] != "content-length" {
		t.Errorf("Content-Length не занял своё место: %v", got)
	}
}

// Без тела заголовка нет вовсе, а место под него не должно оставлять следа.
func TestNoContentLengthWithoutBody(t *testing.T) {
	s := wireSession(t)

	got := wireNames(t, s, &Request{Method: "GET", URL: "https://example.com/x"}, "")

	for _, n := range got {
		if n == "content-length" {
			t.Errorf("пустое место превратилось в заголовок: %v", got)
		}
	}
}

func TestCustomHeaderReachesWireBeforeAnchor(t *testing.T) {
	s := wireSession(t)
	s.headers.Set("X-Api-Key", "secret")

	got := wireNames(t, s, &Request{Method: "GET", URL: "https://example.com/x"}, "")

	at, anchor := indexOf(got, "x-api-key"), indexOf(got, "accept-encoding")
	if at < 0 {
		t.Fatalf("заголовок не дошёл до провода: %v", got)
	}
	if at > anchor {
		t.Errorf("кастомный заголовок после якоря: %v", got)
	}
}
