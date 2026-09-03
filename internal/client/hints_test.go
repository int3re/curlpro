package client

import (
	"io"
	stdhttp "net/http"
	"strings"
	"testing"
	"time"
)

// Подсказки высокой энтропии не уходят, пока сайт их не запросил: браузер
// шлёт их только после Accept-CH в ответе.
func TestHintsSentOnlyAfterAcceptCH(t *testing.T) {
	var got []string
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		got = append(got, r.Header.Get("Sec-CH-UA-Model"))
		w.Header().Set("Accept-CH", "sec-ch-ua-model, sec-ch-ua-platform-version")
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	s := auditSessionProfile(t, "chrome-152-android", Options{
		DefaultHeaders: true, ForceHTTP1: true, Device: "Pixel 8",
	})

	for i := 0; i < 2; i++ {
		if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
			t.Fatalf("запрос %d: %v", i, err)
		}
	}
	if len(got) < 2 {
		t.Fatalf("сервер получил %d запросов", len(got))
	}
	if got[0] != "" {
		t.Errorf("первый запрос ушёл с sec-ch-ua-model %q — сайт его ещё не просил", got[0])
	}
	if got[1] != `"Pixel 8"` {
		t.Errorf("второй запрос: sec-ch-ua-model = %q, ожидалось \"Pixel 8\"", got[1])
	}
}

// Critical-CH заставляет повторить запрос сразу, а не со следующего.
func TestCriticalCHRetriesImmediately(t *testing.T) {
	var models []string
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		models = append(models, r.Header.Get("Sec-CH-UA-Model"))
		w.Header().Set("Accept-CH", "sec-ch-ua-model")
		w.Header().Set("Critical-CH", "sec-ch-ua-model")
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	s := auditSessionProfile(t, "chrome-152-android", Options{
		DefaultHeaders: true, ForceHTTP1: true, Device: "Pixel 7",
	})

	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
		t.Fatal(err)
	}
	if len(models) != 2 {
		t.Fatalf("сервер получил %d запросов, ожидалось 2 (повтор по Critical-CH)", len(models))
	}
	if models[0] != "" || models[1] != `"Pixel 7"` {
		t.Errorf("получено %q и %q, ожидалось пусто и \"Pixel 7\"", models[0], models[1])
	}
}

// Устройство выбирается на сессию и не меняется между запросами.
func TestDeviceIsStableWithinSession(t *testing.T) {
	var seen []string
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if m := r.Header.Get("Sec-CH-UA-Model"); m != "" {
			seen = append(seen, m)
		}
		w.Header().Set("Accept-CH", "sec-ch-ua-model")
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	s := auditSessionProfile(t, "chrome-152-android", Options{
		DefaultHeaders: true, ForceHTTP1: true, Device: "random",
	})
	for i := 0; i < 4; i++ {
		if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) < 3 {
		t.Fatalf("подсказка ушла %d раз", len(seen))
	}
	for _, m := range seen[1:] {
		if m != seen[0] {
			t.Errorf("устройство сменилось внутри сессии: %q против %q", m, seen[0])
		}
	}
}

// Порядок с подсказками — отдельный шаблон: Chromium перестраивает кластер.
func TestHintOrderFollowsMeasuredTemplate(t *testing.T) {
	var order []string
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.Header.Get("Sec-CH-UA-Model") != "" {
			order = nil
			for _, name := range r.Header[stdhttp.CanonicalHeaderKey("X-Wire-Order")] {
				order = append(order, name)
			}
		}
		w.Header().Set("Accept-CH", "sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-form-factors, "+
			"sec-ch-ua-full-version, sec-ch-ua-full-version-list, sec-ch-ua-model, "+
			"sec-ch-ua-platform-version, sec-ch-ua-wow64")
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	s := auditSessionProfile(t, "chrome-152-android", Options{
		DefaultHeaders: true, ForceHTTP1: true, Device: "Pixel 7",
	})
	for i := 0; i < 2; i++ {
		if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
			t.Fatal(err)
		}
	}
	// Сам порядок проверяется на сыром сервере в Python; здесь важно, что
	// шаблон подсказок вообще выбран и заголовки собрались без ошибок.
	tpl := s.template(&Request{Method: "GET", URL: auditURL(srv, "/")})
	names := strings.Join(tpl.names(), " ")
	for _, want := range []string{"sec-ch-ua-model", "sec-ch-ua-platform-version", "sec-ch-ua-form-factors"} {
		if !strings.Contains(names, want) {
			t.Errorf("в шаблоне нет %s: %s", want, names)
		}
	}
}

// auditSessionProfile — сессия на произвольном профиле из каталога.
func auditSessionProfile(t *testing.T, name string, opts Options) *Session {
	t.Helper()
	opts.InsecureSkipVerify = true
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	s, err := New(auditProfile(t, name), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}
