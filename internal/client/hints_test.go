package client

import (
	"io"
	stdhttp "net/http"
	"strings"
	"testing"
	"time"
)

// High-entropy hints do not go out until the site asks for them: a browser
// sends them only after an Accept-CH in a response.
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
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if len(got) < 2 {
		t.Fatalf("the server received %d requests", len(got))
	}
	if got[0] != "" {
		t.Errorf("the first request carried sec-ch-ua-model %q — the site had not asked yet", got[0])
	}
	if got[1] != `"Pixel 8"` {
		t.Errorf("second request: sec-ch-ua-model = %q, expected \"Pixel 8\"", got[1])
	}
}

// Critical-CH makes the request repeat at once rather than from the next one.
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
		t.Fatalf("the server received %d requests, expected 2 (a Critical-CH repeat)", len(models))
	}
	if models[0] != "" || models[1] != `"Pixel 7"` {
		t.Errorf("got %q and %q, expected empty and \"Pixel 7\"", models[0], models[1])
	}
}

// The device is chosen per session and does not change between requests.
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
		t.Fatalf("the hint went out %d times", len(seen))
	}
	for _, m := range seen[1:] {
		if m != seen[0] {
			t.Errorf("the device changed inside a session: %q against %q", m, seen[0])
		}
	}
}

// The order with hints is a separate template: Chromium rebuilds the cluster.
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
	// The order itself is checked against the raw server in Python; what matters
	// here is that the hints template was chosen and the headers assembled cleanly.
	tpl := s.template(&Request{Method: "GET", URL: auditURL(srv, "/")})
	names := strings.Join(tpl.names(), " ")
	for _, want := range []string{"sec-ch-ua-model", "sec-ch-ua-platform-version", "sec-ch-ua-form-factors"} {
		if !strings.Contains(names, want) {
			t.Errorf("the template has no %s: %s", want, names)
		}
	}
}

// auditSessionProfile is a session on an arbitrary profile from the directory.
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
