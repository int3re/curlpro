package client

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
)

// Cookie bookkeeping for export and import.
//
// The fhttp jar exposes nothing beyond the name-value pair for an address:
// no domain, no expiry, no flags. That is not enough to carry a session
// between runs, so a record of our own is kept here — from the same Set-Cookie
// headers that reach the jar. The jar stays the source of truth for sending:
// its domain and path matching is already written and tested.

// Cookie is a cookie in a form that can be saved and restored.
type Cookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
	// Expires is the expiry in epoch seconds. 0 means a session cookie:
	// a browser keeps it until it closes, we keep it until the session closes.
	Expires  int64  `json:"expires,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HTTPOnly bool   `json:"http_only,omitempty"`
	SameSite string `json:"same_site,omitempty"`
	// Created is when the cookie was received, epoch seconds. Chromium's
	// Lax+POST exception depends on it: a cookie without a SameSite
	// attribute still goes on a cross-site POST navigation while younger
	// than two minutes. 0 — an import that did not say — counts as old.
	Created int64 `json:"created,omitempty"`
	// HostOnly marks a cookie set without a Domain attribute: it goes to the
	// host that set it and to none of its subdomains (RFC 6265 5.3 step 6).
	// The export used to drop it, and a saved and reloaded jar sent such a
	// cookie to every subdomain — a different jar from the one saved.
	HostOnly bool `json:"host_only,omitempty"`
}

func cookieKey(domain, path, name string) string {
	return strings.ToLower(domain) + "\x00" + path + "\x00" + name
}

// CookieChange is one record a request changed: its key, whether the new
// one was host-only, and the record it replaced (nil when there was none).
// Undone in reverse order, a request's changes put the jar back exactly,
// touching nothing another request wrote meanwhile.
type CookieChange struct {
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Name     string  `json:"name"`
	HostOnly bool    `json:"host_only,omitempty"`
	Before   *Cookie `json:"before"`
}

// cookieLog collects one request's changes across its hops, preflights and
// retries; the copies of a Request share it.
type cookieLog struct {
	mu   sync.Mutex
	list []CookieChange
}

func (l *cookieLog) add(c CookieChange) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.list = append(l.list, c)
	l.mu.Unlock()
}

func (l *cookieLog) changes() []CookieChange {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]CookieChange(nil), l.list...)
}

// UndoCookies reverts changes a request logged, last first.
func (s *Session) UndoCookies(changes []CookieChange) error {
	jar := s.cookieJar()
	if jar == nil {
		return nil
	}
	for i := len(changes) - 1; i >= 0; i-- {
		ch := changes[i]
		if ch.Before != nil {
			if err := s.SetCookies([]Cookie{*ch.Before}); err != nil {
				return err
			}
			continue
		}
		// The record did not exist: remove what the request set. The jar
		// keys a host-only cookie apart from a domain one, so the deletion
		// takes the same form the cookie was set in.
		u := &url.URL{Scheme: "https", Host: ch.Domain, Path: ch.Path}
		gone := &http.Cookie{Name: ch.Name, Path: ch.Path, MaxAge: -1}
		if !ch.HostOnly {
			gone.Domain = ch.Domain
		}
		jar.SetCookies(u, []*http.Cookie{gone})
		u.Scheme = "http"
		jar.SetCookies(u, []*http.Cookie{gone})
		s.mu.Lock()
		delete(s.cookies, cookieKey(ch.Domain, ch.Path, ch.Name))
		s.mu.Unlock()
	}
	return nil
}

// recordCookies remembers the cookies from a response.
//
// The domain and path come from the cookie itself; when it has none they are
// derived from the request URL per RFC 6265: bare domain, directory as path.
func (s *Session) recordCookies(u *url.URL, cs []*http.Cookie, log *cookieLog) {
	if len(cs) == 0 {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cookies == nil {
		s.cookies = make(map[string]Cookie)
	}
	host := strings.ToLower(u.Hostname())
	for _, c := range cs {
		domain := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		if domain == "" {
			domain = host
		}
		// A Domain the request host is not inside is refused by the jar
		// (RFC 6265 5.3 step 6), and must be refused here too: evil.test
		// setting sid for bank.example used to overwrite bank's record, so
		// the export carried the forged value and bank's Strict cookie was
		// judged by the forger's SameSite=None.
		if host != domain && !strings.HasSuffix(host, "."+domain) {
			continue
		}
		path := c.Path
		if path == "" {
			path = defaultCookiePath(u.Path)
		}
		key := cookieKey(domain, path, c.Name)
		if log != nil {
			ch := CookieChange{Domain: domain, Path: path, Name: c.Name, HostOnly: c.Domain == ""}
			if prev, ok := s.cookies[key]; ok {
				prev := prev
				ch.Before = &prev
			}
			log.add(ch)
		}

		// MaxAge<0 and an expiry in the past mean deletion: that is how a server
		// clears a cookie, and it must not appear in the export.
		if c.MaxAge < 0 || (!c.Expires.IsZero() && c.Expires.Before(now)) {
			delete(s.cookies, key)
			continue
		}
		var expires int64
		switch {
		case c.MaxAge > 0:
			expires = now.Add(time.Duration(c.MaxAge) * time.Second).Unix()
		case !c.Expires.IsZero():
			expires = c.Expires.Unix()
		}
		s.cookies[key] = Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   domain,
			Path:     path,
			Expires:  expires,
			Secure:   c.Secure,
			HTTPOnly: c.HttpOnly,
			SameSite: sameSiteName(c.SameSite),
			Created:  now.Unix(),
			HostOnly: c.Domain == "",
		}
	}
}

// defaultCookiePath is the URL's directory, as RFC 6265, 5.1.4 requires.
func defaultCookiePath(p string) string {
	if !strings.HasPrefix(p, "/") {
		return "/"
	}
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func sameSiteName(v http.SameSite) string {
	switch v {
	case http.SameSiteLaxMode:
		return "lax"
	case http.SameSiteStrictMode:
		return "strict"
	case http.SameSiteNoneMode:
		return "none"
	default:
		return ""
	}
}

func sameSiteValue(name string) http.SameSite {
	switch strings.ToLower(name) {
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}

// Cookies returns the session cookies; expired ones are skipped.
//
// The order is stable — domain, path, name — so an export is reproducible
// and can be kept under version control.
func (s *Session) Cookies() []Cookie {
	now := time.Now().Unix()
	s.mu.Lock()
	out := make([]Cookie, 0, len(s.cookies))
	for _, c := range s.cookies {
		if c.Expires != 0 && c.Expires <= now {
			continue
		}
		out = append(out, c)
	}
	s.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// SetCookies loads cookies into the session.
//
// They go both into the jar and into the record: the jar handles sending, the
// record the next export. The domain is required: without it there is nobody to send to.
func (s *Session) SetCookies(cs []Cookie) error {
	if s.cookieJar() == nil {
		return fmt.Errorf("cookie jar is disabled for this session")
	}
	for _, c := range cs {
		if c.Name == "" || c.Domain == "" {
			return fmt.Errorf("cookie needs both a name and a domain: %+v", c)
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		scheme := "http"
		if c.Secure {
			scheme = "https"
		}
		u := &url.URL{Scheme: scheme, Host: strings.TrimPrefix(c.Domain, "."), Path: path}

		hc := &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     path,
			Domain:   c.Domain,
			Secure:   c.Secure,
			HttpOnly: c.HTTPOnly,
			SameSite: sameSiteValue(c.SameSite),
		}
		// The jar refuses a Domain attribute on an IP address (the older
		// net/http rule fhttp's copy keeps), and an imported cookie for
		// 127.0.0.1 was recorded but never sent. An IP cookie is host-only
		// by nature; setting it without the attribute says exactly that.
		if net.ParseIP(strings.TrimPrefix(c.Domain, ".")) != nil || c.HostOnly {
			hc.Domain = ""
		}
		if c.Expires != 0 {
			hc.Expires = time.Unix(c.Expires, 0)
		}
		s.cookieJar().SetCookies(u, []*http.Cookie{hc})

		s.mu.Lock()
		if s.cookies == nil {
			s.cookies = make(map[string]Cookie)
		}
		norm := c
		norm.Domain = strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		norm.Path = path
		s.cookies[cookieKey(norm.Domain, path, c.Name)] = norm
		s.mu.Unlock()
	}
	return nil
}

// ClearCookies forgets every cookie of the session.
//
// The jar is recreated whole: it cannot delete one by one, and clearing every
// cookie with an empty value would leave junk with foreign expiries inside.
func (s *Session) ClearCookies() error {
	if s.cookieJar() == nil {
		return nil
	}
	jar, err := newCookieJar()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.jar.Store(jar)
	s.cookies = nil
	s.mu.Unlock()
	return nil
}

// newCookieJar creates the jar. A function of its own because it is created in
// two places: when a session opens and when cookies are cleared.
func newCookieJar() (*cookiejar.Jar, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("cookie-jar: %w", err)
	}
	return jar, nil
}
