package client

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
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
}

func cookieKey(domain, path, name string) string {
	return strings.ToLower(domain) + "\x00" + path + "\x00" + name
}

// recordCookies remembers the cookies from a response.
//
// The domain and path come from the cookie itself; when it has none they are
// derived from the request URL per RFC 6265: bare domain, directory as path.
func (s *Session) recordCookies(u *url.URL, cs []*http.Cookie) {
	if len(cs) == 0 {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cookies == nil {
		s.cookies = make(map[string]Cookie)
	}
	for _, c := range cs {
		domain := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		if domain == "" {
			domain = strings.ToLower(u.Hostname())
		}
		path := c.Path
		if path == "" {
			path = defaultCookiePath(u.Path)
		}
		key := cookieKey(domain, path, c.Name)

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
	if s.jar == nil {
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
		if c.Expires != 0 {
			hc.Expires = time.Unix(c.Expires, 0)
		}
		s.jar.SetCookies(u, []*http.Cookie{hc})

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
	if s.jar == nil {
		return nil
	}
	jar, err := newCookieJar()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.jar = jar
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
