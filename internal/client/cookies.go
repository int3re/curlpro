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

// Учёт кук для выгрузки и загрузки.
//
// Банка fhttp наружу не отдаёт ничего, кроме пары «имя-значение» для адреса:
// ни домена, ни срока, ни флагов. Для сохранения сессии между запусками этого
// мало, поэтому здесь ведётся свой учёт — по тем же заголовкам Set-Cookie,
// которые уходят в банку. Банка остаётся источником истины для отправки:
// сопоставление доменов и путей у неё уже написано и проверено.

// Cookie — кука в том виде, в каком её можно сохранить и вернуть.
type Cookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
	// Expires — момент истечения в секундах эпохи. 0 означает сеансовую куку:
	// браузер держит её до закрытия, у нас — до закрытия сессии.
	Expires  int64  `json:"expires,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HTTPOnly bool   `json:"http_only,omitempty"`
	SameSite string `json:"same_site,omitempty"`
}

func cookieKey(domain, path, name string) string {
	return strings.ToLower(domain) + "\x00" + path + "\x00" + name
}

// recordCookies запоминает куки из ответа.
//
// Домен и путь берутся из самой куки, а если их нет — выводятся из адреса
// запроса по RFC 6265: домен без ведущей точки, путь — каталог адреса.
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

		// MaxAge<0 и прошедший срок — удаление: сервер так гасит куку,
		// и в выгрузке её быть не должно.
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

// defaultCookiePath — каталог адреса, как того требует RFC 6265, 5.1.4.
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

// Cookies отдаёт куки сессии; просроченные пропускаются.
//
// Порядок устойчив — домен, путь, имя, — чтобы выгрузка была
// воспроизводимой и её можно было хранить в системе контроля версий.
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

// SetCookies загружает куки в сессию.
//
// Кладутся и в банку, и в учёт: банка отвечает за отправку, учёт — за
// следующую выгрузку. Домен обязателен: без него непонятно, кому куку слать.
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

// ClearCookies забывает все куки сессии.
//
// Банка пересоздаётся целиком: удалять по одной она не умеет, а гасить
// каждую куку пустым значением — оставить в ней мусор с чужими сроками.
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

// newCookieJar создаёт банку. Отдельной функцией, потому что её создают
// в двух местах: при открытии сессии и при очистке кук.
func newCookieJar() (*cookiejar.Jar, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("cookie-jar: %w", err)
	}
	return jar, nil
}
