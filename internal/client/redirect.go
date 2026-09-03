package client

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	http "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/publicsuffix"
)

func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// errRedirectUnsupported означает, что переход возможен по протоколу, но не
// по возможностям клиента (Location ведёт на http://). Такой ответ отдаётся
// вызывающему как есть: 301 с Location полезнее исключения.
var errRedirectUnsupported = errors.New("редирект вне https не поддерживается")

// redirectTarget разрешает Location относительно текущего URL.
func redirectTarget(current, location string) (string, error) {
	base, err := url.Parse(current)
	if err != nil {
		return "", fmt.Errorf("разбор текущего URL: %w", err)
	}
	loc, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("разбор Location %q: %w", location, err)
	}
	next := base.ResolveReference(loc)
	if next.Scheme != "https" {
		return "", fmt.Errorf("%w: %s", errRedirectUnsupported, next.Scheme)
	}
	return next.String(), nil
}

// nextRequest строит запрос следующего шага цепочки.
//
// Что легко сделать неправильно и выдать себя:
//   - 301/302/303 переводят метод в GET и отбрасывают тело (кроме HEAD);
//   - при уходе на другой origin снимаются заголовки авторизации и cookie;
//   - sec-fetch-site считается от инициатора всей цепочки, а не от
//     предыдущего хопа, и sec-fetch-user переживает редирект.
//
// initiator — URL, с которого началась цепочка.
func (s *Session) nextRequest(prev *Request, nextURL string, status int, initiator string) Request {
	// Копия целиком, а меняется только то, что обязано измениться.
	//
	// Ручной перечень полей уже терял BodyFile — и 307 с файлом уходил
	// с пустым телом, — а также per-request таймаут и политику повторов.
	// Следующее добавленное поле потерялось бы так же тихо.
	next := *prev
	next.URL = nextURL
	next.RedirectHop = true
	next.Headers = make(map[string]string, len(prev.Headers))
	for k, v := range prev.Headers {
		next.Headers[k] = v
	}

	if status == http.StatusMovedPermanently ||
		status == http.StatusFound ||
		status == http.StatusSeeOther {
		if !strings.EqualFold(next.Method, http.MethodHead) {
			next.Method = http.MethodGet
		}
		// Тело отбрасывается во всех его видах, иначе GET уйдёт с файлом
		// или собранной формой.
		next.Body = nil
		next.BodyFile = ""
		next.BodySize = 0
		next.Multipart = nil
		dropHeader(next.Headers, "content-type", "content-length")
	}

	if !sameOrigin(prev.URL, nextURL) {
		dropHeader(next.Headers, "authorization", "cookie", "proxy-authorization")
	}

	// Замер Chromium 148: у навигации, начатой браузером (профильное none),
	// инициатора нет, и sec-fetch-site остаётся none на каждом хопе, даже при
	// смене хоста; sec-fetch-user тоже остаётся. Прежняя логика ставила
	// same-origin/cross-site по паре соседних URL и гасила sec-fetch-user —
	// это следовало букве Fetch Metadata для запросов с инициатором, а не
	// тому, что браузер шлёт при переходе по введённому адресу.
	//
	// Если же значение задано явно и это не none, оно считается от
	// инициатора против каждого URL цепочки и только ухудшается:
	// same-origin → same-site → cross-site, обратно не возвращается.
	if cur := s.effectiveHeader(prev, "sec-fetch-site"); cur != "" && cur != "none" {
		setHeader(next.Headers, "sec-fetch-site", worseSite(cur, siteRelation(initiator, nextURL)))
	}
	return next
}

// effectiveHeader возвращает значение заголовка, которое ушло бы в запрос:
// из самого запроса, из сессии или из профиля.
func (s *Session) effectiveHeader(r *Request, name string) string {
	for k, v := range r.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	for _, h := range s.headers.All() {
		if strings.EqualFold(h.Key, name) {
			return h.Value
		}
	}
	if s.opts.DefaultHeaders && !r.NoDefaultHeaders {
		for _, h := range s.template(r).pairs {
			if strings.EqualFold(h.Key, name) {
				return h.Value
			}
		}
	}
	return ""
}

// requestHeader возвращает значение заголовка из запроса или сессии,
// не заглядывая в профиль: modeFor решает по нему, какой набор профиля брать.
func (s *Session) requestHeader(r *Request, name string) string {
	for k, v := range r.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	for _, h := range s.headers.All() {
		if strings.EqualFold(h.Key, name) {
			return h.Value
		}
	}
	return ""
}

// setHeader переписывает значение без учёта регистра имени, чтобы в карте
// не появилось второго ключа под тем же именем.
func setHeader(h map[string]string, name, value string) {
	for k := range h {
		if strings.EqualFold(k, name) {
			h[k] = value
			return
		}
	}
	h[name] = value
}

// siteRelation классифицирует пару URL так, как это делает Fetch Metadata.
func siteRelation(a, b string) string {
	switch {
	case sameOrigin(a, b):
		return "same-origin"
	case sameSite(a, b):
		return "same-site"
	default:
		return "cross-site"
	}
}

var siteRank = map[string]int{"same-origin": 1, "same-site": 2, "cross-site": 3}

func worseSite(a, b string) string {
	if siteRank[b] > siteRank[a] {
		return b
	}
	return a
}

// sameSite сравнивает схему и регистрируемый домен (eTLD+1).
//
// Список публичных суффиксов нужен, потому что по одним меткам не отличить
// a.example.com/b.example.com (same-site) от a.co.uk/b.co.uk (cross-site).
func sameSite(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil || !strings.EqualFold(ua.Scheme, ub.Scheme) {
		return false
	}
	return registrableDomain(ua.Hostname()) == registrableDomain(ub.Hostname())
}

func registrableDomain(host string) string {
	host = strings.ToLower(host)
	if net.ParseIP(host) != nil {
		return host
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host // localhost и прочие имена без суффикса сравниваются целиком
}

// dropHeader убирает заголовки без учёта регистра: перечислять оба написания
// недостаточно, вызывающий мог задать AUTHORIZATION или Content-Type.
func dropHeader(h map[string]string, names ...string) {
	for _, name := range names {
		lowered := strings.ToLower(name)
		for k := range h {
			if strings.ToLower(k) == lowered {
				delete(h, k)
			}
		}
	}
}

// sameOrigin сравнивает схему, хост и порт.
//
// Сравнения одного лишь имени хоста мало: переход с другого порта — уже
// другой источник, и браузер пометил бы его как cross-site.
func sameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) &&
		strings.EqualFold(ua.Hostname(), ub.Hostname()) &&
		defaultPort(ua) == defaultPort(ub)
}

func defaultPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return "443"
}
