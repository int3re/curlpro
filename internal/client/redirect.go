package client

import (
	"fmt"
	"net/url"
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

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
		return "", fmt.Errorf("редирект на %s: поддерживается только https", next.Scheme)
	}
	return next.String(), nil
}

// nextRequest строит запрос следующего шага цепочки.
//
// Три вещи, которые легко сделать неправильно и выдать себя:
//   - 301/302/303 переводят метод в GET и отбрасывают тело (кроме HEAD);
//   - при уходе на другой хост снимаются заголовки авторизации и cookie;
//   - браузер меняет sec-fetch-site на cross-site, а sec-fetch-user снимает
//     вовсе, потому что переход инициирован не пользователем.
func nextRequest(prev *Request, nextURL string, status int) Request {
	next := Request{
		Method:           prev.Method,
		URL:              nextURL,
		Body:             prev.Body,
		HeaderOrder:      prev.HeaderOrder,
		NoDefaultHeaders: prev.NoDefaultHeaders,
		Headers:          make(map[string]string, len(prev.Headers)),
	}
	for k, v := range prev.Headers {
		next.Headers[k] = v
	}

	if status == http.StatusMovedPermanently ||
		status == http.StatusFound ||
		status == http.StatusSeeOther {
		if !strings.EqualFold(next.Method, http.MethodHead) {
			next.Method = http.MethodGet
		}
		next.Body = nil
		delete(next.Headers, "content-type")
		delete(next.Headers, "Content-Type")
		delete(next.Headers, "content-length")
		delete(next.Headers, "Content-Length")
	}

	if !sameHost(prev.URL, nextURL) {
		for _, h := range []string{"authorization", "cookie", "proxy-authorization"} {
			delete(next.Headers, h)
			delete(next.Headers, http.CanonicalHeaderKey(h))
		}
		next.Headers["sec-fetch-site"] = "cross-site"
	} else {
		next.Headers["sec-fetch-site"] = "same-origin"
	}
	delete(next.Headers, "sec-fetch-user")

	return next
}

func sameHost(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(ua.Hostname(), ub.Hostname())
}
