package client

import (
	"net/url"
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

// applyHeaders собирает заголовки запроса и задаёт порядок отправки.
//
// Порядок и регистр — часть отпечатка наравне с набором, поэтому он задаётся
// явно, а не отдаётся на откуп map. Приоритет источников, от низшего к высшему:
// заголовки профиля → заголовки сессии → заголовки запроса.
func (s *Session) applyHeaders(req *http.Request, r *Request, u *url.URL) {
	useDefaults := s.opts.DefaultHeaders && !r.NoDefaultHeaders

	order := make([]string, 0, 16)
	seen := make(map[string]bool, 16)

	add := func(key, value string) {
		req.Header.Set(key, value)
		if lk := strings.ToLower(key); !seen[lk] {
			seen[lk] = true
			order = append(order, key)
		}
	}

	if useDefaults {
		for _, h := range s.profile.ResolvedHeaders() {
			if h.Value != "" {
				add(h.Key, h.Value)
			}
		}
	}
	for k, v := range r.Headers {
		add(k, v)
	}

	if s.jar != nil {
		if cookies := s.jar.Cookies(u); len(cookies) > 0 {
			parts := make([]string, 0, len(cookies))
			for _, c := range cookies {
				parts = append(parts, c.Name+"="+c.Value)
			}
			add("cookie", strings.Join(parts, "; "))
		}
	}

	// Явный порядок из запроса важнее сессионного, тот — важнее собранного.
	if want := firstNonEmpty(r.HeaderOrder, s.opts.HeaderOrder); len(want) > 0 {
		order = reorder(order, want)
	}

	req.Header[http.HeaderOrderKey] = order
	if len(s.profile.HTTP2.PseudoOrder) > 0 {
		req.Header[http.PHeaderOrderKey] = s.profile.HTTP2.PseudoOrder
	}
}

// reorder выстраивает заголовки по want. Не упомянутые в want идут следом,
// сохраняя исходный относительный порядок: неполный список не должен молча
// выбрасывать заголовки из запроса.
func reorder(have, want []string) []string {
	index := make(map[string]int, len(have))
	for i, h := range have {
		index[strings.ToLower(h)] = i
	}

	out := make([]string, 0, len(have))
	used := make(map[string]bool, len(have))
	for _, w := range want {
		lw := strings.ToLower(w)
		if i, ok := index[lw]; ok && !used[lw] {
			out = append(out, have[i])
			used[lw] = true
		}
	}
	for _, h := range have {
		if !used[strings.ToLower(h)] {
			out = append(out, h)
		}
	}
	return out
}

func firstNonEmpty(lists ...[]string) []string {
	for _, l := range lists {
		if len(l) > 0 {
			return l
		}
	}
	return nil
}
