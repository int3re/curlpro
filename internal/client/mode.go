package client

import (
	"net/url"
	"strings"

	"github.com/curlpro/curlpro/internal/profile"
)

// Режимы набора заголовков.
//
// Профиль описывает два запроса браузера: переход по адресу (navigate) и
// fetch/XHR со страницы. Наборы различаются целиком, и запрос с кастомным
// заголовком поверх навигационного набора аномален при любом якоре: в
// браузере кастомный заголовок бывает только у fetch/XHR.
const (
	ModeAuto     = ""
	ModeNavigate = "navigate"
	ModeFetch    = "fetch"
)

// headerTemplate — выбранный набор: пары, порядок, HTTP/1.1-порядок, якорь.
type headerTemplate struct {
	pairs  []profile.HeaderPair
	h1     []string // порядок и регистр HTTP/1.1; nil — приблизить
	anchor string
	fetch  bool
}

// template выбирает набор для запроса.
//
// Если сайт запросил подсказки высокой энтропии, берётся отдельный шаблон:
// с их появлением Chromium перестраивает весь кластер заголовков, и порядок
// получается другой — он снят замером и хранится в профиле целиком.
func (s *Session) template(r *Request) headerTemplate {
	fetch := s.modeFor(r) == ModeFetch
	if want := s.hintsForRequest(r); len(want) > 0 {
		pairs := s.hintTemplate(s.profile.ResolvedHints(fetch, s.device), want)
		base := s.profile.HTTP1.Order
		anchor := s.profile.Headers.CustomAnchor
		if fetch {
			base, anchor = s.profile.Fetch.HTTP1Order, s.profile.Fetch.CustomAnchor
		}
		return headerTemplate{pairs: pairs, h1: hintH1Order(pairs, base), anchor: anchor, fetch: fetch}
	}
	if fetch {
		return headerTemplate{
			pairs:  s.profile.ResolvedFetchHeaders(),
			h1:     s.profile.Fetch.HTTP1Order,
			anchor: s.profile.Fetch.CustomAnchor,
			fetch:  true,
		}
	}
	var h1 []string
	if s.profile.HTTP1.Enabled() {
		h1 = s.profile.HTTP1.Order
	}
	return headerTemplate{
		pairs:  s.profile.ResolvedHeaders(),
		h1:     h1,
		anchor: s.profile.Headers.CustomAnchor,
	}
}

// hintH1Order строит порядок HTTP/1.1 для набора с подсказками.
//
// Шаблон подсказок снят по HTTP/2, где Host и Connection не существуют:
// их берём из обычного порядка HTTP/1.1, оттуда же — регистр знакомых имён.
// Сами подсказки Chrome шлёт в нижнем регистре, как и остальные sec-ch-ua.
func hintH1Order(pairs []profile.HeaderPair, base []string) []string {
	if len(base) == 0 {
		return nil // порядок HTTP/1.1 профиль не задаёт — приблизим кодом
	}
	caseOf := make(map[string]string, len(base))
	for _, n := range base {
		caseOf[strings.ToLower(n)] = n
	}
	out := make([]string, 0, len(pairs)+2)
	for _, n := range base {
		if l := strings.ToLower(n); l == "host" || l == "connection" {
			out = append(out, n)
		}
	}
	for _, h := range pairs {
		l := strings.ToLower(h.Key)
		if l == "host" || l == "connection" {
			continue
		}
		if c, ok := caseOf[l]; ok {
			out = append(out, c)
			continue
		}
		out = append(out, h.Key)
	}
	return out
}

// hintsForRequest возвращает подсказки, запрошенные сайтом для адреса запроса.
func (s *Session) hintsForRequest(r *Request) map[string]bool {
	if r == nil || !s.profile.ClientHints.Enabled() {
		return nil
	}
	u, err := url.Parse(r.URL)
	if err != nil {
		return nil
	}
	return s.hintsFor(u)
}

// names возвращает имена набора в порядке отправки.
func (t headerTemplate) names() []string {
	out := make([]string, len(t.pairs))
	for i, h := range t.pairs {
		out[i] = h.Key
	}
	return out
}

// modeFor определяет режим запроса.
//
// Явный режим запроса важнее сессионного; без обоих режим выводится из
// признаков, по которым запрос не мог быть навигацией: метод, кроме GET,
// HEAD и POST; тело не формы (JSON, XML — форма такого не отправит);
// заголовок, которого в навигационном наборе не бывает. Fetch возможен
// только у профиля с секцией fetch.
func (s *Session) modeFor(r *Request) string {
	mode := r.Mode
	if mode == "" {
		mode = s.opts.Mode
	}
	switch strings.ToLower(mode) {
	case ModeNavigate:
		return ModeNavigate
	case ModeFetch:
		if s.profile.Fetch.Enabled() {
			return ModeFetch
		}
		return ModeNavigate
	}
	if !s.profile.Fetch.Enabled() {
		return ModeNavigate
	}
	switch strings.ToUpper(r.Method) {
	case "", "GET", "HEAD", "POST":
	default:
		return ModeFetch
	}
	if ct := s.requestHeader(r, "content-type"); ct != "" && !isFormContentType(ct) {
		return ModeFetch
	}
	known := map[string]bool{
		// Слоты, которые навигация тоже заполняет: по ним fetch не угадать.
		"cookie": true, "referer": true, "origin": true, "content-type": true, "content-length": true,
	}
	for _, h := range s.profile.Headers.Order {
		known[strings.ToLower(h.Key)] = true
	}
	for k := range r.Headers {
		if !known[strings.ToLower(k)] {
			return ModeFetch
		}
	}
	for _, h := range s.headers.All() {
		if !known[strings.ToLower(h.Key)] {
			return ModeFetch
		}
	}
	return ModeNavigate
}

// isFormContentType сообщает, могла ли HTML-форма отправить такое тело.
func isFormContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch ct {
	case "application/x-www-form-urlencoded", "multipart/form-data", "text/plain":
		return true
	}
	return false
}
