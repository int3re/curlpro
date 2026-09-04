package client

import (
	"net/textproto"
	"net/url"
	"sort"
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

// cookieHeader собирает значение заголовка cookie из jar сессии.
func (s *Session) cookieHeader(u *url.URL) string {
	if s.jar == nil {
		return ""
	}
	cookies := s.jar.Cookies(u)
	if len(cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// http1Order возвращает порядок заголовков для HTTP/1.1.
//
// В HTTP/2 имена обязаны быть строчными, в HTTP/1.1 регистр произволен —
// и браузеры им пользуются. Отсюда отдельный порядок: он несёт и регистр.
//
// Признак берётся из протокола соединения, а не из опции ForceHTTP1: сервер
// без h2 согласует http/1.1 и без принуждения. Раньше порядок зависел от
// опции, и такой запрос уходил со строчными именами, без Connection и
// с Host в самом конце — fhttp дописывал его сам, а сортировщик ставил
// неизвестное имя последним.
func (s *Session) http1Order(h1 bool, tpl headerTemplate) []string {
	if !h1 {
		return nil
	}
	if tpl.h1 != nil {
		return tpl.h1
	}
	return s.http1Fallback(tpl.names())
}

// http1Fallback строит порядок HTTP/1.1 для набора без своего http1-порядка:
// Host первым, как требует RFC 7230, остальные имена в каноническом регистре.
//
// Это приближение, а не отпечаток: Chrome оставляет sec-ch-* и priority
// строчными, Firefox пишет Priority и TE, и без замера угадать нельзя.
// Но приближение лучше прежнего поведения с Host в хвосте.
func (s *Session) http1Fallback(names []string) []string {
	order := make([]string, 0, len(names)+2)
	order = append(order, "Host")
	if s.profile.HTTP1.Connection != "" {
		order = append(order, "Connection")
	}
	for _, n := range names {
		order = append(order, textproto.CanonicalMIMEHeaderKey(n))
	}
	return order
}

// headerKV — заголовок с сохранённым регистром имени.
type headerKV struct{ Key, Value string }

// buildHeaders собирает заголовки запроса в порядке отправки.
//
// Порядок и регистр — часть отпечатка наравне с набором, поэтому он задаётся
// явно, а не отдаётся на откуп map. Приоритет источников, от низшего к высшему:
// заголовки профиля → заголовки сессии → заголовки запроса.
//
// Общий для HTTP/1.1, HTTP/2 и HTTP/3: пути различаются только типом Header
// (fhttp против net/http) и служебными ключами, а правила сборки одни. Пока
// правил было две копии, HTTP/3 тихо терял SuppressHeaders и слот cookie.
//
// h1Order непуст только для HTTP/1.1: там добавляются Host и Connection,
// которых в HTTP/2 не бывает, и берётся заданный профилем регистр.
func (s *Session) buildHeaders(r *Request, u *url.URL, host string, h1Order []string) []headerKV {
	useDefaults := s.useDefaultHeaders(r)
	tpl := s.template(r)

	out := make([]headerKV, 0, 16)
	// slot хранит фактический ключ мапы для каждого имени в нижнем регистре.
	//
	// Без него профиль клал user-agent, пользователь передавал User-Agent —
	// и в карте оказывалось два ключа при одном имени в порядке. HTTP/1.1
	// выдавал две строки, а HTTP/2 — непредсказуемый порядок, потому что
	// сортировщик считает такие ключи равными. Воспроизводилось и без
	// пользователя: профиль кладёт Sec-Fetch-Site, редирект — sec-fetch-site.
	slot := make(map[string]int, 16)

	add := func(key, value string) {
		lk := strings.ToLower(key)
		if i, ok := slot[lk]; ok {
			// Значение переписывается на прежнем месте: так переопределение
			// профильного заголовка сохраняет его позицию в отпечатке.
			out[i].Value = value
			return
		}
		slot[lk] = len(out)
		out = append(out, headerKV{Key: key, Value: value})
	}

	if useDefaults {
		// Для HTTP/1.1 профиль задаёт свой регистр и добавляет Connection,
		// которого в HTTP/2 не бывает.
		if len(h1Order) > 0 {
			s.addHTTP1Headers(add, host, h1Order)
		}
		cookie := s.cookieHeader(u)
		// На HTTP/1.1 профильный http1.order задаёт не только порядок, но
		// и набор: Chrome не шлёт priority на HTTP/1.1, Firefox — TE (замер
		// Chrome 152 и Firefox 154), хотя в HTTP/2 оба присутствуют.
		h1Set := len(h1Order) > 0 && tpl.h1 != nil
		for _, h := range tpl.pairs {
			if h1Set && !nameIn(h.Key, h1Order) {
				continue
			}
			if v := h.For(r.Method); v != "" {
				add(caseFor(h.Key, h1Order), v)
				continue
			}
			// Пустое значение — слот: позиция без значения. Что в неё
			// встаёт, зависит от имени; пустой слот выпадает, а позицию
			// для заголовка, который придёт от сессии, запроса или самого
			// транспорта (content-length), сохранит reorder по порядку профиля.
			switch strings.ToLower(h.Key) {
			case "cookie":
				// cookie встаёт на свою позицию (у Chrome — между accept-language
				// и priority), а не дописывается в конец, что сбивало бы
				// отпечаток даже без единого пользовательского заголовка.
				if cookie != "" {
					add(caseFor(h.Key, h1Order), cookie)
					cookie = ""
				}
			case "origin":
				// Origin браузер шлёт на любой запрос с телом, в том числе
				// на навигационный POST формы (замер Chromium 148). Значение —
				// origin самого запроса: инициатора у клиента нет.
				if sendsOrigin(r.Method) {
					add(caseFor(h.Key, h1Order), originOf(u))
				}
			}
		}
		// Профиль слота не объявил — добавляем как раньше, до пользовательских.
		if cookie != "" {
			add(caseFor("cookie", h1Order), cookie)
		}
	}

	// Заголовки сессии, затем запроса. Переопределение профильного меняет
	// только значение: add() не двигает уже добавленное имя, и позиция
	// в отпечатке сохраняется. Новое имя уходит в конец — так же ведёт себя
	// браузер, добавляя заголовок через fetch().
	for _, h := range s.headers.All() {
		add(h.Key, h.Value)
	}
	// Порядок ключей map недетерминирован, а порядок заголовков наблюдаем,
	// поэтому имена запроса сортируются.
	extra := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		extra = append(extra, k)
	}
	sort.Strings(extra)
	for _, k := range extra {
		add(caseFor(k, h1Order), r.Headers[k])
	}

	// Явный порядок из запроса важнее сессионного, тот — важнее профильного.
	// Кастомные имена вставляются перед якорем профиля, а не в конец:
	// служебный хвост браузер дописывает последним, и заголовок после него —
	// заметная аномалия.
	//
	// Порядок профиля участвует в этой цепочке обязательно, хотя заголовки уже
	// добавлены в нужной последовательности: без него reorder не вызывался бы
	// для HTTP/2 и HTTP/3 вовсе (свой порядок там задаёт не h1Order, а сама
	// сборка) — и якорь работал бы только на HTTP/1.1.
	if want := s.wantOrder(r, h1Order, tpl); len(want) > 0 {
		out = reorder(out, want, tpl.anchor)
	}

	// Заголовки, погашенные явно: они приходят из профиля, поэтому убираются
	// здесь, а не из r.Headers.
	for _, name := range r.SuppressHeaders {
		lowered := strings.ToLower(name)
		for i, h := range out {
			if strings.ToLower(h.Key) == lowered {
				out = append(out[:i], out[i+1:]...)
				break
			}
		}
	}
	return out
}

// wantOrder возвращает желаемый порядок для запроса: явный порядок запроса,
// сессии, HTTP/1.1-порядок профиля или общий порядок профиля.
//
// На шаге редиректа Chromium переставляет client hints: sec-ch-ua,
// sec-ch-ua-mobile и sec-ch-ua-platform уходят после Sec-Fetch-Dest, а Referer
// следует за ними (замер Chrome 152, оба хопа — browser-initiated и по
// ссылке). Профили без sec-ch-* (Firefox, Safari) не затрагиваются.
func (s *Session) wantOrder(r *Request, h1Order []string, tpl headerTemplate) []string {
	want := firstNonEmpty(r.HeaderOrder, s.opts.HeaderOrder, h1Order, tpl.names())
	if r.RedirectHop {
		want = redirectHopOrder(want)
	}
	return want
}

func redirectHopOrder(want []string) []string {
	var hints, rest []string
	for _, name := range want {
		switch ln := strings.ToLower(name); {
		case strings.HasPrefix(ln, "sec-ch-"):
			hints = append(hints, name)
		case ln == "referer":
			// Переставится вслед за client hints.
		default:
			rest = append(rest, name)
		}
	}
	if len(hints) == 0 {
		return want
	}
	block := append(hints, "referer")
	at := len(rest)
	for i, name := range rest {
		if strings.EqualFold(name, "sec-fetch-dest") {
			at = i + 1
			break
		}
	}
	if at == len(rest) {
		for i, name := range rest {
			if strings.EqualFold(name, "accept-encoding") {
				at = i
				break
			}
		}
	}
	out := make([]string, 0, len(want)+1)
	out = append(out, rest[:at]...)
	out = append(out, block...)
	return append(out, rest[at:]...)
}

func nameIn(name string, list []string) bool {
	for _, n := range list {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// pickAnchor выбирает из списка якорей первый, который есть среди имён.
//
// Список нужен, потому что у одного браузера якорь зависит от транспорта:
// у Firefox кастомные заголовки идут перед Connection, которого в HTTP/2
// нет, — там они встают перед Upgrade-Insecure-Requests.
func pickAnchor(anchors string, names []string) string {
	for _, a := range strings.Split(anchors, ",") {
		a = strings.TrimSpace(a)
		if a != "" && nameIn(a, names) {
			return a
		}
	}
	return ""
}

// sendsOrigin сообщает, добавляет ли браузер Origin к запросу с таким методом.
// Fetch: Origin ставится на всё, кроме GET и HEAD.
func sendsOrigin(method string) bool {
	switch strings.ToUpper(method) {
	case "", http.MethodGet, http.MethodHead:
		return false
	}
	return true
}

func originOf(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

// wireOrder возвращает имена для служебного ключа порядка, в нижнем регистре.
//
// В список входят и те имена профиля, которых в запросе ещё нет: Content-Length
// транспорт добавляет сам, уже после сборки заголовков, и без заранее занятого
// места он уходит в самый хвост — тогда как браузер шлёт его сразу за
// Connection. Имя, которому не нашлось заголовка, сортировщик просто не
// встретит, поэтому лишние места безвредны.
//
// Кастомные имена (тех, что нет в профиле) вставляются перед якорем — там же,
// где их разместил reorder.
func wireOrder(built []headerKV, want []string, anchor string) []string {
	out := make([]string, 0, len(built)+len(want))
	if len(want) == 0 {
		for _, h := range built {
			out = append(out, strings.ToLower(h.Key))
		}
		return out
	}

	known := make(map[string]bool, len(want))
	for _, w := range want {
		known[strings.ToLower(w)] = true
	}
	custom := make([]string, 0, 4)
	for _, h := range built {
		if lk := strings.ToLower(h.Key); !known[lk] {
			custom = append(custom, lk)
		}
	}

	anchored := strings.ToLower(pickAnchor(anchor, want))
	for _, w := range want {
		lw := strings.ToLower(w)
		if lw == anchored {
			out = append(out, custom...)
			custom = nil
		}
		out = append(out, lw)
	}
	// Якоря в порядке не оказалось — остаток уходит в конец.
	return append(out, custom...)
}

// applyHeaders записывает заголовки в запрос fhttp (HTTP/1.1 и HTTP/2).
// h1 сообщает, что соединение согласовало http/1.1.
func (s *Session) applyHeaders(req *http.Request, r *Request, u *url.URL, h1 bool) {
	host := u.Host
	if req.Host != "" {
		host = req.Host
	}
	tpl := s.template(r)
	h1Order := s.http1Order(h1, tpl)
	built := s.buildHeaders(r, u, host, h1Order)

	for _, h := range built {
		// Прямая запись в map вместо Set: тот приводит имя к каноническому
		// виду и стёр бы регистр, заданный профилем.
		req.Header[h.Key] = []string{h.Value}
	}
	suppressDefaultUA(req.Header, built, h1)
	// fhttp ищет позицию по имени в нижнем регистре (headerSorter.Less),
	// поэтому порядок передаётся строчным. Регистр, который уйдёт на провод,
	// берётся из ключей самой мапы и здесь не участвует.
	req.Header[http.HeaderOrderKey] = wireOrder(built, s.wantOrder(r, h1Order, tpl), tpl.anchor)
	if len(s.profile.HTTP2.PseudoOrder) > 0 {
		req.Header[http.PHeaderOrderKey] = s.profile.HTTP2.PseudoOrder
	}
}

// suppressDefaultUA не даёт транспорту подставить свой User-Agent.
//
// Без user-agent в карте fhttp пишет Go-http-client/1.1 или /2.0, а h3 —
// quic-go HTTP/3: режим «полный контроль над набором» молча получал самый
// громкий маркер не-браузера.
//
// Форма подавления зависит от транспорта. HTTP/1.1 пишет каждое значение
// строкой, и пустая строка ушла бы на провод как «user-agent: » — там нужен
// пустой слайс, который writeSubset пропускает. HTTP/2 и HTTP/3, наоборот,
// пропускают пустой слайс до проверки didUA и всё равно подставляют
// умолчание — там нужна пустая строка, которую они трактуют как «не слать».
func suppressDefaultUA(h map[string][]string, built []headerKV, h1 bool) {
	for _, kv := range built {
		if strings.EqualFold(kv.Key, "user-agent") {
			return
		}
	}
	if h1 {
		h["user-agent"] = []string{}
	} else {
		h["user-agent"] = []string{""}
	}
}

// addHTTP1Headers добавляет то, чего в HTTP/2 не бывает.
//
// Host обязателен по RFC 7230 и у Chrome идёт первым; Connection браузер шлёт
// явно, хотя keep-alive и так подразумевается в HTTP/1.1.
func (s *Session) addHTTP1Headers(add func(k, v string), host string, order []string) {
	for _, name := range order {
		switch strings.ToLower(name) {
		case "host":
			add(name, host)
		case "connection":
			if v := s.profile.HTTP1.Connection; v != "" {
				add(name, v)
			}
		}
	}
}

// caseFor возвращает имя заголовка в том регистре, который задан профилем.
// Если профиль о нём не знает, регистр остаётся исходным.
func caseFor(key string, order []string) string {
	lk := strings.ToLower(key)
	for _, name := range order {
		if strings.ToLower(name) == lk {
			return name
		}
	}
	return key
}

// reorder выстраивает заголовки по want.
//
// Имена, которых в want нет, вставляются перед anchor, сохраняя исходный
// относительный порядок. Пустой anchor означает «в конец» — прежнее поведение
// и запасной вариант для профилей, где якорь не задан.
//
// Якорь нужен потому, что служебный хвост (accept-encoding, cookie, priority)
// браузер дописывает последним: кастомный заголовок после него заметен.
func reorder(have []headerKV, want []string, anchor string) []headerKV {
	index := make(map[string]int, len(have))
	for i, h := range have {
		index[strings.ToLower(h.Key)] = i
	}

	ordered := make([]headerKV, 0, len(have))
	used := make(map[string]bool, len(have))
	for _, w := range want {
		lw := strings.ToLower(w)
		if i, ok := index[lw]; ok && !used[lw] {
			ordered = append(ordered, have[i])
			used[lw] = true
		}
	}

	rest := make([]headerKV, 0, len(have))
	for _, h := range have {
		if !used[strings.ToLower(h.Key)] {
			rest = append(rest, h)
		}
	}
	if len(rest) == 0 {
		return ordered
	}

	at := len(ordered)
	if anchor != "" {
		lowered := make([]string, len(ordered))
		for i, h := range ordered {
			lowered[i] = strings.ToLower(h.Key)
		}
		la := strings.ToLower(pickAnchor(anchor, lowered))
		for i, n := range lowered {
			if la != "" && n == la {
				at = i
				break
			}
		}
	}
	out := make([]headerKV, 0, len(have))
	out = append(out, ordered[:at]...)
	out = append(out, rest...)
	return append(out, ordered[at:]...)
}

func firstNonEmpty(lists ...[]string) []string {
	for _, l := range lists {
		if len(l) > 0 {
			return l
		}
	}
	return nil
}
