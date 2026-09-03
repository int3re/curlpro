package client

import (
	"net/url"
	"strings"

	"github.com/curlpro/curlpro/internal/profile"
)

// Клиентские подсказки высокой энтропии (User-Agent Client Hints).
//
// Chrome с версии 110 вырезал из User-Agent модель и версию системы: замер
// Pixel 7 на Android 17 даёт «Android 10; K» — одну и ту же заглушку у всех
// телефонов. Настоящее устройство сообщается подсказками sec-ch-ua-model
// и sec-ch-ua-platform-version, и браузер шлёт их не сразу, а только после
// того, как сайт их запросил заголовком Accept-CH в ответе.
//
// Поэтому «разные телефоны» — это не подстановка в User-Agent (такой строки
// у современного Chrome не бывает вовсе), а согласованная пара «устройство
// плюс подсказки», выдаваемая по запросу сайта.

// highEntropyHints — подсказки, которые без Accept-CH не уходят.
//
// sec-ch-ua, sec-ch-ua-mobile и sec-ch-ua-platform сюда не входят: они низкой
// энтропии и шлются всегда, поэтому живут в обычном наборе профиля.
var highEntropyHints = map[string]bool{
	"sec-ch-ua-arch":              true,
	"sec-ch-ua-bitness":           true,
	"sec-ch-ua-form-factors":      true,
	"sec-ch-ua-full-version":      true,
	"sec-ch-ua-full-version-list": true,
	"sec-ch-ua-model":             true,
	"sec-ch-ua-platform-version":  true,
	"sec-ch-ua-wow64":             true,
}

// originKey — ключ памяти подсказок. Chrome помнит Accept-CH по origin,
// а не по адресу: запрошенное на главной уходит и в подресурсы.
func originKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// noteAcceptCH запоминает запрошенные сайтом подсказки.
//
// Возвращает true, если ответ пришёл с Critical-CH на подсказки, которых мы
// в этом запросе не отправляли: Chrome в таком случае повторяет запрос сразу,
// не дожидаясь следующего.
func (s *Session) noteAcceptCH(u *url.URL, resp map[string][]string) bool {
	key := originKey(u)
	if key == "" || !s.profile.ClientHints.Enabled() {
		return false
	}
	accept := hintList(resp, "Accept-CH")
	critical := hintList(resp, "Critical-CH")
	if len(accept) == 0 && len(critical) == 0 {
		return false
	}

	s.mu.Lock()
	if s.acceptCH == nil {
		s.acceptCH = make(map[string]map[string]bool)
	}
	known := s.acceptCH[key]
	if known == nil {
		known = make(map[string]bool)
		s.acceptCH[key] = known
	}
	var added bool
	for _, name := range accept {
		if highEntropyHints[name] && !known[name] {
			known[name] = true
			added = true
		}
	}
	// Critical-CH без Accept-CH браузер не выполняет: список критичных
	// подсказок — подмножество запрошенных.
	var criticalNew bool
	for _, name := range critical {
		if highEntropyHints[name] && known[name] {
			criticalNew = true
		}
	}
	s.mu.Unlock()

	return added && criticalNew
}

// hintsFor возвращает подсказки, которые сайт уже запросил.
func (s *Session) hintsFor(u *url.URL) map[string]bool {
	key := originKey(u)
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.acceptCH[key]) == 0 {
		return nil
	}
	out := make(map[string]bool, len(s.acceptCH[key]))
	for k, v := range s.acceptCH[key] {
		out[k] = v
	}
	return out
}

// hintList разбирает список имён из заголовка ответа.
func hintList(resp map[string][]string, name string) []string {
	var out []string
	for k, vv := range resp {
		if !strings.EqualFold(k, name) {
			continue
		}
		for _, v := range vv {
			for _, part := range strings.Split(v, ",") {
				part = strings.TrimSpace(strings.Trim(strings.TrimSpace(part), `"`))
				if part != "" {
					out = append(out, strings.ToLower(part))
				}
			}
		}
	}
	return out
}

// hintTemplate строит набор с подсказками для запроса.
//
// Из шаблона выкидываются подсказки, которых сайт не просил: их относительный
// порядок при этом сохраняется. Точный порядок Chromium зависит от полного
// набора имён, поэтому для подмножества он приближается — см. docs/CAPTURE.md.
func (s *Session) hintTemplate(pairs []profile.HeaderPair, want map[string]bool) []profile.HeaderPair {
	out := make([]profile.HeaderPair, 0, len(pairs))
	for _, h := range pairs {
		if highEntropyHints[strings.ToLower(h.Key)] && !want[strings.ToLower(h.Key)] {
			continue
		}
		out = append(out, h)
	}
	return out
}
