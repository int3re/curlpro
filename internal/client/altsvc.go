package client

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Автопереход на HTTP/3 по Alt-Svc.
//
// Браузер не ходит по QUIC сразу: он идёт по TCP, видит в ответе заголовок
// Alt-Svc и со следующего запроса к тому же origin пробует HTTP/3. Мы делали
// иначе — h3 включался опцией на всю сессию, — и это само по себе отличало
// клиента: настоящий Chrome первым запросом на новый сайт всегда идёт по TCP.
//
// Неудачная попытка помечает адрес сломанным на растущий срок, как и Chromium:
// в сети, где UDP закрыт, запросы не должны каждый раз спотыкаться о QUIC.
// Это поведение мы наблюдали у него же — «ALT_SVC … is_broken: true».

// Начальный и предельный срок пометки «сломан». Chromium начинает с пяти минут
// и удваивает; больше суток держать бессмысленно — сеть меняется.
const (
	altSvcBrokenBase = 5 * time.Minute
	altSvcBrokenMax  = 24 * time.Hour
)

type altSvcEntry struct {
	// expires — до какого момента действует само объявление (ma).
	expires time.Time
	// broken — до какого момента не пробовать после неудачи.
	broken   time.Time
	failures int
}

// altSvcKey — ключ памяти объявлений: узел и порт.
//
// Не origin из hints.go: объявление Alt-Svc привязано именно к паре
// «узел плюс порт», а схема у нас всегда https.
func altSvcKey(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return strings.ToLower(u.Hostname()) + ":" + port
}

// noteAltSvc запоминает объявление HTTP/3 из ответа.
func (s *Session) noteAltSvc(u *url.URL, headers map[string][]string) {
	if s.opts.DisableAltSvc || u == nil {
		return
	}
	var value string
	for name, vals := range headers {
		if strings.EqualFold(name, "alt-svc") && len(vals) > 0 {
			value = strings.Join(vals, ", ")
			break
		}
	}
	if value == "" {
		return
	}
	key := altSvcKey(u)

	// «clear» отзывает все объявления для origin — обязано работать, иначе
	// сайт, отключивший QUIC, не сможет нас увести обратно на TCP.
	if strings.EqualFold(strings.TrimSpace(value), "clear") {
		s.mu.Lock()
		delete(s.altSvc, key)
		s.mu.Unlock()
		return
	}

	ttl, ok := parseAltSvcH3(value, u)
	if !ok {
		return
	}
	s.mu.Lock()
	if s.altSvc == nil {
		s.altSvc = make(map[string]altSvcEntry)
	}
	e := s.altSvc[key]
	e.expires = time.Now().Add(ttl)
	s.altSvc[key] = e
	s.mu.Unlock()
}

// parseAltSvcH3 ищет в заголовке предложение h3 для того же узла и порта.
//
// Альтернатива на другом порту игнорируется намеренно: браузер её принимает,
// но у нас порт участвует в ключе пула и в :authority, и поддержать это
// вполсилы значит получить запрос с чужим адресом в заголовке.
func parseAltSvcH3(value string, u *url.URL) (time.Duration, bool) {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	for _, alt := range strings.Split(value, ",") {
		parts := strings.Split(alt, ";")
		name, target, found := strings.Cut(strings.TrimSpace(parts[0]), "=")
		if !found || strings.TrimSpace(name) != "h3" {
			continue
		}
		target = strings.Trim(strings.TrimSpace(target), "\"")
		host, altPort, ok := strings.Cut(target, ":")
		if !ok {
			continue
		}
		if host != "" && !strings.EqualFold(host, u.Hostname()) {
			continue // другой узел: наш путь h3 умеет ходить только на свой
		}
		if altPort != port {
			continue
		}
		ttl := 24 * time.Hour
		for _, p := range parts[1:] {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok && strings.EqualFold(k, "ma") {
				if secs, err := strconv.Atoi(strings.Trim(v, "\"")); err == nil && secs > 0 {
					ttl = time.Duration(secs) * time.Second
				}
			}
		}
		return ttl, true
	}
	return 0, false
}

// altSvcH3 сообщает, идти ли к этому адресу по HTTP/3.
func (s *Session) altSvcH3(u *url.URL) bool {
	if s.opts.DisableAltSvc || !s.profile.HTTP3.Enabled() {
		return false
	}
	now := time.Now()
	key := altSvcKey(u)
	s.mu.Lock()
	e, ok := s.altSvc[key]
	s.mu.Unlock()
	if !ok || now.After(e.expires) {
		return false
	}
	return now.After(e.broken)
}

// markAltSvcBroken откладывает следующую попытку HTTP/3 к этому адресу.
func (s *Session) markAltSvcBroken(u *url.URL) {
	key := altSvcKey(u)
	s.mu.Lock()
	if s.altSvc == nil {
		s.altSvc = make(map[string]altSvcEntry)
	}
	e := s.altSvc[key]
	e.failures++
	wait := altSvcBrokenBase << (e.failures - 1)
	if wait > altSvcBrokenMax || wait <= 0 {
		wait = altSvcBrokenMax
	}
	e.broken = time.Now().Add(wait)
	s.altSvc[key] = e
	s.mu.Unlock()
}
