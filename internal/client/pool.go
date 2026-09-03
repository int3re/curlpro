package client

import (
	"context"
	"net/url"
	"strings"
	"time"
)

// Пул соединений.
//
// Ключ — dialSpec целиком: совпадение всех его полей есть необходимое
// и достаточное условие переиспользования. Структура, а не склейка в строку:
// в userinfo прокси нет разделителя, который нельзя было бы встретить
// в самих данных.
//
// Под одним ключом живёт список соединений. Для HTTP/2 в нём одно: потоки
// мультиплексируются. Для HTTP/1.1 — до maxConnsPerHost: пока одно занято
// телом ответа, параллельный запрос идёт по соседнему, как в браузере. Раньше
// пул держал ровно одно, и каждый параллельный запрос поднимал TLS заново
// и выбрасывал соединение после ответа — 96 запросов давали 36 рукопожатий.

const (
	defaultMaxIdleConns    = 64
	defaultIdleConnTimeout = 300 * time.Second
	// maxConnsPerHost — столько соединений к одному хосту держит Chrome
	// по HTTP/1.1. Сверх предела соединение живёт один запрос и закрывается.
	maxConnsPerHost = 6
)

// dialSpec — всё, что определяет, каким получится соединение.
//
// InsecureSkipVerify сюда не входит: поле сессионное и после New не меняется.
// Если появится per-request verify, его придётся добавить сюда тем же
// изменением — иначе запрос без проверки получит соединение с проверкой.
type dialSpec struct {
	addr       string // host:port, hostname в нижнем регистре
	proxy      string // адрес прокси как задан; пусто — напрямую
	forceHTTP1 bool
}

// newDialSpec собирает ключ соединения.
//
// Hostname приводится к нижнему регистру: иначе https://Example.COM
// и https://example.com дали бы два соединения к одному серверу.
func newDialSpec(u *url.URL, proxy string, forceHTTP1 bool) dialSpec {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return dialSpec{
		addr:       strings.ToLower(u.Hostname()) + ":" + port,
		proxy:      proxy,
		forceHTTP1: forceHTTP1,
	}
}

// conn возвращает соединение под spec, при необходимости открывая новое.
func (s *Session) conn(ctx context.Context, u *url.URL, spec dialSpec) (*conn, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errSessionClosed
	}
	// Просроченные собираются под мьютексом, а закрываются после его снятия:
	// закрытие — сетевой вызов, и держать под ним весь пул незачем.
	victims := s.sweepLocked(time.Now())

	if c := s.pickLocked(spec); c != nil && !s.opts.DisableKeepAlive {
		c.acquire()
		c.lastUsed = time.Now()
		s.mu.Unlock()
		closeAll(victims)
		return c, nil
	}
	s.mu.Unlock()
	closeAll(victims)

	c, err := s.dial(ctx, u, spec)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		c.close()
		return nil, errSessionClosed
	}
	// Пока шло рукопожатие, соединение мог открыть и другой вызов. Для HTTP/2
	// второе не нужно — потоки мультиплексируются, и новое закрывается.
	// Для HTTP/1.1 параллельные запросы живут на разных соединениях,
	// поэтому новое остаётся.
	if c.h2 != nil && !s.opts.DisableKeepAlive {
		if old := s.pickLocked(spec); old != nil && old.h2 != nil {
			old.acquire()
			old.lastUsed = time.Now()
			s.mu.Unlock()
			c.close()
			return old, nil
		}
	}

	c.acquire()
	c.lastUsed = time.Now()
	list := s.conns[spec]
	if s.opts.DisableKeepAlive {
		// Соединение не попадает в пул вовсе: release закроет его сразу
		// после ответа, и следующий запрос начнёт рукопожатие заново.
		c.pooled = false
	} else if c.h2 != nil || len(list) < maxConnsPerHost {
		s.conns[spec] = append(list, c)
	} else {
		// Сверх предела браузера: соединение живёт один запрос и закрывается
		// в release, чтобы всплеск параллельных запросов не оставил после
		// себя десятки открытых сокетов.
		c.pooled = false
	}
	over := s.evictLRULocked()
	s.mu.Unlock()

	closeAll(victims)
	closeAll(over)
	return c, nil
}

// pickLocked выбирает из пула соединение, готовое принять запрос.
// Вызывается под s.mu.
func (s *Session) pickLocked(spec dialSpec) *conn {
	for _, c := range s.conns[spec] {
		if c.usable() && c.canTake() {
			return c
		}
	}
	return nil
}

// inPoolLocked сообщает, числится ли соединение в пуле. Сравнение по указателю
// обязательно: за время запроса под тем же ключом могло появиться другое.
func (s *Session) inPoolLocked(c *conn) bool {
	for _, x := range s.conns[c.spec] {
		if x == c {
			return true
		}
	}
	return false
}

// removeLocked убирает соединение из пула, если оно там есть.
func (s *Session) removeLocked(c *conn) {
	list := s.conns[c.spec]
	for i, x := range list {
		if x == c {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(s.conns, c.spec)
	} else {
		s.conns[c.spec] = list
	}
}

// release освобождает соединение после того, как тело ответа дочитано.
func (s *Session) release(c *conn) {
	if c == nil {
		return
	}
	if c.release() > 0 {
		return
	}
	s.mu.Lock()
	pooled := c.pooled && s.inPoolLocked(c)
	if pooled {
		// Время простоя считается от возврата, а не от выдачи: иначе долгий
		// поток делал бы соединение «просроченным» в момент, когда оно
		// только что работало.
		c.lastUsed = time.Now()
	}
	s.mu.Unlock()
	// Соединение вне пула больше никому не достанется — закрываем сразу,
	// иначе оно осталось бы висеть до завершения процесса.
	if !pooled {
		c.close()
	}
}

// evict убирает соединение из пула.
//
// hard=false нужен для HTTP/2: Close там документирован как прерывающий
// текущие запросы, и он оборвал бы потоки соседей. После GOAWAY достаточно
// перестать выдавать соединение и дать ему доиграть.
func (s *Session) evict(c *conn, hard bool) {
	if c == nil {
		return
	}
	s.mu.Lock()
	s.removeLocked(c)
	if !hard && c.h2 != nil {
		s.orphans[c] = struct{}{}
		s.mu.Unlock()
		go s.shutdownOrphan(c)
		return
	}
	s.mu.Unlock()
	c.close()
}

// shutdownOrphan мягко доигрывает HTTP/2-соединение и снимает его с учёта.
func (s *Session) shutdownOrphan(c *conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c.shutdown(ctx)

	s.mu.Lock()
	delete(s.orphans, c)
	s.mu.Unlock()
}

// sweepLocked собирает просроченные и непригодные соединения. Вызывается под s.mu.
func (s *Session) sweepLocked(now time.Time) []*conn {
	ttl := s.opts.IdleConnTimeout
	if ttl <= 0 {
		ttl = defaultIdleConnTimeout
	}
	var victims []*conn
	for spec, list := range s.conns {
		kept := list[:0]
		for _, c := range list {
			switch {
			case c.busy.Load() > 0:
				kept = append(kept, c) // занятое не трогаем: его закроет release
			case !c.usable() || now.Sub(c.lastUsed) > ttl:
				victims = append(victims, c)
			default:
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			delete(s.conns, spec)
		} else {
			s.conns[spec] = kept
		}
	}
	return victims
}

// evictLRULocked вытесняет самые давние простаивающие соединения сверх лимита.
//
// Ограничитель нужен не гипотетически: ротационный прокси с идентификатором
// сессии в логине даёт новый dialSpec на каждый запрос, и без предела пул
// вырос бы до тысяч живых сокетов.
func (s *Session) evictLRULocked() []*conn {
	limit := s.opts.MaxIdleConns
	if limit <= 0 {
		limit = defaultMaxIdleConns
	}
	var victims []*conn
	for s.totalLocked() > limit {
		var oldest *conn
		for _, list := range s.conns {
			for _, c := range list {
				if c.busy.Load() > 0 {
					continue
				}
				if oldest == nil || c.lastUsed.Before(oldest.lastUsed) {
					oldest = c
				}
			}
		}
		if oldest == nil {
			break // все заняты — вытеснять некого
		}
		s.removeLocked(oldest)
		victims = append(victims, oldest)
	}
	return victims
}

func (s *Session) totalLocked() int {
	n := 0
	for _, list := range s.conns {
		n += len(list)
	}
	return n
}

func closeAll(conns []*conn) {
	for _, c := range conns {
		c.close()
	}
}
