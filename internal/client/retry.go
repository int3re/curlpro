package client

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"

	// Тот же форк, что и в остальном клиенте: типы ответов должны совпадать.
	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
)

// Повтор запросов.
//
// По умолчанию повторяются только идемпотентные методы. Повтор POST может
// создать второй заказ или второй платёж: сервер мог обработать запрос
// и не успеть ответить, и клиент этого не различает. Поэтому разрешение
// повторять неидемпотентное — осознанный выбор вызывающего.

// DefaultRetryStatuses — коды, при которых повтор осмыслен.
//
// 429 и 503 сервер шлёт, прямо приглашая повторить; 500, 502 и 504 обычно
// означают временный сбой инфраструктуры. 4xx кроме 408 и 429 не повторяются:
// на неверный запрос второй такой же ответит так же.
var DefaultRetryStatuses = []int{
	http.StatusRequestTimeout,      // 408
	http.StatusTooManyRequests,     // 429
	http.StatusInternalServerError, // 500
	http.StatusBadGateway,          // 502
	http.StatusServiceUnavailable,  // 503
	http.StatusGatewayTimeout,      // 504
}

// idempotentMethods — методы, повтор которых безопасен по RFC 9110.
var idempotentMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodTrace:   true,
	http.MethodPut:     true,
	http.MethodDelete:  true,
}

// RetryPolicy описывает поведение повторов.
type RetryPolicy struct {
	// Attempts — сколько дополнительных попыток после первой.
	// Ноль означает «без повторов».
	Attempts int

	// Statuses — коды ответа, при которых повторять.
	// Пусто означает DefaultRetryStatuses.
	Statuses []int

	// Methods — методы, которые разрешено повторять.
	// Пусто означает только идемпотентные.
	Methods []string

	// Backoff — задержка перед первым повтором; дальше удваивается.
	// Ноль означает 200 мс.
	Backoff time.Duration

	// MaxBackoff ограничивает задержку. Ноль означает 10 с.
	MaxBackoff time.Duration

	// RespectRetryAfter учитывает одноимённый заголовок.
	// Сервер, который просит подождать, знает лучше формулы.
	RespectRetryAfter bool
}

func (p *RetryPolicy) attempts() int {
	if p == nil {
		return 0
	}
	return p.Attempts
}

func (p *RetryPolicy) backoff() time.Duration {
	if p == nil || p.Backoff <= 0 {
		return 200 * time.Millisecond
	}
	return p.Backoff
}

func (p *RetryPolicy) maxBackoff() time.Duration {
	if p == nil || p.MaxBackoff <= 0 {
		return 10 * time.Second
	}
	return p.MaxBackoff
}

// isIdempotent сообщает, безопасен ли повтор метода по RFC 9110.
func isIdempotent(method string) bool {
	if method == "" {
		return true
	}
	return idempotentMethods[strings.ToUpper(method)]
}

// unprocessedError помечает сбой, при котором запрос заведомо не дошёл
// до обработки сервером: его можно повторять даже для POST.
type unprocessedError struct{ err error }

func (e *unprocessedError) Error() string { return e.err.Error() }
func (e *unprocessedError) Unwrap() error { return e.err }

// fatalError помечает сбой, который повтор не исправит: сервер согласовал
// не тот протокол, которого потребовал вызывающий, или профиль не описывает
// затребованный транспорт. Со второй попытки будет ровно то же самое,
// а при retries=3 это три лишних рукопожатия.
type fatalError struct{ err error }

func (e *fatalError) Error() string { return e.err.Error() }
func (e *fatalError) Unwrap() error { return e.err }

// isFatal сообщает, что повторять нечего.
func isFatal(err error) bool {
	var fe *fatalError
	return errors.As(err, &fe)
}

// h2Unprocessed распознаёт ошибки HTTP/2, при которых поток не обрабатывался.
//
// Тот же набор, что у net/http canRetryError: непригодное соединение (запрос
// не отправлялся), GOAWAY с last-stream-id ниже нашего (сервер объявил, что
// поток не обработан) и REFUSED_STREAM. Первые два в fhttp не экспортируются,
// поэтому распознаются по тексту.
func h2Unprocessed(err error) bool {
	var se http2.StreamError
	if errors.As(err, &se) {
		return se.Code == http2.ErrCodeRefusedStream
	}
	msg := err.Error()
	return strings.Contains(msg, "client conn not usable") ||
		strings.Contains(msg, "Server's graceful shutdown GOAWAY")
}

// allowsMethod сообщает, разрешено ли повторять этот метод.
func (p *RetryPolicy) allowsMethod(method string) bool {
	if method == "" {
		method = http.MethodGet
	}
	if p != nil && len(p.Methods) > 0 {
		for _, m := range p.Methods {
			if strings.EqualFold(m, method) {
				return true
			}
		}
		return false
	}
	return idempotentMethods[strings.ToUpper(method)]
}

// allowsStatus сообщает, повторять ли при таком коде ответа.
func (p *RetryPolicy) allowsStatus(code int) bool {
	list := DefaultRetryStatuses
	if p != nil && len(p.Statuses) > 0 {
		list = p.Statuses
	}
	for _, c := range list {
		if c == code {
			return true
		}
	}
	return false
}

// delay вычисляет паузу перед попыткой n (нумерация с единицы).
//
// Экспонента с полным джиттером: без него все клиенты, получившие 503
// одновременно, повторят тоже одновременно и добьют сервер.
func (p *RetryPolicy) delay(n int, resp *http.Response) time.Duration {
	if p != nil && p.RespectRetryAfter && resp != nil {
		if d, ok := parseRetryAfter(resp.Header.Get("Retry-After")); ok {
			if d > p.maxBackoff() {
				return p.maxBackoff()
			}
			return d
		}
	}

	base := p.backoff()
	for i := 1; i < n; i++ {
		base *= 2
		if base >= p.maxBackoff() {
			base = p.maxBackoff()
			break
		}
	}
	return jitter(base)
}

// jitter размазывает задержку по отрезку [base/2, base].
func jitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	half := int64(base / 2)
	if half <= 0 {
		return base
	}
	n, err := rand.Int(rand.Reader, big.NewInt(half))
	if err != nil {
		return base
	}
	return time.Duration(half + n.Int64())
}

// parseRetryAfter разбирает заголовок в обеих формах: секунды и HTTP-дата.
func parseRetryAfter(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d, true
		}
		return 0, true // дата в прошлом — можно повторять сразу
	}
	return 0, false
}

// retryPolicy возвращает политику для запроса с учётом переопределения.
func (s *Session) retryPolicy(r *Request) *RetryPolicy {
	if r != nil && r.Retry != nil {
		return r.Retry
	}
	return s.opts.Retry
}
