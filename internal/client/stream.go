package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync/atomic"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

// Stream — ответ, тело которого читается по частям.
//
// Обычный Do() материализует тело целиком: для мегабайтных загрузок это лишняя
// память и задержка до первого байта. Stream отдаёт тело потоком, но требует
// обязательного Close, иначе соединение останется занятым.
// Redirect — шаг цепочки: чем ответил сервер и куда отправил.
//
// Клиент проходит цепочку сам, и без этого вызывающий видел только конечный
// ответ: понять, был ли переход и через какие адреса, было нельзя.
type Redirect struct {
	Status   int    `json:"status"`
	URL      string `json:"url"`
	Location string `json:"location"`
}

type Stream struct {
	Status  int
	Headers map[string][]string
	Proto   string
	URL     string
	// History — промежуточные ответы, от первого к последнему.
	History []Redirect

	body io.ReadCloser

	// closed атомарный: Close приходит и из GC-потока Python (__del__),
	// и из явного вызова, а обычный bool дал бы двойное закрытие.
	closed atomic.Bool

	// cancel освобождает контекст таймаута. Без него отмена продолжила бы
	// тикать на уже завершённом запросе — и утекала бы до её срабатывания.
	cancel context.CancelFunc

	// conn и sess нужны, чтобы отпустить соединение ровно тогда, когда тело
	// дочитано: для HTTP/1.1 до этого момента писать следующий запрос нельзя.
	conn *conn
	sess *Session
}

// Read читает очередную часть тела.
func (s *Stream) Read(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("поток закрыт")
	}
	return s.body.Read(p)
}

// Close освобождает соединение. Повторный вызов безопасен.
func (s *Stream) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	err := s.body.Close()
	if s.cancel != nil {
		s.cancel()
	}
	if s.sess != nil {
		s.sess.release(s.conn)
	}
	return err
}

// DoStream выполняет запрос с повторами и редиректами, возвращая поток
// вместо готового тела.
//
// Повтор охватывает всю цепочку редиректов целиком: повторять её середину
// бессмысленно, потому что промежуточные ответы уже отброшены.
// DoStream выполняет запрос и отдаёт поток ответа.
//
// Ответ с Critical-CH повторяется один раз: Chrome в этом случае не ждёт
// следующего запроса, а сразу переспрашивает с подсказками, которые сайт
// объявил критичными.
func (s *Session) DoStream(r *Request) (*Stream, error) {
	stream, err := s.doStream(r)
	if err != nil || stream == nil {
		return stream, err
	}
	if u, uerr := url.Parse(stream.URL); uerr == nil {
		s.noteAltSvc(u, stream.Headers)
	}
	if u, uerr := url.Parse(stream.URL); uerr == nil && s.noteAcceptCH(u, stream.Headers) {
		stream.Close()
		if retried, rerr := s.doStream(r); rerr == nil {
			if u2, uerr2 := url.Parse(retried.URL); uerr2 == nil {
				s.noteAcceptCH(u2, retried.Headers)
			}
			return retried, nil
		}
		return nil, err
	}
	return stream, nil
}

func (s *Session) doStream(r *Request) (*Stream, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	limit := s.timeout(r)
	deadline := time.Now().Add(limit)
	policy := s.retryPolicy(r)

	for attempt := 0; ; attempt++ {
		stream, outcome, err := s.attempt(r, deadline, limit)
		if err == nil {
			return stream, nil
		}

		exhausted := attempt >= policy.attempts()
		// Повтор неидемпотентного метода может создать второй заказ: сервер
		// мог обработать запрос и не успеть ответить. Разрешение в Methods
		// снимает запрет для ответов сервера (он ответил, значит, обработал
		// и приглашает повторить), но не для сетевых сбоев после отправки:
		// там повтор безопасен, только если запрос заведомо не обрабатывался.
		forbidden := !policy.allowsMethod(r.Method)
		if !forbidden && outcome.stream == nil && !isIdempotent(r.Method) && !outcome.unprocessed {
			forbidden = true
		}

		if !outcome.retryable || exhausted || forbidden {
			// Ответ сервера — это результат, а не сбой клиента. Исчерпав
			// попытки, отдаём последний ответ наружу: так делают curl
			// и urllib3, и это согласуется с тем, что raise_for_status
			// здесь тоже добровольный.
			if outcome.stream != nil {
				return outcome.stream, nil
			}
			return nil, err
		}

		wait := policy.delay(attempt+1, outcome.header)
		if time.Now().Add(wait).After(deadline) {
			if outcome.stream != nil {
				return outcome.stream, nil
			}
			return nil, fmt.Errorf("%w (повтор не укладывается в таймаут %s)", err, limit)
		}
		// Сон прерывается дедлайном: иначе на исходе бюджета клиент
		// просыпается уже за пределом и всё равно бьёт сервер.
		select {
		case <-time.After(wait):
		case <-time.After(time.Until(deadline)):
			if outcome.stream != nil {
				return outcome.stream, nil
			}
			return nil, fmt.Errorf("таймаут запроса (%s)", limit)
		}
		// Удержанный ответ наружу не уйдёт — его сменит следующая попытка.
		// Раньше он просто терялся вместе с телом, занятостью соединения
		// и отменой контекста: HTTP/1.1-соединение оставалось «занятым»
		// навсегда, и каждый следующий запрос к хосту поднимал новый TLS.
		outcome.stream.discard()
	}
}

// discard дочитывает начало тела и закрывает поток, не отдавая его наружу.
//
// Дочитывается не всё: тело нужно только ради переиспользования соединения,
// и враждебный 503 с гигабайтным телом дренировать целиком незачем — h1Body
// сам выбросит соединение, если тело не кончилось.
func (st *Stream) discard() {
	if st == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(st.body, drainLimit+1))
	_ = st.Close()
}

// attemptOutcome описывает исход попытки.
//
// stream не nil, когда сервер ответил кодом из списка повторяемых: такой ответ
// сохраняется целиком, чтобы отдать его наружу, если попытки закончатся.
//
// unprocessed означает, что запрос заведомо не дошёл до обработки: не удалось
// установить соединение либо HTTP/2 отверг поток до обработки (GOAWAY с меньшим
// last-stream-id, REFUSED_STREAM, непригодное соединение). Только такие сбои
// безопасно повторять для неидемпотентных методов: сетевая ошибка после
// отправки не различает «сервер не получил» и «сервер обработал и не ответил».
type attemptOutcome struct {
	retryable   bool
	unprocessed bool
	header      *http.Response // для чтения Retry-After
	stream      *Stream        // ответ сервера, если он получен
}

// attempt выполняет одну попытку: цепочку редиректов целиком.
//
// Возвращает признак, стоит ли повторять, и ответ, из которого можно
// прочитать Retry-After.
func (s *Session) attempt(r *Request, deadline time.Time, limit time.Duration) (
	*Stream, attemptOutcome, error) {

	maxHops := s.maxRedirects(r)
	follow := s.followRedirects(r)

	current, err := s.prepare(r)
	if err != nil {
		return nil, attemptOutcome{}, err
	}
	// Инициатор цепочки: от него считается sec-fetch-site на каждом хопе.
	initiator := current.URL
	var history []Redirect

	policy := s.retryPolicy(r)

	for hop := 0; ; hop++ {
		if time.Now().After(deadline) {
			return nil, attemptOutcome{}, fmt.Errorf("таймаут запроса (%s)", limit)
		}

		resp, cancel, used, err := s.send(&current, deadline)
		if err != nil {
			// Сетевая ошибка: соединение уже выброшено из пула в send(),
			// поэтому повтор установит TLS заново.
			var up *unprocessedError
			return nil, attemptOutcome{retryable: true, unprocessed: errors.As(err, &up)}, err
		}

		// Код ответа, при котором сервер сам приглашает повторить.
		// Ответ сохраняется целиком: если попытки закончатся, он уйдёт наружу.
		if policy.attempts() > 0 && policy.allowsStatus(resp.StatusCode) {
			held := &Stream{
				Status:  resp.StatusCode,
				Headers: resp.Header,
				Proto:   resp.Proto,
				URL:     current.URL,
				body:    resp.Body,
				cancel:  cancel,
				conn:    used,
				sess:    s,
			}
			return nil, attemptOutcome{retryable: true, header: resp, stream: held},
				fmt.Errorf("сервер ответил %s", resp.Status)
		}

		next := ""
		if follow && isRedirect(resp.StatusCode) {
			if location := resp.Header.Get("Location"); location != "" {
				target, err := redirectTarget(current.URL, location)
				switch {
				case err == nil:
					next = target
					history = append(history, Redirect{
						Status:   resp.StatusCode,
						URL:      current.URL,
						Location: location,
					})
				case errors.Is(err, errRedirectUnsupported):
					// Переход невозможен по нашим возможностям, а не по
					// протоколу: ответ отдаётся как есть, с Location внутри.
				default:
					drain(resp, cancel)
					s.release(used)
					return nil, attemptOutcome{}, err
				}
			}
		}
		if next == "" {
			// Тело здесь уже распаковано: HTTP/2 распаковывает транспорт
			// fhttp, HTTP/1.1 — conn.roundTrip, HTTP/3 — sendH3. Заголовок
			// Content-Encoding при этом остаётся, поэтому повторная
			// распаковка развалилась бы на несовпадении сигнатуры.
			return &Stream{
				Status:  resp.StatusCode,
				Headers: resp.Header,
				Proto:   resp.Proto,
				URL:     current.URL,
				History: history,
				body:    resp.Body,
				cancel:  cancel,
				conn:    used,
				sess:    s,
			}, attemptOutcome{}, nil
		}

		// Тело промежуточного ответа дочитывается ограниченно; если оно
		// не кончилось, соединение переиспользовать нельзя.
		if !drain(resp, cancel) {
			s.evict(used, true)
		}
		s.release(used)

		if hop >= maxHops {
			return nil, attemptOutcome{}, fmt.Errorf("превышен предел редиректов (%d)", maxHops)
		}
		current = s.nextRequest(&current, next, resp.StatusCode, initiator)
	}
}

// drainLimit — сколько байт тела дочитывается ради переиспользования
// соединения. Столько же берёт net/http.
//
// Без предела враждебный 503 с гигабайтным телом вычитывался бы целиком
// на каждой попытке повтора.
const drainLimit = 2 << 10

// drain дочитывает начало тела и закрывает его, снимая таймаут запроса.
//
// Сообщает, кончилось ли тело в пределах лимита. Если нет, соединение
// переиспользовать нельзя: в сокете остались непрочитанные байты, и следующий
// запрос разобрал бы ответ из них.
func drain(resp *http.Response, cancel context.CancelFunc) (drained bool) {
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit+1))
	resp.Body.Close()
	if cancel != nil {
		cancel()
	}
	return n <= drainLimit && (err == nil || err == io.EOF)
}
