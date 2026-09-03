// Package client выполняет HTTP-запросы с отпечатком браузера из профиля.
//
// TLS-рукопожатие ведёт uTLS по ClientHelloSpec профиля; протокол выбирается
// сервером через ALPN, список предложений тоже берётся из профиля. Соединения
// переиспользуются по ключу host:port, но спека для каждого нового соединения
// строится заново: Chrome >=110 перемешивает расширения, и постоянный порядок
// сам по себе отличал бы нас от браузера.
package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	"github.com/bogdanfinn/fhttp/http2"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/profile"
)

// DefaultMaxRedirects повторяет предел, принятый в браузерах.
const DefaultMaxRedirects = 20

// Options настраивают сессию.
type Options struct {
	// InsecureSkipVerify отключает проверку сертификата.
	InsecureSkipVerify bool
	// Timeout ограничивает каждый запрос целиком, включая редиректы.
	Timeout time.Duration
	// Proxy — http://, https:// или socks5:// с необязательными user:pass.
	Proxy string

	// DefaultHeaders включает подстановку заголовков профиля.
	// Выключив его, вызывающая сторона полностью управляет набором и порядком —
	// анти-боты смотрят и на порядок, поэтому такой контроль нужен наружу.
	DefaultHeaders bool
	// HeaderOrder переопределяет порядок отправки. Заголовки, которых здесь нет,
	// идут после перечисленных, сохраняя относительный порядок.
	HeaderOrder []string

	// FollowRedirects включает переходы по 3xx.
	FollowRedirects bool
	// MaxRedirects ограничивает длину цепочки. 0 — DefaultMaxRedirects.
	MaxRedirects int

	// Cookies включает cookie-jar, общий для всех запросов сессии.
	Cookies bool

	// ForceHTTP1 запрещает h2 даже если сервер его предлагает.
	ForceHTTP1 bool

	// HTTP3 отправляет запросы по QUIC вместо TCP.
	//
	// Это отдельный транспорт, а не вариант ALPN, поэтому он выбирается явно.
	// Профиль обязан описывать секцию http3, иначе сессия не создастся.
	HTTP3 bool
}

// Request — запрос в терминах библиотеки.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte

	// Multipart, если задан, кодируется в тело с границей в стиле профиля.
	// Взаимоисключающ с Body.
	Multipart *MultipartForm

	// HeaderOrder переопределяет порядок для одного запроса.
	HeaderOrder []string
	// NoDefaultHeaders отключает заголовки профиля для одного запроса.
	NoDefaultHeaders bool
}

// Response — ответ.
type Response struct {
	Status  int
	Headers map[string][]string
	Body    []byte
	Proto   string
	URL     string // конечный URL после редиректов
}

// Session выполняет запросы с одним профилем.
type Session struct {
	profile *profile.Profile
	opts    Options
	alpn    []string
	jar     *cookiejar.Jar

	mu    sync.Mutex
	conns map[string]*conn

	h3 h3Transport
}

// New создаёт сессию. Спека профиля проверяется сразу, чтобы ошибка в данных
// всплыла при создании, а не на первом запросе.
func New(p *profile.Profile, opts Options) (*Session, error) {
	if p == nil {
		return nil, fmt.Errorf("профиль не задан")
	}
	if _, err := profile.BuildSpec(p); err != nil {
		return nil, err
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxRedirects == 0 {
		opts.MaxRedirects = DefaultMaxRedirects
	}

	s := &Session{
		profile: p,
		opts:    opts,
		alpn:    alpnFromProfile(p),
		conns:   make(map[string]*conn),
	}
	if opts.ForceHTTP1 {
		s.alpn = []string{"http/1.1"}
	}
	if opts.Cookies {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("cookie-jar: %w", err)
		}
		s.jar = jar
	}
	// Отсутствие секции http3 в профиле должно вскрываться при создании сессии,
	// а не на первом запросе.
	if opts.HTTP3 && !p.HTTP3.Enabled() {
		return nil, fmt.Errorf("профиль %q не описывает HTTP/3", p.Name)
	}
	return s, nil
}

// Close закрывает все соединения сессии.
func (s *Session) Close() {
	s.closeH3()

	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.conns {
		c.close()
		delete(s.conns, k)
	}
}

// Do выполняет запрос, при необходимости проходя цепочку редиректов,
// и возвращает тело целиком.
func (s *Session) Do(r *Request) (*Response, error) {
	stream, err := s.DoStream(r)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	data, err := io.ReadAll(stream)
	if err != nil {
		return nil, fmt.Errorf("чтение ответа: %w", err)
	}
	return &Response{
		Status:  stream.Status,
		Headers: stream.Headers,
		Body:    data,
		Proto:   stream.Proto,
		URL:     stream.URL,
	}, nil
}

// prepare разворачивает multipart-форму в тело запроса.
func (s *Session) prepare(r *Request) (Request, error) {
	out := *r
	if out.Multipart == nil {
		return out, nil
	}
	if len(out.Body) > 0 {
		return out, fmt.Errorf("заданы одновременно Body и Multipart")
	}
	body, contentType, err := encodeMultipart(out.Multipart, s.profile.FormBoundaryStyle())
	if err != nil {
		return out, err
	}
	out.Body = body
	if out.Headers == nil {
		out.Headers = map[string]string{}
	}
	// Границу нельзя задать снаружи: она сгенерирована здесь и должна
	// совпасть с телом.
	out.Headers["content-type"] = contentType
	out.Multipart = nil
	return out, nil
}

// send выполняет один запрос без учёта редиректов. Тело ответа остаётся
// открытым — закрыть его обязан вызывающий.
func (s *Session) send(r *Request) (*http.Response, error) {
	u, err := url.Parse(r.URL)
	if err != nil {
		return nil, fmt.Errorf("разбор URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("поддерживается только https, получено %q", u.Scheme)
	}

	if s.opts.HTTP3 {
		resp, err := s.sendH3(r, u)
		if err != nil {
			return nil, err
		}
		return fromStdResponse(resp), nil
	}

	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if len(r.Body) > 0 {
		body = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequest(method, r.URL, body)
	if err != nil {
		return nil, err
	}
	s.applyHeaders(req, r, u)

	c, err := s.conn(u)
	if err != nil {
		return nil, err
	}

	resp, err := c.roundTrip(req)
	if err != nil {
		// Соединение могло протухнуть — выбрасываем, чтобы следующий запрос
		// переустановил TLS, а не бился в закрытый сокет.
		s.drop(hostKey(u))
		return nil, fmt.Errorf("запрос: %w", err)
	}

	if s.jar != nil {
		if cookies := resp.Cookies(); len(cookies) > 0 {
			s.jar.SetCookies(u, cookies)
		}
	}
	return resp, nil
}

func (s *Session) conn(u *url.URL) (*conn, error) {
	key := hostKey(u)

	s.mu.Lock()
	if c, ok := s.conns[key]; ok && c.usable() {
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Unlock()

	c, err := s.dial(u)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Пока мы устанавливали соединение, его мог установить и другой вызов.
	if old, ok := s.conns[key]; ok && old.usable() {
		c.close()
		return old, nil
	}
	if old, ok := s.conns[key]; ok {
		old.close()
	}
	s.conns[key] = c
	return c, nil
}

func (s *Session) drop(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.conns[key]; ok {
		c.close()
		delete(s.conns, key)
	}
}

func (s *Session) dial(u *url.URL) (*conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.opts.Timeout)
	defer cancel()

	raw, err := s.dialRaw(ctx, hostKey(u))
	if err != nil {
		return nil, err
	}

	// Спека строится на каждое соединение: ShuffleChromeTLSExtensions мутирует
	// слайс на месте, поэтому переиспользование заморозило бы порядок.
	spec, err := profile.BuildSpec(s.profile)
	if err != nil {
		raw.Close()
		return nil, err
	}

	// ALPN живёт в самой спеке, и ApplyPreset перекрывает Config.NextProtos.
	// Поэтому ограничение протокола — это правка расширения, а не конфигурации.
	// Отпечаток при этом меняется законно: браузер без h2 так и выглядит.
	if s.opts.ForceHTTP1 {
		if !setALPN(spec, []string{"http/1.1"}) {
			raw.Close()
			return nil, fmt.Errorf("force_http1: в профиле %q нет расширения ALPN", s.profile.Name)
		}
	}

	cfg := &utls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: s.opts.InsecureSkipVerify,
		// Профили, снятые с возобновлённого соединения, содержат pre_shared_key.
		// На первом соединении тикета ещё нет, и uTLS по умолчанию отказывается
		// слать пустое расширение. Браузер в этой ситуации его просто не шлёт —
		// OmitEmptyPsk воспроизводит именно это поведение.
		OmitEmptyPsk: true,
	}
	if len(s.alpn) > 0 {
		cfg.NextProtos = s.alpn
	}

	uconn := utls.UClient(raw, cfg, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		raw.Close()
		return nil, fmt.Errorf("ApplyPreset: %w", err)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	// Протокол выбрал сервер. Пустой ALPN означает HTTP/1.1 — так ведут себя
	// профили браузеров, которые h2 не предлагают.
	switch proto := uconn.ConnectionState().NegotiatedProtocol; proto {
	case "h2":
		cc, err := s.transport().NewClientConn(uconn)
		if err != nil {
			uconn.Close()
			return nil, fmt.Errorf("h2: %w", err)
		}
		return newH2Conn(cc), nil
	case "http/1.1", "":
		return newH1Conn(uconn), nil
	default:
		uconn.Close()
		return nil, fmt.Errorf("сервер согласовал %q — протокол не поддерживается", proto)
	}
}

// transport собирает HTTP/2-транспорт по профилю.
func (s *Session) transport() *http2.Transport {
	h2 := s.profile.HTTP2

	settings := make(map[http2.SettingID]uint32, len(h2.Settings))
	order := make([]http2.SettingID, 0, len(h2.Settings))
	for _, st := range h2.Settings {
		id := http2.SettingID(st.ID)
		settings[id] = st.Value
		order = append(order, id)
	}

	// TLSClientConfig не задаём: рукопожатие делает uTLS, а в NewClientConn
	// передаётся уже установленное соединение.
	tr := &http2.Transport{
		Settings:          settings,
		SettingsOrder:     order,
		ConnectionFlow:    h2.ConnectionWindowUpdate,
		PseudoHeaderOrder: h2.PseudoOrder,
	}
	// Приоритет на HEADERS-кадре.
	//
	// Значение 0 означает «не отправлять»: так ведёт себя Safari. Нулевой
	// PriorityParam не выставляет флаг PRIORITY, тогда как nil заставил бы
	// fhttp подставить свой дефолт (вес 255, exclusive) — он случайно верен
	// для Chrome и неверен для всех остальных.
	if h2.StreamWeight != nil {
		if *h2.StreamWeight == 0 {
			tr.HeaderPriority = &http2.PriorityParam{}
		} else {
			excl := h2.StreamExclusive != nil && *h2.StreamExclusive
			// На проводе вес на единицу меньше заявленного (RFC 7540).
			tr.HeaderPriority = &http2.PriorityParam{
				StreamDep: 0,
				Exclusive: excl,
				Weight:    uint8(*h2.StreamWeight - 1),
			}
		}
	}
	return tr
}

func hostKey(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), "443")
}
