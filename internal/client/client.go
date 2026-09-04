// Package client выполняет HTTP-запросы с отпечатком браузера из профиля.
//
// TLS-рукопожатие ведёт uTLS по ClientHelloSpec профиля; протокол выбирается
// сервером через ALPN, список предложений тоже берётся из профиля. Соединения
// переиспользуются по ключу host:port, но спека для каждого нового соединения
// строится заново: Chrome >=110 перемешивает расширения, и постоянный порядок
// сам по себе отличал бы нас от браузера.
package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
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

	// MaxIdleConns ограничивает число соединений в пуле. 0 — 64.
	//
	// Предел нужен не гипотетически: ротационный прокси с идентификатором
	// сессии в логине даёт новое соединение на каждый запрос.
	MaxIdleConns int
	// IdleConnTimeout — сколько держать неиспользуемое соединение. 0 — 300 с,
	// столько же держит Chrome.
	IdleConnTimeout time.Duration
	// ConnectTimeout ограничивает установку соединения отдельно от Timeout:
	// разрешение имени, TCP и рукопожатие TLS. 0 — только общий предел.
	//
	// Нужен там, где узел молчит: без отдельного предела запрос ждёт весь
	// свой бюджет на мёртвом адресе, хотя понятно всё за секунду.
	// Чтение ответа этим пределом не ограничивается — на него работает Timeout.
	ConnectTimeout time.Duration

	// CACert — путь к своему корневому сертификату (PEM) вместо системных.
	//
	// Нужен для стендов, корпоративных сетей и перехватывающих прокси:
	// без него оставалось только выключить проверку целиком.
	CACert string
	// ClientCert и ClientKey включают взаимную аутентификацию (mTLS).
	ClientCert string
	ClientKey  string

	// TrustEnv разрешает брать прокси из переменных окружения
	// HTTPS_PROXY, HTTP_PROXY и NO_PROXY, как это делают curl и requests.
	// Явно заданный Proxy всегда сильнее.
	TrustEnv bool

	// MaxResponseSize ограничивает тело ответа. 0 — без предела.
	//
	// Без ограничения враждебный или сломанный сервер с бесконечным телом
	// съедает память процесса целиком: для парсера это не теория.
	MaxResponseSize int64

	// DisableAltSvc выключает автопереход на HTTP/3 по заголовку Alt-Svc.
	//
	// По умолчанию переход включён: так делает браузер — первый запрос
	// к сайту всегда идёт по TCP, а на HTTP/3 клиент переходит, только
	// увидев объявление. Выключать стоит там, где UDP заведомо закрыт
	// и лишняя попытка только тратит время.
	DisableAltSvc bool

	// Resolve подменяет адрес узла, не трогая имя в SNI и заголовке Host.
	//
	// Ключ — "host:port" или просто "host" (тогда правило действует на любой
	// порт), значение — "ip" или "ip:port". Аналог --resolve у curl: нужен,
	// чтобы ходить на конкретный сервер за балансировщиком или проверять
	// стенд под настоящим именем. Отпечаток при этом не меняется: имя
	// остаётся тем же, меняется только куда открывается сокет.
	Resolve map[string]string

	// IPVersion ограничивает семейство адресов: "4", "6" или пусто.
	//
	// Нужен там, где у имени есть запись AAAA, но маршрута по IPv6 нет:
	// без ограничения соединение сначала уходит в таймаут.
	IPVersion string

	// DisableKeepAlive выключает переиспользование: каждый запрос получает
	// своё соединение, и оно закрывается сразу после ответа.
	//
	// Полярность как у net/http.Transport.DisableKeepAlives — нулевое
	// значение сохраняет обычное поведение. Заголовок «Connection: close»
	// при этом не отправляется: браузер его не шлёт, и он выдал бы клиента.
	// Клиент просто закрывает сокет, как браузер закрывает простаивающий.
	DisableKeepAlive bool

	// ForceHTTP1 запрещает h2 даже если сервер его предлагает.
	ForceHTTP1 bool

	// HTTP3 отправляет запросы по QUIC вместо TCP.
	//
	// Это отдельный транспорт, а не вариант ALPN, поэтому он выбирается явно.
	// Профиль обязан описывать секцию http3, иначе сессия не создастся.
	HTTP3 bool

	// Retry задаёт повторы. nil означает, что повторов нет.
	Retry *RetryPolicy

	// Mode выбирает набор заголовков: "navigate" — переход по адресу,
	// "fetch" — fetch/XHR, "" или "auto" — по признакам запроса (см. modeFor).
	Mode string

	// Device — имя устройства из секции devices профиля; "random" — случайное
	// из списка. Пусто — устройство не выбирается, и подсказки высокой
	// энтропии остаются со значениями профиля.
	//
	// Устройство держится на сессию: настоящий клиент телефон между запросами
	// не меняет, и смена в середине была бы приметой сама по себе.
	Device string
	// Devices переопределяет список устройств профиля.
	Devices []profile.Device
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

	// BodyFile — путь к файлу, который отправляется телом запроса.
	//
	// Файл читается потоком, а не целиком в память: отправка гигабайтного
	// архива не должна требовать гигабайта памяти. Взаимоисключающ с Body.
	BodyFile string
	// BodySize — размер тела для Content-Length. Ноль при заданном BodyFile
	// означает «взять из файла».
	BodySize int64

	// HeaderOrder переопределяет порядок для одного запроса.
	HeaderOrder []string
	// DefaultHeaders включает или отключает заголовки профиля для одного
	// запроса. nil — как задано у сессии.
	//
	// Указатель, а не bool: сессия может отключить их целиком, и тогда
	// отдельному запросу нужен способ вернуть их обратно.
	DefaultHeaders *bool

	// Protocol насильно задаёт транспорт для одного запроса: ProtoHTTP1,
	// ProtoH2 или ProtoH3. Пусто — как решает сессия: её опции, а на прямых
	// соединениях ещё и Alt-Svc.
	//
	// Указание сильнее и того и другого: вызывающий просит протокол,
	// а не совета.
	Protocol string

	// Переопределения сессионных настроек на один запрос.
	// nil означает «взять из сессии» — это отличает «не задано» от «задано
	// в ноль», что для таймаута и редиректов принципиально разные вещи.

	// Timeout ограничивает этот запрос целиком, включая редиректы и повторы.
	Timeout *time.Duration
	// ConnectTimeout переопределяет предел на установку соединения.
	ConnectTimeout *time.Duration
	// FollowRedirects переопределяет переходы по 3xx.
	FollowRedirects *bool
	// MaxRedirects переопределяет предел длины цепочки.
	MaxRedirects *int
	// Retry переопределяет политику повторов для этого запроса.
	Retry *RetryPolicy

	// Proxy переопределяет прокси сессии.
	//
	// nil означает «взять из сессии», пустая строка — идти напрямую в обход
	// сессионного прокси. Это разные вещи, поэтому указатель, а не строка.
	Proxy *string

	// SuppressHeaders гасит заголовки по имени уже после сборки из профиля.
	//
	// Нужно для случаев вроде sec-fetch-user: он приходит из профиля,
	// и удаление из Headers его не затронуло бы.
	SuppressHeaders []string

	// RedirectHop помечает запрос как шаг цепочки редиректов. Chromium на
	// таком шаге ставит client hints (sec-ch-ua*) не в начало, а после
	// Sec-Fetch-Dest — см. buildHeaders.
	RedirectHop bool

	// Mode переопределяет Options.Mode для одного запроса.
	Mode string

	// Ctx — родительский контекст запроса. nil означает context.Background.
	//
	// Нужен для отмены снаружи: асинхронный вызов из Python отменяется, когда
	// задача asyncio снята, и без контекста запрос продолжал бы жить до своего
	// таймаута, занимая соединение.
	Ctx context.Context
}

// context возвращает родительский контекст запроса.
func (r *Request) context() context.Context {
	if r != nil && r.Ctx != nil {
		return r.Ctx
	}
	return context.Background()
}

// Значения Request.Protocol.
//
// h2 не урезает список ALPN до одного значения: набор из единственного h2
// не шлёт ни один браузер, и подделка отпечатка на этом бы и кончилась.
// Поэтому h2 означает «не уходить в QUIC и не соглашаться на HTTP/1.1»:
// если сервер согласовал http/1.1, запрос падает с внятной ошибкой.
const (
	ProtoHTTP1 = "http1"
	ProtoH2    = "h2"
	ProtoH3    = "h3"
)

// protocol возвращает затребованный запросом транспорт.
func (r *Request) protocol() string {
	if r == nil {
		return ""
	}
	return r.Protocol
}

// useDefaultHeaders решает, добавлять ли заголовки профиля.
func (s *Session) useDefaultHeaders(r *Request) bool {
	if r != nil && r.DefaultHeaders != nil {
		return *r.DefaultHeaders
	}
	return s.opts.DefaultHeaders
}

// proxyFor возвращает адрес прокси для запроса.
func (s *Session) proxyFor(r *Request) string {
	if r != nil && r.Proxy != nil {
		return *r.Proxy
	}
	return s.opts.Proxy
}

// proxyForHost возвращает прокси с учётом переменных окружения.
//
// Явно заданный прокси всегда сильнее: окружение — это умолчание, а не
// приказ. Пустая строка в запросе означает «идти напрямую», и окружение
// её тоже не перебивает.
func (s *Session) proxyForHost(r *Request, host string) string {
	if r != nil && r.Proxy != nil {
		return *r.Proxy
	}
	if s.opts.Proxy != "" {
		return s.opts.Proxy
	}
	if s.opts.TrustEnv {
		return proxyFromEnv(host)
	}
	return ""
}

// connectLimitKey помечает предел на установку соединения в контексте.
type connectLimitKey struct{}

// withConnectLimit кладёт переопределение запроса в контекст.
//
// Значением в контексте, а не аргументом: до dial ведут три пути — пул
// соединений, апгрейд до HTTP/3 и WebSocket, — и лишний параметр пришлось бы
// протаскивать через каждый.
func withConnectLimit(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, connectLimitKey{}, d)
}

// connectContext ограничивает фазу установки соединения.
//
// Возвращает исходный контекст, если отдельного предела нет: лишний слой
// с отменой на каждое соединение стоил бы дороже, чем экономит.
func (s *Session) connectContext(ctx context.Context) (context.Context, context.CancelFunc) {
	limit := s.opts.ConnectTimeout
	if d, ok := ctx.Value(connectLimitKey{}).(time.Duration); ok && d > 0 {
		limit = d
	}
	if limit <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, limit)
}

// timeout возвращает предел для запроса с учётом переопределения.
//
// Ноль отвергается на входе (New и validate), поэтому здесь он означать ничего
// не может: раньше ноль в опциях подставлял 30 секунд, а ноль в запросе давал
// мгновенный таймаут — одно и то же число значило противоположное.
func (s *Session) timeout(r *Request) time.Duration {
	if r != nil && r.Timeout != nil {
		return *r.Timeout
	}
	return s.opts.Timeout
}

// validate проверяет переопределения запроса до отправки.
func (r *Request) validate() error {
	if r == nil {
		return nil
	}
	if r.Timeout != nil && *r.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive, got %s "+
			"(leave it unset for no limit)", *r.Timeout)
	}
	if r.ConnectTimeout != nil && *r.ConnectTimeout <= 0 {
		return fmt.Errorf("connect timeout must be positive, got %s "+
			"(leave it unset for no limit)", *r.ConnectTimeout)
	}
	switch r.Protocol {
	case "", ProtoHTTP1, ProtoH2, ProtoH3:
	default:
		return fmt.Errorf("unknown protocol %q: use %q, %q or %q",
			r.Protocol, ProtoHTTP1, ProtoH2, ProtoH3)
	}
	if r.MaxRedirects != nil && *r.MaxRedirects < 0 {
		return fmt.Errorf("max_redirects cannot be negative, got %d",
			*r.MaxRedirects)
	}
	return nil
}

// followRedirects сообщает, переходить ли по 3xx для этого запроса.
func (s *Session) followRedirects(r *Request) bool {
	if r != nil && r.FollowRedirects != nil {
		return *r.FollowRedirects
	}
	return s.opts.FollowRedirects
}

// maxRedirects возвращает предел длины цепочки для этого запроса.
func (s *Session) maxRedirects(r *Request) int {
	if r != nil && r.MaxRedirects != nil && *r.MaxRedirects > 0 {
		return *r.MaxRedirects
	}
	return s.opts.MaxRedirects
}

// Response — ответ.
type Response struct {
	Status  int
	Headers map[string][]string
	Body    []byte
	Proto   string
	URL     string // конечный URL после редиректов
	// History — пройденные редиректы, от первого к последнему.
	History []Redirect
}

// Session выполняет запросы с одним профилем.
type Session struct {
	profile *profile.Profile
	opts    Options
	alpn    []string
	jar     *cookiejar.Jar

	mu    sync.Mutex
	conns map[dialSpec][]*conn

	// orphans — HTTP/2-соединения, выведенные из пула, но ещё доигрывающие
	// текущие потоки. Без учёта они утекли бы вместе с горутиной чтения.
	orphans map[*conn]struct{}

	// closed под тем же мьютексом, что и пул: иначе запрос, начатый
	// одновременно с Close, оставил бы соединение без владельца.
	closed bool

	// headers — заголовки, добавленные пользователем к сессии. Хранятся
	// отдельно от профильных, чтобы ResetHeaders вернул чистый отпечаток.
	headers *sessionHeaders

	// device — телефон, от имени которого идут запросы этой сессии.
	device profile.Device
	// acceptCH — подсказки, запрошенные сайтом, по origin. Под тем же
	// мьютексом, что и пул: заполняется из ответов, читается при сборке.
	acceptCH map[string]map[string]bool

	// cookies — свой учёт кук для выгрузки: банка отдаёт только пару
	// «имя-значение» для адреса, а сохранить сессию этого мало.
	cookies map[string]Cookie

	// altSvc — объявления HTTP/3 по origin вместе с пометкой «сломан».
	altSvc map[string]altSvcEntry

	// roots и clientCerts готовятся один раз при создании сессии: читать
	// файлы на каждое соединение — лишний ввод-вывод в горячем пути.
	roots       *x509.CertPool
	clientCerts []utls.Certificate

	h3 h3Transport
}

// New создаёт сессию. Спека профиля проверяется сразу, чтобы ошибка в данных
// всплыла при создании, а не на первом запросе.
func New(p *profile.Profile, opts Options) (*Session, error) {
	if p == nil {
		return nil, fmt.Errorf("no profile given: a session needs one to build its fingerprint")
	}
	if _, err := profile.BuildSpec(p); err != nil {
		return nil, err
	}
	if opts.Timeout < 0 {
		return nil, fmt.Errorf("timeout cannot be negative, got %s", opts.Timeout)
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxRedirects == 0 {
		opts.MaxRedirects = DefaultMaxRedirects
	}

	// Устройство выбирается один раз на сессию. Список из опций
	// перекрывает профильный: свои телефоны задаются, не трогая профиль.
	if len(opts.Devices) > 0 {
		clone := *p
		clone.Devices = opts.Devices
		p = &clone
	}
	var dev profile.Device
	if opts.Device != "" {
		var err error
		if dev, err = p.PickDevice(opts.Device); err != nil {
			return nil, err
		}
		// У профилей, где устройство стоит прямо в User-Agent, строка
		// пересобирается: иначе подсказка сказала бы одно, а строка рядом
		// другое — расхождение заметнее, чем одинаковый телефон у всех.
		if ua := p.UserAgentFor(dev); ua != p.Headers.UserAgent {
			clone := *p
			clone.Headers.UserAgent = ua
			p = &clone
		}
	}

	s := &Session{
		profile: p,
		opts:    opts,
		alpn:    alpnFromProfile(p),
		conns:   make(map[dialSpec][]*conn),
		orphans: make(map[*conn]struct{}),
		headers: newSessionHeaders(),
		device:  dev,
	}
	if opts.ForceHTTP1 {
		s.alpn = []string{"http/1.1"}
	}
	// Файлы читаются до первого запроса: ошибка в пути должна вскрываться
	// при создании сессии, а не на середине работы парсера.
	roots, err := loadRoots(opts.CACert)
	if err != nil {
		return nil, err
	}
	certs, err := loadClientCert(opts.ClientCert, opts.ClientKey)
	if err != nil {
		return nil, err
	}
	s.roots, s.clientCerts = roots, certs

	if opts.Cookies {
		jar, err := newCookieJar()
		if err != nil {
			return nil, err
		}
		s.jar = jar
	}
	// Отсутствие секции http3 в профиле должно вскрываться при создании сессии,
	// а не на первом запросе.
	if opts.HTTP3 && !p.HTTP3.Enabled() {
		return nil, fmt.Errorf("profile %q has no http3 section, so it cannot speak HTTP/3", p.Name)
	}
	// Прокси для QUIC не реализован. Молча пойти напрямую нельзя: это раскрыло
	// бы реальный адрес, ради сокрытия которого прокси и задавали.
	if opts.HTTP3 && opts.Proxy != "" {
		return nil, fmt.Errorf("HTTP/3 through a proxy is not supported: QUIC needs " +
			"CONNECT-UDP (RFC 9298), which no available library implements. " +
			"Drop either http3 or the proxy")
	}
	return s, nil
}

// Close закрывает все соединения сессии и запрещает дальнейшее использование.
//
// Без запрета параллельный запрос успевал создать соединение уже после
// опустошения пула — и закрыть его было бы некому.
func (s *Session) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conns := s.conns
	orphans := s.orphans
	s.conns = map[dialSpec][]*conn{}
	s.orphans = map[*conn]struct{}{}
	s.mu.Unlock()

	s.closeH3()
	for _, list := range conns {
		closeAll(list)
	}
	// Сироты доигрывали текущие потоки; при закрытии сессии ждать их незачем.
	for c := range orphans {
		c.close()
	}
}

// ensureOpen отвергает работу с закрытой сессией.
func (s *Session) ensureOpen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSessionClosed
	}
	return nil
}

var errSessionClosed = errors.New("session is closed")

// Do выполняет запрос, при необходимости проходя цепочку редиректов,
// и возвращает тело целиком.
func (s *Session) Do(r *Request) (*Response, error) {
	stream, err := s.DoStream(r)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	// Предел на тело: без него сервер с бесконечным ответом съедает память
	// процесса целиком. Читаем на байт больше, чтобы отличить «ровно предел»
	// от «больше предела».
	var reader io.Reader = stream
	if limit := s.opts.MaxResponseSize; limit > 0 {
		reader = io.LimitReader(stream, limit+1)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if limit := s.opts.MaxResponseSize; limit > 0 && int64(len(data)) > limit {
		return nil, fmt.Errorf("response body is larger than the max_response_size limit of %d bytes", limit)
	}
	return &Response{
		History: stream.History,
		Status:  stream.Status,
		Headers: stream.Headers,
		Body:    data,
		Proto:   stream.Proto,
		URL:     stream.URL,
	}, nil
}

// prepare разворачивает multipart-форму в тело запроса.
//
// Карта заголовков копируется всегда: при повторе один и тот же *Request
// проходит здесь дважды, и запись content-type в карту вызывающего исказила бы
// его запрос, а с ним и отпечаток.
func (s *Session) prepare(r *Request) (Request, error) {
	out := *r
	out.Headers = make(map[string]string, len(r.Headers))
	for k, v := range r.Headers {
		out.Headers[k] = v
	}
	if out.Multipart == nil {
		return out, nil
	}
	if len(out.Body) > 0 {
		return out, fmt.Errorf("request has both Body and Multipart set: pass exactly one")
	}
	body, contentType, err := encodeMultipart(out.Multipart, s.profile.FormBoundaryStyle())
	if err != nil {
		return out, err
	}
	out.Body = body
	// Границу нельзя задать снаружи: она сгенерирована здесь и должна
	// совпасть с телом.
	out.Headers["content-type"] = contentType
	out.Multipart = nil
	return out, nil
}

// send выполняет один запрос без учёта редиректов.
//
// Тело ответа остаётся открытым, и вместе с ним возвращается отмена контекста:
// вызвать её обязан тот, кто закрывает тело, иначе таймаут продолжит тикать
// на уже завершённом запросе.
// Возвращает и само соединение: вызывающий обязан отпустить его через
// Session.release, когда тело дочитано.
func (s *Session) send(r *Request, deadline time.Time) (*http.Response, context.CancelFunc, *conn, error) {
	u, err := url.Parse(r.URL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, nil, nil, fmt.Errorf("only https is supported, got scheme %q", u.Scheme)
	}

	method := r.Method
	if method == "" {
		method = http.MethodGet
	}

	body, size, err := requestBody(r)
	if err != nil {
		return nil, nil, nil, err
	}
	req, err := http.NewRequest(method, r.URL, body)
	if err != nil {
		if c, ok := body.(io.Closer); ok {
			c.Close()
		}
		return nil, nil, nil, err
	}
	// Предел живёт в контексте запроса: HTTP/2 читает его сам,
	// а HTTP/1.1 переносит на дедлайн сокета (см. conn.roundTrip).
	//
	// Дедлайн общий на всю цепочку, а не свой у каждого шага: иначе двадцать
	// редиректов растянулись бы на двадцать таймаутов вместо одного.
	// Отмена возвращается наружу и вызывается при закрытии тела: до этого
	// момента чтение должно оставаться под тем же пределом.
	var cancel context.CancelFunc
	if !deadline.IsZero() {
		var ctx context.Context
		ctx, cancel = context.WithDeadline(r.context(), deadline)
		req = req.WithContext(ctx)
	} else if parent := r.context(); parent != context.Background() {
		var ctx context.Context
		ctx, cancel = context.WithCancel(parent)
		req = req.WithContext(ctx)
	}
	if r != nil && r.ConnectTimeout != nil {
		req = req.WithContext(withConnectLimit(req.Context(), *r.ConnectTimeout))
	}
	// Без явного размера транспорт перешёл бы на chunked-кодирование,
	// которого браузер при отправке файла не использует.
	if size >= 0 {
		req.ContentLength = size
	}

	fail := func(err error) (*http.Response, context.CancelFunc, *conn, error) {
		// Тело могло остаться открытым файлом: без закрытия дескриптор течёт,
		// а с повторами — умножается на число попыток.
		if c, ok := body.(io.Closer); ok {
			c.Close()
		}
		if cancel != nil {
			cancel()
		}
		return nil, nil, nil, err
	}

	// Ветка HTTP/3 стоит здесь, а не раньше: до создания контекста она
	// уходила без таймаута вовсе, и зависший запрос висел бы вечно.
	// Заголовки для неё собирает sendH3 сам: fhttp-запрос ей не нужен.
	// Автопереход по Alt-Svc действует только на прямые соединения: через
	// прокси QUIC не проходит, и предлагать его там нечего.
	forced := r.protocol()
	viaAltSvc := forced == "" && !s.opts.HTTP3 &&
		s.proxyForHost(r, u.Host) == "" && s.altSvcH3(u)
	if forced == ProtoH3 || (forced == "" && s.opts.HTTP3) || viaAltSvc {
		// Опция сессии проверена при её создании, а требование запроса —
		// только здесь: до него профиль мог и не понадобиться.
		if !s.profile.HTTP3.Enabled() {
			return fail(&fatalError{fmt.Errorf(
				"protocol=%s: profile %q has no http3 section",
				ProtoH3, s.profile.Name)})
		}
		if s.proxyForHost(r, u.Host) != "" {
			return fail(&fatalError{fmt.Errorf("HTTP/3 through a proxy is not supported " +
				"(QUIC needs CONNECT-UDP, RFC 9298)")})
		}
		resp, err := s.sendH3(req.Context(), r, u)
		if err == nil {
			// У HTTP/3 своё соединение внутри транспорта, отпускать нечего.
			return fromStdResponse(resp), cancel, nil, nil
		}
		if !viaAltSvc {
			return fail(err)
		}
		// Переход был нашей догадкой по объявлению сайта — откатываемся
		// на TCP и какое-то время больше не пробуем, как делает браузер.
		s.markAltSvcBroken(u)
	}

	forceH1 := s.opts.ForceHTTP1
	if forced != "" {
		forceH1 = forced == ProtoHTTP1
	}
	spec := s.newDialSpec(u, s.proxyForHost(r, u.Host), forceH1)
	c, err := s.conn(req.Context(), u, spec)
	if err != nil {
		// Соединения нет — запрос до сервера не дошёл, повтор безопасен.
		return fail(&unprocessedError{err})
	}
	// Соединение живое, просто не того протокола: возвращаем его в пул
	// и падаем. Повтор бессмыслен — сервер согласует то же самое.
	if forced == ProtoH2 && c.proto != "h2" {
		s.release(c)
		return fail(&fatalError{fmt.Errorf(
			"protocol=%s: server negotiated %s. The ALPN list is left intact on purpose: "+
				"no browser offers h2 alone", ProtoH2, c.proto)})
	}
	// Заголовки собираются после выбора соединения: порядок и регистр
	// HTTP/1.1 зависят от того, что согласовал сервер, а не от опции.
	s.applyHeaders(req, r, u, c.proto == "http/1.1")

	resp, err := c.roundTrip(req.Context(), req)
	if err != nil {
		// Соединение больше непригодно. Для HTTP/2 закрываем мягко: жёсткое
		// закрытие оборвало бы потоки соседних запросов.
		s.release(c)
		s.evict(c, c.h2 == nil)
		err = fmt.Errorf("request failed: %w", err)
		if c.h2 != nil && h2Unprocessed(err) {
			return fail(&unprocessedError{err})
		}
		return fail(err)
	}

	if s.jar != nil {
		if cookies := resp.Cookies(); len(cookies) > 0 {
			s.jar.SetCookies(u, cookies)
			s.recordCookies(u, cookies)
		}
	}
	return resp, cancel, c, nil
}

func (s *Session) dial(ctx context.Context, u *url.URL, ds dialSpec) (*conn, error) {
	// Предел на установку покрывает и TCP, и рукопожатие TLS: для вызывающего
	// это одна фаза «пока соединения нет», и делить её незачем.
	dialCtx, done := s.connectContext(ctx)
	defer done()

	raw, err := s.dialRaw(dialCtx, ds.addr, ds.proxy)
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
	//
	// Признак берётся из dialSpec, а не из опций сессии: он входит в ключ пула,
	// и h1-соединение WebSocket не подменит собой h2-соединение обычных запросов.
	if ds.forceHTTP1 {
		if !setALPN(spec, []string{"http/1.1"}) {
			raw.Close()
			return nil, fmt.Errorf("force_http1: profile %q has no ALPN extension to restrict", s.profile.Name)
		}
	}

	cfg := &utls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: s.opts.InsecureSkipVerify,
		RootCAs:            s.roots,
		Certificates:       s.clientCerts,
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
	// Рукопожатие идёт под тем же пределом, что и TCP: узел, принявший
	// соединение и замолчавший, иначе съел бы весь бюджет запроса.
	if err := uconn.HandshakeContext(dialCtx); err != nil {
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
		return newH2Conn(cc, ds), nil
	case "http/1.1", "":
		return newH1Conn(uconn, ds), nil
	default:
		uconn.Close()
		return nil, fmt.Errorf("server negotiated %q, which is not supported", proto)
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
