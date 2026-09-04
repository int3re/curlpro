// Package profile загружает профили браузеров из JSON и разрешает наследование.
//
// Профиль — это данные, а не код: добавление новой версии Chrome не требует
// пересборки. Базовый профиль несёт захваченные байты ClientHello, а версии
// поверх него описываются дельтами через based_on — для месячного бампа Chrome
// обычно меняются только User-Agent, sec-ch-ua и иногда sigalgs.
package profile

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/big"
	"path"
	"sort"
	"strings"
	"sync"
)

// maxInheritDepth ограничивает глубину цепочки based_on. Реальные цепочки
// короткие (chrome-152 -> 151 -> ... -> 146), так что упереться в лимит
// означает ошибку в данных.
const maxInheritDepth = 32

// Profile — браузерный профиль в том виде, в каком лежит в JSON.
type Profile struct {
	Name    string      `json:"name"`
	BasedOn string      `json:"based_on,omitempty"`
	TLS     TLSSpec     `json:"tls"`
	HTTP1   HTTP1Spec   `json:"http1,omitempty"`
	HTTP2   HTTP2Spec   `json:"http2"`
	HTTP3   HTTP3Spec   `json:"http3,omitempty"`
	QUIC    QUICSpec    `json:"quic,omitempty"`
	Headers HeadersSpec `json:"headers"`
	// WebSocket описывает рукопожатие: у него свой набор и порядок заголовков,
	// не совпадающий с навигационным.
	WebSocket WebSocketSpec `json:"websocket,omitempty"`
	// Devices — телефоны, которыми может представляться сессия.
	Devices []Device `json:"devices,omitempty"`
	// ClientHints — подсказки высокой энтропии, если браузер их поддерживает.
	ClientHints ClientHintsSpec `json:"client_hints,omitempty"`

	// Fetch описывает запросы fetch/XHR: набор, порядок и якорь у них свои.
	Fetch FetchSpec `json:"fetch,omitempty"`
}

// FetchSpec — заголовки запросов fetch() и XMLHttpRequest.
//
// Навигационный набор для них не годится: браузер шлёт accept: */*,
// sec-fetch-mode: cors, sec-fetch-dest: empty, Origin и Referer, а
// upgrade-insecure-requests и sec-fetch-user не шлёт вовсе. Кастомный
// заголовок бывает только у таких запросов, поэтому запрос с ним поверх
// навигационного набора аномален при любом якоре (замер Chrome 152
// и Firefox 154, docs/STAGE15-RESULTS.md).
//
// Пустое значение в order — слот: имя, известное навигационному набору
// (sec-ch-ua*, accept-encoding, accept-language, user-agent), берёт значение
// оттуда, чтобы дельта на новую версию браузера правила его один раз;
// остальные (content-type, content-length, origin, referer, cookie)
// заполняются запросом, библиотекой или транспортом.
type FetchSpec struct {
	Order []HeaderPair `json:"order,omitempty"`
	// HTTP1Order — порядок и регистр для HTTP/1.1, включая Host и Connection.
	HTTP1Order []string `json:"http1_order,omitempty"`
	// CustomAnchor — якорь кастомных заголовков, список через запятую.
	CustomAnchor string `json:"custom_anchor,omitempty"`
}

// Enabled сообщает, описан ли в профиле набор fetch.
func (f FetchSpec) Enabled() bool { return len(f.Order) > 0 }

// ResolvedFetchHeaders возвращает набор fetch, подставив в пустые слоты
// значения из навигационного набора там, где они есть.
func (p *Profile) ResolvedFetchHeaders() []HeaderPair {
	nav := p.ResolvedHeaders()
	out := make([]HeaderPair, 0, len(p.Fetch.Order))
	for _, h := range p.Fetch.Order {
		if h.Value == "" {
			for _, n := range nav {
				if n.Value != "" && strings.EqualFold(n.Key, h.Key) {
					h.Value = n.Value
					// Переопределения по методу переносятся вместе со
					// значением: иначе слот fetch получил бы значение
					// навигации, но потерял бы правило.
					if h.ValueByMethod == nil {
						h.ValueByMethod = n.ValueByMethod
					}
					break
				}
			}
		}
		out = append(out, h)
	}
	return out
}

// ResolvedHints возвращает шаблон с подсказками: fetch=true — набор fetch.
//
// Пустые значения заполняются по имени: сначала из values профиля, потом
// из устройства, потом из обычного набора. Незаполненный слот остаётся
// пустым и на провод не уходит — как и в остальных шаблонах.
func (p *Profile) ResolvedHints(fetch bool, dev Device) []HeaderPair {
	tpl := p.ClientHints.Order
	base := p.ResolvedHeaders()
	if fetch {
		if len(p.ClientHints.FetchOrder) > 0 {
			tpl = p.ClientHints.FetchOrder
		}
		base = p.ResolvedFetchHeaders()
	}
	out := make([]HeaderPair, 0, len(tpl))
	for _, h := range tpl {
		if h.Value == "" {
			h.Value = p.hintValue(h.Key, dev, base)
		}
		out = append(out, h)
	}
	return out
}

// hintValue подбирает значение для имени в шаблоне подсказок.
func (p *Profile) hintValue(key string, dev Device, base []HeaderPair) string {
	switch strings.ToLower(key) {
	case "sec-ch-ua-model":
		if dev.Model != "" {
			return quoteHint(dev.Model)
		}
	case "sec-ch-ua-platform-version":
		if dev.PlatformVersion != "" {
			return quoteHint(dev.PlatformVersion)
		}
	}
	if v, ok := p.ClientHints.Values[strings.ToLower(key)]; ok {
		return v
	}
	for _, b := range base {
		if strings.EqualFold(b.Key, key) && b.Value != "" {
			return b.Value
		}
	}
	if strings.EqualFold(key, "user-agent") {
		return p.Headers.UserAgent
	}
	return ""
}

// quoteHint оборачивает значение в кавычки формата структурированных полей.
func quoteHint(v string) string {
	if strings.HasPrefix(v, "\"") {
		return v
	}
	return "\"" + v + "\""
}

// PickDevice выбирает устройство по имени; пустое имя или "random" — случайное.
//
// Устройство держится на сессию, а не на запрос: настоящий клиент телефон
// между запросами не меняет.
func (p *Profile) PickDevice(name string) (Device, error) {
	if len(p.Devices) == 0 {
		return Device{}, fmt.Errorf("profile %q describes no devices (devices section)", p.Name)
	}
	if name == "" || strings.EqualFold(name, "random") {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(p.Devices))))
		if err != nil {
			return p.Devices[0], nil
		}
		return p.Devices[n.Int64()], nil
	}
	for _, d := range p.Devices {
		if strings.EqualFold(d.Name, name) || strings.EqualFold(d.Model, name) {
			return d, nil
		}
	}
	return Device{}, fmt.Errorf("device %q not found in profile %q", name, p.Name)
}

// WebSocketSpec задаёт заголовки рукопожатия WebSocket в порядке и регистре
// отправки. Пустое значение — слот, заполняемый по имени: host, user-agent,
// origin, sec-websocket-key, sec-websocket-protocol, cookie; для остальных имён
// значение берётся из headers.order (accept-encoding, accept-language).
// Слот без значения в запрос не попадает.
//
// Chrome на рукопожатии не шлёт ни sec-ch-ua, ни sec-fetch-*, ни accept,
// зато шлёт Pragma и Cache-Control и ставит Sec-WebSocket-Key после
// Accept-Language — навигационный набор здесь не годится.
type WebSocketSpec struct {
	Order []HeaderPair `json:"order,omitempty"`
}

// HTTP1Spec описывает отпечаток уровня HTTP/1.1.
//
// Он отличается от HTTP/2 сильнее, чем кажется. В HTTP/2 имена заголовков
// обязаны быть в нижнем регистре, а в HTTP/1.1 регистр произволен — и браузеры
// им пользуются: Chrome шлёт Title-Case для большинства заголовков, но
// sec-ch-* и priority оставляет строчными. Плюс появляются Host и Connection,
// которых в HTTP/2 нет вовсе.
type HTTP1Spec struct {
	// Order задаёт имена заголовков в порядке и регистре отправки.
	// Значения берутся из общей секции headers по имени без учёта регистра.
	//
	// Chrome начинает с Host и Connection: первый обязателен по RFC 7230,
	// второй браузер шлёт явно, хотя keep-alive и так подразумевается.
	Order []string `json:"order,omitempty"`

	// Connection — значение одноимённого заголовка. Пусто означает,
	// что заголовок не отправляется.
	Connection string `json:"connection,omitempty"`
}

// Enabled сообщает, описан ли в профиле HTTP/1.1.
func (h HTTP1Spec) Enabled() bool { return len(h.Order) > 0 }

// HTTP3Spec описывает отпечаток уровня HTTP/3.
//
// Всё перечисленное видно на проводе и различает браузеры. Апстримный uquic
// не управляет ничем из этого, поэтому пакет http3 вендорен в internal/h3.
type HTTP3Spec struct {
	// Settings — пары id/value. Chrome: 1:65536, 6:262144, 7:100, 51:1.
	//
	// Идентификатор шире, чем у HTTP/2: Firefox объявляет WebTransport
	// настройкой 727725890, которая в uint16 не помещается.
	Settings []H3Setting `json:"settings,omitempty"`
	// SettingsOrder задаёт порядок отправки. Chrome: [1, 6, 7, 51], затем GREASE.
	SettingsOrder []uint64 `json:"settings_order,omitempty"`
	// PseudoOrder — порядок псевдо-заголовков. Chrome m,a,s,p; Firefox m,s,a,p.
	PseudoOrder []string `json:"pseudo_order,omitempty"`
	// SendGreaseFrame включает GREASE-кадр на управляющем потоке.
	//
	// Указатель, а не bool: дельта обязана уметь выключить то, что включил
	// предок. С голым bool «false» был неотличим от «не задано», и профиль
	// Firefox поверх базы Chrome не мог убрать GREASE-кадр.
	SendGreaseFrame *bool `json:"send_grease_frame,omitempty"`
	// PriorityParam — тип кадра PRIORITY_UPDATE. Chrome 984832; Firefox не шлёт
	// (ноль). Указатель по той же причине, что и SendGreaseFrame.
	PriorityParam *uint64 `json:"priority_param,omitempty"`
}

// SendsGreaseFrame сообщает, включён ли GREASE-кадр.
func (h HTTP3Spec) SendsGreaseFrame() bool {
	return h.SendGreaseFrame != nil && *h.SendGreaseFrame
}

// PriorityParamValue возвращает тип кадра PRIORITY_UPDATE; ноль — не слать.
func (h HTTP3Spec) PriorityParamValue() uint64 {
	if h.PriorityParam == nil {
		return 0
	}
	return *h.PriorityParam
}

// H3Setting — пара id/value уровня HTTP/3.
type H3Setting struct {
	ID    uint64 `json:"id"`
	Value uint64 `json:"value"`
}

// Enabled сообщает, описан ли в профиле HTTP/3.
func (h HTTP3Spec) Enabled() bool { return len(h.Settings) > 0 }

// TLSSpec описывает ClientHello.
//
// Источник — один из трёх, во взаимоисключающем порядке приоритета:
//   - RawClientHello: байты живого захвата, самый точный;
//   - Extensions: декларативное описание в нашей схеме (см. build.go),
//     им пользуется импорт корпуса curl-impersonate;
//   - ClientHelloSpec: нативный JSON uTLS, принимает только строковые имена.
//
// Остальные поля — оверрайды, применяемые к уже построенной спеке; именно они
// позволяют описать новую версию браузера дельтой.
type TLSSpec struct {
	RawClientHello  string          `json:"raw_client_hello,omitempty"`
	ClientHelloSpec json.RawMessage `json:"client_hello_spec,omitempty"`

	CipherSuites       []uint16    `json:"cipher_suites,omitempty"`
	CompressionMethods []uint8     `json:"compression_methods,omitempty"`
	Extensions         []Extension `json:"extensions,omitempty"`

	SignatureAlgorithms []uint16 `json:"signature_algorithms,omitempty"`
	// TrustAnchors — идентификаторы корней для расширения 0xCA34 в виде
	// относительных OID («11129.9.13»). Порядок в профиле не важен: он
	// разыгрывается заново на каждое соединение, как это делает Chrome.
	TrustAnchors      []string `json:"trust_anchors,omitempty"`
	ALPN              []string `json:"alpn,omitempty"`
	PermuteExtensions *bool    `json:"permute_extensions,omitempty"`

	// AllowBluntMimicry разрешает воспроизводить расширения, которых uTLS
	// не знает, сырыми байтами из raw_client_hello.
	//
	// Так новый примитив браузера не требует релиза: trust_anchors (0xCA34)
	// у Chrome 152 иначе роняет разбор захвата с «unsupported extension».
	// Риск ограничен: ключевой материал (key_share, ECH) uTLS знает и
	// генерирует сам, а сырыми уходят только статические расширения.
	AllowBluntMimicry *bool `json:"allow_blunt_mimicry,omitempty"`
}

// BluntMimicry сообщает, включено ли воспроизведение неизвестных расширений.
func (t TLSSpec) BluntMimicry() bool { return t.AllowBluntMimicry != nil && *t.AllowBluntMimicry }

// HTTP2Spec описывает отпечаток уровня HTTP/2.
type HTTP2Spec struct {
	Settings               []Setting `json:"settings,omitempty"`
	ConnectionWindowUpdate uint32    `json:"connection_window_update,omitempty"`
	PseudoOrder            []string  `json:"pseudo_order,omitempty"`
	StreamWeight           *uint16   `json:"stream_weight,omitempty"`
	StreamExclusive        *bool     `json:"stream_exclusive,omitempty"`
}

// Setting — пара id/value. Порядок в слайсе значим: он воспроизводится
// на проводе и входит в отпечаток.
type Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}

// HeadersSpec задаёт заголовки и их порядок.
type HeadersSpec struct {
	UserAgent string `json:"user_agent,omitempty"`
	// UserAgentTemplate — строка с {model}, {android}, {arch} для профилей,
	// у которых устройство видно в самом User-Agent. Пусто — подстановки нет.
	UserAgentTemplate string       `json:"user_agent_template,omitempty"`
	Order             []HeaderPair `json:"order,omitempty"`

	// FormBoundary — стиль границы multipart-формы: "webkit" или "firefox".
	// Форма границы наблюдаема и различает браузеры, поэтому это часть профиля,
	// а не деталь реализации.
	FormBoundary string `json:"form_boundary,omitempty"`

	// CustomAnchor — имя заголовка, ПЕРЕД которым вставляются заголовки,
	// добавленные пользователем.
	//
	// Служебный хвост (accept-encoding, cookie, priority) браузер дописывает
	// последним, поэтому кастомный заголовок после него заметен. Пусто —
	// вставлять в конец.
	CustomAnchor string `json:"custom_anchor,omitempty"`
}

// HeaderPair — заголовок с его позицией в порядке отправки. Пустое значение —
// слот: позиция для заголовка, который придёт от библиотеки (user-agent,
// cookie, origin), от сессии или запроса (content-type и любое другое имя)
// либо от транспорта (content-length). Слот без значения выпадает.
type HeaderPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	// ValueByMethod переопределяет значение для отдельных методов.
	//
	// Замер Яндекс.Браузера 26.8 на Pixel 7: sdch в Accept-Encoding уходит
	// на GET, HEAD, DELETE и PUT, но не на POST — включая POST с пустым телом.
	// Правило описывается данными, а не кодом: другой браузер выразит своё
	// тем же полем, без правки Go.
	//
	// Пустое значение означает слот: заголовок на этом методе не уходит,
	// если его нечем заполнить.
	ValueByMethod map[string]string `json:"value_by_method,omitempty"`
}

// For возвращает значение заголовка для метода запроса.
func (h HeaderPair) For(method string) string {
	for m, v := range h.ValueByMethod {
		if strings.EqualFold(m, method) {
			return v
		}
	}
	return h.Value
}

// Device — телефон, от имени которого идут запросы.
//
// Chrome с версии 110 вырезал из User-Agent и модель, и версию системы:
// замер Pixel 7 на Android 17 даёт «Android 10; K» — заглушку, одинаковую
// у всех. Настоящее устройство живёт в подсказках sec-ch-ua-model и
// sec-ch-ua-platform-version, и браузер шлёт их только после Accept-CH.
type Device struct {
	Name            string `json:"name"`
	Model           string `json:"model"`
	PlatformVersion string `json:"platform_version"`
	// Arch — архитектура в том виде, в каком её пишет в User-Agent браузер,
	// который её туда пишет (Яндекс: arm_64). Подсказке sec-ch-ua-arch это
	// поле не соответствует: на Android она пустая — замер Pixel 7.
	Arch string `json:"arch,omitempty"`
}

// UserAgentFor подставляет устройство в строку User-Agent.
//
// Работает только там, где браузер устройство в строку пишет: у Яндекса это
// «Linux; arm_64; Android 17; Pixel 7», у Chrome с версии 110 — заглушка
// «Android 10; K», одинаковая у всех, и подставлять туда нечего. Шаблон задаёт
// профиль, поэтому код не решает за браузер, что тот сообщает.
//
// Поддерживаются {model}, {android} (мажор версии), {platform_version} и {arch}.
func (p *Profile) UserAgentFor(dev Device) string {
	tpl := p.Headers.UserAgentTemplate
	if tpl == "" || dev.Model == "" {
		return p.Headers.UserAgent
	}
	android := dev.PlatformVersion
	if i := strings.Index(android, "."); i > 0 {
		android = android[:i]
	}
	arch := dev.Arch
	r := strings.NewReplacer(
		"{model}", dev.Model,
		"{android}", android,
		"{platform_version}", dev.PlatformVersion,
		"{arch}", arch,
	)
	return r.Replace(tpl)
}

// ClientHintsSpec описывает подсказки высокой энтропии.
//
// Values — постоянные для версии браузера (полная версия, разрядность,
// форм-фактор). Модель и версия системы берутся из Device.
//
// Order и FetchOrder — полный порядок заголовков для запроса, в котором
// подсказки есть: с их появлением Chromium перестраивает весь кластер, и
// порядок оказывается функцией от набора имён. Два независимых прогона дали
// одинаковую последовательность, поэтому она снята замером и хранится целиком,
// а не собирается из позиций.
type ClientHintsSpec struct {
	Values     map[string]string `json:"values,omitempty"`
	Order      []HeaderPair      `json:"order,omitempty"`
	FetchOrder []HeaderPair      `json:"fetch_order,omitempty"`
}

// Enabled сообщает, описаны ли подсказки в профиле.
func (c ClientHintsSpec) Enabled() bool { return len(c.Order) > 0 }

// Registry хранит профили и разрешает наследование.
type Registry struct {
	mu  sync.RWMutex
	raw map[string]*Profile
}

func NewRegistry() *Registry {
	return &Registry{raw: make(map[string]*Profile)}
}

// LoadFS загружает все *.json из каталога файловой системы.
// Используется и для встроенных профилей (go:embed), и для пользовательских.
func (r *Registry) LoadFS(fsys fs.FS, dir string) error {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return fmt.Errorf("reading profile directory %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		if err := r.Register(b); err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
	}
	return nil
}

// Register разбирает и регистрирует профиль из JSON.
func (r *Registry) Register(data []byte) error {
	var p Profile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields() // опечатка в поле не должна молча терять настройку
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("parsing profile: %w", err)
	}
	if p.Name == "" {
		return fmt.Errorf("profile has no name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.raw[p.Name] = &p
	return nil
}

// Names возвращает имена зарегистрированных профилей.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.raw))
	for n := range r.raw {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Resolve возвращает профиль со схлопнутой цепочкой based_on.
func (r *Registry) Resolve(name string) (*Profile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	chain, err := r.chain(name)
	if err != nil {
		return nil, err
	}
	// Идём от корня к листу: каждый следующий переопределяет предыдущий.
	out := &Profile{Name: name}
	for i := len(chain) - 1; i >= 0; i-- {
		merge(out, chain[i])
	}
	out.Name = name
	if err := out.validate(); err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	return out, nil
}

// validate отвергает профиль, который молча дал бы не тот отпечаток.
//
// Проверяется схлопнутый профиль, а не файл: дельта вправе не повторять
// поле, если его задал предок.
func (p *Profile) validate() error {
	if p.TLS.RawClientHello == "" && len(p.TLS.ClientHelloSpec) == 0 && len(p.TLS.Extensions) == 0 {
		return fmt.Errorf("no ClientHello source " +
			"(raw_client_hello, extensions or client_hello_spec) in the profile or its ancestors")
	}
	// Умолчания здесь нет намеренно. Перемешивание верно для Chrome >= 110
	// и неверно для Firefox, Safari и старых Chrome; профиль без поля раньше
	// перемешивался, и захваченный Firefox давал новый порядок расширений
	// на каждом соединении — чего локальный validate не видит, потому что
	// JA4 к порядку нечувствителен.
	if p.TLS.PermuteExtensions == nil {
		return fmt.Errorf("tls.permute_extensions is not set: use true for Chrome >= 110 " +
			"and false for every other browser; the library will not guess")
	}
	// pre_shared_key бывает только в захвате возобновлённой сессии. На свежем
	// соединении тикета нет, uTLS шлёт пустое расширение — а клиент выбрасывает
	// его через OmitEmptyPsk. Итог: профиль тихо теряет и PSK, и padding,
	// который на его месте шлёт браузер. Так были испорчены два профиля
	// корпуса, и заметить это удалось только при разборе долгов (STAGE16).
	for _, e := range p.TLS.Extensions {
		if e.Type == "pre_shared_key" {
			return fmt.Errorf("the pre_shared_key extension only appears on a resumed session: " +
				"recapture the profile on a fresh connection, where padding sits in its place")
		}
	}
	// На проводе вес на единицу меньше и укладывается в байт (RFC 7540):
	// значение сверх 256 молча оборачивалось бы при приведении к uint8.
	if w := p.HTTP2.StreamWeight; w != nil && *w > 256 {
		return fmt.Errorf("http2.stream_weight %d is out of the 0..256 range", *w)
	}
	// Порядок SETTINGS обязан покрывать все настройки: непокрытая ушла бы
	// в конец по возрастанию идентификатора, то есть не туда, куда её шлёт
	// браузер, и без единого предупреждения.
	if len(p.HTTP3.SettingsOrder) > 0 {
		listed := make(map[uint64]bool, len(p.HTTP3.SettingsOrder))
		for _, id := range p.HTTP3.SettingsOrder {
			listed[id] = true
		}
		for _, st := range p.HTTP3.Settings {
			if !listed[st.ID] {
				return fmt.Errorf("http3.settings_order does not list setting %d", st.ID)
			}
		}
	}
	return nil
}

// chain собирает цепочку от листа к корню, ловя циклы и обрывы.
func (r *Registry) chain(name string) ([]*Profile, error) {
	var out []*Profile
	seen := map[string]bool{}
	for cur := name; cur != ""; {
		if seen[cur] {
			return nil, fmt.Errorf("based_on cycle: %s -> %s",
				strings.Join(namesOf(out), " -> "), cur)
		}
		seen[cur] = true

		p, ok := r.raw[cur]
		if !ok {
			if len(out) == 0 {
				return nil, fmt.Errorf("profile %q not found", cur)
			}
			return nil, fmt.Errorf("profile %q refers to a missing based_on %q",
				out[len(out)-1].Name, cur)
		}
		out = append(out, p)
		if len(out) > maxInheritDepth {
			return nil, fmt.Errorf("based_on chain is deeper than %d, which usually means a data error",
				maxInheritDepth)
		}
		cur = p.BasedOn
	}
	return out, nil
}

func namesOf(ps []*Profile) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name
	}
	return out
}

// merge накладывает src поверх dst. Заданные поля перекрывают, пустые — нет.
func merge(dst, src *Profile) {
	// Источники ClientHello взаимоисключающи: заданный в потомке вытесняет
	// унаследованный, иначе получилась бы смесь двух разных описаний.
	switch {
	case src.TLS.RawClientHello != "":
		dst.TLS.RawClientHello, dst.TLS.ClientHelloSpec, dst.TLS.Extensions = src.TLS.RawClientHello, nil, nil
	case len(src.TLS.Extensions) > 0:
		dst.TLS.RawClientHello, dst.TLS.ClientHelloSpec, dst.TLS.Extensions = "", nil, src.TLS.Extensions
	case len(src.TLS.ClientHelloSpec) > 0:
		dst.TLS.RawClientHello, dst.TLS.ClientHelloSpec, dst.TLS.Extensions = "", src.TLS.ClientHelloSpec, nil
	}
	if len(src.TLS.CipherSuites) > 0 {
		dst.TLS.CipherSuites = src.TLS.CipherSuites
	}
	if len(src.TLS.CompressionMethods) > 0 {
		dst.TLS.CompressionMethods = src.TLS.CompressionMethods
	}
	if src.TLS.TrustAnchors != nil {
		dst.TLS.TrustAnchors = src.TLS.TrustAnchors
	}
	if src.TLS.SignatureAlgorithms != nil {
		dst.TLS.SignatureAlgorithms = src.TLS.SignatureAlgorithms
	}
	if src.TLS.ALPN != nil {
		dst.TLS.ALPN = src.TLS.ALPN
	}
	if src.TLS.PermuteExtensions != nil {
		dst.TLS.PermuteExtensions = src.TLS.PermuteExtensions
	}
	if src.TLS.AllowBluntMimicry != nil {
		dst.TLS.AllowBluntMimicry = src.TLS.AllowBluntMimicry
	}

	if src.HTTP2.Settings != nil {
		dst.HTTP2.Settings = src.HTTP2.Settings
	}
	if src.HTTP2.ConnectionWindowUpdate != 0 {
		dst.HTTP2.ConnectionWindowUpdate = src.HTTP2.ConnectionWindowUpdate
	}
	if src.HTTP2.PseudoOrder != nil {
		dst.HTTP2.PseudoOrder = src.HTTP2.PseudoOrder
	}
	if src.HTTP2.StreamWeight != nil {
		dst.HTTP2.StreamWeight = src.HTTP2.StreamWeight
	}
	if src.HTTP2.StreamExclusive != nil {
		dst.HTTP2.StreamExclusive = src.HTTP2.StreamExclusive
	}

	if src.HTTP1.Order != nil {
		dst.HTTP1.Order = src.HTTP1.Order
	}
	if src.HTTP1.Connection != "" {
		dst.HTTP1.Connection = src.HTTP1.Connection
	}

	if src.HTTP3.Settings != nil {
		dst.HTTP3.Settings = src.HTTP3.Settings
	}
	if src.HTTP3.SettingsOrder != nil {
		dst.HTTP3.SettingsOrder = src.HTTP3.SettingsOrder
	}
	if src.HTTP3.PseudoOrder != nil {
		dst.HTTP3.PseudoOrder = src.HTTP3.PseudoOrder
	}
	if src.HTTP3.SendGreaseFrame != nil {
		dst.HTTP3.SendGreaseFrame = src.HTTP3.SendGreaseFrame
	}
	if src.HTTP3.PriorityParam != nil {
		dst.HTTP3.PriorityParam = src.HTTP3.PriorityParam
	}

	if src.QUIC.Parrot != "" {
		dst.QUIC.Parrot = src.QUIC.Parrot
	}
	if src.QUIC.ConnectionOptions != "" {
		dst.QUIC.ConnectionOptions = src.QUIC.ConnectionOptions
	}
	if src.QUIC.SendInitialRTT != nil {
		dst.QUIC.SendInitialRTT = src.QUIC.SendInitialRTT
	}
	if src.QUIC.LegacyVersionInformationID != nil {
		dst.QUIC.LegacyVersionInformationID = src.QUIC.LegacyVersionInformationID
	}
	if src.QUIC.GreaseVersionFirst != nil {
		dst.QUIC.GreaseVersionFirst = src.QUIC.GreaseVersionFirst
	}

	if src.WebSocket.Order != nil {
		dst.WebSocket.Order = src.WebSocket.Order
	}
	if src.Headers.UserAgentTemplate != "" {
		dst.Headers.UserAgentTemplate = src.Headers.UserAgentTemplate
	}
	if src.Devices != nil {
		dst.Devices = src.Devices
	}
	if src.ClientHints.Values != nil {
		dst.ClientHints.Values = src.ClientHints.Values
	}
	if src.ClientHints.Order != nil {
		dst.ClientHints.Order = src.ClientHints.Order
	}
	if src.ClientHints.FetchOrder != nil {
		dst.ClientHints.FetchOrder = src.ClientHints.FetchOrder
	}
	if src.Fetch.Order != nil {
		dst.Fetch.Order = src.Fetch.Order
	}
	if src.Fetch.HTTP1Order != nil {
		dst.Fetch.HTTP1Order = src.Fetch.HTTP1Order
	}
	if src.Fetch.CustomAnchor != "" {
		dst.Fetch.CustomAnchor = src.Fetch.CustomAnchor
	}

	if src.Headers.UserAgent != "" {
		dst.Headers.UserAgent = src.Headers.UserAgent
	}
	if src.Headers.Order != nil {
		dst.Headers.Order = src.Headers.Order
	}
	if src.Headers.FormBoundary != "" {
		dst.Headers.FormBoundary = src.Headers.FormBoundary
	}
	if src.Headers.CustomAnchor != "" {
		dst.Headers.CustomAnchor = src.Headers.CustomAnchor
	}
}

// FormBoundaryStyle возвращает стиль границы multipart-формы.
// Если профиль его не задаёт, он выводится из семейства браузера: гадать
// не приходится, потому что стилей всего два.
func (p *Profile) FormBoundaryStyle() string {
	if p.Headers.FormBoundary != "" {
		return p.Headers.FormBoundary
	}
	name := strings.ToLower(p.Name)
	ua := strings.ToLower(p.Headers.UserAgent)
	if strings.HasPrefix(name, "firefox") || strings.HasPrefix(name, "tor") ||
		strings.Contains(ua, "firefox/") {
		return "firefox"
	}
	return "webkit"
}

// ResolvedHeaders возвращает заголовки в порядке отправки, подставив
// User-Agent в позицию с пустым значением.
func (p *Profile) ResolvedHeaders() []HeaderPair {
	out := make([]HeaderPair, 0, len(p.Headers.Order))
	for _, h := range p.Headers.Order {
		if h.Value == "" && strings.EqualFold(h.Key, "user-agent") {
			h.Value = p.Headers.UserAgent
		}
		out = append(out, h)
	}
	return out
}
