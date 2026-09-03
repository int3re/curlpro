// Package profile загружает профили браузеров из JSON и разрешает наследование.
//
// Профиль — это данные, а не код: добавление новой версии Chrome не требует
// пересборки. Базовый профиль несёт захваченные байты ClientHello, а версии
// поверх него описываются дельтами через based_on — для месячного бампа Chrome
// обычно меняются только User-Agent, sec-ch-ua и иногда sigalgs.
package profile

import (
	"encoding/json"
	"fmt"
	"io/fs"
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
	HTTP2   HTTP2Spec   `json:"http2"`
	HTTP3   HTTP3Spec   `json:"http3,omitempty"`
	QUIC    QUICSpec    `json:"quic,omitempty"`
	Headers HeadersSpec `json:"headers"`
}

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
	SendGreaseFrame bool `json:"send_grease_frame,omitempty"`
	// PriorityParam — тип кадра PRIORITY_UPDATE. Chrome 984832; Firefox не шлёт.
	PriorityParam uint64 `json:"priority_param,omitempty"`
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
	ALPN                []string `json:"alpn,omitempty"`
	PermuteExtensions   *bool    `json:"permute_extensions,omitempty"`
}

// HTTP2Spec описывает отпечаток уровня HTTP/2.
type HTTP2Spec struct {
	Settings             []Setting `json:"settings,omitempty"`
	ConnectionWindowUpdate uint32  `json:"connection_window_update,omitempty"`
	PseudoOrder          []string  `json:"pseudo_order,omitempty"`
	StreamWeight         *uint16   `json:"stream_weight,omitempty"`
	StreamExclusive      *bool     `json:"stream_exclusive,omitempty"`
}

// Setting — пара id/value. Порядок в слайсе значим: он воспроизводится
// на проводе и входит в отпечаток.
type Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}

// HeadersSpec задаёт заголовки и их порядок.
type HeadersSpec struct {
	UserAgent string       `json:"user_agent,omitempty"`
	Order     []HeaderPair `json:"order,omitempty"`

	// FormBoundary — стиль границы multipart-формы: "webkit" или "firefox".
	// Форма границы наблюдаема и различает браузеры, поэтому это часть профиля,
	// а не деталь реализации.
	FormBoundary string `json:"form_boundary,omitempty"`
}

// HeaderPair — заголовок с его позицией в порядке отправки. Пустое значение
// означает «подставить из UserAgent», сохранив позицию.
type HeaderPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

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
		return fmt.Errorf("чтение каталога профилей %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("чтение %s: %w", e.Name(), err)
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
		return fmt.Errorf("разбор профиля: %w", err)
	}
	if p.Name == "" {
		return fmt.Errorf("у профиля отсутствует name")
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
	if out.TLS.RawClientHello == "" && len(out.TLS.ClientHelloSpec) == 0 && len(out.TLS.Extensions) == 0 {
		return nil, fmt.Errorf("профиль %q: не задан источник ClientHello "+
			"(raw_client_hello, extensions или client_hello_spec) ни в нём, ни в предках", name)
	}
	return out, nil
}

// chain собирает цепочку от листа к корню, ловя циклы и обрывы.
func (r *Registry) chain(name string) ([]*Profile, error) {
	var out []*Profile
	seen := map[string]bool{}
	for cur := name; cur != ""; {
		if seen[cur] {
			return nil, fmt.Errorf("цикл в based_on: %s -> %s",
				strings.Join(namesOf(out), " -> "), cur)
		}
		seen[cur] = true

		p, ok := r.raw[cur]
		if !ok {
			if len(out) == 0 {
				return nil, fmt.Errorf("профиль %q не найден", cur)
			}
			return nil, fmt.Errorf("профиль %q ссылается на несуществующий based_on %q",
				out[len(out)-1].Name, cur)
		}
		out = append(out, p)
		if len(out) > maxInheritDepth {
			return nil, fmt.Errorf("цепочка based_on глубже %d — вероятна ошибка в данных",
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
	if src.TLS.SignatureAlgorithms != nil {
		dst.TLS.SignatureAlgorithms = src.TLS.SignatureAlgorithms
	}
	if src.TLS.ALPN != nil {
		dst.TLS.ALPN = src.TLS.ALPN
	}
	if src.TLS.PermuteExtensions != nil {
		dst.TLS.PermuteExtensions = src.TLS.PermuteExtensions
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

	if src.HTTP3.Settings != nil {
		dst.HTTP3.Settings = src.HTTP3.Settings
	}
	if src.HTTP3.SettingsOrder != nil {
		dst.HTTP3.SettingsOrder = src.HTTP3.SettingsOrder
	}
	if src.HTTP3.PseudoOrder != nil {
		dst.HTTP3.PseudoOrder = src.HTTP3.PseudoOrder
	}
	if src.HTTP3.SendGreaseFrame {
		dst.HTTP3.SendGreaseFrame = true
	}
	if src.HTTP3.PriorityParam != 0 {
		dst.HTTP3.PriorityParam = src.HTTP3.PriorityParam
	}

	if src.QUIC.Parrot != "" {
		dst.QUIC.Parrot = src.QUIC.Parrot
	}
	if src.QUIC.ConnectionOptions != "" {
		dst.QUIC.ConnectionOptions = src.QUIC.ConnectionOptions
	}
	if src.QUIC.SendInitialRTT {
		dst.QUIC.SendInitialRTT = true
	}
	if src.QUIC.LegacyVersionInformationID {
		dst.QUIC.LegacyVersionInformationID = true
	}
	if src.QUIC.GreaseVersionFirst != nil {
		dst.QUIC.GreaseVersionFirst = src.QUIC.GreaseVersionFirst
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
