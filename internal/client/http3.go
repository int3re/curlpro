package client

import (
	"context"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"net/url"
	"strings"
	"sync"

	quic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/h3"
	"github.com/curlpro/curlpro/internal/profile"
)

// Путь HTTP/3 стоит особняком: это отдельный транспорт поверх UDP, а не ещё
// один вариант ALPN на TCP. Вдобавок вендоренный пакет h3 построен на net/http,
// тогда как остальной клиент — на fhttp: их типы несовместимы, поэтому запрос
// и ответ переводятся между ними явно.

type h3Transport struct {
	once sync.Once
	tr   *h3.Transport
	err  error

	// udp — транспорты QUIC, созданные в Dial. Собранный вручную quic.Transport
	// не считается одноразовым: закрытие соединения его не останавливает,
	// а h3.Transport о нём не знает. Без учёта после каждой сессии оставались
	// UDP-сокет и две горутины.
	udp udpTransports
}

type udpTransports struct {
	mu   sync.Mutex
	list []*quic.Transport
}

func (u *udpTransports) add(t *quic.Transport) {
	u.mu.Lock()
	u.list = append(u.list, t)
	u.mu.Unlock()
}

func (u *udpTransports) closeAll() {
	u.mu.Lock()
	list := u.list
	u.list = nil
	u.mu.Unlock()
	for _, t := range list {
		_ = t.Close()
	}
}

func (s *Session) http3() (*h3.Transport, error) {
	s.h3.once.Do(func() {
		s.h3.tr, s.h3.err = buildH3Transport(s.profile, s.opts, &s.h3.udp)
	})
	if s.h3.tr == nil && s.h3.err == nil {
		// once уже отработал в closeH3: транспорт не создавался и не будет.
		return nil, errSessionClosed
	}
	return s.h3.tr, s.h3.err
}

func buildH3Transport(p *profile.Profile, opts Options, udp *udpTransports) (*h3.Transport, error) {
	if !p.HTTP3.Enabled() {
		return nil, fmt.Errorf("профиль %q не описывает HTTP/3", p.Name)
	}

	// Настройки 0x06 и 0x33 задаются не напрямую, а через поля транспорта —
	// так устроен апстрим, и обойти это, не расходясь с ним, нельзя.
	var maxFieldSection uint64
	datagrams := false
	extra := make(map[uint64]uint64, len(p.HTTP3.Settings))
	for _, st := range p.HTTP3.Settings {
		switch st.ID {
		case 0x06:
			maxFieldSection = st.Value
		case 0x33:
			datagrams = st.Value != 0
		default:
			extra[st.ID] = st.Value
		}
	}

	return &h3.Transport{
		TLSClientConfig:        &utls.Config{InsecureSkipVerify: opts.InsecureSkipVerify},
		QUICConfig:             &quic.Config{EnableDatagrams: datagrams},
		EnableDatagrams:        datagrams,
		MaxResponseHeaderBytes: int(maxFieldSection),
		AdditionalSettings:     extra,
		// Распаковка своя (sendH3), и транспорту вмешиваться незачем. Без
		// этого флага он искал Accept-Encoding по каноническому ключу, не
		// находил строчного ключа профиля и дописывал второй accept-encoding:
		// gzip в хвост — дубль, которого оракулы не показывают.
		DisableCompression: true,
		Fingerprint: &h3.Fingerprint{
			SettingsOrder:   p.HTTP3.SettingsOrder,
			SendGreaseFrame: p.HTTP3.SendsGreaseFrame(),
			PriorityParam:   p.HTTP3.PriorityParamValue(),
		},
		// Повторами управляет сессия: два независимых механизма дали бы вдвое
		// больше запросов, чем заявлено, и не соблюдали бы общий бюджет.
		DisableInternalRetry: true,
		Dial: func(ctx context.Context, addr string, cfg *utls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			// Спека строится заново на каждое соединение: расширения
			// перемешиваются, значения GREASE разыгрываются заново.
			spec, err := quicSpec(p)
			if err != nil {
				return nil, err
			}
			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			ua, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				udpConn.Close()
				return nil, err
			}
			ut := &quic.UTransport{
				Transport: &quic.Transport{Conn: udpConn},
				QUICSpec:  spec,
			}
			conn, err := ut.DialEarly(ctx, ua, cfg, qcfg)
			if err != nil {
				_ = ut.Close()
				udpConn.Close()
				return nil, err
			}
			udp.add(ut.Transport)
			return conn, nil
		},
	}, nil
}

// explainH3Error переводит ошибки нижнего уровня в понятные.
//
// Отдельно разбирается случай динамической таблицы QPACK: профиль объявляет
// ненулевую ёмкость, как Chrome, и сервер вправе ей воспользоваться — но
// библиотека quic-go/qpack динамическую таблицу не реализует вовсе.
// Сообщение «expected Required Insert Count to be zero» об этом не говорит
// ничего, и без подсказки причину искать долго.
func explainH3Error(err error, profileName string) error {
	if strings.Contains(err.Error(), "Required Insert Count") {
		return fmt.Errorf("h3: сервер использовал динамическую таблицу QPACK, "+
			"которая не поддерживается декодером.\n"+
			"Профиль %q объявляет ненулевую ёмкость (SETTINGS 0x01), как это делает Chrome, "+
			"и сервер вправе ей воспользоваться.\n"+
			"Обход: профиль-дельта с \"http3\": {\"settings\": [{\"id\": 1, \"value\": 0}]} — "+
			"ценой расхождения отпечатка в первом же поле SETTINGS.\n"+
			"Исходная ошибка: %w", profileName, err)
	}
	return fmt.Errorf("h3: %w", err)
}

// quicSpec собирает спеку QUIC: паррот uquic плюс правки transport parameters
// из профиля.
func quicSpec(p *profile.Profile) (*quic.QUICSpec, error) {
	id, err := parrotID(p.QUIC.Parrot)
	if err != nil {
		return nil, err
	}
	spec, err := quic.QUICID2Spec(id)
	if err != nil {
		return nil, fmt.Errorf("паррот %q: %w", p.QUIC.Parrot, err)
	}
	if spec.ClientHelloSpec != nil {
		q := p.QUIC
		if err := profile.ApplyQUIC(spec.ClientHelloSpec, &q); err != nil {
			return nil, err
		}
	}
	return &spec, nil
}

func parrotID(name string) (quic.QUICID, error) {
	switch name {
	case "", "chrome146":
		return quic.QUICChrome_146, nil
	case "chrome115":
		return quic.QUICChrome_115, nil
	case "firefox116":
		return quic.QUICFirefox_116A, nil
	default:
		return quic.QUICID{}, fmt.Errorf("неизвестный паррот QUIC %q "+
			"(доступны chrome146, chrome115, firefox116)", name)
	}
}

// sendH3 выполняет один запрос по HTTP/3. Тело ответа остаётся открытым.
//
// Контекст приходит от вызывающего: так таймаут действует и здесь, а тело
// поддерживает BodyFile наравне с обычным путём.
func (s *Session) sendH3(ctx context.Context, r *Request, u *url.URL) (*nethttp.Response, error) {
	tr, err := s.http3()
	if err != nil {
		return nil, err
	}

	method := r.Method
	if method == "" {
		method = nethttp.MethodGet
	}
	body, size, err := requestBody(r)
	if err != nil {
		return nil, err
	}
	req, err := nethttp.NewRequestWithContext(ctx, method, r.URL, body)
	if err != nil {
		if c, ok := body.(io.Closer); ok {
			c.Close()
		}
		return nil, err
	}
	if size >= 0 {
		req.ContentLength = size
	}
	s.applyH3Headers(req, r, u)

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, explainH3Error(err, s.profile.Name)
	}
	if s.jar != nil {
		if cookies := resp.Cookies(); len(cookies) > 0 {
			fc := toFhttpCookies(cookies)
			s.jar.SetCookies(u, fc)
			s.recordCookies(u, fc)
		}
	}

	// В отличие от fhttp, net/http распаковывает только gzip и только когда
	// сам поставил Accept-Encoding. Профиль объявляет ещё br и zstd, поэтому
	// на этом пути распаковка своя. HEAD не трогаем: тело пустое по
	// определению, а Content-Encoding описывает то, что было бы у GET.
	if ce := resp.Header.Get("Content-Encoding"); !resp.Uncompressed && ce != "" && method != nethttp.MethodHead {
		body, err := decompress(resp.Body, ce)
		if err != nil {
			return nil, err
		}
		resp.Body = body
		resp.Uncompressed = true
	}
	return resp, nil
}

// applyH3Headers записывает заголовки в запрос net/http и служебные ключи
// вендоренного пакета.
//
// Сборка общая с HTTP/1.1 и HTTP/2 (buildHeaders): пока здесь была своя копия
// правил, путь HTTP/3 молча терял SuppressHeaders и слот cookie. h1Order не
// передаётся — Host и Connection в HTTP/3 не отправляются.
func (s *Session) applyH3Headers(req *nethttp.Request, r *Request, u *url.URL) {
	built := s.buildHeaders(r, u, req.Host, nil)

	for _, h := range built {
		// Прямая запись вместо Set: тот канонизирует имя, а порядок и регистр
		// задаёт профиль. На провод имена всё равно уйдут строчными — их
		// приводит request_writer.
		req.Header[h.Key] = []string{h.Value}
	}
	suppressDefaultUA(req.Header, built, false)
	tpl := s.template(r)
	req.Header[h3.HeaderOrderKey] = wireOrder(built, s.wantOrder(r, nil, tpl), tpl.anchor)

	pseudo := s.profile.HTTP3.PseudoOrder
	if len(pseudo) == 0 {
		pseudo = s.profile.HTTP2.PseudoOrder
	}
	if len(pseudo) > 0 {
		req.Header[h3.PseudoHeaderOrderKey] = pseudo
	}
}

// closeH3 закрывает транспорт HTTP/3 и UDP-транспорты его соединений.
//
// once здесь «занимается» намеренно: если транспорт ещё не создавался,
// создавать его после закрытия сессии незачем, а параллельный первый запрос
// получит errSessionClosed из http3() вместо гонки за полем tr.
func (s *Session) closeH3() {
	s.h3.once.Do(func() {})
	if s.h3.tr != nil {
		_ = s.h3.tr.Close()
	}
	s.h3.udp.closeAll()
}
