package client

import (
	"bytes"
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
}

func (s *Session) http3() (*h3.Transport, error) {
	s.h3.once.Do(func() {
		s.h3.tr, s.h3.err = buildH3Transport(s.profile, s.opts)
	})
	return s.h3.tr, s.h3.err
}

func buildH3Transport(p *profile.Profile, opts Options) (*h3.Transport, error) {
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
		Fingerprint: &h3.Fingerprint{
			SettingsOrder:   p.HTTP3.SettingsOrder,
			SendGreaseFrame: p.HTTP3.SendGreaseFrame,
			PriorityParam:   p.HTTP3.PriorityParam,
		},
		Dial: func(ctx context.Context, addr string, cfg *utls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			// Спека строится заново на каждое соединение: расширения
			// перемешиваются, значения GREASE разыгрываются заново.
			spec, err := quicSpec(p)
			if err != nil {
				return nil, err
			}
			udp, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			ua, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				udp.Close()
				return nil, err
			}
			ut := &quic.UTransport{
				Transport: &quic.Transport{Conn: udp},
				QUICSpec:  spec,
			}
			return ut.DialEarly(ctx, ua, cfg, qcfg)
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
func (s *Session) sendH3(r *Request, u *url.URL) (*nethttp.Response, error) {
	tr, err := s.http3()
	if err != nil {
		return nil, err
	}

	method := r.Method
	if method == "" {
		method = nethttp.MethodGet
	}
	var body io.Reader
	if len(r.Body) > 0 {
		body = bytes.NewReader(r.Body)
	}
	req, err := nethttp.NewRequest(method, r.URL, body)
	if err != nil {
		return nil, err
	}
	s.applyH3Headers(req, r, u)

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, explainH3Error(err, s.profile.Name)
	}
	if s.jar != nil {
		if cookies := resp.Cookies(); len(cookies) > 0 {
			s.jar.SetCookies(u, toFhttpCookies(cookies))
		}
	}

	// В отличие от fhttp, net/http распаковывает только gzip и только когда
	// сам поставил Accept-Encoding. Профиль объявляет ещё br и zstd, поэтому
	// на этом пути распаковка своя.
	if !resp.Uncompressed {
		body, err := decompress(resp.Body, resp.Header.Get("Content-Encoding"))
		if err != nil {
			return nil, err
		}
		resp.Body = body
	}
	return resp, nil
}

// applyH3Headers повторяет логику applyHeaders для net/http и служебных ключей
// вендоренного пакета.
func (s *Session) applyH3Headers(req *nethttp.Request, r *Request, u *url.URL) {
	useDefaults := s.opts.DefaultHeaders && !r.NoDefaultHeaders

	order := make([]string, 0, 16)
	seen := make(map[string]bool, 16)
	add := func(key, value string) {
		req.Header.Set(key, value)
		if lk := strings.ToLower(key); !seen[lk] {
			seen[lk] = true
			order = append(order, key)
		}
	}

	if useDefaults {
		for _, h := range s.profile.ResolvedHeaders() {
			if h.Value != "" {
				add(h.Key, h.Value)
			}
		}
	}
	for k, v := range r.Headers {
		add(k, v)
	}
	if s.jar != nil {
		if cookies := s.jar.Cookies(u); len(cookies) > 0 {
			parts := make([]string, 0, len(cookies))
			for _, c := range cookies {
				parts = append(parts, c.Name+"="+c.Value)
			}
			add("cookie", strings.Join(parts, "; "))
		}
	}

	if want := firstNonEmpty(r.HeaderOrder, s.opts.HeaderOrder); len(want) > 0 {
		order = reorder(order, want)
	}
	req.Header[h3.HeaderOrderKey] = order

	pseudo := s.profile.HTTP3.PseudoOrder
	if len(pseudo) == 0 {
		pseudo = s.profile.HTTP2.PseudoOrder
	}
	if len(pseudo) > 0 {
		req.Header[h3.PseudoHeaderOrderKey] = pseudo
	}
}

// closeH3 закрывает транспорт HTTP/3, если он создавался.
func (s *Session) closeH3() {
	if s.h3.tr != nil {
		_ = s.h3.tr.Close()
	}
}

var _ = context.Background
