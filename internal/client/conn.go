package client

import (
	"bufio"
	"fmt"
	"net"
	"sync"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/profile"
)

// conn — соединение с сервером поверх уже установленного TLS.
//
// Протокол выбирает сервер через ALPN, а список предложений берётся из профиля:
// у Safari 15 и старых Firefox в ClientHello нет "h2", и навязывать его —
// значит послать отпечаток, которого у этого браузера не бывает.
type conn struct {
	proto string // "h2" или "http/1.1"

	h2 *http2.ClientConn

	// Для HTTP/1.1 запросы по одному соединению строго последовательны:
	// ответ надо дочитать до конца, прежде чем писать следующий запрос.
	mu   sync.Mutex
	raw  net.Conn
	br   *bufio.Reader
	dead bool
}

func newH2Conn(cc *http2.ClientConn) *conn {
	return &conn{proto: "h2", h2: cc}
}

func newH1Conn(c net.Conn) *conn {
	return &conn{proto: "http/1.1", raw: c, br: bufio.NewReader(c)}
}

func (c *conn) usable() bool {
	if c.h2 != nil {
		return c.h2.CanTakeNewRequest()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.dead
}

func (c *conn) roundTrip(req *http.Request) (*http.Response, error) {
	if c.h2 != nil {
		return c.h2.RoundTrip(req)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return nil, fmt.Errorf("соединение закрыто")
	}
	if err := req.Write(c.raw); err != nil {
		c.dead = true
		return nil, fmt.Errorf("отправка запроса: %w", err)
	}
	resp, err := http.ReadResponse(c.br, req)
	if err != nil {
		c.dead = true
		return nil, fmt.Errorf("чтение ответа: %w", err)
	}
	// Close: true в ответе означает, что сервер закроет соединение
	// и переиспользовать его нельзя.
	if resp.Close {
		c.dead = true
	}
	return resp, nil
}

func (c *conn) close() {
	if c.h2 != nil {
		c.h2.Close()
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dead && c.raw != nil {
		c.raw.Close()
		c.dead = true
	}
}

// setALPN подменяет список протоколов в уже построенной спеке.
// Сообщает, нашлось ли расширение: промах должен быть ошибкой, а не тихой
// потерей настройки.
func setALPN(spec *utls.ClientHelloSpec, protos []string) bool {
	for _, e := range spec.Extensions {
		if alpn, ok := e.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = protos
			return true
		}
	}
	return false
}

// alpnFromProfile достаёт список ALPN из профиля.
//
// Для профилей на основе raw_client_hello поле extensions пустое — там ALPN
// зашит в самих байтах и uTLS выставит его сам при ApplyPreset.
func alpnFromProfile(p *profile.Profile) []string {
	for _, e := range p.TLS.Extensions {
		if e.Type == "application_layer_protocol_negotiation" {
			return e.ALPN
		}
	}
	if len(p.TLS.ALPN) > 0 {
		return p.TLS.ALPN
	}
	return nil
}
