package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

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
	spec  dialSpec

	h2 *http2.ClientConn

	// Для HTTP/1.1 запросы по одному соединению строго последовательны:
	// ответ надо дочитать до конца, прежде чем писать следующий запрос.
	// Мьютекс сериализует только сам обмен; закрытие сокета его не берёт.
	mu  sync.Mutex
	raw net.Conn
	br  *bufio.Reader

	// dead атомарный, чтобы usable() не брал c.mu: тот удерживается на всё
	// время запроса, и проверка пригодности под ним заморозила бы пул.
	dead atomic.Bool

	// busy — сколько запросов держат соединение прямо сейчас.
	//
	// Для HTTP/1.1 это 0 или 1: пока тело не дочитано, следующий запрос писать
	// нельзя. Раньше roundTrip отпускал мьютекс сразу после чтения заголовков,
	// и второй запрос писал поверх недочитанного тела, а ответ разбирал
	// из чужих байт — тихая порча данных.
	busy atomic.Int32

	// pooled и lastUsed читаются и пишутся только под Session.mu.
	pooled   bool
	lastUsed time.Time
}

func newH2Conn(cc *http2.ClientConn, spec dialSpec) *conn {
	return &conn{proto: "h2", h2: cc, spec: spec, pooled: true}
}

func newH1Conn(c net.Conn, spec dialSpec) *conn {
	return &conn{proto: "http/1.1", raw: c, br: bufio.NewReader(c), spec: spec, pooled: true}
}

func (c *conn) usable() bool {
	if c.dead.Load() {
		return false
	}
	if c.h2 != nil {
		return c.h2.CanTakeNewRequest()
	}
	return true
}

// canTake сообщает, можно ли выдать соединение ещё одному запросу.
// HTTP/2 мультиплексирует, HTTP/1.1 — нет.
func (c *conn) canTake() bool {
	if c.h2 != nil {
		return true
	}
	return c.busy.Load() == 0
}

func (c *conn) acquire()       { c.busy.Add(1) }
func (c *conn) release() int32 { return c.busy.Add(-1) }

func (c *conn) roundTrip(ctx context.Context, req *http.Request) (*http.Response, error) {
	if c.h2 != nil {
		// Для HTTP/2 предел задаётся контекстом запроса: соединение общее
		// для нескольких потоков, и deadline на сокете оборвал бы чужие.
		return c.h2.RoundTrip(req)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead.Load() {
		return nil, fmt.Errorf("соединение закрыто")
	}

	// В HTTP/1.1 запросы по соединению последовательны, поэтому предел
	// ставится прямо на сокет. Без него медленный ответ висел бы дольше
	// заявленного таймаута: проверка между попытками его не ограничивает.
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.raw.SetDeadline(deadline)
	}

	if err := req.Write(c.raw); err != nil {
		c.dead.Store(true)
		return nil, fmt.Errorf("отправка запроса: %w", err)
	}
	resp, err := http.ReadResponse(c.br, req)
	if err != nil {
		c.dead.Store(true)
		return nil, fmt.Errorf("чтение ответа: %w", err)
	}
	// Close: true в ответе означает, что сервер закроет соединение
	// и переиспользовать его нельзя.
	if resp.Close {
		c.dead.Store(true)
	}
	if resp.Body == http.NoBody {
		return resp, nil
	}

	// Тело от ReadResponse при закрытии дочитывает остаток до EOF (transfer.go,
	// ветка default): так net/http бережёт сокет для следующего запроса.
	// Transport обходит это обёрткой bodyEOFSignal, а здесь Transport
	// не используется — и «прочитать килобайт и закрыть» означало скачать
	// всё тело. Обёртка h1Body отслеживает EOF: недочитанное соединение
	// дешевле выбросить, чем дренировать.
	resp.Body = &h1Body{inner: resp.Body, conn: c, want: resp.ContentLength}

	// Распаковка на пути HTTP/1.1 — своя. У fhttp она живёт в Transport
	// (persistConn.readLoop) и в транспорте HTTP/2; conn.roundTrip ходит мимо
	// обоих, и до этой правки клиент отдавал gzip-байты как тело, хотя профиль
	// объявляет accept-encoding и сервер сжимать вправе.
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && req.Method != http.MethodHead {
		body, err := decompress(resp.Body, ce)
		if err != nil {
			resp.Body.Close()
			c.dead.Store(true)
			return nil, err
		}
		resp.Body = body
		resp.Uncompressed = true
		resp.ContentLength = -1
	}
	return resp, nil
}

// h1Body следит, дошло ли тело HTTP/1.1 до конца.
//
// Полнота определяется либо по EOF, либо по числу прочитанных байт против
// Content-Length: распаковщики вроде brotli останавливаются на последнем блоке,
// не запрашивая EOF у нижнего потока, и без счётчика каждый такой ответ
// выбрасывал бы исправное соединение.
type h1Body struct {
	mu     sync.Mutex
	inner  io.ReadCloser
	conn   *conn
	want   int64 // Content-Length или -1
	read   int64
	sawEOF bool
	closed bool
}

func (b *h1Body) Read(p []byte) (int, error) {
	n, err := b.inner.Read(p)
	b.mu.Lock()
	b.read += int64(n)
	if err == io.EOF {
		b.sawEOF = true
	}
	b.mu.Unlock()
	return n, err
}

func (b *h1Body) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	complete := b.sawEOF || (b.want >= 0 && b.read >= b.want)
	b.mu.Unlock()

	if complete {
		return b.inner.Close()
	}
	// Недочитанное тело: сокет закрывается первым, иначе inner.Close
	// дочитывал бы остаток. Ошибка чтения из закрытого сокета ожидаема
	// и наружу не отдаётся — для вызывающего закрытие прошло штатно.
	b.conn.close()
	_ = b.inner.Close()
	return nil
}

// shutdown мягко доигрывает HTTP/2-соединение, дожидаясь текущих потоков.
func (c *conn) shutdown(ctx context.Context) {
	if c.h2 != nil {
		_ = c.h2.Shutdown(ctx)
		return
	}
	c.close()
}

// close закрывает соединение немедленно.
//
// c.mu здесь не берётся намеренно: net.Conn.Close безопасен из другой
// горутины и прерывает блокирующее чтение. Раньше close ждал мьютекс,
// который roundTrip держит до конца ReadResponse, и Session.Close
// выстаивал очередь за медленным ответом вместо того, чтобы оборвать его.
func (c *conn) close() {
	c.dead.Store(true)
	if c.h2 != nil {
		c.h2.Close()
		return
	}
	if c.raw != nil {
		c.raw.Close()
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
