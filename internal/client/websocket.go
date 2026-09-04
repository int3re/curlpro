package client

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	kflate "github.com/klauspost/compress/flate"

	"github.com/curlpro/curlpro/internal/profile"
)

// WebSocket поверх того же TLS-соединения, что и обычные запросы.
//
// Рукопожатие — это обычный HTTP/1.1-запрос с Upgrade, поэтому его заголовки
// тоже часть отпечатка: браузер шлёт свой набор в своём порядке. Фрейминг
// реализован здесь, а не взят из библиотеки, чтобы не тянуть чужой диалер,
// который открыл бы соединение мимо нашего TLS.

// Опкоды кадров (RFC 6455, раздел 5.2).
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// magicGUID из RFC 6455: сервер приклеивает его к ключу клиента,
// чтобы доказать, что понял протокол, а не просто отразил заголовок.
const magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// defaultMaxMessageSize — предел сообщения, если вызывающий его не задал.
// Длина кадра приходит из сети, и без предела заявленные сервером 2^62 байт
// уходили в make([]byte) — паника, которая в c-shared библиотеке убивает
// процесс Python.
const defaultMaxMessageSize = 64 << 20

// Message — принятое сообщение.
type Message struct {
	// Binary отличает двоичное сообщение от текстового: на проводе это разные
	// опкоды, и сервер вправе их различать.
	Binary bool
	Data   []byte
}

// WebSocket — установленное соединение.
type WebSocket struct {
	conn net.Conn
	br   *bufio.Reader

	// Запись сериализуется: два одновременных сообщения перемешали бы кадры.
	writeMx sync.Mutex
	readMx  sync.Mutex

	closeMx    sync.Mutex
	closed     bool // кадр Close отправлен или получен
	connClosed bool // сокет закрыт

	timeout    time.Duration
	maxMessage int64

	// deflate не nil, когда сервер принял permessage-deflate.
	deflate *permessageDeflate
}

// WebSocketOptions настраивают соединение.
type WebSocketOptions struct {
	// Headers добавляются к рукопожатию поверх заголовков профиля.
	Headers map[string]string
	// Subprotocols объявляются в Sec-WebSocket-Protocol.
	Subprotocols []string
	// Timeout ограничивает рукопожатие и чтение или запись одного сообщения.
	Timeout time.Duration
	// MaxMessageSize ограничивает принимаемое сообщение, в байтах, включая
	// распакованный размер. Ноль — defaultMaxMessageSize.
	MaxMessageSize int64
}

// errWSClosed — соединение закрыто: сервером или вызывающим.
var errWSClosed = errors.New("соединение закрыто")

// DialWebSocket выполняет рукопожатие и возвращает соединение.
//
// Схема wss:// обязательна: ws:// без TLS не имеет смысла, потому что весь
// смысл библиотеки — в отпечатке TLS.
func (s *Session) DialWebSocket(rawURL string, opts WebSocketOptions) (*WebSocket, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("разбор URL: %w", err)
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "https":
	default:
		return nil, fmt.Errorf("поддерживается только wss://, получено %q", u.Scheme)
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = s.opts.Timeout
	}
	maxMessage := opts.MaxMessageSize
	if maxMessage <= 0 {
		maxMessage = defaultMaxMessageSize
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Рукопожатие идёт по HTTP/1.1: Upgrade в HTTP/2 работает иначе
	// (RFC 8441, расширенный CONNECT) и поддерживается не везде.
	c, err := s.dialHTTP1(ctx, u)
	if err != nil {
		return nil, err
	}

	key, err := websocketKey()
	if err != nil {
		c.close()
		return nil, err
	}

	req, err := s.websocketRequest(u, key, opts)
	if err != nil {
		c.close()
		return nil, err
	}

	resp, err := c.roundTrip(ctx, req)
	if err != nil {
		c.close()
		return nil, fmt.Errorf("рукопожатие: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body.Close()
		c.close()
		return nil, fmt.Errorf("сервер ответил %s вместо 101", resp.Status)
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), acceptKey(key); got != want {
		resp.Body.Close()
		c.close()
		return nil, fmt.Errorf("неверный Sec-WebSocket-Accept: %q, ожидался %q", got, want)
	}
	deflate, err := parseDeflate(resp.Header.Get("Sec-WebSocket-Extensions"))
	if err != nil {
		c.close()
		return nil, err
	}

	// Дедлайн рукопожатия снимается: дальше каждое сообщение ставит свой.
	_ = c.raw.SetDeadline(time.Time{})
	return &WebSocket{conn: c.raw, br: c.br, timeout: timeout, maxMessage: maxMessage, deflate: deflate}, nil
}

// wsFallbackOrder — рукопожатие для профиля без секции websocket.
//
// Это RFC-минимум в правдоподобном порядке, а не отпечаток конкретного
// браузера: наборы Chrome и Firefox различаются, и угадывать здесь нечего.
// Профили Chrome и Edge несут замеренный шаблон, см. PROFILE-SCHEMA.md.
var wsFallbackOrder = []profile.HeaderPair{
	{Key: "Host"},
	{Key: "Connection", Value: "Upgrade"},
	{Key: "Upgrade", Value: "websocket"},
	{Key: "Sec-WebSocket-Version", Value: "13"},
	{Key: "Sec-WebSocket-Key"},
	{Key: "Sec-WebSocket-Extensions", Value: "permessage-deflate; client_max_window_bits"},
	{Key: "Origin"},
	{Key: "User-Agent"},
	{Key: "Accept-Encoding"},
	{Key: "Accept-Language"},
	{Key: "Cookie"},
	{Key: "Sec-WebSocket-Protocol"},
}

// websocketHeaders собирает заголовки рукопожатия по шаблону профиля.
//
// Шаблон отдельный от навигационного: Chrome не шлёт на рукопожатии ни
// sec-ch-ua, ни sec-fetch-*, ни accept, зато шлёт Pragma и Cache-Control,
// а Sec-WebSocket-Key ставит после Accept-Language (замер Chromium 148).
// Раньше рукопожатие собиралось из навигационного набора, а WebSocket-имена
// шли «кастомными» в алфавитном порядке перед якорем — и с Host в конце.
//
// Пустое значение — слот, заполняемый по имени; слот без значения выпадает.
func (s *Session) websocketHeaders(u *url.URL, key string, opts WebSocketOptions) []headerKV {
	order := s.profile.WebSocket.Order
	if len(order) == 0 {
		order = wsFallbackOrder
	}
	out := make([]headerKV, 0, len(order)+len(opts.Headers))
	index := make(map[string]int, len(order))
	add := func(k, v string) {
		lk := strings.ToLower(k)
		if i, ok := index[lk]; ok {
			out[i].Value = v
			return
		}
		index[lk] = len(out)
		out = append(out, headerKV{Key: k, Value: v})
	}

	for _, h := range order {
		if h.Value != "" {
			add(h.Key, h.Value)
			continue
		}
		switch strings.ToLower(h.Key) {
		case "host":
			add(h.Key, u.Host)
		case "user-agent":
			if ua := s.profile.Headers.UserAgent; ua != "" {
				add(h.Key, ua)
			}
		case "origin":
			add(h.Key, "https://"+u.Host)
		case "sec-websocket-key":
			add(h.Key, key)
		case "sec-websocket-protocol":
			if len(opts.Subprotocols) > 0 {
				add(h.Key, strings.Join(opts.Subprotocols, ", "))
			}
		case "cookie":
			if c := s.cookieHeader(u); c != "" {
				add(h.Key, c)
			}
		default:
			// accept-encoding, accept-language и прочее берутся из
			// навигационного набора профиля — значения там те же.
			if v := s.profileHeaderValue(h.Key); v != "" {
				add(h.Key, v)
			}
		}
	}

	// Пользовательские заголовки: переопределение меняет значение на месте,
	// новое имя уходит в конец. Из браузера к рукопожатию заголовок не
	// добавить вовсе, так что эталонной позиции у него нет.
	names := make([]string, 0, len(opts.Headers))
	for k := range opts.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		add(k, opts.Headers[k])
	}
	return out
}

// profileHeaderValue возвращает значение заголовка из навигационного набора.
func (s *Session) profileHeaderValue(name string) string {
	for _, h := range s.profile.ResolvedHeaders() {
		if strings.EqualFold(h.Key, name) {
			return h.Value
		}
	}
	return ""
}

// websocketRequest собирает запрос рукопожатия.
func (s *Session) websocketRequest(u *url.URL, key string, opts WebSocketOptions) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	built := s.websocketHeaders(u, key, opts)
	order := make([]string, 0, len(built))
	for _, h := range built {
		req.Header[h.Key] = []string{h.Value}
		order = append(order, strings.ToLower(h.Key))
	}
	suppressDefaultUA(req.Header, built, true)
	req.Header[http.HeaderOrderKey] = order
	return req, nil
}

// dialHTTP1 открывает отдельное соединение, согласуя http/1.1.
//
// Признак передаётся в dialSpec, а не выставляется в опциях сессии: правка
// s.opts на лету была гонкой и меняла ALPN в ClientHello для всех соединений,
// включая обычные запросы. Соединение WebSocket не кладётся в пул: оно
// переходит в собственность сокета и живёт до его закрытия.
func (s *Session) dialHTTP1(ctx context.Context, u *url.URL) (*conn, error) {
	c, err := s.dial(ctx, u, s.newDialSpec(u, s.opts.Proxy, true))
	if err != nil {
		return nil, err
	}
	if c.proto != "http/1.1" {
		c.close()
		return nil, fmt.Errorf("сервер согласовал %s, а для WebSocket нужен http/1.1", c.proto)
	}
	return c, nil
}

func websocketKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("ключ рукопожатия: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

func acceptKey(key string) string {
	h := sha1.Sum([]byte(key + magicGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// permessage-deflate (RFC 7692)
// ---------------------------------------------------------------------------

// permessageDeflate — состояние согласованного расширения.
//
// Рукопожатие объявляет permessage-deflate, потому что так делает Chrome.
// До этой правки сервер, принявший расширение (Python websockets, Node ws),
// слал кадры с RSV1, а клиент отдавал сырой deflate как текст.
type permessageDeflate struct {
	serverNoContext bool
	clientNoContext bool
	clientBits      int

	// window — последние 32 КиБ распакованных данных. При context takeover
	// компрессор сервера ссылается на предыдущие сообщения; вместо хранения
	// состояния декодера между сообщениями окно подаётся словарём.
	window []byte

	// Отправка: один компрессор на соединение, Flush даёт границу сообщения.
	wbuf bytes.Buffer
	w    deflateWriter
}

// deflateWriter — общее у compress/flate и klauspost/compress/flate.
//
// Два компрессора нужны из-за окна: стандартный умеет только 32 КиБ,
// а сервер вправе потребовать меньше через client_max_window_bits.
type deflateWriter interface {
	io.Writer
	Flush() error
	Reset(io.Writer)
}

const deflateWindow = 32 << 10

// deflateTail восстанавливает пустой stored-блок, который отправитель срезал
// (RFC 7692, 7.2.2), а deflateFinal закрывает поток: без финального блока
// flate.Reader сообщил бы ErrUnexpectedEOF вместо EOF на границе сообщения.
var (
	deflateTail  = []byte{0x00, 0x00, 0xff, 0xff}
	deflateFinal = []byte{0x01, 0x00, 0x00, 0xff, 0xff}
)

// parseDeflate разбирает ответное Sec-WebSocket-Extensions.
func parseDeflate(header string) (*permessageDeflate, error) {
	if strings.TrimSpace(header) == "" {
		return nil, nil
	}
	for _, ext := range strings.Split(header, ",") {
		parts := strings.Split(ext, ";")
		if strings.TrimSpace(parts[0]) != "permessage-deflate" {
			return nil, withCode(CodeWSProtocol,
				fmt.Errorf("сервер согласовал расширение %q, которое не предлагалось", strings.TrimSpace(parts[0])))
		}
		d := &permessageDeflate{clientBits: 15}
		for _, p := range parts[1:] {
			name, value, _ := strings.Cut(strings.TrimSpace(p), "=")
			value = strings.Trim(strings.TrimSpace(value), `"`)
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "server_no_context_takeover":
				d.serverNoContext = true
			case "client_no_context_takeover":
				d.clientNoContext = true
			case "server_max_window_bits":
				// Окно сервера ≤ 32 КиБ по определению; декодеру достаточно
				// максимального, ограничение не нужно.
			case "client_max_window_bits":
				if value != "" {
					bits, err := strconv.Atoi(value)
					if err != nil || bits < 8 || bits > 15 {
						return nil, withCode(CodeWSProtocol,
							fmt.Errorf("permessage-deflate: некорректный client_max_window_bits %q", value))
					}
					d.clientBits = bits
				}
			default:
				return nil, withCode(CodeWSProtocol,
					fmt.Errorf("permessage-deflate: неизвестный параметр %q", name))
			}
		}
		return d, nil
	}
	return nil, nil
}

// inflate распаковывает сообщение и пополняет окно.
func (d *permessageDeflate) inflate(compressed []byte, limit int64) ([]byte, error) {
	src := io.MultiReader(bytes.NewReader(compressed), bytes.NewReader(deflateTail), bytes.NewReader(deflateFinal))
	var r io.ReadCloser
	if d.serverNoContext || len(d.window) == 0 {
		r = flate.NewReader(src)
	} else {
		r = flate.NewReaderDict(src, d.window)
	}
	out, err := io.ReadAll(io.LimitReader(r, limit+1))
	r.Close()
	if err != nil {
		return nil, withCode(CodeWSProtocol, fmt.Errorf("permessage-deflate: %w", err))
	}
	if int64(len(out)) > limit {
		return nil, withCode(CodeWSTooBig, fmt.Errorf("сообщение больше предела %d байт после распаковки", limit))
	}
	if !d.serverNoContext {
		d.window = append(d.window, out...)
		if len(d.window) > deflateWindow {
			d.window = append([]byte(nil), d.window[len(d.window)-deflateWindow:]...)
		}
	}
	return out, nil
}

// canCompress сообщает, можно ли сжимать исходящие сообщения.
//
// Раньше при окне меньше 32 КиБ сообщения уходили несжатыми: compress/flate
// такого окна не умеет. Это разрешено RFC, но Chrome сжимал бы, а разница
// видна серверу по каждому кадру.
func (d *permessageDeflate) canCompress() bool { return d != nil }

// newDeflateWriter создаёт компрессор с окном 1<<bits.
//
// Окно меньше стандартного умеет только klauspost/compress; для обычных
// 15 бит остаётся compress/flate, чтобы не менять то, что уже проверено.
func newDeflateWriter(buf *bytes.Buffer, bits int) (deflateWriter, error) {
	if bits >= 15 {
		return flate.NewWriter(buf, flate.DefaultCompression)
	}
	return kflate.NewWriterWindow(buf, 1<<bits)
}

// compress сжимает сообщение, срезая границу stored-блока по RFC 7692, 7.2.1.
func (d *permessageDeflate) compress(payload []byte) ([]byte, error) {
	if d.w == nil {
		w, err := newDeflateWriter(&d.wbuf, d.clientBits)
		if err != nil {
			return nil, err
		}
		d.w = w
	}
	d.wbuf.Reset()
	if d.clientNoContext {
		d.w.Reset(&d.wbuf)
	}
	if _, err := d.w.Write(payload); err != nil {
		return nil, err
	}
	if err := d.w.Flush(); err != nil {
		return nil, err
	}
	out := d.wbuf.Bytes()
	out = bytes.TrimSuffix(out, deflateTail)
	return append([]byte(nil), out...), nil
}

// ---------------------------------------------------------------------------
// Кадры
// ---------------------------------------------------------------------------

// Send отправляет сообщение целиком одним кадром. Если расширение
// согласовано, сообщение сжимается — так делает Chrome.
func (ws *WebSocket) Send(binary bool, data []byte) error {
	op := byte(opText)
	if binary {
		op = opBinary
	}
	if ws.deflate.canCompress() {
		ws.writeMx.Lock()
		compressed, err := ws.deflate.compress(data)
		ws.writeMx.Unlock()
		if err != nil {
			return fmt.Errorf("сжатие сообщения: %w", err)
		}
		return ws.writeFrame(op, compressed, true)
	}
	return ws.writeFrame(op, data, false)
}

// Ping отправляет ping; ответный pong обрабатывается в Recv автоматически.
func (ws *WebSocket) Ping(data []byte) error { return ws.writeFrame(opPing, data, false) }

// writeFrame пишет один кадр.
//
// Клиент обязан маскировать полезную нагрузку (RFC 6455, раздел 5.3):
// немаскированный кадр от клиента сервер должен разорвать, и это заодно
// мгновенно выдало бы не-браузер.
func (ws *WebSocket) writeFrame(opcode byte, payload []byte, compressed bool) error {
	ws.writeMx.Lock()
	defer ws.writeMx.Unlock()

	if ws.isClosed() {
		return withCode(CodeWSClosed, errWSClosed)
	}
	if ws.timeout > 0 {
		_ = ws.conn.SetWriteDeadline(time.Now().Add(ws.timeout))
	}

	head := make([]byte, 0, 14+len(payload))
	first := 0x80 | opcode // FIN + опкод
	if compressed {
		first |= 0x40 // RSV1: сообщение сжато (RFC 7692)
	}
	head = append(head, first)

	n := len(payload)
	switch {
	case n < 126:
		head = append(head, 0x80|byte(n)) // бит маски + длина
	case n <= 0xFFFF:
		head = append(head, 0x80|126)
		head = binary.BigEndian.AppendUint16(head, uint16(n))
	default:
		head = append(head, 0x80|127)
		head = binary.BigEndian.AppendUint64(head, uint64(n))
	}

	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return fmt.Errorf("маска кадра: %w", err)
	}
	head = append(head, mask[:]...)
	for i := 0; i < n; i++ {
		head = append(head, payload[i]^mask[i%4])
	}

	if _, err := ws.conn.Write(head); err != nil {
		return fmt.Errorf("отправка кадра: %w", err)
	}
	return nil
}

// Recv читает следующее сообщение, склеивая продолжения и отвечая на ping.
func (ws *WebSocket) Recv() (*Message, error) {
	ws.readMx.Lock()
	defer ws.readMx.Unlock()

	if ws.isClosed() {
		return nil, withCode(CodeWSClosed, errWSClosed)
	}

	var buf []byte
	var msgOp byte
	compressed := false

	for {
		if ws.timeout > 0 {
			_ = ws.conn.SetReadDeadline(time.Now().Add(ws.timeout))
		}
		fr, err := ws.readFrame(int64(len(buf)))
		if err != nil {
			return nil, err
		}

		switch fr.opcode {
		case opPing:
			// Ответить обязаны: молчание в ответ на ping — тоже поведение,
			// отличающее клиента от браузера.
			if err := ws.writeFrame(opPong, fr.payload, false); err != nil {
				return nil, err
			}
			continue
		case opPong:
			continue
		case opClose:
			code, reason := parseClose(fr.payload)
			// Ответный Close и закрытие сокета — сразу (RFC 6455, 5.5.1).
			// Раньше здесь только выставлялся флаг, и последующий Close()
			// вызывающего выходил по нему, не закрыв сокет: соединение жило
			// до конца процесса.
			ws.closeWith(fr.payload[:min(len(fr.payload), 2)])
			return nil, withCode(CodeWSClosed, fmt.Errorf("соединение закрыто сервером: %d %s", code, reason))
		case opText, opBinary:
			if len(buf) > 0 || msgOp != 0 {
				return nil, ws.fail(CodeWSProtocol, fmt.Errorf("новый кадр данных посреди фрагментированного сообщения"))
			}
			msgOp = fr.opcode
			compressed = fr.rsv1
			if compressed && ws.deflate == nil {
				return nil, ws.fail(CodeWSProtocol, fmt.Errorf("сжатый кадр без согласованного permessage-deflate"))
			}
			buf = append(buf, fr.payload...)
		case opContinuation:
			if msgOp == 0 {
				return nil, ws.fail(CodeWSProtocol, fmt.Errorf("продолжение без начала сообщения"))
			}
			if fr.rsv1 {
				return nil, ws.fail(CodeWSProtocol, fmt.Errorf("RSV1 на кадре продолжения"))
			}
			buf = append(buf, fr.payload...)
		default:
			return nil, ws.fail(CodeWSProtocol, fmt.Errorf("неизвестный опкод 0x%X", fr.opcode))
		}

		if fr.fin {
			if compressed {
				data, err := ws.deflate.inflate(buf, ws.maxMessage)
				if err != nil {
					if Code(err) == CodeWSTooBig {
						ws.closeWith(closePayload(1009))
					} else {
						ws.closeWith(closePayload(1002))
					}
					return nil, err
				}
				buf = data
			}
			return &Message{Binary: msgOp == opBinary, Data: buf}, nil
		}
	}
}

// fail закрывает соединение с кодом «ошибка протокола» и возвращает ошибку.
func (ws *WebSocket) fail(code ErrorCode, err error) error {
	ws.closeWith(closePayload(1002))
	return withCode(code, err)
}

type frame struct {
	fin, rsv1 bool
	opcode    byte
	payload   []byte
}

// readFrame читает один кадр. have — сколько байт сообщения уже накоплено:
// предел действует на сообщение целиком, а не на кадр.
func (ws *WebSocket) readFrame(have int64) (frame, error) {
	var head [2]byte
	if _, err := io.ReadFull(ws.br, head[:]); err != nil {
		return frame{}, fmt.Errorf("чтение кадра: %w", err)
	}
	fr := frame{
		fin:    head[0]&0x80 != 0,
		rsv1:   head[0]&0x40 != 0,
		opcode: head[0] & 0x0F,
	}
	masked := head[1]&0x80 != 0
	length := uint64(head[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(ws.br, ext[:]); err != nil {
			return frame{}, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(ws.br, ext[:]); err != nil {
			return frame{}, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	// Проверка до выделения памяти: длину называет сервер.
	if length > uint64(ws.maxMessage) || have+int64(length) > ws.maxMessage {
		ws.closeWith(closePayload(1009))
		return frame{}, withCode(CodeWSTooBig,
			fmt.Errorf("сообщение больше предела %d байт", ws.maxMessage))
	}

	var mask [4]byte
	if masked {
		// Сервер маскировать не должен, но кадр всё равно надо разобрать.
		if _, err := io.ReadFull(ws.br, mask[:]); err != nil {
			return frame{}, err
		}
	}

	if length > 0 {
		fr.payload = make([]byte, length)
		if _, err := io.ReadFull(ws.br, fr.payload); err != nil {
			return frame{}, fmt.Errorf("чтение полезной нагрузки: %w", err)
		}
		if masked {
			for i := range fr.payload {
				fr.payload[i] ^= mask[i%4]
			}
		}
	}
	return fr, nil
}

func parseClose(payload []byte) (uint16, string) {
	if len(payload) < 2 {
		return 1005, "" // «статус отсутствует» по RFC 6455
	}
	return binary.BigEndian.Uint16(payload[:2]), string(payload[2:])
}

func closePayload(code uint16) []byte {
	return binary.BigEndian.AppendUint16(nil, code)
}

// Close отправляет кадр закрытия и разрывает соединение.
//
// Повторный вызов и вызов после Close от сервера безопасны: сокет в любом
// случае оказывается закрытым.
func (ws *WebSocket) Close(code uint16, reason string) error {
	payload := binary.BigEndian.AppendUint16(nil, code)
	payload = append(payload, reason...)
	return ws.closeWith(payload)
}

// closeWith шлёт Close с данным телом (если ещё не слали) и закрывает сокет.
func (ws *WebSocket) closeWith(payload []byte) error {
	ws.closeMx.Lock()
	alreadyClosed := ws.closed
	ws.closed = true
	ws.closeMx.Unlock()

	var writeErr error
	if !alreadyClosed {
		writeErr = ws.writeCloseFrame(payload)
	}
	ws.closeMx.Lock()
	needClose := !ws.connClosed
	ws.connClosed = true
	ws.closeMx.Unlock()
	if needClose {
		if err := ws.conn.Close(); err != nil && writeErr == nil {
			writeErr = err
		}
	}
	return writeErr
}

// writeCloseFrame пишет кадр Close в обход проверки isClosed: флаг уже
// выставлен, а кадр отправить нужно.
func (ws *WebSocket) writeCloseFrame(payload []byte) error {
	ws.writeMx.Lock()
	defer ws.writeMx.Unlock()
	_ = ws.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	head := []byte{0x80 | opClose, 0x80 | byte(len(payload))}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	head = append(head, mask[:]...)
	for i, b := range payload {
		head = append(head, b^mask[i%4])
	}
	_, err := ws.conn.Write(head)
	return err
}

func (ws *WebSocket) isClosed() bool {
	ws.closeMx.Lock()
	defer ws.closeMx.Unlock()
	return ws.closed
}
