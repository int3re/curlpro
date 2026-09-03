// Command hcapture — стенд, записывающий порядок заголовков живого браузера
// на HTTP/2 и HTTP/3.
//
// Зачем свой сервер. Публичные оракулы имена нормализуют, а порядок HTTP/3
// не показывает ни один: до этого стенда порядок заголовков в HTTP/3 не
// наблюдался ничем, и профиль верили на слово. Здесь HEADERS-кадр разбирается
// как пришёл: HPACK для HTTP/2, свой QPACK-декодер для HTTP/3.
//
// Запуск (браузер поднимается сам, безголовым):
//
//	go run ./cmd/hcapture -auto               # HTTP/2
//	go run ./cmd/hcapture -auto -h3           # HTTP/3, Chrome форсируется на QUIC
//	go run ./cmd/hcapture -h3                 # без браузера: открыть адрес руками
//
// Страница сама делает fetch, XHR и переход по ссылке, поэтому за один запуск
// снимаются оба набора заголовков — навигационный и fetch.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/qpack"
	quic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/quicvarint"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	cqpack "github.com/curlpro/curlpro/internal/qpack"
)

func main() {
	listen := flag.String("listen", "localhost:8443", "адрес стенда")
	h3 := flag.Bool("h3", false, "поднять QUIC и увести браузер на HTTP/3")
	browser := flag.String("browser", "", "путь к Chrome; пусто — не запускать, ждать вручную")
	auto := flag.Bool("auto", false, "запустить браузер, найденный по обычным путям")
	timeout := flag.Duration("timeout", 25*time.Second, "сколько ждать запросов")
	out := flag.String("json", "", "файл для записи снятого")
	certs := flag.String("certs", "capture/certs", "каталог с tls.crt и tls.key")
	flag.Parse()

	certFile = *certs + "/tls.crt"
	keyFile = *certs + "/tls.key"
	// Alt-Svc — единственный способ увести на QUIC браузер, которому нельзя
	// передать --origin-to-force-quic-on: на Android ключи запуска недоступны.
	// Браузер переходит на HTTP/3 со следующего запроса после этого заголовка.
	if *h3 {
		if _, port, err := net.SplitHostPort(*listen); err == nil {
			altSvc = `h3=":` + port + `"; ma=86400`
		}
	}

	s := &srv{}
	var wg sync.WaitGroup

	if *h3 {
		if err := s.listenQUIC(*listen, &wg); err != nil {
			fmt.Fprintln(os.Stderr, "QUIC:", err)
			os.Exit(1)
		}
	}
	// TCP слушается всегда: браузер сначала ходит по TCP и только по
	// Alt-Svc или принудительному ключу переходит на QUIC.
	if err := s.listenTCP(*listen, &wg); err != nil {
		fmt.Fprintln(os.Stderr, "TCP:", err)
		os.Exit(1)
	}

	path := *browser
	if path == "" && *auto {
		path = defaultBrowser()
	}
	var stop func()
	if path != "" {
		stop = launch(path, *listen, *h3)
	} else {
		fmt.Fprintf(os.Stderr, "откройте https://%s/ в браузере\n", *listen)
		stop = func() {}
	}

	// Стенд живёт до таймаута: страница успевает сделать все запросы,
	// а последний переход по ссылке приходит уже под конец.
	time.Sleep(*timeout)
	stop()
	s.closeAll()
	wg.Wait()

	s.report(*out)
}

// record — один запрос в порядке провода.
type record struct {
	Proto   string   `json:"proto"`
	Method  string   `json:"method"`
	Path    string   `json:"path"`
	Headers []string `json:"headers"`
}

type srv struct {
	mu      sync.Mutex
	records []record
	notes   []string
	closers []io.Closer
}

// note записывает наблюдение, не связанное с отдельным запросом.
func (s *srv) note(text string) {
	s.mu.Lock()
	for _, n := range s.notes {
		if n == text {
			s.mu.Unlock()
			return // одно и то же повторяется на каждом соединении
		}
	}
	s.notes = append(s.notes, text)
	s.mu.Unlock()
	fmt.Fprintln(os.Stderr, text)
}

func (s *srv) add(r record) {
	s.mu.Lock()
	s.records = append(s.records, r)
	s.mu.Unlock()
	fmt.Fprintf(os.Stderr, "%s %s %s (%d заголовков)\n", r.Proto, r.Method, r.Path, len(r.Headers))
}

func (s *srv) track(c io.Closer) {
	s.mu.Lock()
	s.closers = append(s.closers, c)
	s.mu.Unlock()
}

func (s *srv) closeAll() {
	s.mu.Lock()
	for _, c := range s.closers {
		_ = c.Close()
	}
	s.closers = nil
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Содержимое: страница сама вызывает fetch, XHR и переходит по ссылке.
// ---------------------------------------------------------------------------

const page = `<!doctype html><meta charset=utf-8><title>hcapture</title>
<body><h1>hcapture</h1><pre id=out></pre>
<script>
const log = m => { document.getElementById('out').textContent += m + "\n"; };
(async () => {
  try {
    await fetch('/fetch-get', {headers: {'X-Api-Key': 'v1'}});
    log('fetch-get');
    await fetch('/fetch-post', {method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Api-Key': 'v1'},
      body: JSON.stringify({a: 1})});
    log('fetch-post');
    await new Promise(r => {
      const x = new XMLHttpRequest();
      x.open('POST', '/xhr-post');
      x.setRequestHeader('X-Api-Key', 'v1');
      x.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      x.onloadend = r;
      x.send('a=1&b=2');
    });
    log('xhr-post');
    setTimeout(() => { location.href = '/second'; }, 300);
  } catch (e) { log('ошибка ' + e); }
})();
</script>`

const second = `<!doctype html><meta charset=utf-8><title>second</title><body>ok`

// route возвращает тело ответа и его тип.
func route(path string) (string, string) {
	switch path {
	case "/":
		return page, "text/html; charset=utf-8"
	case "/second":
		return second, "text/html; charset=utf-8"
	default:
		return `{"ok":true}`, "application/json"
	}
}

// ---------------------------------------------------------------------------
// HTTP/2
// ---------------------------------------------------------------------------

// acceptCH — подсказки высокой энтропии, которые стенд запрашивает.
// Critical-CH заставляет браузер повторить запрос сразу, а не со следующего.
const acceptCH = "sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-full-version-list, sec-ch-ua-model, sec-ch-ua-platform-version, sec-ch-ua-wow64, sec-ch-ua-form-factors, sec-ch-ua-full-version"

var (
	certFile = "capture/certs/tls.crt"
	keyFile  = "capture/certs/tls.key"
	// altSvc непустой, когда поднят QUIC: объявляем поддержку HTTP/3.
	altSvc string
)

func serverTLSConfig(next []string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: next}, nil
}

func (s *srv) listenTCP(addr string, wg *sync.WaitGroup) error {
	cfg, err := serverTLSConfig([]string{"h2", "http/1.1"})
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return err
	}
	s.track(ln)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serveConn(c.(*tls.Conn))
		}
	}()
	return nil
}

func (s *srv) serveConn(c *tls.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	if err := c.Handshake(); err != nil {
		return
	}
	if c.ConnectionState().NegotiatedProtocol == "h2" {
		s.serveH2(c)
	}
}

// serveH2 разбирает кадры вручную: net/http порядок заголовков теряет,
// а именно он здесь и снимается.
func (s *srv) serveH2(c net.Conn) {
	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	buf := make([]byte, len(preface))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != preface {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20},
	); err != nil {
		return
	}

	pending := map[uint32]record{}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			_ = fr.WritePing(true, f.Data)
		case *http2.MetaHeadersFrame:
			r := record{Proto: "h2"}
			for _, hf := range f.Fields {
				switch hf.Name {
				case ":method":
					r.Method = hf.Value
				case ":path":
					r.Path = hf.Value
				}
				r.Headers = append(r.Headers, hf.Name+": "+hf.Value)
			}
			if f.StreamEnded() {
				s.add(r)
				s.respondH2(fr, f.StreamID, r.Path)
			} else {
				pending[f.StreamID] = r
			}
		case *http2.DataFrame:
			if len(f.Data()) > 0 {
				_ = fr.WriteWindowUpdate(0, uint32(len(f.Data())))
				_ = fr.WriteWindowUpdate(f.StreamID, uint32(len(f.Data())))
			}
			if f.StreamEnded() {
				if r, ok := pending[f.StreamID]; ok {
					delete(pending, f.StreamID)
					s.add(r)
					s.respondH2(fr, f.StreamID, r.Path)
				}
			}
		case *http2.GoAwayFrame:
			return
		}
	}
}

func (s *srv) respondH2(fr *http2.Framer, id uint32, path string) {
	body, ctype := route(path)
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: ctype})
	_ = enc.WriteField(hpack.HeaderField{Name: "content-length", Value: fmt.Sprint(len(body))})
	_ = enc.WriteField(hpack.HeaderField{Name: "cache-control", Value: "no-store"})
	_ = enc.WriteField(hpack.HeaderField{Name: "accept-ch", Value: acceptCH})
	_ = enc.WriteField(hpack.HeaderField{Name: "critical-ch", Value: acceptCH})
	if altSvc != "" {
		_ = enc.WriteField(hpack.HeaderField{Name: "alt-svc", Value: altSvc})
	}
	if path == "/" {
		// Кука ставится на первой странице, чтобы следующие запросы показали
		// её позицию: в профиле cookie — слот, поставленный по догадке.
		_ = enc.WriteField(hpack.HeaderField{Name: "set-cookie", Value: "hc=1; path=/"})
	}
	_ = fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: buf.Bytes(), EndHeaders: true,
	})
	_ = fr.WriteData(id, true, []byte(body))
}

// ---------------------------------------------------------------------------
// HTTP/3
// ---------------------------------------------------------------------------

const (
	h3FrameData     = 0x00
	h3FrameHeaders  = 0x01
	h3FrameSettings = 0x04

	h3StreamControl = 0x00
	h3StreamEncoder = 0x02
	h3StreamDecoder = 0x03

	qpackMaxTableCapacity = 4096
	qpackBlockedStreams   = 16
)

// listenQUIC поднимает слушателя на каждом адресе, в который разрешается host.
//
// Один адрес недостаточен: Chrome ходит на localhost по ::1, и слушатель
// только на 127.0.0.1 не получает ни одной датаграммы — на этом уже
// потерян один прогон при снятии QUIC ClientHello.
func (s *srv) listenQUIC(addr string, wg *sync.WaitGroup) error {
	cert, err := utls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	cfg := &utls.Config{
		Certificates: []utls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
	var started int
	for _, a := range resolveAll(host, port) {
		udp, err := net.ListenUDP("udp", a)
		if err != nil {
			continue
		}
		pc := &countingPC{UDPConn: udp}
		ln, err := quic.Listen(pc, cfg, &quic.Config{MaxIdleTimeout: 2 * time.Minute})
		if err != nil {
			pc.Close()
			continue
		}
		started++
		s.track(ln)
		wg.Add(1)
		go func(ln *quic.Listener) {
			defer wg.Done()
			for {
				conn, err := ln.Accept(context.Background())
				if err != nil {
					fmt.Fprintf(os.Stderr, "QUIC %s: %v\n", ln.Addr(), err)
					return
				}
				fmt.Fprintf(os.Stderr, "QUIC соединение с %s\n", conn.RemoteAddr())
				go s.serveH3Conn(conn)
			}
		}(ln)
	}
	if started == 0 {
		return fmt.Errorf("не удалось занять %s ни по одному адресу", addr)
	}
	return nil
}

// countingPC считает принятые датаграммы: без него «браузер не пришёл»
// и «пришёл, но рукопожатие не сложилось» неразличимы.
type countingPC struct {
	*net.UDPConn
	n  atomic.Int64
	wr atomic.Int64
}

func (c *countingPC) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.UDPConn.WriteTo(b, addr)
	if k := c.wr.Add(1); k <= 12 {
		fmt.Fprintf(os.Stderr, "QUIC → %d: %d байт, %s\n", k, len(b), describePacket(b))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "QUIC: ошибка отправки к %s: %v\n", addr, err)
	}
	return n, err
}

func (c *countingPC) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	if err == nil {
		if k := c.n.Add(1); k <= 12 {
			fmt.Fprintf(os.Stderr, "QUIC ← %d: %d байт от %s, %s\n", k, n, addr, describePacket(b[:n]))
		}
	}
	return n, addr, err
}

// describePacket читает открытую часть заголовка QUIC.
//
// Версия и тип пакета не зашифрованы, и по ним видно главное: договорились
// ли стороны о версии вообще и до какой стадии дошло рукопожатие.
func describePacket(b []byte) string {
	if len(b) < 1 {
		return "пусто"
	}
	if b[0]&0x80 == 0 {
		return "короткий заголовок (1-RTT)"
	}
	if len(b) < 7 {
		return "длинный заголовок, обрезан"
	}
	ver := binary.BigEndian.Uint32(b[1:5])
	kinds := map[byte]string{0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
	kind := kinds[(b[0]&0x30)>>4]
	name := fmt.Sprintf("версия 0x%08x", ver)
	switch ver {
	case 0:
		return "Version Negotiation"
	case 0x00000001:
		name = "QUIC v1"
	case 0x6b3343cf:
		name = "QUIC v2"
	}
	if kind == "" {
		kind = "?"
	}
	// Идентификаторы соединения не зашифрованы. Ответ сервера обязан идти
	// с DCID, равным SCID клиента: расхождение здесь означало бы, что клиент
	// наш пакет просто не признает своим.
	cids := ""
	if len(b) > 5 {
		dl := int(b[5])
		if len(b) >= 6+dl+1 {
			dcid := b[6 : 6+dl]
			sl := int(b[6+dl])
			if len(b) >= 7+dl+sl {
				scid := b[7+dl : 7+dl+sl]
				cids = fmt.Sprintf(", dcid=%x scid=%x", dcid, scid)
			}
		}
	}
	return name + ", " + kind + cids
}

// resolveAll разворачивает host во все его адреса.
func resolveAll(host, port string) []*net.UDPAddr {
	var ips []net.IP
	if host == "localhost" {
		ips = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	} else {
		var err error
		if ips, err = net.LookupIP(host); err != nil {
			return nil
		}
	}
	var out []*net.UDPAddr
	for _, ip := range ips {
		a, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			out = append(out, a)
		}
	}
	return out
}

func (s *srv) serveH3Conn(conn *quic.Conn) {
	dec := cqpack.NewDecoder(qpackMaxTableCapacity)
	defer dec.Close(errors.New("соединение закрыто"))

	// Контрольный поток с SETTINGS: без него Chrome закрывает соединение.
	if ctl, err := conn.OpenUniStream(); err == nil {
		var b []byte
		b = quicvarint.Append(b, h3StreamControl)
		var payload []byte
		payload = quicvarint.Append(payload, 0x01) // QPACK_MAX_TABLE_CAPACITY
		payload = quicvarint.Append(payload, qpackMaxTableCapacity)
		payload = quicvarint.Append(payload, 0x07) // QPACK_BLOCKED_STREAMS
		payload = quicvarint.Append(payload, qpackBlockedStreams)
		b = quicvarint.Append(b, h3FrameSettings)
		b = quicvarint.Append(b, uint64(len(payload)))
		b = append(b, payload...)
		_, _ = ctl.Write(b)
	}
	if enc, err := conn.OpenUniStream(); err == nil {
		_, _ = enc.Write(quicvarint.Append(nil, h3StreamEncoder))
	}
	if d, err := conn.OpenUniStream(); err == nil {
		if _, err := d.Write(quicvarint.Append(nil, h3StreamDecoder)); err == nil {
			dec.SetDecoderStream(d)
		}
	}

	go func() {
		for {
			str, err := conn.AcceptUniStream(context.Background())
			if err != nil {
				return
			}
			go s.serveH3Uni(str, dec)
		}
	}()

	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go s.serveH3Stream(str, dec)
	}
}

func (s *srv) serveH3Uni(str *quic.ReceiveStream, dec *cqpack.Decoder) {
	r := quicvarint.NewReader(str)
	t, err := quicvarint.Read(r)
	if err != nil {
		return
	}
	switch t {
	case h3StreamEncoder:
		// Поток кодировщика питает динамическую таблицу: без него
		// ссылки на неё в HEADERS не разворачиваются.
		_ = dec.ReadEncoderStream(str)
	case h3StreamControl:
		s.readControlStream(r)
	default:
		_, _ = io.Copy(io.Discard, str)
	}
}

// readControlStream записывает кадры управляющего потока клиента.
//
// Здесь живёт отпечаток слоя HTTP/3: порядок SETTINGS, GREASE-кадр
// и PRIORITY_UPDATE. Публичные оракулы отдают его строкой perk, но своего
// браузера на телефоне ей не проверить — сюда он приходит как есть.
func (s *srv) readControlStream(r quicvarint.Reader) {
	for {
		t, err := quicvarint.Read(r)
		if err != nil {
			return
		}
		n, err := quicvarint.Read(r)
		if err != nil {
			return
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return
		}
		if t != h3FrameSettings {
			// GREASE-кадры и PRIORITY_UPDATE различаются только типом:
			// содержимое для отпечатка не нужно, а тип — нужен.
			s.note(fmt.Sprintf("кадр управляющего потока: тип %d (0x%x), длина %d", t, t, n))
			continue
		}
		var pairs []string
		br := bytes.NewReader(payload)
		vr := quicvarint.NewReader(br)
		for {
			id, err := quicvarint.Read(vr)
			if err != nil {
				break
			}
			val, err := quicvarint.Read(vr)
			if err != nil {
				break
			}
			pairs = append(pairs, fmt.Sprintf("%d:%d", id, val))
		}
		s.note("SETTINGS клиента: " + strings.Join(pairs, ";"))
	}
}

func (s *srv) serveH3Stream(str *quic.Stream, dec *cqpack.Decoder) {
	defer str.Close()
	r := quicvarint.NewReader(str)
	var rec *record
	for {
		t, err := quicvarint.Read(r)
		if err != nil {
			break
		}
		n, err := quicvarint.Read(r)
		if err != nil {
			break
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(str, payload); err != nil {
			break
		}
		if t != h3FrameHeaders {
			continue // DATA и всё прочее для порядка заголовков не нужны
		}
		out := record{Proto: "h3"}
		next := dec.Decode(uint64(str.StreamID()), payload)
		for {
			hf, err := next()
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "QPACK:", err)
				return
			}
			switch hf.Name {
			case ":method":
				out.Method = hf.Value
			case ":path":
				out.Path = hf.Value
			}
			out.Headers = append(out.Headers, hf.Name+": "+hf.Value)
		}
		rec = &out
		s.add(out)
		break
	}
	if rec == nil {
		return
	}
	body, ctype := route(rec.Path)

	var block bytes.Buffer
	enc := qpack.NewEncoder(&block)
	_ = enc.WriteField(qpack.HeaderField{Name: ":status", Value: "200"})
	_ = enc.WriteField(qpack.HeaderField{Name: "content-type", Value: ctype})
	_ = enc.WriteField(qpack.HeaderField{Name: "content-length", Value: fmt.Sprint(len(body))})
	_ = enc.WriteField(qpack.HeaderField{Name: "accept-ch", Value: acceptCH})
	_ = enc.WriteField(qpack.HeaderField{Name: "critical-ch", Value: acceptCH})
	if rec.Path == "/" {
		_ = enc.WriteField(qpack.HeaderField{Name: "set-cookie", Value: "hc=1; path=/"})
	}
	_ = enc.Close()

	var b []byte
	b = quicvarint.Append(b, h3FrameHeaders)
	b = quicvarint.Append(b, uint64(block.Len()))
	b = append(b, block.Bytes()...)
	b = quicvarint.Append(b, h3FrameData)
	b = quicvarint.Append(b, uint64(len(body)))
	b = append(b, body...)
	_, _ = str.Write(b)
}

// ---------------------------------------------------------------------------
// Браузер и отчёт
// ---------------------------------------------------------------------------

// spkiHash — SHA-256 от SubjectPublicKeyInfo сертификата в base64,
// в том виде, какого ждёт --ignore-certificate-errors-spki-list.
func spkiHash(path string) (string, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", errors.New("сертификат не разобран")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

func defaultBrowser() string {
	for _, c := range []string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/usr/bin/google-chrome", "/usr/bin/chromium",
	} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// launch запускает браузер в свежем профиле и возвращает функцию остановки.
//
// headless: сетевой слой у безголового Chrome тот же, а окно с ошибкой
// сертификата пришлось бы закрывать руками.
func launch(browser, origin string, h3 bool) func() {
	dir, err := os.MkdirTemp("", "curlpro-hcap-")
	if err != nil {
		return func() {}
	}
	args := []string{
		"--headless=new",
		"--user-data-dir=" + dir,
		"--no-first-run",
		"--no-default-browser-check",
		"--ignore-certificate-errors",
	}
	if h3 {
		args = append(args, "--enable-quic", "--origin-to-force-quic-on="+origin)
		// --ignore-certificate-errors на путь QUIC не распространяется:
		// датаграммы Chrome шлёт, но рукопожатие молча бросает. Отпечаток
		// открытого ключа стенда снимает именно эту проверку.
		if h, err := spkiHash(certFile); err == nil {
			args = append(args, "--ignore-certificate-errors-spki-list="+h)
		} else {
			fmt.Fprintln(os.Stderr, "отпечаток ключа:", err)
		}
	}
	args = append(args, "https://"+origin+"/")
	cmd := exec.Command(browser, args...)
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "запуск браузера:", err)
		os.RemoveAll(dir)
		return func() {}
	}
	return func() {
		if runtime.GOOS == "windows" {
			_ = exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprint(cmd.Process.Pid)).Run()
		}
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		time.Sleep(time.Second)
		os.RemoveAll(dir)
	}
}

func (s *srv) report(out string) {
	s.mu.Lock()
	recs := append([]record(nil), s.records...)
	s.mu.Unlock()

	s.mu.Lock()
	notes := append([]string(nil), s.notes...)
	s.mu.Unlock()
	for _, n := range notes {
		fmt.Println(n)
	}
	if len(recs) == 0 {
		fmt.Println("ни одного запроса не снято")
		return
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Path < recs[j].Path })
	for _, r := range recs {
		fmt.Printf("\n=== %s %s %s\n", r.Proto, r.Method, r.Path)
		for _, h := range r.Headers {
			name, value, _ := strings.Cut(h, ": ")
			if len(value) > 60 {
				value = value[:57] + "..."
			}
			fmt.Printf("  %-24s %s\n", name, value)
		}
	}
	if out != "" {
		b, _ := json.MarshalIndent(recs, "", "  ")
		if err := os.WriteFile(out, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "запись:", err)
		} else {
			fmt.Printf("\nзаписано в %s\n", out)
		}
	}
}
