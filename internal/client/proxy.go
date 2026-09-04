package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/proxy"
)

// dialRaw открывает TCP-соединение до addr, при необходимости через прокси.
//
// Адрес прокси приходит параметром, а не читается из опций сессии: отдельный
// запрос вправе его переопределить или отключить.
func (s *Session) dialRaw(ctx context.Context, addr, proxy string) (net.Conn, error) {
	d := &net.Dialer{}
	network := "tcp"
	switch s.opts.IPVersion {
	case "4", "ipv4":
		network = "tcp4"
	case "6", "ipv6":
		network = "tcp6"
	}
	if proxy == "" {
		// Подмена действует только на прямое соединение: через прокси имя
		// разрешает он сам, и наша таблица там ничего не решает.
		return d.DialContext(ctx, network, resolveAddr(s.opts.Resolve, addr))
	}

	pu, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("parsing proxy address: %w", err)
	}

	switch strings.ToLower(pu.Scheme) {
	case "socks5", "socks5h":
		return dialSOCKS5(ctx, pu, addr)
	case "http", "https", "":
		return dialHTTPProxy(ctx, d, pu, addr, s.profile.Headers.UserAgent)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https or socks5)", pu.Scheme)
	}
}

// resolveAddr применяет таблицу подмены к адресу "host:port".
//
// Правило ищется сначала по паре с портом, затем по одному имени: так
// "example.com:443" можно направить отдельно от "example.com". Значение без
// порта сохраняет исходный порт — подменяется только узел.
func resolveAddr(table map[string]string, addr string) string {
	if len(table) == 0 {
		return addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	host = strings.ToLower(host)
	target, ok := table[host+":"+port]
	if !ok {
		target, ok = table[host]
	}
	if !ok {
		return addr
	}
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target
	}
	return net.JoinHostPort(target, port)
}

func dialSOCKS5(ctx context.Context, pu *url.URL, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if pu.User != nil {
		pass, _ := pu.User.Password()
		auth = &proxy.Auth{User: pu.User.Username(), Password: pass}
	}
	host := pu.Host
	if pu.Port() == "" {
		host = net.JoinHostPort(pu.Hostname(), "1080")
	}
	d, err := proxy.SOCKS5("tcp", host, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks5: %w", err)
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", addr)
	}
	return d.Dial("tcp", addr)
}

func dialHTTPProxy(ctx context.Context, d *net.Dialer, pu *url.URL, addr, userAgent string) (net.Conn, error) {
	conn, err := dialProxyConn(ctx, d, pu)
	if err != nil {
		return nil, err
	}
	// Обмен CONNECT идёт по голому сокету и контекста не знает: без дедлайна
	// прокси, принявший TCP и замолчавший, держал бы запрос бесконечно при
	// любом timeout. После туннеля дедлайн снимается — для HTTP/2 сокет общий,
	// и оставшийся предел оборвал бы чужие потоки.
	setDeadline := func(c net.Conn) {
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(deadline)
		}
	}
	clearDeadline := func(c net.Conn) { _ = c.SetDeadline(time.Time{}) }
	setDeadline(conn)

	err = connectProxy(conn, pu, addr, userAgent, false)

	// 407 — это не отказ, а вызов: Chrome отвечает на него повтором
	// с учётными данными. Первый CONNECT уходит без них, как у браузера.
	var need needAuthError
	if errors.As(err, &need) && pu.User != nil {
		if !need.reusable {
			// Прокси закрыл соединение вместе с 407 — второй попытке нужен
			// свежий сокет, иначе повтор уйдёт в закрытый.
			clearDeadline(conn)
			conn.Close()
			if conn, err = dialProxyConn(ctx, d, pu); err != nil {
				return nil, err
			}
			setDeadline(conn)
		}
		err = connectProxy(conn, pu, addr, userAgent, true)
	}
	clearDeadline(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// dialProxyConn открывает соединение до самого прокси.
//
// Для https:// канал до прокси шифруется, и CONNECT уходит уже внутри TLS.
// Раньше схема принималась, но запрос уходил открытым текстом в TLS-порт:
// прокси его не понимал, а логин с паролем утекал в сеть.
//
// TLS здесь обычный, не браузерный: этот отпечаток не видит никто,
// кроме самого прокси.
func dialProxyConn(ctx context.Context, d *net.Dialer, pu *url.URL) (net.Conn, error) {
	host := pu.Host
	if pu.Port() == "" {
		host = net.JoinHostPort(pu.Hostname(), defaultProxyPort(pu.Scheme))
	}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("connecting to proxy: %w", err)
	}
	if strings.EqualFold(pu.Scheme, "https") {
		tconn := tls.Client(conn, &tls.Config{ServerName: pu.Hostname()})
		if err := tconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake with proxy: %w", err)
		}
		conn = tconn
	}
	return conn, nil
}

// needAuthError — прокси ответил 407.
//
// reusable говорит, можно ли повторить по тому же сокету: тело ответа
// дочитано и закрываться прокси не собирается.
type needAuthError struct {
	reusable bool
	scheme   string // схема из Proxy-Authenticate, для сообщения об ошибке
}

func (e needAuthError) Error() string {
	if e.scheme != "" {
		return "proxy requires authentication (" + e.scheme + ")"
	}
	return "proxy requires authentication"
}

func defaultProxyPort(scheme string) string {
	if strings.EqualFold(scheme, "https") {
		return "443"
	}
	return "8080"
}

// connectProxy выполняет CONNECT-туннель до target.
//
// Заголовки — как у Chrome: Host, Proxy-Connection: keep-alive, User-Agent
// браузера. С пустым Header fhttp подставлял Go-http-client/1.1, и прокси
// видел не браузер, а Go: провайдеры прокси клиентов классифицируют.
//
// withAuth=false — первый заход, как у браузера: Chrome шлёт CONNECT без
// учётных данных и добавляет их только в ответ на 407. Прокси, ведущий
// журнал, видит у нас ту же пару запросов, что у Chrome.
func connectProxy(conn net.Conn, pu *url.URL, target, userAgent string, withAuth bool) error {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	req.Header["Host"] = []string{target}
	req.Header["Proxy-Connection"] = []string{"keep-alive"}
	// Пустой слайс запрещает fhttp подставить свой User-Agent.
	req.Header["User-Agent"] = []string{}
	if userAgent != "" {
		req.Header["User-Agent"] = []string{userAgent}
	}
	if withAuth && pu.User != nil {
		pass, _ := pu.User.Password()
		req.Header["Proxy-Authorization"] = []string{
			"Basic " + base64.StdEncoding.EncodeToString([]byte(pu.User.Username()+":"+pass))}
	}
	req.Header[http.HeaderOrderKey] = []string{"host", "proxy-connection", "user-agent", "proxy-authorization"}
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("CONNECT: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return fmt.Errorf("reading proxy response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusProxyAuthRequired && !withAuth {
		return needAuthError{
			// Сокет годен для повтора, только если тело дочитано, прокси
			// не собирается закрываться и в буфере ничего не осталось:
			// иначе второй CONNECT разобрал бы ответ из чужих байтов.
			reusable: drain(resp, nil) && br.Buffered() == 0 && !resp.Close &&
				!strings.EqualFold(resp.Header.Get("Proxy-Connection"), "close"),
			scheme: resp.Header.Get("Proxy-Authenticate"),
		}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy refused CONNECT with %s", resp.Status)
	}
	// Прокси не должен слать тело до CONNECT-ответа; если в буфере что-то
	// осталось, дальнейший TLS-разбор пойдёт по мусору.
	if br.Buffered() > 0 {
		return fmt.Errorf("proxy sent %d unexpected bytes after CONNECT", br.Buffered())
	}
	return nil
}
