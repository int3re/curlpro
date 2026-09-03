package client

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	http "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/proxy"
)

// dialRaw открывает TCP-соединение до addr, при необходимости через прокси.
func (s *Session) dialRaw(ctx context.Context, addr string) (net.Conn, error) {
	d := &net.Dialer{}
	if s.opts.Proxy == "" {
		return d.DialContext(ctx, "tcp", addr)
	}

	pu, err := url.Parse(s.opts.Proxy)
	if err != nil {
		return nil, fmt.Errorf("разбор адреса прокси: %w", err)
	}

	switch strings.ToLower(pu.Scheme) {
	case "socks5", "socks5h":
		return dialSOCKS5(ctx, pu, addr)
	case "http", "https", "":
		return dialHTTPProxy(ctx, d, pu, addr)
	default:
		return nil, fmt.Errorf("схема прокси %q не поддерживается (нужна http, https или socks5)", pu.Scheme)
	}
}

func dialSOCKS5(ctx context.Context, pu *url.URL, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if pu.User != nil {
		pass, _ := pu.User.Password()
		auth = &proxy.Auth{User: pu.User.Username(), Password: pass}
	}
	d, err := proxy.SOCKS5("tcp", pu.Host, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks5: %w", err)
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", addr)
	}
	return d.Dial("tcp", addr)
}

func dialHTTPProxy(ctx context.Context, d *net.Dialer, pu *url.URL, addr string) (net.Conn, error) {
	host := pu.Host
	if pu.Port() == "" {
		host = net.JoinHostPort(pu.Hostname(), defaultProxyPort(pu.Scheme))
	}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("соединение с прокси: %w", err)
	}
	if err := connectProxy(conn, pu, addr); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func defaultProxyPort(scheme string) string {
	if strings.EqualFold(scheme, "https") {
		return "443"
	}
	return "8080"
}

// connectProxy выполняет CONNECT-туннель до target.
func connectProxy(conn net.Conn, pu *url.URL, target string) error {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if pu.User != nil {
		pass, _ := pu.User.Password()
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(pu.User.Username()+":"+pass)))
	}
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("CONNECT: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return fmt.Errorf("ответ прокси: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("прокси вернул %s", resp.Status)
	}
	// Прокси не должен слать тело до CONNECT-ответа; если в буфере что-то
	// осталось, дальнейший TLS-разбор пойдёт по мусору.
	if br.Buffered() > 0 {
		return fmt.Errorf("прокси прислал %d лишних байт после CONNECT", br.Buffered())
	}
	return nil
}

// hostPort нормализует адрес, добавляя порт по умолчанию.
func hostPort(host string, def int) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(def))
}
