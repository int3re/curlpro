package client

import (
	nethttp "net/http"

	http "github.com/bogdanfinn/fhttp"
)

// Мост между net/http и fhttp.
//
// Вендоренный пакет h3 построен на net/http (перейти на fhttp не вышло:
// он собран поверх другого форка utls, типы несовместимы), а остальной
// клиент — на fhttp. Чтобы обе ветки возвращали один тип, ответ HTTP/3
// переводится в fhttp-представление.

func fromStdResponse(r *nethttp.Response) *http.Response {
	out := &http.Response{
		Status:        r.Status,
		StatusCode:    r.StatusCode,
		Proto:         r.Proto,
		ProtoMajor:    r.ProtoMajor,
		ProtoMinor:    r.ProtoMinor,
		Header:        http.Header(r.Header),
		Body:          r.Body,
		ContentLength: r.ContentLength,
		Close:         r.Close,
		Uncompressed:  r.Uncompressed,
		Trailer:       http.Header(r.Trailer),
	}
	return out
}

// toFhttpCookies переводит куки из net/http в fhttp: cookie-jar сессии
// работает со вторым.
func toFhttpCookies(in []*nethttp.Cookie) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(in))
	for _, c := range in {
		out = append(out, &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Domain:   c.Domain,
			Expires:  c.Expires,
			MaxAge:   c.MaxAge,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
			SameSite: http.SameSite(c.SameSite),
			Raw:      c.Raw,
		})
	}
	return out
}
