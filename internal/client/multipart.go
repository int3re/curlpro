package client

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"
)

// FormFile — файл в multipart-форме.
type FormFile struct {
	Field       string `json:"field"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Content     []byte `json:"-"`
}

// MultipartForm описывает форму. Поля отправляются в порядке Order,
// а не в порядке обхода map: порядок частей наблюдаем и стабилен у браузера.
type MultipartForm struct {
	Fields map[string]string `json:"fields"`
	Order  []string          `json:"order"`
	Files  []FormFile        `json:"files"`
}

// boundaryAlphabet повторяет таблицу Blink из
// platform/network/form_data_encoder.cc: 64 символа, как в base64.
const boundaryAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// generateBoundary строит границу в стиле указанного браузера.
//
// Форма границы — часть отпечатка: Chrome шлёт "----WebKitFormBoundary"
// и 16 символов, Firefox — длинную череду дефисов и цифры. Подставить чужой
// стиль значит выдать несоответствие между User-Agent и телом запроса.
func generateBoundary(style string) (string, error) {
	switch strings.ToLower(style) {
	case "", "webkit", "chrome", "safari":
		suffix, err := randomFrom(boundaryAlphabet, 16)
		if err != nil {
			return "", err
		}
		return "----WebKitFormBoundary" + suffix, nil

	case "firefox", "gecko":
		suffix, err := randomFrom("0123456789", 30)
		if err != nil {
			return "", err
		}
		return "---------------------------" + suffix, nil

	default:
		return "", fmt.Errorf("unknown multipart boundary style %q (expected webkit or firefox)", style)
	}
}

func randomFrom(alphabet string, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating multipart boundary: %w", err)
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out), nil
}

// encodeMultipart собирает тело формы и возвращает его вместе с Content-Type.
//
// Кодирование ручное, а не через mime/multipart: тот генерирует границу сам
// и переставляет заголовки частей, а нам нужен контроль над обоими.
func encodeMultipart(form *MultipartForm, style string) (body []byte, contentType string, err error) {
	boundary, err := generateBoundary(style)
	if err != nil {
		return nil, "", err
	}

	var buf bytes.Buffer
	writePart := func(header, content string) {
		buf.WriteString("--" + boundary + "\r\n")
		buf.WriteString(header)
		buf.WriteString("\r\n")
		buf.WriteString(content)
		buf.WriteString("\r\n")
	}

	order := form.Order
	if len(order) == 0 {
		order = make([]string, 0, len(form.Fields))
		for k := range form.Fields {
			order = append(order, k)
		}
	}
	for _, name := range order {
		value, ok := form.Fields[name]
		if !ok {
			continue
		}
		writePart(fmt.Sprintf("Content-Disposition: form-data; name=%q\r\n", name), value)
	}

	for _, f := range form.Files {
		header := fmt.Sprintf("Content-Disposition: form-data; name=%q; filename=%q\r\n",
			f.Field, f.Filename)
		ct := f.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		header += "Content-Type: " + ct + "\r\n"

		buf.WriteString("--" + boundary + "\r\n")
		buf.WriteString(header)
		buf.WriteString("\r\n")
		buf.Write(f.Content)
		buf.WriteString("\r\n")
	}

	buf.WriteString("--" + boundary + "--\r\n")
	return buf.Bytes(), "multipart/form-data; boundary=" + boundary, nil
}
