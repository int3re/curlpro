package client

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// requestBody готовит тело запроса и его размер.
//
// Возвращает -1 как размер, если он неизвестен: тогда транспорт решает сам.
// Для файла размер берётся из файловой системы, иначе транспорт перешёл бы
// на chunked-кодирование, которого браузеры при отправке файла не используют,
// — и это было бы видно на проводе.
func requestBody(r *Request) (io.Reader, int64, error) {
	switch {
	case r.BodyFile != "" && len(r.Body) > 0:
		return nil, 0, fmt.Errorf("request has both Body and BodyFile set: pass exactly one")

	case r.BodyFile != "":
		f, err := os.Open(r.BodyFile)
		if err != nil {
			return nil, 0, fmt.Errorf("request body: %w", err)
		}
		size := r.BodySize
		if size <= 0 {
			st, err := f.Stat()
			if err != nil {
				f.Close()
				return nil, 0, fmt.Errorf("request body: %w", err)
			}
			size = st.Size()
		}
		return f, size, nil

	case len(r.Body) > 0:
		return bytes.NewReader(r.Body), int64(len(r.Body)), nil

	default:
		return nil, -1, nil
	}
}
