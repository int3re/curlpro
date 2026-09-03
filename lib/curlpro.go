// Command curlpro — C-shared библиотека: точка входа для биндингов.
//
// Обмен идёт JSON-строками через char*: это медленнее структур, но избавляет
// от синхронизации C-заголовка с каждым биндингом. Набор экспортов намеренно
// узкий — расширять по мере надобности.
//
// Владение памятью: каждая строка, возвращённая библиотекой, выделена в C
// и должна быть освобождена вызовом curlpro_free. Вызывающая сторона обязана
// освободить её, иначе течь.
//
// Сборка:
//
//	go build -buildmode=c-shared -o dist/curlpro.dll ./lib
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/curlpro/curlpro/internal/client"
	"github.com/curlpro/curlpro/internal/profile"
)

var (
	registry = profile.NewRegistry()

	sessionsMu sync.RWMutex
	sessions   = map[int64]*client.Session{}
	nextID     atomic.Int64
)

// result — единый конверт ответа. Биндинг всегда получает валидный JSON
// и разбирает ошибку из поля error, а не из кода возврата.
type result struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

func respond(data any, err error) *C.char {
	var r result
	if err != nil {
		r.Error = err.Error()
	} else {
		r.OK = true
		if data != nil {
			enc, mErr := json.Marshal(data)
			if mErr != nil {
				r.OK, r.Error = false, "сериализация ответа: "+mErr.Error()
			} else {
				r.Data = enc
			}
		}
	}
	out, _ := json.Marshal(r)
	return C.CString(string(out))
}

//export curlpro_free
func curlpro_free(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

//export curlpro_version
func curlpro_version() *C.char {
	return respond(map[string]string{"version": "0.1.0"}, nil)
}

//export curlpro_profiles_load_dir
func curlpro_profiles_load_dir(dir *C.char) *C.char {
	path := C.GoString(dir)
	if err := registry.LoadFS(os.DirFS(path), "."); err != nil {
		return respond(nil, err)
	}
	return respond(map[string]any{"profiles": registry.Names()}, nil)
}

// curlpro_profile_register регистрирует профиль из JSON в рантайме.
//
// Это ключевая возможность библиотеки: новую версию браузера можно подключить,
// не дожидаясь релиза и не пересобирая нативную часть.
//
//export curlpro_profile_register
func curlpro_profile_register(data *C.char) *C.char {
	if err := registry.Register([]byte(C.GoString(data))); err != nil {
		return respond(nil, err)
	}
	return respond(map[string]any{"profiles": registry.Names()}, nil)
}

//export curlpro_profiles_list
func curlpro_profiles_list() *C.char {
	return respond(map[string]any{"profiles": registry.Names()}, nil)
}

type sessionConfig struct {
	Profile            string   `json:"profile"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify"`
	TimeoutMS          int      `json:"timeout_ms"`
	Proxy              string   `json:"proxy"`
	DefaultHeaders     bool     `json:"default_headers"`
	HeaderOrder        []string `json:"header_order"`
	FollowRedirects    bool     `json:"follow_redirects"`
	MaxRedirects       int      `json:"max_redirects"`
	Cookies            bool     `json:"cookies"`
	ForceHTTP1         bool     `json:"force_http1"`
	HTTP3              bool     `json:"http3"`
}

//export curlpro_session_new
func curlpro_session_new(cfg *C.char) *C.char {
	var c sessionConfig
	if err := json.Unmarshal([]byte(C.GoString(cfg)), &c); err != nil {
		return respond(nil, fmt.Errorf("разбор конфигурации: %w", err))
	}
	p, err := registry.Resolve(c.Profile)
	if err != nil {
		return respond(nil, err)
	}
	s, err := client.New(p, client.Options{
		InsecureSkipVerify: c.InsecureSkipVerify,
		Timeout:            time.Duration(c.TimeoutMS) * time.Millisecond,
		Proxy:              c.Proxy,
		DefaultHeaders:     c.DefaultHeaders,
		HeaderOrder:        c.HeaderOrder,
		FollowRedirects:    c.FollowRedirects,
		MaxRedirects:       c.MaxRedirects,
		Cookies:            c.Cookies,
		ForceHTTP1:         c.ForceHTTP1,
		HTTP3:              c.HTTP3,
	})
	if err != nil {
		return respond(nil, err)
	}

	id := nextID.Add(1)
	sessionsMu.Lock()
	sessions[id] = s
	sessionsMu.Unlock()
	return respond(map[string]any{"session": id}, nil)
}

//export curlpro_session_close
func curlpro_session_close(id C.longlong) *C.char {
	sessionsMu.Lock()
	s, ok := sessions[int64(id)]
	delete(sessions, int64(id))
	sessionsMu.Unlock()
	if !ok {
		return respond(nil, fmt.Errorf("сессия %d не найдена", int64(id)))
	}
	s.Close()
	return respond(nil, nil)
}

type requestJSON struct {
	Method           string            `json:"method"`
	URL              string            `json:"url"`
	Headers          map[string]string `json:"headers"`
	HeaderOrder      []string          `json:"header_order"`
	NoDefaultHeaders bool              `json:"no_default_headers"`
	Multipart        *multipartJSON    `json:"multipart"`
}

// multipartJSON описывает форму. Содержимое файлов едет не здесь, а в бинарной
// части кадра: длины перечислены в file_sizes, порядок совпадает с files.
type multipartJSON struct {
	Fields    map[string]string `json:"fields"`
	Order     []string          `json:"order"`
	Files     []fileJSON        `json:"files"`
	FileSizes []int             `json:"file_sizes"`
}

type fileJSON struct {
	Field       string `json:"field"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
}

// splitFiles режет бинарную часть кадра на содержимое файлов по заявленным длинам.
func splitFiles(m *multipartJSON, blob []byte) (*client.MultipartForm, error) {
	form := &client.MultipartForm{
		Fields: m.Fields,
		Order:  m.Order,
		Files:  make([]client.FormFile, 0, len(m.Files)),
	}
	if len(m.Files) != len(m.FileSizes) {
		return nil, fmt.Errorf("описано %d файлов, но %d длин", len(m.Files), len(m.FileSizes))
	}
	offset := 0
	for i, f := range m.Files {
		size := m.FileSizes[i]
		if size < 0 || offset+size > len(blob) {
			return nil, fmt.Errorf("файл %q выходит за границы данных", f.Filename)
		}
		form.Files = append(form.Files, client.FormFile{
			Field:       f.Field,
			Filename:    f.Filename,
			ContentType: f.ContentType,
			Content:     blob[offset : offset+size],
		})
		offset += size
	}
	return form, nil
}

type responseJSON struct {
	Status  int                 `json:"status"`
	Proto   string              `json:"proto"`
	Headers map[string][]string `json:"headers"`
	URL     string              `json:"url"`
	BodyLen int                 `json:"body_len"`
}

// Тела передаются в бинарном виде, отдельно от JSON.
//
// Раньше тело ехало строкой внутри JSON, и это не просто замедляло обмен:
// произвольные байты — не валидный UTF-8, поэтому ответ портился. Запрос
// 10 000 случайных байт возвращал 18 502 — данные раздувались при перекодировке.
//
// Формат кадра: [uint32 LE длина JSON][JSON][сырое тело].
const frameHeaderLen = 4

func encodeFrame(meta any, body []byte) (*C.char, C.int) {
	js, err := json.Marshal(meta)
	if err != nil {
		js, _ = json.Marshal(result{Error: "сериализация: " + err.Error()})
	}
	total := frameHeaderLen + len(js) + len(body)

	buf := C.malloc(C.size_t(total))
	out := unsafe.Slice((*byte)(buf), total)
	binary.LittleEndian.PutUint32(out[:frameHeaderLen], uint32(len(js)))
	copy(out[frameHeaderLen:], js)
	copy(out[frameHeaderLen+len(js):], body)
	return (*C.char)(buf), C.int(total)
}

func decodeFrame(p *C.char, n C.int) (meta []byte, body []byte, err error) {
	if n < frameHeaderLen {
		return nil, nil, fmt.Errorf("кадр короче заголовка: %d байт", int(n))
	}
	raw := C.GoBytes(unsafe.Pointer(p), n)
	metaLen := int(binary.LittleEndian.Uint32(raw[:frameHeaderLen]))
	if frameHeaderLen+metaLen > len(raw) {
		return nil, nil, fmt.Errorf("длина JSON (%d) выходит за кадр (%d)", metaLen, len(raw))
	}
	return raw[frameHeaderLen : frameHeaderLen+metaLen], raw[frameHeaderLen+metaLen:], nil
}

// respondFrame — аналог respond для ответов с телом.
func respondFrame(data any, body []byte, err error) (*C.char, C.int) {
	var r result
	if err != nil {
		r.Error = err.Error()
		return encodeFrame(r, nil)
	}
	r.OK = true
	if data != nil {
		enc, mErr := json.Marshal(data)
		if mErr != nil {
			r.OK, r.Error = false, "сериализация ответа: "+mErr.Error()
			return encodeFrame(r, nil)
		}
		r.Data = enc
	}
	return encodeFrame(r, body)
}

// curlpro_request принимает и возвращает кадр [uint32 len JSON][JSON][тело].
// Длина возвращаемого кадра пишется в outLen; освобождать через curlpro_free.
//
//export curlpro_request
func curlpro_request(id C.longlong, frame *C.char, frameLen C.int, outLen *C.int) *C.char {
	write := func(p *C.char, n C.int) *C.char {
		if outLen != nil {
			*outLen = n
		}
		return p
	}

	sessionsMu.RLock()
	s, ok := sessions[int64(id)]
	sessionsMu.RUnlock()
	if !ok {
		return write(respondFrame(nil, nil, fmt.Errorf("сессия %d не найдена", int64(id))))
	}

	meta, body, err := decodeFrame(frame, frameLen)
	if err != nil {
		return write(respondFrame(nil, nil, err))
	}
	var r requestJSON
	if err := json.Unmarshal(meta, &r); err != nil {
		return write(respondFrame(nil, nil, fmt.Errorf("разбор запроса: %w", err)))
	}

	req := &client.Request{
		Method:           r.Method,
		URL:              r.URL,
		Headers:          r.Headers,
		Body:             body,
		HeaderOrder:      r.HeaderOrder,
		NoDefaultHeaders: r.NoDefaultHeaders,
	}
	if r.Multipart != nil {
		form, err := splitFiles(r.Multipart, body)
		if err != nil {
			return write(respondFrame(nil, nil, err))
		}
		req.Multipart = form
		req.Body = nil
	}

	resp, err := s.Do(req)
	if err != nil {
		return write(respondFrame(nil, nil, err))
	}
	return write(respondFrame(responseJSON{
		Status:  resp.Status,
		Proto:   resp.Proto,
		Headers: resp.Headers,
		URL:     resp.URL,
		BodyLen: len(resp.Body),
	}, resp.Body, nil))
}

func main() {}
