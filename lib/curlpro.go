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
// Паника внутри экспорта фатальна для процесса, который загрузил библиотеку:
// у cgo нет обработчика, который перевёл бы её в исключение Python. Поэтому
// каждый экспорт ловит recover и отдаёт конверт с ошибкой.
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
//
// code — машинный код ошибки (client.ErrorCode), когда он известен: по тексту
// Python не мог отличить «сервер закрыл WebSocket» от таймаута чтения.
type result struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Code  string          `json:"code,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

func respond(data any, err error) *C.char {
	var r result
	if err != nil {
		r.Error = err.Error()
		r.Code = string(client.Code(err))
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

// recoverInto превращает панику экспорта в конверт с ошибкой.
func recoverInto(out **C.char) {
	if r := recover(); r != nil {
		*out = respond(nil, fmt.Errorf("внутренняя ошибка библиотеки: %v", r))
	}
}

//export curlpro_free
func curlpro_free(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// Version — версия нативной части.
//
// Мажор и минор образуют ABI: Python требует минимум (REQUIRED_VERSION
// в _ffi.py) и отказывается работать со старой библиотекой. Минор поднимается,
// когда Python начинает зависеть от нового экспорта или поля конфигурации —
// иначе старая DLL молча игнорирует незнакомое поле, и опция вроде
// follow_redirects=False просто не действует.
//
// 0.3.0: поле code в конверте, max_message_size у WebSocket, объект retry
// с нулём попыток означает «без повторов», а не «взять из сессии».
// 0.4.0: mode (навигация или fetch) и keep_alive у сессии.
// 0.5.0: device и devices — подсказки высокой энтропии по Accept-CH.
const Version = "0.5.0"

//export curlpro_version
func curlpro_version() *C.char {
	return respond(map[string]string{"version": Version}, nil)
}

//export curlpro_profiles_load_dir
func curlpro_profiles_load_dir(dir *C.char) (out *C.char) {
	defer recoverInto(&out)
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
func curlpro_profile_register(data *C.char) (out *C.char) {
	defer recoverInto(&out)
	if err := registry.Register([]byte(C.GoString(data))); err != nil {
		return respond(nil, err)
	}
	return respond(map[string]any{"profiles": registry.Names()}, nil)
}

//export curlpro_profiles_list
func curlpro_profiles_list() (out *C.char) {
	defer recoverInto(&out)
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
	MaxIdleConns       int      `json:"max_idle_conns"`
	IdleConnTimeoutMS  int      `json:"idle_conn_timeout_ms"`
	// KeepAlive: указатель, потому что отсутствие поля означает «включено».
	// Старый Python со свежей DLL не должен молча получить пересоздание
	// соединения на каждый запрос.
	KeepAlive *bool      `json:"keep_alive"`
	Retry     *retryJSON `json:"retry"`
	// Mode: "navigate", "fetch" или "auto" (пусто) — см. client.Options.Mode.
	Mode string `json:"mode"`
	// Device — имя устройства из секции devices профиля либо "random".
	Device string `json:"device"`
	// Devices переопределяет список устройств профиля.
	Devices []profile.Device `json:"devices"`
}

// retryJSON описывает политику повторов.
type retryJSON struct {
	Attempts          int      `json:"attempts"`
	Statuses          []int    `json:"statuses"`
	Methods           []string `json:"methods"`
	BackoffMS         int      `json:"backoff_ms"`
	MaxBackoffMS      int      `json:"max_backoff_ms"`
	RespectRetryAfter bool     `json:"respect_retry_after"`
}

// toPolicy переводит JSON в политику. Отсутствие объекта (null) — «взять
// из сессии»; объект с нулём попыток — «без повторов». Раньше ноль
// схлопывался в nil, и запрос не мог отключить повторы, заданные сессии.
func (r *retryJSON) toPolicy() *client.RetryPolicy {
	if r == nil {
		return nil
	}
	attempts := r.Attempts
	if attempts < 0 {
		attempts = 0
	}
	return &client.RetryPolicy{
		Attempts:          attempts,
		Statuses:          r.Statuses,
		Methods:           r.Methods,
		Backoff:           time.Duration(r.BackoffMS) * time.Millisecond,
		MaxBackoff:        time.Duration(r.MaxBackoffMS) * time.Millisecond,
		RespectRetryAfter: r.RespectRetryAfter,
	}
}

//export curlpro_session_new
func curlpro_session_new(cfg *C.char) (out *C.char) {
	defer recoverInto(&out)
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
		DisableKeepAlive:   c.KeepAlive != nil && !*c.KeepAlive,
		MaxIdleConns:       c.MaxIdleConns,
		IdleConnTimeout:    time.Duration(c.IdleConnTimeoutMS) * time.Millisecond,
		Retry:              c.Retry.toPolicy(),
		Mode:               c.Mode,
		Device:             c.Device,
		Devices:            c.Devices,
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
func curlpro_session_close(id C.longlong) (out *C.char) {
	defer recoverInto(&out)
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
	// BodyFile отправляет файл потоком, не читая его целиком в память.
	BodyFile string `json:"body_file"`

	// Переопределения сессионных настроек. Указатели отличают «не задано»
	// от «задано в ноль»: для таймаута и редиректов это разные вещи.
	TimeoutMS       *int       `json:"timeout_ms"`
	FollowRedirects *bool      `json:"follow_redirects"`
	MaxRedirects    *int       `json:"max_redirects"`
	Retry           *retryJSON `json:"retry"`
	// Proxy: null — взять из сессии, "" — идти напрямую в обход сессионного.
	Proxy *string `json:"proxy"`
	// Mode переопределяет режим набора заголовков для одного запроса.
	Mode string `json:"mode"`
}

// applyOverrides переносит переопределения запроса в client.Request.
func (r requestJSON) applyOverrides(req *client.Request) {
	if r.TimeoutMS != nil {
		d := time.Duration(*r.TimeoutMS) * time.Millisecond
		req.Timeout = &d
	}
	req.FollowRedirects = r.FollowRedirects
	req.MaxRedirects = r.MaxRedirects
	req.Retry = r.Retry.toPolicy()
	req.Proxy = r.Proxy
	req.Mode = r.Mode
}

// toRequest собирает client.Request из кадра.
func (r requestJSON) toRequest(body []byte) (*client.Request, error) {
	req := &client.Request{
		Method:           r.Method,
		URL:              r.URL,
		Headers:          r.Headers,
		Body:             body,
		BodyFile:         r.BodyFile,
		HeaderOrder:      r.HeaderOrder,
		NoDefaultHeaders: r.NoDefaultHeaders,
	}
	r.applyOverrides(req)
	if r.Multipart != nil {
		form, err := splitFiles(r.Multipart, body)
		if err != nil {
			return nil, err
		}
		req.Multipart = form
		req.Body = nil
	}
	return req, nil
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
		r.Code = string(client.Code(err))
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

// framed выполняет тело экспорта с кадровым ответом: пишет длину в outLen
// и переводит панику в конверт с ошибкой.
func framed(outLen *C.int, f func() (*C.char, C.int)) (out *C.char) {
	var n C.int
	defer func() {
		if r := recover(); r != nil {
			out, n = respondFrame(nil, nil, fmt.Errorf("внутренняя ошибка библиотеки: %v", r))
		}
		if outLen != nil {
			*outLen = n
		}
	}()
	out, n = f()
	return out
}

// curlpro_request принимает и возвращает кадр [uint32 len JSON][JSON][тело].
// Длина возвращаемого кадра пишется в outLen; освобождать через curlpro_free.
//
//export curlpro_request
func curlpro_request(id C.longlong, frame *C.char, frameLen C.int, outLen *C.int) *C.char {
	return framed(outLen, func() (*C.char, C.int) {
		sessionsMu.RLock()
		s, ok := sessions[int64(id)]
		sessionsMu.RUnlock()
		if !ok {
			return respondFrame(nil, nil, fmt.Errorf("сессия %d не найдена", int64(id)))
		}

		meta, body, err := decodeFrame(frame, frameLen)
		if err != nil {
			return respondFrame(nil, nil, err)
		}
		var r requestJSON
		if err := json.Unmarshal(meta, &r); err != nil {
			return respondFrame(nil, nil, fmt.Errorf("разбор запроса: %w", err))
		}
		req, err := r.toRequest(body)
		if err != nil {
			return respondFrame(nil, nil, err)
		}

		resp, err := s.Do(req)
		if err != nil {
			return respondFrame(nil, nil, err)
		}
		return respondFrame(responseJSON{
			Status:  resp.Status,
			Proto:   resp.Proto,
			Headers: resp.Headers,
			URL:     resp.URL,
			BodyLen: len(resp.Body),
		}, resp.Body, nil)
	})
}

func main() {}
