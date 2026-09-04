// Command curlpro is the C-shared library: the entry point for bindings.
//
// The exchange happens through JSON strings passed as char*: slower than
// structs, but it removes the need to keep a C header in sync with every
// binding. The export set is deliberately narrow — widen it when needed.
//
// Memory ownership: every string returned by the library is allocated in C
// and must be released with curlpro_free. The caller has to do it,
// otherwise it leaks.
//
// A panic inside an export is fatal to the process that loaded the library:
// cgo has no handler that would turn it into a Python exception. That is why
// every export catches recover and returns an error envelope.
//
// Build:
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

// result is the single response envelope. A binding always receives valid
// JSON and reads the failure from the error field, not from a return code.
//
// code is the machine-readable error code (client.ErrorCode) when known: from
// the text alone Python could not tell a server close from a read timeout.
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
				r.OK, r.Error = false, "encoding response: "+mErr.Error()
			} else {
				r.Data = enc
			}
		}
	}
	out, _ := json.Marshal(r)
	return C.CString(string(out))
}

// recoverInto turns a panic inside an export into an error envelope.
func recoverInto(out **C.char) {
	if r := recover(); r != nil {
		*out = respond(nil, fmt.Errorf("internal library error: %v", r))
	}
}

//export curlpro_free
func curlpro_free(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// Version is the version of the native part.
//
// Major and minor form the ABI: Python requires a minimum (REQUIRED_VERSION
// in _ffi.py) and refuses to work with an older library. The minor is raised
// whenever Python starts depending on a new export or configuration field —
// otherwise an old DLL silently ignores the unknown field and an option like
// follow_redirects=False simply has no effect.
//
// 0.3.0: the code field in the envelope, max_message_size for WebSocket, and a
// retry object with zero attempts meaning "no retries" rather than "ask the session".
// 0.4.0: mode (navigation or fetch) and keep_alive on the session.
// 0.5.0: device and devices — high-entropy hints driven by Accept-CH.
// 0.6.0: exporting, importing and clearing cookies.
// 0.7.0: asynchronous request start, resolve and ip_version.
// 0.8.0: alt_svc, a custom CA, client certificates, trust_env, a body limit
// and the redirect history in the response.
// 0.9.0: a separate limit on establishing a connection (connect_timeout_ms),
// plus async stream open, chunk read and WebSocket work.
// 0.10.0: per-request protocol (protocol) and per-request profile headers
// (default_headers instead of no_default_headers: they had to be switchable
// on, not only off).
// 0.11.0: per-request switches for the session memory — the cookie jar
// (cookies) and the session headers (session_headers).
const Version = "0.11.0"

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

// curlpro_profile_register registers a profile from JSON at runtime.
//
// This is the library's central feature: a new browser version can be added
// without waiting for a release and without rebuilding the native part.
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
	ConnectTimeoutMS   int      `json:"connect_timeout_ms"`
	CACert             string   `json:"ca_cert"`
	ClientCert         string   `json:"client_cert"`
	ClientKey          string   `json:"client_key"`
	TrustEnv           bool     `json:"trust_env"`
	MaxResponseSize    int64    `json:"max_response_size"`
	// AltSvc is a pointer because a missing field means "enabled".
	AltSvc    *bool             `json:"alt_svc"`
	Resolve   map[string]string `json:"resolve"`
	IPVersion string            `json:"ip_version"`
	// KeepAlive is a pointer because a missing field means "enabled".
	// An old Python with a fresh DLL must not silently end up reopening a
	// connection for every request.
	KeepAlive *bool      `json:"keep_alive"`
	Retry     *retryJSON `json:"retry"`
	// Mode: "navigate", "fetch" or "auto" (empty) — see client.Options.Mode.
	Mode string `json:"mode"`
	// Device is a device name from the profile's devices section, or "random".
	Device string `json:"device"`
	// Devices overrides the profile's device list.
	Devices []profile.Device `json:"devices"`
}

// retryJSON describes the retry policy.
type retryJSON struct {
	Attempts          int      `json:"attempts"`
	Statuses          []int    `json:"statuses"`
	Methods           []string `json:"methods"`
	BackoffMS         int      `json:"backoff_ms"`
	MaxBackoffMS      int      `json:"max_backoff_ms"`
	RespectRetryAfter bool     `json:"respect_retry_after"`
}

// toPolicy turns JSON into a policy. A missing object (null) means "take the
// session's"; an object with zero attempts means "no retries". Zero used to
// collapse into nil, and a request could not switch off the session's retries.
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
		return respond(nil, fmt.Errorf("parsing configuration: %w", err))
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
		ConnectTimeout:     time.Duration(c.ConnectTimeoutMS) * time.Millisecond,
		CACert:             c.CACert,
		ClientCert:         c.ClientCert,
		ClientKey:          c.ClientKey,
		TrustEnv:           c.TrustEnv,
		MaxResponseSize:    c.MaxResponseSize,
		DisableAltSvc:      c.AltSvc != nil && !*c.AltSvc,
		Resolve:            c.Resolve,
		IPVersion:          c.IPVersion,
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

// curlpro_session_cookies returns the session cookies.
//
// The jar inside the client is not exposed: it only yields the name-value pair
// for one address. Here the records are complete, with domain, path and expiry,
// so a session can be saved and continued in another run.
//
//export curlpro_session_cookies
func curlpro_session_cookies(id C.longlong) (out *C.char) {
	defer recoverInto(&out)
	s, err := lookupSession(id)
	if err != nil {
		return respond(nil, err)
	}
	return respond(map[string]any{"cookies": s.Cookies()}, nil)
}

// curlpro_session_set_cookies loads cookies into the session.
//
//export curlpro_session_set_cookies
func curlpro_session_set_cookies(id C.longlong, data *C.char) (out *C.char) {
	defer recoverInto(&out)
	s, err := lookupSession(id)
	if err != nil {
		return respond(nil, err)
	}
	var cs []client.Cookie
	if err := json.Unmarshal([]byte(C.GoString(data)), &cs); err != nil {
		return respond(nil, fmt.Errorf("parsing cookies: %w", err))
	}
	if err := s.SetCookies(cs); err != nil {
		return respond(nil, err)
	}
	return respond(map[string]any{"cookies": s.Cookies()}, nil)
}

// curlpro_session_clear_cookies forgets every cookie of the session.
//
//export curlpro_session_clear_cookies
func curlpro_session_clear_cookies(id C.longlong) (out *C.char) {
	defer recoverInto(&out)
	s, err := lookupSession(id)
	if err != nil {
		return respond(nil, err)
	}
	if err := s.ClearCookies(); err != nil {
		return respond(nil, err)
	}
	return respond(nil, nil)
}

//export curlpro_session_close
func curlpro_session_close(id C.longlong) (out *C.char) {
	defer recoverInto(&out)
	sessionsMu.Lock()
	s, ok := sessions[int64(id)]
	delete(sessions, int64(id))
	sessionsMu.Unlock()
	if !ok {
		return respond(nil, fmt.Errorf("session %d not found", int64(id)))
	}
	s.Close()
	return respond(nil, nil)
}

type requestJSON struct {
	Method         string            `json:"method"`
	URL            string            `json:"url"`
	Headers        map[string]string `json:"headers"`
	HeaderOrder    []string          `json:"header_order"`
	DefaultHeaders *bool             `json:"default_headers"`
	Cookies        *bool             `json:"cookies"`
	SessionHeaders *bool             `json:"session_headers"`
	Protocol       string            `json:"protocol"`
	Multipart      *multipartJSON    `json:"multipart"`
	// BodyFile streams a file instead of reading it whole into memory.
	BodyFile string `json:"body_file"`

	// Per-request overrides of session settings. Pointers tell "not set" from
	// "set to zero": for a timeout and for redirects those differ.
	TimeoutMS        *int       `json:"timeout_ms"`
	ConnectTimeoutMS *int       `json:"connect_timeout_ms"`
	FollowRedirects  *bool      `json:"follow_redirects"`
	MaxRedirects     *int       `json:"max_redirects"`
	Retry            *retryJSON `json:"retry"`
	// Proxy: null takes the session's, "" goes directly, bypassing it.
	Proxy *string `json:"proxy"`
	// Mode overrides the header set for a single request.
	Mode string `json:"mode"`
}

// applyOverrides copies the request overrides into client.Request.
func (r requestJSON) applyOverrides(req *client.Request) {
	if r.TimeoutMS != nil {
		d := time.Duration(*r.TimeoutMS) * time.Millisecond
		req.Timeout = &d
	}
	if r.ConnectTimeoutMS != nil {
		d := time.Duration(*r.ConnectTimeoutMS) * time.Millisecond
		req.ConnectTimeout = &d
	}
	req.FollowRedirects = r.FollowRedirects
	req.MaxRedirects = r.MaxRedirects
	req.Retry = r.Retry.toPolicy()
	req.Proxy = r.Proxy
	req.Mode = r.Mode
}

// toRequest builds a client.Request out of a frame.
func (r requestJSON) toRequest(body []byte) (*client.Request, error) {
	req := &client.Request{
		Method:         r.Method,
		URL:            r.URL,
		Headers:        r.Headers,
		Body:           body,
		BodyFile:       r.BodyFile,
		HeaderOrder:    r.HeaderOrder,
		DefaultHeaders: r.DefaultHeaders,
		Cookies:        r.Cookies,
		SessionHeaders: r.SessionHeaders,
		Protocol:       r.Protocol,
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

// multipartJSON describes the form. File contents travel in the binary part of
// the frame instead: their lengths are listed in file_sizes, in the files order.
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

// splitFiles cuts the binary part of a frame into file contents by declared length.
func splitFiles(m *multipartJSON, blob []byte) (*client.MultipartForm, error) {
	form := &client.MultipartForm{
		Fields: m.Fields,
		Order:  m.Order,
		Files:  make([]client.FormFile, 0, len(m.Files)),
	}
	if len(m.Files) != len(m.FileSizes) {
		return nil, fmt.Errorf("multipart describes %d files but %d lengths", len(m.Files), len(m.FileSizes))
	}
	offset := 0
	for i, f := range m.Files {
		size := m.FileSizes[i]
		if size < 0 || offset+size > len(blob) {
			return nil, fmt.Errorf("file %q runs past the end of the frame data", f.Filename)
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
	History []client.Redirect   `json:"history,omitempty"`
}

// Bodies travel as binary, separately from the JSON.
//
// A body used to ride as a string inside the JSON, which was not merely slow:
// arbitrary bytes are not valid UTF-8, so the response was corrupted. A request
// for 10,000 random bytes returned 18,502 — the data grew during re-encoding.
//
// Frame layout: [uint32 LE JSON length][JSON][raw body].
const frameHeaderLen = 4

func encodeFrame(meta any, body []byte) (*C.char, C.int) {
	js, err := json.Marshal(meta)
	if err != nil {
		js, _ = json.Marshal(result{Error: "encoding: " + err.Error()})
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
		return nil, nil, fmt.Errorf("frame is shorter than its header: %d bytes", int(n))
	}
	raw := C.GoBytes(unsafe.Pointer(p), n)
	metaLen := int(binary.LittleEndian.Uint32(raw[:frameHeaderLen]))
	if frameHeaderLen+metaLen > len(raw) {
		return nil, nil, fmt.Errorf("JSON length (%d) runs past the frame (%d)", metaLen, len(raw))
	}
	return raw[frameHeaderLen : frameHeaderLen+metaLen], raw[frameHeaderLen+metaLen:], nil
}

// respondFrame is respond's counterpart for responses that carry a body.
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
			r.OK, r.Error = false, "encoding response: "+mErr.Error()
			return encodeFrame(r, nil)
		}
		r.Data = enc
	}
	return encodeFrame(r, body)
}

// framed runs an export body with a framed response: it writes the length into
// outLen and turns a panic into an error envelope.
func framed(outLen *C.int, f func() (*C.char, C.int)) (out *C.char) {
	var n C.int
	defer func() {
		if r := recover(); r != nil {
			out, n = respondFrame(nil, nil, fmt.Errorf("internal library error: %v", r))
		}
		if outLen != nil {
			*outLen = n
		}
	}()
	out, n = f()
	return out
}

// curlpro_request takes and returns a frame [uint32 len JSON][JSON][body].
// The returned frame length is written to outLen; free it with curlpro_free.
//
//export curlpro_request
func curlpro_request(id C.longlong, frame *C.char, frameLen C.int, outLen *C.int) *C.char {
	return framed(outLen, func() (*C.char, C.int) {
		sessionsMu.RLock()
		s, ok := sessions[int64(id)]
		sessionsMu.RUnlock()
		if !ok {
			return respondFrame(nil, nil, fmt.Errorf("session %d not found", int64(id)))
		}

		meta, body, err := decodeFrame(frame, frameLen)
		if err != nil {
			return respondFrame(nil, nil, err)
		}
		var r requestJSON
		if err := json.Unmarshal(meta, &r); err != nil {
			return respondFrame(nil, nil, fmt.Errorf("parsing request: %w", err))
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
			History: resp.History,
		}, resp.Body, nil)
	})
}

func main() {}
