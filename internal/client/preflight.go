package client

import (
	"fmt"
	"net/textproto"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"

	"github.com/curlpro/curlpro/internal/fingerprint"
	"github.com/curlpro/curlpro/internal/profile"
)

// The CORS preflight.
//
// A browser sends OPTIONS before a cross-origin fetch that is not "simple":
// a method other than GET, HEAD or POST, a header outside the CORS
// safelist, a Content-Type outside the three form types. The request itself
// goes only after the server has allowed it, and never at all when it has
// not. Measured on Chrome 153 and Firefox 156 (cmd/hcapture -origins): what
// the OPTIONS carries and in what order, that it carries neither cookies
// nor the request's own headers, and that a DELETE gets one without
// access-control-request-headers. A library that sent the request straight
// out produced, for a server logging its preflights, a request no browser
// makes; and a caller who built the OPTIONS by hand with the custom headers
// on it sent something a browser never sends either.

// Preflight is a CORS preflight the session sent before a request, as the
// caller sees it on the response.
type Preflight struct {
	URL     string              `json:"url"`
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	// Cached says no OPTIONS went out: an earlier answer, within its
	// Access-Control-Max-Age, still covered the method and the headers —
	// which is why a browser does not preflight every request either.
	Cached bool `json:"cached,omitempty"`
}

// CORSError: the preflight was refused, or its answer does not allow the
// request. The request was not sent — a browser would not send it — and the
// answer is attached so the caller can see why.
//
// Not a permanent error on purpose: a 503 to OPTIONS is a bad minute, an
// answer without Access-Control-Allow-Origin is forever, and the caller
// tells them apart by Status better than a guess here would.
type CORSError struct {
	Method  string
	URL     string
	Reason  string
	Status  int
	Headers map[string][]string
}

func (e *CORSError) Error() string {
	return fmt.Sprintf("CORS preflight for %s %s: %s", e.Method, e.URL, e.Reason)
}

// preflightEnabled: the request's say, else the session's.
func (s *Session) preflightEnabled(r *Request) bool {
	if r != nil && r.Preflight != nil {
		return *r.Preflight
	}
	return !s.opts.DisablePreflight
}

// preflightNeeded says whether a browser would preflight this request, and
// with which header names in access-control-request-headers.
func (s *Session) preflightNeeded(r *Request, u *url.URL) (bool, []string) {
	if r == nil || r.preflight || !s.preflightEnabled(r) || s.modeFor(r) != ModeFetch {
		return false, nil
	}
	page := s.pageURL(r)
	if page == nil || sameOrigin(page.String(), u.String()) {
		return false, nil
	}
	unsafe := s.corsUnsafeHeaders(r)
	switch strings.ToUpper(r.Method) {
	case "", "GET", "HEAD", "POST":
		return len(unsafe) > 0, unsafe
	}
	return true, unsafe
}

// corsUnsafeHeaders lists the caller's headers a browser cannot send without
// a preflight: everything outside the CORS safelist, lowercase and sorted,
// which is the value of access-control-request-headers. The profile's own
// headers do not count — the browser adds those itself.
func (s *Session) corsUnsafeHeaders(r *Request) []string {
	var all []headerKV
	if s.useSessionHeaders(r) {
		for _, h := range s.headers.All() {
			all = append(all, headerKV{h.Key, h.Value})
		}
	}
	for k, v := range r.Headers {
		all = append(all, headerKV{k, v})
	}
	seen := map[string]bool{}
	var unsafe []string
	safeTotal := 0
	for _, h := range all {
		name := strings.ToLower(h.Key)
		// A name a script cannot set is the browser's own, not the caller's:
		// the sec-fetch-site a redirect hop rewrites, a Referer or Origin
		// given by hand. Fetch's forbidden request-header names never make
		// a request non-simple, because a page never gets to send them.
		if browserOwnedHeader(name) {
			continue
		}
		if corsSafelisted(name, h.Value) {
			safeTotal += len(h.Value)
			continue
		}
		if !seen[name] {
			seen[name] = true
			unsafe = append(unsafe, name)
		}
	}
	// The safelist has a budget: past 1024 bytes of safelisted values, every
	// one of them needs the preflight too (Fetch, "CORS-unsafe request-header names").
	if safeTotal > 1024 {
		for _, h := range all {
			name := strings.ToLower(h.Key)
			if !seen[name] {
				seen[name] = true
				unsafe = append(unsafe, name)
			}
		}
	}
	sort.Strings(unsafe)
	return unsafe
}

// browserOwnedHeader is Fetch's "forbidden request-header name": what a
// script cannot set and the browser fills in itself.
func browserOwnedHeader(name string) bool {
	if strings.HasPrefix(name, "sec-") || strings.HasPrefix(name, "proxy-") {
		return true
	}
	switch name {
	case "accept-charset", "accept-encoding", "access-control-request-headers",
		"access-control-request-method", "connection", "content-length", "cookie",
		"cookie2", "date", "dnt", "expect", "host", "keep-alive", "origin", "referer",
		"set-cookie", "te", "trailer", "transfer-encoding", "upgrade", "via",
		"user-agent":
		return true
	}
	return false
}

// corsSafelisted is the Fetch standard's "CORS-safelisted request-header":
// four names, each with a value under 128 bytes and of a permitted shape.
func corsSafelisted(name, value string) bool {
	if len(value) > 128 {
		return false
	}
	switch name {
	case "accept":
		return !hasCORSUnsafeByte(value)
	case "accept-language", "content-language":
		for i := 0; i < len(value); i++ {
			c := value[i]
			if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
				strings.IndexByte(" *,-.;=", c) >= 0) {
				return false
			}
		}
		return true
	case "content-type":
		if hasCORSUnsafeByte(value) {
			return false
		}
		switch strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0])) {
		case "application/x-www-form-urlencoded", "multipart/form-data", "text/plain":
			return true
		}
		return false
	case "range":
		// A simple range request: bytes=N- or bytes=N-M, one range.
		rest, ok := strings.CutPrefix(value, "bytes=")
		if !ok {
			return false
		}
		first, last, ok := strings.Cut(rest, "-")
		if !ok || first == "" || !digits(first) || (last != "" && !digits(last)) {
			return false
		}
		return true
	}
	return false
}

func digits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// hasCORSUnsafeByte is Fetch's "CORS-unsafe request-header byte".
func hasCORSUnsafeByte(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < 0x20 && c != 0x09 || c == 0x7f || strings.IndexByte("\"():<>?@[\\]{}", c) >= 0 {
			return true
		}
	}
	return false
}

// preflightTemplate is the header set of the OPTIONS: the family's measured
// preflight order over the profile's fetch-set values, or — where no order
// was measured — the fetch set itself minus what a preflight never carries,
// with the two access-control-request-* names slotted after accept.
func (s *Session) preflightTemplate() headerTemplate {
	fetch := s.profile.ResolvedFetchHeaders()
	byName := make(map[string]profile.HeaderPair, len(fetch))
	for _, h := range fetch {
		byName[strings.ToLower(h.Key)] = h
	}
	const reqMethod, reqHeaders = "access-control-request-method", "access-control-request-headers"

	var pairs []profile.HeaderPair
	if order := profile.PreflightOrder(s.profile.Family()); order != nil {
		for _, name := range order {
			switch name {
			case reqMethod, reqHeaders:
				pairs = append(pairs, profile.HeaderPair{Key: name})
			default:
				if h, ok := byName[name]; ok {
					pairs = append(pairs, h)
				}
			}
		}
	} else {
		for _, h := range fetch {
			name := strings.ToLower(h.Key)
			switch {
			case strings.HasPrefix(name, "sec-ch-ua"), name == "cookie",
				name == "content-type", name == "content-length":
				continue
			}
			pairs = append(pairs, h)
			if name == "accept" {
				pairs = append(pairs, profile.HeaderPair{Key: reqMethod}, profile.HeaderPair{Key: reqHeaders})
			}
		}
	}
	return headerTemplate{
		pairs:  pairs,
		h1:     preflightH1Order(pairs, s.profile.Fetch.HTTP1Order),
		anchor: s.profile.Fetch.CustomAnchor,
		fetch:  true,
	}
}

// preflightH1Order is the HTTP/1.1 order of the preflight: Host and
// Connection from the fetch set's own order, the case it prescribes for the
// names it knows, canonical case for the two it cannot know. The stand
// measures HTTP/2, so the case of the two is the usual one, not a measured one.
func preflightH1Order(pairs []profile.HeaderPair, base []string) []string {
	if len(base) == 0 {
		return nil
	}
	caseOf := make(map[string]string, len(base))
	for _, n := range base {
		caseOf[strings.ToLower(n)] = n
	}
	out := make([]string, 0, len(pairs)+2)
	for _, n := range base {
		if l := strings.ToLower(n); l == "host" || l == "connection" {
			out = append(out, n)
		}
	}
	for _, h := range pairs {
		l := strings.ToLower(h.Key)
		if l == "host" || l == "connection" {
			continue
		}
		if c, ok := caseOf[l]; ok {
			out = append(out, c)
			continue
		}
		// A name the fetch set's HTTP/1.1 order does not carry is not sent
		// on HTTP/1.1 at all (Chrome drops priority there); the two names
		// that describe the request are the exception, in canonical case.
		if l == "access-control-request-method" || l == "access-control-request-headers" {
			out = append(out, textproto.CanonicalMIMEHeaderKey(l))
		}
	}
	return out
}

// preflightRequest builds the OPTIONS for a request: same URL, page, proxy
// and transport; no cookies, no session headers, none of the request's own
// headers — only the two that describe it.
func (s *Session) preflightRequest(r *Request, unsafe []string) Request {
	no, yes := false, true
	pf := Request{
		Method:          http.MethodOptions,
		URL:             r.URL,
		Mode:            ModeFetch,
		Page:            r.Page,
		Proxy:           r.Proxy,
		Protocol:        r.Protocol,
		Timeout:         r.Timeout,
		ConnectTimeout:  r.ConnectTimeout,
		ResponseTimeout: r.ResponseTimeout,
		Cookies:         &no,
		SessionHeaders:  &no,
		DefaultHeaders:  &yes,
		Headers:         map[string]string{"access-control-request-method": strings.ToUpper(r.Method)},
		preflight:       true,
		chainOrigin:     r.chainOrigin,
		originTainted:   r.originTainted,
	}
	if len(unsafe) > 0 {
		pf.Headers["access-control-request-headers"] = strings.Join(unsafe, ",")
	}
	return pf
}

// preflight sends the OPTIONS for a request (or finds a cached answer) and
// checks that the answer allows the request. On refusal the error is a
// *CORSError carrying the answer.
func (s *Session) preflight(r *Request, u *url.URL, unsafe []string, deadline time.Time) (Preflight, error) {
	method := strings.ToUpper(r.Method)
	if method == "" {
		method = "GET"
	}
	origin := "null"
	if !r.originTainted {
		if page := s.pageURL(r); page != nil {
			origin = originOf(page)
		}
	}
	credentials := s.credentialsFor(r) == CredentialsInclude
	key := origin + "\x00" + u.String()
	if hit := s.preflightHit(key, method, unsafe, credentials); hit != nil {
		return Preflight{URL: u.String(), Status: hit.status, Headers: hit.header, Cached: true}, nil
	}

	pf := s.preflightRequest(r, unsafe)
	resp, cancel, used, err := s.send(&pf, deadline)
	if err != nil {
		return Preflight{}, fmt.Errorf("CORS preflight for %s %s: %w", method, u, err)
	}
	// Only an HTTP/1.1 connection is lost with an unread body: on HTTP/2
	// closing the body resets its own stream, and a hard close here used to
	// kill every other stream sharing the connection.
	if !drain(resp, cancel) && used != nil && used.h2 == nil {
		s.evict(used, true)
	}
	s.release(used)

	info := Preflight{URL: u.String(), Status: resp.StatusCode, Headers: resp.Header}
	if reason := corsCheck(resp, origin, credentials, method, unsafe); reason != "" {
		return info, &CORSError{Method: method, URL: u.String(), Reason: reason,
			Status: resp.StatusCode, Headers: resp.Header}
	}
	s.preflightStore(key, resp, credentials)
	return info, nil
}

// corsCheck is the Fetch standard's CORS check plus the preflight's own
// two: the status, the origin, the credentials, the method, the headers.
// Returns the reason it fails, or "".
func corsCheck(resp *http.Response, origin string, credentials bool, method string, unsafe []string) string {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Sprintf("the server answered %s", resp.Status)
	}
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	switch {
	case acao == "":
		return "no Access-Control-Allow-Origin in the answer"
	case acao == "*" && credentials:
		return "Access-Control-Allow-Origin is * while the request carries credentials (credentials=include)"
	case acao != "*" && acao != origin:
		return fmt.Sprintf("Access-Control-Allow-Origin %q does not match the page's origin %q", acao, origin)
	}
	if credentials && !strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true") {
		return "the request carries credentials (credentials=include) but Access-Control-Allow-Credentials is not true"
	}
	methods, headers := corsLists(resp.Header)
	switch method {
	case "GET", "HEAD", "POST":
	default:
		if !methods[method] && !(methods["*"] && !credentials) {
			return fmt.Sprintf("method %s is not in Access-Control-Allow-Methods %q", method,
				resp.Header.Get("Access-Control-Allow-Methods"))
		}
	}
	for _, name := range unsafe {
		if headers[name] {
			continue
		}
		if headers["*"] && !credentials && name != "authorization" {
			continue
		}
		return fmt.Sprintf("header %s is not in Access-Control-Allow-Headers %q", name,
			resp.Header.Get("Access-Control-Allow-Headers"))
	}
	return ""
}

// corsLists reads the allowed methods (upper case) and headers (lower case).
func corsLists(h http.Header) (methods, headers map[string]bool) {
	methods, headers = map[string]bool{}, map[string]bool{}
	for _, v := range h.Values("Access-Control-Allow-Methods") {
		for _, m := range strings.Split(v, ",") {
			if m = strings.TrimSpace(m); m != "" {
				methods[strings.ToUpper(m)] = true
			}
		}
	}
	for _, v := range h.Values("Access-Control-Allow-Headers") {
		for _, n := range strings.Split(v, ",") {
			if n = strings.TrimSpace(n); n != "" {
				headers[strings.ToLower(n)] = true
			}
		}
	}
	return methods, headers
}

// PreviewPreflight reports the OPTIONS a request would be preceded by,
// without sending anything: the names in send order and the pairs, and
// whether one is needed at all — false, with nothing else, for a request a
// browser sends straight out. The same assembly the real preflight runs.
func (s *Session) PreviewPreflight(r *Request) ([]string, []fingerprint.HeaderKV, bool, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, nil, false, err
	}
	if r == nil {
		r = &Request{}
	}
	req := *r
	if req.Method == "" {
		req.Method = "GET"
	}
	if req.URL == "" {
		req.URL = "https://example.com/"
	}
	if err := s.checkMode(&req); err != nil {
		return nil, nil, false, err
	}
	if err := req.validate(s.cookieJar() != nil); err != nil {
		return nil, nil, false, err
	}
	u, err := parseURL(req.URL)
	if err != nil {
		return nil, nil, false, configErr("parsing %q: %v", req.URL, err)
	}
	needed, unsafe := s.preflightNeeded(&req, u)
	if !needed {
		return nil, nil, false, nil
	}
	pf := s.preflightRequest(&req, unsafe)
	h1 := req.Protocol == ProtoHTTP1 || (req.Protocol == "" && (s.opts.ForceHTTP1 || u.Scheme == "http"))
	names, pairs := s.previewFor(&pf, u, h1)
	return names, pairs, true, nil
}

// preflightEntry is a cached answer: what it allows and until when.
type preflightEntry struct {
	allowMethods, allowHeaders map[string]bool
	// credentials says the answer allowed a credentialed request; such an
	// answer covers an uncredentialed one too, not the other way round.
	credentials bool
	expires     time.Time
	status      int
	header      http.Header
}

func (s *Session) preflightHit(key, method string, unsafe []string, credentials bool) *preflightEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.preflights[key]
	if !ok {
		return nil
	}
	if time.Now().After(e.expires) {
		delete(s.preflights, key)
		return nil
	}
	if credentials && !e.credentials {
		return nil
	}
	switch method {
	case "GET", "HEAD", "POST":
	default:
		if !e.allowMethods[method] && !e.allowMethods["*"] {
			return nil
		}
	}
	for _, n := range unsafe {
		if !e.allowHeaders[n] && !(e.allowHeaders["*"] && n != "authorization") {
			return nil
		}
	}
	return e
}

// preflightStore keeps an allowing answer for its Access-Control-Max-Age:
// five seconds without the header, capped the way the family caps it.
func (s *Session) preflightStore(key string, resp *http.Response, credentials bool) {
	age := profile.PreflightDefaultMaxAge
	if v := resp.Header.Get("Access-Control-Max-Age"); v != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 0 {
			return // an invalid or negative value: not cached at all
		}
		age = time.Duration(n) * time.Second
		if cap := profile.PreflightMaxAge(s.profile.Family()); age > cap {
			age = cap
		}
	}
	if age <= 0 {
		return
	}
	methods, headers := corsLists(resp.Header)
	s.mu.Lock()
	if s.preflights == nil {
		s.preflights = make(map[string]*preflightEntry)
	}
	s.preflights[key] = &preflightEntry{allowMethods: methods, allowHeaders: headers, credentials: credentials,
		expires: time.Now().Add(age), status: resp.StatusCode, header: resp.Header}
	s.mu.Unlock()
}
