package client

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

// The HTTP cache: a browser's memory of what it fetched.
//
// A browser does not fetch a page's stylesheets, scripts and images anew on
// every visit. A fresh response comes out of its cache with no request at
// all; a stale one, or one the server said to check (no-cache), goes out as a
// conditional request — If-None-Match, If-Modified-Since — and a 304 answer
// hands back the stored body. A client that downloads every resource on
// every page load looks like nothing a browser does, and pays for it.
//
// Measured on the hcapture -cache stand (Chrome 154, Firefox 156; docs/
// STAGE22-RESULTS.md): the freshness rules are RFC 9111's — max-age, Expires,
// a tenth of the Last-Modified age for a response with no explicit lifetime,
// no-cache and no-store; the cache is partitioned by the top-level site, so a
// resource cached under one site is fetched anew under another; a reload
// revalidates the document alone, with cache-control: max-age=0 in Chrome and
// without it in Firefox; the validators take the places the profile's slots
// say, which differ between the two browsers and between a document, a fetch
// and a subresource.

// Cache modes, as fetch()'s RequestInit.cache names them.
const (
	CacheDefault      = "default"
	CacheNoStore      = "no-store"
	CacheNoCache      = "no-cache"
	CacheForceCache   = "force-cache"
	CacheOnlyIfCached = "only-if-cached"
)

// Cache outcomes, as a response reports them.
const (
	CacheMiss        = "miss"        // fetched from the network, and stored when it could be
	CacheHit         = "hit"         // served from the cache, no request made
	CacheRevalidated = "revalidated" // a conditional request, answered 304, served from the cache
)

// CacheOptions switches the cache on for a session.
type CacheOptions struct {
	// MaxBytes caps what the cache holds; the entries used longest ago go
	// first. 0 means 64 MiB in memory, 256 MiB on disk.
	MaxBytes int64
	// Dir keeps the cache on disk, one file per entry, so the next session
	// opened on it starts as a returning visitor does. Empty keeps it in memory.
	Dir string
}

// CacheStats counts what the cache did.
type CacheStats struct {
	// Enabled is false for a session without a cache, and the rest zero.
	Enabled bool `json:"enabled"`
	// Dir is where the cache lives, "" in memory.
	Dir         string `json:"dir,omitempty"`
	Entries     int    `json:"entries"`
	Bytes       int64  `json:"bytes"`
	MaxBytes    int64  `json:"max_bytes"`
	Hits        int64  `json:"hits"`
	Revalidated int64  `json:"revalidated"`
	Misses      int64  `json:"misses"`
	Stored      int64  `json:"stored"`
}

// cacheEntry is one stored response.
type cacheEntry struct {
	Key    string
	URL    string
	Status int
	Proto  string
	Header map[string][]string
	Body   []byte
	// RequestTime and ResponseTime bound the exchange that produced the
	// entry, for its age (RFC 9111 4.2.3).
	RequestTime, ResponseTime time.Time
	// Vary holds the values the request carried for the names the response
	// varies on.
	Vary map[string]string
}

func (e *cacheEntry) size() int64 {
	n := int64(len(e.Body)) + int64(len(e.Key)) + 256
	for k, vs := range e.Header {
		for _, v := range vs {
			n += int64(len(k) + len(v))
		}
	}
	return n
}

// cacheControl is a parsed Cache-Control header.
type cacheControl map[string]string

func parseCacheControl(h map[string][]string) cacheControl {
	cc := cacheControl{}
	for _, line := range headerValues(h, "Cache-Control") {
		for _, part := range strings.Split(line, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			k, v, _ := strings.Cut(part, "=")
			cc[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return cc
}

func (cc cacheControl) has(k string) bool { _, ok := cc[k]; return ok }

func (cc cacheControl) seconds(k string) (time.Duration, bool) {
	v, ok := cc[k]
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, true // a malformed value is taken as zero: stale at once
	}
	return time.Duration(n) * time.Second, true
}

// headerValues returns every value of a header, by any case of its name.
func headerValues(h map[string][]string, name string) []string {
	var out []string
	for k, vs := range h {
		if strings.EqualFold(k, name) {
			out = append(out, vs...)
		}
	}
	return out
}

func headerValue(h map[string][]string, name string) string {
	if vs := headerValues(h, name); len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// lifetime is how long the entry is fresh (RFC 9111 4.2.1): max-age, then
// Expires against Date, then a tenth of the time since Last-Modified — the
// heuristic both browsers use. Zero means it must be revalidated before use.
func (e *cacheEntry) lifetime() time.Duration {
	cc := parseCacheControl(e.Header)
	if cc.has("no-cache") {
		return 0
	}
	if d, ok := cc.seconds("max-age"); ok {
		return d
	}
	date := e.date()
	if exp := headerValue(e.Header, "Expires"); exp != "" {
		t, err := http.ParseTime(exp)
		if err != nil || !t.After(date) {
			return 0
		}
		return t.Sub(date)
	}
	if lm := headerValue(e.Header, "Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil && date.After(t) {
			return date.Sub(t) / 10
		}
	}
	return 0
}

// date is the response's Date, or when it arrived.
func (e *cacheEntry) date() time.Time {
	if d := headerValue(e.Header, "Date"); d != "" {
		if t, err := http.ParseTime(d); err == nil {
			return t
		}
	}
	return e.ResponseTime
}

// age is the entry's current age (RFC 9111 4.2.3).
func (e *cacheEntry) age(now time.Time) time.Duration {
	apparent := e.ResponseTime.Sub(e.date())
	if apparent < 0 {
		apparent = 0
	}
	var ageValue time.Duration
	if a := headerValue(e.Header, "Age"); a != "" {
		if n, err := strconv.ParseInt(a, 10, 64); err == nil && n > 0 {
			ageValue = time.Duration(n) * time.Second
		}
	}
	corrected := ageValue + e.ResponseTime.Sub(e.RequestTime)
	initial := apparent
	if corrected > initial {
		initial = corrected
	}
	return initial + now.Sub(e.ResponseTime)
}

func (e *cacheEntry) fresh(now time.Time) bool {
	return e.age(now) < e.lifetime()
}

func (e *cacheEntry) etag() string         { return headerValue(e.Header, "ETag") }
func (e *cacheEntry) lastModified() string { return headerValue(e.Header, "Last-Modified") }

// storable says whether a response may go into the cache, and is worth it: a
// 200 or 203 to a GET, not no-store, not Vary: *, with a lifetime or a
// validator to revalidate it by.
func storable(resp *http.Response) bool {
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNonAuthoritativeInfo {
		return false
	}
	cc := parseCacheControl(resp.Header)
	if cc.has("no-store") {
		return false
	}
	for _, v := range headerValues(resp.Header, "Vary") {
		if strings.TrimSpace(v) == "*" {
			return false
		}
	}
	if cc.has("max-age") || headerValue(resp.Header, "Expires") != "" ||
		headerValue(resp.Header, "ETag") != "" || headerValue(resp.Header, "Last-Modified") != "" {
		return true
	}
	return false
}

// cacheStore is where entries live: memory or a directory.
type cacheStore interface {
	get(key string) *cacheEntry
	put(e *cacheEntry)
	remove(key string)
	clear()
	stats() (entries int, bytes int64)
}

// httpCache is a session's cache: the store, its limits and its counters.
type httpCache struct {
	store    cacheStore
	dir      string
	max      int64
	entryMax int64
	hits     atomic.Int64
	revalid  atomic.Int64
	misses   atomic.Int64
	stored   atomic.Int64
}

func newHTTPCache(o *CacheOptions) (*httpCache, error) {
	max := o.MaxBytes
	if max <= 0 {
		max = 64 << 20
		if o.Dir != "" {
			max = 256 << 20
		}
	}
	// One entry takes at most an eighth of the cache and never more than
	// 32 MiB: a video is not what this cache is for.
	entryMax := max / 8
	if entryMax > 32<<20 {
		entryMax = 32 << 20
	}
	c := &httpCache{dir: o.Dir, max: max, entryMax: entryMax}
	if o.Dir == "" {
		c.store = newMemStore(max)
		return c, nil
	}
	ds, err := newDiskStore(o.Dir, max)
	if err != nil {
		return nil, err
	}
	c.store = ds
	return c, nil
}

// memStore keeps entries in memory, least recently used first out.
type memStore struct {
	mu    sync.Mutex
	max   int64
	bytes int64
	items map[string]*list.Element
	lru   *list.List // front: most recently used
}

func newMemStore(max int64) *memStore {
	return &memStore{max: max, items: map[string]*list.Element{}, lru: list.New()}
}

func (m *memStore) get(key string) *cacheEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.items[key]
	if !ok {
		return nil
	}
	m.lru.MoveToFront(el)
	return el.Value.(*cacheEntry)
}

func (m *memStore) put(e *cacheEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.items[e.Key]; ok {
		m.bytes -= el.Value.(*cacheEntry).size()
		m.lru.Remove(el)
	}
	m.items[e.Key] = m.lru.PushFront(e)
	m.bytes += e.size()
	for m.bytes > m.max && m.lru.Len() > 1 {
		old := m.lru.Back()
		oe := old.Value.(*cacheEntry)
		m.lru.Remove(old)
		delete(m.items, oe.Key)
		m.bytes -= oe.size()
	}
}

func (m *memStore) remove(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.items[key]; ok {
		m.bytes -= el.Value.(*cacheEntry).size()
		m.lru.Remove(el)
		delete(m.items, key)
	}
}

func (m *memStore) clear() {
	m.mu.Lock()
	m.items, m.bytes = map[string]*list.Element{}, 0
	m.lru.Init()
	m.mu.Unlock()
}

func (m *memStore) stats() (int, int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items), m.bytes
}

// diskStore keeps one gob file per entry, named by the key's hash; the file's
// modification time is its last use, and the oldest go first past the limit.
type diskStore struct {
	dir   string
	max   int64
	mu    sync.Mutex
	files map[string]diskFile // by file name
	bytes int64
}

type diskFile struct {
	size int64
	used time.Time
}

const diskSuffix = ".curlpro-cache"

func newDiskStore(dir string, max int64) (*diskStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, configErr("cache directory %q: %v", dir, err)
	}
	d := &diskStore{dir: dir, max: max, files: map[string]diskFile{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, configErr("cache directory %q: %v", dir, err)
	}
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), diskSuffix) {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		d.files[de.Name()] = diskFile{size: info.Size(), used: info.ModTime()}
		d.bytes += info.Size()
	}
	d.mu.Lock()
	d.evictLocked()
	d.mu.Unlock()
	return d, nil
}

func diskName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16]) + diskSuffix
}

func (d *diskStore) get(key string) *cacheEntry {
	name := diskName(key)
	d.mu.Lock()
	_, ok := d.files[name]
	d.mu.Unlock()
	if !ok {
		return nil
	}
	f, err := os.Open(filepath.Join(d.dir, name))
	if err != nil {
		return nil
	}
	defer f.Close()
	var e cacheEntry
	if gob.NewDecoder(f).Decode(&e) != nil || e.Key != key {
		return nil
	}
	now := time.Now()
	_ = os.Chtimes(filepath.Join(d.dir, name), now, now)
	d.mu.Lock()
	if df, ok := d.files[name]; ok {
		df.used = now
		d.files[name] = df
	}
	d.mu.Unlock()
	return &e
}

func (d *diskStore) put(e *cacheEntry) {
	name := diskName(e.Key)
	var buf bytes.Buffer
	if gob.NewEncoder(&buf).Encode(e) != nil {
		return
	}
	tmp, err := os.CreateTemp(d.dir, "tmp-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(buf.Bytes())
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), filepath.Join(d.dir, name)) != nil {
		os.Remove(tmp.Name())
		return
	}
	d.mu.Lock()
	if old, ok := d.files[name]; ok {
		d.bytes -= old.size
	}
	d.files[name] = diskFile{size: int64(buf.Len()), used: time.Now()}
	d.bytes += int64(buf.Len())
	d.evictLocked()
	d.mu.Unlock()
}

func (d *diskStore) evictLocked() {
	if d.bytes <= d.max {
		return
	}
	names := make([]string, 0, len(d.files))
	for n := range d.files {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return d.files[names[i]].used.Before(d.files[names[j]].used) })
	for _, n := range names {
		if d.bytes <= d.max {
			break
		}
		d.bytes -= d.files[n].size
		delete(d.files, n)
		os.Remove(filepath.Join(d.dir, n))
	}
}

func (d *diskStore) remove(key string) {
	name := diskName(key)
	d.mu.Lock()
	if old, ok := d.files[name]; ok {
		d.bytes -= old.size
		delete(d.files, name)
	}
	d.mu.Unlock()
	os.Remove(filepath.Join(d.dir, name))
}

func (d *diskStore) clear() {
	d.mu.Lock()
	for n := range d.files {
		os.Remove(filepath.Join(d.dir, n))
	}
	d.files, d.bytes = map[string]diskFile{}, 0
	d.mu.Unlock()
}

func (d *diskStore) stats() (int, int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.files), d.bytes
}

// CacheStats reports what the session's cache holds and has done; zero
// without a cache.
func (s *Session) CacheStats() CacheStats {
	c := s.cache
	if c == nil {
		return CacheStats{}
	}
	n, b := c.store.stats()
	return CacheStats{Enabled: true, Dir: c.dir, Entries: n, Bytes: b, MaxBytes: c.max, Hits: c.hits.Load(),
		Revalidated: c.revalid.Load(), Misses: c.misses.Load(), Stored: c.stored.Load()}
}

// ClearCache empties the session's cache, on disk too.
func (s *Session) ClearCache() {
	if s.cache != nil {
		s.cache.store.clear()
	}
}

// cacheKey is where a request's response is kept: the top-level site it is
// made under (topLevel: the URL's own for a navigation, the TopLevel's or
// the page's otherwise) and the URL without its fragment. Both browsers key their cache by the top-level site:
// a stylesheet cached under one site was fetched anew under another.
func (s *Session) cacheKey(r *Request, u *url.URL) string {
	top := s.topLevelFor(r, u)
	clean := *u
	clean.Fragment, clean.RawFragment = "", ""
	return schemefulSite(top) + " " + clean.String()
}

// cacheMode is the request's cache mode, validated.
func (r *Request) cacheMode() string {
	if r == nil || r.CacheMode == "" {
		return CacheDefault
	}
	return r.CacheMode
}

func validateCacheMode(m string) error {
	switch m {
	case "", CacheDefault, CacheNoStore, CacheNoCache, CacheForceCache, CacheOnlyIfCached:
		return nil
	}
	return configErr("cache=%q: use %q, %q, %q, %q or %q", m,
		CacheDefault, CacheNoStore, CacheNoCache, CacheForceCache, CacheOnlyIfCached)
}

// cacheable says a request may use the cache at all: a GET without a body,
// not a preflight, and without a validator or a range of the caller's own —
// those are the caller managing the exchange by hand.
func (s *Session) cacheable(r *Request) bool {
	if s.cache == nil || r.preflight || r.cacheMode() == CacheNoStore {
		return false
	}
	if m := strings.ToUpper(r.Method); m != "" && m != http.MethodGet {
		return false
	}
	if len(r.Body) > 0 || r.BodyFile != "" || r.Multipart != nil {
		return false
	}
	for k := range r.Headers {
		switch strings.ToLower(k) {
		case "if-none-match", "if-modified-since", "if-match", "if-unmodified-since", "if-range", "range":
			return false
		}
	}
	return true
}

// varyValues are the values a request carries for the names a response
// varies on, from the headers the library would send.
func (s *Session) varyValues(r *Request, u *url.URL, header map[string][]string) map[string]string {
	var names []string
	for _, v := range headerValues(header, "Vary") {
		for _, n := range strings.Split(v, ",") {
			if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
				names = append(names, n)
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	built := s.buildHeaders(r, u, u.Host, nil)
	out := make(map[string]string, len(names))
	for _, n := range names {
		for _, h := range built {
			if strings.EqualFold(h.Key, n) {
				out[n] = h.Value
			}
		}
	}
	return out
}

func sameVary(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// cachedBody is a body served from the cache, and says so.
type cachedBody struct {
	*bytes.Reader
	outcome string
}

func (cachedBody) Close() error { return nil }

// missBody marks a network response the cache looked for and did not keep.
type missBody struct{ io.ReadCloser }

// cacheOutcome is how the cache served a response, "" when it did not take part.
func cacheOutcome(body io.ReadCloser) string {
	switch b := body.(type) {
	case cachedBody:
		return b.outcome
	case *teeBody, missBody:
		return CacheMiss
	}
	return ""
}

func (e *cacheEntry) response(outcome string) *http.Response {
	header := make(http.Header, len(e.Header))
	for k, vs := range e.Header {
		header[k] = append([]string(nil), vs...)
	}
	return &http.Response{
		Status:     strconv.Itoa(e.Status) + " " + http.StatusText(e.Status),
		StatusCode: e.Status,
		Proto:      e.Proto,
		Header:     header,
		Body:       cachedBody{bytes.NewReader(e.Body), outcome},
	}
}

// teeBody passes a network body through and stores it once it ends; a body
// that grows past the entry limit, errs or is closed early is not stored.
type teeBody struct {
	io.ReadCloser
	cache *httpCache
	entry *cacheEntry
	buf   bytes.Buffer
	done  bool
}

func (t *teeBody) Read(p []byte) (int, error) {
	n, err := t.ReadCloser.Read(p)
	if !t.done && n > 0 {
		if int64(t.buf.Len()+n) > t.cache.entryMax {
			t.done = true
			t.buf = bytes.Buffer{}
		} else {
			t.buf.Write(p[:n])
		}
	}
	if err == io.EOF && !t.done {
		t.done = true
		t.entry.Body = append([]byte(nil), t.buf.Bytes()...)
		t.cache.store.put(t.entry)
		t.cache.stored.Add(1)
	} else if err != nil && err != io.EOF {
		t.done = true
	}
	return n, err
}

// sendCached is send with the session's cache in front of it: a fresh entry
// answers without the network; one that has validators goes out as a
// conditional request, and a 304 answers from the entry; a new response that
// may be stored is stored as its body is read.
func (s *Session) sendCached(r *Request, deadline time.Time) (*http.Response, context.CancelFunc, *conn, error) {
	if !s.cacheable(r) {
		if r.cacheMode() == CacheNoCache && !r.preflight {
			// A reload says so whether or not anything is stored: the
			// header goes out from the profile's slot all the same.
			reload := *r
			reload.reloadCacheControl = "max-age=0"
			return s.send(&reload, deadline)
		}
		return s.send(r, deadline)
	}
	u, err := parseURL(r.URL)
	if err != nil {
		return s.send(r, deadline)
	}
	c := s.cache
	mode := r.cacheMode()
	key := s.cacheKey(r, u)
	entry := c.store.get(key)
	if entry != nil && entry.Vary != nil && !sameVary(entry.Vary, s.varyValues(r, u, entry.Header)) {
		entry = nil
	}
	now := time.Now()
	switch {
	case entry != nil && (mode == CacheForceCache || mode == CacheOnlyIfCached):
		c.hits.Add(1)
		return entry.response(CacheHit), nil, nil, nil
	case mode == CacheOnlyIfCached:
		// fetch() rejects here; a 504 is what the standard's cache answers.
		return &http.Response{Status: "504 Gateway Timeout", StatusCode: http.StatusGatewayTimeout,
			Proto: "HTTP/1.1", Header: http.Header{}, Body: cachedBody{bytes.NewReader(nil), CacheMiss}}, nil, nil, nil
	case entry != nil && mode == CacheDefault && entry.fresh(now):
		c.hits.Add(1)
		return entry.response(CacheHit), nil, nil, nil
	}

	cond := *r
	conditional := false
	if entry != nil {
		cond.condETag, cond.condLastModified = entry.etag(), entry.lastModified()
		conditional = cond.condETag != "" || cond.condLastModified != ""
	}
	if mode == CacheNoCache {
		// A reload's document: Chrome adds cache-control: max-age=0, and the
		// slot is only in the profiles of the browsers that send it.
		cond.reloadCacheControl = "max-age=0"
	}
	started := time.Now()
	resp, cancel, used, err := s.send(&cond, deadline)
	if err != nil {
		return nil, nil, nil, err
	}
	if resp.StatusCode == http.StatusNotModified && conditional {
		drain(resp, cancel)
		s.release(used)
		fresh := *entry
		fresh.Header = make(map[string][]string, len(entry.Header))
		for k, vs := range entry.Header {
			fresh.Header[k] = vs
		}
		// RFC 9111 4.3.4: the 304's headers replace the stored ones, all but
		// the ones that describe the body.
		for k, vs := range resp.Header {
			switch strings.ToLower(k) {
			case "content-length", "content-encoding", "transfer-encoding", "content-range":
				continue
			}
			for sk := range fresh.Header {
				if strings.EqualFold(sk, k) {
					delete(fresh.Header, sk)
				}
			}
			fresh.Header[k] = vs
		}
		fresh.RequestTime, fresh.ResponseTime = started, time.Now()
		c.store.put(&fresh)
		c.revalid.Add(1)
		return fresh.response(CacheRevalidated), nil, nil, nil
	}
	c.misses.Add(1)
	if storable(resp) && !parseCacheControl(r.headerMap()).has("no-store") {
		e := &cacheEntry{
			Key: key, URL: u.String(), Status: resp.StatusCode, Proto: resp.Proto,
			Header:      map[string][]string(resp.Header.Clone()),
			RequestTime: started, ResponseTime: time.Now(),
		}
		e.Vary = s.varyValues(r, u, e.Header)
		resp.Body = &teeBody{ReadCloser: resp.Body, cache: c, entry: e}
	} else {
		if entry != nil && parseCacheControl(resp.Header).has("no-store") {
			c.store.remove(key)
		}
		resp.Body = missBody{resp.Body}
	}
	return resp, cancel, used, nil
}

// headerMap is the request's own headers as a header map, for the checks that
// read them like a response's.
func (r *Request) headerMap() map[string][]string {
	out := make(map[string][]string, len(r.Headers))
	for k, v := range r.Headers {
		out[k] = []string{v}
	}
	return out
}
