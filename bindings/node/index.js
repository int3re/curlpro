'use strict';
// Node.js binding of libcurlpro over koffi. The contract is docs/C-ABI.md.
//
// Blocking calls (session.request) hold the JS thread for the whole request;
// they are there for scripts. Servers use the async ones (requestAsync, get,
// post…): the work runs inside the library and one koffi worker waits on
// curlpro_result_wait for every call in flight in the process.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const koffi = require('koffi');

const REQUIRED = [0, 30];
const FRAME_HEADER = 4;
const DEFAULT_PROFILE = 'chrome-157-windows';

class CurlproError extends Error {
  /**
   * @param {string} message
   * @param {string|null} code   timeout, proxy, proxy_auth, configuration, … (docs/C-ABI.md)
   * @param {object|null} details
   */
  constructor(message, code = null, details = null) {
    super(message);
    this.name = 'CurlproError';
    this.code = code;
    this.details = details;
  }

  /** Retrying the same call cannot change the outcome. */
  get permanent() {
    return ['configuration', 'profile_capability', 'proxy_auth'].includes(this.code);
  }
}

// ---- loading -------------------------------------------------------------------

function libraryFile() {
  return process.platform === 'win32' ? 'curlpro.dll'
    : process.platform === 'darwin' ? 'libcurlpro.dylib' : 'libcurlpro.so';
}

function findLibrary() {
  if (process.env.CURLPRO_LIBRARY) return process.env.CURLPRO_LIBRARY;
  const local = path.join(__dirname, 'lib', libraryFile());
  if (fs.existsSync(local)) return local;
  // The published package depends on @curlpro/<platform>-<arch> optionally:
  // npm installs only the one matching this machine.
  try {
    const pkg = path.dirname(require.resolve('@curlpro/' + process.platform + '-' + process.arch + '/package.json'));
    const file = path.join(pkg, 'lib', libraryFile());
    if (fs.existsSync(file)) return file;
  } catch { /* not installed: a source checkout */ }
  return libraryFile(); // the system loader's search path
}

let native = null;

function lib() {
  if (native) return native;
  const l = koffi.load(findLibrary());
  const f = (proto) => l.func(proto);
  const n = {
    free: f('void curlpro_free(void *s)'),
    version: f('void *curlpro_version()'),
    profiles_load_dir: f('void *curlpro_profiles_load_dir(const char *dir)'),
    profiles_load_bundle: f('void *curlpro_profiles_load_bundle(const char *path, const char *keys)'),
    profile_register: f('void *curlpro_profile_register(const char *json)'),
    profiles_list: f('void *curlpro_profiles_list()'),
    profile_capabilities: f('void *curlpro_profile_capabilities(const char *name)'),
    profile_get: f('void *curlpro_profile_get(const char *name)'),
    session_new: f('void *curlpro_session_new(const char *config)'),
    session_close: f('void *curlpro_session_close(int64_t s)'),
    session_fingerprint: f('void *curlpro_session_fingerprint(int64_t s, const char *url)'),
    session_preview: f('void *curlpro_session_preview(int64_t s, const char *spec)'),
    session_set_header: f('void *curlpro_session_set_header(int64_t s, const char *name, const char *value)'),
    session_remove_header: f('void *curlpro_session_remove_header(int64_t s, const char *name)'),
    session_suppress_header: f('void *curlpro_session_suppress_header(int64_t s, const char *name)'),
    session_reset_headers: f('void *curlpro_session_reset_headers(int64_t s)'),
    session_headers: f('void *curlpro_session_headers(int64_t s)'),
    session_set_page: f('void *curlpro_session_set_page(int64_t s, const char *url)'),
    session_set_top_level: f('void *curlpro_session_set_top_level(int64_t s, const char *url)'),
    session_cookies: f('void *curlpro_session_cookies(int64_t s)'),
    session_set_cookies: f('void *curlpro_session_set_cookies(int64_t s, const char *json)'),
    session_clear_cookies: f('void *curlpro_session_clear_cookies(int64_t s)'),
    session_cache_info: f('void *curlpro_session_cache_info(int64_t s)'),
    session_clear_cache: f('void *curlpro_session_clear_cache(int64_t s)'),
    request: f('void *curlpro_request(int64_t s, const uint8_t *frame, int len, _Out_ int *out_len)'),
    stream_open: f('void *curlpro_stream_open(int64_t s, const uint8_t *frame, int len, _Out_ int *out_len)'),
    stream_read: f('int curlpro_stream_read(int64_t st, _Out_ uint8_t *buf, int len)'),
    stream_error: f('void *curlpro_stream_error(int64_t st)'),
    stream_close: f('void *curlpro_stream_close(int64_t st)'),
    ws_connect: f('void *curlpro_ws_connect(int64_t s, const char *config)'),
    ws_send: f('void *curlpro_ws_send(int64_t ws, const uint8_t *frame, int len, _Out_ int *out_len)'),
    ws_recv: f('void *curlpro_ws_recv(int64_t ws, _Out_ int *out_len)'),
    ws_close: f('void *curlpro_ws_close(int64_t ws, int code, const char *reason)'),
    request_start: f('void *curlpro_request_start(int64_t s, const uint8_t *frame, int len)'),
    stream_open_start: f('void *curlpro_stream_open_start(int64_t s, const uint8_t *frame, int len)'),
    stream_read_start: f('void *curlpro_stream_read_start(int64_t st, int len)'),
    ws_connect_start: f('void *curlpro_ws_connect_start(int64_t s, const char *config)'),
    ws_send_start: f('void *curlpro_ws_send_start(int64_t ws, const uint8_t *frame, int len)'),
    ws_recv_start: f('void *curlpro_ws_recv_start(int64_t ws)'),
    result_wait: f('int64_t curlpro_result_wait(int timeout_ms)'),
    result_take: f('void *curlpro_result_take(int64_t id, _Out_ int *out_len)'),
    request_cancel: f('void *curlpro_request_cancel(int64_t id)'),
    async_pending: f('int64_t curlpro_async_pending()'),
    debug_counts: f('void *curlpro_debug_counts()'),
  };

  const v = unwrap(JSON.parse(takeString(n, n.version()))).version;
  const [maj, min] = v.split('.').map(Number);
  if (maj < REQUIRED[0] || (maj === REQUIRED[0] && min < REQUIRED[1])) {
    throw new CurlproError(`libcurlpro ${v} is older than the required ${REQUIRED.join('.')}.x: it would silently ignore options`);
  }
  n.versionString = v;
  native = n;
  return n;
}

// ---- envelopes and frames ---------------------------------------------------------

function takeString(n, p) {
  if (!p) throw new CurlproError('the library returned nothing (out of memory?)');
  try { return koffi.decode.string(p); } finally { n.free(p); }
}

function unwrap(env) {
  if (env.ok) return env.data;
  throw new CurlproError(env.error || 'unknown error', env.code || null, env.details || null);
}

/** Takes ownership of an envelope, frees it, returns data or throws. */
function envelope(p) {
  const n = lib();
  return unwrap(JSON.parse(takeString(n, p)));
}

/** Takes ownership of a frame, frees it, returns { data, body }. */
function frame(p, len) {
  const n = lib();
  if (!p) throw new CurlproError('the library returned nothing (out of memory?)');
  try {
    const bytes = Buffer.from(koffi.decode(p, 'uint8_t', len));
    const metaLen = bytes.readUInt32LE(0);
    const env = JSON.parse(bytes.subarray(FRAME_HEADER, FRAME_HEADER + metaLen).toString('utf8'));
    return { data: unwrap(env), body: bytes.subarray(FRAME_HEADER + metaLen) };
  } finally {
    n.free(p);
  }
}

function makeFrame(meta, body) {
  const json = Buffer.from(JSON.stringify(meta), 'utf8');
  const b = body == null ? Buffer.alloc(0) : Buffer.isBuffer(body) ? body
    : typeof body === 'string' ? Buffer.from(body, 'utf8') : Buffer.from(body);
  const head = Buffer.alloc(FRAME_HEADER);
  head.writeUInt32LE(json.length, 0);
  return Buffer.concat([head, json, b]);
}

function callFramed(fn, ...args) {
  const out = [0];
  const p = fn(...args, out);
  return frame(p, out[0]);
}

// ---- async completions ---------------------------------------------------------------
//
// The ready queue is process-wide, so there is one waiter: a koffi async call of
// curlpro_result_wait, re-armed while anything is in flight. A call can finish
// before its id is registered (early), and a cancelled one still arrives
// (abandoned) — both are handled as in the Python binding.

const waiting = new Map();
const early = new Set();
const abandoned = new Set();
let pumping = false;

function pump() {
  if (pumping) return;
  pumping = true;
  const n = lib();
  const loop = () => {
    n.result_wait.async(250, (err, idRaw) => {
      if (err) { pumping = false; for (const w of waiting.values()) w.reject(err); waiting.clear(); return; }
      const id = Number(idRaw);
      if (id !== 0) {
        if (abandoned.delete(id)) { /* cancelled: nobody wants it */ }
        else if (waiting.has(id)) settle(id);
        else early.add(id);
      }
      if (waiting.size === 0 && Number(n.async_pending()) === 0) { pumping = false; return; }
      loop();
    });
  };
  loop();
}

function settle(id) {
  const w = waiting.get(id);
  waiting.delete(id);
  try { w.resolve(callFramed(lib().result_take, id)); } catch (e) { w.reject(e); }
}

/** Starts a call and resolves with its { data, body }. */
function runAsync(start, signal) {
  const id = Number(envelope(start()).request);
  return new Promise((resolve, reject) => {
    waiting.set(id, { resolve, reject });
    if (early.delete(id)) settle(id);
    if (signal) {
      const onAbort = () => {
        if (!waiting.delete(id)) return;
        abandoned.add(id);
        lib().free(lib().request_cancel(id));
        reject(signal.reason ?? new CurlproError('aborted'));
      };
      if (signal.aborted) onAbort(); else signal.addEventListener('abort', onAbort, { once: true });
    }
    pump();
  });
}

// ---- profiles ---------------------------------------------------------------------

function cacheDir() {
  if (process.env.CURLPRO_CACHE_DIR) return process.env.CURLPRO_CACHE_DIR;
  if (process.platform === 'win32') return path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'curlpro');
  if (process.platform === 'darwin') return path.join(os.homedir(), 'Library', 'Caches', 'curlpro');
  return path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache'), 'curlpro');
}

let autoloaded = false;

const profiles = {
  /** Loads every *.json profile under a directory. */
  loadDir: (dir) => envelope(lib().profiles_load_dir(dir)).profiles,
  /** Loads a signed bundle (profiles.json.gz + .sig). */
  loadBundle: (file, keys = process.env.CURLPRO_BUNDLE_KEYS || '') => envelope(lib().profiles_load_bundle(file, keys)),
  /** Registers one profile from a JSON string or object; it may be based_on a registered one. */
  register: (profile) => {
    profiles.ensureLoaded(); // a profile may be based_on a stock one
    return envelope(lib().profile_register(typeof profile === 'string' ? profile : JSON.stringify(profile))).profiles;
  },
  list: () => envelope(lib().profiles_list()).profiles || [],
  /** The profile with inheritance resolved. */
  get: (name) => { profiles.ensureLoaded(); return envelope(lib().profile_get(name)); },
  /** What the profile can do, without opening a session. */
  capabilities: (name) => { profiles.ensureLoaded(); return envelope(lib().profile_capabilities(name)); },
  /** CURLPRO_PROFILES or ./profiles next to the package, then the cached signed bundle — once, if the registry is empty. */
  ensureLoaded() {
    if (autoloaded) return;
    autoloaded = true;
    if (profiles.list().length > 0) return;
    const dir = process.env.CURLPRO_PROFILES || path.join(__dirname, 'profiles');
    if (fs.existsSync(dir)) profiles.loadDir(dir);
    const bundle = path.join(cacheDir(), 'profiles.json.gz');
    if (fs.existsSync(bundle) && fs.existsSync(bundle + '.sig')) {
      try { profiles.loadBundle(bundle); } catch { /* a stale bundle: the directory is enough */ }
    }
  },
};

// ---- session ------------------------------------------------------------------------

/** Browser defaults; the ABI's own zero values are not (a missing boolean is false there). */
function sessionConfig(o) {
  const cfg = {
    profile: o.profile || DEFAULT_PROFILE,
    timeout_ms: o.timeout ?? 30000,
    default_headers: o.defaultHeaders ?? true,
    follow_redirects: o.followRedirects ?? true,
    max_redirects: o.maxRedirects ?? 20,
    cookies: o.cookies ?? true,
    resume: o.resume ?? true,
    trust_env: o.trustEnv ?? true,
    http3: o.http3 ?? false,
    force_http1: o.forceHttp1 ?? false,
    insecure_skip_verify: o.insecure ?? false,
  };
  if (o.proxy != null) cfg.proxy = o.proxy;
  if (o.mode != null) cfg.mode = o.mode;
  if (o.page != null) cfg.page = o.page;
  return { ...cfg, ...(o.extra || {}) };
}

function requestMeta(method, url, o = {}) {
  const meta = { method, url };
  if (o.headers) meta.headers = o.headers;
  if (o.timeout != null) meta.timeout_ms = o.timeout;
  if (o.protocol) meta.protocol = o.protocol;
  let body = o.body;
  if (o.json !== undefined) {
    body = JSON.stringify(o.json);
    meta.headers = { 'content-type': 'application/json', ...(meta.headers || {}) };
  }
  return { meta: { ...meta, ...(o.extra || {}) }, body };
}

class Response {
  constructor(data, body) {
    this.status = data.status;
    /** "HTTP/1.1", "HTTP/2.0" or "HTTP/3.0" */
    this.proto = data.proto;
    /** The final URL, after redirects. */
    this.url = data.url;
    /** { name: [values] }, names in lower case. */
    this.headers = data.headers || {};
    /** Already decompressed. */
    this.body = body;
    /** history, preflights, cache, cookie_changes. */
    this.raw = data;
  }

  header(name) {
    const v = this.headers[name.toLowerCase()] ?? Object.entries(this.headers).find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1];
    return v ? v[0] : undefined;
  }

  text() { return this.body.toString('utf8'); }
  json() { return JSON.parse(this.text()); }
}

class Session {
  /**
   * @param {object|string} [options] profile name, or { profile, timeout (ms), proxy, http3, mode, page, extra }
   */
  constructor(options = {}) {
    if (typeof options === 'string') options = { profile: options };
    lib();
    profiles.ensureLoaded();
    this.profile = options.profile || DEFAULT_PROFILE;
    this._id = Number(envelope(lib().session_new(JSON.stringify(sessionConfig(options)))).session);
  }

  get id() {
    if (!this._id) throw new CurlproError('the session is closed', 'session_closed');
    return this._id;
  }

  /** Blocking: holds the JS thread until the response is in. */
  requestSync(method, url, options = {}) {
    const { meta, body } = requestMeta(method, url, options);
    const f = makeFrame(meta, body);
    const { data, body: out } = callFramed(lib().request, this.id, f, f.length);
    return new Response(data, out);
  }

  /** @returns {Promise<Response>} options: { headers, body, json, timeout, protocol, signal, extra } */
  async request(method, url, options = {}) {
    const { meta, body } = requestMeta(method, url, options);
    const f = makeFrame(meta, body);
    const id = this.id;
    const { data, body: out } = await runAsync(() => lib().request_start(id, f, f.length), options.signal);
    return new Response(data, out);
  }

  get(url, options) { return this.request('GET', url, options); }
  post(url, options) { return this.request('POST', url, options); }
  put(url, options) { return this.request('PUT', url, options); }
  delete(url, options) { return this.request('DELETE', url, options); }

  /** Opens a response as a stream; read it with for await. */
  async stream(method, url, options = {}) {
    const { meta, body } = requestMeta(method, url, options);
    const f = makeFrame(meta, body);
    const id = this.id;
    const { data } = await runAsync(() => lib().stream_open_start(id, f, f.length), options.signal);
    return new ResponseStream(data);
  }

  /** A WebSocket whose upgrade carries the profile's fingerprint. */
  async websocket(url, options = {}) {
    const cfg = { url, headers: options.headers, subprotocols: options.subprotocols, timeout_ms: options.timeout };
    const id = this.id;
    const { data } = await runAsync(() => lib().ws_connect_start(id, JSON.stringify(cfg)), options.signal);
    return new WebSocket(data.socket);
  }

  /** ja3, ja3n, ja4, akamai… for this URL, computed without sending anything. */
  fingerprint(url) { return envelope(lib().session_fingerprint(this.id, url)); }

  /** The headers a request would carry, in order, without sending it. */
  preview(method, url, headers) { return envelope(lib().session_preview(this.id, JSON.stringify({ method, url, headers }))); }

  setHeader(name, value) { return envelope(lib().session_set_header(this.id, name, value)); }
  removeHeader(name) { return envelope(lib().session_remove_header(this.id, name)).removed; }
  /** Never send this header, even when the profile would. */
  suppressHeader(name) { return envelope(lib().session_suppress_header(this.id, name)); }
  resetHeaders() { return envelope(lib().session_reset_headers(this.id)); }
  setPage(url) { return envelope(lib().session_set_page(this.id, url)); }
  cookies() { return envelope(lib().session_cookies(this.id)).cookies || []; }
  setCookies(list) { return envelope(lib().session_set_cookies(this.id, JSON.stringify(list))).cookies; }
  clearCookies() { envelope(lib().session_clear_cookies(this.id)); }
  cacheInfo() { return envelope(lib().session_cache_info(this.id)); }

  close() {
    const id = this._id;
    this._id = 0;
    if (id) envelope(lib().session_close(id));
  }

  [Symbol.dispose]() { this.close(); }
}

class ResponseStream {
  constructor(data) {
    this._id = Number(data.stream);
    this.status = data.status;
    this.proto = data.proto;
    this.url = data.url;
    this.headers = data.headers || {};
    this.raw = data;
  }

  /** The next chunk, or null at the end of the body. */
  async read(size = 65536) {
    if (!this._id) return null;
    const id = this._id;
    const { data, body } = await runAsync(() => lib().stream_read_start(id, size));
    return data && data.eof ? null : body;
  }

  async *[Symbol.asyncIterator]() {
    try {
      for (let chunk; (chunk = await this.read()) !== null;) yield chunk;
    } finally {
      this.close();
    }
  }

  close() {
    const id = this._id;
    this._id = 0;
    if (id) lib().free(lib().stream_close(id));
  }
}

class WebSocket {
  constructor(id) { this._id = Number(id); }

  get id() {
    if (!this._id) throw new CurlproError('the socket is closed', 'ws_closed');
    return this._id;
  }

  /** Sends a string as a text message, a Buffer as a binary one. */
  async send(message) {
    const binary = typeof message !== 'string';
    const f = makeFrame({ binary, ping: false }, message);
    const id = this.id;
    await runAsync(() => lib().ws_send_start(id, f, f.length));
  }

  /** The next message: { binary, data: Buffer, text() }. Rejects with code "ws_closed" once closed. */
  async receive() {
    const id = this.id;
    const { data, body } = await runAsync(() => lib().ws_recv_start(id));
    return { binary: !!(data && data.binary), data: body, text: () => body.toString('utf8') };
  }

  close(code = 1000, reason = '') {
    const id = this._id;
    this._id = 0;
    if (id) lib().free(lib().ws_close(id, code, reason));
  }
}

module.exports = {
  Session,
  Response,
  ResponseStream,
  WebSocket,
  CurlproError,
  profiles,
  version: () => lib().versionString,
  debugCounts: () => envelope(lib().debug_counts()),
  asyncPending: () => Number(lib().async_pending()),
};
