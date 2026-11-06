//! Rust binding of libcurlpro: an HTTP client that sends a real browser's
//! network fingerprint — TLS ClientHello, HTTP/2 and HTTP/3 settings, header
//! order. The contract is docs/C-ABI.md in the curlpro repository.
//!
//! ```no_run
//! let s = curlpro::Session::new("chrome-157-windows")?;
//! let r = s.get("https://example.com/")?;
//! println!("{} {} {} bytes", r.status, r.proto, r.body.len());
//! # Ok::<(), curlpro::Error>(())
//! ```
//!
//! The calls block. In async code run them with `spawn_blocking`: requests on
//! one session run in parallel.

use std::collections::BTreeMap;
use std::ffi::{c_char, c_int, c_longlong, CStr, CString};
use std::fmt;
use std::io;
use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};

/// The ABI this binding was written against; an older library is refused.
pub const REQUIRED: (u32, u32) = (0, 30);

const FRAME_HEADER: usize = 4;
const DEFAULT_PROFILE: &str = "chrome-157-windows";

// ---- errors -------------------------------------------------------------------------

/// An error the library reported. Branch on `code`, not on the message.
#[derive(Debug, Clone)]
pub struct Error {
    pub message: String,
    /// timeout, proxy, proxy_auth, proxy_closed, configuration, profile_capability,
    /// cors, too_large, session_closed, ws_closed, ws_too_big, ws_protocol — or None.
    pub code: Option<String>,
    /// proxy/proxy_auth: {stage, status}; cors: {method, url, reason, status, headers}.
    pub details: Option<Value>,
}

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Error { message: message.into(), code: None, details: None }
    }

    /// Retrying the same call cannot change the outcome.
    pub fn permanent(&self) -> bool {
        matches!(self.code.as_deref(), Some("configuration" | "profile_capability" | "proxy_auth"))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.code {
            Some(c) => write!(f, "{} [{}]", self.message, c),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

// ---- the library ------------------------------------------------------------------------

type Handle = c_longlong;
type FnFree = unsafe extern "C" fn(*mut c_char);
type FnS0 = unsafe extern "C" fn() -> *mut c_char;
type FnS1 = unsafe extern "C" fn(*const c_char) -> *mut c_char;
type FnS2 = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char;
type FnH = unsafe extern "C" fn(Handle) -> *mut c_char;
type FnHS = unsafe extern "C" fn(Handle, *const c_char) -> *mut c_char;
type FnHSS = unsafe extern "C" fn(Handle, *const c_char, *const c_char) -> *mut c_char;
type FnFrame = unsafe extern "C" fn(Handle, *const c_char, c_int, *mut c_int) -> *mut c_char;
type FnRead = unsafe extern "C" fn(Handle, *mut c_char, c_int) -> c_int;
type FnRecv = unsafe extern "C" fn(Handle, *mut c_int) -> *mut c_char;
type FnWsClose = unsafe extern "C" fn(Handle, c_int, *const c_char) -> *mut c_char;

struct Api {
    // Never dropped: a Go runtime cannot be unloaded.
    _lib: ManuallyDrop<libloading::Library>,
    free: FnFree,
    #[allow(dead_code)] // called once, in load()
    version: FnS0,
    profiles_load_dir: FnS1,
    profiles_load_bundle: FnS2,
    profile_register: FnS1,
    profiles_list: FnS0,
    profile_capabilities: FnS1,
    profile_get: FnS1,
    session_new: FnS1,
    session_close: FnH,
    session_fingerprint: FnHS,
    session_preview: FnHS,
    session_set_header: FnHSS,
    session_remove_header: FnHS,
    session_suppress_header: FnHS,
    session_reset_headers: FnH,
    session_set_page: FnHS,
    session_cookies: FnH,
    session_set_cookies: FnHS,
    session_clear_cookies: FnH,
    request: FnFrame,
    stream_open: FnFrame,
    stream_read: FnRead,
    stream_error: FnH,
    stream_close: FnH,
    ws_connect: FnHS,
    ws_send: FnFrame,
    ws_recv: FnRecv,
    ws_close: FnWsClose,
    debug_counts: FnS0,
    version_string: String,
}

static API: OnceLock<std::result::Result<Api, Error>> = OnceLock::new();

fn api() -> Result<&'static Api> {
    API.get_or_init(load).as_ref().map_err(Clone::clone)
}

/// CURLPRO_LIBRARY, else next to the executable (where a release archive puts
/// it), else the platform's file name through the loader's search path.
fn library_path() -> PathBuf {
    if let Some(p) = std::env::var_os("CURLPRO_LIBRARY").filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    let file = libloading::library_filename("curlpro");
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) {
        let local = dir.join(&file);
        if local.exists() {
            return local;
        }
    }
    PathBuf::from(file)
}

fn load() -> Result<Api> {
    let path = library_path();
    // SAFETY: loading libcurlpro runs the Go runtime's initialisers and nothing else.
    let lib = unsafe { libloading::Library::new(&path) }
        .map_err(|e| Error::new(format!("loading {}: {e}", path.display())))?;
    // Not even on the error paths below: unloading a Go runtime crashes the process.
    let lib = ManuallyDrop::new(lib);

    macro_rules! sym {
        ($ty:ty, $name:literal) => {{
            // SAFETY: the signature is the one include/curlpro.h declares.
            let s = unsafe { lib.get::<$ty>(concat!($name, "\0").as_bytes()) }
                .map_err(|e| Error::new(format!("libcurlpro has no {}: {e}", $name)))?;
            *s
        }};
    }

    let free = sym!(FnFree, "curlpro_free");
    let version = sym!(FnS0, "curlpro_version");
    let profiles_load_dir = sym!(FnS1, "curlpro_profiles_load_dir");
    let profiles_load_bundle = sym!(FnS2, "curlpro_profiles_load_bundle");
    let profile_register = sym!(FnS1, "curlpro_profile_register");
    let profiles_list = sym!(FnS0, "curlpro_profiles_list");
    let profile_capabilities = sym!(FnS1, "curlpro_profile_capabilities");
    let profile_get = sym!(FnS1, "curlpro_profile_get");
    let session_new = sym!(FnS1, "curlpro_session_new");
    let session_close = sym!(FnH, "curlpro_session_close");
    let session_fingerprint = sym!(FnHS, "curlpro_session_fingerprint");
    let session_preview = sym!(FnHS, "curlpro_session_preview");
    let session_set_header = sym!(FnHSS, "curlpro_session_set_header");
    let session_remove_header = sym!(FnHS, "curlpro_session_remove_header");
    let session_suppress_header = sym!(FnHS, "curlpro_session_suppress_header");
    let session_reset_headers = sym!(FnH, "curlpro_session_reset_headers");
    let session_set_page = sym!(FnHS, "curlpro_session_set_page");
    let session_cookies = sym!(FnH, "curlpro_session_cookies");
    let session_set_cookies = sym!(FnHS, "curlpro_session_set_cookies");
    let session_clear_cookies = sym!(FnH, "curlpro_session_clear_cookies");
    let request = sym!(FnFrame, "curlpro_request");
    let stream_open = sym!(FnFrame, "curlpro_stream_open");
    let stream_read = sym!(FnRead, "curlpro_stream_read");
    let stream_error = sym!(FnH, "curlpro_stream_error");
    let stream_close = sym!(FnH, "curlpro_stream_close");
    let ws_connect = sym!(FnHS, "curlpro_ws_connect");
    let ws_send = sym!(FnFrame, "curlpro_ws_send");
    let ws_recv = sym!(FnRecv, "curlpro_ws_recv");
    let ws_close = sym!(FnWsClose, "curlpro_ws_close");
    let debug_counts = sym!(FnS0, "curlpro_debug_counts");

    // SAFETY: curlpro_version takes nothing and returns an envelope we own.
    let data = unwrap(parse(&unsafe { take_string(free, version()) }?)?)?;
    let v = data["version"].as_str().unwrap_or("0.0.0").to_string();
    let mut parts = v.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let got = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    if got < REQUIRED {
        return Err(Error::new(format!(
            "libcurlpro {v} is older than the required {}.{}.x: it would silently ignore options",
            REQUIRED.0, REQUIRED.1
        )));
    }

    Ok(Api {
        _lib: lib,
        free,
        version,
        profiles_load_dir,
        profiles_load_bundle,
        profile_register,
        profiles_list,
        profile_capabilities,
        profile_get,
        session_new,
        session_close,
        session_fingerprint,
        session_preview,
        session_set_header,
        session_remove_header,
        session_suppress_header,
        session_reset_headers,
        session_set_page,
        session_cookies,
        session_set_cookies,
        session_clear_cookies,
        request,
        stream_open,
        stream_read,
        stream_error,
        stream_close,
        ws_connect,
        ws_send,
        ws_recv,
        ws_close,
        debug_counts,
        version_string: v,
    })
}

/// The library's version, loading and checking it on first use.
pub fn version() -> Result<String> {
    Ok(api()?.version_string.clone())
}

/// Sessions, streams, sockets and pending calls still registered: for leak tests.
pub fn debug_counts() -> Result<Value> {
    let a = api()?;
    envelope(a, unsafe { (a.debug_counts)() })
}

// ---- envelopes and frames -------------------------------------------------------------------

/// SAFETY: p is NULL or a NUL-terminated string the library returned.
unsafe fn take_string(free: FnFree, p: *mut c_char) -> Result<String> {
    if p.is_null() {
        return Err(Error::new("the library returned nothing (out of memory?)"));
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    free(p);
    Ok(s)
}

fn parse(s: &str) -> Result<Value> {
    serde_json::from_str(s).map_err(|e| Error::new(format!("bad JSON from the library: {e}")))
}

fn unwrap(env: Value) -> Result<Value> {
    if env.get("ok").and_then(Value::as_bool) == Some(true) {
        return Ok(env.get("data").cloned().unwrap_or(Value::Null));
    }
    Err(Error {
        message: env.get("error").and_then(Value::as_str).unwrap_or("unknown error").to_string(),
        code: env.get("code").and_then(Value::as_str).map(str::to_string),
        details: env.get("details").filter(|d| !d.is_null()).cloned(),
    })
}

/// Takes ownership of an envelope, frees it, returns data or the error.
fn envelope(a: &Api, p: *mut c_char) -> Result<Value> {
    // SAFETY: every envelope-returning export gives a NUL-terminated string.
    unwrap(parse(&unsafe { take_string(a.free, p) }?)?)
}

/// Takes ownership of a frame, frees it, splits it into data and body.
fn frame(a: &Api, p: *mut c_char, len: c_int) -> Result<(Value, Vec<u8>)> {
    if p.is_null() {
        return Err(Error::new("the library returned nothing (out of memory?)"));
    }
    // SAFETY: the library wrote len bytes at p; they are copied before freeing.
    let bytes = unsafe { std::slice::from_raw_parts(p as *const u8, len.max(0) as usize) }.to_vec();
    unsafe { (a.free)(p) };
    if bytes.len() < FRAME_HEADER {
        return Err(Error::new(format!("frame shorter than its header: {} bytes", bytes.len())));
    }
    let n = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let end = FRAME_HEADER + n;
    if end > bytes.len() {
        return Err(Error::new("frame JSON runs past the frame"));
    }
    let env: Value = serde_json::from_slice(&bytes[FRAME_HEADER..end])
        .map_err(|e| Error::new(format!("bad JSON from the library: {e}")))?;
    Ok((unwrap(env)?, bytes[end..].to_vec()))
}

fn make_frame(meta: &Value, body: &[u8]) -> Vec<u8> {
    let json = serde_json::to_vec(meta).expect("a JSON value always serialises");
    let mut f = Vec::with_capacity(FRAME_HEADER + json.len() + body.len());
    f.extend_from_slice(&(json.len() as u32).to_le_bytes());
    f.extend_from_slice(&json);
    f.extend_from_slice(body);
    f
}

fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::new("a string argument contains a NUL byte"))
}

fn call_frame(a: &Api, f: FnFrame, handle: Handle, frame_bytes: &[u8]) -> Result<(Value, Vec<u8>)> {
    if frame_bytes.len() > i32::MAX as usize {
        return Err(Error { message: "request larger than 2 GiB".into(), code: Some("too_large".into()), details: None });
    }
    let mut out: c_int = 0;
    // SAFETY: the frame outlives the call; out receives the returned length.
    let p = unsafe { f(handle, frame_bytes.as_ptr() as *const c_char, frame_bytes.len() as c_int, &mut out) };
    frame(a, p, out)
}

// ---- profiles -----------------------------------------------------------------------------------

/// The process-wide profile registry. It starts empty.
pub mod profiles {
    use super::*;

    fn names(v: Value) -> Vec<String> {
        v.get("profiles")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|n| n.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    }

    /// Loads every *.json profile under a directory.
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<Vec<String>> {
        let a = api()?;
        let d = cstr(&dir.as_ref().to_string_lossy())?;
        Ok(names(envelope(a, unsafe { (a.profiles_load_dir)(d.as_ptr()) })?))
    }

    /// Loads a signed bundle (profiles.json.gz + .sig); keys: extra base64 Ed25519 keys, comma-separated.
    pub fn load_bundle(path: impl AsRef<Path>, keys: Option<&str>) -> Result<Value> {
        let a = api()?;
        let p = cstr(&path.as_ref().to_string_lossy())?;
        let env_keys = std::env::var("CURLPRO_BUNDLE_KEYS").unwrap_or_default();
        let k = cstr(keys.unwrap_or(&env_keys))?;
        envelope(a, unsafe { (a.profiles_load_bundle)(p.as_ptr(), k.as_ptr()) })
    }

    /// Registers one profile from JSON; it may be `based_on` a registered one
    /// (the stock profiles are loaded first, as for a session).
    pub fn register(profile_json: &str) -> Result<Vec<String>> {
        let a = api()?;
        ensure_loaded()?;
        let j = cstr(profile_json)?;
        Ok(names(envelope(a, unsafe { (a.profile_register)(j.as_ptr()) })?))
    }

    pub fn list() -> Result<Vec<String>> {
        let a = api()?;
        Ok(names(envelope(a, unsafe { (a.profiles_list)() })?))
    }

    /// The profile with inheritance resolved.
    pub fn get(name: &str) -> Result<Value> {
        let a = api()?;
        ensure_loaded()?;
        let n = cstr(name)?;
        envelope(a, unsafe { (a.profile_get)(n.as_ptr()) })
    }

    /// What the profile can do, without opening a session.
    pub fn capabilities(name: &str) -> Result<Value> {
        let a = api()?;
        ensure_loaded()?;
        let n = cstr(name)?;
        envelope(a, unsafe { (a.profile_capabilities)(n.as_ptr()) })
    }

    static AUTOLOADED: Mutex<bool> = Mutex::new(false);

    /// Loads profiles once when the registry is empty: CURLPRO_PROFILES, else
    /// ./profiles; then the signed bundle the Python package caches.
    pub fn ensure_loaded() -> Result<()> {
        let mut done = AUTOLOADED.lock().unwrap_or_else(|e| e.into_inner());
        if *done {
            return Ok(());
        }
        *done = true;
        if !list()?.is_empty() {
            return Ok(());
        }
        let dir = std::env::var_os("CURLPRO_PROFILES").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("profiles"));
        if dir.is_dir() {
            load_dir(&dir)?;
        }
        let bundle = cache_dir().join("profiles.json.gz");
        if bundle.exists() && bundle.with_extension("gz.sig").exists() {
            let _ = load_bundle(&bundle, None); // a stale bundle: the directory is enough
        }
        Ok(())
    }

    fn cache_dir() -> PathBuf {
        if let Some(d) = std::env::var_os("CURLPRO_CACHE_DIR") {
            return PathBuf::from(d);
        }
        let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).unwrap_or_default();
        if cfg!(windows) {
            std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|| home.join("AppData").join("Local")).join("curlpro")
        } else if cfg!(target_os = "macos") {
            home.join("Library").join("Caches").join("curlpro")
        } else {
            std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".cache")).join("curlpro")
        }
    }
}

// ---- session --------------------------------------------------------------------------------------

/// Session settings. The defaults are the browser's, as in the Python Session;
/// the ABI's own zero values are not (a missing boolean is false there).
#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub profile: String,
    pub timeout: Duration,
    pub proxy: Option<String>,
    pub http3: bool,
    pub follow_redirects: bool,
    pub cookies: bool,
    /// "navigate", "fetch" or None (auto).
    pub mode: Option<String>,
    /// Any other session field of docs/C-ABI.md, sent as is.
    pub extra: Map<String, Value>,
}

impl Default for SessionOptions {
    fn default() -> Self {
        SessionOptions {
            profile: DEFAULT_PROFILE.into(),
            timeout: Duration::from_secs(30),
            proxy: None,
            http3: false,
            follow_redirects: true,
            cookies: true,
            mode: None,
            extra: Map::new(),
        }
    }
}

impl SessionOptions {
    fn to_json(&self) -> Value {
        let mut o = json!({
            "profile": self.profile,
            "timeout_ms": self.timeout.as_millis() as u64,
            "default_headers": true,
            "follow_redirects": self.follow_redirects,
            "max_redirects": 20,
            "cookies": self.cookies,
            "resume": true,
            "trust_env": true,
            "http3": self.http3,
        });
        if let Some(p) = &self.proxy {
            o["proxy"] = json!(p);
        }
        if let Some(m) = &self.mode {
            o["mode"] = json!(m);
        }
        for (k, v) in &self.extra {
            o[k.as_str()] = v.clone();
        }
        o
    }
}

/// One request. Headers are merged into the profile's and sent in its order.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Any other request field of docs/C-ABI.md ("timeout_ms", "protocol", "proxy"…), sent as is.
    pub extra: Map<String, Value>,
}

impl Request {
    pub fn new(method: &str, url: &str) -> Self {
        Request { method: method.into(), url: url.into(), headers: Vec::new(), body: Vec::new(), extra: Map::new() }
    }

    pub fn get(url: &str) -> Self {
        Self::new("GET", url)
    }

    pub fn post(url: &str) -> Self {
        Self::new("POST", url)
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub fn set(mut self, field: &str, value: Value) -> Self {
        self.extra.insert(field.into(), value);
        self
    }

    fn to_frame(&self) -> Vec<u8> {
        let mut meta = Map::new();
        meta.insert("method".into(), json!(self.method));
        meta.insert("url".into(), json!(self.url));
        if !self.headers.is_empty() {
            let h: Map<String, Value> = self.headers.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
            meta.insert("headers".into(), Value::Object(h));
        }
        for (k, v) in &self.extra {
            meta.insert(k.clone(), v.clone());
        }
        make_frame(&Value::Object(meta), &self.body)
    }
}

/// A response with its body read whole (already decompressed).
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    /// "HTTP/1.1", "HTTP/2.0" or "HTTP/3.0".
    pub proto: String,
    /// The final URL, after redirects.
    pub url: String,
    /// Lower-case names; repeated headers keep every value.
    pub headers: BTreeMap<String, Vec<String>>,
    pub body: Vec<u8>,
    /// history, preflights, cache, cookie_changes: everything the library reported.
    pub raw: Value,
}

impl Response {
    fn from_parts(data: Value, body: Vec<u8>) -> Self {
        let mut headers = BTreeMap::new();
        if let Some(h) = data.get("headers").and_then(Value::as_object) {
            for (k, v) in h {
                let vals = v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
                headers.insert(k.to_ascii_lowercase(), vals);
            }
        }
        Response {
            status: data.get("status").and_then(Value::as_u64).unwrap_or(0) as u16,
            proto: data.get("proto").and_then(Value::as_str).unwrap_or("").to_string(),
            url: data.get("url").and_then(Value::as_str).unwrap_or("").to_string(),
            headers,
            body,
            raw: data,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).and_then(|v| v.first()).map(String::as_str)
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|e| Error::new(format!("the body is not that JSON: {e}")))
    }
}

/// One browser: its TLS/HTTP fingerprint, connection pool, cookies and headers.
/// Send + Sync: requests on one session run in parallel. Closed on drop.
#[derive(Debug)]
pub struct Session {
    id: Handle,
    pub profile: String,
}

impl Session {
    pub fn new(profile: &str) -> Result<Self> {
        Self::with_options(SessionOptions { profile: profile.into(), ..Default::default() })
    }

    pub fn with_options(options: SessionOptions) -> Result<Self> {
        let a = api()?;
        profiles::ensure_loaded()?;
        let cfg = cstr(&options.to_json().to_string())?;
        let data = envelope(a, unsafe { (a.session_new)(cfg.as_ptr()) })?;
        let id = data.get("session").and_then(Value::as_i64).ok_or_else(|| Error::new("session_new returned no handle"))?;
        Ok(Session { id, profile: options.profile })
    }

    /// Sends a request and blocks until the whole response is in.
    pub fn send(&self, request: &Request) -> Result<Response> {
        let a = api()?;
        let (data, body) = call_frame(a, a.request, self.id, &request.to_frame())?;
        Ok(Response::from_parts(data, body))
    }

    pub fn get(&self, url: &str) -> Result<Response> {
        self.send(&Request::get(url))
    }

    pub fn post(&self, url: &str, content_type: &str, body: impl Into<Vec<u8>>) -> Result<Response> {
        self.send(&Request::post(url).header("content-type", content_type).body(body))
    }

    /// Opens a response as a stream (std::io::Read); returns once the headers are in.
    pub fn stream(&self, request: &Request) -> Result<ResponseStream> {
        let a = api()?;
        let (data, _) = call_frame(a, a.stream_open, self.id, &request.to_frame())?;
        let id = data.get("stream").and_then(Value::as_i64).ok_or_else(|| Error::new("no stream handle"))?;
        Ok(ResponseStream { id, head: Response::from_parts(data, Vec::new()) })
    }

    /// A WebSocket whose upgrade carries the profile's fingerprint.
    pub fn websocket(&self, url: &str, headers: &[(&str, &str)]) -> Result<WebSocket> {
        let a = api()?;
        let h: Map<String, Value> = headers.iter().map(|(k, v)| (k.to_string(), json!(v))).collect();
        let cfg = cstr(&json!({ "url": url, "headers": h }).to_string())?;
        let data = envelope(a, unsafe { (a.ws_connect)(self.id, cfg.as_ptr()) })?;
        let id = data.get("socket").and_then(Value::as_i64).ok_or_else(|| Error::new("no socket handle"))?;
        Ok(WebSocket { id })
    }

    /// ja3, ja3n, ja4, akamai… for this URL, computed without sending anything.
    pub fn fingerprint(&self, url: &str) -> Result<Value> {
        let a = api()?;
        let u = cstr(url)?;
        envelope(a, unsafe { (a.session_fingerprint)(self.id, u.as_ptr()) })
    }

    /// The headers a request would carry, in order, without sending it.
    pub fn preview(&self, method: &str, url: &str) -> Result<Value> {
        let a = api()?;
        let spec = cstr(&json!({ "method": method, "url": url }).to_string())?;
        envelope(a, unsafe { (a.session_preview)(self.id, spec.as_ptr()) })
    }

    pub fn set_header(&self, name: &str, value: &str) -> Result<()> {
        let a = api()?;
        let (n, v) = (cstr(name)?, cstr(value)?);
        envelope(a, unsafe { (a.session_set_header)(self.id, n.as_ptr(), v.as_ptr()) }).map(|_| ())
    }

    pub fn remove_header(&self, name: &str) -> Result<bool> {
        let a = api()?;
        let n = cstr(name)?;
        let d = envelope(a, unsafe { (a.session_remove_header)(self.id, n.as_ptr()) })?;
        Ok(d.get("removed").and_then(Value::as_bool).unwrap_or(false))
    }

    /// Never send this header, even when the profile would.
    pub fn suppress_header(&self, name: &str) -> Result<()> {
        let a = api()?;
        let n = cstr(name)?;
        envelope(a, unsafe { (a.session_suppress_header)(self.id, n.as_ptr()) }).map(|_| ())
    }

    pub fn reset_headers(&self) -> Result<()> {
        let a = api()?;
        envelope(a, unsafe { (a.session_reset_headers)(self.id) }).map(|_| ())
    }

    pub fn set_page(&self, url: &str) -> Result<()> {
        let a = api()?;
        let u = cstr(url)?;
        envelope(a, unsafe { (a.session_set_page)(self.id, u.as_ptr()) }).map(|_| ())
    }

    pub fn cookies(&self) -> Result<Value> {
        let a = api()?;
        Ok(envelope(a, unsafe { (a.session_cookies)(self.id) })?.get("cookies").cloned().unwrap_or(Value::Array(vec![])))
    }

    pub fn set_cookies(&self, cookies: &Value) -> Result<()> {
        let a = api()?;
        let c = cstr(&cookies.to_string())?;
        envelope(a, unsafe { (a.session_set_cookies)(self.id, c.as_ptr()) }).map(|_| ())
    }

    pub fn clear_cookies(&self) -> Result<()> {
        let a = api()?;
        envelope(a, unsafe { (a.session_clear_cookies)(self.id) }).map(|_| ())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Ok(a) = api() {
            let _ = envelope(a, unsafe { (a.session_close)(self.id) });
        }
    }
}

/// A response body read in pieces. Closed on drop.
#[derive(Debug)]
pub struct ResponseStream {
    id: Handle,
    /// Status, proto, url and headers; its body is empty.
    pub head: Response,
}

impl io::Read for ResponseStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let a = api().map_err(io::Error::other)?;
        let len = buf.len().min(i32::MAX as usize) as c_int;
        // SAFETY: buf is writable for len bytes.
        let n = unsafe { (a.stream_read)(self.id, buf.as_mut_ptr() as *mut c_char, len) };
        if n < 0 {
            let e = envelope(a, unsafe { (a.stream_error)(self.id) }).err().unwrap_or_else(|| Error::new("stream read failed"));
            return Err(io::Error::other(e));
        }
        Ok(n as usize)
    }
}

impl Drop for ResponseStream {
    fn drop(&mut self) {
        if let Ok(a) = api() {
            let _ = envelope(a, unsafe { (a.stream_close)(self.id) });
        }
    }
}

/// One WebSocket message.
#[derive(Debug, Clone)]
pub struct Message {
    pub binary: bool,
    pub data: Vec<u8>,
}

impl Message {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }
}

/// A WebSocket whose upgrade carried the profile's fingerprint. Closed on drop.
#[derive(Debug)]
pub struct WebSocket {
    id: Handle,
}

impl WebSocket {
    pub fn send_text(&self, text: &str) -> Result<()> {
        self.send(false, false, text.as_bytes())
    }

    pub fn send_binary(&self, data: &[u8]) -> Result<()> {
        self.send(true, false, data)
    }

    pub fn ping(&self, data: &[u8]) -> Result<()> {
        self.send(false, true, data)
    }

    fn send(&self, binary: bool, ping: bool, payload: &[u8]) -> Result<()> {
        let a = api()?;
        call_frame(a, a.ws_send, self.id, &make_frame(&json!({ "binary": binary, "ping": ping }), payload)).map(|_| ())
    }

    /// Blocks for the next message; an Error with code "ws_closed" once closed.
    pub fn receive(&self) -> Result<Message> {
        let a = api()?;
        let mut out: c_int = 0;
        let p = unsafe { (a.ws_recv)(self.id, &mut out) };
        let (data, body) = frame(a, p, out)?;
        Ok(Message { binary: data.get("binary").and_then(Value::as_bool).unwrap_or(false), data: body })
    }

    pub fn close(self, code: i32, reason: &str) -> Result<()> {
        let a = api()?;
        let r = cstr(reason)?;
        let res = envelope(a, unsafe { (a.ws_close)(self.id, code, r.as_ptr()) }).map(|_| ());
        std::mem::forget(self); // already closed
        res
    }
}

impl Drop for WebSocket {
    fn drop(&mut self) {
        if let Ok(a) = api() {
            let _ = envelope(a, unsafe { (a.ws_close)(self.id, 1000, b"\0".as_ptr() as *const c_char) });
        }
    }
}
