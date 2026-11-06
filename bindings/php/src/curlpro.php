<?php
// PHP binding of libcurlpro over FFI (PHP 8.1+, ext-ffi, ffi.enable=1 or preload).
// The contract is docs/C-ABI.md. Calls block; requests on one session may run
// in parallel from several processes or threads (ZTS).

declare(strict_types=1);

namespace Curlpro;

use FFI;

/** An error the library reported. Branch on $code, not on the message. */
class CurlproException extends \RuntimeException
{
    /**
     * @param ?string $errorCode timeout, proxy, proxy_auth, proxy_closed, configuration,
     *     profile_capability, cors, too_large, session_closed, ws_closed, ws_too_big, ws_protocol
     */
    public function __construct(string $message, public readonly ?string $errorCode = null, public readonly ?array $details = null)
    {
        parent::__construct($message);
    }

    /** Retrying the same call cannot change the outcome. */
    public function permanent(): bool
    {
        return in_array($this->errorCode, ['configuration', 'profile_capability', 'proxy_auth'], true);
    }
}

/** The native library: loading, the version check, envelopes and frames. */
final class Library
{
    public const REQUIRED = [0, 30];
    private const FRAME_HEADER = 4;

    // include/curlpro.h without the preprocessor, which FFI::cdef does not run.
    private const CDEF = <<<'C'
        typedef long long curlpro_handle;
        void curlpro_free(char *s);
        char *curlpro_version(void);
        char *curlpro_profiles_load_dir(const char *dir);
        char *curlpro_profiles_load_bundle(const char *path, const char *keys);
        char *curlpro_profile_register(const char *profile_json);
        char *curlpro_profiles_list(void);
        char *curlpro_profile_capabilities(const char *name);
        char *curlpro_profile_get(const char *name);
        char *curlpro_session_new(const char *config_json);
        char *curlpro_session_close(curlpro_handle session);
        char *curlpro_session_fingerprint(curlpro_handle session, const char *url);
        char *curlpro_session_preview(curlpro_handle session, const char *spec_json);
        char *curlpro_session_set_header(curlpro_handle session, const char *name, const char *value);
        char *curlpro_session_remove_header(curlpro_handle session, const char *name);
        char *curlpro_session_suppress_header(curlpro_handle session, const char *name);
        char *curlpro_session_reset_headers(curlpro_handle session);
        char *curlpro_session_set_page(curlpro_handle session, const char *page_url);
        char *curlpro_session_cookies(curlpro_handle session);
        char *curlpro_session_set_cookies(curlpro_handle session, const char *cookies_json);
        char *curlpro_session_clear_cookies(curlpro_handle session);
        char *curlpro_request(curlpro_handle session, const char *frame, int frame_len, int *out_len);
        char *curlpro_stream_open(curlpro_handle session, const char *frame, int frame_len, int *out_len);
        int curlpro_stream_read(curlpro_handle stream, char *buf, int buf_len);
        char *curlpro_stream_error(curlpro_handle stream);
        char *curlpro_stream_close(curlpro_handle stream);
        char *curlpro_ws_connect(curlpro_handle session, const char *config_json);
        char *curlpro_ws_send(curlpro_handle socket, const char *frame, int frame_len, int *out_len);
        char *curlpro_ws_recv(curlpro_handle socket, int *out_len);
        char *curlpro_ws_close(curlpro_handle socket, int code, const char *reason);
        char *curlpro_debug_counts(void);
        C;

    private static ?FFI $ffi = null;
    private static string $version = '';
    private static bool $autoloaded = false;

    public static function ffi(): FFI
    {
        if (self::$ffi !== null) {
            return self::$ffi;
        }
        $path = getenv('CURLPRO_LIBRARY') ?: self::defaultPath();
        $ffi = FFI::cdef(self::CDEF, $path);
        self::$ffi = $ffi;
        $v = self::envelope($ffi->curlpro_version())['version'] ?? '0.0.0';
        [$maj, $min] = array_map('intval', explode('.', $v));
        if ($maj < self::REQUIRED[0] || ($maj === self::REQUIRED[0] && $min < self::REQUIRED[1])) {
            self::$ffi = null;
            throw new CurlproException(sprintf(
                'libcurlpro %s is older than the required %d.%d.x: it would silently ignore options',
                $v, self::REQUIRED[0], self::REQUIRED[1]
            ));
        }
        self::$version = $v;
        return $ffi;
    }

    public static function version(): string
    {
        self::ffi();
        return self::$version;
    }

    private static function defaultPath(): string
    {
        $file = match (PHP_OS_FAMILY) {
            'Windows' => 'curlpro.dll',
            'Darwin' => 'libcurlpro.dylib',
            default => 'libcurlpro.so',
        };
        $lib = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'lib' . DIRECTORY_SEPARATOR;
        // The release archive keeps one library per platform: lib/<platform>/.
        $os = match (PHP_OS_FAMILY) { 'Windows' => 'win32', 'Darwin' => 'darwin', default => 'linux' };
        $arch = in_array(strtolower(php_uname('m')), ['aarch64', 'arm64'], true) ? 'arm64' : 'x64';
        foreach ([$lib . $os . '-' . $arch . DIRECTORY_SEPARATOR . $file, $lib . $file] as $candidate) {
            if (is_file($candidate)) {
                return $candidate;
            }
        }
        return $file;
    }

    /** Takes ownership of an envelope, frees it, returns data or throws. */
    public static function envelope($p): mixed
    {
        if ($p === null) {
            throw new CurlproException('the library returned nothing (out of memory?)');
        }
        try {
            $json = FFI::string($p);
        } finally {
            self::$ffi->curlpro_free($p);
        }
        return self::unwrap(json_decode($json, true, 512, JSON_THROW_ON_ERROR));
    }

    /** Takes ownership of a frame, frees it, returns [data, body]. */
    public static function frame($p, int $len): array
    {
        if ($p === null) {
            throw new CurlproException('the library returned nothing (out of memory?)');
        }
        try {
            $bytes = FFI::string($p, $len);
        } finally {
            self::$ffi->curlpro_free($p);
        }
        $n = unpack('V', substr($bytes, 0, self::FRAME_HEADER))[1];
        $env = json_decode(substr($bytes, self::FRAME_HEADER, $n), true, 512, JSON_THROW_ON_ERROR);
        return [self::unwrap($env), (string) substr($bytes, self::FRAME_HEADER + $n)];
    }

    public static function makeFrame(array $meta, string $body = ''): string
    {
        $json = json_encode($meta, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        return pack('V', strlen($json)) . $json . $body;
    }

    /** Calls a function that takes a frame and returns one. */
    public static function callFramed(string $fn, int $handle, string $frame): array
    {
        $ffi = self::ffi();
        $out = $ffi->new('int');
        $p = $ffi->$fn($handle, $frame, strlen($frame), FFI::addr($out));
        return self::frame($p, $out->cdata);
    }

    private static function unwrap(array $env): mixed
    {
        if (($env['ok'] ?? false) === true) {
            return $env['data'] ?? null;
        }
        throw new CurlproException($env['error'] ?? 'unknown error', $env['code'] ?? null, $env['details'] ?? null);
    }

    /** CURLPRO_PROFILES or ./profiles, then the cached signed bundle — once, if the registry is empty. */
    public static function ensureProfiles(): void
    {
        if (self::$autoloaded) {
            return;
        }
        self::$autoloaded = true;
        if (Profiles::list() !== []) {
            return;
        }
        $dir = getenv('CURLPRO_PROFILES') ?: getcwd() . DIRECTORY_SEPARATOR . 'profiles';
        if (is_dir($dir)) {
            Profiles::loadDir($dir);
        }
        $bundle = self::cacheDir() . DIRECTORY_SEPARATOR . 'profiles.json.gz';
        if (is_file($bundle) && is_file($bundle . '.sig')) {
            try {
                Profiles::loadBundle($bundle);
            } catch (CurlproException) {
                // a stale bundle: the directory is enough
            }
        }
    }

    private static function cacheDir(): string
    {
        if ($d = getenv('CURLPRO_CACHE_DIR')) {
            return $d;
        }
        $home = getenv('HOME') ?: (getenv('USERPROFILE') ?: '.');
        return match (PHP_OS_FAMILY) {
            'Windows' => (getenv('LOCALAPPDATA') ?: $home . '\\AppData\\Local') . '\\curlpro',
            'Darwin' => $home . '/Library/Caches/curlpro',
            default => (getenv('XDG_CACHE_HOME') ?: $home . '/.cache') . '/curlpro',
        };
    }
}

/** The process-wide profile registry. It starts empty. */
final class Profiles
{
    public static function loadDir(string $dir): array
    {
        return Library::envelope(Library::ffi()->curlpro_profiles_load_dir($dir))['profiles'] ?? [];
    }

    public static function loadBundle(string $path, ?string $keys = null): array
    {
        return Library::envelope(Library::ffi()->curlpro_profiles_load_bundle($path, $keys ?? (getenv('CURLPRO_BUNDLE_KEYS') ?: '')));
    }

    public static function register(string $profileJson): array
    {
        Library::ensureProfiles(); // a profile may be based_on a stock one
        return Library::envelope(Library::ffi()->curlpro_profile_register($profileJson))['profiles'] ?? [];
    }

    public static function list(): array
    {
        return Library::envelope(Library::ffi()->curlpro_profiles_list())['profiles'] ?? [];
    }

    public static function get(string $name): array
    {
        Library::ensureProfiles();
        return Library::envelope(Library::ffi()->curlpro_profile_get($name));
    }

    public static function capabilities(string $name): array
    {
        Library::ensureProfiles();
        return Library::envelope(Library::ffi()->curlpro_profile_capabilities($name));
    }
}

/** A response with its body read whole (already decompressed). */
final class Response
{
    public readonly int $status;
    /** "HTTP/1.1", "HTTP/2.0" or "HTTP/3.0" */
    public readonly string $proto;
    /** The final URL, after redirects. */
    public readonly string $url;
    /** @var array<string, string[]> lower-case names */
    public readonly array $headers;

    public function __construct(public readonly array $raw, public readonly string $body)
    {
        $this->status = (int) ($raw['status'] ?? 0);
        $this->proto = (string) ($raw['proto'] ?? '');
        $this->url = (string) ($raw['url'] ?? '');
        $this->headers = array_change_key_case($raw['headers'] ?? [], CASE_LOWER);
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)][0] ?? null;
    }

    public function json(): mixed
    {
        return json_decode($this->body, true, 512, JSON_THROW_ON_ERROR);
    }
}

/**
 * One browser: its TLS/HTTP fingerprint, connection pool, cookies and headers.
 * Closed on destruction or with close().
 */
final class Session
{
    private int $id;

    /**
     * @param array $options session fields of docs/C-ABI.md; the browser defaults are filled in
     *     (the ABI's own zero values are not the browser's: a missing boolean is false there).
     */
    public function __construct(public readonly string $profile = 'chrome-156-windows', array $options = [])
    {
        Library::ffi();
        Library::ensureProfiles();
        $cfg = $options + [
            'profile' => $profile,
            'timeout_ms' => 30000,
            'default_headers' => true,
            'follow_redirects' => true,
            'max_redirects' => 20,
            'cookies' => true,
            'resume' => true,
            'trust_env' => true,
        ];
        $data = Library::envelope(Library::ffi()->curlpro_session_new(json_encode($cfg, JSON_THROW_ON_ERROR)));
        $this->id = (int) $data['session'];
    }

    /**
     * @param array $options headers (name => value), body (string), json (encoded as the body),
     *     timeout_ms, protocol ("http1", "h2", "h3"), or any other request field of docs/C-ABI.md
     */
    public function request(string $method, string $url, array $options = []): Response
    {
        $body = (string) ($options['body'] ?? '');
        unset($options['body']);
        if (array_key_exists('json', $options)) {
            $body = json_encode($options['json'], JSON_THROW_ON_ERROR);
            $options['headers'] = ($options['headers'] ?? []) + ['content-type' => 'application/json'];
            unset($options['json']);
        }
        $meta = ['method' => $method, 'url' => $url] + $options;
        [$data, $out] = Library::callFramed('curlpro_request', $this->id(), Library::makeFrame($meta, $body));
        return new Response($data, $out);
    }

    public function get(string $url, array $options = []): Response
    {
        return $this->request('GET', $url, $options);
    }

    public function post(string $url, array $options = []): Response
    {
        return $this->request('POST', $url, $options);
    }

    /** ja3, ja3n, ja4, akamai… for this URL, computed without sending anything. */
    public function fingerprint(string $url): array
    {
        return Library::envelope(Library::ffi()->curlpro_session_fingerprint($this->id(), $url));
    }

    /** The headers a request would carry, in order, without sending it. */
    public function preview(string $method, string $url, array $headers = []): array
    {
        $spec = ['method' => $method, 'url' => $url] + ($headers ? ['headers' => $headers] : []);
        return Library::envelope(Library::ffi()->curlpro_session_preview($this->id(), json_encode($spec, JSON_THROW_ON_ERROR)));
    }

    public function setHeader(string $name, string $value): void
    {
        Library::envelope(Library::ffi()->curlpro_session_set_header($this->id(), $name, $value));
    }

    /** Never send this header, even when the profile would. */
    public function suppressHeader(string $name): void
    {
        Library::envelope(Library::ffi()->curlpro_session_suppress_header($this->id(), $name));
    }

    public function cookies(): array
    {
        return Library::envelope(Library::ffi()->curlpro_session_cookies($this->id()))['cookies'] ?? [];
    }

    public function setCookies(array $cookies): void
    {
        Library::envelope(Library::ffi()->curlpro_session_set_cookies($this->id(), json_encode($cookies, JSON_THROW_ON_ERROR)));
    }

    public function clearCookies(): void
    {
        Library::envelope(Library::ffi()->curlpro_session_clear_cookies($this->id()));
    }

    public function close(): void
    {
        if ($this->id !== 0) {
            $id = $this->id;
            $this->id = 0;
            Library::envelope(Library::ffi()->curlpro_session_close($id));
        }
    }

    public function __destruct()
    {
        try {
            $this->close();
        } catch (\Throwable) {
            // nothing useful to do in a destructor
        }
    }

    private function id(): int
    {
        if ($this->id === 0) {
            throw new CurlproException('the session is closed', 'session_closed');
        }
        return $this->id;
    }
}
