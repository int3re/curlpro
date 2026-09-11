# Measuring okhttp

okhttp is a library, not a browser, so it is the one client in the corpus that
anyone can measure on their own machine, deterministically, with no device and
no build tool: a JVM and four jars.

## What is here

- [Probe.java](Probe.java) — makes one request to the stand per run, with a
  fresh `OkHttpClient` **and a fresh `SSLContext`** each time, optionally with
  Conscrypt installed as the TLS provider. This is what the two profiles were
  captured with.
- [Big.java](Big.java) — downloads a URL and reports size and time. Used to show
  that the real okhttp fetches 45 MB where our reproduction of it once failed
  ([docs/FHTTP-PATCH.md](../../docs/FHTTP-PATCH.md)).
- [pom.xml](pom.xml) — the exact coordinates, for anyone who prefers Maven.

The jars are not committed. Fetch them from Maven Central into `lib/`:

```
com.squareup.okhttp3:okhttp-jvm:5.5.0
com.squareup.okio:okio-jvm:3.18.1
org.jetbrains.kotlin:kotlin-stdlib:2.1.21
org.conscrypt:conscrypt-openjdk-uber:2.7.0
```

## Two stacks, two profiles

On Android okhttp's TLS comes from the platform — Conscrypt, which is BoringSSL.
On a desktop JVM it comes from SunJSSE. They produce different ClientHellos, so
both were captured and both are named for exactly what they are:

| Profile | Provider | JA4 |
|---|---|---|
| `okhttp-5.5-conscrypt` | Conscrypt 2.7.0 on the JVM — the library Android ships, its own version | `t13d1512h2_8daaf6152771_40271e0a5736` |
| `okhttp-5.5-jvm` | SunJSSE, Temurin 21 | `t13d1114h2_5e2a75874763_62776a4e08ff` |

Neither is called `android-*`: nothing here was checked on a device, and a name
that promised Android would promise the unverified. The HTTP/2 layer is
okhttp's own and identical on both — `4:16777216|16711681|0|m,p,a,s`.

## Running it

```bash
bash scripts/gen-certs.sh                       # once
go run ./cmd/curlpro capture --name okhttp-5.5-conscrypt --manual --wait 120s
```

In a second shell, with `CP` holding the four jars plus `.`:

```bash
javac -cp "$CP" -d capture/okhttp capture/okhttp/Probe.java
for i in 1 2 3 4 5; do java -cp "$CP:capture/okhttp" Probe https://www.example.com:8443/json/detail conscrypt; done
```

Drop the trailing `conscrypt` for the JVM profile. On Windows the classpath
separator is `;`.

## Two traps

**SNI.** SunJSSE sends no `server_name` for a host without a dot. A stand reached
as `localhost` therefore captured `t13i…` — the `i` says "no SNI" — instead of the
`t13d…` a real deployment produces. The probe resolves `www.example.com` to
127.0.0.1 through okhttp's own `Dns` hook; the stand's certificate already
carries that name.

**Resumption.** A reused `OkHttpClient` keeps its TLS session and the next
handshake resumes with `pre_shared_key`. The capture drops resumed handshakes
by design (they are not the message a profile describes), so five runs on one
client yielded one sample and four skips. Hence a new client *and* a new
`SSLContext` per run: the context owns the session cache.
