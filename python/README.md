# curlpro

HTTP-клиент с сетевым отпечатком браузера: TLS ClientHello, кадры HTTP/2
и HTTP/3, порядок и регистр заголовков.

```bash
pip install curlpro
```

```python
import curlpro

with curlpro.Session("chrome-151-windows") as s:
    r = s.get("https://example.com")
    print(r.status, r.text[:200])
```

Ни Go, ни компилятора не нужно: нативная библиотека и все 47 профилей уже
внутри колеса, и профили подхватываются сами.

## Зачем ещё один

Существующие решения хранят профили браузеров в компилируемом коде: новый Chrome
выходит каждые 4 недели, и каждый раз это правка C или Go, пересборка и релиз.
Здесь профиль — данные, и его можно подключить в рантайме:

```python
curlpro.register_profile({
    "name": "chrome-152-windows",
    "based_on": "chrome-151-windows",
    "headers": {"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/152.0.0.0 ..."},
})
```

## Что внутри

Тонкая ctypes-обёртка над нативной библиотекой на Go: рукопожатие ведёт
[uTLS](https://github.com/refraction-networking/utls), HTTP/2 —
[fhttp](https://github.com/bogdanfinn/fhttp), QUIC —
[uquic](https://github.com/refraction-networking/uquic).

Отпечаток сверен с `tls.browserleaks.com`: Chrome 151 даёт
`t13d1516h2_8daaf6152771_806a8c22fdea` — тот же JA4, что живой браузер.

## Границы

Библиотека закрывает сетевой слой. Она **не** подделывает JS-отпечаток
(canvas, WebGL, navigator) — это уровень браузера, там нужен Playwright.
Совпадение сетевого отпечатка необходимо, но не достаточно: современные
системы скорят JA4 вместе с JA4H, JA3S/JARM и поведенческим анализом.

Поддерживаются HTTP/1.1, HTTP/2, HTTP/3 и WebSocket, куки, редиректы, прокси
(HTTP CONNECT и SOCKS5), multipart, потоковое чтение и отправка, асинхронный API.

```python
# WebSocket: рукопожатие по шаблону профиля браузера, permessage-deflate поддержан
with curlpro.Session() as s:
    with s.websocket("wss://echo.websocket.org/", max_message_size=1 << 20) as ws:
        ws.send("привет")        # str  → текстовый кадр
        ws.send(b"\x00\xff")     # bytes → двоичный
        for message in ws:       # до закрытия сервером — curlpro.WebSocketClosed;
            print(message)       # таймаут тишины — CurlProError с .code == "timeout"

# Большой файл уходит потоком, а не через память
with curlpro.Session() as s:
    s.post("https://example.com/upload", body_file="archive.zip")

# Соединение переиспользуется между запросами, как у браузера.
# keep_alive=False даёт каждому запросу своё — нужно, когда балансировщик
# прибивает клиента к одному узлу
with curlpro.Session(keep_alive=False) as s:
    s.get("https://example.com/")
```

Отпечаток HTTP/3 сверен с Chrome 144 на `quic.browserleaks.com`:

```python
with curlpro.Session("chrome-151-windows", http3=True) as s:
    print(s.get("https://quic.browserleaks.com/fp").json()["h3_text"])
    # 1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p
```

Динамическая таблица QPACK поддержана своим декодером: профиль объявляет
ёмкость, как Chrome, и ответ сервера, который ей пользуется, разбирается.

## Установка

Готовые колёса собраны для Linux (x86-64 и ARM64, glibc 2.28+), macOS 13+
(Intel и Apple Silicon) и Windows x64. Минимум macOS 13 задан не нами: столько
требует Go 1.27, на котором собрана нативная часть.

Платформы вне этого списка — Alpine и другой musl, Windows на ARM, старые glibc
или macOS — ставятся из исходного архива, и тогда нужны Go и компилятор C:

```bash
pip download curlpro --no-binary :all: --no-deps
tar -xzf curlpro-0.2.0.tar.gz && cd curlpro-0.2.0/go
CGO_ENABLED=1 go build -buildmode=c-shared -o ../curlpro/lib/libcurlpro.so ./lib
```

Библиотека ищется по `CURLPRO_LIBRARY`, затем в `curlpro/lib/`, затем в `dist/`.

Полная документация и исходники — [github.com/int3re/curlpro](https://github.com/int3re/curlpro).
