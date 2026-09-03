# curlpro

HTTP-клиент с сетевым отпечатком браузера: TLS ClientHello, кадры HTTP/2,
порядок и регистр заголовков.

```python
import curlpro

curlpro.load_profiles("profiles")

with curlpro.Session("chrome-151-windows") as s:
    r = s.get("https://example.com")
    print(r.status, r.text[:200])
```

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
[fhttp](https://github.com/bogdanfinn/fhttp).

Отпечаток сверен с `tls.browserleaks.com`: Chrome 151 даёт
`t13d1516h2_8daaf6152771_806a8c22fdea` — тот же JA4, что живой браузер.

## Границы

Библиотека закрывает сетевой слой. Она **не** подделывает JS-отпечаток
(canvas, WebGL, navigator) — это уровень браузера, там нужен Playwright.
Совпадение сетевого отпечатка необходимо, но не достаточно: современные
системы скорят JA4 вместе с JA4H, JA3S/JARM и поведенческим анализом.

Поддерживаются HTTP/1.1, HTTP/2 и HTTP/3, куки, редиректы, прокси
(HTTP CONNECT и SOCKS5), multipart, потоковое чтение, асинхронный API.

Отпечаток HTTP/3 сверен с Chrome 144 на `quic.browserleaks.com`:

```python
with curlpro.Session("chrome-151-windows", http3=True) as s:
    print(s.get("https://quic.browserleaks.com/fp").json()["h3_text"])
    # 1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p
```

Известное ограничение: профиль объявляет ёмкость динамической таблицы QPACK,
как Chrome, но декодер её не поддерживает — сервер, который ей воспользуется,
вернёт неразбираемый ответ.

## Установка

Пока собирается из исходников — нужны Go и C-компилятор:

```powershell
.\build.ps1
cd python; $env:PYTHONPATH='.'; python -m pytest tests
```

Библиотека ищется по `CURLPRO_LIBRARY`, затем в `curlpro/lib/`, затем в `dist/`.
