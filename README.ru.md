# curlPro

**HTTP-клиент с сетевым отпечатком браузера. Профиль браузера — JSON-файл, а не код.**

[![PyPI](https://img.shields.io/pypi/v/curlpro)](https://pypi.org/project/curlpro/)
[![Python](https://img.shields.io/pypi/pyversions/curlpro)](https://pypi.org/project/curlpro/)
[![tests](https://github.com/int3re/curlpro/actions/workflows/test.yml/badge.svg)](https://github.com/int3re/curlpro/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

*[English](README.md) · [Документы](#документы)*

```bash
pip install curlpro
```

```python
import curlpro

with curlpro.Session("chrome-151-windows") as s:
    r = s.get("https://tls.browserleaks.com/json")
    print(r.json()["ja4"])      # t13d1516h2_8daaf6152771_806a8c22fdea — как у Chrome
```

Новый Chrome выходит раз в четыре недели. У `curl_cffi` и `tls-client` это правка C
или Go, пересборка и релиз; здесь — правка JSON, которую можно сделать прямо из
Python и не ждать никого:

```python
curlpro.register_profile({
    "name": "chrome-153-windows",
    "based_on": "chrome-152-windows",
    "headers": {"user_agent": "...Chrome/153.0.0.0..."},
})
```

---

## Содержание

[Что умеет](#что-умеет) · [Чем отличается](#чем-отличается) · [Установка](#установка) ·
[Быстрый старт](#быстрый-старт) · [Сессия](#сессия) · [Запрос](#запрос) ·
[Протокол на запрос](#протокол-на-запрос) · [Память сессии](#память-сессии) ·
[Проверки ответа](#проверки-ответа) · [Откат кук](#откат-кук) ·
[Ошибки и перехватчики](#ошибки-и-перехватчики) · [Потоки](#потоки) ·
[WebSocket](#websocket) · [Асинхронность](#асинхронность) · [HTTP/3](#http3) ·
[Сеть](#сеть-прокси-подмена-адреса-tls) ·
[Свой отпечаток](#свой-отпечаток-без-запроса) · [Персона](#персона-личность-между-запусками) ·
[Совместимость с requests](#совместимость-с-requests) · [Куки](#куки-между-запусками) ·
[Мобильные профили](#мобильные-профили-и-client-hints) ·
[Навигация и fetch](#навигация-и-fetch) · [Профили как данные](#профили-как-данные) ·
[Проверено замером](#проверено-замером) · [Границы](#границы)

---

## Что умеет

- **50 профилей**: Chrome 98–152, Edge, Firefox 133–155, Safari, Tor, Яндекс.Браузер, okhttp 5.5;
  мобильные — Chrome и Яндекс для Android, Safari для iOS.
- **Все слои отпечатка сразу** — TLS, HTTP/2, HTTP/3, HTTP/1.1 и WebSocket
  (таблица ниже).
- **HTTP/3 с проверенным отпечатком** и автопереходом по `Alt-Svc`, как в браузере.
- **Нативная асинхронность**: запрос уходит в горутину, поток на процесс — один.
- **WebSocket** с рукопожатием по профилю и `permessage-deflate`.
- **Потоковое чтение и отправка**, multipart, распаковка `gzip`/`deflate`/`br`/`zstd`.
- **Совместимость с requests**: `params`, `auth`, `r.json()`, `r.history`,
  `r.elapsed`, `raise_for_status()`.
- **Инструменты парсера**: проверки ответа, откат кук, `cookies.txt`, хук ошибок,
  подмена адреса узла, повторы с `Retry-After`.
- **Отпечаток без запроса**: `session.fingerprint()` отдаёт JA3, JA3N, JA4, JA4H
  и строку Akamai, посчитанные офлайн — без сети и без оракула.
- **Аудит согласованности**: `session.audit()` ищет противоречия внутри личности —
  причину, по которой верный отпечаток всё равно палят.
- **Персоны**: личность — профиль, устройство, куки, заголовки — сохраняется
  в файл и открывается заново такой же.
- **Открытый `http://` и `ws://`** для собственного сервиса: солверу или
  внутреннему API второй HTTP-клиент не нужен.
- **Профиль как данные**: JSON с наследованием, регистрация в рантайме, снятие
  профиля с живого браузера одной командой.

Что именно воспроизводится:

| Слой | Что задаётся профилем |
|---|---|
| TLS | ClientHello целиком: шифры, расширения и их порядок, GREASE, ALPS, ECH, `trust_anchors`, перемешивание расширений на каждое соединение |
| HTTP/2 | SETTINGS и их порядок, размер окна, `PRIORITY` на HEADERS, порядок псевдо-заголовков |
| HTTP/3 | SETTINGS, GREASE-кадр, `PRIORITY_UPDATE`, transport parameters QUIC, порядок заголовков |
| HTTP/1.1 | порядок **и регистр** имён, `Host` и `Connection` — свой набор, не как в HTTP/2 |
| Заголовки | два набора (переход по адресу и `fetch`), позиции слотов, якорь пользовательских |
| WebSocket | набор и порядок заголовков рукопожатия, `permessage-deflate` |
| Форма | стиль границы multipart: `----WebKitFormBoundary` у Chrome, дефисы у Firefox |

## Чем отличается

| | curlPro | curl_cffi | tls-client | wreq / rnet |
|---|---|---|---|---|
| Профиль браузера | **JSON-данные**, регистрация в рантайме | C-структуры; путь через данные — платный API | Go-литералы в коде | Rust-код |
| Новая версия браузера | правка файла | релиз библиотеки (или подписка) | PR → мерж → тег → пересборка под 8 платформ | релиз библиотеки |
| Снятие профиля с браузера | `curlpro capture` — стенд, браузер, профиль | вручную | вручную | вручную |
| HTTP/3 | есть, отпечаток сверен с Chrome | нет | у 5 профилей из ~40 | есть |
| WebSocket с отпечатком профиля | есть | есть | нет | нет |
| Язык обёртки | Python поверх Go | Python поверх C | Go, обёртки поверх | Rust, обёртка PyO3 |

Разбор по исходникам — в [docs/RESEARCH.md](docs/RESEARCH.md); там же о том, почему
«профили в компилируемом коде» ломаются структурно, а не по вине мейнтейнера.

### Открытый http://

`http://` и `ws://` работают. ClientHello в открытом канале нет, значит нет
и отпечатка TLS, но половина профиля для HTTP/1.1 применяется по-прежнему —
порядок и регистр заголовков берутся из профиля, а больше открытому серверу
и не видно. Смысл не в маскировке: если собственный сервис ходит по обычному
HTTP — солвер, внутреннее API, — незачем держать рядом второй HTTP-клиент.

Две вещи отвергаются, а не понижаются молча: `protocol="h2"` поверх `http://`
это h2c, на котором не говорит ни один браузер, а `protocol="h3"` без TLS
невозможен по определению. Редирект с `https://` на `http://` тоже не
выполняется — 3xx отдаётся вместе с `Location`, и решение остаётся за
вызывающим; пойти по нему значило бы отправить куки и учётные данные запроса
открытым текстом.


### Как отказаться от JA4H

JA4 для TLS — BSD-3 и свободен. JA4H — нет: FoxIO License 1.1 и patent-pending,
внутреннее и академическое использование свободно, коммерческая монетизация
требует OEM у FoxIO. Библиотека под Apache 2.0, то есть обязательство возникает
у того, кто выпускает продукт, считающий это значение, а не у библиотеки. Но
проверка зависимостей не взвешивает обязательства — она помечает лицензии.

Поэтому JA4H можно исключить целиком:

```bash
go build -tags nofoxio -buildmode=c-shared -o dist/libcurlpro.so ./lib
```

В такой бинарник код под лицензией FoxIO не попадает вовсе. Всё остальное не
меняется: JA3, JA3N, JA4, строка Akamai, превью заголовков и аудит считаются
как прежде — это под тестом, который в CI гоняется с этим флагом.
`fingerprint().ja4h` возвращается пустым, а `fingerprint().ja4h_available`
равен `False`: сообщается явно, а не оставляется на догадку — настоящая
реализация пустую строку не возвращает никогда.

Колёса на PyPI собраны без флага, JA4H в них есть.

## Установка

```bash
pip install curlpro
```

Ни Go, ни компилятора не нужно: нативная библиотека и все 50 профилей уже
внутри колеса. Готовые колёса собраны для пяти платформ:

| Платформа | Колесо |
|---|---|
| Linux x86-64, glibc 2.28+ | `manylinux_2_28_x86_64` |
| Linux ARM64, glibc 2.28+ | `manylinux_2_28_aarch64` |
| macOS 13+, Intel | `macosx_13_0_x86_64` |
| macOS 13+, Apple Silicon | `macosx_13_0_arm64` |
| Windows x64 | `win_amd64` |

Минимум macOS 13 задан не нами: столько требует Go 1.27, на котором собрана
нативная часть.

Те же файлы лежат на [странице релиза](https://github.com/int3re/curlpro/releases/latest) —
если ставить нужно без обращения к индексу:

```bash
pip install curlpro-*-manylinux_2_28_x86_64.whl
```

**Платформы вне таблицы** — Alpine и другой musl, Windows на ARM, старые glibc
или macOS — колеса не имеют. Там исходный архив собирается руками, и тогда Go
и компилятор C нужны: один `pip install` оставил бы пакет без нативной части,
и падение случилось бы не при установке, а при первом обращении.

```bash
pip download curlpro --no-binary :all: --no-deps
tar -xzf curlpro-*.tar.gz && cd curlpro-*/go
CGO_ENABLED=1 go build -buildmode=c-shared -o ../curlpro/lib/libcurlpro.so ./lib
```

`CGO_ENABLED=1` здесь не для красоты: без него сборка падает с «build
constraints exclude all Go files», и по этой фразе причину не найти.

### Из репозитория

Для разработки и для правки профилей:

```powershell
.\build.ps1                                        # → dist/curlpro.dll
cd python; $env:PYTHONPATH='.'; python -m pytest tests
```

Профили подхватываются сами только из колеса. При запуске из репозитория
их указывают явно:

```python
curlpro.load_profiles("profiles")
```

## Быстрый старт

```python
import curlpro

# Одиночный запрос — без сессии
r = curlpro.get("https://example.com", impersonate="firefox-144-macos")

# Сессия: соединения переиспользуются, куки живут между запросами
with curlpro.Session("chrome-151-windows") as s:
    s.headers["X-Api-Key"] = "secret"          # во всех последующих запросах
    r = s.post("https://example.com/api", json_body={"id": 7})
    print(r.status, r.json())
```

Асинхронно — тот же API, те же аргументы:

```python
import asyncio, curlpro

async def main(urls):
    async with curlpro.AsyncSession("chrome-151-windows") as s:
        return await asyncio.gather(*(s.get(u) for u in urls))

asyncio.run(main(urls))
```

## Сессия

```python
curlpro.Session("chrome-151-windows", proxy="socks5://127.0.0.1:1080", retries=3)
```

| Параметр | Значение |
|---|---|
| `impersonate` | имя профиля; по умолчанию `chrome-151-windows` |
| `timeout` | предел на запрос целиком; пара `(соединение, всего)` ограничивает установку соединения отдельно |
| `proxy` | `http://`, `https://`, `socks5://` или `socks5h://`, можно с `user:pass`. Адрес без схемы — `1.2.3.4:8080` — читается как `http://`; определения на ощупь нет, SOCKS надо назвать явно. `HTTP_PROXY` читается для запросов по `http://`, `HTTPS_PROXY` — по `https://`, `ALL_PROXY` для обоих, `NO_PROXY` исключает. Первый CONNECT идёт без учётных данных и добавляет их после 407, как Chrome; прокси, который вместо 407 рвёт соединение, получает второй CONNECT с учётными данными на новом соединении, а рвущий и его — ошибку с кодом `proxy_closed` |
| `trust_env` | брать прокси из `HTTPS_PROXY`/`ALL_PROXY` с учётом `NO_PROXY` |
| `verify` | `True` — системные корни, путь к PEM — доверять только ему, `False` — не проверять |
| `cert` | пара `(сертификат, ключ)` для mTLS |
| `retries`, `retry_statuses`, `retry_methods`, `retry_backoff`, `retry_max_backoff`, `respect_retry_after` | политика повторов; по умолчанию повторяются только идемпотентные методы |
| `allow_redirects`, `max_redirects` | переходы по 3xx |
| `cookies` | банка кук, общая для запросов сессии |
| `default_headers`, `header_order`, `mode` | заголовки профиля, желаемый порядок, набор (`navigate`/`fetch`/`auto`) |
| `force_http1`, `http3`, `alt_svc` | транспорт: запретить h2, сразу QUIC, автопереход по `Alt-Svc` |
| `keep_alive`, `max_idle_conns`, `idle_conn_timeout` | переиспользование соединений и размер пула |
| `resolve`, `ip_version` | подмена адреса узла, семейство адресов (`"4"`/`"6"`) |
| `device`, `devices` | телефон для мобильных профилей и свой список устройств |
| `max_response_size` | предел размера тела; без него бесконечный ответ съест память. Ограничивает `read()`, но не `iter_content()` |
| `hooks` | перехватчики `request`, `response`, `error` |

## Запрос

Всё, что задано у сессии, переопределяется на один запрос:

```python
s.get(url, timeout=(3, 30), protocol="h2", cookies=False, retries=0)
```

| Параметр | Значение |
|---|---|
| `params`, `auth` | строка запроса и `Authorization` — как в requests |
| `data`, `json_body`, `fields`, `files`, `body_file` | тело: байты, JSON, форма, multipart, файл потоком |
| `headers`, `header_order` | свои заголовки и порядок |
| `protocol` | `1.1`/`http1`, `2`/`h2`, `3`/`h3` — транспорт этого запроса |
| `timeout` | число или пара `(соединение, всего)` |
| `proxy` | адрес, либо `False` — в обход прокси сессии |
| `cookies` | `False` — не слать и не запоминать куки |
| `session_headers` | `False` — без заголовков, добавленных сессии |
| `default_headers` | `True`/`False` — заголовки профиля, в обе стороны |
| `mode` | `navigate` или `fetch` — какой набор заголовков брать |
| `allow_redirects`, `max_redirects`, `retries`, … | переопределения политик сессии |
| `expect` | проверка ответа (см. ниже) |
| `rollback_cookies` | откатить банку, если запрос не удался |

Ответ отвечает тем же, чем и в requests:

```python
r.status, r.ok, r.proto            # 200, True, "HTTP/2.0"
r.text, r.content, r.json()        # кодировка из Content-Type, BOM или <meta charset>
r.headers, r.header("server")      # все значения и первое без учёта регистра
r.cookies, r.history, r.elapsed    # куки ответа, цепочка редиректов, время
r.raise_for_status()               # HTTPError со статусом и ответом внутри
```

## Протокол на запрос

Указание сильнее и опций сессии, и перехода по `Alt-Svc`. Замер против
`cloudflare-quic.com` в одной сессии:

```python
with curlpro.Session("chrome-151-windows") as s:
    s.get(url).proto                      # HTTP/2.0 — первый запрос
    s.get(url).proto                      # HTTP/3.0 — перешли по Alt-Svc
    s.get(url, protocol="h2").proto       # HTTP/2.0 — но этот остался на TCP
    s.get(url, protocol=1.1).proto        # HTTP/1.1
    s.get(url, protocol=3).proto          # HTTP/3.0
```

`h2` при этом **не урезает список ALPN** до одного значения: такого не шлёт ни один
браузер. Если сервер согласовал `http/1.1`, запрос падает с внятной ошибкой, а не
уезжает молча не по тому протоколу. Ошибка помечена неповторяемой — со второй
попытки сервер согласует то же самое.

## Память сессии

Сессия помнит куки и добавленные заголовки. Отдельному запросу это можно выключить:

```python
s.get(url, cookies=False)          # мимо банки: не слать и не запоминать
s.get(url, session_headers=False)  # без заголовков, добавленных сессии
s.get(url, default_headers=False)  # без заголовков профиля — только свои
```

Изоляция кук двусторонняя намеренно: «не использовать память» читается как «не
трогать её вовсе». Такой запрос не принесёт в банку куку, из-за которой следующий
пойдёт под чужой личностью — например, при проверке страницы «как аноним».

`default_headers` и `session_headers` разделены: первое — набор браузера (он и есть
отпечаток), второе — то, что дописали вы. Выключение одного не трогает другое.

## Проверки ответа

Парсер вокруг каждого запроса пишет одно и то же: проверить статус, найти на
странице признак успеха, убедиться, что вместо неё не пришла капча. Написанные
руками, эти проверки забываются по одной — и редирект на страницу блокировки
выглядит как «парсер перестал находить данные».

```python
from curlpro import Expect

r = s.get(url, expect=Expect(status=200, body="Личный кабинет",
                             not_body="captcha", non_empty=True))
```

| Поле | Что проверяет |
|---|---|
| `status`, `not_status` | код ответа; несколько значений — «одно из» |
| `body`, `not_body` | подстрока в теле; несколько — «все» |
| `non_empty` | тело не пустое |
| `json` | тело разбирается как JSON |
| `headers`, `not_headers` | подстрока в строках `имя: значение` |

Несовпадение поднимает `ExpectationFailed` — это `CurlProError`, значит ловится
вместе с сетевыми ошибками. Сообщение называет, что именно не сошлось и что пришло:

```
the body contains the forbidden 'captcha' (200 https://example.com/)
```

Проверка идёт **после** перехватчиков ответа: наружу уходит их замена, её и надо
проверять.

## Откат кук

Неудачный вход не должен оставлять сессию наполовину авторизованной:

```python
s.post(login, fields=creds, expect=Expect(body="Личный кабинет"),
       rollback_cookies=True)          # не вышло — банка как до запроса

with s.cookies.transaction():          # то же на несколько запросов
    s.post(login, fields=creds)
    s.get(account).raise_for_status()  # исключение — откат всего блока
```

Снимок снимается до отправки: после сбоя банка уже изменена, и копировать нечего.
Половина логина хуже, чем его отсутствие.

## Ошибки и перехватчики

Любой сбой приходит исключением, которое называет и причину, и следствие.
Ветвиться следует по типу или по `code`, но не по тексту:

```python
try:
    r = s.get(url, timeout=(3, 30))
    r.raise_for_status()
except curlpro.Timeout:                   # code == "timeout"
    ...                                   # предел истёк, повтор осмыслен
except curlpro.ExpectationFailed as e:    # code == "expectation"
    print(e.response.text)                # ответ сохранён — в нём причина
except curlpro.HTTPError as e:            # поднимает raise_for_status()
    print(e.status, e.response.text)
except curlpro.WebSocketClosed:           # code == "ws_closed"
    ...
except curlpro.CurlProError as e:         # всё остальное из нативной части
    print(e.code, e)
```

Коды исходов: `timeout`, `expectation`, `session_closed`, `ws_closed`, `ws_too_big`,
`ws_protocol`. Текст написан для человека и называет следствие, а не только факт:

```
timeout must be positive, got 0s (leave it unset for no limit)
unsupported proxy scheme "ftp" (use http, https or socks5)
protocol=h2: server negotiated http/1.1. The ALPN list is left intact on
  purpose: no browser offers h2 alone
```

Три точки вмешательства без правки библиотеки:

```python
with curlpro.Session() as s:
    @s.on_request
    def sign(meta):                       # meta можно менять на месте
        meta.setdefault("headers", {})["X-Signature"] = sign_it(meta["url"])

    @s.on_response
    def log(resp):                        # можно вернуть замену
        print(resp.status, resp.url)

    @s.on_error
    def alert(exc):                       # сеть, таймаут, несовпавшее ожидание
        logging.warning("запрос не удался: %s", exc)
```

## Потоки

Тело читается частями — мегабайтная загрузка не занимает мегабайт памяти:

```python
with s.stream("GET", url, timeout=5) as r:       # аргументы те же, что у request()
    for chunk in r.iter_content(64 * 1024):
        out.write(chunk)

with s.stream("GET", ndjson_url) as r:
    for line in r.iter_lines():                  # построчно, тело не собирается
        handle(json.loads(line))
```

`max_response_size` сессии ограничивает `read()` — вызов, который собирает
тело в память, — и намеренно не ограничивает `iter_content()`: чтение по кускам
и есть способ работать с телом больше памяти. Обе ошибки приходят с кодом
`too_large`.

Закрыть поток, не дочитав, — дёшево: соединение выбрасывается, а не дренируется.
Отправка симметрична: `body_file=` шлёт файл потоком с явным `Content-Length` —
без него транспорт ушёл бы в chunked, чего браузер при отправке файла не делает.

```python
s.post("https://example.com/upload", body_file="archive.zip")
```

## WebSocket

Рукопожатие — обычный запрос с `Upgrade`, поэтому его заголовки тоже часть
отпечатка и берутся из профиля.

```python
with curlpro.Session("chrome-151-windows") as s:
    with s.websocket("wss://echo.websocket.org/", max_message_size=1 << 20) as ws:
        ws.send("привет")          # str → текстовый кадр
        ws.send(b"\x00\xff")       # bytes → двоичный
        ws.ping()
        for message in ws:         # до закрытия сервером (WebSocketClosed);
            print(message)         # таймаут тишины — CurlProError с code="timeout"
```

`permessage-deflate` объявляется и поддерживается, в том числе с окном меньше
32 КиБ, которое требуют некоторые серверы.

## Асинхронность

Запрос уходит в горутину, а поток-приёмник на процесс — один. 128 запросов
по 0.3 с занимают 0.37 с, а не 1.27 с, как через пул из 32 потоков.

```python
async with curlpro.AsyncSession("firefox-144-macos") as s:
    results = await asyncio.gather(*(s.get(u) for u in urls))

    # Потоковое чтение и WebSocket — там же и так же, без пула потоков
    async with s.stream("GET", url) as r:
        async for chunk in r.iter_content():
            out.write(chunk)

    async with s.websocket("wss://example.com/ws") as ws:
        await ws.send("привет")
        print(await ws.recv())
```

Снятая задача отменяет запрос в нативной части: соединение освобождается сразу,
а не висит до своего таймаута.

## HTTP/3

Включается сам, как в браузере: первый запрос идёт по TCP, а увидев в ответе
`Alt-Svc`, клиент со следующего переходит на QUIC. Если QUIC не проходит, запрос
откатывается на TCP, и попытка какое-то время не повторяется.

```python
with curlpro.Session("chrome-151-windows") as s:
    print(s.get("https://cloudflare-quic.com/").proto)   # HTTP/2.0
    print(s.get("https://cloudflare-quic.com/").proto)   # HTTP/3.0

with curlpro.Session("chrome-151-windows", http3=True) as s:   # сразу QUIC
    print(s.get("https://quic.browserleaks.com/fp").json()["h3_text"])
    # 1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p — как Chrome
```

## Сеть: прокси, подмена адреса, TLS

```python
curlpro.Session(
    proxy="socks5://user:pw@127.0.0.1:1080",   # http, https и socks5
    resolve={"example.com:443": "10.0.0.7"},   # как --resolve у curl
    ip_version="4",                            # только A-записи
    verify="ca.pem",                           # свой корень доверия
    cert=("client.pem", "key.pem"),            # взаимная аутентификация
    max_response_size=10 << 20,                # предел размера тела
)
```

Подмена адреса не меняет отпечаток: имя в SNI и заголовке `Host` остаётся прежним,
меняется только то, куда открывается сокет. Через `https://`-прокси канал до самого
прокси шифруется, а первый `CONNECT` уходит без учётных данных и добавляет их
только после 407 — так делает Chrome.

## Свой отпечаток без запроса

Что увидит сервер — считается локально, из тех же байтов ClientHello, что
ушли бы на провод. Ни сети, ни оракула:

```python
with curlpro.Session("chrome-151-windows") as s:
    fp = s.fingerprint()
    print(fp.ja4)       # t13d1516h2_8daaf6152771_806a8c22fdea
    print(fp.akamai)    # 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
    print(fp.headers)   # порядок имён, как они уйдут
```

Раньше эти значения можно было узнать только у browserleaks, то есть проверка
зависела от чужого сервиса. Расчёт сверен с 50 захватами из
`reference/baselines`: **JA4 50/50, JA3N 50/50, Akamai 50/50**.

`diff()` отвечает на вопрос, который и возникает после правки профиля — заметил
ли сервер:

```python
a = curlpro.Session("chrome-151-windows").fingerprint()
b = curlpro.Session("chrome-152-windows").fingerprint()
a.diff(b)["extensions"]      # ... -> добавилось 'ca34', это trust_anchors
```

Учитываются опции самой сессии: `force_http1` урезает ALPN, а ALPN — два символа
JA4, поэтому у такой сессии отпечаток другой, и это честно.

**JA4H** — отпечаток самого запроса: метод, протокол, наличие кук и реферера,
число заголовков, язык и хеши имён заголовков и кук. Два клиента с одинаковым
TLS могут различаться здесь, поэтому системы защиты считают их вместе.

```python
s.fingerprint().ja4h          # ge20nn13enus_0c2c1d640f3e_000000000000_000000000000
```

> **Лицензия у JA4H другая.** Сам JA4 для TLS — BSD-3 и свободен. JA4H идёт под
> [FoxIO License 1.1](https://github.com/FoxIO-LLC/ja4), patent-pending:
> внутреннее и академическое использование свободно, коммерческая монетизация
> требует OEM-лицензии у FoxIO. Библиотека под Apache 2.0, так что обязательство
> возникает у того, кто выпускает продукт, считающий эти значения.

Одна тонкость намеренная: `fp.ja3` у Chrome ≥110 **меняется** между
соединениями — расширения перемешиваются, и двенадцать сборок дают двенадцать
значений. Это не дефект: замороженный порядок сам по себе аномалия. Сравнивать
надо `ja4` или `ja3n`, они сортируют.

## Персона: личность между запусками

Профиль, прокси, устройство, заголовки и куки — одна личность и один файл:

```python
p = curlpro.Persona.new("chrome-151-windows", proxy="http://user:pass@host:8080")
p.save("accounts/user42.json")

# в следующем запуске — тот же отпечаток, тот же выход, те же куки
p = curlpro.Persona.load("accounts/user42.json")
with p.session() as s:
    s.get("https://example.com/")
p.save()
```

Куки забираются даже если блок бросил исключение: недоделанный логин — тоже
состояние. Запись атомарная — процесс, убитый посреди неё, иначе оставил бы
не устаревший аккаунт, а потерянный.

Ротацию персона не делает намеренно: какую выбрать, когда вывести из оборота и
как разложить по прокси — политика, и она ваша. Библиотека тут гадала бы.

## Совместимость с requests

```python
import curlpro.requests as requests

r = requests.get("https://example.com/", timeout=10)
print(r.status_code, r.text[:200])
```

Существующий код меняет один импорт. Это подмножество, и оно об этом говорит:
аргумент, который обёртка выполнить не может, **отвергается с объяснением**, а
не игнорируется — тихо потерянный `verify=False` выглядит работающим ровно до
момента, когда это важно. Не реализованы адаптеры транспорта, хуки requests и
`stream=True` (для потока есть `Session.stream`, который держит соединение).

Исключения не дублируются: `requests.HTTPError` — это и есть
`curlpro.HTTPError`, поэтому старый `except` ловит новые ошибки.

## Куки между запусками

```python
with curlpro.Session("chrome-152-windows") as s:
    s.cookies.load_file("state.json")     # нет файла — не ошибка, первый запуск
    s.post("https://example.com/login", fields={"user": "u", "password": "p"})
    print(s.get("https://example.com/account").text)
    s.cookies.save("state.json")
```

Куки видны целиком — домен, путь, срок, флаги — и читается формат Netscape,
тот самый `cookies.txt` от `curl -c`, wget и расширений браузера. `load_file`
узнаёт его по содержимому, а не по имени:

```python
s.cookies["sid"]                          # значение
s.cookies.all()                           # полные записи
s.cookies.set("token", "xyz", domain="example.com")
s.cookies.load_file("cookies.txt")        # curl, wget, расширение браузера
s.cookies.save_netscape("cookies.txt")    # обратно, для чужого инструмента
```

## Мобильные профили и client hints

Chrome с версии 110 вырезал из `User-Agent` и модель, и версию системы: у любого
телефона там `Android 10; K`. Настоящее устройство живёт в подсказках
`sec-ch-ua-model` и `sec-ch-ua-platform-version`, и браузер шлёт их только после
того, как сайт запросил их заголовком `Accept-CH`.

```python
with curlpro.Session("chrome-152-android", device="random") as s:
    s.get(url)          # sec-ch-ua-model: "SM-S911B" — но только если сайт
                        # запросил подсказки; до этого их нет, как у браузера
```

Устройство выбирается один раз на сессию: настоящий клиент телефон между запросами
не меняет. Свой список задаётся параметром `devices`.

## Навигация и fetch

Браузер шлёт разные заголовки при переходе по адресу и при запросе `fetch()`
со страницы: у второго `accept: */*`, `sec-fetch-mode: cors`, `Origin` и `Referer`,
но нет `upgrade-insecure-requests` и `sec-fetch-user`. Кастомный заголовок бывает
только у fetch — поэтому набор переключается сам, по методу, типу тела и именам
заголовков:

```python
s.get(url)                                  # набор перехода по адресу
s.get(url, headers={"X-Api-Key": "k"})      # набор fetch: так шлёт браузер
s.get(url, headers={"X-Api-Key": "k"}, mode="navigate")   # если нужно иначе
```

## Профили как данные

Профиль — JSON с наследованием: потомок хранит только отличия. Вот **весь** профиль
Chrome 110 после схлопывания:

```json
{
  "based_on": "chrome-98-windows",
  "name": "chrome-110-windows",
  "tls": { "permute_extensions": true },
  "headers": { }
}
```

Вся разница с Chrome 98 на уровне TLS — перемешивание расширений, появившееся
именно в 110-й версии. Профиль можно добавить в рантайме или собрать из готового:

```python
curlpro.register_profile(json.load(open("chrome-153-windows.json")))

base = curlpro.Profile.from_file("profiles/chrome-152-windows.json")
base.derive("chrome-153-windows",
            headers={"user_agent": "...Chrome/153.0.0.0..."}).register()
```

### Новый браузер за четыре команды

```powershell
curlpro capture  -name chrome-152-windows -samples 5
curlpro validate -only chrome-152-windows -oracle https://localhost:8443/json -insecure
curlpro diff     chrome-151-windows chrome-152-windows
curlpro collapse -apply
```

`capture` поднимает стенд, приводит браузер, сводит сэмплы и пишет профиль;
`validate` сверяет отпечаток с эталоном; `diff` показывает дельту между версиями;
`collapse` сводит профили с одинаковым ClientHello в цепочки `based_on`.

Схема профиля — в [docs/PROFILE-SCHEMA.md](docs/PROFILE-SCHEMA.md), методика
снятия — в [docs/CAPTURE.md](docs/CAPTURE.md).

## Проверено замером

Отпечаток проверяется замером, а не рассуждением. Эталоны сняты с живых браузеров:

| Профиль | JA4 | Источник |
|---|---|---|
| `chrome-151-windows` | `t13d1516h2_8daaf6152771_806a8c22fdea` | [reference/](reference/), 6 сэмплов |
| `yandex-26.8-android` | `t13d1516h2_8daaf6152771_806a8c22fdea` | `tls.peet.ws` плюс свой стенд по USB |
| `chrome-152-android` | `t13d1517h2_8daaf6152771_cb7bf5808d99` | 5 сэмплов с Pixel 7 по USB |

Chrome 151 отсутствует в публичных корпусах: curl-impersonate доходит до 150,
wreq-util — до 149. Отпечаток HTTP/3 сверен с `quic.browserleaks.com`, порядок
заголовков HTTP/2 и HTTP/3 — собственным стендом `cmd/hcapture`, который разбирает
кадр HEADERS как он пришёл.

Скорость — 400 запросов, локальный стенд, переиспользуемое соединение:

| библиотека | req/s | медиана | |
|---|---|---|---|
| **curlpro** | **1775** | 0.53 ms | 100% |
| curl_cffi | 1352 | 0.70 ms | 76% |
| requests (без отпечатка) | 867 | 1.12 ms | 49% |

## Границы

Библиотека закрывает сетевой слой: TLS ClientHello, кадры HTTP/2 и HTTP/3, порядок
и регистр заголовков. Она **не** подделывает JS-отпечаток (canvas, WebGL,
`navigator`) — это уровень браузера, и для таких задач ответ Playwright.
Совпадение сетевого отпечатка необходимо, но не достаточно: современные системы
скорят JA4 вместе с JA4H, JA3S/JARM и поведенческим анализом.

Разбор HTML сюда намеренно не входит: это работа `selectolax` или `lxml`.

## Стек

```
Python (ctypes) → libcurlpro.{so,dll,dylib} → Go
                                               ├── uTLS  (ClientHello)
                                               ├── fhttp (HTTP/2)
                                               └── uquic (HTTP/3, вендор internal/h3)
```

Go выбран из-за двух возможностей uTLS: `ClientHelloSpec.UnmarshalJSON` — профиль
как данные, и `Fingerprinter.RawClientHello` — обучение профиля из захваченных
байтов. Вместе они замыкают цикл «снял браузер → получил профиль» без единой
строчки кода.

Язык кода и сообщений ошибок — английский, документации — русский.

## Документы

Начинать лучше с [docs/AUDIT-BRIEF.md](docs/AUDIT-BRIEF.md): он самодостаточен и
описывает текущее состояние, тогда как `ARCHITECTURE.md` писался в начале и местами
устарел.

| Файл | Содержание |
|---|---|
| [docs/AUDIT-BRIEF.md](docs/AUDIT-BRIEF.md) | **Срез состояния:** карта репозитория, инварианты («выглядит багом, но так задумано»), способы проверки |
| [docs/AUDIT-QUESTIONS.md](docs/AUDIT-QUESTIONS.md) | Известные долги, пробелы в проверке, места, где нужна помощь |
| [docs/PROFILE-SCHEMA.md](docs/PROFILE-SCHEMA.md) | Схема JSON-профиля, наследование `based_on`, полный список полей |
| [docs/CAPTURE.md](docs/CAPTURE.md) | Методика снятия эталона: команды, подводные камни, публичные оракулы |
| [docs/FINGERPRINT-SPEC.md](docs/FINGERPRINT-SPEC.md) | Форматы JA3/JA4/JA4H/Akamai, текущие значения браузеров, расхождения между сервисами |
| [docs/RESEARCH.md](docs/RESEARCH.md) | Разбор curl-impersonate, curl_cffi, uTLS, tls-client, httpcloak, wreq — по исходникам |
| [docs/HTTP3-RESEARCH.md](docs/HTTP3-RESEARCH.md) | HTTP/3: разбор оракулов, формат `perk`, расхождения QUIC-слоя |
| [ARCHITECTURE.md](ARCHITECTURE.md) · [ROADMAP.md](ROADMAP.md) | Выбор стека и границы подхода; этапы, риски, что осознанно не делаем |
| [docs/RELEASE.md](docs/RELEASE.md) | Выпуск версии: колёса на пяти платформах, доверенная публикация на PyPI |
| [internal/h3/README.md](internal/h3/README.md) | Вендоренный пакет http3: что изменено против апстрима и зачем |
| `docs/STAGE*-RESULTS.md` | Хронология по этапам: что замерено, что найдено и чем закончилось. Ключевые — [14](docs/STAGE14-RESULTS.md) (внешний аудит, 20 находок), [15](docs/STAGE15-RESULTS.md) (набор `fetch`, QPACK, захват QUIC), [16](docs/STAGE16-RESULTS.md) (порядок заголовков HTTP/3, CONNECT после 407) |

## Лицензия

Apache 2.0, текст — в [LICENSE](LICENSE). Сторонний код и его лицензии перечислены
в [NOTICE](NOTICE): проект стоит на uTLS и uquic (BSD-3-Clause), fhttp и
quic-go/qpack (MIT), и содержит копию пакета `http3` из uquic с правками под
отпечаток — они описаны в [internal/h3/README.md](internal/h3/README.md).

Профили браузеров — данные, а не код: часть снята собственными замерами живых
браузеров, часть импортирована из сигнатур curl-impersonate.
