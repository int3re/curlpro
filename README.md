# curlPro

*[English summary](README.en.md) — документация проекта ведётся на русском.*

Python-библиотека для HTTP-запросов с подделкой сетевого отпечатка браузера.

**Статус:** этапы 0–8 пройдены, долги роадмапа закрыты (этап 15). Python-библиотека
поверх Go-ядра: 47 профилей в JSON (Chrome 98–152, Edge, Firefox, Safari, Tor,
Яндекс.Браузер; мобильные — Chrome и Яндекс для Android, Safari для iOS),
HTTP/1.1, HTTP/2, HTTP/3 и WebSocket, отпечаток подтверждён на
`tls.browserleaks.com` и `quic.browserleaks.com`, скорость выше curl_cffi.

```python
import curlpro

curlpro.load_profiles("profiles")
with curlpro.Session("chrome-151-windows") as s:
    r = s.get("https://tls.browserleaks.com/json")
    print(r.json()["ja4"])      # t13d1516h2_8daaf6152771_806a8c22fdea
```

Есть HTTP/1.1, HTTP/2, HTTP/3 и WebSocket, куки, редиректы, прокси
(HTTP CONNECT и SOCKS5), распаковка `gzip`/`deflate`/`br`/`zstd`, потоковая
отправка файлов, контроль набора и порядка заголовков, асинхронный API:

```python
# Асинхронность нативная: запрос уходит в горутину, поток на процесс один.
# 128 запросов по 0.3 с занимают 0.37 с, а не 1.27 с, как через пул потоков.
async with curlpro.AsyncSession("firefox-144-macos", proxy="socks5://127.0.0.1:1080") as s:
    results = await asyncio.gather(*(s.get(u) for u in urls))

    # Потоковое чтение и WebSocket там же и так же: без пула потоков
    async with s.stream("GET", url) as r:
        async for chunk in r.iter_content():
            out.write(chunk)
    async with s.websocket("wss://example.com/ws") as ws:
        await ws.send("привет")
        print(await ws.recv())

# HTTP/3 включается сам, как в браузере: первый запрос идёт по TCP, а увидев
# в ответе Alt-Svc, клиент со следующего переходит на QUIC. Если QUIC не
# проходит, запрос откатывается на TCP, и попытка какое-то время не повторяется.
with curlpro.Session("chrome-151-windows") as s:
    print(s.get("https://cloudflare-quic.com/").proto)   # HTTP/2.0
    print(s.get("https://cloudflare-quic.com/").proto)   # HTTP/3.0

# Явное включение тоже осталось: тогда первый же запрос уходит по QUIC
with curlpro.Session("chrome-151-windows", http3=True) as s:
    print(s.get("https://quic.browserleaks.com/fp").json()["h3_text"])
    # 1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p — как Chrome

# WebSocket: рукопожатие по шаблону профиля, permessage-deflate поддержан
with curlpro.Session() as s:
    with s.websocket("wss://echo.websocket.org/", max_message_size=1 << 20) as ws:
        ws.send("привет")          # str → текстовый кадр
        ws.send(b"\x00\xff")       # bytes → двоичный
        for message in ws:         # до закрытия сервером (WebSocketClosed);
            print(message)         # таймаут тишины — CurlProError с code="timeout"

# Большой файл отправляется потоком, а не через память
with curlpro.Session() as s:
    s.post("https://example.com/upload", body_file="archive.zip")

# Повторы, переопределения на запрос и заголовки сессии
with curlpro.Session(retries=3, proxy="socks5://127.0.0.1:1080") as s:
    s.headers["X-Api-Key"] = "secret"     # во всех последующих запросах
    s.get(url, timeout=2.0)               # свой предел на этот запрос
    s.get(url, timeout=(3, 30))           # отдельно на соединение и на всё
    s.get(url, allow_redirects=False)     # без перехода по 3xx
    s.get(url, proxy=False)               # в обход прокси сессии
    s.get(url, retries=0)                 # без повторов, хотя у сессии они есть
    s.get(url, mode="navigate")           # набор перехода по адресу, не fetch
    s.get(url, protocol="h3")             # этот запрос — по QUIC
    s.get(url, protocol=1.1)              # а этот — по HTTP/1.1
    s.get(url, default_headers=False)     # без заголовков профиля, только свои
    s.headers.clear()                     # остаются только профильные
    with s.stream("GET", url, timeout=5) as r:   # те же аргументы, что у request()
        first = next(r.iter_content())    # закрыть, не дочитав, — дёшево

# Протокол выбирается на каждый запрос: `1.1`/`http1`, `2`/`h2`, `3`/`h3`.
# Указание сильнее и опций сессии, и перехода по Alt-Svc. Замер против
# cloudflare-quic.com в одной сессии:
with curlpro.Session("chrome-151-windows") as s:
    s.get(url).proto                      # HTTP/2.0 — первый запрос
    s.get(url).proto                      # HTTP/3.0 — перешли по Alt-Svc
    s.get(url, protocol="h2").proto       # HTTP/2.0 — но этот остался на TCP
    s.get(url, protocol=3).proto          # HTTP/3.0

# h2 при этом не урезает список ALPN до одного значения: такого не шлёт
# ни один браузер. Если сервер согласовал http/1.1, запрос падает с ошибкой,
# а не уезжает молча не по тому протоколу.

# Соединение между запросами переиспользуется — так делает браузер, и TLS
# не пересогласовывается заново. Выключается на сессии:
with curlpro.Session(keep_alive=False) as s:   # своё соединение на каждый запрос
    s.get(url)

# Мобильные профили умеют представляться разными телефонами
with curlpro.Session("chrome-152-android", device="random") as s:
    s.get(url)          # sec-ch-ua-model: "SM-S911B" — но только если сайт
                        # запросил подсказки заголовком Accept-CH
```

## Скорость

400 запросов, локальный стенд, переиспользуемое соединение:

| библиотека | req/s | медиана | |
|---|---|---|---|
| **curlpro** | **1775** | 0.53 ms | 100% |
| curl_cffi | 1352 | 0.70 ms | 76% |
| requests (без отпечатка) | 867 | 1.12 ms | 49% |

Профиль можно добавить не дожидаясь релиза — ради этого всё и затевалось:

```python
curlpro.register_profile({
    "name": "chrome-152-windows",
    "based_on": "chrome-151-windows",
    "headers": {"user_agent": "...Chrome/152.0.0.0..."},
})

# то же объектом, если профиль удобнее собирать из существующего
base = curlpro.Profile.from_file("profiles/chrome-152-windows.json")
base.derive("chrome-153-windows",
            headers={"user_agent": "...Chrome/153.0.0.0..."}).register()
```

## Для парсера

Сессия переносится между запусками: авторизация не теряется при перезапуске.

```python
with curlpro.Session("chrome-152-windows") as s:
    s.cookies.load_file("state.json")     # нет файла — не ошибка, первый запуск
    s.post("https://example.com/login", fields={"user": "u", "password": "p"})
    page = s.get("https://example.com/account")
    print(page.text)                      # кодировка из Content-Type,
                                          # BOM или <meta charset>
    s.cookies.save("state.json")
```

Куки видны целиком — домен, путь, срок, флаги:

```python
s.cookies["sid"]                          # значение
s.cookies.all()                           # полные записи
s.cookies.set("token", "xyz", domain="example.com")
s.cookies.clear()
```

Читается и формат Netscape — тот самый `cookies.txt` от `curl -c`, wget
и расширений браузера. `load_file` узнаёт его по содержимому, а не по имени:

```python
s.cookies.load_file("cookies.txt")        # curl, wget, расширение браузера
s.cookies.save_netscape("cookies.txt")    # обратно, для чужого инструмента
```

Перехватчики дают вклиниться до отправки и после ответа, не трогая саму
библиотеку:

```python
with curlpro.Session() as s:
    @s.on_request
    def sign(meta):                       # meta можно менять на месте
        meta.setdefault("headers", {})["X-Signature"] = sign_it(meta["url"])

    @s.on_response
    def log(resp):
        print(resp.status, resp.url)
```

Адрес узла можно подменить, не трогая имя, — как `--resolve` у curl. Полезно,
когда нужно попасть на конкретный сервер за балансировщиком, или когда стенд
должен отвечать под настоящим именем:

```python
curlpro.Session(resolve={"example.com:443": "10.0.0.7"}, ip_version="4")
```

Имя в SNI и заголовке `Host` остаётся прежним, поэтому отпечаток не меняется.

Привычные аргументы requests на месте, и ответ отвечает тем же:

```python
r = s.get(url, params={"page": 2}, auth=("user", "pw"))
r.raise_for_status()                  # curlpro.HTTPError со статусом и ответом
r.elapsed, r.history, r.cookies       # время, цепочка редиректов, куки ответа
with s.stream("GET", url) as chunked:
    for line in chunked.iter_lines(): # построчно, не собирая тело
        ...
```

Сетевая часть тоже без сюрпризов: свой корневой сертификат
(`verify="ca.pem"`), взаимная аутентификация (`cert=("client.pem", "key.pem")`),
прокси из переменных окружения с учётом `NO_PROXY` (`trust_env=True`),
предел размера ответа (`max_response_size`) — без него сервер с бесконечным
телом съедает память процесса.

Разбор HTML сюда намеренно не входит: это работа `selectolax` или `lxml`.

## Два набора заголовков

Браузер шлёт разные заголовки при переходе по адресу и при запросе `fetch()`
со страницы: у второго `accept: */*`, `sec-fetch-mode: cors`, `Origin`
и `Referer`, но нет `upgrade-insecure-requests` и `sec-fetch-user`. Кастомный
заголовок бывает только у fetch, поэтому библиотека переключает набор сама —
по методу, типу тела и именам заголовков:

```python
with curlpro.Session() as s:
    s.get(url)                                  # набор перехода по адресу
    s.get(url, headers={"X-Api-Key": "k"})      # набор fetch: так шлёт браузер
    s.get(url, headers={"X-Api-Key": "k"}, mode="navigate")   # если нужно иначе
```

## Добавить новый браузер

```powershell
curlpro capture  -name chrome-152-windows -samples 5
curlpro validate -only chrome-152-windows -oracle https://localhost:8443/json -insecure
curlpro diff     chrome-151-windows chrome-152-windows
curlpro collapse -apply
```

`capture` поднимает стенд, приводит браузер, сводит сэмплы и пишет профиль;
`validate` сверяет отпечаток с эталоном; `diff` показывает дельту между версиями;
`collapse` сводит профили с одинаковым ClientHello в цепочки `based_on`.

Насколько дельта-модель работает, видно на самих данных — вот весь профиль
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
именно в 110-й версии.

## Сборка

```powershell
.\build.ps1                                        # → dist/curlpro.dll
cd python; $env:PYTHONPATH='.'; python -m pytest tests
```

Нужны Go и C-компилятор (MinGW-w64 на Windows) — cgo без него не соберёт
`c-shared`. Go-часть (`cmd/probe`, `cmd/import`) собирается и без него.

## Лицензия

Apache 2.0, текст — в [LICENSE](LICENSE). Сторонний код и его лицензии
перечислены в [NOTICE](NOTICE): проект стоит на uTLS и uquic (BSD-3-Clause),
fhttp и quic-go/qpack (MIT), и содержит копию пакета `http3` из uquic
с правками под отпечаток — они описаны в
[internal/h3/README.md](internal/h3/README.md).

Профили браузеров — данные, а не код: часть снята собственными замерами
живых браузеров, часть импортирована из сигнатур curl-impersonate.

## Задача

Существующие решения (`curl_cffi`, `tls-client`) хранят профили браузеров в компилируемом
коде. Новый Chrome выходит каждые 4 недели, и каждый раз это правка C или Go, пересборка
и релиз. У `curl_cffi` есть путь через данные, но он закрыт платным API.

Здесь профиль браузера — JSON-файл. Обновление под новую версию — правка данных,
включая возможность добавить профиль из Python в рантайме, не дожидаясь релиза библиотеки.

## Документы

Начинать лучше с [docs/AUDIT-BRIEF.md](docs/AUDIT-BRIEF.md): он самодостаточен и
описывает текущее состояние, тогда как `ARCHITECTURE.md` писался в начале и
местами устарел.

| Файл | Содержание |
|---|---|
| [docs/AUDIT-BRIEF.md](docs/AUDIT-BRIEF.md) | **Срез состояния:** карта репозитория, инварианты («выглядит багом, но так задумано»), способы проверки |
| [docs/AUDIT-QUESTIONS.md](docs/AUDIT-QUESTIONS.md) | Известные долги, пробелы в проверке, места, где нужна помощь |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Выбор стека и обоснование, границы подхода |
| [ROADMAP.md](ROADMAP.md) | Этапы реализации, что осознанно не делаем, риски |
| [docs/RESEARCH.md](docs/RESEARCH.md) | Разбор curl-impersonate, curl_cffi, uTLS, tls-client, httpcloak, wreq — по исходникам |
| [docs/FINGERPRINT-SPEC.md](docs/FINGERPRINT-SPEC.md) | Точные форматы JA3/JA4/JA4H/Akamai, текущие значения браузеров, расхождения между сервисами проверки |
| [docs/CAPTURE.md](docs/CAPTURE.md) | Методика снятия эталона: команды, подводные камни, публичные эндпоинты, готовые корпуса |
| [docs/PROFILE-SCHEMA.md](docs/PROFILE-SCHEMA.md) | Схема JSON-профиля, наследование `based_on`, полный список полей |
| [docs/STAGE0-RESULTS.md](docs/STAGE0-RESULTS.md) | Снятие эталона Chrome 151, разобранные расхождения, заметки по инструментам Windows |
| [docs/STAGE1-RESULTS.md](docs/STAGE1-RESULTS.md) | Go-ядро: совпадение отпечатка, ловушка с кешированием спеки |
| [docs/STAGE2-RESULTS.md](docs/STAGE2-RESULTS.md) | Профили в JSON: разведка кодека uTLS, пост-процессор ECH, исправленный дефект захвата |
| [docs/STAGE3-RESULTS.md](docs/STAGE3-RESULTS.md) | Импорт 43 сигнатур, три ошибки JA3N, несогласованность корпуса |
| [docs/STAGE4-RESULTS.md](docs/STAGE4-RESULTS.md) | FFI и Python: устройство биндинга, проверка на browserleaks, ловушка ctypes с утечкой |
| [docs/STAGE5-RESULTS.md](docs/STAGE5-RESULTS.md) | Полноценный клиент: бенчмарк, найденная порча бинарных тел, редиректы и куки |
| [docs/STAGE6-RESULTS.md](docs/STAGE6-RESULTS.md) | Инструменты: validate нашёл два нерабочих профиля, почему JA4 колеблется |
| [docs/STAGE7-RESULTS.md](docs/STAGE7-RESULTS.md) | HTTP/3, две гонки в QUIC, priority по семействам, схлопывание профилей |
| [docs/STAGE14-RESULTS.md](docs/STAGE14-RESULTS.md) | Внешний аудит: 20 подтверждённых находок и что по ним исправлено |
| [docs/STAGE15-RESULTS.md](docs/STAGE15-RESULTS.md) | Закрытие долгов: набор `fetch`, динамическая таблица QPACK, GOAWAY, захват QUIC |
| [docs/STAGE16-RESULTS.md](docs/STAGE16-RESULTS.md) | Порядок заголовков HTTP/3, CONNECT после 407, окно deflate, `keep_alive` |
| [docs/RELEASE.md](docs/RELEASE.md) | Выпуск версии: колёса на пяти платформах, доверенная публикация на PyPI |
| [docs/STAGE8-RESULTS.md](docs/STAGE8-RESULTS.md) | CI и колёса: почему валидация по расписанию, сборка на пяти платформах |
| [docs/STAGE9-RESULTS.md](docs/STAGE9-RESULTS.md) | HTTP/1.1 (регистр заголовков), потоковая отправка, WebSocket |
| [docs/STAGE10-RESULTS.md](docs/STAGE10-RESULTS.md) | Повторы, переопределения на запрос, заголовки сессии; два найденных бага |
| [docs/STAGE11-RESULTS.md](docs/STAGE11-RESULTS.md) | Закрытие багов аудита: WebSocket ломал отпечаток сессии, HTTP/3 игнорировал прокси |
| [docs/STAGE12-RESULTS.md](docs/STAGE12-RESULTS.md) | Пул соединений: занятость, вытеснение по указателю, ограничители роста |
| [docs/STAGE13-RESULTS.md](docs/STAGE13-RESULTS.md) | Слоты заголовков и якорь; три бага, вскрытых объединением путей; прогоны на устаревшей DLL |
| [docs/PLAN-SESSION-FEATURES.md](docs/PLAN-SESSION-FEATURES.md) | Проектные материалы к этапу 10 с разбором разногласий |
| [docs/HTTP3-RESEARCH.md](docs/HTTP3-RESEARCH.md) | HTTP/3: разбор оракулов, формат `perk`, три расхождения QUIC-слоя |
| [internal/h3/README.md](internal/h3/README.md) | Вендоренный пакет http3: что изменено против апстрима и зачем |

## Снятые эталоны

| Профиль | JA4 | Источник |
|---|---|---|
| `chrome-151-windows` | `t13d1516h2_8daaf6152771_806a8c22fdea` | [reference/](reference/), 6 сэмплов |
| `yandex-26.8-android` | `t13d1516h2_8daaf6152771_806a8c22fdea` | [reference/](reference/): `tls.peet.ws` плюс свой стенд по USB |
| `chrome-152-android` | `t13d1517h2_8daaf6152771_cb7bf5808d99` | [reference/](reference/), 5 сэмплов с Pixel 7 по USB |

Chrome 151 отсутствует в публичных корпусах — curl-impersonate доходит до 150,
wreq-util до 149.

## Стек

```
Python (ctypes) → libcurlpro.{so,dll,dylib} → Go
                                               ├── uTLS  (ClientHello)
                                               └── fhttp (HTTP/2)
```

Go выбран из-за двух возможностей uTLS: `ClientHelloSpec.UnmarshalJSON` (профиль как данные)
и `Fingerprinter.RawClientHello` (обучение профиля из захваченных байтов). Вместе они
замыкают цикл «снял браузер → получил профиль» без единой строчки кода.

## Границы

Библиотека закрывает сетевой слой: TLS ClientHello, кадры HTTP/2 и HTTP/3, порядок
и регистр заголовков. Она **не** подделывает JS-отпечаток (canvas, WebGL, navigator) —
это уровень браузера. Совпадение сетевого отпечатка необходимо, но не достаточно:
современные системы скорят JA4 вместе с JA4H, JA3S/JARM и поведенческим анализом.
