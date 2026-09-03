# curlPro

Python-библиотека для HTTP-запросов с подделкой сетевого отпечатка браузера.

**Статус:** этапы 0–5 пройдены (кроме HTTP/3). Работает Python-библиотека поверх
Go-ядра: 44 профиля в JSON (Chrome 98–151, Edge, Firefox, Safari, Tor), отпечаток
подтверждён на `tls.browserleaks.com`, скорость выше curl_cffi.

```python
import curlpro

curlpro.load_profiles("profiles")
with curlpro.Session("chrome-151-windows") as s:
    r = s.get("https://tls.browserleaks.com/json")
    print(r.json()["ja4"])      # t13d1516h2_8daaf6152771_806a8c22fdea
```

Есть HTTP/1.1, HTTP/2 и HTTP/3, куки, редиректы, прокси (HTTP CONNECT и SOCKS5),
распаковка `gzip`/`deflate`/`br`/`zstd`, контроль набора и порядка заголовков,
асинхронный API:

```python
async with curlpro.AsyncSession("firefox-144-macos", proxy="socks5://127.0.0.1:1080") as s:
    results = await asyncio.gather(*(s.get(u) for u in urls))

# HTTP/3 — отдельный транспорт, выбирается явно
with curlpro.Session("chrome-151-windows", http3=True) as s:
    print(s.get("https://quic.browserleaks.com/fp").json()["h3_text"])
    # 1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p — как Chrome
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

## Задача

Существующие решения (`curl_cffi`, `tls-client`) хранят профили браузеров в компилируемом
коде. Новый Chrome выходит каждые 4 недели, и каждый раз это правка C или Go, пересборка
и релиз. У `curl_cffi` есть путь через данные, но он закрыт платным API.

Здесь профиль браузера — JSON-файл. Обновление под новую версию — правка данных,
включая возможность добавить профиль из Python в рантайме, не дожидаясь релиза библиотеки.

## Документы

| Файл | Содержание |
|---|---|
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
| [docs/STAGE8-RESULTS.md](docs/STAGE8-RESULTS.md) | CI и колёса: почему валидация по расписанию, сборка на пяти платформах |
| [docs/HTTP3-RESEARCH.md](docs/HTTP3-RESEARCH.md) | HTTP/3: разбор оракулов, формат `perk`, три расхождения QUIC-слоя |
| [internal/h3/README.md](internal/h3/README.md) | Вендоренный пакет http3: что изменено против апстрима и зачем |

## Снятые эталоны

| Профиль | JA4 | Источник |
|---|---|---|
| `chrome-151-windows` | `t13d1516h2_8daaf6152771_806a8c22fdea` | [reference/](reference/), 6 сэмплов |

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
