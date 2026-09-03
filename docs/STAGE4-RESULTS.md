# Этап 4 — результаты

Дата: 2026-09-01.

Цель: нативная библиотека и Python-обёртка, включая регистрацию профиля
в рантайме — ту возможность, ради которой проект и затевался.

## Результат

```python
import curlpro

curlpro.load_profiles("profiles")            # 44 профиля
with curlpro.Session("chrome-151-windows") as s:
    r = s.get("https://tls.browserleaks.com/json")
    print(r.json()["ja4"])                   # t13d1516h2_8daaf6152771_806a8c22fdea
```

`go test ./internal/...` — 9 тестов, `pytest python/tests` — 5 тестов, все проходят.

## Проверка на внешнем оракуле

Раньше сверка шла против локального стенда. Здесь — против `tls.browserleaks.com`,
то есть настоящего интернета и независимой реализации подсчёта.

| Профиль | JA4 | Akamai HTTP/2 |
|---|---|---|
| chrome-151-windows | `t13d1516h2_8daaf6152771_806a8c22fdea` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| firefox-144-macos | `t13d1717h2_5b57614c22b0_3cbfd9057e0d` | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` |
| safari-26.0-macos | `t13d2014h2_a09f3c656075_d0a99439f9b1` | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` |

JA4 Chrome совпал с эталоном, снятым с живого браузера на этапе 0.
JA3N Firefox (`e4147a4860c1f347354f0a84d8787c02`) совпал с записанным в корпусе
curl-impersonate. Все три Akamai-строки совпали с [FINGERPRINT-SPEC.md](FINGERPRINT-SPEC.md),
написанным до начала реализации.

## Заодно закрыт вопрос из этапа 0

На стенде секция PRIORITY выходила `1:1:0:256`, в корпусе curl-impersonate — `0`.
На browserleaks получилось **`0`**, как в корпусе.

Это окончательно подтверждает разбор из [STAGE0-RESULTS.md](STAGE0-RESULTS.md):
fingerproxy засчитывает в `Priorities[]` priority-флаг, приходящий внутри
HEADERS-кадра, тогда как канонический формат Akamai учитывает только
самостоятельные PRIORITY-кадры. Расхождения между Chrome 150 и 151 не было —
расходились две реализации подсчёта.

## Устройство

```
Python (ctypes)  →  dist/curlpro.dll  →  Go
   session.py         lib/curlpro.go      internal/client  → uTLS + fhttp
   profiles.py                            internal/profile
   _ffi.py
```

**Обмен JSON-строками через `char*`.** Медленнее структур, но избавляет от
синхронизации C-заголовка с каждым биндингом: добавление поля не ломает ABI.

**Единый конверт ответа** `{"ok":…, "error":…, "data":…}`. Биндинг всегда получает
валидный JSON и разбирает ошибку из поля, а не из кода возврата.

**Восемь экспортов** — сознательно мало (у httpcloak их 102, у tls-client 6):
`curlpro_free`, `curlpro_version`, `curlpro_profiles_load_dir`,
`curlpro_profile_register`, `curlpro_profiles_list`, `curlpro_session_new`,
`curlpro_session_close`, `curlpro_request`.

**Владение памятью.** Каждая строка от библиотеки выделена в C и освобождается
через `curlpro_free`. В `_ffi.py` это делает `_call()` в `finally`, наружу
указатели не выдаются.

Тонкость ctypes: `restype` объявлен как `c_void_p`, а не `c_char_p`. Иначе ctypes
конвертирует результат в `bytes` и **теряет исходный указатель**, который нужен
для освобождения, — тихая утечка на каждом вызове.

## Ключевая возможность

`test_register_profile_at_runtime` проверяет то, ради чего выбирался весь стек:

```python
curlpro.register_profile({
    "name": "chrome-152-test",
    "based_on": "chrome-151-windows",
    "headers": {"user_agent": "...Chrome/152.0.0.0..."},
})
```

Профиль сразу пригоден для запросов, TLS-отпечаток унаследован от родителя.
Ни пересборки нативной части, ни ожидания релиза, ни платного API — то, чего
нет ни у curl_cffi (обновления профилей за `IMPERSONATE_API_KEY`), ни у
tls-client (нужен Go-код, мерж PR и пересборка библиотек под 8 платформ).

## Сборка

cgo требует C-компилятора; на этой машине поставлен MinGW-w64 (GCC 16.2.0,
x86_64-ucrt-posix) в `D:\mingw64`. Скрипт [build.ps1](../build.ps1) находит его
сам среди типичных путей.

```powershell
.\build.ps1                        # → dist/curlpro.dll (16 МБ)
cd python; $env:PYTHONPATH='.'; python -m pytest tests
```

`_ffi.py` ищет библиотеку в трёх местах по порядку: `CURLPRO_LIBRARY`,
`curlpro/lib/` (как в wheel), `dist/` (сборка из репозитория).

## Что осталось

- **Только HTTP/2.** При ALPN `http/1.1` соединение отклоняется с явной ошибкой.
  Настоящий Chrome умеет оба; профили Safari 15 и старые Firefox без h2 работать
  не будут.
- **Прокси не проверен.** Код CONNECT написан, но живого теста не было.
- **Нет cookie-jar и редиректов** — сейчас это забота вызывающей стороны.
- **Асинхронного API нет**, только синхронный.
- Сборка wheels под Linux/macOS — этап 6.
