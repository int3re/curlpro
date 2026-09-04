"""Сессия и функции уровня модуля в стиле requests."""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlencode, urlsplit, urlunsplit

from ._ffi import HTTPError, _call, call_framed, encode
from .cookies import Cookies
from .encoding import detect as detect_encoding
from .headers import SessionHeaders
from .profiles import ensure_loaded
from .proxies import proxy_for as env_proxy
from .stream import StreamResponse
from .websocket import WebSocket, connect as ws_connect

DEFAULT_PROFILE = "chrome-151-windows"


def _proxy_override(proxy: str | bool | None) -> str | None:
    """Переводит аргумент proxy в значение для нативной части.

    Три состояния, и их приходится различать: ``None`` — наследовать прокси
    сессии, ``False`` — идти напрямую в обход него, строка — использовать
    указанный. Одной строкой это не выразить, потому что пустая строка уже
    занята под «напрямую».
    """
    if proxy is None:
        return None
    if proxy is False:
        return ""
    if proxy is True:
        raise ValueError("proxy=True бессмысленно: укажите адрес или False")
    if not isinstance(proxy, str):
        raise TypeError(f"proxy должен быть строкой, False или None, получено {type(proxy).__name__}")
    return proxy


def _retry_config(
    retries: int | None,
    statuses: Iterable[int] | None,
    methods: Iterable[str] | None,
    backoff: float | None,
    max_backoff: float | None,
    respect_retry_after: bool,
) -> dict[str, Any] | None:
    """Собирает политику повторов.

    ``None`` — «не задано»: у сессии это «без повторов», у запроса —
    «взять из сессии». Ноль — явное «без повторов»: так запрос может
    отключить повторы, которые заданы сессии. Раньше ноль схлопывался
    в ``None`` и отключить их на один запрос было нельзя.

    По умолчанию повторяются только идемпотентные методы: повтор POST может
    создать второй заказ, потому что сервер мог обработать запрос и не успеть
    ответить. Разрешить это можно явным списком в ``retry_methods``.
    """
    if retries is None:
        return None
    return {
        "attempts": int(retries),
        "statuses": list(statuses) if statuses else None,
        "methods": list(methods) if methods else None,
        "backoff_ms": int((backoff or 0.2) * 1000),
        "max_backoff_ms": int((max_backoff or 10.0) * 1000),
        "respect_retry_after": respect_retry_after,
    }


def _build_multipart(
    fields: Mapping[str, str] | None,
    files: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], bytes]:
    """Готовит описание формы и склеенное содержимое файлов.

    Границу формы генерирует нативная часть в стиле профиля: её вид отличает
    Chrome от Firefox и потому относится к отпечатку, а не к деталям кодирования.

    Значение ``files`` — либо ``bytes``, либо кортеж
    ``(filename, content)`` / ``(filename, content, content_type)``.
    """
    fields = dict(fields or {})
    described: list[dict[str, str]] = []
    sizes: list[int] = []
    blob = bytearray()

    for field, value in (files or {}).items():
        content_type = ""
        if isinstance(value, (bytes, bytearray)):
            filename, content = field, bytes(value)
        elif isinstance(value, tuple):
            if len(value) == 2:
                filename, content = value
            elif len(value) == 3:
                filename, content, content_type = value
            else:
                raise ValueError(f"files[{field!r}]: ожидался кортеж из 2 или 3 элементов")
        else:
            raise TypeError(f"files[{field!r}]: ожидались bytes или кортеж")

        if isinstance(content, str):
            content = content.encode("utf-8")
        described.append(
            {"field": field, "filename": filename, "content_type": content_type}
        )
        sizes.append(len(content))
        blob += content

    meta = {
        "fields": fields,
        "order": list(fields),
        "files": described,
        "file_sizes": sizes,
    }
    return meta, bytes(blob)


def _with_params(url: str, params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None) -> str:
    """Дописывает параметры запроса к адресу.

    Уже имеющаяся строка запроса сохраняется: в requests так же, и адрес
    вида "/search?lang=ru" с параметрами не теряет свой lang.
    """
    if not params:
        return url
    items: list[tuple[str, str]] = []
    pairs = params.items() if hasattr(params, "items") else params
    for key, value in pairs:
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            items.extend((key, str(v)) for v in value if v is not None)
        elif isinstance(value, bool):
            items.append((key, "true" if value else "false"))
        else:
            items.append((key, str(value)))
    if not items:
        return url
    parts = urlsplit(url)
    query = urlencode(items, doseq=False)
    if parts.query:
        query = parts.query + "&" + query
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _auth_header(auth: tuple[str, str] | str | None) -> str | None:
    """Базовая авторизация: пара превращается в заголовок, строка идёт как есть."""
    if auth is None:
        return None
    if isinstance(auth, str):
        return auth
    user, password = auth
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return "Basic " + token


def _request_meta(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
    auth: tuple[str, str] | str | None = None,
    data: bytes | str | None = None,
    json_body: Any = None,
    files: Mapping[str, Any] | None = None,
    fields: Mapping[str, str] | None = None,
    body_file: str | Any = None,
    header_order: Iterable[str] | None = None,
    default_headers: bool | None = None,
    timeout: float | None = None,
    allow_redirects: bool | None = None,
    max_redirects: int | None = None,
    retries: int | None = None,
    retry_statuses: Iterable[int] | None = None,
    retry_methods: Iterable[str] | None = None,
    retry_backoff: float | None = None,
    retry_max_backoff: float | None = None,
    respect_retry_after: bool = True,
    proxy: str | bool | None = None,
    mode: str | None = None,
) -> tuple[dict[str, Any], bytes]:
    # params и auth — привычные аргументы requests; здесь они превращаются
    # в адрес со строкой запроса и в обычный заголовок, дальше всё как обычно.
    url = _with_params(url, params)
    if credentials := _auth_header(auth):
        headers = dict(headers or {})
        headers.setdefault("Authorization", credentials)
    """Собирает кадр запроса. Общий для request() и stream(): раньше у потока
    была своя урезанная копия без таймаута, прокси, повторов и файлов."""
    hdrs = dict(headers or {})
    multipart = None

    if body_file is not None:
        if data is not None or json_body is not None or files or fields:
            raise ValueError("body_file несовместим с data, json_body и multipart")
        body_file = str(body_file)
    elif files or fields:
        if data is not None or json_body is not None:
            raise ValueError("multipart несовместим с data и json_body")
        multipart, data = _build_multipart(fields, files)
    elif json_body is not None:
        if data is not None:
            raise ValueError("укажите либо data, либо json_body, не оба")
        data = encode(json_body)
        hdrs.setdefault("content-type", "application/json")

    if isinstance(data, str):
        data = data.encode("utf-8")

    meta = {
        "method": method.upper(),
        "url": url,
        "headers": hdrs,
        "header_order": list(header_order) if header_order else None,
        "no_default_headers": default_headers is False,
        "multipart": multipart,
        "body_file": body_file or "",
        # None означает «взять из сессии»; ноль — осмысленное значение,
        # поэтому передаётся именно отсутствие, а не подстановка.
        "timeout_ms": None if timeout is None else int(timeout * 1000),
        "follow_redirects": allow_redirects,
        "max_redirects": max_redirects,
        "retry": _retry_config(
            retries, retry_statuses, retry_methods,
            retry_backoff, retry_max_backoff, respect_retry_after,
        ),
        # None — взять из сессии, False — идти напрямую в обход
        # сессионного прокси, строка — использовать указанный.
        "proxy": _proxy_override(proxy),
        # None — режим сессии; "navigate" или "fetch" — явный набор заголовков.
        "mode": mode or "",
    }
    return meta, data or b""


class Redirect:
    """Шаг цепочки редиректов: куда ответил сервер и каким статусом."""

    __slots__ = ("status", "url", "location")

    def __init__(self, status: int, url: str, location: str):
        self.status = status
        self.url = url
        self.location = location

    def __repr__(self) -> str:
        return f"<Redirect {self.status} {self.url} → {self.location}>"


class Response:
    """Ответ сервера."""

    __slots__ = ("status", "proto", "headers", "content", "url", "elapsed",
                 "history", "_encoding")

    def __init__(self, status: int, proto: str, headers: dict[str, list[str]],
                 content: bytes, url: str = "", elapsed: float = 0.0,
                 history: list | None = None):
        self.status = status
        self.proto = proto
        self.headers = headers
        self.content = content
        self.url = url
        #: Время запроса целиком, включая редиректы и повторы, в секундах.
        self.elapsed = elapsed
        #: Промежуточные ответы цепочки редиректов, от первого к последнему.
        self.history: list[Redirect] = history or []
        self._encoding: str | None = None

    @property
    def cookies(self) -> dict[str, str]:
        """Куки, установленные этим ответом.

        Именно этим, а не всей сессией: у сессии для этого есть свой
        ``cookies``, куда попадают в том числе куки прошлых запросов.
        """
        out: dict[str, str] = {}
        for name, values in self.headers.items():
            if name.lower() != "set-cookie":
                continue
            for v in values:
                pair = v.split(";", 1)[0]
                key, _, value = pair.partition("=")
                if key.strip():
                    out[key.strip()] = value.strip()
        return out

    @property
    def encoding(self) -> str:
        """Кодировка тела: из Content-Type, затем BOM, затем сам документ.

        Определяется один раз и запоминается. Присваивание перекрывает
        определённое значение — сайт может объявить кодировку неверно,
        и тогда решать вызывающему.
        """
        if self._encoding is None:
            self._encoding = detect_encoding(self.content, self.header("content-type"))
        return self._encoding

    @encoding.setter
    def encoding(self, value: str) -> None:
        self._encoding = value

    @property
    def text(self) -> str:
        return self.content.decode(self.encoding, errors="replace")

    def json(self) -> Any:
        """Разбор JSON.

        Байты отдаются как есть: json.loads сам распознаёт UTF-8, UTF-16
        и UTF-32 по RFC 8259. Кодировка из заголовка тут не годится —
        сайты объявляют в ней что угодно, а тело всё равно UTF-8.
        """
        return json.loads(self.content)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def raise_for_status(self) -> "Response":
        """Поднимает :class:`HTTPError` при статусе 4xx или 5xx."""
        if not self.ok:
            raise HTTPError(f"HTTP {self.status} для {self.url}", response=self)
        return self

    def header(self, name: str) -> str | None:
        """Первое значение заголовка без учёта регистра."""
        lowered = name.lower()
        for key, values in self.headers.items():
            if key.lower() == lowered and values:
                return values[0]
        return None

    def __repr__(self) -> str:
        return f"<Response {self.status} {self.proto} {len(self.content)}b>"


class Session:
    """Сессия с одним профилем и переиспользованием соединений.

    :param impersonate: имя профиля
    :param verify: проверять сертификат сервера. ``True`` — системные корни,
        путь к файлу PEM — доверять только этому корню, ``False`` — не
        проверять вовсе
    :param cert: пара путей ``(сертификат, ключ)`` для взаимной
        аутентификации (mTLS)
    :param trust_env: брать прокси из переменных окружения ``HTTPS_PROXY``,
        ``ALL_PROXY`` с учётом ``NO_PROXY``. Явно заданный ``proxy`` сильнее
    :param max_response_size: предел размера тела в байтах; 0 — без предела.
        Без него сервер с бесконечным ответом съедает память процесса
    :param timeout: предел на запрос целиком, включая редиректы, в секундах
    :param proxy: ``http://``, ``https://`` или ``socks5://``, можно с user:pass
    :param default_headers: подставлять заголовки профиля. Выключите, чтобы
        полностью управлять набором и порядком самостоятельно — анти-боты
        смотрят и на порядок. Без своего ``user-agent`` заголовок не уходит
        вовсе: подставлять умолчание Go библиотека не станет
    :param header_order: желаемый порядок заголовков; не перечисленные идут
        следом, сохраняя относительный порядок
    :param allow_redirects: переходить по 3xx
    :param max_redirects: предел длины цепочки
    :param cookies: включить cookie-jar, общий для запросов сессии
    :param force_http1: не предлагать h2, даже если профиль его содержит
    :param http3: отправлять запросы по QUIC вместо TCP. Профиль обязан
        описывать секцию ``http3``, иначе сессия не создастся. Это отдельный
        транспорт, а не вариант ALPN, поэтому выбирается явно
    :param alt_svc: переходить на HTTP/3, увидев в ответе заголовок
        ``Alt-Svc``. Так делает браузер: первый запрос к сайту всегда идёт
        по TCP, а на QUIC он переходит, только увидев объявление. Неудачная
        попытка откладывает следующую и откатывает запрос на TCP. Требует
        профиля с секцией ``http3``; через прокси не действует
    :param resolve: подмена адреса узла: ``{"example.com:443": "10.0.0.7"}``.
        Имя в SNI и заголовке Host остаётся прежним — меняется только то,
        куда открывается сокет. Аналог ``--resolve`` у curl: нужен, чтобы
        попасть на конкретный сервер за балансировщиком. Через прокси
        не действует: там имя разрешает он сам
    :param ip_version: ограничить семейство адресов: ``"4"`` или ``"6"``.
        Нужно там, где у имени есть запись AAAA, а маршрута по IPv6 нет
    :param keep_alive: переиспользовать соединение между запросами. Включено:
        так делает браузер, и рукопожатие TLS не повторяется на каждый запрос.
        ``False`` закрывает соединение сразу после ответа — нужно, когда
        балансировщик прибивает клиента к одному узлу. Заголовок
        ``Connection: close`` при этом не отправляется: браузер его не шлёт
    :param device: телефон, от имени которого идёт сессия: имя из секции
        ``devices`` профиля или ``"random"``. Современный Chrome вырезал модель
        из ``User-Agent`` (там у всех ``Android 10; K``), поэтому устройство
        сообщается подсказками ``sec-ch-ua-model`` и
        ``sec-ch-ua-platform-version`` — и только после того, как сайт запросил
        их заголовком ``Accept-CH``. Выбирается один раз на сессию
    :param devices: свой список устройств вместо профильного; каждый элемент —
        ``{"name": ..., "model": ..., "platform_version": ...}``
    :param retries: сколько повторов делать после первой попытки
    :param mode: набор заголовков: ``"navigate"`` — переход по адресу,
        ``"fetch"`` — запрос fetch/XHR со страницы, ``"auto"`` — по признакам
        запроса (метод кроме GET/HEAD/POST, тело не формы, кастомный
        заголовок означают fetch). У профиля должна быть секция ``fetch``
    """

    def __init__(
        self,
        impersonate: str = DEFAULT_PROFILE,
        *,
        verify: bool | str = True,
        cert: tuple[str, str] | None = None,
        trust_env: bool = True,
        max_response_size: int = 0,
        timeout: float = 30.0,
        proxy: str | None = None,
        default_headers: bool = True,
        header_order: Iterable[str] | None = None,
        allow_redirects: bool = True,
        max_redirects: int = 20,
        cookies: bool = True,
        force_http1: bool = False,
        http3: bool = False,
        alt_svc: bool = True,
        resolve: Mapping[str, str] | None = None,
        ip_version: str | None = None,
        keep_alive: bool = True,
        hooks: Mapping[str, Iterable[Callable[..., Any]]] | None = None,
        device: str | None = None,
        devices: Iterable[Mapping[str, str]] | None = None,
        max_idle_conns: int = 0,
        idle_conn_timeout: float = 0.0,
        retries: int = 0,
        retry_statuses: Iterable[int] | None = None,
        retry_methods: Iterable[str] | None = None,
        retry_backoff: float = 0.2,
        retry_max_backoff: float = 10.0,
        respect_retry_after: bool = True,
        mode: str = "auto",
    ):
        # Профили, вложенные в пакет, подгружаются при первом обращении:
        # после pip install библиотека должна работать без лишних шагов.
        ensure_loaded()
        self._id = _call(
            "curlpro_session_new",
            encode(
                {
                    "profile": impersonate,
                    # verify=True — системные корни, строка — свой корень,
                    # False — без проверки вовсе.
                    "insecure_skip_verify": verify is False,
                    "ca_cert": verify if isinstance(verify, str) else "",
                    "client_cert": cert[0] if cert else "",
                    "client_key": cert[1] if cert else "",
                    # Окружение читает Python: на Linux нативная часть
                    # видит его таким, каким оно было при старте процесса,
                    # и правка os.environ в рантайме до неё не доходит.
                    "trust_env": False,
                    "max_response_size": int(max_response_size),
                    "timeout_ms": int(timeout * 1000),
                    "proxy": proxy or "",
                    "default_headers": default_headers,
                    "header_order": list(header_order) if header_order else None,
                    "follow_redirects": allow_redirects,
                    "max_redirects": max_redirects,
                    "cookies": cookies,
                    "force_http1": force_http1,
                    "http3": http3,
                    "alt_svc": alt_svc,
                    "resolve": dict(resolve) if resolve else None,
                    "ip_version": ip_version or "",
                    "keep_alive": keep_alive,
                    "device": device or "",
                    "devices": [dict(d) for d in devices] if devices else None,
                    "max_idle_conns": max_idle_conns,
                    "idle_conn_timeout_ms": int(idle_conn_timeout * 1000),
                    "retry": _retry_config(
                        retries or None, retry_statuses, retry_methods,
                        retry_backoff, retry_max_backoff, respect_retry_after,
                    ),
                    "mode": "" if mode == "auto" else mode,
                }
            ),
        )["session"]
        self.impersonate = impersonate
        self._trust_env = trust_env
        self._closed = False
        #: Заголовки, добавляемые ко всем запросам сессии. Хранятся отдельно
        #: от профильных, поэтому clear() возвращает чистый отпечаток.
        self.headers = SessionHeaders(self._id)
        #: Куки сессии: чтение, изменение, сохранение и загрузка из файла.
        self.cookies = Cookies(self._id)
        #: Перехватчики: "request" вызывается перед отправкой и получает
        #: описание запроса, "response" — после, с готовым ответом. Оба могут
        #: вернуть замену; вернувший None ничего не меняет.
        self.hooks: dict[str, list[Callable[..., Any]]] = {"request": [], "response": []}
        for event, fns in (hooks or {}).items():
            if event not in self.hooks:
                raise ValueError(f"неизвестное событие {event!r}: есть request и response")
            self.hooks[event].extend(fns)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
        auth: tuple[str, str] | str | None = None,
        data: bytes | str | None = None,
        json_body: Any = None,
        files: Mapping[str, Any] | None = None,
        fields: Mapping[str, str] | None = None,
        body_file: str | Any = None,
        header_order: Iterable[str] | None = None,
        default_headers: bool | None = None,
        timeout: float | None = None,
        allow_redirects: bool | None = None,
        max_redirects: int | None = None,
        retries: int | None = None,
        retry_statuses: Iterable[int] | None = None,
        retry_methods: Iterable[str] | None = None,
        retry_backoff: float | None = None,
        retry_max_backoff: float | None = None,
        respect_retry_after: bool = True,
        proxy: str | bool | None = None,
        mode: str | None = None,
    ) -> Response:
        if self._closed:
            raise RuntimeError("сессия закрыта")

        if proxy is None and self._trust_env:
            # Явный proxy сильнее окружения; False означает «идти напрямую»
            # и тоже не перебивается.
            proxy = env_proxy(url)

        meta, body = _request_meta(
            method, url, headers=headers, params=params, auth=auth,
            data=data, json_body=json_body,
            files=files, fields=fields, body_file=body_file,
            header_order=header_order, default_headers=default_headers,
            timeout=timeout, allow_redirects=allow_redirects,
            max_redirects=max_redirects, retries=retries,
            retry_statuses=retry_statuses, retry_methods=retry_methods,
            retry_backoff=retry_backoff, retry_max_backoff=retry_max_backoff,
            respect_retry_after=respect_retry_after, proxy=proxy, mode=mode,
        )
        for hook in self.hooks["request"]:
            replaced = hook(meta)
            if replaced is not None:
                meta = replaced

        started = time.perf_counter()
        payload, content = call_framed("curlpro_request", self._id, body=body, meta=meta)
        spent = time.perf_counter() - started
        return self._after(Response(
            status=payload["status"],
            proto=payload.get("proto", ""),
            headers=payload.get("headers") or {},
            content=content,
            url=payload.get("url") or url,
            elapsed=spent,
            history=[Redirect(h.get("status", 0), h.get("url", ""), h.get("location", ""))
                     for h in payload.get("history") or []],
        ))

    def _after(self, response: Response) -> Response:
        """Пропускает ответ через перехватчики."""
        for hook in self.hooks["response"]:
            replaced = hook(response)
            if replaced is not None:
                response = replaced
        return response

    def on_request(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Добавляет перехватчик запроса. Годится и как декоратор."""
        self.hooks["request"].append(fn)
        return fn

    def on_response(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Добавляет перехватчик ответа. Годится и как декоратор."""
        self.hooks["response"].append(fn)
        return fn

    def stream(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        data: bytes | str | None = None,
        json_body: Any = None,
        files: Mapping[str, Any] | None = None,
        fields: Mapping[str, str] | None = None,
        body_file: str | Any = None,
        header_order: Iterable[str] | None = None,
        default_headers: bool | None = None,
        timeout: float | None = None,
        allow_redirects: bool | None = None,
        max_redirects: int | None = None,
        retries: int | None = None,
        retry_statuses: Iterable[int] | None = None,
        retry_methods: Iterable[str] | None = None,
        retry_backoff: float | None = None,
        retry_max_backoff: float | None = None,
        respect_retry_after: bool = True,
        proxy: str | bool | None = None,
        mode: str | None = None,
    ) -> "StreamResponse":
        """Открывает ответ для чтения по частям.

        Принимает те же аргументы, что и :meth:`request`. Поток удерживает
        соединение до закрытия, поэтому использовать его следует через ``with``.
        Закрытие потока с недочитанным телом выбрасывает соединение, а не
        дочитывает остаток: прочитать килобайт и закрыть — дёшево.
        """
        if self._closed:
            raise RuntimeError("сессия закрыта")

        meta, body = _request_meta(
            method, url, headers=headers, data=data, json_body=json_body,
            files=files, fields=fields, body_file=body_file,
            header_order=header_order, default_headers=default_headers,
            timeout=timeout, allow_redirects=allow_redirects,
            max_redirects=max_redirects, retries=retries,
            retry_statuses=retry_statuses, retry_methods=retry_methods,
            retry_backoff=retry_backoff, retry_max_backoff=retry_max_backoff,
            respect_retry_after=respect_retry_after, proxy=proxy, mode=mode,
        )
        payload, _ = call_framed("curlpro_stream_open", self._id, body=body, meta=meta)
        return StreamResponse(payload)

    def websocket(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        subprotocols: Iterable[str] | None = None,
        timeout: float = 30.0,
        max_message_size: int = 0,
    ) -> "WebSocket":
        """Открывает WebSocket с заголовками рукопожатия из профиля.

        ``timeout`` ограничивает рукопожатие и ожидание одного сообщения;
        ``max_message_size`` — предел принимаемого сообщения в байтах
        (ноль — 64 МиБ). Соединение держится до закрытия — используйте ``with``.
        """
        if self._closed:
            raise RuntimeError("сессия закрыта")
        return ws_connect(self._id, url, headers=headers, subprotocols=subprotocols,
                          timeout=timeout, max_message_size=max_message_size)

    def get(self, url: str, **kw: Any) -> Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> Response:
        return self.request("POST", url, **kw)

    def put(self, url: str, **kw: Any) -> Response:
        return self.request("PUT", url, **kw)

    def patch(self, url: str, **kw: Any) -> Response:
        return self.request("PATCH", url, **kw)

    def delete(self, url: str, **kw: Any) -> Response:
        return self.request("DELETE", url, **kw)

    def head(self, url: str, **kw: Any) -> Response:
        return self.request("HEAD", url, **kw)

    def options(self, url: str, **kw: Any) -> Response:
        return self.request("OPTIONS", url, **kw)

    def close(self) -> None:
        if not self._closed:
            _call("curlpro_session_close", self._id)
            self._closed = True

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        # Сессия держит открытые сокеты на стороне Go: без закрытия они
        # переживут сборку Python-объекта.
        try:
            self.close()
        except Exception:
            pass


def request(method: str, url: str, *, impersonate: str = DEFAULT_PROFILE,
            verify: bool = True, timeout: float = 30.0, proxy: str | None = None,
            **kw: Any) -> Response:
    """Одиночный запрос. Для серии запросов используйте Session."""
    session_kw = {
        k: kw.pop(k)
        for k in ("default_headers", "header_order", "allow_redirects",
                  "max_redirects", "cookies", "force_http1", "http3")
        if k in kw
    }
    with Session(impersonate, verify=verify, timeout=timeout, proxy=proxy,
                 **session_kw) as s:
        return s.request(method, url, **kw)


def get(url: str, **kw: Any) -> Response:
    return request("GET", url, **kw)


def post(url: str, **kw: Any) -> Response:
    return request("POST", url, **kw)


def put(url: str, **kw: Any) -> Response:
    return request("PUT", url, **kw)


def patch(url: str, **kw: Any) -> Response:
    return request("PATCH", url, **kw)


def delete(url: str, **kw: Any) -> Response:
    return request("DELETE", url, **kw)


def head(url: str, **kw: Any) -> Response:
    return request("HEAD", url, **kw)


def options(url: str, **kw: Any) -> Response:
    return request("OPTIONS", url, **kw)
