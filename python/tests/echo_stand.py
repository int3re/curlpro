"""A cleartext echo stand for the cookie, preflight and proxy tests.

Every request is recorded with its method, path and headers; the handler
answers what a test asked for. Plain HTTP on purpose: the questions here are
about which headers go out, and the rules do not depend on the transport.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class EchoStand:
    """``with EchoStand() as st:`` — ``st.url`` is ``http://127.0.0.1:PORT``.

    ``st.seen`` is the list of recorded requests, each a dict with ``method``,
    ``path`` and the headers by their lowercase names. ``st.routes`` maps a
    path to ``(status, headers, body)`` or to a callable taking the request
    dict and returning that triple.
    """

    def __init__(self) -> None:
        self.seen: list[dict] = []
        self.routes: dict = {}
        stand = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                if length:
                    self.rfile.read(length)
                rec = {"method": self.command, "path": self.path}
                for k, v in self.headers.items():
                    rec.setdefault(k.lower(), v)
                rec["_order"] = [k for k in self.headers.keys()]
                stand.seen.append(rec)
                route = stand.routes.get(self.path.split("?", 1)[0])
                if callable(route):
                    route = route(rec)
                status, headers, body = route or (200, [], b"{}")
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            do_GET = do_POST = do_OPTIONS = do_DELETE = do_PUT = _handle

            def do_CONNECT(self) -> None:  # a proxy that answers the way the test set
                rec = {"method": "CONNECT", "path": self.path}
                for k, v in self.headers.items():
                    rec.setdefault(k.lower(), v)
                stand.seen.append(rec)
                route = stand.routes.get("CONNECT")
                if callable(route):
                    route = route(rec)
                status, headers, body = route or (502, [], b"")
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def log_message(self, *a) -> None:  # noqa: ANN002
                pass

        # Threaded: a browser — and the session, whose pool is partitioned
        # like Chromium's by credentials and by the page's site — opens
        # more than one connection, and a server that serves one at a time
        # leaves the second waiting behind the first kept-alive socket.
        ThreadingHTTPServer.allow_reuse_address = True
        ThreadingHTTPServer.daemon_threads = True
        # The default backlog of five refuses a burst of parallel connections
        # outright, which is the stand failing, not the client.
        ThreadingHTTPServer.request_queue_size = 128
        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._srv.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    def __enter__(self) -> "EchoStand":
        if not self._thread.is_alive():
            self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._srv.shutdown()
        self._srv.server_close()

    def last(self) -> dict:
        return self.seen[-1]

    def methods(self) -> list[str]:
        return [f'{r["method"]} {r["path"].split("?", 1)[0]}' for r in self.seen]
