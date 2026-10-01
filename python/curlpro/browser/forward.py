"""A local proxy that hands a browser's traffic to a proxy with credentials.

Chrome takes a proxy on its command line but not the credentials for it; a
proxy that asks for them gets a login prompt nobody answers. This forwarder
listens on 127.0.0.1, takes Chrome's requests as a plain HTTP proxy would and
passes them to the real proxy with the credentials added — for an
``http://``/``https://`` proxy in ``Proxy-Authorization``, for a
``socks5://`` one in the SOCKS username/password exchange (RFC 1929).

It does not look inside: a CONNECT tunnel carries the browser's own TLS, byte
for byte, so what the site sees is the browser's handshake and nothing of
ours. Only a cleartext ``http://`` request, which Chrome sends to an HTTP proxy
as a whole URL, is read far enough to be passed on.
"""

from __future__ import annotations

import base64
import socket
import socketserver
import ssl
import struct
import threading
from urllib.parse import unquote, urlsplit


def _pipe(a: socket.socket, b: socket.socket) -> None:
    def one(src: socket.socket, dst: socket.socket) -> None:
        try:
            while data := src.recv(65536):
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
    t = threading.Thread(target=one, args=(b, a), daemon=True)
    t.start()
    one(a, b)
    t.join()


def _exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("the proxy closed the connection")
        data += chunk
    return data


def _read_head(sock: socket.socket) -> tuple[bytes, bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("closed before the request head ended")
        data += chunk
        if len(data) > 64 * 1024:
            raise ConnectionError("request head too long")
    head, rest = data.split(b"\r\n\r\n", 1)
    return head, rest


class Forwarder:
    """Forwards to ``upstream`` (``http://``, ``https://``, ``socks5://`` or
    ``socks5h://``, with ``user:pass@``). ``address`` is what to give Chrome
    as ``--proxy-server``. Use as a context manager, or call close()."""

    def __init__(self, upstream: str):
        u = urlsplit(upstream if "://" in upstream else "http://" + upstream)
        if u.scheme not in ("http", "https", "socks5", "socks5h"):
            raise ValueError(f"cannot forward to a {u.scheme}:// proxy")
        self._u = u
        self._user, self._password = unquote(u.username or ""), unquote(u.password or "")
        forwarder = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                try:
                    forwarder._serve(self.request)
                except (OSError, ConnectionError, ValueError):
                    pass

        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self.address = f"http://127.0.0.1:{self._server.server_address[1]}"

    def _open_upstream(self) -> socket.socket:
        u = self._u
        default = {"http": 80, "https": 443}.get(u.scheme, 1080)
        sock = socket.create_connection((u.hostname, u.port or default), timeout=30)
        if u.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=u.hostname)
        return sock

    def _auth_header(self) -> bytes:
        if not self._user:
            return b""
        token = base64.b64encode(f"{self._user}:{self._password}".encode()).decode()
        return f"Proxy-Authorization: Basic {token}\r\n".encode()

    def _socks(self, host: str, port: int) -> socket.socket:
        s = self._open_upstream()
        methods = b"\x00\x02" if self._user else b"\x00"
        s.sendall(b"\x05" + bytes([len(methods)]) + methods)
        ver, method = _exact(s, 2)
        if method == 0x02:
            user, pw = self._user.encode(), self._password.encode()
            s.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
            if _exact(s, 2)[1:2] != b"\x00":
                raise ConnectionError("the SOCKS proxy refused the credentials")
        elif method != 0x00:
            raise ConnectionError("the SOCKS proxy offers no method we speak")
        name = host.encode("idna")
        # The name goes to the proxy, which resolves it: a browser behind
        # SOCKS resolves remotely, and so does this.
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", port))
        reply = _exact(s, 4)
        if reply[1] != 0x00:
            raise ConnectionError(f"the SOCKS proxy refused {host}:{port}")
        atyp = reply[3]
        if atyp == 3:
            _exact(s, _exact(s, 1)[0] + 2)
        else:
            _exact(s, (16 if atyp == 4 else 4) + 2)
        return s

    def _serve(self, client: socket.socket) -> None:
        head, rest = _read_head(client)
        lines = head.split(b"\r\n")
        method, target, version = lines[0].split(b" ", 2)
        socks = self._u.scheme.startswith("socks")
        if method == b"CONNECT":
            host, _, port = target.decode().rpartition(":")
            if socks:
                up = self._socks(host.strip("[]"), int(port))
            else:
                up = self._open_upstream()
                up.sendall(b"CONNECT " + target + b" HTTP/1.1\r\nHost: " + target + b"\r\n"
                           + self._auth_header() + b"\r\n")
                answer, extra = _read_head(up)
                if b" 200" not in answer.split(b"\r\n", 1)[0]:
                    client.sendall(answer + b"\r\n\r\n" + extra)
                    return
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            if rest:
                up.sendall(rest)
            _pipe(client, up)
            return
        # A cleartext request in absolute form.
        kept = [line for line in lines[1:] if not line.lower().startswith(b"proxy-")]
        if socks:
            u = urlsplit(target.decode())
            up = self._socks(u.hostname or "", u.port or 80)
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")
            up.sendall(b" ".join([method, path.encode(), version]) + b"\r\n"
                       + b"\r\n".join(kept) + b"\r\n\r\n" + rest)
        else:
            up = self._open_upstream()
            up.sendall(lines[0] + b"\r\n" + b"\r\n".join(kept) + b"\r\n" + self._auth_header()
                       + b"\r\n" + rest)
        _pipe(client, up)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> "Forwarder":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
