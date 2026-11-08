"""Tiny RFC 6455 client + echo server (stdlib only) for the WebSocket scenarios."""
import base64
import hashlib
import os
import socket
import struct
import threading
import contextlib

from lib import free_port

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def accept_key(k):
    return base64.b64encode(hashlib.sha1(k.encode() + GUID).digest()).decode()


def read_exact(s, n):
    b = b""
    while len(b) < n:
        d = s.recv(n - len(b))
        if not d:
            raise ConnectionError("closed")
        b += d
    return b


def read_frame(s, want_fin=False):
    h = read_exact(s, 2)
    op = h[0] & 0x0F
    fin = bool(h[0] & 0x80)
    masked = h[1] & 0x80
    ln = h[1] & 0x7F
    if ln == 126:
        ln = struct.unpack(">H", read_exact(s, 2))[0]
    elif ln == 127:
        ln = struct.unpack(">Q", read_exact(s, 8))[0]
    mask = read_exact(s, 4) if masked else None
    data = read_exact(s, ln)
    if mask:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return (op, data, fin) if want_fin else (op, data)


def read_message(s):
    """Reassembles fragmented messages (a proxy may legally re-fragment)."""
    op, data, fin = read_frame(s, True)
    while not fin:
        _, more, fin = read_frame(s, True)
        data += more
    return op, data


def write_frame(s, op, data, mask=False):
    h = bytes([0x80 | op])
    ln = len(data)
    mb = 0x80 if mask else 0
    if ln < 126:
        h += bytes([mb | ln])
    elif ln < 65536:
        h += bytes([mb | 126]) + struct.pack(">H", ln)
    else:
        h += bytes([mb | 127]) + struct.pack(">Q", ln)
    if mask:
        m = os.urandom(4)
        data = bytes(b ^ m[i % 4] for i, b in enumerate(data))
        h += m
    s.sendall(h + data)


class WSEchoServer:
    """Accepts websocket upgrades on any path; echoes text frames prefixed with 'echo:'.

    .requests holds (path, headers) of every handshake.
    """

    def __init__(self):
        self.port = free_port()
        self.requests = []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.listen(16)
        self.alive = True
        threading.Thread(target=self._loop, daemon=True).start()

    @property
    def addr(self):
        return "127.0.0.1:%d" % self.port

    def _loop(self):
        while self.alive:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._conn, args=(c,), daemon=True).start()

    def _conn(self, c):
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = c.recv(4096)
                if not d:
                    return
                buf += d
            head = buf.split(b"\r\n\r\n")[0].decode("latin1").split("\r\n")
            path = head[0].split(" ")[1]
            hdrs = {}
            for ln in head[1:]:
                k, _, v = ln.partition(":")
                hdrs[k.strip().lower()] = v.strip()
            self.requests.append((path, hdrs))
            if "websocket" not in hdrs.get("upgrade", "").lower():
                body = b"not a websocket"
                c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
                return
            c.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Accept: %s\r\n\r\n" % accept_key(hdrs["sec-websocket-key"])).encode())
            while True:
                op, data = read_message(c)
                if op == 8:
                    write_frame(c, 8, data)
                    return
                if op == 1:
                    write_frame(c, 1, b"echo:" + data)
                elif op == 2:
                    write_frame(c, 2, data)
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                c.close()

    def close(self):
        self.alive = False
        with contextlib.suppress(Exception):
            self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def ws_connect(port, host, path="/", headers=None, timeout=8, tls=False):
    """Returns (socket, status_line, response_headers). Socket is usable for frames when status is 101."""
    s = socket.create_connection(("127.0.0.1", port), timeout)
    if tls:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s)
    key = base64.b64encode(os.urandom(16)).decode()
    h = {"Host": host, "Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Key": key,
         "Sec-WebSocket-Version": "13"}
    h.update(headers or {})
    req = "GET %s HTTP/1.1\r\n" % path + "".join("%s: %s\r\n" % kv for kv in h.items()) + "\r\n"
    s.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    rh = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        rh[k.strip().lower()] = v.strip()
    return s, lines[0], rh
