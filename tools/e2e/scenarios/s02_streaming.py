"""WebSocket, streaming, large transfers, upstream aborts, unix socket upstream."""
import contextlib
import hashlib
import http.client
import os
import socket
import threading
import time

import ws
from lib import *


class RawServer:
    """TCP server that hands every accepted connection to fn(conn) in a thread."""

    def __init__(self, fn):
        self.port = free_port()
        self.s = socket.socket()
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("127.0.0.1", self.port))
        self.s.listen(16)
        self.fn = fn
        self.alive = True
        threading.Thread(target=self._loop, daemon=True).start()

    @property
    def addr(self):
        return "127.0.0.1:%d" % self.port

    def _loop(self):
        while self.alive:
            try:
                c, _ = self.s.accept()
            except OSError:
                return
            threading.Thread(target=self._h, args=(c,), daemon=True).start()

    def _h(self, c):
        try:
            self.fn(c)
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                c.close()

    def close(self):
        self.alive = False
        with contextlib.suppress(Exception):
            self.s.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def read_request_head(c):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = c.recv(65536)
        if not d:
            return None
        buf += d
    return buf


@scenario("websocket_proxy", ["70", "199"])
def websocket_proxy():
    """WebSocket echo through a host rule, and through a vdir with a base path."""
    with Zoraxy() as z, ws.WSEchoServer() as w:
        z.add_rule("ws.test", w.addr)
        s, st, h = ws.ws_connect(z.proxy, "ws.test", "/chat?room=1")
        check("101" in st, "handshake status: " + st)
        ws.write_frame(s, 1, b"hello", mask=True)
        op, data = ws.read_message(s)
        check(data == b"echo:hello", "echo frame: %r" % data)
        big = os.urandom(70000)
        ws.write_frame(s, 2, big, mask=True)
        op, data = ws.read_message(s)
        check(data == big, "binary 70k frame corrupted")
        ws.write_frame(s, 8, b"\x03\xe8", mask=True)
        s.close()
        check(w.requests[0][0] == "/chat?room=1", "backend saw path %s" % w.requests[0][0])
        # vdir with base path: /app/ -> backend, backend sees stripped path
        with Backend(name="plain") as plain:
            z.add_rule("wv.test", plain.addr)
            z.api("/api/proxy/vdir/add", type="host", endpoint="wv.test", path="/app", domain=w.addr)
            s, st, h = ws.ws_connect(z.proxy, "wv.test", "/app/socket")
            check("101" in st, "vdir handshake: " + st)
            ws.write_frame(s, 1, b"via-vdir", mask=True)
            op, data = ws.read_message(s)
            check(data == b"echo:via-vdir", "vdir echo: %r" % data)
            s.close()
            vpath = w.requests[-1][0]
            check(vpath == "/socket", "vdir ws path to backend was %r, expected '/socket'" % vpath)
        return "ws text/70KB binary echo via host rule; vdir /app -> backend path %s" % vpath


@scenario("websocket_origin_and_disable", ["70"])
def websocket_origin_and_disable():
    """Cross-origin WS is refused unless 'bypass origin check'; per-rule WS disable works."""
    with Zoraxy() as z, ws.WSEchoServer() as w:
        z.add_rule("wo.test", w.addr, bpwsorg=False)
        s, st, h = ws.ws_connect(z.proxy, "wo.test", "/", headers={"Origin": "http://evil.example"})
        bad = "101" not in st
        s.close()
        s, st2, h = ws.ws_connect(z.proxy, "wo.test", "/", headers={"Origin": "http://wo.test"})
        good = "101" in st2
        s.close()
        check(bad, "cross-origin WebSocket upgrade accepted with origin check on: " + st)
        check(good, "same-origin WebSocket refused: " + st2)
        z.edit_rule("wo.test", disableWebSocket=True)
        s, st3, h = ws.ws_connect(z.proxy, "wo.test", "/", headers={"Origin": "http://wo.test"})
        s.close()
        check("101" not in st3, "WebSocket still upgraded with disableWebSocket: " + st3)
        return "cross-origin=%s same-origin=%s disabled=%s" % (st, st2, st3)


@scenario("streaming_chunked", ["dpcore-streaming"])
def streaming_chunked():
    """Chunked response is flushed incrementally (first chunk arrives long before the last)."""
    def handler(c):
        read_request_head(c)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
        for i in range(5):
            data = ("tick-%d\n" % i).encode()
            c.sendall(b"%x\r\n%s\r\n" % (len(data), data))
            time.sleep(0.4)
        c.sendall(b"0\r\n\r\n")

    with Zoraxy() as z, RawServer(handler) as b:
        z.add_rule("st.test", b.addr)
        conn = http.client.HTTPConnection("127.0.0.1", z.proxy, timeout=10)
        conn.request("GET", "/", headers={"Host": "st.test"})
        t0 = time.time()
        r = conn.getresponse()
        first = r.read1(100) if hasattr(r, "read1") else r.read(7)
        t_first = time.time() - t0
        rest = r.read()
        t_all = time.time() - t0
        conn.close()
        check(b"tick-0" in first, "first chunk wrong: %r" % first)
        check(t_first < 1.0, "first chunk delayed %.2fs: response is buffered" % t_first)
        check(t_all > 1.4, "whole stream finished in %.2fs: not streamed" % t_all)
        check(rest.count(b"tick") + first.count(b"tick") == 5, "chunks lost")
        return "first chunk after %.2fs, full stream %.2fs, 5/5 chunks" % (t_first, t_all)


@scenario("large_transfer_integrity", ["dpcore-streaming"])
def large_transfer_integrity():
    """24 MiB upload and 48 MiB download keep exact bytes (sha256) through the proxy."""
    blob = os.urandom(1 << 20)
    total_dl = 48

    def handler(h, rec, b):
        if rec["method"] == "POST":
            send(h, 200, "%s %d" % (hashlib.sha256(rec["body"]).hexdigest(), len(rec["body"])))
        else:
            h.send_response(200)
            h.send_header("Content-Length", str(total_dl << 20))
            h.end_headers()
            for _ in range(total_dl):
                h.wfile.write(blob)

    with Zoraxy() as z, Backend(handler) as b:
        z.add_rule("big.test", b.addr)
        up = os.urandom(24 << 20)
        r = z.req("big.test", "/up", "POST", {"Content-Type": "application/octet-stream"}, up, timeout=60)
        want = "%s %d" % (hashlib.sha256(up).hexdigest(), len(up))
        check(r.text == want, "upload mismatch: got %r want %r" % (r.text, want))
        r = z.req("big.test", "/down", timeout=60)
        h = hashlib.sha256()
        for _ in range(total_dl):
            h.update(blob)
        check(len(r.body) == total_dl << 20, "download length %d" % len(r.body))
        check(hashlib.sha256(r.body).hexdigest() == h.hexdigest(), "download corrupted")
        # chunked upload (no content-length)
        r = z.req("big.test", "/up", "POST", {"Content-Type": "application/octet-stream", "Transfer-Encoding": "chunked"},
                  (b"x" * 4096 for _ in range(64)), timeout=30, chunked=True)
        want = "%s %d" % (hashlib.sha256(b"x" * 4096 * 64).hexdigest(), 4096 * 64)
        check(r.text == want, "chunked upload mismatch: %r" % r.text)
        return "24MiB upload + 48MiB download sha256 equal; chunked upload 256KiB equal"


@scenario("upstream_abort_midstream", ["dpcore-abort"])
def upstream_abort_midstream():
    """Upstream dies mid-body: client must see a failed transfer, never a 'complete' body."""
    def declared(c):  # Content-Length 4 MiB, sends 1 MiB then closes
        read_request_head(c)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % (4 << 20))
        c.sendall(b"a" * (1 << 20))
        time.sleep(0.2)

    def chunked(c):  # chunked, abandoned without the terminating 0 chunk
        read_request_head(c)
        c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        for _ in range(8):
            c.sendall(b"%x\r\n%s\r\n" % (4096, b"b" * 4096))
        time.sleep(0.2)

    results = []
    with Zoraxy() as z, RawServer(declared) as d, RawServer(chunked) as ch:
        z.add_rule("d.test", d.addr)
        z.add_rule("c.test", ch.addr)
        for host in ("d.test", "c.test"):
            conn = http.client.HTTPConnection("127.0.0.1", z.proxy, timeout=15)
            conn.request("GET", "/", headers={"Host": host})
            outcome = None
            try:
                r = conn.getresponse()
                body = r.read()
                outcome = "COMPLETE-LOOKING status=%d len=%d" % (r.status, len(body))
            except (http.client.IncompleteRead, http.client.RemoteDisconnected, ConnectionError, socket.timeout) as e:
                outcome = "failed(%s)" % type(e).__name__
            conn.close()
            results.append((host, outcome))
            check(outcome.startswith("failed"), "%s: client saw a complete response after upstream abort: %s" % (host, outcome))
        return "; ".join("%s -> %s" % x for x in results)


@scenario("unix_socket_upstream", ["663"])
def unix_socket_upstream():
    """Rule whose upstream is a unix socket (unix:/path)."""
    d = tempfile.mkdtemp(prefix="zx-uds-")
    sock = os.path.join(d, "b.sock")
    try:
        with Zoraxy() as z, Backend(name="uds", unix=sock) as b:
            z.add_rule("u.test", "unix:" + sock)
            r = z.req("u.test", "/via/uds?a=1")
            check(r.status == 200, "status %d body %r log=%s" % (r.status, r.body[:200], z.logtail(500)))
            j = r.json()
            check(j["backend"] == "uds" and j["path"] == "/via/uds?a=1", "unexpected: %r" % j)
            return "proxied to unix:%s, path preserved" % sock
    finally:
        shutil.rmtree(d, ignore_errors=True)
