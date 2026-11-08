"""Shared helpers for the Zoraxy data-plane end-to-end harness.

Standard library only; Playwright is imported lazily by the few scenarios that drive the admin UI.
"""
import contextlib
import http.client
import http.cookiejar
import http.server
import json
import os
import re
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SRC = os.path.join(ROOT, "src")
BIN = os.environ.get("ZORAXY_BIN") or os.path.join(tempfile.gettempdir(), "zoraxy-e2e-bin")
PORT_BASE = int(os.environ.get("E2E_PORT_BASE", "28810"))
PORT_SPAN = 190

_ports = {"next": PORT_BASE}


def free_port():
    """Hand out ports from the reserved range, skipping ones in use."""
    for _ in range(PORT_SPAN * 2):
        p = _ports["next"]
        _ports["next"] += 1
        if _ports["next"] >= PORT_BASE + PORT_SPAN:
            _ports["next"] = PORT_BASE
        with contextlib.closing(socket.socket()) as s:
            try:
                s.bind(("127.0.0.1", p))
            except OSError:
                continue
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
            try:
                s.bind(("127.0.0.1", p))
            except OSError:
                continue
        return p
    raise RuntimeError("no free port in range")


class Skip(Exception):
    """Scenario cannot be tested here; message says why."""


class Fail(AssertionError):
    pass


def check(cond, msg):
    if not cond:
        raise Fail(msg)


def build(force=False):
    if os.path.exists(BIN) and not force and os.environ.get("E2E_NOBUILD"):
        return BIN
    env = dict(os.environ)
    env.setdefault("GOTMPDIR", os.path.expanduser("~/.cache/go-tmp"))
    os.makedirs(env["GOTMPDIR"], exist_ok=True)
    subprocess.check_call(["go", "build", "-o", BIN, "."], cwd=SRC, env=env)
    return BIN


HELPER_BIN = os.path.join(tempfile.gettempdir(), "zoraxy-e2e-helper")


def helper():
    """Builds tools/e2e/helpers (Go) once and returns the binary path."""
    if not os.path.exists(HELPER_BIN) or os.path.getmtime(HELPER_BIN) < max(
            os.path.getmtime(os.path.join(HERE, "helpers", f)) for f in os.listdir(os.path.join(HERE, "helpers"))
            if f.endswith(".go")):
        env = dict(os.environ, GOFLAGS="-mod=mod", GOTMPDIR=os.path.expanduser("~/.cache/go-tmp"))
        os.makedirs(env["GOTMPDIR"], exist_ok=True)
        subprocess.check_call(["go", "build", "-o", HELPER_BIN, "."], cwd=os.path.join(HERE, "helpers"), env=env)
    return HELPER_BIN


def helper_json(*args, timeout=30):
    out = subprocess.run([helper()] + list(args), capture_output=True, timeout=timeout)
    try:
        return json.loads(out.stdout.decode().strip().splitlines()[-1])
    except Exception:
        raise Fail("helper %s failed: %s %s" % (args[0], out.stdout[-300:], out.stderr[-300:]))


class Proc:
    """A background process killed on exit."""

    def __init__(self, argv, **kw):
        self.p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=os.setsid, **kw)

    def close(self):
        with contextlib.suppress(Exception):
            os.killpg(os.getpgid(self.p.pid), signal.SIGKILL)
        with contextlib.suppress(Exception):
            self.p.wait(5)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


# --------------------------------------------------------------------------- instance

class Zoraxy:
    """A throw-away Zoraxy instance: own conf/db/tmp dir, admin port, proxy port."""

    def __init__(self, tls=False, extra_args=None, noauth=True, name="z", certs=(), env=None, plugins=()):
        self.dir = tempfile.mkdtemp(prefix="zx-e2e-" + name + "-")
        self.admin = free_port()
        self.proxy = free_port()
        self.tls = tls
        self.noauth = noauth
        self.extra = list(extra_args or [])
        self.env = dict(env or {})
        self.proc = None
        self.csrf = ""
        self.opener = None
        os.symlink(os.path.join(SRC, "web"), os.path.join(self.dir, "web"))
        # plugins: iterable of (folder_name, binary_path) seeded into ./plugins/<folder>/<folder>
        for nm, binp in plugins:
            pd = os.path.join(self.dir, "plugins", nm)
            os.makedirs(pd, exist_ok=True)
            shutil.copy(binp, os.path.join(pd, nm))
            os.chmod(os.path.join(pd, nm), 0o755)
        # certs: iterable of (name, crt_path, key_path) pre-seeded into conf/certs (name.pem / name.key)
        for nm, crt, key in certs:
            cd = os.path.join(self.dir, "conf", "certs")
            os.makedirs(cd, exist_ok=True)
            shutil.copy(crt, os.path.join(cd, nm + ".pem"))
            shutil.copy(key, os.path.join(cd, nm + ".key"))

    # lifecycle
    def start(self, wait_proxy=True):
        args = [BIN, "-dev", "-port", ":%d" % self.admin, "-conf", "./conf", "-dbpath", "./sys.db",
                "-default_inbound_port", str(self.proxy), "-default_inbound_enabled=true",
                "-mdns=false", "-enablelog=false"]
        if self.noauth:
            args.append("-noauth")
        args += self.extra
        self.log = open(os.path.join(self.dir, "zoraxy.log"), "ab")
        self.proc = subprocess.Popen(args, cwd=self.dir, stdout=self.log, stderr=subprocess.STDOUT,
                                     preexec_fn=os.setsid, env=dict(os.environ, **self.env))
        t0 = time.time()
        while time.time() - t0 < 40:
            if self.proc.poll() is not None:
                raise Fail("zoraxy exited early:\n" + self.logtail())
            try:
                urllib.request.urlopen("http://127.0.0.1:%d/" % self.admin, timeout=1).read()
                break
            except Exception:
                time.sleep(0.3)
        else:
            raise Fail("zoraxy admin did not come up:\n" + self.logtail())
        self._session()
        # ReverseProxyInit starts the listener asynchronously; API calls that restart it must not race that
        wait_for(lambda: "Dynamic Reverse Proxy service started" in self.logtail(200000), timeout=30, msg="proxy service start")
        if not self.tls:
            self.api("/api/cert/tls", set="false")
        if wait_proxy:
            self.wait_proxy()
        return self

    def wait_proxy(self, timeout=20):
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                socket.create_connection(("127.0.0.1", self.proxy), 0.5).close()
                return
            except OSError:
                time.sleep(0.2)
        raise Fail("proxy listener never came up on %d:\n%s" % (self.proxy, self.logtail()))

    def stop(self):
        if self.proc and self.proc.poll() is None:
            with contextlib.suppress(Exception):
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            try:
                self.proc.wait(8)
            except Exception:
                with contextlib.suppress(Exception):
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        with contextlib.suppress(Exception):
            self.log.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def restart(self):
        """Stop the process but keep the data dir, then start again (same ports)."""
        with contextlib.suppress(Exception):
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
        self.proc.wait(10)
        self.log.close()
        return self.start()

    def logtail(self, n=3000):
        try:
            with open(os.path.join(self.dir, "zoraxy.log"), "rb") as f:
                return f.read()[-n:].decode("utf8", "replace")
        except Exception:
            return ""

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.stop()

    # admin API (the same endpoints the UI uses)
    def _session(self):
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        html = self.opener.open("http://127.0.0.1:%d/index.html" % self.admin, timeout=10).read().decode()
        m = re.search(r'zoraxy.csrf.Token" content="([^"]+)"', html)
        self.csrf = m.group(1) if m else ""

    def api(self, _p, method="POST", raw=False, json_body=None, headers=None, **form):
        url = "http://127.0.0.1:%d%s" % (self.admin, _p)
        data = None
        h = {"X-CSRF-Token": self.csrf}
        if headers:
            h.update(headers)
        enc = {k: ("true" if v is True else "false" if v is False else v) for k, v in form.items() if v is not None}
        if method == "GET":
            if enc:
                url += "?" + urllib.parse.urlencode(enc)
        elif json_body is not None:
            data = json.dumps(json_body).encode()
            h["Content-Type"] = "application/json"
        else:
            data = urllib.parse.urlencode(enc).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            body = self.opener.open(req, timeout=30).read()
        except urllib.error.HTTPError as e:
            body = e.read()
            if raw:
                return e.code, body
            raise Fail("%s %s -> HTTP %d %s" % (method, _p, e.code, body[:200]))
        if raw:
            return 200, body
        try:
            v = json.loads(body)
        except Exception:
            return body.decode("utf8", "replace")
        if isinstance(v, dict) and v.get("error"):
            raise Fail("%s %s -> error: %s" % (method, _p, v["error"]))
        return v

    def get(self, _p, **q):
        return self.api(_p, method="GET", **q)

    def add_rule(self, host, upstream, tls=False, **kw):
        """Create a host-type rule like the 'New proxy rule' dialog does (POST /api/proxy/add)."""
        form = dict(type="host", rootname=host, ep=upstream, tls=tls, tlsval=False, bypassGlobalTLS=True,
                    bpwsorg=True, enableUtm=False)
        form.update(kw)
        return self.api("/api/proxy/add", **form)

    def edit_rule(self, host, **kw):
        return self.api("/api/proxy/edit", rootname=host, **kw)

    def del_rule(self, host):
        return self.api("/api/proxy/del", ep=host)

    def detail(self, host):
        return self.api("/api/proxy/detail", type="host", epname=host)

    # data-plane client
    def req(self, host, path="/", method="GET", headers=None, body=None, timeout=15, chunked=False, src=None):
        return http_req("127.0.0.1", self.proxy, host, path, method, headers, body, timeout, tls=self.tls, chunked=chunked, src=src)


# --------------------------------------------------------------------------- raw http client

class Resp:
    def __init__(self, status, headers, body, set_cookies=None):
        self.status = status
        self.headers = headers
        self.body = body
        self.set_cookies = set_cookies or []

    @property
    def text(self):
        return self.body.decode("utf8", "replace")

    def json(self):
        return json.loads(self.body)

    def h(self, k, d=None):
        return self.headers.get(k.lower(), d)

    def __repr__(self):
        return "<Resp %s %r>" % (self.status, self.body[:120])


def http_req(addr, port, host, path="/", method="GET", headers=None, body=None, timeout=15, tls=False,
             cert=None, chunked=False, src=None):
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if cert:
            ctx.load_cert_chain(*cert)
        conn = http.client.HTTPSConnection(addr, port, timeout=timeout, context=ctx)
        sni = (host or "").split(":")[0]
        raw = socket.create_connection((addr, port), timeout, source_address=(src, 0) if src else None)
        conn.sock = ctx.wrap_socket(raw, server_hostname=sni or None)  # SNI follows the Host header
    else:
        conn = http.client.HTTPConnection(addr, port, timeout=timeout, source_address=(src, 0) if src else None)
    h = {"Host": host} if host else {}
    h.update(headers or {})
    try:
        conn.request(method, path, body=body, headers=h, encode_chunked=chunked)
        r = conn.getresponse()
        data = r.read()
        return Resp(r.status, {k.lower(): v for k, v in r.getheaders()}, data, r.msg.get_all("Set-Cookie") or [])
    finally:
        conn.close()


def raw_exchange(addr, port, payload, timeout=10, tls=False, stop_at=None):
    s = socket.create_connection((addr, port), timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s)
    s.sendall(payload)
    buf = b""
    s.settimeout(timeout)
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            if stop_at and stop_at in buf:
                break
    except (socket.timeout, ConnectionError, ssl.SSLError):
        pass
    s.close()
    return buf


# --------------------------------------------------------------------------- backends

class Backend:
    """Threaded HTTP/1.1 backend. handler(h, rec, backend) is called for every request.

    Every request is recorded in .log (method, path, headers, body, client).
    """

    def __init__(self, handler=None, name="b", unix=None, bind="127.0.0.1"):
        self.log = []
        self.name = name
        self.handler = handler or default_echo
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _do(self):
                body = b""
                if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                    while True:
                        ln = int(self.rfile.readline().strip() or b"0", 16)
                        if ln == 0:
                            self.rfile.readline()
                            break
                        body += self.rfile.read(ln)
                        self.rfile.readline()
                else:
                    n = int(self.headers.get("Content-Length") or 0)
                    if n:
                        body = self.rfile.read(n)
                rec = dict(method=self.command, path=self.path, headers={k.lower(): v for k, v in self.headers.items()},
                           body=body, client=self.client_address)
                outer.log.append(rec)
                outer.handler(self, rec, outer)

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _do

        if unix:
            class UServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
                daemon_threads = True

                def get_request(self):
                    r = super().get_request()
                    return r[0], ("unix", 0)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(unix)
            self.srv = UServer(unix, H)
            self.port = None
            self.unix = unix
        else:
            class Srv(socketserver.ThreadingMixIn, http.server.HTTPServer):
                daemon_threads = True
                allow_reuse_address = True
                request_queue_size = 128
            self.port = free_port()
            self.srv = Srv((bind, self.port), H)
            self.unix = None
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    @property
    def addr(self):
        return "127.0.0.1:%d" % self.port

    def close(self):
        with contextlib.suppress(Exception):
            self.srv.shutdown()
            self.srv.server_close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def send(h, status=200, body=b"", headers=None, ctype="text/plain"):
    if isinstance(body, str):
        body = body.encode()
    h.send_response(status)
    h.send_header("Content-Type", ctype)
    h.send_header("Content-Length", str(len(body)))
    for k, v in (headers or {}).items():
        h.send_header(k, v)
    h.end_headers()
    if h.command != "HEAD":
        h.wfile.write(body)


def default_echo(h, rec, b):
    """Responds with JSON describing the request as the backend saw it."""
    out = dict(backend=b.name, method=rec["method"], path=rec["path"], headers=rec["headers"],
               body=rec["body"].decode("latin1"), client=list(rec["client"]) if rec["client"] else None)
    send(h, 200, json.dumps(out), ctype="application/json")


# --------------------------------------------------------------------------- certificates

def openssl(*args, cwd=None):
    return subprocess.run(["openssl"] + list(args), check=True, capture_output=True, cwd=cwd)


def make_ca(d, cn="E2E Test CA"):
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt", "-days", "2",
            "-subj", "/CN=" + cn, cwd=d)
    return os.path.join(d, "ca.crt"), os.path.join(d, "ca.key")


def make_leaf(d, cn, ca=None, san=None, name=None, client=False):
    ca = ca or (os.path.join(d, "ca.crt"), os.path.join(d, "ca.key"))
    name = name or cn.replace("*", "star")
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", name + ".key", "-out", name + ".csr", "-subj", "/CN=" + cn, cwd=d)
    with open(os.path.join(d, name + ".ext"), "w") as f:
        f.write("subjectAltName=%s\nextendedKeyUsage=%s\n" % (san or "DNS:" + cn, "clientAuth" if client else "serverAuth"))
    openssl("x509", "-req", "-in", name + ".csr", "-CA", ca[0], "-CAkey", ca[1], "-CAcreateserial", "-out", name + ".crt",
            "-days", "2", "-extfile", name + ".ext", cwd=d)
    return os.path.join(d, name + ".crt"), os.path.join(d, name + ".key")


# --------------------------------------------------------------------------- scenario registry

SCENARIOS = {}


def scenario(name, issues=(), needs=""):
    def deco(fn):
        SCENARIOS[name] = dict(fn=fn, issues=list(issues), doc=(fn.__doc__ or "").strip(), needs=needs)
        return fn
    return deco


def wait_for(fn, timeout=10, step=0.2, msg="condition"):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        try:
            v = fn()
            if v:
                return v
        except Exception as e:
            last = e
        time.sleep(step)
    raise Fail("timed out waiting for " + msg + (" (%s)" % last if last else ""))


# --------------------------------------------------------------------------- fake third-party HTTPS services

class FakeHTTPS:
    """Stands in for external HTTPS APIs (Turnstile, reCAPTCHA, Friendly Captcha siteverify ...).

    Zoraxy is started with HTTPS_PROXY=<this CONNECT proxy> and SSL_CERT_FILE=<our CA>, so the real
    binary talks to what it believes is e.g. challenges.cloudflare.com. handler(host, path, headers, body)
    returns (status, dict). .calls records (host, path, body).
    """

    def __init__(self, hostnames, handler, workdir):
        self.handler = handler
        self.calls = []
        ca = make_ca(workdir, "E2E Fake Provider CA")
        san = ",".join("DNS:" + h for h in hostnames)
        self.crt, self.key = make_leaf(workdir, hostnames[0], ca, san=san, name="fake")
        self.ca_file = ca[0]
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(self.crt, self.key)
        self.port = free_port()
        outer = self

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                outer._serve(self.request)

        class S(socketserver.ThreadingMixIn, socketserver.TCPServer):
            daemon_threads = True
            allow_reuse_address = True
        self.srv = S(("127.0.0.1", self.port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    @property
    def env(self):
        return {"HTTPS_PROXY": "http://127.0.0.1:%d" % self.port, "https_proxy": "http://127.0.0.1:%d" % self.port,
                "SSL_CERT_FILE": self.ca_file, "NO_PROXY": "", "no_proxy": ""}

    def _serve(self, c):
        try:
            c.settimeout(10)
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = c.recv(4096)
                if not d:
                    return
                buf += d
            first = buf.split(b"\r\n")[0].decode()
            if not first.startswith("CONNECT"):
                c.sendall(b"HTTP/1.1 400 no\r\nContent-Length: 0\r\n\r\n")
                return
            host = first.split()[1].split(":")[0]
            c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            t = self.ctx.wrap_socket(c, server_side=True)
            data = b""
            while b"\r\n\r\n" not in data:
                d = t.recv(65536)
                if not d:
                    return
                data += d
            head, _, body = data.partition(b"\r\n\r\n")
            lines = head.decode("latin1").split("\r\n")
            path = lines[0].split()[1]
            hdrs = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:])}
            n = int(hdrs.get("content-length", 0))
            while len(body) < n:
                body += t.recv(65536)
            self.calls.append((host, path, body.decode("latin1"), hdrs))
            status, obj = self.handler(host, path, hdrs, body)
            out = json.dumps(obj).encode()
            t.sendall(("HTTP/1.1 %d X\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (status, len(out))).encode() + out)
            t.close()
        except Exception:
            pass

    def close(self):
        with contextlib.suppress(Exception):
            self.srv.shutdown()
            self.srv.server_close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def build_example_plugin(name):
    """Builds example/plugins/<name> (needs only the SDK copy that is committed in its mod/ dir)."""
    out = os.path.join(tempfile.gettempdir(), "zoraxy-e2e-plugin-" + name)
    d = os.path.join(ROOT, "example", "plugins", name)
    env = dict(os.environ, GOFLAGS="-mod=mod", GOTMPDIR=os.path.expanduser("~/.cache/go-tmp"))
    os.makedirs(env["GOTMPDIR"], exist_ok=True)
    subprocess.check_call(["go", "build", "-o", out, "."], cwd=d, env=env)
    return out
