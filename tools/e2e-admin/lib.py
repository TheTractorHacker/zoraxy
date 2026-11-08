"""Helpers for the admin end-to-end suite: throw-away Zoraxy instances, an API client
(cookie session + CSRF), local receiver/backend servers and a result recorder.

Everything runs under a temp dir with its own conf/db/ports. Nothing here touches a real install."""
import http.cookiejar, http.server, json, os, re, shutil, signal, socket, ssl, subprocess
import tempfile, threading, time, urllib.error, urllib.parse, urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BIN = os.environ.get("ZORAXY_BIN", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".build", "zoraxy"))
PORT_BASE = int(os.environ.get("E2E_PORT_BASE", "28830"))
PORT_MAX = PORT_BASE + 19
_ports_used = set()
_procs = []


def alloc_port():
    for p in range(PORT_BASE, PORT_MAX + 1):
        if p in _ports_used:
            continue
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
        except OSError:
            continue
        finally:
            s.close()
        _ports_used.add(p)
        return p
    raise RuntimeError("out of ports")


def free_port(p):
    _ports_used.discard(p)


class Check(Exception):
    pass


def check(cond, msg):
    if not cond:
        raise Check(msg)
    return True


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Client:
    """Admin API client: keeps cookies, fetches the CSRF token from /login.html or /."""

    def __init__(self, base):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),
                                                  urllib.request.HTTPSHandler(context=ctx), NoRedirect)
        self.csrf = None

    def raw(self, method, path, data=None, headers=None, timeout=30):
        h = dict(headers or {})
        body = None
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data, doseq=True).encode()
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, (bytes, str)):
            body = data.encode() if isinstance(data, str) else data
        if self.csrf and method != "GET":
            h.setdefault("X-CSRF-Token", self.csrf)
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=h)
        try:
            r = self.opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            r = e
        return (r.status if hasattr(r, "status") else r.code), r.read(), dict(r.headers)

    def refresh_csrf(self):
        st, body, _ = self.raw("GET", "/login.html")
        if st != 200:
            st, body, _ = self.raw("GET", "/")
        m = re.search(rb'zoraxy.csrf.Token" content="([^"]+)"', body)
        if m:
            self.csrf = m.group(1).decode()
        return self.csrf

    def get(self, path, **q):
        if q:
            path += ("&" if "?" in path else "?") + urllib.parse.urlencode(q, doseq=True)
        st, body, _ = self.raw("GET", path)
        return st, _j(body)

    def post(self, path, **form):
        if not self.csrf:
            self.refresh_csrf()
        st, body, _ = self.raw("POST", path, form)
        return st, _j(body)

    def ok(self, path, method="POST", **form):
        """call and require HTTP 200 and no {"error":...}; returns parsed body"""
        st, js = (self.post(path, **form) if method == "POST" else self.get(path, **form))
        check(st == 200, f"{path}: HTTP {st} {js!r:.200}")
        if isinstance(js, dict) and js.get("error"):
            raise Check(f"{path}: error {js['error']}")
        return js

    def login(self, user, pw):
        self.refresh_csrf()
        st, js = self.post("/api/auth/login", username=user, password=pw)
        self.refresh_csrf()
        return st, js


def _j(b):
    try:
        return json.loads(b)
    except Exception:
        return b.decode(errors="replace")


class Instance:
    def __init__(self, name, noauth=True, flags=(), env=None, tls=False, binary=None, workdir=None, port=None):
        self.name = name
        self.dir = workdir or tempfile.mkdtemp(prefix=f"e2e-{name}-")
        self.port = port or alloc_port()
        self.noauth = noauth
        self.flags = list(flags)
        self.env = env or {}
        self.tls = tls
        self.bin = binary or BIN
        self.proc = None
        web = os.path.join(self.dir, "web")
        if not os.path.exists(web):
            os.symlink(os.path.join(ROOT, "src", "web"), web)
        self.client = None

    @property
    def url(self):
        return f"{'https' if self.tls else 'http'}://127.0.0.1:{self.port}"

    def start(self, wait=True):
        args = [self.bin, "-port", f":{self.port}", "-conf", "./conf", "-dbpath", "./sys.db", "-mdns=false",
                "-fastgeoip=false", "-dev"] + (["-noauth"] if self.noauth else []) + self.flags
        env = dict(os.environ, **self.env)
        self.log = open(os.path.join(self.dir, "zoraxy.log"), "ab")
        self.proc = subprocess.Popen(args, cwd=self.dir, stdout=self.log, stderr=subprocess.STDOUT, env=env,
                                     start_new_session=True)
        _procs.append(self.proc)
        self.client = Client(self.url)
        if wait:
            self.wait_up()
        return self

    def wait_up(self, timeout=40):
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                raise Check(f"{self.name}: exited early rc={self.proc.returncode}: {self.tail()}")
            try:
                st, _, _ = self.client.raw("GET", "/login.html", timeout=2)
                if st in (200, 302, 401, 403):
                    return
            except Exception:
                pass
            time.sleep(0.3)
        raise Check(f"{self.name}: not up: {self.tail()}")

    def tail(self, n=1500):
        try:
            return open(os.path.join(self.dir, "zoraxy.log"), errors="replace").read()[-n:]
        except Exception:
            return ""

    def stop(self, sig=signal.SIGTERM):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, sig)
            except Exception:
                pass
            try:
                self.proc.wait(10)
            except Exception:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except Exception:
                    pass

    def restart(self, **kw):
        self.stop()
        self.proc = None
        return self.start(**kw)

    def cleanup(self, keep=False):
        self.stop()
        free_port(self.port)
        if not keep:
            shutil.rmtree(self.dir, ignore_errors=True)


def kill_all():
    for p in _procs:
        if p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except Exception:
                pass


class Recorder:
    """HTTP server recording every request; handler(req)->(status, headers, body)"""

    def __init__(self, handler=None, tls_cert=None, port=None):
        self.reqs = []
        self.handler = handler or (lambda r: (200, {}, b"ok"))
        self.port = port or alloc_port()
        rec = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _do(self):
                ln = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(ln) if ln else b""
                r = {"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body,
                     "peer": self.client_address[0], "time": time.time()}
                rec.reqs.append(r)
                st, hd, bd = rec.handler(r)
                if isinstance(bd, str):
                    bd = bd.encode()
                self.send_response(st)
                for k, v in hd.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(bd)))
                self.end_headers()
                self.wfile.write(bd)

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _do

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), H)
        if tls_cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls_cert)
            self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()
        free_port(self.port)

    def wait_for(self, pred, timeout=15):
        end = time.time() + timeout
        while time.time() < end:
            for r in list(self.reqs):
                if pred(r):
                    return r
            time.sleep(0.2)
        return None


def http_get(url, headers=None, timeout=10, host=None):
    """plain GET that does not follow redirects; returns (status, body, headers)"""
    h = dict(headers or {})
    if host:
        h["Host"] = host
    op = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    try:
        r = op.open(urllib.request.Request(url, headers=h), timeout=timeout)
    except urllib.error.HTTPError as e:
        r = e
    return (r.status if hasattr(r, "status") else r.code), r.read(), dict(r.headers)


def wait_until(pred, timeout=15, step=0.3):
    end = time.time() + timeout
    while time.time() < end:
        try:
            v = pred()
            if v:
                return v
        except Exception:
            pass
        time.sleep(step)
    return None


def selfsigned(dirpath, cn="localhost", days=30):
    crt, key = os.path.join(dirpath, f"{cn}.crt"), os.path.join(dirpath, f"{cn}.key")
    subprocess.check_call(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                           "-days", str(days), "-subj", f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn},IP:127.0.0.1"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return crt, key
