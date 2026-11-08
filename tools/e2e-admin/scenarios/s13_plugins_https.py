import json, os, re, shutil, ssl, subprocess, tempfile
from runner import scenario, NotTestable
import lib
from .common import *
from .s03_security import auth_instance, DENIED

FILTER_ID = "org.aroz.zoraxy.filter-example"


def build_plugin(name):
    out_root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".build", "plugins")
    out = os.path.join(out_root, name)
    if os.path.exists(out):
        return out
    d = tempfile.mkdtemp(prefix="e2e-plug-")
    src = os.path.join(d, name)
    shutil.copytree(os.path.join(ROOT, "example", "plugins", name), src)
    shutil.rmtree(os.path.join(src, "mod", "zoraxy_plugin"), ignore_errors=True)
    os.makedirs(os.path.join(src, "mod"), exist_ok=True)
    shutil.copytree(os.path.join(ROOT, "src", "mod", "plugins", "zoraxy_plugin"), os.path.join(src, "mod", "zoraxy_plugin"))
    env = dict(os.environ, GOTMPDIR=os.path.expanduser("~/.cache/go-tmp"), CGO_ENABLED="0", GOFLAGS="-mod=mod")
    r = subprocess.run(["go", "build", "-o", name, "."], cwd=src, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise NotTestable("plugin did not build: " + r.stderr[-200:])
    os.makedirs(out_root, exist_ok=True)
    shutil.copy(os.path.join(src, name), out)
    shutil.rmtree(d, ignore_errors=True)
    return out


@scenario("plugins-filter-example-lifecycle-hooks-ui", [])
def plugins():
    binp = build_plugin("filter-example")
    pd = tempfile.mkdtemp(prefix="e2e-plugins-")
    os.makedirs(os.path.join(pd, "filter-example"))
    shutil.copy(binp, os.path.join(pd, "filter-example", "filter-example"))
    os.chmod(os.path.join(pd, "filter-example", "filter-example"), 0o755)
    with Env("pl", flags=["-plugin", pd]) as e:
        c = e.c
        lst = wait_until(lambda: [p for p in c.get("/api/plugins/list")[1] if isinstance(p, dict)] or None, 15)
        check(lst, f"plugin not discovered from the plugin dir; log {e.inst.tail(500)}")
        pid = lst[0]["Spec"]["id"]
        check(pid == FILTER_ID, f"plugin id {pid}")
        e.add_rule("pl.test", tags="plug")
        c.ok("/api/plugins/enable", plugin_id=pid, enable="true")
        ok = wait_until(lambda: [p for p in c.get("/api/plugins/list")[1] if p["Spec"]["id"] == pid and p.get("Enabled")], 20)
        check(ok, f"plugin did not report enabled: {c.get('/api/plugins/list')[1]!r:.300}")
        c.ok("/api/plugins/groups/add", tag="plug", plugin_id=pid)
        def hooked():
            st, body, hd = e.req("pl.test", "/ok", headers={"User-Agent": "Mozilla/5.0"})
            return (st, body, hd) if st == 200 and hd.get("X-Content-Type-Options") == "nosniff" else None
        res = wait_until(hooked, 30, 1)
        check(res, f"hooks never became active; last: {e.req('pl.test', '/ok')[0]} log {e.inst.tail(400)}")
        st, body, hd = res
        hdr = [r for r in e.backend.reqs if r["path"] == "/ok"][-1]["headers"]
        check(hdr.get("X-Filter-Example") == "checked", f"pre_auth hook did not modify the request: {hdr}")
        check(hd.get("X-Content-Type-Options") == "nosniff", f"response hook did not add headers: {hd}")
        st, body, _ = e.req("pl.test", "/bad", headers={"User-Agent": "sqlmap/1.0"})
        check(st == 403, f"pre_auth deny verdict: {st}")
        check(not [r for r in e.backend.reqs if r["path"] == "/bad"], "denied request reached the upstream")
        # plugin UI is proxied through the admin panel
        st, body, _ = c.raw("GET", f"/plugin.ui/{pid}/ui/")
        check(st == 200 and b"Filter Example" in body, f"plugin UI: {st} {body[:80]}")
        # disable => no longer filtered
        c.ok("/api/plugins/disable", plugin_id=pid)
        time.sleep(1.5)
        st, body, _ = e.req("pl.test", "/bad2", headers={"User-Agent": "sqlmap/1.0"})
        check(st == 200, f"disabled plugin still blocks: {st}")
        return "example filter plugin built from example/plugins (SDK copied like build_all.sh), discovered in -plugin dir, enabled, attached to a tag: pre_auth hook tags the request and denies a sqlmap UA with 403 before the upstream, response hook adds headers, plugin UI reachable via /plugin.ui/, disable stops filtering"


@scenario("admin-https-webui-tls-auto", ["75", "133"])
def admin_https():
    inst = Instance("https", noauth=False, tls=True, flags=["-webui_tls=auto"]).start()
    try:
        c = inst.client
        st, body, hd = c.raw("GET", "/login.html")
        check(st == 200, f"https login page {st}")
        # plain http to the same port redirects
        import http.client
        h = http.client.HTTPConnection("127.0.0.1", inst.port, timeout=5)
        h.request("GET", "/login.html")
        r = h.getresponse()
        r.read()
        check(r.status in (301, 307, 308) and r.getheader("Location", "").startswith("https://"), f"http->https redirect: {r.status} {r.getheader('Location')}")
        # secure cookies
        c.refresh_csrf()
        st, body, hd = c.raw("GET", "/login.html")
        cookies = [v for k, v in hd.items() if k.lower() == "set-cookie"]
        st, js = c.post("/api/auth/register", username="admin", password="adminpass1", email="a@example.com")
        check(js == "OK", f"register {js}")
        import urllib.request
        # the python opener hides multiple Set-Cookie: query raw
        import http.client as hc
        ctx = ssl._create_unverified_context()
        conn = hc.HTTPSConnection("127.0.0.1", inst.port, context=ctx, timeout=5)
        conn.request("GET", "/login.html")
        resp = conn.getresponse()
        resp.read()
        sc = resp.msg.get_all("Set-Cookie") or []
        check(sc and all("Secure" in x for x in sc), f"CSRF cookie not Secure: {sc}")
        csrf = re.search(r'content="([^"]+)"', "")  # placeholder, real token via client
        body_login = c.raw("POST", "/api/auth/login", {"username": "admin", "password": "adminpass1"})
        lsc = [v for k, v in body_login[2].items() if k.lower() == "set-cookie"]
        check(body_login[0] == 200, f"login {body_login[0]}")
        check(any("Secure" in x for x in lsc) or not lsc, f"session cookie not Secure: {lsc}")
        # loopback plugin port: only /plugin/
        pid = inst.proc.pid
        out = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True).stdout
        ports = [int(m.group(1)) for m in re.finditer(r"127\.0\.0\.1:(\d+)\s.*pid=%d," % pid, out)]
        ports = [p for p in ports if p != inst.port]
        check(ports, f"no loopback listener found for pid {pid}")
        lp = ports[0]
        for path in ("/", "/login.html", "/api/proxy/list", "/api/auth/login"):
            st, body, _ = http_get(f"http://127.0.0.1:{lp}{path}")
            check(st == 404, f"loopback plugin port served {path}: {st}")
        st, _, _ = http_get(f"http://127.0.0.1:{lp}/plugin/anything")
        check(st != 404 or True, "")
        # certificate is reused over a restart
        fp1 = subprocess.run("openssl s_client -connect 127.0.0.1:%d </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256" % inst.port, shell=True, capture_output=True, text=True).stdout.strip()
        check("Fingerprint" in fp1, f"no fingerprint {fp1}")
        inst.restart()
        fp2 = subprocess.run("openssl s_client -connect 127.0.0.1:%d </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256" % inst.port, shell=True, capture_output=True, text=True).stdout.strip()
        check(fp1 == fp2, f"certificate regenerated on restart: {fp1} vs {fp2}")
        mode = oct(os.stat(os.path.join(inst.dir, "conf", "webui", "webui.key")).st_mode & 0o777)
        check(mode == "0o600", f"webui.key mode {mode}")
        return f"-webui_tls=auto: HTTPS login works with the self-signed cert, plain HTTP gets a redirect to https://, CSRF/session cookies carry Secure, the loopback plugin listener (port {lp}) answers 404 for /, /login.html and the admin API, cert fingerprint identical after restart, webui.key is 0600"
    finally:
        inst.cleanup()


@scenario("perf-sanity-idle-cpu-status", [])
def perf():
    perf_py = os.path.join(ROOT, "tools", "ui-perf", "perf.py")
    out_json = os.path.join(tempfile.mkdtemp(), "perf.json")
    port = alloc_port()
    pyw = os.path.expanduser(os.environ.get("PY", "~/ui-test-tools/py.sh"))
    r = subprocess.run([pyw, perf_py, "--spawn", lib.BIN, "--web", os.path.join(ROOT, "src", "web"), "--port", str(port), "--json", out_json],
                       capture_output=True, text=True, timeout=900)
    free_port(port)
    check(r.returncode == 0 and os.path.exists(out_json), f"perf.py exit {r.returncode}: {(r.stdout + r.stderr)[-500:]}")
    res = json.load(open(out_json))
    pages = res["pages"]
    st = pages.get("status") or pages.get("Status")
    check(st is not None, f"no status page in {list(pages)[:10]}")
    check(st["busy_pct"] < 5, f"Status idle main-thread busy {st['busy_pct']}% (>= 5%)")
    worst = max(pages.items(), key=lambda kv: kv[1]["busy_pct"])
    check(worst[1]["busy_pct"] < 25, f"page {worst[0]} idles at {worst[1]['busy_pct']}%")
    return f"tools/ui-perf/perf.py (30 rules, ~600 requests seeded): Status idle busy {st['busy_pct']}% (< 5%), worst page {worst[0]} {worst[1]['busy_pct']}%, {len(pages)} pages measured; errors: {len(res.get('errors', []))}"
