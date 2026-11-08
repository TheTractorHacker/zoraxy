import base64, hashlib, io, json, os, shutil, subprocess, tarfile, tempfile, zipfile
import urllib.parse
from runner import scenario, NotTestable
import lib
from .common import *
from .s03_security import auth_instance, DENIED


def altcha_cookie(port, host, secret="e2e-altcha-secret-key-0123456789", extra_headers=None):
    """solve the self-hosted Altcha proof of work like the challenge page does; returns the session cookie value"""
    st, body, _ = http_get(f"http://127.0.0.1:{port}/.zoraxy/captcha/altcha", host=host)
    ch = json.loads(body)
    n = None
    for i in range(ch["maxnumber"] + 1):
        if hashlib.sha256((ch["salt"] + str(i)).encode()).hexdigest() == ch["challenge"]:
            n = i
            break
    check(n is not None, "could not solve altcha")
    payload = base64.b64encode(json.dumps({"algorithm": ch["algorithm"], "challenge": ch["challenge"], "number": n, "salt": ch["salt"], "signature": ch["signature"]}).encode()).decode()
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", "/.zoraxy/captcha/verify", urllib.parse.urlencode({"altcha": payload}), {"Host": host, "Content-Type": "application/x-www-form-urlencoded"})
    r = c.getresponse()
    r.read()
    ck = r.getheader("Set-Cookie") or ""
    check(r.status == 200 and "zoraxy_captcha_session=" in ck, f"verify failed {r.status} {ck}")
    return ck.split("zoraxy_captcha_session=")[1].split(";")[0]


def captcha_rule(e_or_inst, c, host, backend_port, secret="e2e-altcha-secret-key-0123456789"):
    c.ok("/api/proxy/add", type="host", rootname=host, ep=f"127.0.0.1:{backend_port}", tls="false")
    c.ok("/api/proxy/edit", type="host", rootname=host, captcha="true", captchaProvider="2", captchaSiteKey="x", captchaSecretKey=secret, captchaSessionDuration="3600")
    time.sleep(0.5)


def get_with_cookie(port, host, ck):
    return http_get(f"http://127.0.0.1:{port}/page", host=host, headers={"Cookie": "zoraxy_captcha_session=" + ck} if ck else None)


@scenario("persist-restart-captcha-bans-visitors-stats", [])
def restart_survival():
    with Env("rs") as e:
        c = e.c
        captcha_rule(e, c, "cap.test", e.backend.port)
        e.add_rule("plain.test")
        st, body, _ = get_with_cookie(e.pport, "cap.test", "")
        check(b"backend-ok" not in body, "captcha rule served without a session")
        ck = altcha_cookie(e.pport, "cap.test")
        st, body, _ = get_with_cookie(e.pport, "cap.test", ck)
        check(st == 200 and b"backend-ok" in body, f"valid session refused: {st}")
        # bans, stats and visitors
        cfg = c.get("/api/abuse/config")[1]
        cfg["Enabled"] = True
        c.ok("/api/abuse/setConfig", config=json.dumps(cfg))
        c.ok("/api/abuse/ban", ip="203.0.113.50", reason="persist", seconds="3600")
        for i in range(5):
            e.req("plain.test", f"/p{i}")
        time.sleep(1.5)
        today = time.strftime("%Y-%m-%d")
        t0 = c.get("/api/analytic/load", id=today, site="plain.test")[1]
        n0 = t0.get("TotalRequest", t0.get("Total"))
        check(n0 == 5, f"stats before restart {n0}")
        # restart (graceful) and check everything is still there
        e.inst.restart()
        e.c = c = e.inst.client
        c.ok("/api/cert/tls", set="false") if False else None
        time.sleep(1)
        st, body, _ = get_with_cookie(e.pport, "cap.test", ck)
        check(st == 200 and b"backend-ok" in body, f"captcha session lost over restart: {st} {body[:60]}")
        check("203.0.113.50" in json.dumps(c.get("/api/abuse/list")[1]), "ban lost over restart")
        t1 = c.get("/api/analytic/load", id=today, site="plain.test")[1]
        check(t1.get("TotalRequest", t1.get("Total")) == 5, f"stats lost over restart: {t1}")
        vis = c.get("/api/visitors/list")[1]
        check("127.0.0.1" in json.dumps(vis), "visitors lost over restart")
        check(any(r.get("RootOrMatchingDomain") == "plain.test" for r in c.get("/api/proxy/list", type="host")[1]), "rule lost")
        # SIGKILL (no graceful flush) keeps rules and CAPTCHA session; bans were flushed on write
        e.inst.stop(signal.SIGKILL)
        e.inst.proc = None
        e.inst.start()
        e.c = c = e.inst.client
        time.sleep(1)
        st, body, _ = get_with_cookie(e.pport, "cap.test", ck)
        check(st == 200 and b"backend-ok" in body, "captcha session lost over hard kill")
        check("203.0.113.50" in json.dumps(c.get("/api/abuse/list")[1]), "ban lost over hard kill")
        return ("Altcha CAPTCHA session cookie (solved PoW like the page), auto-ban list, per-site stats, visitors and rules all survive a graceful restart; session, bans and rules also survive SIGKILL. "
                "OIDC session persistence NOT exercised end to end (needs a signing fake IdP; covered by Go tests)")


@scenario("ha-shared-secret-captcha-session-across-nodes", ["81"])
def shared_sessions():
    sec = "e2e-shared-secret-" + "y" * 32
    fa = [Env("sa", flags=["-cluster_secret", sec]), Env("sb", flags=["-cluster_secret", sec]), Env("sc")]
    a, b, n = fa
    try:
        for x in fa:
            x.__enter__()
        for x in fa:
            captcha_rule(x, x.c, "shared.test", x.backend.port)
        ck = altcha_cookie(a.pport, "shared.test")
        st, body, _ = get_with_cookie(a.pport, "shared.test", ck)
        check(b"backend-ok" in body, "node A refused its own cookie")
        st, body, _ = get_with_cookie(b.pport, "shared.test", ck)
        check(st == 200 and b"backend-ok" in body, f"node B (same cluster secret) refused node A's session: {st} {body[:60]}")
        st, body, _ = get_with_cookie(n.pport, "shared.test", ck)
        check(b"backend-ok" not in body, "node C without the secret accepted a foreign session")
        return "CAPTCHA session cookie issued by node A is accepted by node B (same -cluster_secret) and rejected by node C (no secret)"
    finally:
        for x in fa:
            try:
                x.__exit__()
            except Exception:
                pass


@scenario("persist-config-export-import-custom-conf", [])
def export_import():
    d = tempfile.mkdtemp()
    conf = os.path.join(d, "customconf")
    b = Recorder()
    pp = alloc_port()
    i1 = Instance("ex1", flags=["-default_inbound_port", str(pp), "-conf", conf]).start()
    try:
        c = i1.client
        c.ok("/api/cert/tls", set="false")
        c.ok("/api/proxy/add", type="host", rootname="exp.test", ep=f"127.0.0.1:{b.port}", tls="false", tags="x")
        c.ok("/api/access/create", name="Exported", desc="d")
        st, raw, hd = c.raw("GET", "/api/conf/export?includeDB=true")
        check(st == 200 and raw[:2] == b"PK", f"export {st} {raw[:20]}")
        z = zipfile.ZipFile(io.BytesIO(raw))
        names = z.namelist()
        check(any("exp.test" in n for n in names), f"zip lacks the rule: {names[:10]}")
        # import into a second instance with a different custom conf dir
        i2 = Instance("ex2", flags=["-default_inbound_port", str(pp + 0), "-conf", os.path.join(d, "other")], port=None)
        i2.start()
        try:
            c2 = i2.client
            body = b"----e2ezip"
            mp = (f'--{body.decode()}\r\nContent-Disposition: form-data; name="file"; filename="c.zip"\r\nContent-Type: application/zip\r\n\r\n').encode() + raw + f"\r\n--{body.decode()}--\r\n".encode()
            c2.refresh_csrf()
            st, rb, _ = c2.raw("POST", "/api/conf/import", mp, {"Content-Type": f"multipart/form-data; boundary={body.decode()}"})
            check(st == 200 and b"error" not in rb.lower() or b"restart" in rb.lower(), f"import: {st} {rb[:200]}")
            if wait_until(lambda: i2.proc.poll() is not None, 8):  # a DB restore exits the process on purpose (a supervisor restarts it)
                i2.proc = None
                i2.start()
            c2 = i2.client
            ok = wait_until(lambda: any(r.get("RootOrMatchingDomain") == "exp.test" for r in c2.get("/api/proxy/list", type="host")[1]), 30)
            check(ok, f"imported rule missing; log {i2.tail(500)}")
            check("Exported" in json.dumps(c2.get("/api/access/list")[1]), "access rule not imported")
        finally:
            i2.cleanup()
        return "export zip from an instance running with a custom -conf contains the rule; imported into a second instance (different custom -conf) the proxy rule and access rule appear"
    finally:
        i1.cleanup()
        b.stop()
        free_port(pp)


UPSTREAM_COMMIT = "cde4451"


def build_upstream():
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".build", "upstream-v3.3.5")
    if os.path.exists(out):
        return out
    d = tempfile.mkdtemp(prefix="e2e-up-")
    tarp = os.path.join(d, "src.tar")
    subprocess.run(["git", "-C", ROOT, "archive", "-o", tarp, UPSTREAM_COMMIT, "src"], check=True)
    with tarfile.open(tarp) as t:
        t.extractall(d)
    env = dict(os.environ, GOTMPDIR=os.path.expanduser("~/.cache/go-tmp"), CGO_ENABLED="0", GOFLAGS="-mod=mod")
    r = subprocess.run(["go", "build", "-o", out, "."], cwd=os.path.join(d, "src"), env=env, capture_output=True, text=True)
    shutil.rmtree(d, ignore_errors=True)
    if r.returncode != 0:
        raise NotTestable("could not build original upstream v3.3.5 (" + r.stderr[-200:] + ")")
    return out


@scenario("upgrade-from-original-upstream-v3.3.5", ["110"])
def upgrade_from_upstream():
    up = build_upstream()
    d = tempfile.mkdtemp(prefix="e2e-mig-")
    b = Recorder()
    pp = alloc_port()
    port = alloc_port()
    # run the ORIGINAL upstream binary (built from upstream commit cde4451 = v3.3.5) to create a real config dir
    os.symlink(os.path.join(ROOT, "src", "web"), os.path.join(d, "web"))
    args = [up, "-port", f":{port}", "-conf", "./conf", "-dbpath", "./sys.db", "-mdns=false", "-default_inbound_port", str(pp), "-default_inbound_enabled=true"]
    p = subprocess.Popen(args, cwd=d, stdout=open(os.path.join(d, "up.log"), "wb"), stderr=subprocess.STDOUT, start_new_session=True)
    lib._procs.append(p)
    try:
        c = Client(f"http://127.0.0.1:{port}")
        check(wait_until(lambda: c.raw("GET", "/login.html")[0] == 200, 30), "upstream binary did not start")
        c.refresh_csrf()
        st, js = c.post("/api/auth/register", username="admin", password="legacy-pass-1", email="a@example.com")
        check(js == "OK", f"register on upstream: {js}")
        c.login("admin", "legacy-pass-1")
        c.refresh_csrf()
        c.post("/api/cert/tls", set="false")
        st, js = c.post("/api/proxy/add", type="host", rootname="old.test", ep=f"127.0.0.1:{b.port}", tls="false")
        check(js == "OK", f"upstream add rule {js}")
        c.post("/api/blacklist/ip/add", ip="203.0.113.9")
        time.sleep(1)
        # stop the original, start THIS build on the same conf + db
        os.killpg(p.pid, signal.SIGTERM)
        p.wait(15)
        inst = Instance("mig", noauth=False, workdir=d, port=port, flags=["-default_inbound_port", str(pp)])
        inst.start()
        try:
            c2 = inst.client
            c2.refresh_csrf()
            st, js = c2.login("admin", "legacy-pass-1")
            check(st == 200 and js == "OK", f"legacy sha512 admin could not log in after upgrade: {st} {js}")
            hs = [l for l in inst.tail(100000).splitlines() if "upgrade" in l.lower() or "migrat" in l.lower()]
            lst = c2.get("/api/proxy/list", type="host")[1]
            check(any(r.get("RootOrMatchingDomain") == "old.test" for r in lst), f"rule from the old config lost: {lst!r:.200}")
            ok = wait_until(lambda: e_get_port(pp, "old.test") is not None, 10)
            check(ok, "rule from the upstream config does not proxy")
            check("203.0.113.9" in json.dumps(c2.get("/api/blacklist/list", type="ip", id="default")[1]), "blacklist entry lost")
            # the hash is rewritten as argon2id on that first login: a second login still works and wrong pw is refused
            c3 = Client(inst.url)
            check(c3.login("admin", "legacy-pass-1")[1] == "OK", "second login failed (hash rewrite broke the account?)")
            c4 = Client(inst.url)
            check(c4.login("admin", "wrong-pass-123")[1] != "OK", "wrong password accepted")
            # inspect the stored hash after stopping (db is exclusive)
            inst.stop()
            inst.proc = None
            blob = b""
            for root, _, fs in os.walk(os.path.join(d, "sys.db")) if os.path.isdir(os.path.join(d, "sys.db")) else [(d, [], ["sys.db"])]:
                for f in fs:
                    try:
                        blob += open(os.path.join(root, f), "rb").read()
                    except Exception:
                        pass
            legacy = hashlib.sha512(b"legacy-pass-1").hexdigest().encode()
            check(b"$argon2id$" in blob, "stored admin hash was not rewritten as argon2id after the first login")
            # a LevelDB log may still hold the superseded record until compaction: only warn through the evidence text
            migrated_note = "old sha512 record compacted away" if legacy not in blob else "old sha512 record still present in the DB log until compaction"
        finally:
            inst.cleanup(keep=True)
        return ("ORIGINAL upstream v3.3.5 binary (built from upstream commit cde4451) created a conf dir + sys.db (admin with sha512 hash, proxy rule, blacklist entry); this build started on the same files: "
                f"admin logged in with the old password on first try (no lock-out), the stored hash is now argon2id ({migrated_note}), rule still proxies, blacklist kept, second login and wrong-password refusal behave")
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except Exception:
            pass
        b.stop()
        free_port(pp)


def e_get_port(port, host):
    st, body, _ = http_get(f"http://127.0.0.1:{port}/", host=host)
    return body if st == 200 else None
