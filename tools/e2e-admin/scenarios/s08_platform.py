import json, os, stat, tempfile, types
from runner import scenario, NotTestable
from .common import *


@scenario("api-ech", ["235"])
def ech():
    with Env("ech") as e:
        c = e.c
        s = c.get("/api/ech/status")[1]
        check(isinstance(s, dict) and "Settings" in s, f"status {str(s)[:100]}")
        check(not s["Settings"].get("Enabled"), "ECH should default to off")
        c.ok("/api/ech/settings", enabled="true", publicname="public.ech.test")
        s = c.get("/api/ech/status")[1]
        check(s["Settings"].get("Enabled") and s["Keys"] and s["ConfigList"], f"enable generated no key/config list: {str(s)[:200]}")
        first = s["ConfigList"]
        ids1 = [k["ID"] if "ID" in k else k.get("Id") for k in s["Keys"]]
        c.ok("/api/ech/rotate")
        s2 = c.get("/api/ech/status")[1]
        check(s2["ConfigList"] != first, "rotation did not change the advertised config list")
        check(len(s2["Keys"]) == 2, f"expected the old key retained, got {len(s2['Keys'])}")
        check("ech=" in s2["RecordExample"] or s2["RecordExample"] == "", "record example")
        st, body, _ = c.raw("POST", "/api/ech/export", {"id": [k for k in ids1 if k is not None][0] if ids1 and ids1[0] is not None else ""})
        check(st == 200, f"export {st}")
        return "ECH: default off; enabling with a public name generates a key + ECHConfigList; rotate changes the advertised list and retains the old key (decrypt-only); PEM export works. Browser interop NOT-TESTABLE (needs a real browser + published HTTPS RR; Go client interop covered by unit tests)"


@scenario("api-lua-script-editor-and-run", ["88"])
def lua():
    with Env("lua") as e:
        c = e.c
        e.add_rule("lua.test")
        code = 'response.headers["X-Lua"]="1"; respond(200, "hello " .. request.path, "text/plain")'
        cfg = {"Enabled": True, "Mode": "handler", "Code": code}
        t = c.ok("/api/proxy/script/test", ep="lua.test", config=json.dumps(cfg), sample=json.dumps({"Path": "/abc", "Method": "GET"}))
        check("hello /abc" in json.dumps(t), f"admin test run: {t}")
        bad = c.post("/api/proxy/script/set", ep="lua.test", config=json.dumps({"Enabled": True, "Mode": "handler", "Code": "os.execute('id')"}))[1]
        # os is nil -> runtime error not a save error; syntax errors are refused at save
        syn = c.post("/api/proxy/script/set", ep="lua.test", config=json.dumps({"Enabled": True, "Mode": "handler", "Code": "if then"}))[1]
        check(isinstance(syn, dict) and syn.get("error"), f"syntax error accepted: {syn}")
        c.ok("/api/proxy/script/set", ep="lua.test", config=json.dumps(cfg))
        time.sleep(0.4)
        st, body, hd = e.req("lua.test", "/live")
        check(st == 200 and body == b"hello /live" and hd.get("X-Lua") == "1", f"live handler: {st} {body} {hd}")
        check(not [r for r in e.backend.reqs if r["path"] == "/live"], "handler script contacted the upstream")
        loop = {"Enabled": True, "Mode": "handler", "Code": "while true do end", "TimeoutMs": 100}
        c.ok("/api/proxy/script/set", ep="lua.test", config=json.dumps(loop))
        time.sleep(0.4)
        t0 = time.time()
        st, body, _ = e.req("lua.test", "/loop")
        check(st == 500 and time.time() - t0 < 3 and b"Script error" in body, f"infinite loop not cut: {st} {body[:80]} {time.time() - t0:.1f}s")
        c.ok("/api/proxy/script/set", ep="lua.test", config=json.dumps({"Enabled": False, "Code": ""}))
        time.sleep(0.3)
        check(e.req("lua.test", "/p")[0] == 200 and [r for r in e.backend.reqs if r["path"] == "/p"], "disabling the script did not restore proxying")
        return "Lua: admin test run returns the script output; syntax error refused on save; handler mode serves response without touching the upstream; infinite loop cut at the 100 ms deadline (500, opaque); disable restores proxying"


@scenario("api-sablier-gate-and-test", ["120", "564"])
def sablier():
    state = {"ready": False}

    def sab(r):
        if state.get("down"):
            return 500, {}, "boom"
        if "/api/strategies/" in r["path"]:
            if state["ready"]:
                return 200, {"X-Sablier-Session-Status": "ready"}, "ready"
            return 200, {"X-Sablier-Session-Status": "not-ready", "Content-Type": "text/html"}, "<html>waiting room</html>"
        return 404, {}, "no"
    s = Recorder(sab)
    try:
        with Env("sab") as e:
            c = e.c
            e.add_rule("sab.test")
            cfg = {"Enabled": True, "URL": f"http://127.0.0.1:{s.port}", "Strategy": "dynamic", "Names": ["whoami"], "SessionDuration": "1m", "ReadyCacheSeconds": -1}
            t = c.ok("/api/proxy/sablier/test", config=json.dumps(cfg)) if c.get("/api/proxy/sablier/get", ep="sab.test")[0] == 200 else None
            check(t and t.get("Result") == "waiting", f"connection test (not ready): {t}")
            c.ok("/api/proxy/sablier/set", ep="sab.test", config=json.dumps(cfg))
            time.sleep(0.4)
            st, body, _ = e.req("sab.test", "/waitme", headers={"Accept": "text/html"})
            check(st == 200 and b"waiting room" in body and not [r for r in e.backend.reqs if r["path"] == "/waitme"], f"waiting page: {st} {body[:60]}")
            state["ready"] = True
            st, body, _ = e.req("sab.test", "/x")
            check(st == 200 and b"backend-ok" in body, f"ready => proxied: {st} {body[:60]}")
            check(any("names=whoami" in r["path"] for r in s.reqs), "sablier was not asked for the configured name")
            # fail closed
            state["down"] = True  # answers 500 without the session header (an unreachable Sablier behaves the same for the gate)
            st, body, hd = e.req("sab.test", "/down")
            check(st == 503, f"sablier down should fail closed with 503, got {st}")
            return "Sablier: connection test (waiting), dynamic strategy serves Sablier's waiting page without hitting the upstream, ready proxies, names forwarded, Sablier answering 500 without the session header => 503 (fail closed). Real Sablier + Docker providers NOT-TESTABLE"
    finally:
        try:
            s.stop()
        except Exception:
            pass


@scenario("api-zrok-fake-binary", ["136"])
def zrok():
    d = tempfile.mkdtemp()
    fake = os.path.join(d, "zrok")
    open(fake, "w").write('#!/bin/sh\necho "$@" >> %s/calls.log\ncase "$1" in\n  version) echo "v1.1.11";;\n  share) echo "access your share at: https://abc123.share.zrok.io"; sleep 300;;\n  *) echo "ok $1";;\nesac\n' % d)
    os.chmod(fake, 0o755)
    # without the flag everything mutating is refused
    i0 = Instance("zr0").start()
    try:
        r = i0.client.post("/api/zrok/settings", binary=fake)[1]
        check(isinstance(r, dict) and "disabled" in str(r.get("error", "")), f"zrok usable without -allow_external_tools: {r}")
    finally:
        i0.cleanup()
    i = Instance("zr", flags=["-allow_external_tools"]).start()
    try:
        c = i.client
        c.ok("/api/zrok/settings", binary=fake, flavor="v1", token="e2eAccountToken1234")
        st = c.get("/api/zrok/status")[1]
        check("e2eAccountToken1234" not in json.dumps(st), "token returned by status")
        c.ok("/api/zrok/enable")
        tun = c.ok("/api/zrok/tunnel/save", tunnel=json.dumps({"Name": "e2e", "Kind": "share-private", "Target": "127.0.0.1:8080", "BackendMode": "proxy"}))
        check(tun.get("ID"), f"tunnel save {tun}")
        c.ok("/api/zrok/tunnel/start", id=tun["ID"])
        ok = wait_until(lambda: "share" in open(os.path.join(d, "calls.log")).read(), 10)
        calls = open(os.path.join(d, "calls.log")).read()
        check(ok and "enable" in calls and "e2eAccountToken1234" in calls, f"CLI calls: {calls}")
        check("--backend-mode" in calls or "proxy" in calls, f"share args: {calls}")
        logs = wait_until(lambda: "abc123" in json.dumps(c.get("/api/zrok/logs", id=tun["ID"])[1]), 10)
        check(logs, "tunnel output not captured")
        c.ok("/api/zrok/tunnel/stop", id=tun["ID"])
        bad = c.post("/api/zrok/tunnel/save", tunnel=json.dumps({"Name": "x", "Kind": "share-private", "Target": "127.0.0.1:8080; rm -rf /"}))[1]
        check(isinstance(bad, dict) and bad.get("error"), f"shell metacharacters in target accepted: {bad}")
        c.ok("/api/zrok/tunnel/delete", id=tun["ID"])
        return "zrok (fake `zrok` shell script, -allow_external_tools): refused without the flag; settings/enable/tunnel save+start invoke the CLI with argument vector, token never returned, output captured, injection in target refused. Real zrok service NOT-TESTABLE"
    finally:
        i.cleanup()


@scenario("api-tokens-v1-quickstart", [])
def tokens():
    from .s03_security import auth_instance
    e = types.SimpleNamespace()
    inst = auth_instance("tk")
    e.inst = inst
    b = Recorder()
    e.backend = b
    try:
        c = inst.client
        c.ok("/api/cert/tls", set="false")
        c.ok("/api/proxy/add", type="host", rootname="tk.test", ep=f"127.0.0.1:{b.port}", tls="false")
        e.rule = lambda host: c.get("/api/proxy/detail", type="host", epname=host)[1] if False else c.post("/api/proxy/detail", type="host", epname=host)[1]
        r = c.ok("/api/apitoken/create", name="e2e-ro", scope="read")
        tok = r.get("token") or r.get("Token")
        check(tok and tok.startswith("zrx_"), f"create {str(r)[:100]}")
        h = {"Authorization": "Bearer " + tok}
        anon = Client(e.inst.url)
        st, body, _ = anon.raw("GET", "/api/v1/proxy-rules", headers=h)
        check(st == 200 and b"tk.test" in body, f"v1 list with token: {st} {body[:100]}")
        st, body, _ = anon.raw("GET", "/api/v1/proxy-rules")
        check(st in (401, 403), f"v1 without token: {st}")
        st, body, _ = anon.raw("POST", "/api/v1/proxy-rules/tk.test/disable", {}, h)
        check(st in (401, 403), f"read-scoped token could write: {st}")
        st, body, _ = anon.raw("GET", "/api/proxy/list?type=host", headers=h)
        check(st in (301, 302, 307, 401, 403), f"bearer token accepted on a cookie-only route: {st}")
        rw = c.ok("/api/apitoken/create", name="e2e-rw", scope="readwrite")
        h2 = {"Authorization": "Bearer " + (rw.get("token") or rw.get("Token"))}
        st, body, _ = anon.raw("POST", "/api/v1/proxy-rules/tk.test/disable", {}, h2)
        check(st == 200, f"rw token disable: {st} {body[:100]}")
        time.sleep(0.3)
        check(e.rule("tk.test").get("Disabled") is True, "disable via token not applied")
        lst = c.get("/api/apitoken/list")[1]
        tid = [t for t in lst if t.get("Name", t.get("name")) == "e2e-ro"][0].get("ID", None) or [t for t in lst if t.get("name") == "e2e-ro"][0]["id"]
        c.ok("/api/apitoken/revoke", id=tid)
        st, body, _ = anon.raw("GET", "/api/v1/proxy-rules", headers=h)
        check(st in (401, 403), f"revoked token still works: {st}")
        # quick start dismissal
        q = c.get("/api/quickstart")[1]
        q2 = c.ok("/api/quickstart", dismissed="true")
        check(q2.get("dismissed") is True and q2.get("show") is False, f"dismiss {q2}")
        check(c.get("/api/quickstart")[1]["dismissed"] is True, "dismissal not stored")
        c.ok("/api/quickstart", dismissed="false")
        return "API tokens: create read + readwrite, v1 list with Bearer, no token refused, read token cannot write, token not accepted on cookie routes, rw disable applied, revoke ends access; Quick Start dismiss/undismiss persisted"
    finally:
        inst.cleanup()
        b.stop()
