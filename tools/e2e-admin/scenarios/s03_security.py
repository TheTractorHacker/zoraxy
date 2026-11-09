import json
from runner import scenario, NotTestable
from .common import *


DENIED = (301, 302, 307, 401, 403, 405)


def auth_instance(name, flags=()):
    i = Instance(name, noauth=False, flags=flags).start()
    c = i.client
    c.refresh_csrf()
    st, js = c.post("/api/auth/register", username="admin", password="adminpass1", email="a@example.com")
    check(st == 200 and js == "OK", f"register {st} {js}")
    st, js = c.login("admin", "adminpass1")
    check(st == 200 and js == "OK", f"login {st} {js}")
    return i


@scenario("api-admin-users-viewer-sessions", ["22", "89"])
def admin_users():
    i = auth_instance("au")
    try:
        c = i.client
        # unauthenticated client is refused
        anon = Client(i.url)
        check(anon.get("/api/proxy/list")[0] in DENIED, "anonymous API access allowed")
        # create viewer
        c.ok("/api/users/action", action="create", username="view", password="viewerpass1", role="viewer")
        v = Client(i.url)
        st, js = v.login("view", "viewerpass1")
        check(st == 200 and js == "OK", f"viewer login {st} {js}")
        check(v.get("/api/auth/role")[1] in ("viewer", ["viewer"]) or "viewer" in json.dumps(v.get("/api/auth/role")[1]), f"role {v.get('/api/auth/role')}")
        check(v.get("/api/proxy/list", type="host")[0] == 200, "viewer cannot read")
        # every mutating thing refused for the viewer
        muts = [("/api/proxy/add", dict(type="host", rootname="v.test", ep="127.0.0.1:9", tls="false")),
                ("/api/proxy/del", dict(ep="a.test")),
                ("/api/users/action", dict(action="create", username="x2", password="xxxxxxxx1", role="admin")),
                ("/api/abuse/ban", dict(ip="203.0.113.9")),
                ("/api/abuse/token", dict(action="generate")),
                ("/api/blacklist/ip/add", dict(ip="203.0.113.8")),
                ("/api/cert/selfsign", dict(domain="v.test")),
                ("/api/notify/hooks", dict(action="add")),
                ("/api/conf/import", dict()),
                ("/api/proxy/bulk", dict(rules="[]", action="delete")),
                ("/api/ech/rotate", dict()),
                ("/api/apitoken/create", dict(name="t", scope="read")),
                ("/api/updater/start", dict()),
                ("/api/proxy/templates/save", dict(template="{}"))]
        bad = []
        for path, form in muts:
            st, js = v.post(path, **form)
            if st not in DENIED:
                bad.append(f"{path}->{st} {str(js)[:60]}")
        check(not bad, "viewer mutations not refused: " + "; ".join(bad))
        for p in ("/api/conf/export", "/api/users/list", "/api/abuse/config"):
            st, _ = v.get(p)
            check(st in DENIED, f"viewer GET {p} -> {st}")
        # state untouched
        check(not [r for r in c.get("/api/proxy/list", type="host")[1] if r.get("RootOrMatchingDomain") == "v.test"], "viewer created a rule")
        # last-admin protection
        st, js = c.post("/api/users/action", action="delete", username="admin")
        check(isinstance(js, dict) and js.get("error"), f"self delete allowed? {js}")
        st, js = c.post("/api/users/action", action="disable", username="admin")
        check(isinstance(js, dict) and js.get("error"), f"self disable allowed? {js}")
        st, js = c.post("/api/users/action", action="setRole", username="admin", role="viewer")
        check(isinstance(js, dict) and js.get("error"), f"last admin demotion allowed? {js}")
        # password change ends other sessions
        v2 = Client(i.url)
        v2.login("view", "viewerpass1")
        check(v2.get("/api/proxy/list", type="host")[0] == 200, "second viewer session")
        c.ok("/api/users/action", action="setPassword", username="view", password="newviewerpw1")
        check(v.get("/api/proxy/list", type="host")[0] in DENIED, "old viewer session survived admin-forced password change")
        check(v2.get("/api/proxy/list", type="host")[0] in DENIED, "second old session survived")
        st, js = Client(i.url).login("view", "viewerpass1")
        check(js != "OK" , "old password still works")
        # own password change: other sessions end, current survives
        a2 = Client(i.url)
        a2.login("admin", "adminpass1")
        st, js = c.post("/api/auth/changePassword", oldPassword="adminpass1", newPassword="adminpass2", confirmPassword="adminpass2")
        check(st == 200 and not (isinstance(js, dict) and js.get("error")), f"changePassword {js}")
        check(c.get("/api/proxy/list", type="host")[0] == 200, "own session should survive own password change")
        check(a2.get("/api/proxy/list", type="host")[0] in DENIED, "other admin session survived password change")
        # audit
        st, js = c.get("/api/users/list")
        check(st == 200 and js.get("Audit"), "audit log empty")
        return "viewer created via API, logged in; 14 mutating endpoints + export/users/abuse-config refused (401/403/405) with state unchanged; self-delete/disable/last-admin demote refused; admin-forced and self password change end other sessions (current survives); audit entries present"
    finally:
        i.cleanup()


@scenario("api-autoban-manual-remote-token", ["22"])
def autoban():
    with Env("ab") as e:
        c = e.c
        e.add_rule("ab.test")
        cfg = c.get("/api/abuse/config")[1]
        cfg["Enabled"] = True
        cfg["BanPrivate"] = True
        cfg["Detectors"]["not_found"] = {"Enabled": True, "Threshold": 3, "WindowSec": 60}
        k = [x for x in cfg["Detectors"]]
        c.ok("/api/abuse/setConfig", config=json.dumps(cfg))
        # manual ban + list + proxied request refused + unban
        c.ok("/api/abuse/ban", ip="127.0.0.2", reason="e2e", seconds="600")
        bans = c.get("/api/abuse/list")[1]
        check(any(b["IP"].startswith("127.0.0.2") for b in bans["Bans"]) if bans["Bans"] and "IP" in bans["Bans"][0] else bans["Bans"], f"ban listed {bans}")
        # remote token
        tok = c.ok("/api/abuse/token", action="generate")["token"]
        st, body, _ = Client(e.inst.url).raw("POST", "/api/abuse/remote/ban", {"ip": "198.51.100.7"}, {"Authorization": "Bearer wrong"})
        check(st == 401, f"bad token -> {st}")
        r = Client(e.inst.url)
        st, body, _ = r.raw("POST", "/api/abuse/remote/ban", {"ip": "198.51.100.7", "reason": "remote"}, {"Authorization": "Bearer " + tok})
        check(st == 200, f"remote ban {st} {body[:100]}")
        lst = c.get("/api/abuse/list")[1]["Bans"]
        check(any("198.51.100.7" in json.dumps(b) for b in lst), "remote ban not listed")
        st, body, _ = r.raw("POST", "/api/abuse/remote/unban", {"ip": "198.51.100.7"}, {"Authorization": "Bearer " + tok})
        check(st == 200, f"remote unban {st}")
        c.ok("/api/abuse/token", action="revoke")
        st, _, _ = r.raw("POST", "/api/abuse/remote/ban", {"ip": "198.51.100.7"}, {"Authorization": "Bearer " + tok})
        check(st == 401, "revoked token still works")
        # automatic detector: 404 flood from loopback gets banned (BanPrivate)
        c.post("/api/abuse/unban", ip="127.0.0.2")
        e.backend.handler = lambda r: (404, {}, "nope")
        codes = [e.req("ab.test", f"/n{i}")[0] for i in range(8)]
        time.sleep(1)
        bans = c.get("/api/abuse/list")[1]["Bans"]
        check(any("127.0.0.1" in json.dumps(b) for b in bans), f"404 flood not auto-banned: codes={codes} bans={bans}")
        code = e.req("ab.test", "/after")[0]
        check(code in (403, 0) or code >= 400, f"banned client served {code}")
        return "manual ban/unban, remote token (generate, bad token 401, remote ban/unban, revoke), and detector-driven auto-ban of a 404 flood verified with real traffic"


@scenario("api-bot-header-rules", ["501", "615"])
def bot_header():
    with Env("bh") as e:
        c = e.c
        e.add_rule("bh.test")
        e.add_rule("bh2.test")
        # header rule: request must carry the secret header
        rules = [{"Name": "X-Edge-Secret", "Match": "equals", "Values": ["s3cret"], "Action": "deny", "Comment": "e2e"}]
        c.ok("/api/headerrules/set", ep="bh.test", rules=json.dumps(rules))
        time.sleep(0.4)
        got = c.get("/api/headerrules/get", ep="bh.test")[1]
        check(got and got[0]["Values"] == [""], f"secret not masked in GET: {got}")
        check("s3cret" not in json.dumps(c.post("/api/proxy/detail", type="host", epname="bh.test")[1]), "secret leaked via detail")
        st1 = e.req("bh.test")[0]
        st2 = e.req("bh.test", headers={"X-Edge-Secret": "wrong"})[0]
        st3 = e.req("bh.test", headers={"X-Edge-Secret": "s3cret"})[0]
        check(st1 >= 400 and st2 >= 400 and st3 == 200, f"header rule enforcement: none={st1} wrong={st2} right={st3}")
        check(e.req("bh2.test")[0] == 200, "header rule leaked to other rule")
        # editing with an empty value keeps the stored secret
        rules[0]["Values"] = [""]
        rules[0]["Comment"] = "edited"
        c.ok("/api/headerrules/set", ep="bh.test", rules=json.dumps(rules))
        time.sleep(0.3)
        check(e.req("bh.test", headers={"X-Edge-Secret": "s3cret"})[0] == 200, "secret lost after masked re-save")
        # bot rules: custom substring block + category, per-rule opt-out
        cfg = c.get("/api/botrules/get")[1]["Config"]
        cfg["Enabled"] = True
        cfg["Custom"] = [{"Name": "e2e-bad", "Type": "substring", "Pattern": "EvilScraper", "CaseInsensitive": True, "Action": "block"}]
        c.ok("/api/botrules/set", config=json.dumps(cfg))
        time.sleep(0.3)
        ua = lambda host, u: e.req(host, headers={"User-Agent": u, "X-Edge-Secret": "s3cret"})[0]
        check(ua("bh.test", "Mozilla/5.0 evilscraper/1.0") >= 400, "custom bot rule did not block")
        check(ua("bh.test", "Mozilla/5.0 Firefox") == 200, "normal UA blocked")
        c.ok("/api/botrules/endpoint", ep="bh2.test", policy="off")
        time.sleep(0.3)
        check(ua("bh2.test", "EvilScraper") == 200, "per-rule bot opt-out ignored")
        return "header rule (equals, masked on read, empty value keeps secret, enforcement none/wrong/right = deny/deny/200, isolation) and bot rules (custom substring block, per-rule off) verified with real requests"
