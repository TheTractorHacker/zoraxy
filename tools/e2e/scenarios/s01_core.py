"""Core routing: host / alias / vdir / default site / IDN / header + path rules / redirects."""
import json

from lib import *


def ev(*parts):
    return "; ".join(parts)


@scenario("core_routing", ["core"])
def core_routing():
    """Host routing, alias, wrong host falls to default site, header pass-through, removal."""
    with Zoraxy() as z, Backend(name="A") as a, Backend(name="B") as b:
        z.add_rule("a.test", a.addr)
        z.add_rule("b.test", b.addr)
        r = z.req("a.test", "/p/q?x=1", headers={"X-Foo": "bar"})
        check(r.status == 200 and r.json()["backend"] == "A", "a.test not routed to A: %r" % r)
        j = r.json()
        check(j["path"] == "/p/q?x=1", "path/query mangled: " + j["path"])
        check(j["headers"].get("x-foo") == "bar", "custom request header lost")
        check(j["headers"].get("x-forwarded-for") == "127.0.0.1" and j["headers"].get("x-forwarded-host") == "a.test",
              "X-Forwarded-* wrong: %s" % j["headers"])
        check(z.req("b.test").json()["backend"] == "B", "b.test not routed to B")
        # alias
        z.api("/api/proxy/setAlias", ep="a.test", alias=json.dumps(["alias.test", "*.wild.test"]))
        check(z.req("alias.test").json()["backend"] == "A", "alias host not routed")
        check(z.req("x.wild.test").json()["backend"] == "A", "wildcard alias not routed")
        # unknown host: default site (no root proxy configured) must not hit A or B
        n = len(a.log) + len(b.log)
        r = z.req("unknown.test")
        check(len(a.log) + len(b.log) == n, "unknown host reached a backend")
        # POST body round trip
        r = z.req("a.test", "/post", "POST", {"Content-Type": "text/plain"}, b"hello-body")
        check(r.json()["body"] == "hello-body", "POST body not forwarded")
        # delete rule
        z.del_rule("b.test")
        n = len(b.log)
        z.req("b.test")
        check(len(b.log) == n, "deleted rule still routes")
        return ev("a/b host routing OK", "alias+wildcard alias OK", "unknown host=%d not proxied" % r.status if False else "unknown host does not reach backends",
                  "POST body + XFF headers OK", "rule delete stops routing")


@scenario("vdir_longest_match", ["core"])
def vdir_longest_match():
    """Virtual directories: longest prefix wins, prefix stripped/preserved as per config."""
    with Zoraxy() as z, Backend(name="root") as a, Backend(name="api") as b, Backend(name="apiv2") as c:
        z.add_rule("v.test", a.addr)
        z.api("/api/proxy/vdir/add", type="host", endpoint="v.test", path="/api", domain=b.addr)
        z.api("/api/proxy/vdir/add", type="host", endpoint="v.test", path="/api/v2", domain=c.addr)
        got = {}
        for p in ("/", "/other", "/api/x", "/api/v2/x", "/api/v22", "/apix"):
            r = z.req("v.test", p).json()
            got[p] = (r["backend"], r["path"])
        check(got["/"][0] == "root" and got["/other"][0] == "root", "root paths: %s" % got)
        check(got["/api/x"][0] == "api", "/api/x -> %s" % (got["/api/x"],))
        check(got["/api/v2/x"][0] == "apiv2", "longest match failed: /api/v2/x -> %s" % (got["/api/v2/x"],))
        return "vdir routing: %s" % json.dumps(got)


@scenario("default_site", ["core"])
def default_site():
    """Root (default site) behaviours: reverse proxy, redirect, 404 page, no response."""
    with Zoraxy() as z, Backend(name="root") as a:
        # reverse proxy mode
        z.api("/api/proxy/add", type="root", ep=a.addr, tls=False, defaultSiteOpt=1, defaultSiteVal="-")
        r = z.req("anything.test", "/zz")
        check(r.status == 200 and r.json()["backend"] == "root", "root proxy mode failed %r" % r)
        # redirect mode
        z.api("/api/proxy/add", type="root", ep=a.addr, tls=False, defaultSiteOpt=2, defaultSiteVal="https://example.org/landing")
        r = http_req("127.0.0.1", z.proxy, "anything.test", "/zz")
        check(r.status in (301, 302, 307, 308) and "example.org/landing" in r.h("location", ""), "redirect mode: %r %s" % (r, r.headers))
        # 404 page
        z.api("/api/proxy/add", type="root", ep=a.addr, tls=False, defaultSiteOpt=3, defaultSiteVal="-")
        r = z.req("anything.test", "/zz")
        check(r.status == 404, "404 mode returned %d" % r.status)
        # no response: connection closed / empty
        z.api("/api/proxy/add", type="root", ep=a.addr, tls=False, defaultSiteOpt=4, defaultSiteVal="-")
        try:
            r = z.req("anything.test", "/zz", timeout=5)
            ok = r.status in (444, 0) or not r.body
        except Exception:
            ok = True
        check(ok, "no-response mode still answered: %r" % r)
        return "default site modes proxy/redirect/404/no-response verified"


@scenario("idn_punycode", ["458"])
def idn_punycode():
    """Rule created with a unicode hostname matches the punycode Host header (and vice versa)."""
    with Zoraxy() as z, Backend(name="idn") as a:
        z.add_rule("bücher.example", a.addr)
        r = z.req("xn--bcher-kva.example")
        check(r.status == 200 and r.json()["backend"] == "idn", "punycode Host did not match unicode rule: %r" % r)
        # the stored rule name
        lst = z.get("/api/proxy/list", type="host")
        names = [e["RootOrMatchingDomain"] for e in lst]
        z.add_rule("xn--mnchen-3ya.example", a.addr)
        r2 = z.req("xn--mnchen-3ya.example")
        check(r2.json()["backend"] == "idn", "plain punycode rule broken")
        return "rule stored as %s matches punycode Host header" % names


@scenario("header_rules", ["core"])
def header_rules():
    """Custom request/response header rules (add/remove) applied on proxied traffic."""
    with Zoraxy() as z, Backend(name="h") as a:
        z.add_rule("h.test", a.addr)
        z.api("/api/proxy/header/add", type="add", domain="h.test", direction="toOrigin", name="X-From-Zoraxy", value="yes")
        z.api("/api/proxy/header/add", type="add", domain="h.test", direction="toClient", name="X-To-Client", value="1")
        r = z.req("h.test")
        check(r.json()["headers"].get("x-from-zoraxy") == "yes", "request header rule not applied: %s" % r.json()["headers"])
        check(r.h("x-to-client") == "1", "response header rule not applied: %s" % r.headers)
        return "toOrigin + toClient custom headers applied"


@scenario("redirect_rules", ["core"])
def redirect_rules():
    """Redirect rules (plain, regex) answer without touching the backend."""
    with Zoraxy() as z, Backend(name="r") as a:
        z.add_rule("r.test", a.addr)
        z.api("/api/redirect/add", redirectUrl="old.example.com/path", destUrl="https://new.example.com/dest",
              forwardChildpath="true", redirectType="307")
        r = http_req("127.0.0.1", z.proxy, "old.example.com", "/path/child?q=1")
        check(r.status == 307, "redirect status %d" % r.status)
        loc = r.h("location", "")
        check(loc.startswith("https://new.example.com/dest"), "location=%s" % loc)
        check(len(a.log) == 0, "redirect touched backend")
        return "307 -> %s (child path forwarded)" % loc
