"""Proxy ops: error pages, static responses, CORS, bandwidth, redirects, variables, templates, bulk edit, API tokens."""
import json
import urllib.request

from lib import *


@scenario("ops_error_pages_static_cors", ["313", "431", "680"])
def ops_error_pages_static_cors():
    """Custom error page for upstream 502/503, static (public) response, CORS preflight and headers, request id."""
    def h(hh, rec, b):
        if rec["path"].startswith("/fail"):
            send(hh, 503, "upstream raw body")
        elif rec["path"].startswith("/hdr"):
            send(hh, 200, "ok", {"Access-Control-Allow-Origin": "https://upstream.invalid"})
        else:
            send(hh, 200, "app")

    with Zoraxy() as z, Backend(h, name="ops") as b:
        z.add_rule("ops.test", b.addr, rate=True, ratenum=1000)
        cfg = {
            "ErrorPages": {"Mode": "on", "Statuses": [502, 503], "Template": "<html><body>custom {{.Status}} for {{.Host}} id={{.RequestID}} rule={{.RuleName}}</body></html>"},
            "StaticResponses": [{"Name": "robots", "Path": "/robots.txt", "Status": 200, "ContentType": "text/plain", "Body": "User-agent: *\nDisallow: /secret # {{host}}", "Public": True,
                                 "Headers": [{"Name": "X-Static", "Value": "{{rule_name}}"}]}],
            "CORS": {"Enabled": True, "AllowedOrigins": ["https://app.example.com", "https://*.partner.example"], "AllowedMethods": ["GET", "POST"],
                     "AllowCredentials": True, "MaxAgeSeconds": 600, "ExposeHeaders": ["X-Req"]},
            "ExposeRequestID": True,
        }
        z.api("/api/proxy/ops/set", ep="ops.test", config=json.dumps(cfg))
        r = z.req("ops.test", "/fail")
        check(r.status == 503 and "custom 503 for ops.test" in r.text and "upstream raw body" not in r.text, "error page: %d %r" % (r.status, r.text[:150]))
        check(r.h("x-request-id"), "no X-Request-Id")
        r = z.req("ops.test", "/robots.txt")
        check(r.status == 200 and "Disallow: /secret # ops.test" in r.text and r.h("x-static") == "ops.test", "static response: %d %r %s" % (r.status, r.text, r.headers))
        n = len(b.log)
        check(all(x["path"] != "/robots.txt" for x in b.log), "static response reached the upstream")
        pre = z.req("ops.test", "/api", "OPTIONS", {"Origin": "https://app.example.com", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "x-custom"})
        check(pre.status in (200, 204) and pre.h("access-control-allow-origin") == "https://app.example.com", "preflight: %d %s" % (pre.status, pre.headers))
        check(pre.h("access-control-allow-credentials") == "true" and pre.h("access-control-max-age") == "600", "preflight creds/max-age: %s" % pre.headers)
        check(len(b.log) == n, "preflight went to the upstream")
        sub = z.req("ops.test", "/api", "OPTIONS", {"Origin": "https://x.partner.example", "Access-Control-Request-Method": "GET"})
        check(sub.status in (200, 204) and sub.h("access-control-allow-origin") == "https://x.partner.example", "wildcard origin: %d" % sub.status)
        evil = z.req("ops.test", "/api", "OPTIONS", {"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
        check(evil.status == 403 and not evil.h("access-control-allow-origin"), "evil origin preflight: %d %s" % (evil.status, evil.headers))
        badm = z.req("ops.test", "/api", "OPTIONS", {"Origin": "https://app.example.com", "Access-Control-Request-Method": "DELETE"})
        check(badm.status == 403, "disallowed method preflight: %d" % badm.status)
        # normal response: upstream's own ACAO replaced by ours
        ok = z.req("ops.test", "/hdr", headers={"Origin": "https://app.example.com"})
        check(ok.h("access-control-allow-origin") == "https://app.example.com", "ACAO on response: %s" % ok.h("access-control-allow-origin"))
        no = z.req("ops.test", "/hdr", headers={"Origin": "https://evil.example"})
        check(no.h("access-control-allow-origin") != "https://evil.example", "evil origin reflected")
        return "error page replaces upstream 503 body; static public response with {{host}}/{{rule_name}}; preflight answered by proxy (ok/wildcard/evil=403/bad method=403); upstream ACAO overridden"


@scenario("ops_bandwidth", ["689"])
def ops_bandwidth():
    """Per-response bandwidth limit slows a 256 KiB download to roughly the configured rate."""
    with Zoraxy() as z, Backend(lambda h, rec, b: send(h, 200, b"z" * (256 * 1024)), name="bw") as b:
        z.add_rule("bw.test", b.addr)
        t0 = time.time()
        r = z.req("bw.test")
        free = time.time() - t0
        check(len(r.body) == 256 * 1024, "short body")
        z.api("/api/proxy/ops/set", ep="bw.test", config=json.dumps({"Bandwidth": {"BytesPerSecond": 128 * 1024}}))
        t0 = time.time()
        r = z.req("bw.test", timeout=30)
        slow = time.time() - t0
        check(len(r.body) == 256 * 1024 and r.body == b"z" * (256 * 1024), "limited body corrupted/short (%d)" % len(r.body))
        check(slow >= 1.2, "256KiB at 128KiB/s took only %.2fs (unlimited %.2fs): limit not applied" % (slow, free))
        check(slow < 6, "limit far too strict: %.2fs" % slow)
        return "256KiB: %.2fs unlimited vs %.2fs with 128KiB/s" % (free, slow)


@scenario("redirect_advanced_regex", ["826"])
def redirect_advanced_regex():
    """Advanced (lookahead) regex redirects with capture substitution; catastrophic pattern times out instead of hanging."""
    with Zoraxy() as z, Backend(name="r") as b:
        z.add_rule("rx.test", b.addr)
        z.api("/api/redirect/regex", enable=True)
        z.api("/api/redirect/advancedregex", enable=True)
        z.api("/api/redirect/add", redirectUrl=r"^legacy\.test/(?!keep)(\w+)/(\d+)$", destUrl="https://new.example.com/moved", forwardChildpath="false", redirectType="301")
        r = http_req("127.0.0.1", z.proxy, "legacy.test", "/items/42")
        check(r.status == 301 and r.h("location", "").startswith("https://new.example.com/moved"), "lookahead redirect: %d %s" % (r.status, r.h("location")))
        r2 = http_req("127.0.0.1", z.proxy, "legacy.test", "/keepme/42")
        check(r2.status != 301, "negative lookahead ignored (%d)" % r2.status)
        # catastrophic pattern must not hang the proxy
        z.api("/api/redirect/add", redirectUrl=r"^evil\.test/(a+)+$", destUrl="https://x.example/", forwardChildpath="false", redirectType="302")
        t0 = time.time()
        r3 = http_req("127.0.0.1", z.proxy, "evil.test", "/" + "a" * 40 + "!", timeout=10)
        dt = time.time() - t0
        check(dt < 5, "catastrophic regex blocked the request for %.1fs" % dt)
        return "lookahead redirect -> %s; negative lookahead respected; ReDoS pattern answered in %.2fs" % (r.h("location"), dt)


@scenario("rule_templates_bulk_edit", ["924"])
def rule_templates_bulk_edit():
    """Create rule from a built-in template, then bulk edit (tags, WAF source, rate limit, disable, delete w/o confirm)."""
    with Zoraxy() as z, Backend(name="bk") as b:
        tpl = z.get("/api/proxy/templates/list")
        names = [t.get("Name") for t in tpl]
        check("Secure web app" in names, "built-in templates: %s" % names)
        z.add_rule("t1.test", b.addr, template="Secure web app")
        z.add_rule("t2.test", b.addr)
        z.add_rule("t3.test", b.addr)
        d = z.detail("t1.test")
        check(d.get("BlockCommonExploits") or d.get("HeaderRewriteRules") or d.get("Tags"), "template changed nothing on t1: %s" % json.dumps(d)[:200])
        rules = ["t1.test", "t2.test", "t3.test"]
        res = z.api("/api/proxy/bulk", rules=json.dumps(rules), action="add_tags", params=json.dumps({"Tags": ["bulk", "e2e"]}))
        check(all(x.get("OK") for x in res["results"]), "bulk add_tags: %s" % res)
        check("bulk" in (z.detail("t2.test").get("Tags") or []), "tag not applied")
        dry = z.api("/api/proxy/bulk", rules=json.dumps(rules), action="disable", params="{}", dryrun=True)
        check(z.req("t2.test").status == 200, "dry run changed state")
        z.api("/api/proxy/bulk", rules=json.dumps(["t2.test", "t3.test"]), action="set_ratelimit", params=json.dumps({"RateLimitEnabled": True, "RateLimit": 2, "RateLimitBurst": 0}))
        codes = [z.req("t2.test").status for _ in range(15)]
        check(429 in codes, "bulk rate limit not effective: %s" % codes)
        z.api("/api/proxy/bulk", rules=json.dumps(["t3.test"]), action="set_waf", params=json.dumps({"WAFSource": "block"}))
        attack = z.req("t3.test", "/s?q=" + urllib.parse.quote("' OR 1=1 UNION SELECT a FROM b--")).status
        check(attack == 403, "bulk WAF block not effective (%d)" % attack)
        z.api("/api/proxy/bulk", rules=json.dumps(["t1.test"]), action="disable", params="{}")
        n = len(b.log)
        z.req("t1.test")
        check(len(b.log) == n, "disabled rule still proxied")
        rd = z.api("/api/proxy/bulk", rules=json.dumps(["t2.test"]), action="delete", params="{}", raw=True)
        check(b"Confirm" in rd[1] or b"confirm" in rd[1] or b"error" in rd[1], "delete without Confirm not refused: %r" % rd[1][:150])
        still = z.detail("t2.test")
        check(still and "error" not in still, "delete without Confirm removed the rule")
        return "template list=%s; bulk tags/ratelimit(429 seen)/WAF(403)/disable ok; dry run no-op; delete needs Confirm" % names


@scenario("api_v1_tokens", ["382"])
def api_v1_tokens():
    """/api/v1 with Bearer tokens: read vs readwrite scope, expiry, IP allow-list, revocation; no cookie/CSRF needed."""
    with Zoraxy() as z, Backend(name="v1") as b:
        z.add_rule("v1.test", b.addr)
        def call(tok, method, path, body=None):
            req = urllib.request.Request("http://127.0.0.1:%d%s" % (z.admin, path), method=method,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers=dict({"Content-Type": "application/json"}, **({"Authorization": "Bearer " + tok} if tok else {})))
            try:
                r = urllib.request.urlopen(req, timeout=10)
                return r.status, r.read()
            except urllib.error.HTTPError as e:
                return e.code, e.read()
        mk = lambda **kw: z.api("/api/apitoken/create", **kw)
        ro = mk(name="ro", scope="read")["token"]
        rw = mk(name="rw", scope="readwrite")["token"]
        exp = mk(name="exp", scope="readwrite", expires=int(time.time()) + 2)["token"]
        ipt = mk(name="ip", scope="read", cidrs="10.9.9.0/24")["token"]
        check(call(None, "GET", "/api/v1/proxy-rules")[0] == 401, "no token accepted")
        s, body = call(ro, "GET", "/api/v1/proxy-rules")
        check(s == 200 and b"v1.test" in body, "read token list: %d %r" % (s, body[:100]))
        check(call(ro, "POST", "/api/v1/proxy-rules", {"type": "host", "rootname": "x.test", "ep": b.addr})[0] in (401, 403), "read token could write")
        s, body = call(rw, "POST", "/api/v1/proxy-rules", {"type": "host", "rootname": "new.test", "ep": b.addr, "tls": False, "bypassGlobalTLS": True})
        check(s in (200, 201), "readwrite create: %d %r" % (s, body[:150]))
        check(z.req("new.test").json()["backend"] == "v1", "rule created by API v1 does not route")
        check(call(ipt, "GET", "/api/v1/proxy-rules")[0] in (401, 403), "IP allow-list ignored")
        check(call(exp, "GET", "/api/v1/proxy-rules")[0] == 200, "fresh expiring token refused")
        time.sleep(3.2)
        check(call(exp, "GET", "/api/v1/proxy-rules")[0] == 401, "expired token still accepted")
        # revoke
        lst = z.get("/api/apitoken/list")
        tid = [t.get("ID") or t.get("Id") or t.get("id") for t in lst if t.get("Name") == "rw" or t.get("name") == "rw"][0]
        z.api("/api/apitoken/revoke", id=tid)
        check(call(rw, "GET", "/api/v1/proxy-rules")[0] == 401, "revoked token still accepted")
        return "401 w/o token; read scope lists but cannot write; readwrite created new.test (routes); IP allow-list, expiry (2s), revoke enforced (token-on-legacy-route refusal needs auth mode: covered by apiv1_test.go)"
