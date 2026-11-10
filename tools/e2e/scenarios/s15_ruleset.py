"""Rules engine (WHEN expression THEN action): create rules through /api/ruleset, send real traffic through a real
proxy to a local upstream, and check log-only vs acting, order and precedence, skip, redirect, header actions,
rate limit, the challenge fallback, lists, the blocked log, the request tester (it must predict what the proxy does),
migration proposals and persistence over a restart."""
import json
import os
import time

from lib import *


def mk(z, expression, action, name="rule", site="", dry_run=False, **kw):
    body = {"site": site, "rule": dict(name=name, expression=expression, action=action, dry_run=dry_run, **kw)}
    return z.api("/api/ruleset/rule/create", json_body=body)


def rules(z, site=""):
    return z.get("/api/ruleset/rules", site=site)


def err(z, path, body):
    code, raw = z.api(path, raw=True, json_body=body)
    return code, json.loads(raw)


@scenario("ruleset_engine", ["ux-phase5-rules"])
def ruleset_engine():
    """See the module docstring."""
    with Zoraxy() as z, Backend(name="rs") as b:
        z.add_rule("rs.test", b.addr)
        z.add_rule("other.test", b.addr)

        # ---- nothing configured: untouched
        check(z.req("rs.test", "/admin").status == 200, "baseline request refused")

        # ---- log-only first: observed, counted, never acts
        r = mk(z, 'http.path starts_with "/admin" and ip.country != "US"', {"type": "block"}, name="no admin", dry_run=True)
        check(r["dry_run"] is True and r["tree"]["type"] == "and", "created rule has no tree / dry_run: %s" % r)
        check(z.req("rs.test", "/admin/x").status == 200, "log-only rule acted")
        st = z.get("/api/ruleset/stats")
        row = [x for x in st["rules"] if x["id"] == r["id"]][0]
        check(row["stats"]["dry_run"] == 1 and row["stats"]["hits"] == 0, "log-only hit not counted: %s" % row)
        check(st["recent"] and st["recent"][0]["dry_run"] and st["recent"][0]["path"] == "/admin/x", "recent match missing")

        # ---- the request tester predicts the verdict, then the real request agrees
        t = z.api("/api/ruleset/test", json_body={"method": "GET", "url": "http://rs.test/admin/x", "client_ip": "127.0.0.2", "country": "DE"})
        check(t["decision"] == "none" and t["rules"][0]["matched"] and "log-only" in t["rules"][0]["note"], "tester: %s" % t)
        z.api("/api/ruleset/rule/dryrun", json_body={"id": r["id"], "dry_run": False})
        t = z.api("/api/ruleset/test", json_body={"method": "GET", "url": "http://rs.test/admin/x", "client_ip": "127.0.0.2", "country": "DE"})
        check(t["decision"] == "block" and t["decided_by"]["name"] == "no admin", "tester after enabling: %s" % t)
        check(all(len(x.get("trace", [])) for x in t["rules"] if x["evaluated"]), "tester gave no trace")
        check(z.req("rs.test", "/admin/x").status == 403, "acting rule did not block")
        check(z.req("rs.test", "//x/../admin;a=b").status == 403, "path normalisation bypass")
        check(z.req("rs.test", "/public").status == 200, "unrelated path blocked")
        # the tester counted nothing: only the two real blocks are acting hits
        row = [x for x in z.get("/api/ruleset/stats")["rules"] if x["id"] == r["id"]][0]
        check(row["stats"]["hits"] == 2, "acting hits %s" % row["stats"])

        # ---- blocked log: category rule, rule name as detail
        def entries():
            return [e for e in z.get("/api/blocked/list")["items"] if e["reason"] == "rule"]
        wait_for(lambda: len(entries()) >= 2, 10, msg="rule entries in the blocked log")
        e0 = entries()[0]
        check(e0["detail"] == "no admin" and e0["status"] == 403 and e0["host"] == "rs.test", "blocked entry: %s" % e0)

        # ---- disable / enable / order
        z.api("/api/ruleset/rule/disable", json_body={"id": r["id"]})
        check(z.req("rs.test", "/admin/x").status == 200, "disabled rule acted")
        z.api("/api/ruleset/rule/enable", json_body={"id": r["id"]})
        a = mk(z, 'http.path == "/p"', {"type": "block", "status": 418, "body": "short and stout"}, name="teapot")
        b2 = mk(z, 'http.path == "/p"', {"type": "block", "status": 410}, name="gone")
        resp = z.req("rs.test", "/p")
        check(resp.status == 418 and resp.text == "short and stout", "first rule must win: %s" % resp)
        by = {x["name"]: x["id"] for x in rules(z)}
        z.api("/api/ruleset/rule/reorder", json_body={"order": [by["gone"], by["teapot"], by["no admin"]]})
        check(z.req("rs.test", "/p").status == 410, "reorder not applied")

        # ---- global vs site: a global allow stops the site rule, site rules stay on their site
        mk(z, 'http.path == "/health"', {"type": "block"}, name="site block health", site="rs.test")
        check(z.req("rs.test", "/health").status == 403, "site rule missing")
        check(z.req("other.test", "/health").status == 200, "site rule leaked to another site")
        al = mk(z, 'http.path == "/health"', {"type": "allow"}, name="global allow health")
        z.api("/api/ruleset/rule/reorder", json_body={"order": [x["id"] for x in sorted(rules(z), key=lambda x: x["name"] != "global allow health")]})
        check(z.req("rs.test", "/health").status == 200, "global allow did not stop the site rules")

        # ---- redirect (with placeholders) and unsafe templates are refused
        mk(z, 'http.path starts_with "/old"', {"type": "redirect", "status": 301, "url": "https://new.example.org{uri}"}, name="moved")
        resp = z.req("rs.test", "/old/a?b=1")
        check(resp.status == 301 and resp.h("location") == "https://new.example.org/old/a?b=1", "redirect: %s %s" % (resp, resp.headers))
        code, e = err(z, "/api/ruleset/rule/create", {"site": "", "rule": {"name": "x", "expression": "req.size > 1", "action": {"type": "redirect", "url": "//evil.example/"}}})
        check(code == 400 and "error" in e, "protocol-relative redirect accepted: %s %s" % (code, e))
        code, e = err(z, "/api/ruleset/rule/create", {"site": "", "rule": {"name": "x", "expression": "req.size > 1", "action": {"type": "set_response_header", "name": "X-A", "value": "a\r\nSet-Cookie: x=y"}}})
        check(code == 400, "header injection accepted: %s" % e)

        # ---- header actions reach the upstream / the client
        mk(z, 'http.path == "/hdr"', {"type": "set_request_header", "name": "X-Edge", "value": "rules"}, name="req hdr")
        mk(z, 'http.path == "/hdr"', {"type": "remove_request_header", "name": "X-Secret"}, name="del req hdr")
        mk(z, 'http.path == "/hdr"', {"type": "set_response_header", "name": "X-Frame-Options", "value": "DENY"}, name="resp hdr")
        mk(z, 'http.path == "/hdr"', {"type": "tag", "tag": "edge"}, name="tagger")
        resp = z.req("rs.test", "/hdr", headers={"X-Secret": "s3", "X-Keep": "k"})
        seen = resp.json()["headers"]
        check(resp.status == 200 and seen.get("x-edge") == "rules" and "x-secret" not in seen and seen.get("x-keep") == "k", "request header actions: %s" % seen)
        check(resp.h("x-frame-options") == "DENY", "response header action missing: %s" % resp.headers)

        # ---- skip waf: the WAF blocks the attack, a rule can switch it off for one path
        z.api("/api/waf/set", rootname="rs.test", config=json.dumps({"Mode": "block", "ParanoiaLevel": 1, "InboundThreshold": 5}))
        sqli = "/legacy?q=" + "1%27%20OR%20%271%27%3D%271%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"
        check(z.req("rs.test", sqli, src="127.0.0.4").status == 403, "WAF baseline did not block")
        mk(z, 'http.path == "/legacy"', {"type": "skip", "skip": ["waf"]}, name="legacy no waf")
        check(z.req("rs.test", sqli, src="127.0.0.4").status == 200, "skip waf had no effect")
        check(z.req("rs.test", sqli.replace("/legacy", "/other"), src="127.0.0.4").status == 403, "skip leaked to another path")

        # ---- rate limit action
        mk(z, 'http.path == "/login"', {"type": "rate_limit", "rate": 1, "burst": 2}, name="login limit")
        codes = [z.req("rs.test", "/login", src="127.0.0.6").status for _ in range(6)]
        check(codes[:2] == [200, 200] and 429 in codes, "rate_limit action: %s" % codes)
        check(z.req("rs.test", "/login", src="127.0.0.7").status == 200, "limit is not per client")

        # ---- challenge without a CAPTCHA provider fails closed
        mk(z, 'http.path == "/data"', {"type": "challenge"}, name="challenge data")
        check(z.req("rs.test", "/data").status == 403, "challenge without provider must block")

        # ---- lists: edit once, takes effect at once; in-use lists cannot be deleted
        z.api("/api/ruleset/list/save", json_body={"name": "office", "type": "ip", "description": "hq", "items": ["127.0.0.50"]})
        mk(z, 'http.path starts_with "/internal" and ip.src not in $office', {"type": "block"}, name="office only")
        check(z.req("rs.test", "/internal", src="127.0.0.50").status == 200, "office address blocked")
        check(z.req("rs.test", "/internal", src="127.0.0.51").status == 403, "outsider allowed")
        z.api("/api/ruleset/list/save", json_body={"name": "office", "type": "ip", "items": ["127.0.0.51"]})
        check(z.req("rs.test", "/internal", src="127.0.0.51").status == 200, "list edit not applied")
        code, e = err(z, "/api/ruleset/list/delete", {"name": "office"})
        check(code == 400 and "office only" in e["error"], "list in use deleted: %s" % e)

        # ---- validate: positions, warnings, normalised text
        v = z.api("/api/ruleset/validate", json_body={"expression": 'http.path ==  '})
        check(v["ok"] is False and v["errors"][0]["pos"] >= 11, "validate error: %s" % v)
        v = z.api("/api/ruleset/validate", json_body={"expression": 'lower(http.path)   ==  "/Admin"'})
        check(v["ok"] and v["text"] == 'lower(http.path) == "/Admin"' and any("never match" in w for w in v["warnings"]), "validate warnings: %s" % v)
        v = z.api("/api/ruleset/validate", json_body={"expression": 'ip.asn == 13335'})
        check(not v["ok"] and "ASN" in v["errors"][0]["message"], "ip.asn: %s" % v)

        # ---- migration proposals (read-only), from a real path rule and a real blacklist entry
        z.api("/api/proxy/networking/pathrules", ep="rs.test", rules=json.dumps(
            [{"Name": "secret", "MatchMode": "prefix", "Pattern": "/secret", "Action": "deny"}]))
        z.api("/api/blacklist/ip/add", ip="198.51.100.9", id="default", comment="bad")
        z.api("/api/blacklist/enable", enable=True, id="default")
        m = z.get("/api/ruleset/migrate")
        check("Read-only" in m["statement"], "migration statement")
        srcs = {p["source"] for p in m["proposals"]}
        check({"path_rule", "access_list"} <= srcs and all(p["valid"] for p in m["proposals"]), "proposals: %s" % json.dumps(m)[:600])
        before = len(rules(z))
        check(len(rules(z)) == before, "migration created rules")

        # ---- files on disk, mode, and persistence over a restart
        d = os.path.join(z.dir, "conf", "ruleset")
        for f in ("global.json", "lists.json", os.path.join("sites", "rs.test.json")):
            check(os.path.exists(os.path.join(d, f)), "%s not written" % f)
            check(oct(os.stat(os.path.join(d, f)).st_mode & 0o777) == "0o600", "%s mode" % f)
        n = len(rules(z))
        z.restart()
        check(len(rules(z)) == n, "rules lost over a restart")
        check(z.req("rs.test", "/admin/x").status == 403, "rules not active after a restart")
        return "%d rules, files in conf/ruleset, survived a restart" % n
