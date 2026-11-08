"""WAF (Coraza + CRS): block / detection, central policy inheritance, profiles, exclusions, events."""
import json
import urllib.parse

from lib import *

SQLI = "/search?q=" + urllib.parse.quote("1' OR '1'='1' UNION SELECT username,password FROM users--")
XSS = "/c?x=" + urllib.parse.quote("<script>alert(document.cookie)</script>")
TRAV = "/f?file=" + urllib.parse.quote("../../../../etc/passwd")
CLEAN = "/search?q=hello+world"
ATTACKS = {"sqli": SQLI, "xss": XSS, "traversal": TRAV}


def codes(z, host):
    return {k: z.req(host, p).status for k, p in ATTACKS.items()}


@scenario("waf_block_and_detect", ["82"])
def waf_block_and_detect():
    """Custom per-rule WAF: block mode returns 403 for SQLi/XSS/traversal and passes clean traffic;
    detection mode passes everything but records events; events are visible via the API."""
    with Zoraxy() as z, Backend(name="app") as b:
        z.add_rule("w.test", b.addr)
        check(all(c == 200 for c in codes(z, "w.test").values()), "WAF off should pass everything")
        z.api("/api/waf/set", rootname="w.test", config=json.dumps({"Mode": "block", "ParanoiaLevel": 1, "InboundThreshold": 5}))
        c = codes(z, "w.test")
        check(all(v == 403 for v in c.values()), "block mode did not block all attacks: %s" % c)
        n = len(b.log)
        clean = z.req("w.test", CLEAN)
        check(clean.status == 200, "clean request blocked: %d" % clean.status)
        # POST body attack
        r = z.req("w.test", "/login", "POST", {"Content-Type": "application/x-www-form-urlencoded"},
                  b"user=admin&pass=" + urllib.parse.quote("' OR 1=1 --").encode())
        check(r.status == 403, "POST body SQLi not blocked: %d" % r.status)
        check(r.h("x-request-id"), "blocked response lacks X-Request-Id")
        blocked_hits = len(b.log) - n
        check(blocked_hits == 1, "backend saw %d requests, only the clean one expected" % blocked_hits)
        ev = z.get("/api/waf/events", limit=50)
        blocked = [e for e in ev if e.get("action") == "blocked"]
        check(len(blocked) >= 4, "expected >=4 blocked events, got %d" % len(blocked))
        # detection only
        z.api("/api/waf/set", rootname="w.test", config=json.dumps({"Mode": "detection_only"}))
        before = len(z.get("/api/waf/events", limit=500))
        c2 = codes(z, "w.test")
        check(all(v == 200 for v in c2.values()), "detection_only blocked: %s" % c2)
        ev2 = z.get("/api/waf/events", limit=500)
        det = [e for e in ev2 if e.get("action") == "detected"]
        check(len(ev2) > before and len(det) >= 3, "detection events missing (%d new)" % (len(ev2) - before))
        ex = blocked[0]
        return "block: %s -> all 403, clean 200, backend untouched by attacks; detection: all 200 + %d 'detected' events; event sample keys=%s" % (
            c, len(det), sorted(ex.keys())[:8])


@scenario("waf_central_policy", ["82"])
def waf_central_policy():
    """Central policy inheritance, per-rule overrides, built-in profile, rule exclusion, trusted IP bypass."""
    with Zoraxy() as z, Backend(name="app") as b:
        z.add_rule("inh.test", b.addr)
        z.add_rule("off.test", b.addr)
        z.add_rule("prof.test", b.addr)
        z.api("/api/waf/policy", policy=json.dumps({"Enabled": True, "DefaultMode": "block", "ParanoiaLevel": 1,
                                                    "InboundThreshold": 5, "AllowEndpointOverride": True}))
        z.api("/api/waf/endpoint/set", rootname="off.test", source="off")
        z.api("/api/waf/endpoint/set", rootname="prof.test", source="profile", profile="Strict")
        ci = codes(z, "inh.test")
        co = codes(z, "off.test")
        cp = codes(z, "prof.test")
        check(all(v == 403 for v in ci.values()), "inheriting rule not blocked by central policy: %s" % ci)
        check(all(v == 200 for v in co.values()), "source=off rule still filtered: %s" % co)
        check(all(v == 403 for v in cp.values()), "profile Strict did not block: %s" % cp)
        cov = z.get("/api/waf/coverage")
        profs = [p.get("Name") for p in z.get("/api/waf/profiles")]
        check("Strict" in profs and "WordPress" in profs, "built-in profiles missing: %s" % profs)
        # switch the central default to detection only: inheriting rule passes, events recorded
        z.api("/api/waf/policy", policy=json.dumps({"Enabled": True, "DefaultMode": "detection_only", "ParanoiaLevel": 1,
                                                    "InboundThreshold": 5, "AllowEndpointOverride": True}))
        ci2 = codes(z, "inh.test")
        check(all(v == 200 for v in ci2.values()), "policy detection_only still blocking: %s" % ci2)
        z.api("/api/waf/policy", policy=json.dumps({"Enabled": True, "DefaultMode": "block", "ParanoiaLevel": 1,
                                                    "InboundThreshold": 5, "AllowEndpointOverride": True}))
        # exclude the rule(s) that fire on the traversal attack for this endpoint only
        ev = z.get("/api/waf/events", limit=200, endpoint="inh.test", action="blocked")
        trav_rules = sorted({r["id"] for e in ev if "passwd" in e.get("uri", "") for r in e.get("rules", [])
                             if r["id"] not in (949110, 949111, 959100, 980130)})
        check(trav_rules, "no traversal rule ids found in events: %s" % (ev[:1],))
        for rid in trav_rules:
            z.api("/api/waf/exclude", ruleid=rid, scope="endpoint", rootname="inh.test")
        z2 = z.req("inh.test", CLEAN).status
        check(z2 == 200, "clean blocked after exclusion")
        t = z.req("inh.test", TRAV).status
        s = z.req("inh.test", SQLI).status
        check(t == 200, "traversal still blocked after excluding rules %s (%d)" % (trav_rules, t))
        check(s == 403, "SQLi no longer blocked after excluding traversal rules (%d)" % s)
        # trusted IP bypass
        z.api("/api/waf/policy", policy=json.dumps({"Enabled": True, "DefaultMode": "block", "ParanoiaLevel": 1,
                                                    "InboundThreshold": 5, "AllowedIPs": ["127.0.0.1"]}))
        cb = codes(z, "inh.test")
        check(all(v == 200 for v in cb.values()), "AllowedIPs bypass ignored: %s" % cb)
        return ("inherit=block %s; source=off %s; profile Strict %s; policy->detection passes; exclusion of %s let traversal=%d while SQLi stays 403; AllowedIPs bypass ok"
                % (ci, co, cp, trav_rules, t))
