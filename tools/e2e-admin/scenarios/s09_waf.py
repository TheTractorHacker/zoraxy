import json
from runner import scenario, NotTestable
from .common import *

ATTACK = "/search?q=1%27%20OR%20%271%27%3D%271%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"


@scenario("api-waf-modes-events-exclusions-coverage", ["82"])
def waf():
    with Env("waf") as e:
        c = e.c
        e.add_rule("w1.test")
        e.add_rule("w2.test")
        pol = c.get("/api/waf/policy")[1]
        check(pol.get("Enabled") is False, f"first run should not enable the WAF by itself: {pol}")
        check(e.req("w1.test", ATTACK)[0] == 200, "attack blocked with the WAF off")
        # central policy: enabled, inherit mode block via endpoint source
        st, js = c.post("/api/waf/endpoint/set", rootname="w1.test", source="detection_only")
        check(st == 200 and not (isinstance(js, dict) and js.get("error")), f"endpoint set detection_only: {js}")
        c.post("/api/waf/policy", policy=json.dumps(dict(pol, Enabled=True)))
        time.sleep(0.5)
        st = e.req("w1.test", ATTACK)[0]
        check(st == 200, f"detection_only must not block: {st}")
        ev = c.get("/api/waf/events", limit="20")[1]
        check("942" in json.dumps(ev) or "w1.test" in json.dumps(ev), f"no WAF event recorded for the detected attack: {json.dumps(ev)[:200]}")
        # block mode
        c.ok("/api/waf/endpoint/set", rootname="w1.test", source="block")
        time.sleep(0.5)
        st = e.req("w1.test", ATTACK)[0]
        check(st == 403, f"block mode: attack got {st}")
        check(e.req("w1.test", "/search?q=hello")[0] == 200, "block mode blocked a normal request")
        # per-rule exclusion for the whole endpoint lets the attack through again (all SQLi rule ids found in the events)
        ev = c.get("/api/waf/events", limit="50")[1]
        ids = sorted({str(r["id"]) for x in ev for r in (x.get("rules") or []) if x.get("endpoint") == "w1.test"})
        check(ids, f"events carry no rule ids: {json.dumps(ev[0] if ev else ev)[:900]}")
        for rid in ids:
            c.post("/api/waf/exclude", rootname="w1.test", ruleid=rid)
        time.sleep(0.8)
        st = e.req("w1.test", ATTACK)[0]
        check(st == 200, f"exclusion of {ids} did not let the request through: {st}")
        # coverage: bulk set across rules, then the other rule blocks too
        cov = c.get("/api/waf/coverage")[1]
        check("w2.test" in json.dumps(cov), f"coverage lacks w2.test: {json.dumps(cov)[:200]}")
        r = c.ok("/api/proxy/bulk", rules=json.dumps(["w2.test"]), action="set_waf", params=json.dumps({"WAFSource": "block"}))
        check(all(x["OK"] for x in r["results"]), f"bulk set_waf {r}")
        time.sleep(0.6)
        check(e.req("w2.test", ATTACK)[0] == 403, "bulk-set WAF block mode not enforced on w2")
        return "WAF: off by default (attack passes), detection_only logs an event without blocking, block mode returns 403 for SQLi and 200 for normal requests, rule exclusion releases the request, bulk set_waf (coverage) enforces block on another rule"
