"""Plugin request/response hooks with the example filter plugin."""
import json

from lib import *


@scenario("plugin_filter_hooks", ["83"])
def plugin_filter_hooks():
    """Example filter plugin (real process): pre_auth denies matching User-Agents, tags requests, adds response headers,
    and fails open when the plugin process dies."""
    binp = build_example_plugin("filter-example")
    with Zoraxy(plugins=[("filter-example", binp)]) as z, Backend(lambda h, rec, b: send(h, 200, json.dumps({"headers": rec["headers"]}), {"X-Powered-By": "upstream"}, ctype="application/json"), name="app") as app:
        z.add_rule("pl.test", app.addr)
        pid = None
        lst = z.get("/api/plugins/list")
        for p in lst:
            sp = p.get("Spec") or p
            if "filter-example" in json.dumps(sp):
                pid = sp.get("id") or sp.get("ID")
        check(pid, "plugin not discovered: %s" % json.dumps(lst)[:300])
        z.api("/api/plugins/enable", plugin_id=pid, enable=True)
        z.api("/api/plugins/hooks/set", plugin_id=pid, **{"global": True})
        def up():
            r = z.req("pl.test", "/", headers={"User-Agent": "Mozilla"})
            return r if r.h("x-content-type-options") == "nosniff" else None
        ok = wait_for(up, timeout=15, msg="plugin to be active (response header)")
        check(ok.json()["headers"].get("x-filter-example") == "checked", "pre_auth header modification missing: %s" % ok.json()["headers"])
        check(not ok.h("x-powered-by"), "response hook did not remove X-Powered-By")
        check(ok.h("referrer-policy") == "strict-origin-when-cross-origin", "response header missing")
        n = len(app.log)
        bad = z.req("pl.test", "/", headers={"User-Agent": "sqlmap/1.7"})
        check(bad.status == 403 and len(app.log) == n, "pre_auth deny not applied: %d" % bad.status)
        # kill the plugin process: failure policy is open => traffic keeps flowing
        import subprocess
        subprocess.run(["pkill", "-9", "-f", z.dir + "/plugins/filter-example/filter-example"])
        time.sleep(1)
        after = z.req("pl.test", "/", headers={"User-Agent": "Mozilla"}, timeout=10)
        check(after.status == 200, "plugin down + fail-open policy but request failed (%d)" % after.status)
        return "plugin discovered as %s; pre_auth: sqlmap UA=403 (upstream untouched), others tagged X-Filter-Example; response hook: nosniff/referrer-policy added, X-Powered-By removed; plugin killed => still 200 (fail open)" % pid
