import json, os
from runner import scenario, NotTestable
from .common import *


@scenario("api-per-site-log-files", ["596"])
def sitelogs():
    with Env("sl") as e:
        c = e.c
        e.add_rule("log1.test")
        e.add_rule("log2.test")
        cfg = c.get("/api/log/sites/config")[1]
        check(cfg.get("mode") == "off", f"default should be off: {cfg}")
        cfg["rules"] = {"log1.test": "also"}
        cfg["format"] = "json"
        st, js = c.post_json("/api/log/sites/config", cfg)
        check(st == 200 and js.get("rules", {}).get("log1.test") == "also", f"config {js}")
        for i in range(3):
            e.req("log1.test", f"/one{i}")
            e.req("log2.test", f"/two{i}")
        time.sleep(1.5)
        base = os.path.join(e.inst.dir, "log", "sites")
        files = []
        for d, _, fs in os.walk(base):
            files += [os.path.join(d, f) for f in fs]
        check(any("log1" in f for f in files) and not any("log2" in f for f in files), f"site log files: {files}")
        txt = open([f for f in files if "log1" in f][0]).read()
        check("/one0" in txt and "/two0" not in txt and txt.strip().startswith("{"), f"site log content: {txt[:200]}")
        return "per-site log: default off, enabling one rule in json mode writes only that rule's file under log/sites/<rule>/ with just its requests"
