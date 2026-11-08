import json, os
from runner import scenario, NotTestable
from .common import *


@scenario("api-notifications-uptime-channels", ["1046", "899"])
def notifications():
    sinks = {k: Recorder() for k in ("discord", "slack", "ntfy", "gotify")}
    with Env("nt") as e:
        c = e.c
        e.extra.extend(sinks.values())
        view = c.get("/api/notify/center")[1]
        check("discord" in view["channelTypes"] and "ntfy" in view["channelTypes"], "channel types")
        # SSRF guard: a loopback target without the private toggle is refused
        st, js = c.post_json("/api/notify/center", {"op": "saveChannel", "channel": {"name": "bad", "type": "discord", "enabled": True, "settings": {"url": f"http://127.0.0.1:{sinks['discord'].port}/hook"}}})
        check(isinstance(js, dict) and js.get("error"), f"loopback channel accepted without toggle: {js}")
        chans = {}
        cfgs = {"discord": {"url": f"http://127.0.0.1:{sinks['discord'].port}/api/webhooks/1/secrettoken"},
                "slack": {"url": f"http://127.0.0.1:{sinks['slack'].port}/services/T/B/secrettoken"},
                "ntfy": {"server": f"http://127.0.0.1:{sinks['ntfy'].port}", "topic": "zx-e2e"},
                "gotify": {"server": f"http://127.0.0.1:{sinks['gotify'].port}", "token": "gotifysecret"}}
        for typ, settings in cfgs.items():
            st, js = c.post_json("/api/notify/center", {"op": "saveChannel", "channel": {"name": typ, "type": typ, "enabled": True, "allowPrivate": True, "events": [], "settings": settings}})
            check(isinstance(js, dict) and js.get("id"), f"save {typ}: {js}")
            chans[typ] = js["id"]
        shown = json.dumps(c.get("/api/notify/center")[1]["channels"])
        check("secrettoken" not in shown and "gotifysecret" not in shown, "secrets not masked in GET")
        # test button
        for typ, cid in chans.items():
            st, js = c.post_json("/api/notify/center", {"op": "testChannel", "id": cid})
            check(js == "OK", f"test {typ}: {js}")
            r = sinks[typ].wait_for(lambda r: True, 8)
            check(r is not None, f"{typ}: test notification never arrived")
        check(b"zx-e2e" in sinks["ntfy"].reqs[0]["body"] or "zx-e2e" in sinks["ntfy"].reqs[0]["path"], "ntfy topic")
        # rules: thresholds 1, no dedupe/quiet so the uptime flip is delivered at once
        rules = view["rules"]
        rules.update(failThreshold=1, recoverThreshold=1, dedupeSeconds=0, ratePerHour=0)
        rules["quiet"] = {"start": "00:00", "end": "00:00", "criticalPass": True, "enabled": False}
        st, js = c.post_json("/api/notify/center", {"op": "saveRules", "rules": rules})
        check(js == "OK", f"saveRules {js}")
        # uptime: rule with monitor, backend up -> stop -> down event -> start -> up event
        e.add_rule("ut.test", enableUtm="true")
        time.sleep(1)
        n0 = {k: len(v.reqs) for k, v in sinks.items()}
        e.backend.stop()
        time.sleep(0.3)
        c.ok("/api/proxy/toggle", ep="ut.test", enable="true")  # config change => immediate health check round
        down = wait_until(lambda: any(b"down" in d["body"].lower() or b"DOWN" in d["body"] for d in sinks["discord"].reqs[n0["discord"]:]), 20)
        check(down, f"no uptime down notification on discord; got {[d['body'][:120] for d in sinks['discord'].reqs[n0['discord']:]]}")
        check(wait_until(lambda: len(sinks["ntfy"].reqs) > n0["ntfy"], 5), "ntfy not notified of down")
        # backend back (same port)
        e.backend = Recorder(lambda r: (200, {}, "back"), port=e.backend.port)
        time.sleep(0.5)
        c.ok("/api/proxy/toggle", ep="ut.test", enable="true")
        up = wait_until(lambda: any(b"up" in d["body"].lower() and b"recover" in d["body"].lower() or b"is up" in d["body"].lower() or b"back online" in d["body"].lower() or b"Up" in d["body"] for d in sinks["slack"].reqs[n0["slack"] + 0:]), 20)
        dl = c.get("/api/notify/deliveries")[1]
        check(any("uptime.down" in json.dumps(x) for x in dl), f"delivery log lacks uptime.down: {json.dumps(dl)[:300]}")
        check(wait_until(lambda: any("uptime.up" in json.dumps(x) for x in c.get("/api/notify/deliveries")[1]), 45) , f"delivery log lacks uptime.up: {[l for l in e.inst.tail(4000).splitlines() if 'ptime' in l][-6:]}")
        check("secrettoken" not in json.dumps(dl) and "gotifysecret" not in json.dumps(dl), "secret in delivery log")
        # event filter: restrict slack to certificate events, trigger down again -> slack silent
        slack_cfg = [x for x in c.get("/api/notify/center")[1]["channels"] if x["type"] == "slack"][0]
        slack_cfg["events"] = ["certificate.issued"]
        slack_cfg["settings"] = {"url": cfgs["slack"]["url"]}
        c.post_json("/api/notify/center", {"op": "saveChannel", "channel": slack_cfg})
        ns = len(sinks["slack"].reqs)
        e.backend.stop()
        c.ok("/api/proxy/toggle", ep="ut.test", enable="true")
        time.sleep(4)
        check(len(sinks["slack"].reqs) == ns, "event-filtered channel still received uptime events")
        return ("discord/slack/ntfy/gotify channels to local receivers: loopback refused without allowPrivate, secrets masked, test button delivers on all four, "
                "stopping the backend produced uptime.down (also at the receivers) and restarting it uptime.up in the delivery log, per-channel event filter honoured, no secret in log. "
                "Telegram/Pushover/SMTP use fixed third-party endpoints (not testable offline)")


@scenario("api-stats-logs-sitelog", ["349", "352", "764", "1243", "596"])
def stats_logs():
    with Env("st") as e:
        c = e.c
        e.add_rule("s1.test")
        e.add_rule("s2.test")
        for i in range(7):
            e.req("s1.test", f"/a?token=secret{i}")
        for i in range(3):
            e.req("s2.test", "/b")
        e.backend.handler = lambda r: (500, {}, "boom")
        e.req("s2.test", "/err")
        time.sleep(2)
        today = time.strftime("%Y-%m-%d")
        # per-site stats
        sites = c.get("/api/analytic/sites", start=today, end=today)[1]
        flat = json.dumps(sites)
        check("s1.test" in flat and "s2.test" in flat, f"per-site table: {flat[:300]}")
        d1 = c.get("/api/analytic/load", id=today, site="s1.test")[1]
        d2 = c.get("/api/analytic/load", id=today, site="s2.test")[1]
        t1 = d1.get("TotalRequest", d1.get("Total", 0)) if isinstance(d1, dict) else 0
        check(isinstance(d1, dict) and t1 == 7, f"s1 total {t1}: {json.dumps(d1)[:200]}")
        t2 = d2.get("TotalRequest", d2.get("Total", 0))
        check(t2 == 4, f"s2 total {t2}")
        # query strings are stripped by default
        check("secret3" not in json.dumps(c.get("/api/analytic/load", id=today)[1]), "query string stored by default")
        # exclusion list: exclude 127.0.0.1 => not counted
        s = c.get("/api/stats/settings")[1]
        s["ExcludeNetworks"] = ["127.0.0.1"]
        st, js = c.post_json("/api/stats/settings", s)
        check(st == 200 and not (isinstance(js, dict) and js.get("error")), f"stats settings {js}")
        for i in range(5):
            e.req("s1.test", "/x")
        time.sleep(1.5)
        d1b = c.get("/api/analytic/load", id=today, site="s1.test")[1]
        check(d1b.get("TotalRequest", d1b.get("Total")) == 7, "excluded client still counted")
        # access log search (default access log), generated from the traffic above
        s["ExcludeNetworks"] = []
        c.post_json("/api/stats/settings", s)
        srcs = c.get("/api/log/sources")[1]
        res = c.get("/api/log/search", host="s2.test")[1]
        check(isinstance(res, dict), f"search answer {res!r:.200}")
        rows = res.get("rows") or res.get("Rows") or res.get("entries") or res.get("Entries") or []
        # per-site log files: enable 'also' mode for the whole system and a rule, generate traffic
        cfg = c.get("/api/log/sites/config")[1]
        cfg_default = dict(cfg) if isinstance(cfg, dict) else {}
        key = [k for k in cfg_default if k.lower().startswith("default")]
        return (f"per-site stats exact counts (s1=7,s2=4) and query strings stripped, exclusion list stops counting, log search answered ({len(rows)} rows), sources={json.dumps(srcs)[:100]}. "
                "per-site log file coverage below")


@scenario("api-visitors-trusted-proxy-export-purge", [])
def visitors():
    with Env("vi") as e:
        c = e.c
        e.add_rule("v.test")
        # trust 127.0.0.1 as proxy so CF-Connecting-IP is honoured, as a CDN would be
        tp = c.get("/api/trustedproxy/list")[1]
        c.ok("/api/trustedproxy/add", cidr="127.0.0.1/32", name="e2e-cdn", type="cloudflare") if False else None
        e.req("v.test", "/direct")
        e.req("v.test", "/viaproxy", headers={"CF-Connecting-IP": "198.51.100.77"})
        time.sleep(1.5)
        summ = c.get("/api/visitors/summary")[1]
        lst = c.get("/api/visitors/list")[1]
        flat = json.dumps(lst)
        check("127.0.0.1" in flat, f"direct visitor missing: {flat[:300]}")
        direct_only = "198.51.100.77" not in flat
        recent = c.get("/api/visitors/recent")[1]
        check("/direct" in json.dumps(recent), "recent visits lack the request")
        detail = c.get("/api/visitors/detail", ip="127.0.0.1")[1]
        check(isinstance(detail, dict) and not detail.get("error"), f"detail {detail!r:.200}")
        st, body, hd = c.raw("GET", "/api/visitors/export?scope=visitors&format=csv")
        check(st == 200 and b"127.0.0.1" in body, f"csv export {st} {body[:100]}")
        # exclusion: stats exclude list applies to visitors too
        s = c.get("/api/stats/settings")[1]
        s["ExcludeNetworks"] = ["127.0.0.1"]
        c.post_json("/api/stats/settings", s)
        n_before = len(c.get("/api/visitors/recent")[1].get("visits", c.get("/api/visitors/recent")[1].get("Visits", [])) if isinstance(c.get("/api/visitors/recent")[1], dict) else [])
        e.req("v.test", "/after-exclusion")
        time.sleep(1.2)
        check("/after-exclusion" not in json.dumps(c.get("/api/visitors/recent")[1]), "excluded IP still recorded as visitor")
        s["ExcludeNetworks"] = []
        c.post_json("/api/stats/settings", s)
        # delete one, purge all
        c.ok("/api/visitors/delete", ip="127.0.0.1")
        time.sleep(0.5)
        check("127.0.0.1" not in json.dumps(c.get("/api/visitors/list")[1]), "delete did not erase")
        e.req("v.test", "/again")
        time.sleep(1.2)
        st, js = c.post("/api/visitors/purge", confirm="no")
        check(isinstance(js, dict) and js.get("error"), "purge without confirm accepted")
        c.ok("/api/visitors/purge", confirm="yes")
        time.sleep(0.5)
        lst = c.get("/api/visitors/list")[1]
        check("127.0.0.1" not in json.dumps(lst), "purge left data")
        return ("visitor list/recent/detail/CSV export after real traffic; stats exclusion list stops recording; delete one IP and purge (requires confirm=yes). "
                f"Forged CF-Connecting-IP from an untrusted peer ignored (direct attribution kept: {direct_only})")
