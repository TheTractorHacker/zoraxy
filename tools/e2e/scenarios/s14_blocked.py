"""Blocked request log (Statistics > Blocked): real blocked traffic through a real proxy ends up in /api/blocked/* with the right reason."""
import json
import time
import urllib.parse

from lib import *

SQLI = "/search?q=" + urllib.parse.quote("1' OR '1'='1' UNION SELECT username,password FROM users--")


def wait_entries(z, n, **q):
    """The proxy records from a goroutine; poll until n entries are listed."""
    t0 = time.time()
    while time.time() - t0 < 10:
        d = z.get("/api/blocked/list", **q)
        if d["total"] >= n:
            return d
        time.sleep(0.2)
    return z.get("/api/blocked/list", **q)


@scenario("blocked_request_log", ["stats-blocked"])
def blocked_request_log():
    """WAF attack, blacklisted client, rate limit and bot rule each show up with their reason; clean traffic and
    the query string do not; filters, summary, clear and persistence over a restart work."""
    with Zoraxy() as z, Backend(name="blk") as b:
        z.add_rule("blk.test", b.addr, rate=True, ratenum=2, rateburst=2)
        z.api("/api/waf/set", rootname="blk.test", config=json.dumps({"Mode": "block", "ParanoiaLevel": 1, "InboundThreshold": 5}))
        z.api("/api/botrules/set", config=json.dumps({"Enabled": True, "Categories": {"scanner": {"Enabled": True, "Action": "block"}}}))
        z.api("/api/blacklist/ip/add", ip="127.0.0.3", id="default", comment="e2e")
        z.api("/api/blacklist/enable", enable=True, id="default")

        check(z.req("blk.test", "/", src="127.0.0.2").status == 200, "clean request refused")
        check(z.req("blk.test", SQLI, src="127.0.0.4").status == 403, "WAF attack not blocked")
        check(z.req("blk.test", "/secret?token=abc", src="127.0.0.3").status == 403, "blacklisted client served")
        check(z.req("blk.test", "/", src="127.0.0.5", headers={"User-Agent": "sqlmap/1.7"}).status == 403, "bot UA served")
        codes = [z.req("blk.test", "/burst", src="127.0.0.6").status for _ in range(12)]
        check(429 in codes, "rate limit never triggered: %s" % codes)

        d = wait_entries(z, 4 + codes.count(429))
        by_ip = {}
        for e in d["items"]:
            by_ip.setdefault(e["ip"], []).append(e)
        want = {"127.0.0.4": "waf", "127.0.0.3": "blacklist", "127.0.0.5": "bot", "127.0.0.6": "ratelimit"}
        for ip, reason in want.items():
            got = {e["reason"] for e in by_ip.get(ip, [])}
            check(got == {reason}, "%s: reasons %s, want %s (all: %s)" % (ip, got, reason, json.dumps(d["items"])[:400]))
        check("127.0.0.2" not in by_ip, "the clean request was logged as blocked")
        waf = by_ip["127.0.0.4"][0]
        check(waf["status"] == 403 and waf["host"] == "blk.test" and "tx " in waf["detail"], "WAF entry lacks facts: %s" % waf)
        check(by_ip["127.0.0.3"][0]["path"] == "/secret", "query string stored: %s" % by_ip["127.0.0.3"][0]["path"])

        s = z.get("/api/blocked/summary")
        reasons = {r["key"]: r["n"] for r in s["reasons"]}
        check(set(reasons) == {"waf", "blacklist", "bot", "ratelimit"}, "summary reasons: %s" % reasons)
        check(sum(x["n"] for x in s["hourly"]) == s["total"], "hourly series does not add up")
        check(len(s["reasonInfo"]) >= 10 and all(r["why"] for r in s["reasonInfo"]), "reason explanations missing")
        # the Status page counter and the log agree
        today = z.get("/api/stats/glance")
        check(today["BlockedToday"] >= s["total"], "Blocked today (%s) smaller than the log (%s)" % (today["BlockedToday"], s["total"]))

        # filters
        check(z.get("/api/blocked/list", reason="waf")["total"] == 1, "reason filter")
        check(z.get("/api/blocked/list", ip="127.0.0.3")["total"] == 1, "ip filter")
        check(z.get("/api/blocked/list", host="blk.test")["total"] == s["total"], "host filter")
        code, _ = z.api("/api/blocked/list", method="GET", raw=True, reason="nope")
        check(code == 200, "bad reason must answer with an error object")

        # persistence: saved at shutdown, reloaded
        total = s["total"]
        z.restart()
        d2 = z.get("/api/blocked/list")
        check(d2["total"] == total, "log not restored after restart: %d vs %d" % (d2["total"], total))

        # clear needs the confirmation
        code, body = z.api("/api/blocked/clear", raw=True)
        check(b"confirmation" in body, "clear without confirm: %r" % body)
        z.api("/api/blocked/clear", confirm="yes")
        check(z.get("/api/blocked/list")["total"] == 0, "clear did not empty the log")
        return "reasons %s; clean request and query string not stored; restart kept %d entries; Blocked today >= log" % (json.dumps(reasons), total)
