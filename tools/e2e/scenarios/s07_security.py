"""Rate limiting, path rules, allowed peers, header rules, bot rules, auto-ban."""
import json
import urllib.parse

from lib import *


def burst(z, host, n, path="/", src=None, headers=None):
    codes = []
    for _ in range(n):
        codes.append(z.req(host, path, src=src, headers=headers).status)
    return codes


@scenario("rate_limit", ["87", "726"])
def rate_limit():
    """Per-rule rate limit with burst, per-client buckets, and per-path rate_limit path rules."""
    with Zoraxy() as z, Backend(name="rl") as b:
        z.add_rule("rl.test", b.addr, rate=True, ratenum=5, rateburst=0)
        c = burst(z, "rl.test", 40)
        n429 = c.count(429)
        check(c[0] == 200 and n429 >= 20, "5 rps limit did not trigger as expected: %s" % c)
        other = burst(z, "rl.test", 3, src="127.0.0.9")
        check(other == [200, 200, 200], "other client shares the bucket: %s" % other)
        time.sleep(1.2)
        check(z.req("rl.test").status == 200, "limit did not recover after a second")
        # burst: 1 rps with burst 15 lets ~15 immediately
        z.edit_rule("rl.test", rate=True, ratenum=1, rateburst=15)
        time.sleep(1.2)
        c2 = burst(z, "rl.test", 30, src="127.0.0.10")
        ok2 = c2.count(200)
        check(12 <= ok2 <= 20, "burst 15 allowed %d of 30: %s" % (ok2, c2))
        # path rule: /login limited to 2 rps (burst 2), other paths free
        z.add_rule("pl.test", b.addr)
        z.api("/api/proxy/networking/pathrules", ep="pl.test", rules=json.dumps(
            [{"Name": "login-limit", "MatchMode": "prefix", "Pattern": "/login", "Action": "rate_limit", "RateLimit": 2, "RateBurst": 2}]))
        login = burst(z, "pl.test", 12, "/login")
        check(login.count(429) >= 6 and login[0] == 200, "per-path limit not applied: %s" % login)
        free = burst(z, "pl.test", 12, "/home")
        check(set(free) == {200}, "unlisted path got limited: %s" % free)
        return "rule 5rps: %d/40 x429 (other client unaffected, recovers); burst15: %d/30 passed; /login path rule: %d/12 x429 while /home 12/12 ok" % (
            n429, ok2, login.count(429))


@scenario("path_rules_bypass", ["238", "726"])
def path_rules_bypass():
    """Deny path rule on /admin cannot be bypassed with encoding / dot-segment / ;param / slash tricks."""
    def leaked(path):
        p = urllib.parse.urlsplit(path).path
        for _ in range(3):
            p = urllib.parse.unquote(p)
        p = "/".join(s.split(";")[0] for s in p.replace("\\", "/").split("/"))
        import posixpath
        p = posixpath.normpath("/" + p)
        return p == "/admin" or p.startswith("/admin/")

    with Zoraxy() as z, Backend(name="pr") as b:
        z.add_rule("pr.test", b.addr)
        z.api("/api/proxy/networking/pathrules", ep="pr.test", rules=json.dumps(
            [{"Name": "no-admin", "MatchMode": "prefix", "Pattern": "/admin", "Action": "deny"}]))
        check(z.req("pr.test", "/admin/panel").status == 403, "direct /admin/panel not denied")
        check(z.req("pr.test", "/public").status == 200, "public path denied")
        variants = ["/admin", "/admin/", "//admin/x", "/./admin/x", "/x/../admin/x", "/x/%2e%2e/admin/x", "/%61dmin/x",
                    "/%2561dmin/x", "/admin;x=1/y", "/admin%3Bx=1/y", "/admin%00/x", "/admin%2fx", "/.%2e/admin/x",
                    "/%2e/admin", "/admin/.", "/admin/../admin/x", "/ADMIN/x", "/admin%5cx", "/admin%09/x"]
        bad = {}
        res = {}
        for v in variants:
            n = len(b.log)
            r = z.req("pr.test", v)
            res[v] = r.status
            if len(b.log) > n and r.status == 200 and leaked(b.log[-1]["path"]):
                bad[v] = b.log[-1]["path"]
        check(not bad, "deny rule bypassed: %s" % bad)
        return "19 bypass variants for deny /admin: none reached an /admin resource; statuses=%s" % json.dumps(res)


@scenario("allowed_peers", ["761"])
def allowed_peers():
    """Only listed direct peers may connect; forwarded headers do not influence the decision."""
    with Zoraxy() as z, Backend(name="ap") as b:
        z.add_rule("ap.test", b.addr)
        z.api("/api/proxy/networking/peers", ep="ap.test", cidrs=json.dumps(["127.0.0.2/32"]))
        bad = z.req("ap.test", src="127.0.0.1", headers={"X-Forwarded-For": "127.0.0.2", "X-Real-Ip": "127.0.0.2"})
        good = z.req("ap.test", src="127.0.0.2")
        check(bad.status in (403, 404) or bad.status == 0, "disallowed peer served (%d)" % bad.status)
        check(good.status == 200, "allowed peer refused (%d)" % good.status)
        return "peer 127.0.0.1 -> %d (even with XFF=127.0.0.2); peer 127.0.0.2 -> %d" % (bad.status, good.status)


@scenario("header_rules_access", ["1356"])
def header_rules_access():
    """Header rules gate access on a secret header (equals / regex / present), values masked in the API."""
    with Zoraxy() as z, Backend(name="hr") as b:
        z.add_rule("hr.test", b.addr)
        z.api("/api/headerrules/set", ep="hr.test", rules=json.dumps(
            [{"Name": "X-Edge-Secret", "Match": "equals", "Values": ["s3cr3t-token"], "Action": "deny"}]))
        r1 = z.req("hr.test").status
        r2 = z.req("hr.test", headers={"X-Edge-Secret": "wrong"}).status
        r3 = z.req("hr.test", headers={"X-Edge-Secret": "s3cr3t-token"}).status
        check((r1, r2, r3) == (403, 403, 200), "equals rule: none=%d wrong=%d right=%d" % (r1, r2, r3))
        got = json.dumps(z.get("/api/headerrules/get", ep="hr.test"))
        det = json.dumps(z.detail("hr.test"))
        check("s3cr3t-token" not in got and "s3cr3t-token" not in det, "header rule secret exposed by the API")
        z.api("/api/headerrules/set", ep="hr.test", rules=json.dumps(
            [{"Name": "X-Tenant", "Match": "regex", "Values": ["^acme-[0-9]+$"], "Action": "deny"}]))
        c = [z.req("hr.test", headers={"X-Tenant": v}).status for v in ("acme-42", "acme-x", "evil acme-42")]
        check(c == [200, 403, 403], "regex rule: %s" % c)
        return "equals: none/wrong=403 right=200; regex full-match enforced; secret masked in /api/headerrules/get and /api/proxy/detail"


@scenario("bot_rules", ["615"])
def bot_rules():
    """Bot rules by User-Agent: category (AI crawler, scanner), custom substring, empty UA; per-rule opt-out."""
    with Zoraxy() as z, Backend(name="bot") as b:
        z.add_rule("bot.test", b.addr)
        z.add_rule("nobot.test", b.addr)
        cfg = {"Enabled": True, "Categories": {"ai_crawler": {"Enabled": True, "Action": "block"}, "scanner": {"Enabled": True, "Action": "block"}},
               "Custom": [{"Name": "mine", "Type": "substring", "Pattern": "EvilScraper", "CaseInsensitive": True, "Action": "block"}],
               "BlockEmptyUA": "block"}
        z.api("/api/botrules/set", config=json.dumps(cfg))
        ua = lambda host, u: z.req(host, headers={"User-Agent": u} if u is not None else {"User-Agent": ""}).status
        res = {u: ua("bot.test", u) for u in ("Mozilla/5.0 (X11) Firefox/120", "GPTBot/1.1", "sqlmap/1.7", "xx evilscraper/9", "")}
        check(res["Mozilla/5.0 (X11) Firefox/120"] == 200, "browser UA blocked: %s" % res)
        check(all(res[k] == 403 for k in ("GPTBot/1.1", "sqlmap/1.7", "xx evilscraper/9")), "bot UAs not blocked: %s" % res)
        check(res[""] == 403, "empty UA not blocked: %s" % res)
        z.api("/api/botrules/endpoint", ep="nobot.test", policy="off")
        check(ua("nobot.test", "GPTBot/1.1") == 200, "per-rule opt-out ignored")
        return "UA results %s; nobot.test opt-out -> 200" % json.dumps(res)


@scenario("auto_ban", ["22"])
def auto_ban():
    """Repeated 404s ban the client; others stay served; spoofed X-Forwarded-For cannot ban a victim or dodge a ban; unban works."""
    def h404(h, rec, b):
        send(h, 404 if rec["path"].startswith("/missing") else 200, "x")

    with Zoraxy() as z, Backend(h404, name="ab") as b:
        z.add_rule("ab.test", b.addr)
        cfg = z.get("/api/abuse/config")
        cfg.pop("RemoteTokenSet", None)
        cfg.pop("AllKinds", None)
        cfg.update(Enabled=True, BanSeconds=120, BanPrivate=True, EscalationFactor=1)
        cfg["Detectors"]["not_found"] = {"Enabled": True, "Threshold": 5, "WindowSec": 60}
        z.api("/api/abuse/setConfig", config=json.dumps(cfg))
        attacker, victim = "127.0.0.5", "127.0.0.7"
        for i in range(8):
            z.req("ab.test", "/missing%d" % i, src=attacker)
        ban = z.req("ab.test", "/", src=attacker)
        check(ban.status in (403, 429), "attacker not banned after 8x404 (got %d)" % ban.status)
        check(z.req("ab.test", "/", src="127.0.0.6").status == 200, "unrelated client affected")
        lst = z.get("/api/abuse/list")
        check(any(attacker in json.dumps(x) for x in lst.get("Bans") or []), "ban not listed: %s" % json.dumps(lst)[:200])
        # banned client tries to dodge with a forged identity
        dodge = z.req("ab.test", "/", src=attacker, headers={"X-Forwarded-For": "8.8.8.8", "X-Real-Ip": "8.8.8.8", "CF-Connecting-IP": "8.8.8.8"})
        check(dodge.status in (403, 429), "ban evaded with forged client IP headers (%d)" % dodge.status)
        # a third party (127.0.0.6) forges the victim's address while generating 404s
        for i in range(10):
            z.req("ab.test", "/missing-v%d" % i, src="127.0.0.6", headers={"X-Forwarded-For": victim, "X-Real-Ip": victim})
        v = z.req("ab.test", "/", src=victim)
        check(v.status == 200, "victim %s got banned through a spoofed X-Forwarded-For (%d)" % (victim, v.status))
        # unban
        z.api("/api/abuse/unban", ip=attacker)
        check(z.req("ab.test", "/", src=attacker).status == 200, "unban did not restore access")
        return "attacker banned after 5x404 (%d), other client 200, forged XFF did not dodge or ban victim, unban restored access" % ban.status
