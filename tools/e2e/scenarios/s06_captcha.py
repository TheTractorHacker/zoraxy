"""CAPTCHA: challenge page, branding, session cookies, exemptions, Altcha PoW, provider siteverify (fake HTTPS)."""
import base64
import hashlib
import json
import re
import urllib.parse

from lib import *

SECRET = "e2e-altcha-secret-0123456789abcdef0123456789"
ALTCHA = dict(captcha=True, captchaProvider=2, captchaSecretKey=SECRET, captchaSessionDuration=600)


def solve_altcha(z, host, tamper=False):
    r = z.req(host, "/.zoraxy/captcha/altcha")
    check(r.status == 200, "altcha challenge endpoint: %d %r" % (r.status, r.body[:100]))
    ch = r.json()
    n = None
    for i in range(ch["maxnumber"] + 1):
        if hashlib.sha256((ch["salt"] + str(i)).encode()).hexdigest() == ch["challenge"]:
            n = i
            break
    check(n is not None, "no solution within maxnumber")
    if tamper:
        n = (n + 1) % (ch["maxnumber"] + 1)
    payload = dict(algorithm=ch["algorithm"], challenge=ch["challenge"], number=n, salt=ch["salt"], signature=ch["signature"])
    return base64.b64encode(json.dumps(payload).encode()).decode()


def verify(z, host, field, token, headers=None):
    h = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    h.update(headers or {})
    return z.req(host, "/.zoraxy/captcha/verify", "POST", h, urllib.parse.urlencode({field: token}).encode())


def cookie_of(r):
    sc = " ".join(r.set_cookies)
    m = re.search(r"zoraxy_captcha_session=([^;]+)", sc)
    return ("zoraxy_captcha_session=" + m.group(1)) if m else None


@scenario("captcha_altcha_flow", ["77", "222"])
def captcha_altcha_flow():
    """Challenge page 403 (branded) -> Altcha PoW solved -> session cookie -> upstream; replay/tamper/foreign-host refused."""
    with Zoraxy() as z, Backend(name="site") as b, Backend(name="other") as b2:
        brand = dict(captchaTitle="Acme Gatekeeper", captchaHeading="Hold on, {domain}", captchaMessage="Prove you are not a robot.",
                     captchaAccent="#ff6600", captchaTheme="dark")
        z.add_rule("cap.test", b.addr, **ALTCHA, **brand)
        z.add_rule("cap2.test", b2.addr, **ALTCHA)
        r = z.req("cap.test", "/page", headers={"Accept": "text/html"})
        check(r.status == 403, "challenge status %d" % r.status)
        check(len(b.log) == 0, "backend reached without session")
        for needle in ("Acme Gatekeeper", "Hold on, cap.test", "Prove you are not a robot.", "#ff6600"):
            check(needle in r.text, "branding %r missing from challenge page" % needle)
        check(r.h("x-zoraxy-captcha-reason") == "no-cookie", "reason header: %s" % r.h("x-zoraxy-captcha-reason"))
        check("nonce-" in r.h("content-security-policy", ""), "CSP nonce missing: %s" % r.h("content-security-policy"))
        # wrong / tampered solutions
        bad = verify(z, "cap.test", "altcha", solve_altcha(z, "cap.test", tamper=True))
        check(bad.status == 401 and cookie_of(bad) is None, "tampered PoW accepted: %d %r" % (bad.status, bad.body[:100]))
        check(verify(z, "cap.test", "altcha", "garbage").status in (400, 401), "garbage accepted")
        # good solution
        tok = solve_altcha(z, "cap.test")
        ok = verify(z, "cap.test", "altcha", tok)
        check(ok.status == 200 and ok.json().get("success") is True, "good PoW refused: %d %r" % (ok.status, ok.body[:100]))
        ck = cookie_of(ok)
        check(ck, "no session cookie issued")
        sc = " ".join(ok.set_cookies)
        check("HttpOnly" in sc, "session cookie not HttpOnly: " + sc)
        # replay of the solved challenge
        rep = verify(z, "cap.test", "altcha", tok)
        check(rep.status == 401, "replayed PoW accepted (%d)" % rep.status)
        # cookie accepted
        r = z.req("cap.test", "/page", headers={"Cookie": ck})
        check(r.status == 200 and r.json()["backend"] == "site", "valid session not accepted: %d" % r.status)
        # tampered cookie
        flipped = ck[:-3] + ("AAA" if not ck.endswith("AAA") else "BBB")
        r = z.req("cap.test", "/page", headers={"Cookie": flipped})
        check(r.status == 403 and r.h("x-zoraxy-captcha-reason") == "invalid", "tampered cookie: %d %s" % (r.status, r.h("x-zoraxy-captcha-reason")))
        # cookie of cap.test is not valid for cap2.test
        r = z.req("cap2.test", "/", headers={"Cookie": ck})
        check(r.status == 403 and r.h("x-zoraxy-captcha-reason") == "wrong-host", "cross-host cookie: %d %s" % (r.status, r.h("x-zoraxy-captcha-reason")))
        # session survives a restart (stateless HMAC cookie)
        z.restart()
        r = z.req("cap.test", "/page", headers={"Cookie": ck})
        check(r.status == 200, "session cookie not valid after restart (%d, %s)" % (r.status, r.h("x-zoraxy-captcha-reason")))
        # min duration clamp: 30 seconds configured -> effective >= 60
        return "challenge 403 branded(title/heading/message/accent) with CSP nonce; bad/tampered/replayed PoW 401; good PoW -> HttpOnly cookie -> 200; flipped cookie=invalid; foreign host=wrong-host; cookie survives restart"


@scenario("captcha_exemptions", ["228"])
def captcha_exemptions():
    """Protected path prefixes and exemption rules (path prefix / exact / regex / CIDR), traversal and XFF spoofing."""
    with Zoraxy() as z, Backend(name="site") as b:
        z.add_rule("ex.test", b.addr, **ALTCHA, captchaPathPrefixes="/private")
        def st(p, **kw):
            return z.req("ex.test", p, **kw).status
        check(st("/public") == 200, "unprotected path challenged")
        check(st("/private/area") == 403, "protected path not challenged")
        check(st("/private") == 403, "protected path exact not challenged")
        bypass = {}
        for p in ("/public/../private/x", "//private/x", "/%70rivate/x", "/private/../private/x", "/public/%2e%2e/private/x",
                  "/Private/x", "/private%2fx", "/./private/x", "/private;a=b/x"):
            bypass[p] = st(p)
        # Anything answered 200 *and reaching a backend path that is under /private* is a bypass
        leaked = {}
        for p, code in bypass.items():
            if code == 200:
                leaked[p] = b.log[-1]["path"]
        # a 200 whose backend path is NOT a private resource is fine (e.g. /Private/x is a different path on a case sensitive upstream)
        real_leaks = {p: bp for p, bp in leaked.items() if bp.lower().replace("%70", "p").lstrip("/").startswith("private") and p not in ("/Private/x",)}
        check(not real_leaks, "CAPTCHA bypass via path tricks: %s" % real_leaks)
        # now protect everything and add exemptions
        z.edit_rule("ex.test", captcha=True, captchaProvider=2, captchaSecretKey=SECRET, captchaPathPrefixes="")
        check(st("/anything") == 403, "protect-all not effective")
        for typ, val, mode in ((0, "/healthz", ""), (0, "/exact", "exact"), (0, r"^/api/v[0-9]+/status$", "regex")):
            z.api("/api/proxy/captcha/exceptions/add", ep="ex.test", type=typ, value=val, mode=mode)
        check(st("/healthz/deep") == 200, "prefix exemption not applied")
        check(st("/exact") == 200 and st("/exact/x") == 403, "exact exemption wrong (/exact=%d /exact/x=%d)" % (st("/exact"), st("/exact/x")))
        check(st("/api/v2/status") == 200 and st("/api/v2/status/x") == 403 and st("/api/vx/status") == 403, "regex exemption wrong")
        check(st("/healthz/../secret") == 403, "exemption bypassed with dot-dot")
        # CIDR exemption: our peer is 127.0.0.1 -> exempt everything; spoofed header from 127.0.0.9 does not help another range
        z.api("/api/proxy/captcha/exceptions/add", ep="ex.test", type=1, value="10.1.2.0/24")
        check(st("/secret", headers={"X-Forwarded-For": "10.1.2.3", "X-Real-Ip": "10.1.2.3"}) == 403, "spoofed XFF/X-Real-IP satisfied a CIDR exemption")
        z.api("/api/proxy/captcha/exceptions/add", ep="ex.test", type=1, value="127.0.0.1/32")
        check(st("/secret") == 200, "CIDR exemption for the real peer not applied")
        lst = z.get("/api/proxy/captcha/exceptions/list", ep="ex.test")
        return "protect /private only; 9 traversal/encoding variants: %s; exemptions prefix/exact/regex/CIDR ok; spoofed XFF ignored; %d rules listed" % (
            sorted(set(bypass.values())), len(lst) if hasattr(lst, "__len__") else -1)


def _providers(tmpd):
    def handler(host, path, hdrs, body):
        form = urllib.parse.parse_qs(body.decode()) if "json" not in hdrs.get("content-type", "") else {}
        if host.endswith("cloudflare.com"):
            tok = form.get("response", [""])[0]
            if tok == "good":
                return 200, {"success": True, "hostname": "tp.test", "action": "login", "cdata": "xyz"}
            if tok == "goodhost":
                return 200, {"success": True, "hostname": "ts.test"}
            if tok == "wronghost":
                return 200, {"success": True, "hostname": "evil.example"}
            return 200, {"success": False, "error-codes": ["invalid-input-response"]}
        if host.endswith("google.com"):
            tok = form.get("response", [""])[0]
            if tok == "good":
                return 200, {"success": True, "hostname": "tp.test", "score": 0.9, "action": "access"}
            if tok == "low":
                return 200, {"success": True, "hostname": "tp.test", "score": 0.1, "action": "access"}
            return 200, {"success": False, "error-codes": ["invalid-input-response"]}
        if host.endswith("frcapi.com"):
            j = json.loads(body.decode())
            if j.get("response") == "good" and hdrs.get("x-api-key") == "FRCSECRET":
                return 200, {"success": True, "data": {"challenge": {"origin": "https://tp.test"}}}
            return 200, {"success": False, "error": {"error_code": "response_invalid"}}
        return 404, {}
    return handler


@scenario("captcha_third_party_providers", ["222", "77"])
def captcha_third_party_providers():
    """Turnstile / reCAPTCHA v2+v3 / Friendly Captcha server-side verification, against a fake siteverify
    (real binary, HTTPS_PROXY + SSL_CERT_FILE redirect the provider hosts to a local TLS fake)."""
    d = tempfile.mkdtemp(prefix="zx-prov-")
    try:
        with FakeHTTPS(["challenges.cloudflare.com", "www.google.com", "global.frcapi.com", "eu.frcapi.com"], _providers(d), d) as fake:
            with Zoraxy(env=fake.env) as z, Backend(name="site") as b:
                ev = []
                cases = [
                    ("ts.test", dict(captcha=True, captchaProvider=0, captchaSiteKey="1x00000000000000000000AA", captchaSecretKey="tsecret"), "cf-turnstile-response"),
                    ("rc2.test", dict(captcha=True, captchaProvider=1, captchaSiteKey="rk", captchaSecretKey="rsecret", captchaRecaptchaVersion="v2"), "g-recaptcha-response"),
                    ("rc3.test", dict(captcha=True, captchaProvider=1, captchaSiteKey="rk", captchaSecretKey="rsecret", captchaRecaptchaVersion="v3", captchaRecaptchaScore="0.5"), "g-recaptcha-response"),
                    ("fr.test", dict(captcha=True, captchaProvider=3, captchaSiteKey="FC_SITE", captchaSecretKey="FRCSECRET"), "frc-captcha-response"),
                ]
                for host, kw, field in cases:
                    z.add_rule(host, b.addr, **kw)
                    page = z.req(host, "/", headers={"Accept": "text/html"})
                    check(page.status == 403 and (kw.get("captchaSiteKey", "") in page.text), "%s challenge page: %d" % (host, page.status))
                    bad = verify(z, host, field, "nope")
                    check(bad.status == 401 and not cookie_of(bad), "%s: bad token accepted (%d)" % (host, bad.status))
                    good = verify(z, host, field, "good")
                    if host == "fr.test":
                        pass
                    check(good.status == 200 and cookie_of(good), "%s: good token refused (%d %r) fake calls=%s log=%s" % (
                        host, good.status, good.body[:120], fake.calls[-2:], z.logtail(400)))
                    r = z.req(host, "/x", headers={"Cookie": cookie_of(good)})
                    check(r.status == 200 and r.json()["backend"] == "site", "%s: session not honoured" % host)
                    ev.append(host)
                # reCAPTCHA v3 low score refused
                low = verify(z, "rc3.test", "g-recaptcha-response", "low")
                check(low.status == 401, "v3 low score accepted (%d)" % low.status)
                # hostname verification
                z.edit_rule("ts.test", captcha=True, captchaProvider=0, captchaSiteKey="1x00000000000000000000AA", captchaSecretKey="tsecret", captchaVerifyHostname=True)
                wh = verify(z, "ts.test", "cf-turnstile-response", "wronghost")
                check(wh.status == 401, "hostname mismatch accepted with VerifyHostname (%d)" % wh.status)
                gd = verify(z, "ts.test", "cf-turnstile-response", "goodhost")
                check(gd.status == 200, "good token refused with VerifyHostname (%d %r)" % (gd.status, gd.body[:100]))
                hosts_called = sorted({c[0] for c in fake.calls})
                return "verified %s via fake siteverify (hosts contacted %s); low reCAPTCHA v3 score and wrong hostname refused" % (ev, hosts_called)
    finally:
        shutil.rmtree(d, ignore_errors=True)
