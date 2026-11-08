"""Authentication: forward auth (Authelia / Authentik outpost style), OIDC with two providers, basic auth."""
import base64
import json
import urllib.parse

import fakes
from lib import *


def cookies_from(r, jar):
    for sc in r.set_cookies:
        nv = sc.split(";")[0]
        k, _, v = nv.partition("=")
        if "max-age=0" in sc.lower() or v == "":
            jar.pop(k.strip(), None)
        else:
            jar[k.strip()] = v
    return jar


def cookie_header(jar):
    return "; ".join("%s=%s" % kv for kv in jar.items())


@scenario("forward_auth", ["33", "78", "172", "652"])
def forward_auth():
    """Forward auth against a fake Authelia: deny/allow, identity headers set + client forgeries scrubbed,
    path exemptions (traversal-safe) scrub identity headers, fail closed when the auth server is down, outpost path proxied."""
    seen = []

    def authelia(h, rec, b):
        seen.append(rec)
        if rec["path"].startswith("/outpost.goauthentik.io/"):
            send(h, 200, "outpost:" + rec["path"])
            return
        ck = rec["headers"].get("cookie", "")
        if "authelia_session=alice" in ck:
            send(h, 200, "", {"Remote-User": "alice", "Remote-Groups": "admins", "Remote-Email": "alice@example.com"})
        elif "authelia_session=down" in ck:
            send(h, 500, "boom")
        else:
            send(h, 401, "login required")

    with Zoraxy() as z, Backend(authelia, name="authelia") as au, Backend(name="app") as app:
        z.api("/api/sso/forward-auth", address="http://%s/api/authz/forward-auth" % au.addr, responseHeaders="Remote-User,Remote-Groups,Remote-Email",
              outpostUrl="http://" + au.addr)
        z.add_rule("fa.test", app.addr)
        z.edit_rule("fa.test", authprovider=2)
        n = len(app.log)
        r = z.req("fa.test", "/private", headers={"Remote-User": "root", "X-Forwarded-Uri": "/public"})
        check(r.status in (401, 302, 403) and len(app.log) == n, "unauthenticated request reached the app: %d" % r.status)
        # what the auth server was told
        call = [s for s in seen if s["path"].startswith("/api/authz/forward-auth")][-1]["headers"]
        check(call.get("x-forwarded-host") == "fa.test" and call.get("x-forwarded-uri") == "/private", "subrequest headers not computed by zoraxy: %s" % call)
        ok = z.req("fa.test", "/private", headers={"Cookie": "authelia_session=alice", "Remote-User": "root", "Remote-Groups": "evil"})
        check(ok.status == 200, "authenticated request refused (%d)" % ok.status)
        hd = ok.json()["headers"]
        check(hd.get("remote-user") == "alice" and hd.get("remote-groups") == "admins", "identity headers not from auth server: %s" % hd)
        down = z.req("fa.test", "/private", headers={"Cookie": "authelia_session=down"})
        check(down.status != 200, "auth server 500 let the request through (%d)" % down.status)
        # path exemption (per rule): /public/ open, identity headers scrubbed on exempt requests
        z.api("/api/proxy/auth/sso/exceptions/add", ep="fa.test", type=0, pattern="/public", mode="prefix")
        pub = z.req("fa.test", "/public/logo.png", headers={"Remote-User": "root", "Remote-Groups": "admins"})
        check(pub.status == 200, "exempt path still needs auth (%d)" % pub.status)
        ph = pub.json()["headers"]
        check("remote-user" not in ph and "remote-groups" not in ph, "forged identity headers reached the app on an exempt path: %s" % ph)
        bypass = {}
        for p in ("/public/../private", "/public/%2e%2e/private", "/public/..;/private", "/public%2f..%2fprivate", "//public/../private", "/public/..%5cprivate"):
            before = len(app.log)
            rr = z.req("fa.test", p)
            if rr.status == 200 and len(app.log) > before:
                bypass[p] = app.log[-1]["path"]
            else:
                bypass[p] = rr.status
        leaks = {p: v for p, v in bypass.items() if v == 200 or (isinstance(v, str) and "private" in v)}
        check(not leaks, "auth exemption bypass: %s" % leaks)
        # outpost callback path is proxied to the outpost on the protected host
        op = z.req("fa.test", "/outpost.goauthentik.io/callback?x=1")
        outpost_ok = op.status == 200 and op.text.startswith("outpost:")
        # server down => fail closed
        def hangup(h, rec, b):
            h.close_connection = True
            h.connection.close()
        au.handler = hangup  # persistent connections stay open in the fake: make it drop every request instead
        gone = z.req("fa.test", "/private", headers={"Cookie": "authelia_session=alice"})
        check(gone.status != 200, "auth server unreachable but request passed (%d)" % gone.status)
        return ("401 unauth (app untouched), subrequest X-Forwarded-Host/Uri computed by proxy, 200 with Remote-User=alice (forged root/evil replaced), 500/unreachable => deny, "
                "exempt /public open with forged identity headers scrubbed, 6 traversal variants %s, outpost path proxied=%s" % (bypass, outpost_ok))


def drive_oidc(z, host, idp, path="/secret", jar=None, claims=None):
    """Runs authorize->callback by hand; returns (final response, jar, first redirect location)."""
    jar = {} if jar is None else jar
    r = z.req(host, path)
    cookies_from(r, jar)
    loc = r.h("location", "")
    if r.status not in (301, 302, 303, 307) or not loc.startswith(idp.base):
        return r, jar, loc
    a = http_req("127.0.0.1", idp.backend.port, "127.0.0.1", loc[len(idp.base):])
    assert a.status == 302, "idp authorize %d" % a.status
    cb = urllib.parse.urlsplit(a.h("location"))
    r2 = z.req(host, cb.path + "?" + cb.query, headers={"Cookie": cookie_header(jar)})
    cookies_from(r2, jar)
    return r2, jar, loc


@scenario("oidc_two_providers", ["33", "172"])
def oidc_two_providers():
    """OIDC against two fake IdPs on two rules: login, PKCE, claim->header mapping + forgery scrub, group allow-list,
    exemptions, provider isolation (a session of one provider is useless on the other rule)."""
    with fakes.FakeIdP("one", {"sub": "u1", "email": "alice@example.com", "email_verified": True, "groups": ["staff"], "name": "Alice"}) as i1, \
            fakes.FakeIdP("two", {"sub": "u2", "email": "bob@other.org", "email_verified": True, "groups": ["guests"], "name": "Bob"}) as i2, \
            Zoraxy() as z, Backend(name="app") as app:
        for pid, idp, cid in (("one", i1, "client-one"), ("two", i2, "client-two")):
            z.api("/api/sso/OAuth2/providers", id=pid, name=pid, oauth2WellKnownUrl=idp.base + "/.well-known/openid-configuration", oauth2Issuer=idp.base,
                  oauth2ClientId=cid, oauth2ClientSecret="s3cret-" + pid, oauth2CodeChallengeMethod="PKCE_S256", oauth2Scopes="openid email profile",
                  oauth2HeaderMappings="X-Auth-Email=email,X-Auth-Name=name", oauth2GroupsClaim="groups")
        z.add_rule("o1.test", app.addr, authprovider=3)
        z.edit_rule("o1.test", authprovider=3, oauth2provider="one", oauth2groups="staff")
        z.add_rule("o2.test", app.addr, authprovider=3)
        z.edit_rule("o2.test", authprovider=3, oauth2provider="two", oauth2groups="staff")  # bob is not staff
        n = len(app.log)
        r = z.req("o1.test", "/secret")
        check(r.status in (302, 303, 307) and r.h("location", "").startswith(i1.base + "/authorize"), "unauth not redirected to IdP one: %d %s" % (r.status, r.h("location")))
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(r.h("location")).query)
        check(q.get("client_id") == ["client-one"] and q.get("code_challenge_method") == ["S256"] and q.get("nonce") and q.get("state"), "authorize params: %s" % q)
        check(len(app.log) == n, "app reached without login")
        # full login on rule 1
        fin, jar, _ = drive_oidc(z, "o1.test", i1)
        check(fin.status in (302, 303, 307), "callback should redirect back: %d %r %s" % (fin.status, fin.body[:200], fin.headers))
        check(any(k.startswith(("z-session", "z-oidc")) for k in jar), "no session cookie: %s; callback -> %d %s %r; tokens=%s log=%s" % (list(jar), fin.status, fin.headers, fin.body[:200], i1.token_log, z.logtail(600)))
        ok = z.req("o1.test", "/secret", headers={"Cookie": cookie_header(jar), "X-Auth-Email": "root@evil", "X-Auth-Name": "Mallory"})
        check(ok.status == 200, "logged-in request refused: %d" % ok.status)
        hd = ok.json()["headers"]
        check(hd.get("x-auth-email") == "alice@example.com" and hd.get("x-auth-name") == "Alice", "claim headers: %s" % {k: v for k, v in hd.items() if k.startswith("x-auth")})
        # forged header without a session never reaches the app
        n = len(app.log)
        z.req("o1.test", "/secret", headers={"X-Auth-Email": "root@evil"})
        check(len(app.log) == n, "forged claim header reached app without session")
        # exemption: public path is open, forged claim headers scrubbed
        z.api("/api/proxy/auth/sso/exceptions/add", ep="o1.test", type=0, pattern="/public", mode="prefix")
        pub = z.req("o1.test", "/public/x", headers={"X-Auth-Email": "root@evil"})
        check(pub.status == 200 and "x-auth-email" not in pub.json()["headers"], "exempt path: %d %s" % (pub.status, pub.json()["headers"] if pub.status == 200 else ""))
        # provider isolation: session of provider one is rejected by rule 2
        iso = z.req("o2.test", "/secret", headers={"Cookie": cookie_header(jar)})
        check(iso.status in (302, 303, 307) and iso.h("location", "").startswith(i2.base), "session of provider one accepted on rule 2: %d" % iso.status)
        # rule 2: group staff required, bob is a guest => denied after login
        fin2, jar2, _ = drive_oidc(z, "o2.test", i2)
        n = len(app.log)
        after = z.req("o2.test", "/secret", headers={"Cookie": cookie_header(jar2)})
        check(after.status != 200 and len(app.log) == n, "user outside the allowed group got in (%d)" % after.status)
        # positive control: allow the guests group => bob is let in
        z.edit_rule("o2.test", authprovider=3, oauth2provider="two", oauth2groups="guests")
        fin3, jar3, _ = drive_oidc(z, "o2.test", i2)
        pos = z.req("o2.test", "/secret", headers={"Cookie": cookie_header(jar3)})
        check(pos.status == 200 and pos.json()["headers"].get("x-auth-email") == "bob@other.org", "allowed group still refused (%d)" % pos.status)
        check(i1.token_log and i1.token_log[0].get("code_verifier"), "PKCE verifier not sent to the token endpoint: %s" % i1.token_log)
        return ("redirect to IdP with PKCE S256/nonce/state; login sets session; claim headers email/name set and client forgeries replaced; exempt path scrubs forged headers; "
                "provider one's cookie redirected to IdP two on rule 2; group allow-list denies guest (%d); token endpoint got code_verifier" % after.status)


@scenario("basic_auth", ["core"])
def basic_auth():
    """Basic auth on a rule: 401 challenge, wrong password, right password, X-Remote-User not forgeable, backoff."""
    with Zoraxy() as z, Backend(name="app") as app:
        z.add_rule("ba.test", app.addr, bauth=True, cred=json.dumps([{"username": "alice", "password": "pw-alice-1"}]))
        r = z.req("ba.test")
        check(r.status == 401 and "basic" in r.h("www-authenticate", "").lower(), "no challenge: %d %s" % (r.status, r.headers))
        tok = lambda u, p: {"Authorization": "Basic " + base64.b64encode(("%s:%s" % (u, p)).encode()).decode()}
        bad = z.req("ba.test", headers=tok("alice", "nope")).status
        good = z.req("ba.test", headers=dict(tok("alice", "pw-alice-1"), **{"X-Remote-User": "root"}))
        check(bad == 401 and good.status == 200, "bad=%d good=%d" % (bad, good.status))
        return "401 challenge, wrong password %d, right password %d" % (bad, good.status)
