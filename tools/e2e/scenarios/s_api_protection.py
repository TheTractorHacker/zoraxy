"""API protection (waf/apiguard*.go): structural limits, allow-list, OpenAPI, log vs block, byte-identical replay."""
import hashlib
import json

from lib import *

SPEC = """openapi: 3.0.0
info: {title: E2E, version: "1"}
paths:
  /items:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties: {name: {type: string}}
      responses: {"201": {description: created}}
    get:
      responses: {"200": {description: ok}}
"""
JSON = {"Content-Type": "application/json"}


def nested(n):
    return b"[" * n + b"]" * n


@scenario("api_protection_log_and_block", ["82"])
def api_protection_log_and_block():
    """Through the real proxy path: limits, allow-list and OpenAPI in log mode (events only) and block mode
    (400/405/413 + WAF block accounting), allowed bodies reach the upstream byte for byte (also chunked)."""
    with Zoraxy() as z, Backend(name="app") as b:
        z.add_rule("api.test", b.addr)
        deep, ok = nested(40), json.dumps({"name": "x", "pad": "y" * 5000}).encode()

        def cfg(mode, **extra):
            c = {"Mode": mode, "AllowList": [{"Path": "/items", "Methods": ["GET", "POST"], "ContentTypes": ["application/json"]}],
                 "OpenAPI": {"Spec": SPEC}}
            c.update(extra)
            z.api("/api/waf/api/set", scope="endpoint", name="api.test", config=json.dumps(c))

        # ---- log mode: everything passes, events are recorded
        cfg("log")
        n = len(b.log)
        codes = [z.req("api.test", "/items", "POST", JSON, deep).status,
                 z.req("api.test", "/items", "DELETE").status,
                 z.req("api.test", "/other").status,
                 z.req("api.test", "/items", "POST", JSON, b'{"nope":1}').status]
        check(codes == [200] * 4, "log mode must not block: %s" % codes)
        check(len(b.log) - n == 4, "backend saw %d of 4 requests" % (len(b.log) - n))
        ev = [e for e in z.get("/api/waf/events", limit=50, kind="api")]
        viol = sorted({e["violation"] for e in ev})
        check(all(e["action"] == "detected" and e["kind"] == "api" for e in ev), "log events must be 'detected': %s" % ev[:1])
        check("json.depth" in viol and "allow.method" in viol and "openapi.path" in viol and "openapi.body" in viol, "violations: %s" % viol)
        st = z.get("/api/waf/stats")
        check(st["api"] >= 4 and st["api_blocked"] == 0, "stats %s" % {k: st[k] for k in ("api", "api_blocked")})

        # ---- block mode
        cfg("block")
        n = len(b.log)
        r1 = z.req("api.test", "/items", "POST", JSON, deep)
        r2 = z.req("api.test", "/items", "DELETE")
        r3 = z.req("api.test", "/other")
        r4 = z.req("api.test", "/items", "POST", JSON, b'{"nope":1}')
        r5 = z.req("api.test", "/items", "POST", {"Content-Type": "text/plain"}, b"hi")
        check([r1.status, r2.status, r3.status, r4.status, r5.status] == [400, 405, 404, 400, 415],
              "block statuses: %s" % [r.status for r in (r1, r2, r3, r4, r5)])
        check(len(b.log) == n, "blocked requests reached the upstream")
        check(b"[[[[" not in r1.body and r1.h("x-request-id"), "block response must be generic and carry a request id")
        # allowed, byte-identical, plain and chunked
        for chunked in (False, True):
            n = len(b.log)
            r = z.req("api.test", "/items", "POST", JSON, ok, chunked=chunked)
            check(r.status == 200 and len(b.log) == n + 1, "valid request failed (chunked=%s): %s" % (chunked, r))
            got = b.log[-1]["body"]
            check(hashlib.sha256(got).digest() == hashlib.sha256(ok).digest(), "upstream body differs (chunked=%s)" % chunked)
        ev = z.get("/api/waf/events", limit=100, kind="api", action="blocked")
        check(len(ev) >= 5, "blocked events: %d" % len(ev))
        check(not [e for e in z.get("/api/waf/events", limit=100, kind="waf")], "kind=waf must not return API events")
        cov = z.get("/api/waf/coverage")
        check(any(c.get("APIMode") == "block" for c in cov), "coverage lacks the API mode: %s" % cov)

        # ---- limits without a spec, then oversize + XXE
        z.api("/api/waf/api/set", scope="endpoint", name="api.test",
              config=json.dumps({"Mode": "block", "Limits": {"MaxBodyBytes": 2048, "JSONMaxKeys": 3}}))
        check(z.req("api.test", "/x", "POST", JSON, b"x" * 5000).status == 413, "oversize body not rejected with 413")
        check(z.req("api.test", "/x", "POST", JSON, b'{"a":1,"b":2,"c":3,"d":4}').status == 400, "key limit")
        xxe = b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>'
        check(z.req("api.test", "/x", "POST", {"Content-Type": "application/xml"}, xxe).status == 400, "XXE not rejected")
        check(z.req("api.test", "/x", "POST", {"Content-Type": "application/xml"}, b"<a><b/></a>").status == 200, "plain XML rejected")
        check(z.req("api.test", "/" + "a" * 9000).status == 414, "long URL not rejected with 414")

        # ---- invalid config is refused, a bad spec cannot be saved
        try:
            z.api("/api/waf/api/set", scope="endpoint", name="api.test", config=json.dumps({"Mode": "block", "OpenAPI": {"Spec": "nonsense"}}))
            check(False, "bad spec accepted")
        except Fail as e:
            check("OpenAPI" in str(e), "unclear error for a bad spec: %s" % e)
        # ---- turned off again
        z.api("/api/waf/api/set", scope="endpoint", name="api.test", config="")
        check(z.req("api.test", "/items", "POST", JSON, deep).status == 200, "still blocking after clearing")
        return "log: 4/4 passed with %d events (%s); block: 400/405/404/400/415, upstream untouched, valid bodies byte-identical (plain+chunked); 413/414/XXE ok" % (len(ev), ",".join(viol))
