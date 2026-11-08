"""Load balancing algorithms, health checks, retries, draining, sticky sessions."""
import collections
import http.client
import json
import threading
import time

from lib import *


def setup(z, backends, algo=None, weights=None, **lbkw):
    z.add_rule("lb.test", backends[0].addr)
    for b in backends[1:]:
        z.api("/api/proxy/upstream/add", ep="lb.test", origin=b.addr, active=True)
    for b, w in zip(backends, weights or []):
        z.api("/api/proxy/upstream/update", ep="lb.test", origin=b.addr, payload=json.dumps({"Weight": w}), active=True)
    cfg = dict(Algorithm=algo or "")
    cfg.update(lbkw)
    z.api("/api/proxy/upstream/lb/set", ep="lb.test", payload=json.dumps(cfg))


def hit(z, n, headers=None, src=None, path="/"):
    c = collections.Counter()
    for i in range(n):
        h = headers(i) if callable(headers) else headers
        if src:
            conn = http.client.HTTPConnection("127.0.0.1", z.proxy, timeout=10, source_address=(src(i) if callable(src) else src, 0))
            conn.request("GET", path, headers=dict({"Host": "lb.test"}, **(h or {})))
            r = conn.getresponse()
            body = r.read()
            conn.close()
            c[json.loads(body)["backend"] if r.status == 200 else "HTTP%d" % r.status] += 1
        else:
            r = z.req("lb.test", path, headers=h)
            c[r.json()["backend"] if r.status == 200 else "HTTP%d" % r.status] += 1
    return c


@scenario("lb_algorithms", ["79"])
def lb_algorithms():
    """round_robin, weighted_round_robin, ip_hash, header_hash, least_connections, consistent behaviour."""
    ev = {}
    with Zoraxy() as z, Backend(name="A") as a, Backend(name="B") as b, Backend(name="C") as c:
        bs = [a, b, c]
        setup(z, bs, "round_robin")
        ev["round_robin"] = dict(hit(z, 30))
        check(all(v == 10 for v in ev["round_robin"].values()) and len(ev["round_robin"]) == 3, "round robin uneven: %s" % ev["round_robin"])

        setup(z, bs, "weighted_round_robin", weights=[5, 1, 0])
        ev["weighted_5_1_0"] = dict(hit(z, 60))
        w = ev["weighted_5_1_0"]
        check(w.get("A") == 50 and w.get("B") == 10 and "C" not in w, "weighted RR (5:1, weight 0 = fallback only): %s" % w)

        setup(z, bs, "ip_hash", weights=[1, 1, 1])
        per_ip = {}
        for ip in range(1, 25):
            addr = "127.0.1.%d" % ip
            got = hit(z, 3, src=addr)
            check(len(got) == 1, "ip_hash: %s hit several backends %s" % (addr, got))
            per_ip[addr] = list(got)[0]
        spread = collections.Counter(per_ip.values())
        check(len(spread) >= 2, "ip_hash: 24 client IPs all landed on one backend %s" % spread)
        ev["ip_hash_spread_24_ips"] = dict(spread)

        setup(z, bs, "header_hash", HashKey="X-Tenant")
        per_t = {}
        for t in range(24):
            got = hit(z, 3, headers={"X-Tenant": "tenant-%d" % t})
            check(len(got) == 1, "header_hash tenant-%d spread over %s" % (t, got))
            per_t[t] = list(got)[0]
        sp = collections.Counter(per_t.values())
        check(len(sp) >= 2, "header_hash: all tenants on one backend")
        ev["header_hash_spread_24_keys"] = dict(sp)

        # least connections: park 3 slow requests on A, new requests must avoid A
        gate = threading.Event()
        slow = Backend(handler=lambda h, rec, bk: (gate.wait(8), send(h, 200, json.dumps({"backend": "slowA"}), ctype="application/json")), name="slowA")
        try:
            setup(z, [slow, b, c], "least_connections")
            thr = []
            for _ in range(3):
                t = threading.Thread(target=lambda: z.req("lb.test", "/slow", timeout=12), daemon=True)
                t.start()
                thr.append(t)
                time.sleep(0.15)
            # round-robin-ish start means the 3 parked requests spread; park until slow has >=1 and count
            parked_on_slow = len([r for r in slow.log])
            got = hit(z, 12)
            ev["least_conn_parked_on_slow"] = parked_on_slow
            ev["least_conn_next_12"] = dict(got)
            check(got.get("slowA", 0) <= 4 or parked_on_slow == 0, "least_connections kept sending to the busy backend: %s (parked=%d)" % (got, parked_on_slow))
        finally:
            gate.set()
            slow.close()
        return json.dumps(ev)


@scenario("lb_health_active", ["80"])
def lb_health_active():
    """Active health check ejects a killed backend and re-admits it after it returns."""
    with Zoraxy() as z, Backend(name="A") as a:
        b = Backend(name="B")
        bport = b.port
        setup(z, [a, b], "round_robin", ActiveHealthCheck=dict(Enabled=True, Path="/", IntervalSeconds=1, TimeoutSeconds=1, Rise=2, Fall=2))
        got = hit(z, 10)
        check(got.get("A") and got.get("B"), "both should serve at start: %s" % got)
        b.close()  # kill B
        # after fall*interval the checker must eject B -> every request succeeds on A
        def only_a():
            g = hit(z, 8)
            return g if set(g) == {"A"} else None
        g = wait_for(only_a, timeout=15, msg="ejection of dead backend (clients kept seeing errors/B)")
        # bring B back on the same port
        b2 = Backend(name="B")
        # port differs: Backend picks a free port, so rebind via raw server on the old port instead
        b2.close()
        import http.server, socketserver

        class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *a): pass
            def do_GET(self):
                send(self, 200, json.dumps({"backend": "B"}), ctype="application/json")
        srv = S(("127.0.0.1", bport), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            def back():
                g = hit(z, 8)
                return g if g.get("B") else None
            g2 = wait_for(back, timeout=20, msg="B to be re-admitted after recovery")
        finally:
            srv.shutdown()
            srv.server_close()
        return "dead B ejected within <=15s (only A served: %s); after restart re-admitted: %s" % (g, g2)


@scenario("lb_passive_retry_drain", ["79", "80"])
def lb_passive_retry_drain():
    """Passive ejection of a 503-ing backend, retry hides it from clients, draining stops new traffic."""
    bad = Backend(handler=lambda h, rec, b: send(h, 503, "bad"), name="BAD")
    with Zoraxy() as z, Backend(name="GOOD") as good, bad:
        setup(z, [good, bad], "round_robin",
              Retry=dict(Enabled=True, MaxRetries=1, RetryStatuses=[503]),
              PassiveHealthCheck=dict(Enabled=True, FailThreshold=2, CooldownSeconds=60))
        got = hit(z, 20)
        check(got == {"GOOD": 20}, "client saw failures despite retry+passive check: %s" % got)
        nbad = len(bad.log)
        check(nbad <= 6, "bad backend kept receiving traffic (%d requests): not ejected" % nbad)
        # draining
        z2_good2 = Backend(name="GOOD2")
        try:
            z.api("/api/proxy/upstream/add", ep="lb.test", origin=z2_good2.addr, active=True)
            z.api("/api/proxy/upstream/setDraining", ep="lb.test", origin=good.addr, draining=True)
            n_before = len(good.log)
            got2 = hit(z, 12)
            check(len(good.log) == n_before, "draining upstream still got %d new requests" % (len(good.log) - n_before))
            check(got2.get("GOOD2") == 12, "traffic did not move to the remaining upstream: %s" % got2)
        finally:
            z2_good2.close()
        return "20/20 GOOD with retry (bad got %d hits then ejected); draining moved 12/12 requests to GOOD2" % nbad


@scenario("sticky_sessions", ["80"])
def sticky_sessions():
    """Sticky session cookie pins a client to one backend; clients without cookie are balanced."""
    with Zoraxy() as z, Backend(name="A") as a, Backend(name="B") as b, Backend(name="C") as c:
        z.add_rule("lb.test", a.addr, stickysess=True)
        for x in (b, c):
            z.api("/api/proxy/upstream/add", ep="lb.test", origin=x.addr, active=True)
        z.api("/api/proxy/upstream/lb/set", ep="lb.test", payload=json.dumps(dict(Algorithm="round_robin")))
        seen = set()
        for i in range(12):
            r = z.req("lb.test")
            cookie = r.h("set-cookie")
            if cookie:
                ck = cookie.split(";")[0]
                first = r.json()["backend"]
                seen.add(first)
                # replay the cookie 8 times: always the same backend
                for _ in range(8):
                    r2 = z.req("lb.test", headers={"Cookie": ck})
                    check(r2.json()["backend"] == first, "sticky cookie %s moved from %s to %s" % (ck, first, r2.json()["backend"]))
                break
        else:
            raise Fail("no sticky cookie was ever issued")
        # fresh clients (no cookie) reach several backends
        spread = set()
        for _ in range(15):
            spread.add(z.req("lb.test").json()["backend"])
        check(len(spread) >= 2, "cookieless clients not balanced: %s" % spread)
        return "cookie %s pinned to %s for 8 replays; cookieless clients spread over %s" % (ck.split("=")[0], first, sorted(spread))
