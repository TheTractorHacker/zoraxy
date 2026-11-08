"""Client IP handling (trusted proxies, forwarded headers, PROXY protocol), access rules, bulk import, GeoIP."""
import json
import socket
import struct

from lib import *


def client_seen(r):
    """IP the upstream was told (X-Real-Ip / first X-Forwarded-For)."""
    h = r.json()["headers"]
    return h.get("x-real-ip"), h.get("x-forwarded-for")


@scenario("client_ip_trust_and_spoofing", ["934", "1359"])
def client_ip_trust_and_spoofing():
    """Forwarded headers from untrusted peers are ignored for access control and (optionally) sanitised towards the
    upstream; a trusted proxy's CF-Connecting-IP / X-Forwarded-For is honoured."""
    with Zoraxy() as z, Backend(name="ip") as b:
        z.add_rule("ip.test", b.addr)
        z.api("/api/blacklist/ip/add", ip="9.9.9.9", id="default", comment="e2e")
        z.api("/api/blacklist/enable", enable=True, id="default")
        spoof = {"X-Forwarded-For": "9.9.9.9", "CF-Connecting-IP": "9.9.9.9", "X-Real-Ip": "9.9.9.9", "True-Client-IP": "9.9.9.9"}
        r = z.req("ip.test", headers=spoof)
        tp = z.get("/api/trustedproxy/list")
        # 1. loopback peer: is it trusted by default? Either way a spoofed blacklisted address must not matter unless trusted+enabled
        listed = json.dumps(tp)
        z.api("/api/blacklist/ip/add", ip="127.0.0.3", id="default", comment="direct peer")
        direct = z.req("ip.test", src="127.0.0.3")
        check(direct.status == 403, "blacklisted direct peer served (%d)" % direct.status)
        if "127.0.0.1" not in listed and "127.0.0.0" not in listed:
            check(r.status == 200, "untrusted peer's forged headers triggered the blacklist (%d)" % r.status)
        # 2. upstream header sanitising
        z.edit_rule("ip.test", sanitiseClientIP=True)
        r2 = z.req("ip.test", src="127.0.0.4", headers={"X-Forwarded-For": "6.6.6.6", "CF-Connecting-IP": "6.6.6.6", "True-Client-IP": "6.6.6.6", "X-Real-Ip": "6.6.6.6"})
        h = r2.json()["headers"]
        check(r2.status == 200, "request refused (%d)" % r2.status)
        check("6.6.6.6" not in json.dumps(h), "forged client IP headers reached the upstream with sanitise on: %s" % h)
        check("127.0.0.4" in (h.get("x-real-ip", "") + h.get("x-forwarded-for", "")), "real peer missing from rebuilt headers: %s" % h)
        z.edit_rule("ip.test", sanitiseClientIP=False)
        r3 = z.req("ip.test", src="127.0.0.4", headers={"X-Forwarded-For": "6.6.6.6"})
        # 3. trusted proxy honoured: trust 127.0.0.8 and enable header trust on the default rule
        z.api("/api/trustedproxy/add", ip="127.0.0.8", desc="e2e lb")
        z.api("/api/whitelist/trustProxy", enable=True, id="default")
        t = z.req("ip.test", src="127.0.0.8", headers={"CF-Connecting-IP": "9.9.9.9"})
        check(t.status == 403, "trusted proxy's CF-Connecting-IP (blacklisted) not honoured (%d)" % t.status)
        t2 = z.req("ip.test", src="127.0.0.8", headers={"X-Forwarded-For": "9.9.9.9, 10.0.0.1"})
        check(t2.status == 403, "trusted proxy's X-Forwarded-For not honoured (%d)" % t2.status)
        u = z.req("ip.test", src="127.0.0.4", headers={"CF-Connecting-IP": "9.9.9.9", "X-Forwarded-For": "9.9.9.9"})
        check(u.status == 200, "UNtrusted peer's forged header still honoured after trust enabled (%d)" % u.status)
        # observation: precedence when both X-Real-Ip and CF-Connecting-IP arrive from a trusted peer
        prec = z.req("ip.test", src="127.0.0.8", headers={"X-Real-Ip": "1.1.1.1", "CF-Connecting-IP": "9.9.9.9"})
        return ("untrusted forged headers ignored (%d); direct blacklisted peer 403; sanitise drops forged headers (upstream saw %s); trusted proxy CF-Connecting-IP/XFF honoured (403), "
                "untrusted peer still ignored; precedence X-Real-Ip>CF-Connecting-IP => %d" % (r.status, {k: h.get(k) for k in ("x-real-ip", "x-forwarded-for")}, prec.status))


def proxy_v2(src, dst, sport, dport):
    sig = b"\r\n\r\n\x00\r\nQUIT\n"
    return sig + bytes([0x21, 0x11]) + struct.pack(">H", 12) + socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack(">HH", sport, dport)


@scenario("proxy_protocol", ["934"])
def proxy_protocol():
    """PROXY v1/v2 on the TLS listener gives the announced client address (blacklist applies to it)."""
    d = tempfile.mkdtemp(prefix="zx-pp-")
    try:
        ca = make_ca(d)
        crt = make_leaf(d, "pp.test", ca)
        with Zoraxy(tls=True, certs=[("pp.test", crt[0], crt[1])]) as z, Backend(name="pp") as b:
            z.add_rule("pp.test", b.addr)
            z.api("/api/blacklist/ip/add", ip="198.51.100.7", id="default", comment="e2e")
            z.api("/api/blacklist/enable", enable=True, id="default")
            z.get("/api/proxy/proxyProtocol", enable="true")
            z.wait_proxy()
            time.sleep(0.5)

            def via(hdr):
                s = socket.create_connection(("127.0.0.1", z.proxy), 5)
                s.sendall(hdr)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                t = ctx.wrap_socket(s, server_hostname="pp.test")
                t.sendall(b"GET / HTTP/1.1\r\nHost: pp.test\r\nConnection: close\r\n\r\n")
                out = b""
                t.settimeout(5)
                try:
                    while True:
                        x = t.recv(65536)
                        if not x:
                            break
                        out += x
                except Exception:
                    pass
                t.close()
                return out.split(b"\r\n")[0].decode(errors="replace"), out

            out = {}
            for name, hdr in (("v1", b"PROXY TCP4 198.51.100.7 127.0.0.1 40000 443\r\n"), ("v2", proxy_v2("198.51.100.7", "127.0.0.1", 40000, 443)),
                              ("v1-clean", b"PROXY TCP4 198.51.100.8 127.0.0.1 40000 443\r\n")):
                out[name] = via(hdr)[0]
            check("403" in out["v1"] and "403" in out["v2"], "PROXY-announced blacklisted client was not blocked: %s" % out)
            check(" 200" in out["v1-clean"], "announced clean client refused: %s" % out)
            return "TLS listener honoured PROXY v1+v2 announced address: 198.51.100.7 (blacklisted) -> 403, 198.51.100.8 -> 200 (%s)" % out
    finally:
        shutil.rmtree(d, ignore_errors=True)


@scenario("proxy_protocol_upstream", ["934"])
def proxy_protocol_upstream():
    """Upstream configured for PROXY protocol v1/v2 receives the header with the real client address."""
    seen = []

    def handler(c):
        buf = b""
        c.settimeout(5)
        while b"\r\n\r\n" not in buf:
            d = c.recv(4096)
            if not d:
                break
            buf += d
        seen.append(buf)
        body = b"ok"
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n" + body)

    from scenarios.s02_streaming import RawServer
    with Zoraxy() as z, RawServer(handler) as up:
        z.add_rule("pu.test", up.addr)
        z.api("/api/proxy/upstream/update", ep="pu.test", origin=up.addr, payload=json.dumps({"ProxyProtocol": 1}), active=True)
        r = z.req("pu.test", src="127.0.0.6")
        check(r.status == 200, "proxied status %d (%s)" % (r.status, z.logtail(300)))
        check(seen and seen[0].startswith(b"PROXY TCP4 127.0.0.6 "), "v1 header: %r" % (seen[0][:60] if seen else None))
        v1 = seen[0].split(b"\r\n")[0].decode()
        seen.clear()
        z.api("/api/proxy/upstream/update", ep="pu.test", origin=up.addr, payload=json.dumps({"ProxyProtocol": 2}), active=True)
        r = z.req("pu.test", src="127.0.0.6")
        check(r.status == 200 and seen and seen[0].startswith(b"\r\n\r\n\x00\r\nQUIT\n"), "v2 header missing: %r" % (seen[0][:20] if seen else None))
        ip = socket.inet_ntoa(seen[0][16:20])
        check(ip == "127.0.0.6", "v2 source address %s" % ip)
        return "upstream got '%s' (v1) and a v2 binary header with source %s" % (v1, ip)


@scenario("access_rules_lists", ["512"])
def access_rules_lists():
    """Blacklist and whitelist (IP, CIDR, wildcard), per-rule attach, and bulk import of 200k entries without slowing requests."""
    with Zoraxy() as z, Backend(name="acl") as b:
        z.add_rule("acl.test", b.addr)
        z.add_rule("free.test", b.addr)
        z.api("/api/access/create", name="strict", desc="e2e", trustProxy=False)
        rules = z.get("/api/access/list")
        sid = [r["ID"] for r in rules if r.get("Name") == "strict"][0]
        z.api("/api/access/attach", id=sid, host="acl.test")
        z.api("/api/blacklist/ip/add", ip="127.0.0.0/29", id=sid, comment="cidr")
        z.api("/api/blacklist/enable", enable=True, id=sid)
        c = {ip: z.req("acl.test", src=ip).status for ip in ("127.0.0.1", "127.0.0.5", "127.0.0.9")}
        check(c["127.0.0.1"] == 403 and c["127.0.0.5"] == 403 and c["127.0.0.9"] == 200, "CIDR blacklist: %s" % c)
        check(z.req("free.test", src="127.0.0.1").status == 200, "default rule host affected by strict rule")
        # whitelist mode
        z.api("/api/blacklist/enable", enable=False, id=sid)
        z.api("/api/whitelist/ip/add", ip="127.0.0.9", id=sid, comment="only")
        z.api("/api/whitelist/enable", enable=True, id=sid)
        w = {ip: z.req("acl.test", src=ip).status for ip in ("127.0.0.9", "127.0.0.10")}
        check(w["127.0.0.9"] == 200 and w["127.0.0.10"] == 403, "whitelist: %s" % w)
        # bulk import 200k blacklist entries into the default rule
        def lat(n=25):
            ts = []
            for _ in range(n):
                t0 = time.time()
                z.req("free.test", src="127.0.0.2")
                ts.append((time.time() - t0) * 1000)
            return sorted(ts)[n // 2]
        base = lat()
        import random
        random.seed(7)
        lines = ["# e2e"] + ["%d.%d.%d.%d" % (random.randint(11, 99), random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)) for _ in range(200000)]
        text = "\n".join(lines)
        t0 = time.time()
        rep = z.api("/api/access/import/apply", id="default", list="blacklist", text=text)
        dt = time.time() - t0
        check(rep.get("accepted", 0) > 190000, "import report: %s" % json.dumps(rep)[:200])
        z.api("/api/blacklist/enable", enable=True, id="default")
        victim = lines[500]
        # lookup speed: 40 requests while the 200k list is active
        per = lat()
        check(per < base * 1.5 + 5, "median request latency %.1f ms with 200k blacklist entries vs %.1f ms without" % (per, base))
        # the imported entry is enforced on the wire only if we can use that address as source: use /api/info/ipcheck
        chk = z.get("/api/info/ipcheck", ip=victim) if True else None
        return "CIDR blacklist, per-rule attach, whitelist ok; imported 200k entries in %.1fs (report keys %s); median request latency %.1f ms with list active vs %.1f ms without; ipcheck(%s)=%s" % (
            dt, sorted(rep.keys())[:5], per, base, victim, json.dumps(chk)[:80])


@scenario("country_block_geoip", ["238"])
def country_block_geoip():
    """Country blacklist and country 'challenge' using a trusted proxy to present foreign client addresses."""
    with Zoraxy() as z, Backend(name="geo") as b:
        z.add_rule("geo.test", b.addr)
        info = z.get("/api/info/geoip", ip="8.8.8.8")
        cc = (info.get("CountryIsoCode") or info.get("country") or json.dumps(info))
        if "US" not in json.dumps(info):
            raise Skip("GeoIP database has no entry for 8.8.8.8: %s" % json.dumps(info)[:120])
        z.api("/api/trustedproxy/add", ip="127.0.0.8", desc="e2e")
        z.api("/api/whitelist/trustProxy", enable=True, id="default")
        z.api("/api/blacklist/country/add", cc="US", id="default", comment="e2e")
        z.api("/api/blacklist/enable", enable=True, id="default")
        us = z.req("geo.test", src="127.0.0.8", headers={"X-Forwarded-For": "8.8.8.8"})
        other = z.req("geo.test", src="127.0.0.8", headers={"X-Forwarded-For": "81.2.69.142"})
        check(us.status == 403, "US client not blocked (%d)" % us.status)
        info2 = z.get("/api/info/geoip", ip="81.2.69.142")
        check(other.status == 200 or "US" in json.dumps(info2), "non-US client blocked (%d, geo %s)" % (other.status, json.dumps(info2)[:80]))
        return "US (8.8.8.8 via trusted proxy) -> %d; 81.2.69.142 -> %d" % (us.status, other.status)
