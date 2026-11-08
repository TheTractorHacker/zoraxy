"""Lua script handlers, Sablier gate, DNS responder, TCP/UDP stream proxy."""
import json
import socket
import struct

from lib import *


@scenario("lua_script_handler", ["88"])
def lua_script_handler():
    """Lua handler answers without the upstream, hook mode adds headers and continues, sandbox escapes and infinite loops
    return an error quickly instead of executing or hanging."""
    with Zoraxy() as z, Backend(name="app") as app:
        z.add_rule("lua.test", app.addr)
        code = '''
local q = request.args and request.args.name or "world"
response.status = 201
response.headers["X-Lua"] = "yes"
response.body = "hello " .. q .. " from " .. request.method .. " " .. request.path .. " h=" .. (request.headers["x-probe"] or "-")
'''
        z.api("/api/proxy/script/set", ep="lua.test", config=json.dumps({"Enabled": True, "Mode": "handler", "Code": code}))
        n = len(app.log)
        r = z.req("lua.test", "/greet?name=zoraxy", headers={"X-Probe": "p1"})
        check(r.status == 201 and r.h("x-lua") == "yes" and r.text == "hello zoraxy from GET /greet h=p1", "handler: %d %r %s" % (r.status, r.text, r.headers))
        check(len(app.log) == n, "handler mode contacted the upstream")
        # hook mode: set a request header, continue to the upstream
        hook = 'request_header_set("X-From-Lua", "hooked")'
        z.api("/api/proxy/script/set", ep="lua.test", config=json.dumps({"Enabled": True, "Mode": "hook", "Code": hook}))
        r = z.req("lua.test", "/x")
        check(r.status == 200 and r.json()["headers"].get("x-from-lua") == "hooked", "hook mode: %d %s" % (r.status, r.text[:100]))
        # sandbox: every escape either fails to save (compile) or errors opaquely at runtime; never runs
        escapes = {
            "os.execute": 'os.execute("touch /tmp/zx-e2e-pwned"); response.body="x"',
            "io.open": 'local f = io.open("/etc/passwd"); response.body = f:read("*a")',
            "io.popen": 'local f = io.popen("id"); response.body = f:read("*a")',
            "require": 'local s = require("os"); response.body = "x"',
            "load": 'local f = load("return 1"); response.body = tostring(f())',
            "dofile": 'dofile("/etc/passwd")',
            "debug": 'response.body = debug.getinfo(1).source',
            "package": 'response.body = tostring(package.loaded.os)',
            "getfenv": 'response.body = tostring(getfenv(0))',
            "string.dump": 'response.body = string.dump(function() end)',
        }
        out = {}
        for name, src in escapes.items():
            try:
                z.api("/api/proxy/script/set", ep="lua.test", config=json.dumps({"Enabled": True, "Mode": "handler", "Code": src}))
            except Fail as e:
                out[name] = "rejected at save"
                continue
            r = z.req("lua.test", "/e", timeout=10)
            check(r.status >= 500 and "root:" not in r.text and "uid=" not in r.text, "sandbox escape %s returned %d %r" % (name, r.status, r.text[:100]))
            out[name] = r.status
        check(not os.path.exists("/tmp/zx-e2e-pwned"), "os.execute actually ran")
        # infinite loop must be cut off
        z.api("/api/proxy/script/set", ep="lua.test", config=json.dumps({"Enabled": True, "Mode": "handler", "Code": "while true do end", "TimeoutMs": 200}))
        t0 = time.time()
        r = z.req("lua.test", "/loop", timeout=10)
        dt = time.time() - t0
        check(r.status >= 500 and dt < 3, "infinite loop: status %d after %.1fs" % (r.status, dt))
        # still responsive afterwards
        check(z.req("lua.test", "/again", timeout=10).status >= 500, "proxy unresponsive after loop")
        return "handler 201 w/o upstream; hook adds header and proxies; %d sandbox escapes %s; infinite loop cut at %.2fs (status %d)" % (len(out), out, dt, r.status)


@scenario("sablier_gate", ["120"])
def sablier_gate():
    """Fake Sablier: waiting page while starting, proxy once ready, fail closed (503) when Sablier is down, bypass paths."""
    state = {"ready": False, "calls": []}

    def sablier(h, rec, b):
        state["calls"].append(rec["path"])
        if state["ready"]:
            send(h, 200, "ready", {"X-Sablier-Session-Status": "ready"})
        else:
            send(h, 200, "<html><body>Starting your workload...</body></html>", {"X-Sablier-Session-Status": "not-ready"}, ctype="text/html")

    with Zoraxy() as z, Backend(sablier, name="sablier") as sab, Backend(name="app") as app:
        z.add_rule("sab.test", app.addr)
        cfg = {"Enabled": True, "URL": "http://" + sab.addr, "Strategy": "dynamic", "Names": ["web"], "SessionDuration": "5m",
               "ReadyCacheSeconds": -1, "BypassPaths": ["/healthz"]}
        z.api("/api/proxy/script/set" if False else "/api/proxy/sablier/set", ep="sab.test", config=json.dumps(cfg))
        n = len(app.log)
        r = z.req("sab.test", "/", headers={"Accept": "text/html"})
        check(r.status == 200 and "Starting your workload" in r.text and r.h("cache-control") == "no-store", "waiting page: %d %r" % (r.status, r.text[:80]))
        check(len(app.log) == n, "upstream hit while workload starting")
        check(any("/api/strategies/dynamic" in c and "names=web" in c for c in state["calls"]), "sablier call: %s" % state["calls"])
        state["ready"] = True
        r = z.req("sab.test", "/")
        check(r.status == 200 and r.json()["backend"] == "app", "ready but not proxied: %d" % r.status)
        # bypass path never asks sablier
        before = len(state["calls"])
        z.req("sab.test", "/healthz")
        check(len(state["calls"]) == before, "bypass path consulted sablier")
        # sablier down => 503 + Retry-After (fail closed)
        sab.handler = lambda h, rec, b: (setattr(h, "close_connection", True), h.connection.close())
        down = z.req("sab.test", "/x", headers={"Accept": "application/json"})
        check(down.status == 503, "sablier down: %d (fail closed expected)" % down.status)
        return "waiting page served w/o touching upstream (dynamic strategy, names=web), proxied once ready, bypass path skipped, Sablier down -> %d %s" % (down.status, down.h("retry-after"))


def dns_query(name, qtype=1, tcp=False, port=0, addr="127.0.0.1"):
    hdr = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", qtype, 1)
    msg = hdr + q
    if tcp:
        s = socket.create_connection((addr, port), 5)
        s.sendall(struct.pack(">H", len(msg)) + msg)
        ln = struct.unpack(">H", s.recv(2))[0]
        data = b""
        while len(data) < ln:
            data += s.recv(ln - len(data))
        s.close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(msg, (addr, port))
        data, _ = s.recvfrom(4096)
        s.close()
    flags = struct.unpack(">H", data[2:4])[0]
    rcode = flags & 0xF
    an = struct.unpack(">H", data[6:8])[0]
    ips = []
    if an:
        # skip question then parse answers (names are compressed pointers in practice)
        i = 12
        while data[i] != 0:
            i += data[i] + 1
        i += 5
        for _ in range(an):
            if data[i] & 0xC0 == 0xC0:
                i += 2
            else:
                while data[i] != 0:
                    i += data[i] + 1
                i += 1
            t, c, ttl, rl = struct.unpack(">HHIH", data[i:i + 10])
            i += 10
            if t == 1:
                ips.append(socket.inet_ntoa(data[i:i + 4]))
            i += rl
    return rcode, ips


@scenario("dns_responder", ["769"])
def dns_responder():
    """UDP and TCP A queries for proxy rule hostnames and aliases (wildcard); other names REFUSED."""
    with Zoraxy() as z, Backend(name="app") as app:
        z.add_rule("dns.test", app.addr)
        z.api("/api/proxy/setAlias", ep="dns.test", alias=json.dumps(["*.wild.test"]))
        port = free_port()
        cfg = {"enabled": True, "listenAddr": "127.0.0.1:%d" % port, "ipv4": "192.0.2.55", "ttl": 30}
        z.api("/api/tools/dnsresponder", config=json.dumps(cfg))
        wait_for(lambda: dns_query("dns.test", port=port), timeout=10, msg="dns responder")
        out = {}
        for name, tcp in (("dns.test", False), ("dns.test", True), ("x.wild.test", False), ("unknown.example", False), ("unknown.example", True)):
            out["%s/%s" % (name, "tcp" if tcp else "udp")] = dns_query(name, tcp=tcp, port=port)
        check(out["dns.test/udp"] == (0, ["192.0.2.55"]), "udp A: %s" % out)
        check(out["dns.test/tcp"] == (0, ["192.0.2.55"]), "tcp A: %s" % out)
        check(out["x.wild.test/udp"] == (0, ["192.0.2.55"]), "wildcard alias: %s" % out)
        check(out["unknown.example/udp"][0] == 5 and out["unknown.example/tcp"][0] == 5, "non-hosted name must be REFUSED: %s" % out)
        return "UDP+TCP A dns.test -> 192.0.2.55, wildcard alias answered, others REFUSED (rcode 5): %s" % out


@scenario("stream_proxy", ["1075"])
def stream_proxy():
    """TCP and UDP relay through the stream proxy; an access rule blacklist blocks a client."""
    import socketserver
    import threading
    tcp_port = free_port()
    udp_port = free_port()

    class TCPEcho(socketserver.BaseRequestHandler):
        def handle(self):
            while True:
                d = self.request.recv(4096)
                if not d:
                    return
                self.request.sendall(d)

    class UDPEcho(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            sock.sendto(b"udp:" + data, self.client_address)

    ts = socketserver.ThreadingTCPServer(("127.0.0.1", tcp_port), TCPEcho)
    ts.daemon_threads = True
    us = socketserver.ThreadingUDPServer(("127.0.0.1", udp_port), UDPEcho)
    for s in (ts, us):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        with Zoraxy() as z:
            front = free_port()
            z.api("/api/streamprox/config/add", name="e2e-echo", listenAddr="127.0.0.1:%d" % front, proxyAddr="127.0.0.1:%d" % tcp_port,
                  timeout=5, useTCP=True, useUDP=False, proxyProtocolVersion=0, enableLogging=False, accessRuleUUID="default")
            lst = z.get("/api/streamprox/config/list")
            uid = [c.get("UUID") for c in lst if c.get("Name") == "e2e-echo"][0]
            z.api("/api/streamprox/config/start", uuid=uid)
            wait_for(lambda: socket.create_connection(("127.0.0.1", front), 0.5), msg="stream listener")
            s = socket.create_connection(("127.0.0.1", front), 5)
            s.sendall(b"ping")
            check(s.recv(100) == b"ping", "tcp relay")
            big = os.urandom(200000)
            s.sendall(big)
            got = b""
            s.settimeout(5)
            while len(got) < len(big):
                got += s.recv(65536)
            check(got == big, "tcp relay of 200KB corrupted")
            s.close()
            # UDP
            ufront = free_port()
            z.api("/api/streamprox/config/add", name="e2e-udp", listenAddr="127.0.0.1:%d" % ufront, proxyAddr="127.0.0.1:%d" % udp_port,
                  timeout=5, useTCP=False, useUDP=True, proxyProtocolVersion=0, enableLogging=False, accessRuleUUID="default")
            lst = z.get("/api/streamprox/config/list")
            uid2 = [c.get("UUID") for c in lst if c.get("Name") == "e2e-udp"][0]
            z.api("/api/streamprox/config/start", uuid=uid2)
            time.sleep(0.5)
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.settimeout(5)
            u.sendto(b"dgram", ("127.0.0.1", ufront))
            data, _ = u.recvfrom(100)
            check(data == b"udp:dgram", "udp relay: %r" % data)
            u.close()
            # access rule: blacklist 127.0.0.1 on the default rule blocks the stream client
            z.api("/api/blacklist/ip/add", ip="127.0.0.1", id="default", comment="e2e")
            z.api("/api/blacklist/enable", enable=True, id="default")
            time.sleep(0.3)
            blocked = False
            try:
                s = socket.create_connection(("127.0.0.1", front), 5)
                s.sendall(b"ping")
                s.settimeout(3)
                d = s.recv(100)
                blocked = (d == b"")
            except (ConnectionError, socket.timeout):
                blocked = True
            check(blocked, "blacklisted client still relayed through the stream proxy")
            return "TCP relay (+200KB intact), UDP relay, blacklist on the access rule closes the TCP client"
    finally:
        for s in (ts, us):
            s.shutdown()
            s.server_close()
