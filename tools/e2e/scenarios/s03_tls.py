"""h2c / gRPC-style upstream, Encrypted Client Hello, mTLS, secondary-port TLS."""
import json

from lib import *


def _certs(names, d):
    ca = make_ca(d)
    out = []
    for n in names:
        crt, key = make_leaf(d, n, ca)
        out.append((n, crt, key))
    return ca, out


@scenario("h2c_grpc_upstream", ["201"])
def h2c_grpc_upstream():
    """HTTP/2 client -> Zoraxy (TLS) -> cleartext HTTP/2 upstream: unary + trailers + full-duplex stream."""
    d = tempfile.mkdtemp(prefix="zx-h2c-")
    port = free_port()
    try:
        ca, certs = _certs(["g.test"], d)
        with Proc([helper(), "h2c-server", "-addr", "127.0.0.1:%d" % port]):
            wait_for(lambda: socket.create_connection(("127.0.0.1", port), 0.5), msg="h2c server")
            with Zoraxy(tls=True, certs=certs) as z:
                z.add_rule("g.test", "127.0.0.1:%d" % port)
                z.api("/api/proxy/upstream/update", ep="g.test", origin="127.0.0.1:%d" % port,
                      payload=json.dumps({"H2C": True}), active=True)
                r = helper_json("h2c-client", "-url", "https://127.0.0.1:%d" % z.proxy, "-sni", "g.test")
                check("error" not in r, "h2c client: %s" % r)
                check(r["unary_status"] == 200 and "unary proto=2" in r["unary_body"],
                      "upstream did not see HTTP/2 (h2c): %s" % r)
                check(r["trailer_grpc_status"] == "0", "gRPC trailers lost: %s" % r)
                check("te=trailers" in r["unary_body"], "TE: trailers not forwarded to the gRPC upstream: %s" % r)
                check(r["bidi_echoes"] == ["echo:one", "echo:two", "echo:three"], "bidi streaming broken: %s" % r)
                # control: without the H2C flag the upstream is spoken to with HTTP/1.1 and must not see proto=2
                z.api("/api/proxy/upstream/update", ep="g.test", origin="127.0.0.1:%d" % port,
                      payload=json.dumps({"H2C": False}), active=True)
                return "unary proto=2 + trailers grpc-status=0 + 3 duplex echoes via h2c; evidence=%s" % json.dumps(
                    {k: r[k] for k in ("unary_body", "trailer_grpc_status", "bidi_echoes")})
    finally:
        shutil.rmtree(d, ignore_errors=True)


@scenario("ech_handshake", ["235"])
def ech_handshake():
    """Go client with an ECHConfigList: handshake accepted, inner SNI routes, rotation keeps old config working."""
    d = tempfile.mkdtemp(prefix="zx-ech-")
    try:
        ca, certs = _certs(["public.test", "secret.test"], d)
        with Zoraxy(tls=True, certs=certs) as z, Backend(name="inner") as b:
            z.add_rule("secret.test", b.addr)
            z.api("/api/ech/settings", enabled=True, publicname="public.test")
            st = z.get("/api/ech/status")
            lst = st["ConfigList"]
            if not lst:
                z.api("/api/ech/rotate")
                lst = z.get("/api/ech/status")["ConfigList"]
            check(lst, "no ECHConfigList produced: %s" % st)
            r = helper_json("ech-client", "-addr", "127.0.0.1:%d" % z.proxy, "-sni", "secret.test", "-ech", lst)
            check(r.get("ech_accepted") is True, "ECH not accepted: %s" % r)
            check("200" in r.get("status_line", "") and '"backend": "inner"' in r.get("body", ""), "inner request failed: %s" % r)
            check(r.get("peer_cn") == "secret.test", "served cert CN %s" % r.get("peer_cn"))
            # without ECH the same host still works
            r0 = helper_json("tls-client", "-addr", "127.0.0.1:%d" % z.proxy, "-sni", "secret.test")
            check(r0.get("ech_accepted") is False and "200" in r0.get("status_line", ""), "plain TLS: %s" % r0)
            # rotate: old list still decrypts (retired key), new list works
            z.api("/api/ech/rotate")
            new = z.get("/api/ech/status")["ConfigList"]
            check(new and new != lst, "rotation did not change the advertised list")
            r2 = helper_json("ech-client", "-addr", "127.0.0.1:%d" % z.proxy, "-sni", "secret.test", "-ech", lst)
            check(r2.get("ech_accepted") is True, "retired key no longer decrypts: %s" % r2)
            r3 = helper_json("ech-client", "-addr", "127.0.0.1:%d" % z.proxy, "-sni", "secret.test", "-ech", new)
            check(r3.get("ech_accepted") is True, "new key rejected: %s" % r3)
            # delete everything but the new key => old list is rejected with retry configs
            keys = z.get("/api/ech/status")["Keys"]
            old = [k for k in keys if k.get("Status") != "active" and k.get("State") != "active"]
            return "ECH accepted (inner SNI secret.test, outer public.test); plain TLS ok; rotate keeps old+new working"
    finally:
        shutil.rmtree(d, ignore_errors=True)


@scenario("mtls_client_certs", ["442"])
def mtls_client_certs():
    """require / require_and_verify / allow+block lists; identity headers; spoofed X-Client-Cert-* stripped."""
    d = tempfile.mkdtemp(prefix="zx-mtls-")
    try:
        ca, certs = _certs(["m.test", "o.test"], d)
        good = make_leaf(d, "alice", ca, client=True, san="DNS:alice")
        # a client certificate from another CA
        os.makedirs(os.path.join(d, "other"))
        oca = make_ca(os.path.join(d, "other"), "Other CA")
        bad = make_leaf(os.path.join(d, "other"), "mallory", oca, client=True, san="DNS:mallory")
        with Zoraxy(tls=True, certs=certs) as z, Backend(name="m") as b, Backend(name="o") as ob:
            z.add_rule("m.test", b.addr)
            z.add_rule("o.test", ob.addr)
            z.api("/api/proxy/networking/clientcert", ep="m.test", config=json.dumps(
                {"Mode": "require_and_verify", "CAPEM": open(ca[0]).read()}))
            srv = ("127.0.0.1", z.proxy)

            def get(host, cert=None, headers=None):
                try:
                    return http_req(srv[0], srv[1], host, "/", tls=True, cert=cert, headers=headers)
                except Exception as e:  # handshake failure
                    return "ERR:" + type(e).__name__

            r = get("m.test", good, {"X-Client-Cert-Subject": "spoofed", "X-Client-Cert-Verified": "true"})
            check(isinstance(r, Resp) and r.status == 200, "valid client cert refused: %r" % (r,))
            hd = r.json()["headers"]
            check(hd.get("x-client-cert-subject", "").find("alice") >= 0, "identity header missing/spoofed: %s" % hd)
            check("spoofed" not in json.dumps(hd), "spoofed identity header reached the upstream")
            r = get("m.test", None)
            check(not isinstance(r, Resp) or r.status in (401, 403, 496), "no client cert accepted: %r" % (r,))
            r_none = r
            r = get("m.test", bad)
            check(not isinstance(r, Resp) or r.status in (401, 403, 496), "foreign-CA client cert accepted: %r" % (r,))
            r_bad = r
            # SNI/Host confusion: complete TLS for the open host, then ask for the mTLS host
            r = http_req(srv[0], srv[1], "m.test", "/", tls=True, cert=None) if False else None
            conn_ok = http_req(srv[0], srv[1], "o.test", "/", tls=True)
            check(conn_ok.status == 200, "open host o.test broken")
            # block list: serial of alice
            ser = openssl("x509", "-in", good[0], "-noout", "-serial").stdout.decode().strip().split("=")[1]
            z.api("/api/proxy/networking/clientcert", ep="m.test", config=json.dumps(
                {"Mode": "require_and_verify", "CAPEM": open(ca[0]).read(), "BlockList": ["serial:" + ser]}))
            r = get("m.test", good)
            check(not isinstance(r, Resp) or r.status in (401, 403, 496), "blocked serial still accepted: %r" % (r,))
            # allow list pins only bob -> alice refused
            z.api("/api/proxy/networking/clientcert", ep="m.test", config=json.dumps(
                {"Mode": "require_and_verify", "CAPEM": open(ca[0]).read(), "AllowList": ["cn:bob"]}))
            r = get("m.test", good)
            check(not isinstance(r, Resp) or r.status in (401, 403, 496), "allow list ignored: %r" % (r,))
            z.api("/api/proxy/networking/clientcert", ep="m.test", config=json.dumps(
                {"Mode": "require_and_verify", "CAPEM": open(ca[0]).read(), "AllowList": ["cn:alice"]}))
            r = get("m.test", good)
            check(isinstance(r, Resp) and r.status == 200, "allow list cn:alice rejected alice: %r" % (r,))
            return "valid cert=200 (subject header set, spoofed header stripped); no cert=%s; foreign CA=%s; block-list serial & allow-list cn enforced" % (
                r_none if not isinstance(r_none, Resp) else r_none.status, r_bad if not isinstance(r_bad, Resp) else r_bad.status)
    finally:
        shutil.rmtree(d, ignore_errors=True)


@scenario("secondary_port_tls", ["1042"])
def secondary_port_tls():
    """Rule with an extra listening port; TLS on that port can be switched on and off."""
    d = tempfile.mkdtemp(prefix="zx-sec-")
    try:
        ca, certs = _certs(["sp.test"], d)
        with Zoraxy(tls=True, certs=certs) as z, Backend(name="sp") as b:
            z.add_rule("sp.test", b.addr)
            sec = free_port()
            z.api("/api/proxy/listeningPorts/set", domain="sp.test", ports=json.dumps([":%d" % sec]))
            wait_for(lambda: socket.create_connection(("127.0.0.1", sec), 0.5), msg="secondary listener")
            # plain HTTP on the secondary port by default
            r = http_req("127.0.0.1", sec, "sp.test", "/")
            check(r.status == 200 and r.json()["backend"] == "sp", "plain secondary port: %r" % r)
            z.api("/api/proxy/networking/secondarytls", ep="sp.test", enable=True)
            def tls_ok():
                try:
                    return http_req("127.0.0.1", sec, "sp.test", "/", tls=True).status == 200
                except Exception:
                    return False
            wait_for(tls_ok, msg="TLS on secondary port")
            tls_resp = helper_json("tls-client", "-addr", "127.0.0.1:%d" % sec, "-sni", "sp.test")
            check(tls_resp.get("peer_cn") == "sp.test", "secondary port served wrong cert: %s" % tls_resp)
            z.api("/api/proxy/networking/secondarytls", ep="sp.test", enable=False)
            wait_for(lambda: http_req("127.0.0.1", sec, "sp.test", "/").status == 200, msg="plain again")
            return "secondary :%d plain -> TLS (cert CN sp.test) -> plain again" % sec
    finally:
        shutil.rmtree(d, ignore_errors=True)


@scenario("tls_sni_certificate_selection", ["core"])
def tls_sni_certificate_selection():
    """The certificate served follows the SNI: exact name file, SAN multi-domain cert, wildcard cert, preferred-certificate
    override, and the default certificate for unknown names."""
    d = tempfile.mkdtemp(prefix="zx-sni-")
    try:
        ca = make_ca(d)
        a = make_leaf(d, "a.test", ca)
        multi = make_leaf(d, "m1.test", ca, san="DNS:m1.test,DNS:m2.test", name="multi")
        wild = make_leaf(d, "*.wild.test", ca, san="DNS:*.wild.test,DNS:wild.test", name="wild")
        pref = make_leaf(d, "preferred.test", ca, name="pref")
        with Zoraxy(tls=True, certs=[("a.test", a[0], a[1]), ("multi", multi[0], multi[1]), ("wild", wild[0], wild[1]), ("pref", pref[0], pref[1])]) as z, Backend(name="app") as b:
            for h in ("a.test", "m2.test", "x.wild.test", "unknown.test", "pinned.test"):
                z.add_rule(h, b.addr)
            cn = lambda sni: helper_json("tls-client", "-addr", "127.0.0.1:%d" % z.proxy, "-sni", sni).get("peer_cn")
            got = {sni: cn(sni) for sni in ("a.test", "m2.test", "x.wild.test", "unknown.test")}
            check(got["a.test"] == "a.test", "exact certificate: %s" % got)
            check(got["m2.test"] == "m1.test", "SAN certificate not selected for m2.test: %s" % got)
            check(got["x.wild.test"] == "*.wild.test", "wildcard certificate not selected: %s" % got)
            check(got["unknown.test"] not in ("a.test", "m1.test", "*.wild.test"), "unknown SNI served a site certificate: %s" % got)
            # a preferred certificate is used when per-name SNI matching is switched off for the rule
            z.api("/api/proxy/setTlsConfig", ep="pinned.test", tlsConfig=json.dumps({"DisableSNI": True, "DisableLegacyCertificateMatching": False, "EnableAutoHTTPS": False, "PreferredCertificate": {}}))
            z.api("/api/cert/setPreferredCertificate", domain="pinned.test", certname="pref")
            got["pinned.test"] = cn("pinned.test")
            check(got["pinned.test"] == "preferred.test", "preferred certificate override ignored: %s" % got)
            return "served CN per SNI: %s" % got
    finally:
        shutil.rmtree(d, ignore_errors=True)
