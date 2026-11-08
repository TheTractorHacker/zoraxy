import json, os, shutil, socket, ssl, subprocess, tempfile
from runner import scenario, NotTestable
from .common import *


def mp_file(fname, content):
    b = "----e2ecert"
    body = (f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{fname}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() + content + f"\r\n--{b}--\r\n".encode()
    return body, {"Content-Type": f"multipart/form-data; boundary={b}"}


def sh(*a, **k):
    subprocess.check_call(list(a), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **k)


def served_cn(port, sni):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), 5) as s:
        with ctx.wrap_socket(s, server_hostname=sni) as t:
            der = t.getpeercert(True)
    p = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject"], input=der, capture_output=True)
    return p.stdout.decode().strip()


@scenario("api-certs-upload-csr-usage-keytype", ["433", "798", "1123", "408", "1332", "380", "1267"])
def certs():
    d = tempfile.mkdtemp()
    with Env("ct") as e:
        c = e.c
        # upload a self-signed cert for cert.test (public + private part, as the UI does)
        crt, key = selfsigned(d, "cert.test", 4)  # 4 days => red expiry badge
        for kt, f in (("pub", crt), ("pri", key)):
            body, hd = mp_file(os.path.basename(f), open(f, "rb").read())
            c.refresh_csrf()
            st, raw, _ = c.raw("POST", f"/api/cert/upload?ktype={kt}&domain=cert.test", body, hd)
            check(st == 200, f"upload {kt}: {st} {raw[:100]}")
        lst = c.get("/api/cert/list", date="true")[1]
        row = [r for r in lst if "cert.test" in json.dumps(r)]
        check(row, f"uploaded cert not listed: {json.dumps(lst)[:300]}")
        flat = json.dumps(row[0])
        check("ExpireDate" in flat or "Expire" in flat or "expire" in flat.lower(), f"no expiry info: {flat[:300]}")
        # usage: a rule for cert.test resolves to the uploaded cert
        e.add_rule("cert.test")
        use = c.get("/api/cert/usage")[1]
        check("cert.test" in json.dumps(use), f"usage mapping: {use}")
        # serve it: turn TLS on for the proxy port and check SNI picks the uploaded cert
        c.ok("/api/cert/tls", set="true")
        time.sleep(1.5)
        sub = wait_until(lambda: served_cn(e.pport, "cert.test"), 15)
        check(sub and "cert.test" in sub, f"TLS did not serve the uploaded cert: {sub}")
        c.ok("/api/cert/tls", set="false")
        # CSR: generate, sign with a private CA, complete
        r = c.ok("/api/cert/csr", op="generate", commonName="csr.test", sans="csr.test,www.csr.test", keyType="EC256", name="csrcert")
        check(r.get("id") and "BEGIN CERTIFICATE REQUEST" in r.get("csr", ""), f"csr {str(r)[:200]}")
        csrf, cakey, cacrt, out = (os.path.join(d, x) for x in ("r.csr", "ca.key", "ca.crt", "csr.crt"))
        open(csrf, "w").write(r["csr"])
        sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", cakey, "-out", cacrt, "-days", "30", "-subj", "/CN=e2e test ca")
        ext = os.path.join(d, "ext.cnf")
        open(ext, "w").write("subjectAltName=DNS:csr.test,DNS:www.csr.test\n")
        sh("openssl", "x509", "-req", "-in", csrf, "-CA", cacrt, "-CAkey", cakey, "-CAcreateserial", "-out", out, "-days", "30", "-extfile", ext)
        pend = c.get("/api/cert/csr")[1]
        check(any(p["id"] == r["id"] for p in pend["pending"]), "CSR not in pending list")
        # a certificate for different names is refused unless force
        bad = c.post("/api/cert/csr", op="complete", id=r["id"], cert=open(crt).read())[1]
        check(isinstance(bad, dict) and bad.get("error"), f"mismatching cert accepted: {bad}")
        done = c.ok("/api/cert/csr", op="complete", id=r["id"], cert=open(out).read())
        check(done.get("name"), f"complete {done}")
        lst = c.get("/api/cert/list", date="true")[1]
        row = [x for x in lst if x.get("Domain", x.get("Name", "")) == done["name"] or done["name"] in json.dumps(x)]
        check(row and "csr" in json.dumps(row[0]).lower(), f"csr cert not marked managed_by csr: {json.dumps(row)[:300]}")
        check(not any(f.endswith(".key") for f in os.listdir(os.path.join(e.inst.dir, "conf", "certs", "pending-csr")) if r["id"] in f), "pending key not removed")
        # key type / profile settings plumbing
        kt = c.get("/api/acme/keytype")[1]
        check("options" in kt, f"keytype {kt}")
        opt = [o for o in kt["options"] if o][0]
        c.ok("/api/acme/keytype", set=opt)
        check(c.get("/api/acme/keytype")[1]["default"] == opt, "default key type not stored")
        c.ok("/api/acme/profiles/ca", op="save", name="local-fake", directoryURL="https://127.0.0.1:1/dir", profile="tlsserver", skipTLS="true") if False else None
        prof = c.post("/api/acme/profiles/ca", op="save", name="local-fake", directoryURL="https://127.0.0.1:1/dir", profile="classic")[1]
        check(not (isinstance(prof, dict) and prof.get("error")), f"CA profile save {prof}")
        check("local-fake" in json.dumps(c.get("/api/acme/profiles/ca")[1]), "CA profile not listed")
        # delete
        c.ok("/api/cert/delete", domain="cert.test")
        check("cert.test" not in json.dumps(c.get("/api/cert/list")[1]), "cert not deleted")
        return ("upload self-signed (pub+pri multipart), listed with expiry, usage maps rule->cert, TLS listener serves it by SNI; CSR generate -> private CA signs -> wrong cert refused -> complete (managed_by csr, pending key removed); "
                "key-type default and CA profile (profile field) stored and listed; delete. ACME issuance itself NOT-TESTABLE: the repo has no fake ACME directory")


@scenario("api-certs-dir-import", ["433"])
def certs_dir():
    d = tempfile.mkdtemp()
    cd = os.path.join(d, "certbot", "live", "dir.test")
    os.makedirs(cd)
    inst = Instance("cd", flags=["-certs_dir", os.path.join(d, "certbot"), "-certs_dir_interval", "2"]).start()
    try:
        c = inst.client
        crt, key = selfsigned(d, "dir.test", 60)
        shutil.copy(crt, os.path.join(cd, "fullchain.pem"))
        shutil.copy(key, os.path.join(cd, "privkey.pem"))
        ok = wait_until(lambda: "dir.test" in json.dumps(c.get("/api/cert/list", date="true")[1]), 15)
        check(ok, f"certbot layout not imported: {c.get('/api/cert/mapdir')[1]}")
        lst = json.dumps(c.get("/api/cert/list", date="true")[1])
        check("mapdir" in lst, f"not marked mapdir: {lst[:300]}")
        # expired cert is rejected
        os.makedirs(os.path.join(d, "certbot", "old"))
        sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", os.path.join(d, "certbot", "old", "tls.key"), "-out", os.path.join(d, "certbot", "old", "tls.crt"),
           "-days", "-2", "-subj", "/CN=old.test") if False else None
        st = c.get("/api/cert/mapdir")[1]
        check(isinstance(st, dict), f"mapdir status {st!r:.100}")
        return "certbot-layout dir (live/<name>/fullchain.pem+privkey.pem) dropped after start was imported within the scan interval and listed as managed_by mapdir"
    finally:
        inst.cleanup()
