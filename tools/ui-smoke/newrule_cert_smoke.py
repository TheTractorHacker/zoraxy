"""Smoke scenario of the "HTTPS certificate" field of the New proxy rule dialog. exec()'d by smoke.py (namespace: fail, current, args,
os, re); run alone with --newrule-cert-only. Needs the instance's proxy port at UI port + 1 (as tools/ui-smoke/run.sh starts it) and
openssl on the PATH. It makes its own certificates and rules and removes them again.

Checks: the empty-list hint; the options (names, expiry) and the grouping by the typed hostname; the mismatch warning (does not block);
the rule is created with the choice (one request: TlsOptions.PreferredCertificate for the host and every alias, SNI matching off for
this rule only); the success toast does not offer "Create certificate for this host"; a rule created without a choice keeps the
default TLS options; an unknown certificate name creates nothing; and a REAL TLS handshake with SNI returns the chosen certificate.
Screenshots (light, dark, 390px) are written to --out. It needs a store without certificates (a fresh instance), so it only runs
with --newrule-cert-only, not in the full run."""

import socket
import ssl
import subprocess
import tempfile

NRC_HOST = "nrc-pick.smoke.test"
NRC_ALIAS = "nrc-alias.smoke.test"
NRC_PLAIN = "nrc-plain.smoke.test"
NRC_CERTS = ["nrc-cert-a", "nrc-cert-b", "nrc-cert-c"]


def newrule_cert_ui(pg, ctx):
    tmp = tempfile.mkdtemp()

    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: x => res({error: 'HTTP ' + x.status}), dataType: 'json'}))""", [url, data])

    def shot(name, sel="#newRuleModal"):
        pg.locator(sel).screenshot(path=os.path.join(args.out, name))

    def make_cert(name, sans):
        key, crt = os.path.join(tmp, name + ".key"), os.path.join(tmp, name + ".pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-subj", "/CN=" + name,
                        "-addext", "subjectAltName=" + ",".join("DNS:" + s for s in sans)], check=True, capture_output=True)
        return crt, key

    def upload(name, crt, key):
        pem, pri = open(crt).read(), open(key).read()
        return js("""async ([cn, pem, key]) => {
            const tok = document.querySelector('meta[name="zoraxy.csrf.Token"]').content, out = [];
            for (const [kt, body] of [['pub', pem], ['pri', key]]) {
                const f = new FormData(); f.append('file', new Blob([body]), kt);
                const r = await fetch('/api/cert/upload?ktype=' + kt + '&domain=' + cn, {method: 'POST', headers: {'X-CSRF-Token': tok}, body: f});
                out.push(r.status);
            }
            return out; }""", [name, pem, pri])

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    def open_dialog(**opts):
        js("o => openNewRuleDialog(o)", opts)
        pg.wait_for_selector("#newRuleModal.visible", timeout=8000)
        pg.wait_for_timeout(700)

    def close_dialog():
        pg.click("#nrCancel")
        pg.wait_for_selector("#newRuleModal", state="hidden", timeout=8000)

    def hint():
        return js("document.getElementById('nrCertHint').innerText")

    def options():
        return js("[...document.querySelectorAll('#nrCert option')].map(o => [o.value, o.textContent])")

    def rule(host):
        for r in js("fetch('/api/proxy/list?type=host').then(r => r.json())"):
            if r["RootOrMatchingDomain"] == host:
                return r
        return None

    current["page"] = "newrule-cert"
    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)
    for h in (NRC_HOST, NRC_PLAIN):
        post("/api/proxy/del", {"ep": h})
    for n in NRC_CERTS:
        js("async n => { await fetch('/api/cert/delete?domain=' + n, {method: 'POST', headers: {'X-CSRF-Token': document.querySelector('meta[name=\"zoraxy.csrf.Token\"]').content}}); }", n)

    # ---- 1. no certificates: the field is there, says how to get one, and the form still works
    pre = js("fetch('/api/cert/list').then(r => r.json())")
    if not pre:  # (after other scenarios the store may hold certificates: then this part is skipped)
        open_dialog()
        if not pg.is_visible("#nrCert"):
            fail("newrule-cert", "the certificate field must be visible without opening More options")
        if options() != [["", "Automatic (match by hostname)"]]:
            fail("newrule-cert", f"with no certificates only Automatic is offered, got {options()}")
        if "No certificates yet" not in hint() or "Certificates page" not in hint():
            fail("newrule-cert", f"the empty list must explain how to get a certificate, got {hint()!r}")
        shot("newrule-cert-empty-light.png")
        theme(True)
        shot("newrule-cert-empty-dark.png")
        theme(False)
        close_dialog()

    # ---- 2. certificates: a and b cover the host (b also an alias), c does not
    files = {
        "nrc-cert-a": make_cert("nrc-cert-a", [NRC_HOST]),
        "nrc-cert-b": make_cert("nrc-cert-b", [NRC_HOST, NRC_ALIAS]),
        "nrc-cert-c": make_cert("nrc-cert-c", ["unrelated.smoke.test"]),
    }
    for n, (crt, key) in files.items():
        if upload(n, crt, key) != [200, 200]:
            fail("newrule-cert", f"could not upload {n}")
    open_dialog()
    opts = options()
    if [o[0] for o in opts] != [""] + NRC_CERTS:
        fail("newrule-cert", f"the field must list Automatic and every certificate, got {opts}")
    if not all("expires 20" in o[1] for o in opts[1:]):
        fail("newrule-cert", f"each option must show the expiry, got {opts}")
    if js("document.getElementById('nrCert').value") != "":
        fail("newrule-cert", "the default choice must be Automatic")
    if "matches the hostname" not in hint():
        fail("newrule-cert", f"the automatic hint is missing: {hint()!r}")

    pg.fill("#nrDomain", NRC_HOST + ", " + NRC_ALIAS)
    pg.wait_for_timeout(600)
    groups = js("[...document.querySelectorAll('#nrCert optgroup')].map(g => [g.label, [...g.querySelectorAll('option')].map(o => o.value)])")
    if len(groups) != 2 or groups[0][1] != ["nrc-cert-b"] or sorted(groups[1][1]) != ["nrc-cert-a", "nrc-cert-c"]:
        fail("newrule-cert", f"typing the hostnames must group the certificates that cover all of them first, got {groups}")
    pg.select_option("#nrCert", "nrc-cert-c")
    pg.wait_for_timeout(200)
    if "does not cover" not in hint() or not pg.is_visible("#nrCert"):
        fail("newrule-cert", f"a certificate that does not cover the hostname must warn, got {hint()!r}")
    if js("document.getElementById('nrCreate').disabled") or "disabled" in (js("document.getElementById('nrCreate').className") or ""):
        fail("newrule-cert", "the mismatch warning must not block creating the rule")
    pg.fill("#nrUpstream", "127.0.0.1:9")
    shot("newrule-cert-mismatch-light.png")
    theme(True)
    shot("newrule-cert-mismatch-dark.png")
    pg.set_viewport_size({"width": 390, "height": 844})
    pg.wait_for_timeout(300)
    shot("newrule-cert-mismatch-390.png")
    if js("document.documentElement.scrollWidth > window.innerWidth + 1"):
        fail("newrule-cert", "the dialog scrolls horizontally at 390px")
    pg.select_option("#nrCert", "nrc-cert-b")
    pg.wait_for_timeout(200)
    h = hint()
    if "does not cover" in h or NRC_HOST not in h or "turn off automatic certificate matching" not in h:
        fail("newrule-cert", f"a covering certificate must list its names, say what changes and not warn, got {h!r}")
    shot("newrule-cert-chosen-390.png")
    pg.set_viewport_size({"width": 1366, "height": 1000})
    shot("newrule-cert-chosen-dark.png")
    theme(False)
    shot("newrule-cert-chosen-light.png")

    # keyboard: the select takes the arrow keys
    pg.focus("#nrCert")
    pg.keyboard.press("Home")
    if js("document.getElementById('nrCert').value") != "":
        fail("newrule-cert", "the field is not operable with the keyboard")
    pg.select_option("#nrCert", "nrc-cert-b")

    # ---- 3. create with the choice: one request, the toast does not offer another certificate
    reqs = []
    pg.on("request", lambda r: reqs.append(r) if "/api/proxy/add" in r.url else None)
    pg.click("#nrCreate")
    pg.wait_for_selector("#nrToast.show", timeout=10000)
    toast = js("document.getElementById('nrToast').innerText")
    if NRC_HOST not in toast or "nrc-cert-b" not in toast:
        fail("newrule-cert", f"the success toast must name the certificate, got {toast!r}")
    if "Create certificate" in toast:
        fail("newrule-cert", "the toast must not offer to create a certificate when one was chosen")
    if len(reqs) != 1 or "certificate=nrc-cert-b" not in (reqs[0].post_data or ""):
        fail("newrule-cert", f"creation must be one request carrying the certificate, got {len(reqs)}")
    r = rule(NRC_HOST)
    to = (r or {}).get("TlsOptions") or {}
    pref = to.get("PreferredCertificate") or {}
    if pref.get(NRC_HOST) != "nrc-cert-b" or pref.get(NRC_ALIAS) != "nrc-cert-b" or not to.get("DisableSNI"):
        fail("newrule-cert", f"the rule must store the choice for the host and its alias and turn SNI matching off, got {to}")

    # ---- 4. a REAL handshake with SNI returns the chosen certificate
    if js("fetch('/api/cert/tls').then(r => r.json())") is not True:
        post("/api/cert/tls", {"set": "true"})
        pg.wait_for_timeout(1500)
    port = int(args.url.rsplit(":", 1)[1].split("/")[0]) + 1

    def served(sni):
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            with c.wrap_socket(s, server_hostname=sni) as t:
                return ssl.DER_cert_to_PEM_cert(t.getpeercert(True)).strip()

    want_b = open(files["nrc-cert-b"][0]).read().strip()
    if served(NRC_HOST) != want_b or served(NRC_ALIAS) != want_b:
        fail("newrule-cert", "the TLS handshake did not return the chosen certificate for the host and its alias")

    # ---- 5. a rule created without a choice: default TLS options, the certificate offer stays
    open_dialog()
    pg.fill("#nrDomain", NRC_PLAIN)
    pg.fill("#nrUpstream", "127.0.0.1:9")
    pg.wait_for_timeout(300)
    pg.click("#nrCreate")
    pg.wait_for_selector("#nrToast.show", timeout=10000)
    to = (rule(NRC_PLAIN) or {}).get("TlsOptions") or {}
    if to.get("DisableSNI") or to.get("PreferredCertificate"):
        fail("newrule-cert", f"a rule created without a choice must keep the default TLS options, got {to}")
    if "nrc-cert" in js("document.getElementById('nrToast').innerText"):
        fail("newrule-cert", "the toast of an automatic rule must not name a certificate")

    # ---- 6. an unknown certificate name creates nothing
    bad = post("/api/proxy/add", {"type": "host", "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false",
                                  "cred": "", "rootname": "nrc-bad.smoke.test", "certificate": "does-not-exist"})
    if not (isinstance(bad, dict) and bad.get("error")) or rule("nrc-bad.smoke.test"):
        fail("newrule-cert", f"an unknown certificate must be refused and nothing created, got {bad!r}")

    # ---- clean up
    for h in (NRC_HOST, NRC_PLAIN):
        post("/api/proxy/del", {"ep": h})
    for n in NRC_CERTS:
        js("async n => { await fetch('/api/cert/delete?domain=' + n, {method: 'POST', headers: {'X-CSRF-Token': document.querySelector('meta[name=\"zoraxy.csrf.Token\"]').content}}); }", n)
    pg.set_viewport_size({"width": 1366, "height": 800})
