"""Smoke scenario of the fallback-certificate diagnostics (Tools > Encrypted Client Hello card "Fallback certificate served for these
names", the info line under "Certificate for each hostname", GET /api/ech/fallbacks). exec()'d by smoke.py (namespace: fail, current,
args, os, re); run alone with --ech-fallback-only. Needs the instance's HTTPS proxy port at UI port + 1 (as tools/ui-smoke/run.sh starts
it) and openssl on the PATH. ECH stays OFF: that is the situation of a browser using an ECH config of another provider.

Checks: with no such handshake the card says "Nothing has reached the fallback certificate" and the TLS tab shows no info line; REAL TLS
handshakes with SNI cloudflare-ech.com (python ssl and openssl s_client), an unknown name, a name that is a proxy rule (never listed) and
no SNI (openssl -noservername) are classified (ECH outer name of another provider / unknown / no SNI); the certificate served for every
name is unchanged by the diagnostics (the rule host gets the self-signed localhost fallback like any other name here, the outer name gets
the same one); the card shows each row with class, count, last seen and a next step; the TLS tab shows the one info line with a link to
the ECH page. Screenshots (light, dark, 390px) are written to --out."""

import socket
import ssl
import subprocess

EF_HOST = "ech-fb-rule.smoke.test"


def ech_fallback_ui(pg, ctx):
    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: x => res({error: 'HTTP ' + x.status}), dataType: 'json'}))""", [url, data])

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    def shot(name, sel):
        pg.locator(sel).screenshot(path=os.path.join(args.out, name))

    port = int(args.url.rsplit(":", 1)[1].split("/")[0]) + 1
    current["page"] = "ech-fallback"
    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)
    post("/api/proxy/del", {"ep": EF_HOST})
    if js("fetch('/api/cert/tls').then(r => r.json())") is not True:
        post("/api/cert/tls", {"set": "true"})
        pg.wait_for_timeout(1500)
    r = post("/api/proxy/add", {"type": "host", "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false", "cred": "", "rootname": EF_HOST})
    if isinstance(r, dict) and r.get("error"):
        fail("ech-fallback", f"could not create the rule: {r}")

    def served(sni):
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            with c.wrap_socket(s, server_hostname=sni) as t:
                return ssl.DER_cert_to_PEM_cert(t.getpeercert(True)).strip()

    def openssl_served(args_):
        p = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{port}"] + args_ + ["-showcerts"], input=b"", capture_output=True, timeout=15)
        m = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", p.stdout, re.S)
        return m.group(0).decode().strip() if m else None

    def table():
        return js("fetch('/api/ech/fallbacks').then(r => r.json())")

    def open_ech():
        js("openTabById('ech')")
        pg.wait_for_selector("#echFbCard", timeout=8000)
        pg.wait_for_timeout(900)

    def open_tls_tab():
        js("openTabById('httprp')")
        pg.wait_for_timeout(800)
        js("""h => fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => { initHttpProxyRuleEditorModal(l.filter(x => x.RootOrMatchingDomain === h)[0]); })""", EF_HOST)
        pg.wait_for_selector("#httprpEditModalWrapper .hrp-main", state="visible", timeout=8000)
        pg.wait_for_timeout(900)
        pg.click("#hrpMode [data-value='advanced']")  # the per-hostname table is an Advanced card
        pg.wait_for_timeout(500)
        js("document.getElementById('hrpTab-tls').click()")
        pg.wait_for_timeout(900)

    # ---- 1. empty state (nothing probed yet)
    t0 = table()
    if t0.get("Entries"):
        fail("ech-fallback", f"the table must start empty on a fresh instance, got {t0}")
    open_ech()
    if "Nothing has reached the fallback certificate" not in js("document.getElementById('echFbEmpty').innerText"):
        fail("ech-fallback", "the empty state text is missing")
    shot("ech-fallback-empty-light.png", "#echFbCard")
    open_tls_tab()
    if js("$('#httprpEditModalWrapper .hrp-echnote').is(':visible')"):
        fail("ech-fallback", "the TLS info line must be hidden while no foreign ECH name was seen")
    if js("(() => { const e = document.querySelector('#httprpEditModalWrapper .hrp-echnote'); return e.getBoundingClientRect().height; })()") > 1:
        fail("ech-fallback", "the hidden info line must not use any space")

    # ---- 2. real handshakes
    before_rule = served(EF_HOST)  # a rule host: never listed, whatever certificate it gets
    outer = served("cloudflare-ech.com")
    unknown = served("scanner.smoke.test")
    for _ in range(2):
        served("cloudflare-ech.com")
    o2 = openssl_served(["-servername", "cloudflare-ech.com"])
    o3 = openssl_served(["-noservername"])
    if not o2 or not o3:
        fail("ech-fallback", "openssl s_client could not connect")
    if outer != unknown or o2 != outer or o3 != outer:
        fail("ech-fallback", "the certificate served for the outer name, an unknown name and no SNI must be the same fallback certificate")
    if served("cloudflare-ech.com") != outer or served(EF_HOST) != before_rule:
        fail("ech-fallback", "the served certificates changed between handshakes")
    t = table()
    ents = {e["Name"]: e for e in t["Entries"]}
    want = {"cloudflare-ech.com": ("foreign-ech", 5), "scanner.smoke.test": ("unknown", 1), "": ("no-sni", 1)}
    for n, (cls, cnt) in want.items():
        e = ents.get(n)
        if not e or e["Class"] != cls or e["Count"] != cnt or e["LastSeen"] < e["FirstSeen"]:
            fail("ech-fallback", f"entry {n!r}: want {cls} x{cnt}, got {e}")
    if EF_HOST in ents:
        fail("ech-fallback", "a name that matches a proxy rule must not be listed")
    if not t["HasForeignECH"] or t["Entries"][0]["Name"] != "cloudflare-ech.com":
        fail("ech-fallback", "the foreign ECH name must be flagged and listed first")

    # ---- 3. the card
    open_ech()
    txt = js("document.getElementById('echFbCard').innerText")
    for s in ("Fallback certificate served for these names", "ECH outer name of another provider", "5 handshakes", "last seen", "cloudflare-ech.com",
              "Unknown host / scanner / IP access", "No SNI", "override or block the HTTPS record"):
        if s not in txt:
            fail("ech-fallback", f"the card lacks {s!r}: {txt!r}")
    if js("document.getElementById('echFbEmpty').offsetParent !== null"):
        fail("ech-fallback", "the empty state must be hidden when there are rows")
    shot("ech-fallback-card-light.png", "#echFbCard")
    theme(True)
    shot("ech-fallback-card-dark.png", "#echFbCard")
    pg.set_viewport_size({"width": 390, "height": 844})
    pg.wait_for_timeout(400)
    shot("ech-fallback-card-390.png", "#echFbCard")
    if js("document.documentElement.scrollWidth > window.innerWidth + 1"):
        fail("ech-fallback", "the ECH page scrolls horizontally at 390px")
    if js("(() => { const c = document.getElementById('echFbCard'); return c.scrollWidth > c.clientWidth + 1; })()"):
        fail("ech-fallback", "the card overflows its box at 390px")
    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)

    # ---- 4. the TLS tab info line
    open_tls_tab()
    if not js("$('#httprpEditModalWrapper .hrp-echnote').is(':visible')"):
        fail("ech-fallback", "the info line must show once a foreign ECH name was seen")
    note = js("document.querySelector('#httprpEditModalWrapper .hrp-echnote').innerText")
    if "name you cannot choose a certificate for" not in note or "Encrypted Client Hello" not in note:
        fail("ech-fallback", f"info line text: {note!r}")
    if js("document.querySelectorAll('#httprpEditModalWrapper .hrp-echnote').length") != 1:
        fail("ech-fallback", "there must be exactly one info line")
    shot("ech-fallback-tlsline-light.png", "#httprpEditModalWrapper .hrp-card[data-hrp-card='certs']")
    theme(True)
    shot("ech-fallback-tlsline-dark.png", "#httprpEditModalWrapper .hrp-card[data-hrp-card='certs']")
    pg.set_viewport_size({"width": 390, "height": 844})
    pg.wait_for_timeout(400)
    shot("ech-fallback-tlsline-390.png", "#httprpEditModalWrapper .hrp-card[data-hrp-card='certs']")
    if js("document.documentElement.scrollWidth > window.innerWidth + 1"):
        fail("ech-fallback", "the TLS tab scrolls horizontally at 390px")
    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)
    # the link opens the ECH page
    js("document.querySelector('#httprpEditModalWrapper .hrp-echnote a').click()")
    pg.wait_for_timeout(900)
    if js("location.hash") != "#ech":
        fail("ech-fallback", f"the link must open the ECH page, hash is {js('location.hash')!r}")

    post("/api/proxy/del", {"ep": EF_HOST})
    pg.set_viewport_size({"width": 1366, "height": 800})
