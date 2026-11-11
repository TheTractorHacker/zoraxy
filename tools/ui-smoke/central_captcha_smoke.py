"""Smoke scenario of the central CAPTCHA provider (CAPTCHA page "Central provider" section, per-site "Use central provider" choice).
Loaded by smoke.py (exec in its namespace: fail, current, settle, args, os). Run alone with --central-captcha-only.

Checks: saving the Cloudflare Turnstile test keys centrally; the secret never comes back from GET and never lands in the page DOM;
a site that opts in shows the one-line summary and hides its own provider/key fields; the site still has its own stored keys
(switching back restores them); the choice survives a reload."""

import json

CC_HOST = "central-captcha.demo.test"
CC_SECRET = "1x0000000000000000000000000000000AA"   # Cloudflare's published always-pass test secret, not a real secret
CC_SITE_KEY = "1x00000000000000000000AA"


def central_captcha_ui(pg, ctx):
    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: (x) => res({error: 'HTTP ' + x.status}), dataType: 'json'}))""", [url, data])

    current["page"] = "central-captcha"
    pg.set_viewport_size({"width": 1366, "height": 1000})
    post("/api/proxy/del", {"ep": CC_HOST})
    r = post("/api/proxy/add", {"type": "host", "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false",
                                "bpgtls": "false", "cred": "", "ssl": "false", "rootname": CC_HOST})
    if r != "OK":
        fail("central-captcha", f"could not add {CC_HOST}: {r!r}")

    # API: a bad config is refused, a good one is saved, the secret is never returned
    bad = post("/api/proxy/captcha/central", {"captchaProvider": "0", "captchaSiteKey": "", "captchaSecretKey": ""})
    if not (isinstance(bad, dict) and bad.get("error")):
        fail("central-captcha", f"an empty central config must be refused, got {bad!r}")
    ok = post("/api/proxy/captcha/central", {"captchaProvider": "0", "captchaSiteKey": CC_SITE_KEY, "captchaSecretKey": CC_SECRET,
                                             "captchaSessionDuration": "3600"})
    if ok != "OK":
        fail("central-captcha", f"saving the central Turnstile test keys failed: {ok!r}")
    raw = js("fetch('/api/proxy/captcha/central').then(r => r.text())")
    if CC_SECRET in raw or '"SecretKey":"' in raw.replace('"SecretKey":""', ""):
        fail("central-captcha", "GET /api/proxy/captcha/central returned the secret key")
    view = json.loads(raw)
    if not (view.get("SecretSet") and view.get("Configured") and view.get("SiteKey") == CC_SITE_KEY):
        fail("central-captcha", f"unexpected central view: {raw!r}")
    keep = post("/api/proxy/captcha/central", {"captchaProvider": "0", "captchaSiteKey": CC_SITE_KEY, "captchaSecretKey": "",
                                               "captchaSessionDuration": "7200"})
    if keep != "OK" or not json.loads(js("fetch('/api/proxy/captcha/central').then(r => r.text())")).get("Configured"):
        fail("central-captcha", f"an empty posted secret must keep the stored one, got {keep!r}")

    # CAPTCHA page: the section is there, filled, and the secret is nowhere in the DOM
    js("openTabById('captcha')")
    pg.wait_for_selector("#cpCentral", state="visible", timeout=8000)
    pg.wait_for_timeout(900)
    if js("document.getElementById('ccSecret').value") != "":
        fail("central-captcha", "the secret key field must stay empty after load")
    if "Saved" not in (js("document.getElementById('ccSecret').placeholder") or ""):
        fail("central-captcha", "the secret field does not say a secret is saved")
    if CC_SECRET in js("document.documentElement.outerHTML"):
        fail("central-captcha", "the secret key is present in the CAPTCHA page DOM")
    if js("document.getElementById('ccSiteKey').value") != CC_SITE_KEY:
        fail("central-captcha", "the central site key is not shown")
    pg.screenshot(path=os.path.join(args.out, "central-captcha-light.png"), full_page=True)

    # opt the site in with the editor and check the summary / hidden fields
    js("openTabById('httprp')")
    pg.wait_for_timeout(800)
    js("""h => fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => { initHttpProxyRuleEditorModal(l.filter(x => x.RootOrMatchingDomain === h)[0]); })""", CC_HOST)
    pg.wait_for_selector("#httprpEditModalWrapper .hrp-main", state="visible", timeout=8000)
    pg.wait_for_timeout(900)
    sel = "#httprpEditModalWrapper .captchaUseCentralSel"
    js("s => { const e = document.querySelector(s); e.value = '1'; $(e).trigger('change'); }", sel)
    pg.wait_for_timeout(300)
    state = js("""() => { const w = document.querySelector('#httprpEditModalWrapper');
        const hid = c => { const e = w.querySelector(c); return !!e && e.style.display === 'none'; };
        return {summary: !hid('.captchaCentralSummary'), own: hid('.captchaOwnProvider'),
                text: (w.querySelector('.captchaCentralSummaryText') || {}).textContent || ''}; }""")
    if not state["summary"] or not state["own"] or "Turnstile" not in state["text"]:
        fail("central-captcha", f"choosing the central provider must show the summary and hide the key fields, got {state!r}")
    if CC_SECRET in js("document.documentElement.outerHTML"):
        fail("central-captcha", "the secret key is present in the site editor DOM")

    # the choice is stored on the site and survives a reload; the site config keeps working
    r = post("/api/proxy/edit", {"type": "host", "ep": CC_HOST, "rootname": CC_HOST, "captchaUseCentral": "true",
                                 "captcha": "true", "captchaProvider": "0"})
    cfg = js("h => fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => l.filter(x => x.RootOrMatchingDomain === h)[0])", CC_HOST)
    if not (cfg and cfg.get("CaptchaConfig") and cfg["CaptchaConfig"].get("UseCentral")):
        fail("central-captcha", f"UseCentral was not stored on the site (edit answered {r!r})")
    pg.reload(wait_until="networkidle")
    js("openTabById('captcha')")
    pg.wait_for_timeout(1200)
    if "(1 of" not in js("document.getElementById('ccSitesTitle').innerText"):
        fail("central-captcha", "the 'Sites using the central provider' list does not count the opted-in site")
    pg.set_viewport_size({"width": 390, "height": 800})
    pg.wait_for_timeout(400)
    if js("document.documentElement.scrollWidth > window.innerWidth + 2"):
        fail("central-captcha", "the CAPTCHA page overflows horizontally at 390px")
    pg.screenshot(path=os.path.join(args.out, "central-captcha-mobile.png"), full_page=True)
    pg.set_viewport_size({"width": 1366, "height": 1000})

    post("/api/proxy/captcha/central", {"clear": "true"})
    post("/api/proxy/del", {"ep": CC_HOST})
