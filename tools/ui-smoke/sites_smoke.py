"""Smoke scenario of the Sites pages audit fixes (Default Site, Stream Proxy, Redirection, Path routes, rule rename and creation,
rate limit, site editor sub views, HTTP Proxy list). Every check below failed before the fix. Loaded by smoke.py (exec in its
namespace: fail, current, settle, check_horizontal, args, os)."""

import json

SITES_HOSTS = ["sitesfix-a.demo.test", "sitesfix-b.demo.test"]


def sites_ui(pg, ctx):
    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: (x) => res({error: 'HTTP ' + x.status + ' ' + x.statusText}), dataType: 'json'}))""", [url, data])

    def is_err(r):
        return isinstance(r, dict) and bool(r.get("error"))

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=True)

    def host_names():
        return js("fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => l.map(x => x.RootOrMatchingDomain))")

    def contrast(sel, bg="#ffffff"):
        return js("""([sel, bg]) => {
            const el = document.querySelector(sel); if (!el) return null;
            const lum = c => { const m = c.match(/[\\d.]+/g).map(Number); const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
                return 0.2126 * f(m[0]) + 0.7152 * f(m[1]) + 0.0722 * f(m[2]); };
            const tmp = document.createElement('i'); tmp.style.color = bg; document.body.appendChild(tmp);
            const b = lum(getComputedStyle(tmp).color); tmp.remove();
            const a = lum(getComputedStyle(el).color), o = parseFloat(getComputedStyle(el).opacity);
            const hi = Math.max(a, b), lo = Math.min(a, b); return (hi + 0.05) / (lo + 0.05) * (o < 1 ? 0.5 : 1); }""", [sel, bg])

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    pg.set_viewport_size({"width": 1366, "height": 1000})
    theme(False)
    base = {"type": "host", "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false", "bpgtls": "false", "cred": "", "ssl": "false"}

    # ---------------------------------------------------------------- error answers are always valid JSON (root cause of "Request failed (HTTP 200)")
    current["page"] = "sites-api"
    for h in SITES_HOSTS:
        post("/api/proxy/del", {"ep": h})
    r = post("/api/proxy/add", dict(base, rootname=SITES_HOSTS[0]))
    if r != "OK":
        fail("sites", f"could not add {SITES_HOSTS[0]}: {r!r}")
    r = post("/api/proxy/vdir/add", {"type": "host", "endpoint": SITES_HOSTS[0], "path": "/b c!!", "domain": "not host", "reqTLS": "false", "skipValid": "false"})
    if not is_err(r) or str(r.get("error", "")).startswith("HTTP"):
        fail("sites", f"vdir add with an invalid prefix must answer a readable error, got {r!r}")
    r = post("/api/proxy/vdir/add", {"type": "host", "endpoint": SITES_HOSTS[0], "path": "/ok", "domain": "not host", "reqTLS": "false", "skipValid": "false"})
    if not is_err(r) or "valid host" not in str(r.get("error", "")):
        fail("sites", f"vdir add with an invalid target must say why, got {r!r}")

    # ---------------------------------------------------------------- hostnames: creation and rename
    current["page"] = "sites-hostnames"
    for bad in ("bad host!!", "http://a.test", "a" * 300, "a" * 64 + ".test", ""):
        r = post("/api/proxy/add", dict(base, rootname=bad))
        if not is_err(r):
            fail("validation", f"/api/proxy/add accepted the hostname {bad[:30]!r}: {r!r}")
    if any(("bad host" in n or "http://a.test" in n or len(n) > 100) for n in host_names()):
        fail("validation", "an invalid hostname ended up in the rule list")
    r = post("/api/proxy/add", dict(base, rootname="UPPER.Sitesfix.Test"))
    if r != "OK" or "upper.sitesfix.test" not in host_names():
        fail("validation", f"a mixed case hostname must be stored lower case: {r!r} {host_names()}")
    post("/api/proxy/del", {"ep": "upper.sitesfix.test"})
    r = post("/api/proxy/add", dict(base, rootname=SITES_HOSTS[0]))
    if not is_err(r):
        fail("validation", f"adding a rule for an existing host must be refused: {r!r}")
    for bad in ("bad host!!", "http://x.test", "", "a" * 300, SITES_HOSTS[0]):
        r = post("/api/proxy/setHostname", {"oldHostname": SITES_HOSTS[0], "newHostname": bad})
        if not is_err(r):
            fail("validation", f"setHostname accepted {bad[:30]!r}: {r!r}")
        if SITES_HOSTS[0] not in host_names():
            fail("validation", f"the rule vanished after a rename to {bad[:30]!r}")
            break
    r = post("/api/proxy/setHostname", {"oldHostname": SITES_HOSTS[0], "newHostname": SITES_HOSTS[1]})
    if r != "OK" or SITES_HOSTS[1] not in host_names() or SITES_HOSTS[0] in host_names():
        fail("validation", f"a valid rename must work: {r!r} {host_names()}")
    post("/api/proxy/setHostname", {"oldHostname": SITES_HOSTS[1], "newHostname": SITES_HOSTS[0]})

    # ---------------------------------------------------------------- Default Site
    current["page"] = "sites-defaultsite"
    for opt, val, ep in ((1, "not a host!!", "not a host!!"), (1, "", ""), (1, "x" * 500, "x" * 500), (2, "javascript:alert(1)", "127.0.0.1:9"), (2, "", "127.0.0.1:9"), (2, "example.com", "127.0.0.1:9")):
        r = post("/api/proxy/add", {"type": "root", "tls": "false", "ep": ep, "defaultSiteOpt": opt, "defaultSiteVal": val})
        if not is_err(r):
            fail("validation", f"default site option {opt} accepted {val[:30]!r}: {r!r}")
    js("openTabById('setroot')")
    pg.wait_for_timeout(800)
    pg.click("input[name=defaultsiteOption][value=proxy] >> xpath=..")
    pg.fill("#proxyRoot", "")
    pg.click("button:has-text('Apply Changes')")
    pg.wait_for_timeout(300)
    if not js("document.querySelector('#defaultSiteProxyOptions .defaultSiteError')"):
        fail("defaultsite", "an empty reverse proxy target shows no message")
    if js("document.querySelector('button[onclick^=setProxyRoot]').classList.contains('disabled')"):
        fail("defaultsite", "Apply Changes stays disabled after an empty submit")
    shot("sites-defaultsite-empty.png")
    pg.fill("#proxyRoot", "not a host!!")
    pg.click("button:has-text('Apply Changes')")
    pg.wait_for_timeout(300)
    shot("sites-defaultsite-bad-target.png")
    if "valid host" not in (js("(document.querySelector('#defaultSiteProxyOptions .defaultSiteError') || {}).innerText") or ""):
        fail("defaultsite", "an invalid reverse proxy target is not reported")
    if js("document.querySelector('button[onclick^=setProxyRoot]').classList.contains('disabled')"):
        fail("defaultsite", "Apply Changes is disabled after an invalid target")
    pg.click("input[name=defaultsiteOption][value=redirect] >> xpath=..")
    pg.fill("#redirectDomain", "javascript:alert(1)")
    pg.click("button:has-text('Apply Changes')")
    pg.wait_for_timeout(300)
    if not js("document.querySelector('#defaultSiteRedirectOptions .defaultSiteError')"):
        fail("defaultsite", "a javascript: redirect target is not reported")
    shot("sites-defaultsite-bad-redirect.png")
    js("initRootInfo()")
    pg.wait_for_timeout(600)

    # ---------------------------------------------------------------- Redirection
    current["page"] = "sites-redirect"
    for src, dst in (("loop.sitesfix.test", "loop.sitesfix.test"), ("a.sitesfix.test", "javascript:alert(1)"), ("bad url!!", "not a url"), ("b.sitesfix.test", "x" * 2500), ("c" * 500, "d.sitesfix.test")):
        r = post("/api/redirect/add", {"redirectUrl": src, "destUrl": dst, "forwardChildpath": "true", "redirectType": 307, "deviceType": "all"})
        if not is_err(r):
            fail("validation", f"/api/redirect/add accepted {src[:20]!r} -> {dst[:20]!r}: {r!r}")
    post("/api/redirect/delete", {"redirectUrl": "old.sitesfix.test"})
    r = post("/api/redirect/add", {"redirectUrl": "old.sitesfix.test", "destUrl": "shop.sitesfix.test", "forwardChildpath": "true", "redirectType": 307, "deviceType": "all"})
    if r != "OK":
        fail("redirect", f"a valid redirection rule was refused: {r!r}")
    r = post("/api/redirect/add", {"redirectUrl": "old.sitesfix.test", "destUrl": "other.sitesfix.test", "forwardChildpath": "true", "redirectType": 307, "deviceType": "all"})
    if not is_err(r):
        fail("validation", f"adding a redirection for an existing source must not overwrite it: {r!r}")
    js("openTabById('redirectset')")
    pg.wait_for_timeout(800)
    if js("document.querySelectorAll('#redirectionRuleList tr').length") != 1:
        fail("redirect", "the redirection list does not show exactly the one valid rule")
    # duplicate through the form: an error message, no success banner, the typed values stay
    pg.fill("#rurl", "old.sitesfix.test")
    pg.fill("input[name=destination-url]", "other.sitesfix.test")
    pg.click("#addRedirectBtn")
    pg.wait_for_timeout(600)
    if js("document.getElementById('ruleAddSucc').offsetParent !== null"):
        fail("redirect", "a duplicate redirection source shows the success banner")
    if pg.input_value("#rurl") != "old.sitesfix.test":
        fail("redirect", "the form was cleared although the add failed")
    shot("sites-redirect-duplicate.png")
    # rapid double click adds one rule only
    pg.fill("#rurl", "dbl.sitesfix.test")
    pg.fill("input[name=destination-url]", "dest.sitesfix.test")
    pg.dblclick("#addRedirectBtn")
    pg.wait_for_timeout(900)
    n = js("[...document.querySelectorAll('#redirectionRuleList tr')].filter(t => t.innerText.includes('dbl.sitesfix.test')).length")
    if n != 1:
        fail("redirect", f"a double click created {n} rules")
    # labels
    if "Forward Pathname" not in js("document.querySelector('#redirectset table thead').innerText"):
        fail("text", "the Redirection column should be called Forward Pathname")
    if js("[...document.querySelectorAll('#redirectionRuleList button')].filter(b => !b.getAttribute('aria-label')).length"):
        fail("a11y", "a Redirection row button has no aria-label")
    if js("[...document.querySelectorAll('#redirectset input[type=text]')].filter(i => !i.getAttribute('aria-label') && !i.labels.length).length"):
        fail("a11y", "a Redirection form input has no label")
    # deleting asks first (a ZxUI dialog, not window.confirm)
    pg.click("#redirectionRuleList tr:has-text('dbl.sitesfix.test') button[title='Delete redirection rule']")
    pg.wait_for_timeout(300)
    if not js("!!document.querySelector('.zx-dialog, .zx-modal, [role=alertdialog], [role=dialog].zx-confirm')"):
        fail("redirect", "deleting a redirection rule shows no confirmation dialog")
    js("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'}))")
    pg.wait_for_timeout(300)
    for s in ("old.sitesfix.test", "dbl.sitesfix.test"):
        post("/api/redirect/delete", {"redirectUrl": s})

    # ---------------------------------------------------------------- Stream Proxy
    current["page"] = "sites-stream"
    for old in js("fetch('/api/streamprox/config/list').then(r => r.json()).then(l => l.filter(c => c.Name.startsWith('sitesfix')).map(c => c.UUID))"):
        post("/api/streamprox/config/delete", {"uuid": old})
    good = {"name": "sitesfix-ssh", "listenAddr": ":29218", "proxyAddr": "127.0.0.1:22", "useTCP": "true", "useUDP": "false", "timeout": 10, "proxyProtocolVersion": 0}
    r = post("/api/streamprox/config/add", good)
    if is_err(r):
        fail("stream", f"a valid stream proxy was refused: {r!r}")
    for label, patch in (("empty name", {"name": ""}), ("garbage listen", {"name": "sitesfix-x", "listenAddr": "not an address"}), ("port 0", {"name": "sitesfix-x", "listenAddr": ":0"}),
                         ("port 99999", {"name": "sitesfix-x", "listenAddr": ":99999"}), ("duplicate port", {"name": "sitesfix-x"}), ("duplicate name", {"listenAddr": ":29219"}),
                         ("garbage target", {"name": "sitesfix-x", "listenAddr": ":29219", "proxyAddr": "nope"}), ("no protocol", {"name": "sitesfix-x", "listenAddr": ":29219", "useTCP": "false"}),
                         ("long name", {"name": "n" * 400, "listenAddr": ":29219"})):
        r = post("/api/streamprox/config/add", dict(good, **patch))
        if not is_err(r):
            fail("validation", f"stream proxy add accepted {label}: {r!r}")
    js("openTabById('streamproxy')")
    pg.wait_for_timeout(900)
    rows = js("document.querySelectorAll('#proxyTable tbody tr.streamproxConfig').length")
    if rows != 1:
        fail("stream", f"{rows} stream proxy rows, expected 1 (invalid configs were created)")
    c = contrast("#proxyTable .statusText")
    if c is not None and c < 4.5:
        fail("contrast", f"the Running / Stopped status text has contrast {c:.2f}:1")
    if js("[...document.querySelectorAll('#proxyTable tbody button')].filter(b => !b.getAttribute('aria-label')).length"):
        fail("a11y", "a Stream Proxy row button has no aria-label")
    if js("[...document.querySelectorAll('#streamProxyForm input[type=text]')].filter(i => i.offsetParent && !i.getAttribute('aria-label') && !i.labels.length).length"):
        fail("a11y", "a Stream Proxy form input has no label")
    shot("sites-stream-list.png")
    # invalid input through the form keeps what was typed and reports the reason
    pg.fill("#streamProxyForm input[name=name]", "sitesfix-form")
    pg.fill("#streamProxyForm input[name=listenAddr]", "not an address")
    pg.fill("#streamProxyForm input[name=proxyAddr]", "127.0.0.1:22")
    js("$('#streamProxyForm input[name=useTCP]').parent().checkbox('set checked')")
    pg.click("#addStreamProxyButton")
    pg.wait_for_timeout(600)
    if pg.input_value("#streamProxyForm input[name=listenAddr]") != "not an address":
        fail("stream", "the form was cleared although the add failed")
    if js("document.querySelectorAll('#proxyTable tbody tr.streamproxConfig').length") != 1:
        fail("stream", "an invalid config was added through the form")
    # a double click on a valid config creates one
    pg.fill("#streamProxyForm input[name=listenAddr]", ":29219")
    pg.dblclick("#addStreamProxyButton")
    pg.wait_for_timeout(900)
    if js("document.querySelectorAll('#proxyTable tbody tr.streamproxConfig').length") != 2:
        fail("stream", "a double click on Create did not create exactly one config")
    # delete asks first
    pg.click("#proxyTable tbody tr:has-text('sitesfix-form') button[title='Delete Config']")
    pg.wait_for_timeout(300)
    if js("document.querySelectorAll('#proxyTable tbody tr.streamproxConfig').length") != 2:
        fail("stream", "Delete removed the config without asking")
    js("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'}))")
    pg.wait_for_timeout(300)
    # edit scrolls the form into view
    pg.click("#proxyTable tbody tr:has-text('sitesfix-ssh') button[title='Edit Config']")
    pg.wait_for_timeout(900)
    if not js("(() => { const r = document.getElementById('addproxyConfig').getBoundingClientRect(); return r.top < innerHeight && r.bottom > 0; })()"):
        fail("stream", "Edit does not bring the form into view")
    check_horizontal(pg, "Stream Proxy")
    for u in js("fetch('/api/streamprox/config/list').then(r => r.json()).then(l => l.filter(c => c.Name.startsWith('sitesfix')).map(c => c.UUID))"):
        post("/api/streamprox/config/delete", {"uuid": u})

    # ---------------------------------------------------------------- rate limit values
    current["page"] = "sites-ratelimit"
    for v in ("99999999999", "0", "-5", "1.5"):
        r = post("/api/proxy/edit", {"rootname": SITES_HOSTS[0], "rate": "true", "ratenum": v})
        if not is_err(r):
            fail("validation", f"/api/proxy/edit accepted the rate limit {v!r}: {r!r}")

    # ---------------------------------------------------------------- site editor: sub view title, Esc goes back one level, WAF help
    current["page"] = "sites-editor"
    orig_pol = js("fetch('/api/waf/policy').then(r => r.json())")
    post("/api/waf/policy", {"policy": json.dumps(dict(orig_pol, Enabled=True, DefaultMode="block"))})
    js("openTabById('httprp')")
    pg.wait_for_timeout(900)
    if "WAF (global)" not in js("document.getElementById('httpProxyList').innerText"):
        fail("list", "the Protection column shows no WAF although the global WAF is on and the rule follows it")
    js("""h => fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => { initHttpProxyRuleEditorModal(l.filter(x => x.RootOrMatchingDomain === h)[0]); })""", SITES_HOSTS[0])
    pg.wait_for_selector("#httprpEditModalWrapper .hrp-main", state="visible", timeout=8000)
    pg.wait_for_timeout(800)
    help_txt = js("document.getElementById('hrpProtHelp').innerText")
    if "off until you enable it" in help_txt or "currently blocking" not in help_txt:
        fail("text", f"the WAF help text does not reflect the global WAF state: {help_txt!r}")
    # renaming to an invalid hostname through the editor: a message, the old name stays, the rule stays
    pg.click("#httprpEditModalWrapper .downstream_primary_hostname_edit_btn")
    pg.fill("#httprpEditModalWrapper .downstream_primary_hostname_edit_input input", "bad host!!")
    pg.click("#httprpEditModalWrapper .saveDownstreamHostnameBtn")
    pg.wait_for_timeout(700)
    if SITES_HOSTS[0] not in host_names():
        fail("editor", "the rule vanished after an invalid rename in the editor")
    if SITES_HOSTS[0] not in js("document.getElementById('hrpTitleHost').innerText"):
        fail("editor", "the editor title shows the invalid hostname")
    shot("sites-editor-rename-bad.png")
    pg.click("#httprpEditModalWrapper .cancelDownstreamHostnameBtn")
    js("HrpEditor.setMode('advanced')")
    pg.click("#httprpEditModal .hrpedit_menu_item[cfgpage=security]")
    pg.wait_for_timeout(500)
    shot("sites-editor-security.png")
    js("HrpEditor.setMode('easy')")
    js("editUpstreams(document.getElementById('httprpEditModal').getAttribute('editing-host') ? decodeURIComponent(document.getElementById('httprpEditModal').getAttribute('editing-host')) : '')")
    pg.wait_for_timeout(1200)
    title = js("document.querySelector('#httprpEditModal .editor_side_title').innerText")
    if "Upstreams" not in title or SITES_HOSTS[0] not in title:
        fail("editor", f"the sub view has no title with the host, got {title!r}")
    shot("sites-editor-subview.png")
    frame = [f for f in pg.frames if "upstreams.html" in f.url]
    if not frame:
        fail("editor", "the Upstreams sub view did not load")
    else:
        frame[0].locator("body").click(position={"x": 5, "y": 5})
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(800)
        if not js("document.getElementById('httprpEditModalWrapper').offsetParent !== null && getComputedStyle(document.getElementById('httprpEditModal')).display !== 'none'"):
            fail("editor", "Esc inside a sub view closed the whole editor")
        if js("getComputedStyle(document.querySelector('#httprpEditModal .editor_side_wrapper')).display") != "none":
            fail("editor", "Esc inside a sub view did not go back to the site settings")
    pg.keyboard.press("Escape")
    pg.wait_for_timeout(600)
    if js("document.getElementById('httprpEditModalWrapper').offsetParent !== null"):
        js("document.querySelector('#httprpEditModal .httpProxyEditClosePC').click()")
        pg.wait_for_timeout(600)
    post("/api/waf/policy", {"policy": json.dumps(orig_pol)})

    # ---------------------------------------------------------------- Path routes: the real reason, not "Request failed (HTTP 200)"
    current["page"] = "sites-vdir"
    js("openTabById('vdir')")
    pg.wait_for_timeout(700)
    js("h => { $('#vdirBaseRoutingRule').val(h).trigger('change'); }", SITES_HOSTS[0])
    pg.wait_for_timeout(700)
    pg.fill("#virtualDirectoryPath", "/b c!!")
    pg.fill("#virtualDirectoryDomain", "not host")
    js("addVdirToHost()")
    pg.wait_for_timeout(900)
    msg = js("document.getElementById('messageBox') ? document.getElementById('messageBox').innerText : ''")
    toast_txt = js("(document.querySelector('.zx-toast-region') || document.body).innerText")
    if "Request failed (HTTP" in toast_txt or "Request failed (HTTP" in msg:
        fail("vdir", "a failed path route add still reports 'Request failed (HTTP 200)'")
    if "spaces" not in (msg + toast_txt):
        fail("vdir", f"the real reason is not shown for an invalid path prefix: {msg!r}")
    shot("sites-vdir-bad.png")

    # ---------------------------------------------------------------- HTTP Proxy list
    current["page"] = "sites-list"
    js("openTabById('httprp')")
    pg.wait_for_timeout(900)
    up_nowrap = js("""[...document.querySelectorAll('#httpProxyList .ptUps .ptUp')].every(a => a.getBoundingClientRect().height < 30)""")
    if not up_nowrap:
        fail("layout", "an upstream address wraps inside the port")
    shot("sites-httprp-list.png")
    pg.set_viewport_size({"width": 390, "height": 844})
    pg.wait_for_timeout(500)
    check_horizontal(pg, "HTTP Proxy 390")
    clipped = js("(() => { const s = document.getElementById('ptSeg'); return s ? s.scrollWidth - s.clientWidth : 0; })()")
    if clipped > 2:
        fail("layout", f"the status filter group is clipped by {clipped}px at 390px")
    shot("sites-httprp-list-390.png")
    pg.set_viewport_size({"width": 1366, "height": 1000})

    # ---------------------------------------------------------------- dark theme: red outline button and footer text
    current["page"] = "sites-dark"
    theme(True)
    js("openTabById('streamproxy')")
    pg.wait_for_timeout(700)
    shot("sites-stream-dark.png")
    theme(False)

    # ---------------------------------------------------------------- no console warning from the plugin iframe
    current["page"] = "sites-console"
    warns = []
    p2 = ctx.new_page()
    p2.on("console", lambda m: warns.append(m.text) if m.type in ("warning", "error") else None)
    p2.goto(args.url + "/", wait_until="networkidle")
    p2.wait_for_timeout(1000)
    p2.close()
    for w in warns:
        if "Unrecognized feature" in w:
            fail("console", "the plugin iframe still has an invalid allow attribute: " + w)

    current["page"] = "sites-cleanup"
    for h in SITES_HOSTS:
        post("/api/proxy/del", {"ep": h})
