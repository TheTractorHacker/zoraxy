#!/usr/bin/env python3
"""Zoraxy admin UI smoke test (Playwright, headless Chromium).

Opens every menu page of the admin UI (light and dark theme), fails on
JavaScript errors, console errors, failed or 4xx/5xx requests and pages whose
component did not load, takes a screenshot per page, and checks that the left
navigation scrolls on its own (mouse wheel over the nav must scroll the nav,
not the page) on a short desktop viewport and on a phone-sized viewport.

Usage:  smoke.py [--url http://127.0.0.1:8000] [--out DIR] [--allow REGEX ...]
Run it against a throw-away instance started with -noauth (see run.sh).
Exit code 0 = pass, 1 = failures.
"""
import argparse
import os
import re
import sys

from playwright.sync_api import sync_playwright

ap = argparse.ArgumentParser()
ap.add_argument("--url", default=os.environ.get("ZORAXY_URL", "http://127.0.0.1:8000"))
ap.add_argument("--out", default=os.environ.get("SMOKE_OUT", os.path.expanduser("~/ui-smoke-shots")))
ap.add_argument("--no-page-sweep", action="store_true", help="skip the per-tab screenshot sweep (faster; for focused runs on a busy machine)")
ap.add_argument("--i18n-only", action="store_true", help="run only the multi-language scenario")
ap.add_argument("--zrok-fake", default=os.environ.get("SMOKE_ZROK_FAKE", ""), help="path of a fake zrok script; enables the zrok flow (the instance needs -allow_external_tools)")
ap.add_argument("--allow", action="append", default=[], help="regex of messages whose failure is tolerated")
args = ap.parse_args()
os.makedirs(args.out, exist_ok=True)

# Offline-tolerant: external fetches (plugin store, update check, ...) may fail in a sandbox.
allow = [re.compile(a) for a in args.allow] + [
    re.compile(r"favicon"),
    re.compile(r"ERR_ABORTED"),  # a navigation cancelled the in-flight polling requests of the previous page

    re.compile(r"ERR_ABORTED"),  # a request cancelled by a reload / page switch is not a failure
    re.compile(r"ERR_(NAME_NOT_RESOLVED|INTERNET_DISCONNECTED|CONNECTION)"),
    re.compile(r"429.*/api/updater/check|429 \(Too Many Requests\).*/api/updater/check"),  # GitHub unauthenticated quota exhausted: the updater reports it as 429 by design
]
failures = []
current = {"page": "init"}


def fail(kind, msg):
    s = f"[{current['page']}] {kind}: {msg}"
    if any(a.search(s) for a in allow):
        print("  (tolerated) " + s)
        return
    if s not in failures:
        failures.append(s)
        print("  FAIL " + s)


def settle(pg, ms=700):
    pg.wait_for_timeout(ms)
    try:
        pg.wait_for_load_state("networkidle", timeout=5000)
    except Exception:
        pass


def hoverpoint(pg, sel="#mainmenu"):
    return pg.evaluate("""sel => { const r = document.querySelector(sel).getBoundingClientRect();
        const top = Math.max(r.top, 60), bot = Math.min(r.bottom, innerHeight);
        return {x: r.left + Math.min(r.width, 200) / 2, y: (top + bot) / 2} }""", sel)


def check_horizontal(pg, label):
    ov = pg.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    if ov > 2:
        fail("layout", f"{label}: page overflows horizontally by {ov}px")


class FakeOIDC:
    """Minimal OpenID Provider for the provider-manager smoke test: discovery + empty JWKS only."""

    def __init__(self, port):
        import http.server
        import json as _json
        import threading
        holder = {}

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path.endswith("/.well-known/openid-configuration"):
                    base, issuer = holder["base"], holder["base"] + "/"
                    body = {"issuer": issuer, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token",
                            "userinfo_endpoint": base + "/userinfo", "jwks_uri": base + "/jwks",
                            "code_challenge_methods_supported": ["S256"], "id_token_signing_alg_values_supported": ["RS256"],
                            "grant_types_supported": ["authorization_code", "refresh_token"], "scopes_supported": ["openid", "profile", "email", "offline_access"]}
                elif self.path == "/jwks":
                    body = {"keys": []}
                else:
                    body = {"ok": True}
                raw = _json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)  # port 0 = any free port
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.issuer = self.base + "/"
        holder["base"] = self.base
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()

def serve_upstream():
    """A tiny local upstream (200 OK) for the connection test of the new-rule dialog."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        do_HEAD = do_GET

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


API = """([u, d, m]) => new Promise(res => $.cjax({url: u, method: m || 'POST', data: d, success: res, error: res}))"""


def proxy_ux(pg, ctx):
    """Navigation structure, Quick Start dismissal, HTTP proxy table (seeded with 36 rules), multi-select, filters,
    sorting, status pill, bulk preview and the New proxy rule dialog."""
    out = lambda n: os.path.join(args.out, n)
    pg.set_viewport_size({"width": 1366, "height": 900})

    # ---- navigation: structure, icons, collapse, migration ----
    current["page"] = "nav-structure"
    pg.evaluate("openTabById('status')")
    settle(pg, 400)
    groups = pg.eval_on_selector_all("#mainmenu .menugroup-items", "els => els.map(e => e.id.replace('group-', ''))")
    if groups != ["proxy", "security", "certs", "observe", "tools", "system"]:
        fail("nav", f"unexpected nav groups {groups}")
    missing = pg.evaluate("""() => [...document.querySelectorAll('#mainmenu a.item[tag]')].filter(a => {
        const i = a.querySelector(':scope > i.icon'); if (!i) return true;
        const c = getComputedStyle(i, '::before').content; return !c || c === 'none' || c === 'normal' || c === '""'; }).map(a => a.getAttribute('tag'))""")
    if missing:
        fail("nav", f"menu items without a rendered icon: {missing}")
    for tab in ("status", "httprp", "setroot", "redirectset", "vdir", "streamproxy", "globalsettings", "rules", "seccenter", "waf", "access",
                "trustproxy", "sso", "cert", "acme", "stats", "utm", "webserv", "networktool", "iface", "utils", "cluster", "fleet", "apitokens", "updater"):
        if pg.locator(f"#mainmenu a.item[tag='{tab}']").count() != 1:
            fail("nav", f"menu item for tab {tab} missing or duplicated")
    pg.evaluate("if ($('#group-tools').is(':hidden')) toggleMenuGroup('tools')")
    pg.wait_for_timeout(400)
    pg.click("#mainmenu .menugroup-header:has(#chevron-tools)")
    pg.wait_for_timeout(450)
    if pg.is_visible("#group-tools"):
        fail("nav", "clicking a group header did not collapse the group")
    if pg.evaluate("JSON.parse(localStorage.getItem('zoraxy_menu_groups')).tools") is not False:
        fail("nav", "collapsed state not saved")
    pg.click("#mainmenu .menugroup-header:has(#chevron-tools)")
    pg.wait_for_timeout(450)
    if not pg.is_visible("#group-tools"):
        fail("nav", "clicking the header again did not expand the group")
    # state saved by the previous menu (old group ids) is carried over to the groups that replaced them
    pg.evaluate("localStorage.setItem('zoraxy_menu_groups', JSON.stringify({reverseproxy:false, others:false, security:true, accessconn:true}))")
    pg.reload(wait_until="networkidle")
    pg.wait_for_timeout(900)
    st = pg.evaluate("JSON.parse(localStorage.getItem('zoraxy_menu_groups'))")
    if st.get("proxy") is not False or st.get("system") is not False or st.get("_v") != 2 or "reverseproxy" in st:
        fail("nav", f"menu state migration wrong: {st}")
    pg.evaluate("localStorage.removeItem('zoraxy_menu_groups')")
    pg.reload(wait_until="networkidle")
    pg.wait_for_timeout(900)
    pg.screenshot(path=out("nav-groups.png"))

    # ---- Quick Start: dismiss, stays away after a reload, comes back from Ingress ----
    current["page"] = "quickstart"
    was_shown = pg.evaluate("fetch('/api/quickstart').then(r => r.json())").get("show")
    pg.evaluate("setQuickStartDismissed(true)")
    settle(pg, 700)
    if pg.is_visible("#qstartNavItem"):
        fail("quickstart", "Quick Start menu item still visible after dismissing")
    if pg.evaluate("fetch('/api/quickstart').then(r => r.json())").get("dismissed") is not True:
        fail("quickstart", "dismissal not stored on the server")
    pg.reload(wait_until="networkidle")
    pg.wait_for_timeout(800)
    if pg.is_visible("#qstartNavItem") or pg.evaluate("location.hash") != "#status":
        fail("quickstart", f"a dismissed instance should land on Status without the item (hash {pg.evaluate('location.hash')})")
    pg.evaluate("openTabById('globalsettings')")
    settle(pg, 500)
    if not pg.is_visible(".quickStartShowAgain"):
        fail("quickstart", "'Show Quick Start again' is missing in Ingress")
    else:
        pg.click(".quickStartShowAgain")
        settle(pg, 600)
        if not pg.is_visible("#qstartNavItem"):
            fail("quickstart", "Quick Start did not come back")
    if not was_shown:
        pg.evaluate("setQuickStartDismissed(true)")  # leave the instance as we found it
        pg.wait_for_timeout(400)

    # ---- seed rules and exercise the table ----
    current["page"] = "proxytable"
    up = serve_upstream()
    port = up.server_address[1]
    names = []
    tagsets = ["web,prod", "api", "media,home", "staging", "internal,admin", "", "web"]
    try:
        pg.evaluate("openTabById('httprp')")
        settle(pg, 600)
        for i in range(36):
            host = f"smoke{i:02d}.example.invalid"
            names.append(host)
            pg.evaluate(API, ["/api/proxy/add", {"type": "host", "rootname": host, "ep": f"127.0.0.1:{port}/svc{i}", "tls": False, "tlsval": False,
                                                 "bypassGlobalTLS": False, "tags": tagsets[i % 7], "rate": i % 5 == 0, "ratenum": 100, "bauth": False, "access": "default"}])
        for i in (3, 12, 21, 30):
            pg.evaluate(API, ["/api/proxy/toggle", {"ep": names[i], "enable": False}])
        t = pg.evaluate("""() => { const t0 = performance.now(); return new Promise(res => listProxyEndpoints(true).then(() => res(performance.now() - t0))) }""")
        rows = pg.locator("#httpProxyList tr.ptRow").count()
        print(f"proxy table: reload + render {t:.0f} ms, {rows} rows in the DOM")
        if t > 3000:
            fail("perf", f"loading and rendering the proxy table took {t:.0f} ms")
        if pg.evaluate("ProxyTable.state.list.length") < 36 or rows > 50:
            fail("table", f"expected the seeded rules in the model and at most one page of rows, got {rows} rows")
        pg.screenshot(path=out("httprp-table.png"))

        # search, status and tag filters
        pg.fill("#searchInput", "smoke0")
        pg.wait_for_timeout(400)
        n = pg.locator("#httpProxyList tr.ptRow").count()
        if n != 10:
            fail("table", f"search 'smoke0' should show 10 rules, got {n}")
        pg.fill("#searchInput", "")
        pg.wait_for_timeout(300)
        pg.click("#ptSeg button[data-f=disabled]")
        pg.wait_for_timeout(300)
        n = pg.locator("#httpProxyList tr.ptRow").count()
        if n != 4:
            fail("table", f"disabled filter should show 4 rules, got {n}")
        pg.click("#ptSeg button[data-f=all]")
        pg.wait_for_timeout(200)
        pg.click("#ptTagChips .ptChip[data-tag=api]")
        pg.wait_for_timeout(300)
        tags = pg.eval_on_selector_all("#httpProxyList tr.ptRow", "els => els.map(e => e.querySelector('.ptTagsCell').innerText)")
        if not tags or any("api" not in x for x in tags):
            fail("table", f"tag filter wrong: {tags[:3]}")
        pg.screenshot(path=out("httprp-filter-tag.png"))
        pg.click("#ptClear")
        pg.wait_for_timeout(300)
        # sorting
        pg.click("#httpProxyTable th[data-sort=host]")
        pg.wait_for_timeout(300)
        if pg.evaluate("ProxyTable.state.sort.dir") != -1:
            fail("table", "clicking the sorted Host header did not reverse the order")
        pg.click("#httpProxyTable th[data-sort=host]")
        pg.wait_for_timeout(300)

        # selection: click + shift range, bulk preview, Esc, select all on the page
        pg.fill("#searchInput", "smoke")
        pg.wait_for_timeout(300)
        boxes = pg.locator("#httpProxyList .bulkSel")
        boxes.nth(1).click()
        boxes.nth(5).click(modifiers=["Shift"])
        pg.wait_for_timeout(200)
        got = pg.evaluate("ProxyTable.selected().length")
        if got != 5:
            fail("select", f"shift-click range should select 5 rules, got {got}")
        if not pg.is_visible("#bulkBar"):
            fail("select", "bulk bar not visible with a selection")
        pg.screenshot(path=out("httprp-selected.png"))
        pg.evaluate("window.scrollTo(0, 600)")
        pg.wait_for_timeout(300)
        top = pg.evaluate("document.getElementById('bulkBar').getBoundingClientRect().top")
        if not (45 <= top <= 140):
            fail("select", f"the bulk bar does not stay visible below the menu bar while scrolling (top {top:.0f}px)")
        pg.evaluate("window.scrollTo(0, 0)")
        pg.wait_for_timeout(200)
        pg.click("#bulkBar button[data-act=waf]")
        pg.wait_for_selector("#bulkModal", state="visible", timeout=5000)
        pg.select_option("#bulkWafSrc", "detection_only")
        pg.click("#bulkModal .actions button:has-text('Preview')")
        pg.wait_for_function("document.querySelector('#bulkModal .content').innerText.indexOf('would change') > -1", timeout=8000)
        pg.screenshot(path=out("httprp-bulk-preview.png"))
        pg.click("#bulkModal .actions button:has-text('Cancel')")
        pg.wait_for_timeout(600)
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(200)
        if pg.evaluate("ProxyTable.selected().length") != 0 or pg.is_visible("#bulkBar"):
            fail("select", "Esc did not clear the selection")
        pg.check("#bulkSelectAll")
        pg.wait_for_timeout(200)
        if pg.evaluate("ProxyTable.selected().length") != pg.locator("#httpProxyList tr.ptRow").count():
            fail("select", "select all did not select every row on the page")
        pg.click("#bulkBar button[data-act=clear]")
        pg.fill("#searchInput", "")
        pg.wait_for_timeout(200)

        # status pill: one click disables, the undo toast re-enables
        pg.fill("#searchInput", names[0])
        pg.wait_for_timeout(300)
        pg.locator(f"#httpProxyList tr.ptRow[data-ep='{names[0]}'] .ptPill").click()
        pg.wait_for_timeout(700)
        if pg.evaluate(API, ["/api/proxy/detail", {"type": "host", "epname": names[0]}]).get("Disabled") is not True:
            fail("pill", "clicking the status pill did not disable the rule")
        if not pg.is_visible("#ptToast .ptToastAct"):
            fail("pill", "no undo toast after toggling")
        else:
            pg.click("#ptToast .ptToastAct")
            pg.wait_for_timeout(700)
            if pg.evaluate(API, ["/api/proxy/detail", {"type": "host", "epname": names[0]}]).get("Disabled") is not False:
                fail("pill", "undo did not re-enable the rule")
        pg.fill("#searchInput", "")
        pg.wait_for_timeout(200)

        # pagination
        pg.select_option("#ptPageSize", "25")
        pg.wait_for_timeout(300)
        if pg.locator("#httpProxyList tr.ptRow").count() != 25 or not pg.is_visible("#ptNext"):
            fail("table", "page size 25 should render 25 rows and a next button")
        pg.click("#ptNext")
        pg.wait_for_timeout(300)
        pg.select_option("#ptPageSize", "50")

        # phone layout of the table
        pg.set_viewport_size({"width": 390, "height": 800})
        pg.wait_for_timeout(300)
        check_horizontal(pg, "httprp mobile")
        pg.screenshot(path=out("httprp-table-mobile.png"))
        pg.set_viewport_size({"width": 1366, "height": 900})

        # ---- New proxy rule dialog ----
        current["page"] = "newrule"
        pg.click("#ptNewRule")
        pg.wait_for_selector("#newRuleModal", state="visible", timeout=5000)
        pg.click("#nrCreate")
        pg.wait_for_timeout(200)
        if "error" not in (pg.get_attribute("#nrFDomain", "class") or ""):
            fail("newrule", "empty domain not flagged")
        pg.fill("#nrDomain", "not a host!")
        pg.keyboard.press("Tab")
        if "error" not in (pg.get_attribute("#nrFDomain", "class") or ""):
            fail("newrule", "invalid domain not flagged")
        pg.fill("#nrDomain", names[1])
        pg.keyboard.press("Tab")
        if "already has a proxy rule" not in pg.inner_text("#nrDomainErr"):
            fail("newrule", "duplicate domain not flagged")
        newhost = "created-by-dialog.example.invalid"
        names.append(newhost)
        pg.fill("#nrDomain", newhost)
        pg.fill("#nrUpstream", "127.0.0.1:1")
        pg.keyboard.press("Tab")
        pg.wait_for_function("document.getElementById('nrTestRes').innerText.indexOf('cannot connect') > -1", timeout=10000)
        pg.fill("#nrUpstream", f"127.0.0.1:{port}")
        pg.keyboard.press("Tab")
        pg.wait_for_function("document.getElementById('nrTestRes').innerText.indexOf('Reachable') > -1", timeout=10000)
        pg.click(".nrTpl:has-text('API backend')")
        pg.screenshot(path=out("newrule-dialog.png"))
        pg.press("#nrUpstream", "Enter")  # Enter submits
        pg.wait_for_selector("#newRuleModal", state="hidden", timeout=8000)
        pg.wait_for_selector("#nrToast.show", timeout=5000)
        pg.wait_for_function("document.querySelector('#httpProxyList tr.ptFlash') !== null", timeout=8000)
        if pg.get_attribute("#httpProxyList tr.ptFlash", "data-ep") != newhost:
            fail("newrule", "the new rule row was not highlighted")
        labels = pg.eval_on_selector_all("#nrToast button", "els => els.map(e => e.innerText)")
        if "Open rule" not in labels or "Add another" not in labels:
            fail("newrule", f"success toast lacks quick actions: {labels}")
        pg.screenshot(path=out("newrule-created.png"))
        detail = pg.evaluate(API, ["/api/proxy/detail", {"type": "host", "epname": newhost}])
        if not detail.get("RequireRateLimit"):
            fail("newrule", "the API backend template was not applied to the new rule")
        pg.click("#nrToast button:has-text('Add another')")
        pg.wait_for_selector("#newRuleModal", state="visible", timeout=20000)
        pg.wait_for_timeout(800)  # let the open animation finish
        pg.keyboard.press("Escape")
        pg.wait_for_selector("#newRuleModal", state="hidden", timeout=20000)
        # the old form stays reachable
        pg.evaluate("openTabById('rules')")
        settle(pg, 400)
        if not pg.is_visible("#rootname"):
            fail("newrule", "the advanced rule form is not reachable")
    except Exception as ex:
        fail("proxy-ux", f"scenario failed: {' '.join(str(ex).split()[:40])}")
        pg.screenshot(path=out("proxy-ux-failure.png"))
    finally:
        up.shutdown()
        if names:
            pg.evaluate("""([n]) => new Promise(res => $.cjax({url: '/api/proxy/bulk', method: 'POST',
                data: {rules: JSON.stringify(n), action: 'delete', params: JSON.stringify({Confirm: true}), dryrun: false}, success: res, error: res}))""", [names])
        pg.evaluate("openTabById('httprp')")
        settle(pg, 500)
        pg.screenshot(path=out("httprp-empty.png"))


def i18n_checks(pg, ctx):
    """Runtime translation layer: English is a no-op, zh-CN switch is fast, stable (no mutation feedback loop) and complete enough."""
    current["page"] = "i18n"
    pg.set_viewport_size({"width": 1366, "height": 800})
    api = lambda path, data: pg.evaluate("""([p, d]) => new Promise(res => $.cjax({url: p, method: 'POST', data: d,
        success: r => res(r), error: e => res({error: 'http ' + e.status})}))""", [path, data])
    hosts = [f"i18n{i:02d}.smoke.invalid" for i in range(36)]
    try:
        pg.evaluate("localStorage.removeItem('zoraxy.lang')")
        pg.goto(args.url + "/", wait_until="networkidle")
        pg.wait_for_selector("#mainmenu .item")
        for h in hosts:
            api("/api/proxy/add", {"type": "host", "rootname": h, "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false"})
        pg.evaluate("openTabById('httprp')")
        pg.evaluate("listProxyEndpoints()")
        settle(pg, 1200)
        st = pg.evaluate("i18n.stats()")
        if st["lang"] != "en" or st["observing"]:
            fail("i18n", f"English mode must not observe the DOM: {st}")
        if pg.locator("#httpProxyList tr").count() < 36:
            fail("i18n", "expected 36 rules in the table for the performance check")
        en_nav = pg.inner_text("#mainmenu a.item[tag=status]").strip()
        en_title = pg.inner_text("#httprp h2, #httprp h1").strip() if pg.locator("#httprp h2, #httprp h1").count() else ""

        # switch through the picker in the top bar
        t0 = pg.evaluate("performance.now()")
        pg.select_option(".menubar select.i18n-picker", "zh-CN")
        pg.wait_for_function("i18n.lang === 'zh-CN' && i18n.stats().observing", timeout=5000)
        total = pg.evaluate("performance.now()") - t0
        st = pg.evaluate("i18n.stats()")
        print(f"i18n: switch to zh-CN: apply {st['lastApplyMs']:.0f} ms main thread (wall {total:.0f} ms incl. dictionary load), "
              f"{st['strings']} strings, {st['patterns']} patterns")
        if st["lastApplyMs"] > 300:
            fail("i18n", f"switching language took {st['lastApplyMs']:.0f} ms of main thread (> 300 ms) on the HTTP Proxy page with 36 rules")
        settle(pg, 800)
        nav = pg.inner_text("#mainmenu a.item[tag=status]").strip()
        if nav == en_nav or "状态" not in nav:
            fail("i18n", f"nav item not translated: {en_nav!r} -> {nav!r}")
        if pg.evaluate("document.documentElement.lang") != "zh-CN":
            fail("i18n", "<html lang> not updated")
        if "代理" not in pg.inner_text("#httprp"):
            fail("i18n", "HTTP Proxy page text did not change")
        if pg.evaluate("document.title").startswith("Control Panel"):
            fail("i18n", "document title not translated")
        saved = pg.evaluate("fetch('/api/i18n/language').then(r => r.json())")
        if saved.get("language") != "zh-CN":
            fail("i18n", f"language choice was not saved on the server: {saved}")
        if pg.evaluate("localStorage.getItem('zoraxy.lang')") != "zh-CN":
            fail("i18n", "language choice not stored in localStorage")
        pg.screenshot(path=os.path.join(args.out, "i18n-zh-CN-httprp.png"))

        # no feedback loop: after settling, the DOM must be quiet (only count text/attribute churn caused by us)
        pg.evaluate("""() => { window.__mut = 0; window.__mo = new MutationObserver(r => { window.__mut += r.filter(x => {
            const el = x.target.nodeType === 1 ? x.target : x.target.parentElement;
            if (!el || el.offsetParent === null) return false;   // hidden tabs rotate their own widgets (app store carousel)
            return x.type === 'characterData' || (x.type === 'attributes' && ['placeholder','title','aria-label','alt','value','label'].includes(x.attributeName))
            || (x.type === 'childList' && [...x.addedNodes].some(n => n.nodeType === 3)); }).length; });
            window.__mo.observe(document.documentElement, {subtree: true, childList: true, characterData: true, attributes: true}); }""")
        pg.wait_for_timeout(2500)
        n = pg.evaluate("window.__mut")
        pg.evaluate("window.__mo.disconnect()")
        if n > 0:
            fail("i18n", f"{n} text/attribute mutations after settling (feedback loop?)")
        for _ in range(12):
            if pg.evaluate("i18n.stats().queued") == 0:
                break
            pg.wait_for_timeout(500)
        if pg.evaluate("i18n.stats().queued") != 0:
            fail("i18n", "translation queue never drained")

        # lazily loaded component + snippet iframe pick the language up
        for tab in ("seccenter", "waf", "cert", "globalsettings"):
            pg.evaluate("t => openTabById(t)", tab)
            settle(pg, 900)
        if "界面语言" not in pg.inner_text("#globalsettings"):
            fail("i18n", "Ingress / settings page not translated (language picker label)")
        pg.screenshot(path=os.path.join(args.out, "i18n-zh-CN-settings.png"))
        pg.evaluate("openTabById('seccenter')")
        settle(pg, 900)
        pg.screenshot(path=os.path.join(args.out, "i18n-zh-CN-seccenter.png"))

        # back to English: originals restored, observer gone
        pg.select_option(".menubar select.i18n-picker", "en")
        pg.wait_for_function("i18n.lang === 'en' && !i18n.stats().observing", timeout=5000)
        pg.evaluate("openTabById('httprp')")
        settle(pg, 700)
        if pg.inner_text("#mainmenu a.item[tag=status]").strip() != en_nav:
            fail("i18n", "English text not restored after switching back")
        # German layout check
        pg.select_option(".menubar select.i18n-picker", "de")
        pg.wait_for_function("i18n.lang === 'de'", timeout=5000)
        settle(pg, 900)
        pg.screenshot(path=os.path.join(args.out, "i18n-de-httprp.png"))
        check_horizontal(pg, "desktop")
        pg.evaluate("openTabById('seccenter')")
        settle(pg, 900)
        pg.screenshot(path=os.path.join(args.out, "i18n-de-seccenter.png"))
        # snippet standalone page in zh-CN picks the stored language and shares the engine
        pg.evaluate("i18n.setLanguage('zh-CN')")
        sp = ctx.new_page()
        sp.on("pageerror", lambda e: fail("pageerror", str(e)))
        sp.on("console", lambda m: m.type == "error" and fail("console.error", m.text + " " + m.location.get("url", "")))
        sp.goto(args.url + "/snippet/notifications.html", wait_until="networkidle")
        sp.wait_for_timeout(1200)
        if sp.evaluate("document.documentElement.lang") != "zh-CN" or not sp.evaluate("/[\\u4e00-\\u9fff]/.test(document.body.innerText)"):
            fail("i18n", "snippet page did not follow the stored language")
        sp.close()
    except Exception as ex:
        fail("i18n", f"i18n flow failed: {' '.join(str(ex).split()[:40])}")
        pg.screenshot(path=os.path.join(args.out, "i18n-failure.png"))
    finally:
        try:
            pg.evaluate("i18n.setLanguage('en')")
            api("/api/i18n/language", {"language": ""})
            for h in hosts:
                api("/api/proxy/del", {"ep": h})
            pg.evaluate("localStorage.removeItem('zoraxy.lang')")
        except Exception:
            pass


def blocked_view(pg):
    """Statistics > Blocked: honest empty state on a fresh instance, then (with mocked API data, the real data path is
    covered by the Go tests and tools/e2e blocked_request_log) reason chips, filters, IP click, links and the Status KPI."""
    import json as _json
    current["page"] = "stats-blocked"
    pg.set_viewport_size({"width": 1366, "height": 900})
    pg.evaluate("openTabById('stats')")
    settle(pg)
    pg.evaluate("statsOpenBlocked({})")
    settle(pg, 900)
    if "Nothing has been blocked yet" not in pg.inner_text("#sbEmpty"):
        fail("blocked", "empty state missing on a fresh instance: " + pg.inner_text("#sbEmpty")[:80])
    pg.screenshot(path=os.path.join(args.out, "blocked-empty.png"))
    info = [{"key": k, "label": l, "why": "why " + k, "tab": t, "where": w, "sec": sec} for k, l, t, w, sec in (
        ("waf", "WAF", "waf", "WAF events", ""), ("ratelimit", "Rate limit", "httprp", "HTTP Proxy", ""),
        ("bot", "Bot rule", "seccenter", "Security Center, Bot rules", "bots"), ("blacklist", "Blacklist", "access", "Access Rules", ""))]
    items = [{"seq": i, "t": 1700000000 + i, "ip": "198.51.100.%d" % (i % 3 + 1), "host": "a.test", "method": "GET", "path": "/p%d" % i,
              "status": 403, "reason": ["waf", "ratelimit", "bot"][i % 3], "detail": "d%d" % i} for i in range(1, 7)]
    seen = []

    def handler(route):
        url = route.request.url
        seen.append(url)
        reason = re.search(r"reason=([a-z-]+)", url)
        ip = re.search(r"ip=([0-9.]+)", url)
        its = [x for x in items if (not reason or x["reason"] == reason.group(1)) and (not ip or x["ip"] == ip.group(1))]
        summ = {"total": len(its), "reasons": [{"key": "waf", "n": 2}, {"key": "ratelimit", "n": 2}, {"key": "bot", "n": 2}], "topIPs": [{"key": "198.51.100.1", "n": 2}],
                "topHosts": [{"key": "a.test", "n": 6}], "topPaths": [{"key": "/p1", "n": 1}], "hourly": [{"hour": 1700000000 + 3600 * i, "n": i % 4} for i in range(24)],
                "oldest": 1700000001, "newest": 1700000006, "capacity": 2000, "kept": 6, "recorded": 6, "enabled": True, "truncated": False, "excludeBlocked": False,
                "sinceStart": {}, "reasonInfo": info}
        body = {"Summary": summ, "List": {"total": len(its), "items": its[::-1], "next": 0}}
        route.fulfill(status=200, content_type="application/json", body=_json.dumps(body))
    pg.route("**/api/blocked/overview*", handler)
    pg.click("#sbReload")
    settle(pg, 700)
    if pg.locator("#sbBody tr").count() != 6:
        fail("blocked", "expected 6 rows, got %d" % pg.locator("#sbBody tr").count())
    if pg.locator("#sbReasons .chip").count() != 3:
        fail("blocked", "reason breakdown missing")
    pg.click("#sbReasons .chip[data-reason=waf]")
    settle(pg, 500)
    if not any("reason=waf" in u for u in seen) or pg.locator("#sbBody tr").count() != 2:
        fail("blocked", "clicking a reason did not filter (rows %d)" % pg.locator("#sbBody tr").count())
    pg.click("#sbReasons .chip[data-reason=waf]")  # toggles off
    pg.click("#sbBody tr >> nth=0 >> .mono")
    settle(pg, 500)
    if not any("ip=198.51.100" in u for u in seen) or not pg.is_visible("#sbIpTag"):
        fail("blocked", "clicking an IP did not filter")
    pg.click("#sbIpClear")
    settle(pg, 400)
    pg.screenshot(path=os.path.join(args.out, "blocked-filled.png"), full_page=True)
    pg.click("#sbReasons [data-rule=waf]")
    settle(pg, 400)
    if not pg.is_visible("#waf"):
        fail("blocked", "the reason link did not open the WAF page")
    pg.evaluate("statsOpenBlocked({reason: 'bot'})")
    settle(pg, 500)
    if pg.locator("#sbBody tr").count() != 2:
        fail("blocked", "statsOpenBlocked with a reason did not filter")
    # Status page: the KPI card and the legend open the view
    for sel in ("#kpiBlocked", "#legendBlocked"):
        pg.evaluate("openTabById('status')")
        settle(pg, 900)
        pg.click(sel)
        settle(pg, 500)
        if not (pg.is_visible("#stats") and pg.is_visible("#sBlocked")):
            fail("blocked", sel + " on the Status page did not open the Blocked view")
    pg.unroute("**/api/blocked/overview*")
    # phone width: no horizontal overflow, rows are cards
    pg.set_viewport_size({"width": 400, "height": 850})
    pg.evaluate("statsOpenBlocked({})")
    settle(pg, 700)
    check_horizontal(pg, "blocked phone")
    pg.set_viewport_size({"width": 1366, "height": 900})
    pg.evaluate("openTabById('stats')")
    pg.evaluate("document.querySelector('#stats [data-stab=overview]').click()")
    settle(pg, 700)
    pg.screenshot(path=os.path.join(args.out, "stats-overview.png"), full_page=True)
def ech_zrok_ui(pg, ctx):
    """Tools > Encrypted Client Hello and Tools > Tunnels (zrok): guided flows, inline confirmations, dark/light and 400px."""
    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=True)

    def theme(want_dark):
        if pg.evaluate("document.body.classList.contains('darkTheme')") != want_dark:
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(300)

    def small_buttons(sel):
        bad = pg.evaluate("""sel => [...document.querySelectorAll(sel + ' button, ' + sel + ' a.button')].filter(b => b.offsetParent !== null).filter(b => {
            const r = b.getBoundingClientRect(); const t = (b.textContent || '').trim() || b.getAttribute('aria-label') || b.getAttribute('title');
            return !t || r.height < 24 || r.width < 24 }).map(b => b.outerHTML.slice(0, 80))""", sel)
        if bad:
            fail("a11y", f"{sel}: buttons without text or smaller than 24px: {bad[:2]}")

    dialogs = []
    pg.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    theme(False)
    pg.set_viewport_size({"width": 1366, "height": 900})

    # ================= ECH =================
    current["page"] = "ech-flow"
    pg.evaluate("""host => new Promise(res => $.cjax({url: '/api/proxy/add', method: 'POST',
        data: {type: 'host', rootname: host, ep: '127.0.0.1:9', tls: false, tlsval: false, bypassGlobalTLS: false}, success: res, error: res}))""", "ech-smoke.example.com")
    pg.evaluate("openTabById('ech')")
    settle(pg, 900)
    if "Disabled" not in pg.inner_text("#echStatePill"):
        fail("ech", "state pill should say Disabled by default: " + pg.inner_text("#echStatePill"))
    shot("ech-initial-light.png")
    pg.fill("#echPublicName", "ech.example.com")
    pg.evaluate("$('#echEnabled').checkbox('set checked')")
    pg.click("#echSave")
    pg.wait_for_selector("#echApplyWarn", state="visible", timeout=8000)  # no certificate for the public name: warns before enabling
    if "ERR_ECH_FALLBACK_CERTIFICATE_INVALID" not in pg.inner_text("#echApplyWarn"):
        fail("ech", "pre-flight warning does not name ERR_ECH_FALLBACK_CERTIFICATE_INVALID")
    pg.click("#echApplyAnyway")
    pg.wait_for_function("document.getElementById('echStatePill').innerText.includes('attention')", timeout=8000)
    if "ERR_ECH_FALLBACK_CERTIFICATE_INVALID" not in pg.inner_text("#echBanners"):
        fail("ech", "red state banner missing after enabling without a valid public-name certificate")
    if pg.locator("#echRecords tbody tr").count() != 1 or "ech-smoke.example.com" not in pg.inner_text("#echRecords"):
        fail("ech", "expected one per-domain DNS record row for ech-smoke.example.com")
    if "ech=" not in pg.inner_text("#echRecords"):
        fail("ech", "HTTPS record text missing ech=")
    pg.click("#echRecords tbody button")
    pg.click("#echSelfRun")
    pg.wait_for_selector("#echSelfResult .echBanner", timeout=8000)  # listener not running / not TLS in the smoke instance: a clear message, not raw JSON
    st = pg.inner_text("#echSelfResult")
    if "{" in st or ("decrypted" not in st and "not running" not in st and "TLS mode" not in st):
        fail("ech", "local handshake result should be a readable message (decrypted / not running / TLS mode): " + st)
    pg.click("#echDomainsRun")
    pg.wait_for_function("document.querySelector('#echDomainsResult table, #echDomainsResult .echBanner')", timeout=30000)
    pg.click("#echRotateNow")
    pg.wait_for_selector("#echRotateConfirm", state="visible")
    pg.click("#echRotateYes")
    pg.wait_for_function("document.querySelectorAll('#echKeys tbody tr').length == 2", timeout=8000)
    pg.locator("#echKeys tbody tr").nth(1).locator("button", has_text="Export").click()
    pg.wait_for_selector("#echExportBox", state="visible")
    if "PRIVATE KEY" not in pg.input_value("#echExportText"):
        fail("ech", "export did not return a PEM")
    pg.click("#echCloseExport")
    pg.locator("#echKeys tbody tr").nth(1).locator("button", has_text="Delete").first.click()
    pg.locator("#echKeys tbody tr").nth(1).locator("button", has_text="Delete key").click()
    pg.wait_for_function("document.querySelectorAll('#echKeys tbody tr').length == 1", timeout=8000)
    small_buttons("#echPanel")
    shot("ech-enabled-light.png")
    theme(True)
    shot("ech-enabled-dark.png")
    pg.set_viewport_size({"width": 400, "height": 800})
    pg.wait_for_timeout(300)
    check_horizontal(pg, "ech 400px")
    shot("ech-400-dark.png")
    theme(False)
    shot("ech-400-light.png")
    pg.set_viewport_size({"width": 1366, "height": 900})
    pg.evaluate("""() => new Promise(res => $.cjax({url: '/api/ech/settings', method: 'POST', data: {enabled: 'false', publicname: ''}, success: res, error: res}))""")
    pg.evaluate("""host => new Promise(res => $.cjax({url: '/api/proxy/del', method: 'POST', data: {ep: host}, success: res, error: res}))""", "ech-smoke.example.com")

    # ================= zrok =================
    current["page"] = "zrok-flow"
    pg.evaluate("openTabById('zrok')")
    settle(pg, 900)
    shot("zrok-initial-light.png")
    if not args.zrok_fake:
        if dialogs:
            fail("dialog", f"native dialogs used: {dialogs}")
        return
    if "not installed" not in pg.inner_text("#zkPill"):
        fail("zrok", "pill should report that zrok is not installed: " + pg.inner_text("#zkPill"))
    if not pg.is_visible("#zkInstall"):
        fail("zrok", "install help should be visible while no binary exists")
    pg.fill("#zkBin", args.zrok_fake)
    pg.click("#zkSaveSettings")
    pg.wait_for_function("document.getElementById('zkInstall').style.display == 'none'", timeout=8000)
    pg.fill("#zkToken", "smokeAccountToken123")
    pg.click("#zkEnable")
    pg.wait_for_selector("#zkEnableResult .zkBanner.good", timeout=15000)
    pg.click("#zrokPanel .zkKind[data-kind=share-private]")
    pg.fill("#zkName", "smoke-share")
    pg.fill("#zkTarget", "127.0.0.1:8080")
    pg.click("#zkTunnelSave")
    pg.wait_for_selector("#zkTunnels .zkTunnel", timeout=8000)
    pg.locator("#zkTunnels .zkTunnel").first.locator("button", has_text="Start").click()
    pg.wait_for_function("document.querySelector('#zkTunnels .zkState.running')", timeout=15000)
    pg.locator("#zkTunnels .zkTunnel").first.locator("button", has_text="Log").click()
    pg.wait_for_selector("#zkTunnels .zkLog pre", timeout=8000)
    shot("zrok-running-light.png")
    small_buttons("#zrokPanel")
    theme(True)
    shot("zrok-running-dark.png")
    pg.set_viewport_size({"width": 400, "height": 800})
    pg.wait_for_timeout(300)
    check_horizontal(pg, "zrok 400px")
    shot("zrok-400-dark.png")
    theme(False)
    shot("zrok-400-light.png")
    pg.set_viewport_size({"width": 1366, "height": 900})
    pg.locator("#zkTunnels .zkTunnel").first.locator("button", has_text="Stop").click()
    pg.wait_for_function("document.querySelector('#zkTunnels .zkState.stopped')", timeout=10000)
    pg.locator("#zkTunnels .zkTunnel").first.locator("button", has_text="Delete").first.click()
    pg.locator("#zkTunnels .zkTunnel").first.locator("button", has_text="Delete tunnel").click()
    pg.wait_for_function("document.querySelectorAll('#zkTunnels .zkTunnel').length == 0", timeout=8000)
    if "No tunnels yet" not in pg.inner_text("#zkTunnels"):
        fail("zrok", "empty state missing after deleting the last tunnel")
    pg.click("#zkDisable")
    pg.click("#zkConfirmYes")
    pg.wait_for_function("document.getElementById('zkPill').innerText.includes('not enabled')", timeout=15000)
    if dialogs:
        fail("dialog", f"native dialogs used: {dialogs}")


def main():
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context(viewport={"width": 1366, "height": 800})
        pg = ctx.new_page()
        pg.on("pageerror", lambda e: fail("pageerror", str(e) + " @ " + " | ".join((e.stack or "").splitlines()[1:3])))
        pg.on("console", lambda m: m.type == "error" and fail("console.error", m.text + " " + m.location.get("url", "")))
        pg.on("requestfailed", lambda r: fail("requestfailed", f"{r.url} {r.failure}"))
        pg.on("response", lambda r: r.status >= 400 and fail("http", f"{r.status} {r.url}"))
        pg.goto(args.url + "/", wait_until="networkidle")
        pg.wait_for_selector("#mainmenu .item")
        pg.wait_for_timeout(800)
        current["page"] = "landing"
        qs = pg.evaluate("fetch('/api/quickstart').then(r => r.json())")
        want = "#qstart" if qs.get("show") else "#status"
        if pg.evaluate("location.hash") != want:
            fail("quickstart", f"landed on {pg.evaluate('location.hash')}, expected {want} (quickstart state {qs})")

        if args.i18n_only:
            i18n_checks(pg, ctx)
            b.close()
            return
        tabs = pg.eval_on_selector_all("#mainmenu .item[tag]", "els => els.map(e => e.getAttribute('tag'))")
        tabs = list(dict.fromkeys(tabs))
        if args.no_page_sweep:
            tabs = []
        print(f"{len(tabs)} tabs: {tabs}")
        for theme in ("light", "dark"):
            is_dark = pg.evaluate("document.body.classList.contains('darkTheme')")
            if (theme == "dark") != is_dark:
                pg.evaluate("toggleTheme()")
            for t in tabs:
                current["page"] = f"{t}/{theme}"
                print("page", current["page"])
                pg.evaluate("t => openTabById(t)", t)
                settle(pg)
                vis = pg.evaluate("""t => { const e = document.getElementById(t); if (!e) return 'missing';
                    return (e.offsetParent !== null ? 'visible' : 'hidden') + ':' + e.innerText.trim().length }""", t)
                if vis.startswith("missing") or vis.startswith("hidden"):
                    fail("tab", f"container #{t} is {vis}")
                elif vis.endswith(":0"):
                    fail("tab", f"container #{t} is empty (component not loaded?)")
                check_horizontal(pg, "desktop")
                pg.screenshot(path=os.path.join(args.out, f"{t}-{theme}.png"))

        # ---- nav: the Recent block must not repeat the always visible top level items ----
        current["page"] = "nav-recent"
        recent = pg.eval_on_selector_all("#group-recent .recent-item", "els => els.map(e => e.getAttribute('title'))")
        if any(t in ("Status", "Quick Start") for t in recent):
            fail("nav", f"Recent repeats the top level items listed right below it: {recent}")
        if len(recent) == 0 and tabs:
            fail("nav", "Recent is empty after visiting every page")

        # ---- standalone pages: access log search, notifications, statistics filters ----
        for name in ("logsearch", "notifications", "statsFilters"):
            current["page"] = "snippet/" + name
            print("page", current["page"])
            sp = ctx.new_page()
            sp.on("pageerror", lambda e: fail("pageerror", str(e)))
            sp.on("console", lambda m: m.type == "error" and fail("console.error", m.text + " " + m.location.get("url", "")))
            sp.on("response", lambda r: r.status >= 400 and fail("http", f"{r.status} {r.url}"))
            sp.goto(args.url + "/snippet/" + name + ".html", wait_until="networkidle")
            sp.wait_for_timeout(700)
            if sp.evaluate("document.body.innerText.trim().length") < 50:
                fail("page", f"{name} rendered (almost) nothing")
            check_horizontal(sp, name)
            sp.screenshot(path=os.path.join(args.out, f"snippet-{name}.png"))
            sp.close()

        # ---- Security Center sub tabs and the Access rule Options tab ----
        current["page"] = "seccenter-tabs"
        pg.evaluate("openTabById('seccenter')")
        settle(pg)
        for sec in pg.eval_on_selector_all("#secTabs .item", "els => els.map(e => e.getAttribute('data-sec'))"):
            current["page"] = f"seccenter/{sec}"
            pg.click(f"#secTabs .item[data-sec='{sec}']")
            settle(pg, 900)
            if pg.evaluate("document.getElementById('secPane').innerText.trim().length") < 20:
                fail("tab", f"security tab {sec} is empty")
            check_horizontal(pg, "desktop")
            pg.screenshot(path=os.path.join(args.out, f"seccenter-{sec}.png"))
        current["page"] = "access-options"
        pg.evaluate("openTabById('access')")
        settle(pg)
        pg.click(".menu .accesscontrol.item[data-tab='tab_options']")
        settle(pg, 900)
        if pg.evaluate("document.getElementById('accessOptionsPane').innerText.trim().length") < 20:
            fail("tab", "access Options tab is empty")
        pg.screenshot(path=os.path.join(args.out, "access-options.png"))

        # ---- nav scroll behaviour at a short viewport ----
        current["page"] = "nav-scroll"
        if pg.evaluate("document.body.classList.contains('darkTheme')"):
            pg.evaluate("toggleTheme()")
        pg.set_viewport_size({"width": 1366, "height": 420})
        pg.evaluate("openTabById('httprp')")  # a long page, so the page itself can scroll too
        settle(pg)
        pg.evaluate("document.querySelectorAll('#mainmenu .menugroup-items').forEach(e => e.style.display='block')")
        info = pg.evaluate("""() => { const n = document.querySelector('.toolbar'); const r = n.getBoundingClientRect();
            return {sh: n.scrollHeight, ch: n.clientHeight, bottom: r.bottom, ih: innerHeight,
                    pageScrollable: document.documentElement.scrollHeight > innerHeight} }""")
        print("nav metrics", info)
        if info["sh"] <= info["ch"]:
            fail("nav", "nav is not taller than its box, cannot scroll (box not limited to the viewport?)")
        if info["bottom"] > info["ih"] + 1:
            fail("nav", f"nav box extends below the viewport ({info['bottom']} > {info['ih']})")
        if not info["pageScrollable"]:
            fail("nav", "test precondition: page is not scrollable")
        pt = hoverpoint(pg, ".toolbar")
        pg.mouse.move(pt["x"], pt["y"])
        before = pg.evaluate("[document.querySelector('.toolbar').scrollTop, window.scrollY]")
        pg.mouse.wheel(0, 300)
        pg.wait_for_timeout(500)
        after = pg.evaluate("[document.querySelector('.toolbar').scrollTop, window.scrollY]")
        print("nav scrollTop/page scrollY before", before, "after", after)
        if after[0] <= before[0]:
            fail("nav", "mouse wheel over the nav did not scroll the nav")
        if after[1] != before[1]:
            fail("nav", "mouse wheel over the nav scrolled the page")
        for _ in range(15):  # past the end of the nav: must not chain into the page
            pg.mouse.wheel(0, 600)
            pg.wait_for_timeout(30)
        pg.wait_for_timeout(400)
        if pg.evaluate("window.scrollY") != before[1]:
            fail("nav", "scroll chaining: page scrolled once the nav hit its end")
        pg.screenshot(path=os.path.join(args.out, "nav-scrolled-short.png"))

        # ---- UX kit: menu filter, "/" shortcut, aria labels ----
        current["page"] = "uxkit"
        pg.set_viewport_size({"width": 1366, "height": 800})
        pg.evaluate("openTabById('status')")
        pg.wait_for_timeout(300)
        pg.keyboard.press("/")
        if pg.evaluate("document.activeElement && document.activeElement.id") != "navFilterInput":
            fail("uxkit", "'/' did not focus the menu filter")
        pg.keyboard.type("updat")
        pg.wait_for_timeout(200)
        vis = pg.evaluate("[...document.querySelectorAll('#mainmenu a.item[tag]')].filter(a => a.offsetParent !== null).map(a => a.getAttribute('tag'))")
        if vis != ["updater"]:
            fail("uxkit", f"menu filter 'updat' should leave only the updater item, got {vis}")
        pg.screenshot(path=os.path.join(args.out, "nav-filter.png"))
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(200)
        n = pg.evaluate("[...document.querySelectorAll('#mainmenu a.item[tag]')].filter(a => a.offsetParent !== null).length")
        if n < 5:
            fail("uxkit", "clearing the filter did not restore the menu")
        unlabeled = pg.evaluate("""() => [...document.querySelectorAll('button, a.button')].filter(b => b.offsetParent !== null
            && !b.textContent.trim() && !b.getAttribute('aria-label') && !b.getAttribute('title')).map(b => b.outerHTML.slice(0, 90))""")
        if unlabeled:
            fail("a11y", f"{len(unlabeled)} visible icon-only buttons without a label, e.g. {unlabeled[0]}")

        # ---- HTTP proxy rule editor: create a rule, open editor, unsaved-changes guard ----
        current["page"] = "editor"
        pg.evaluate("openTabById('httprp')")
        settle(pg)
        host = "smoke-test.invalid"
        pg.evaluate("""host => new Promise(res => $.cjax({url: '/api/proxy/add', method: 'POST',
            data: {type: 'host', rootname: host, ep: '127.0.0.1:9', tls: false, tlsval: false, bypassGlobalTLS: false}, success: res, error: res}))""", host)
        pg.evaluate("listProxyEndpoints()")
        settle(pg, 900)
        try:
            pg.screenshot(path=os.path.join(args.out, "httprp-with-rule.png"))
            # bulk edit: selection checkbox, action bar and a modal
            if pg.locator("#httpProxyList .bulkSel").count() < 1:
                fail("bulk", "no selection checkbox in the proxy rule table")
            else:
                pg.click("#httpProxyList .bulkSel")
                if not pg.is_visible("#bulkBar"):
                    fail("bulk", "bulk action bar did not appear after selecting a rule")
                else:
                    pg.click("#bulkBar button[data-act=tags]")
                    pg.wait_for_selector("#bulkModal", state="visible", timeout=5000)
                    pg.screenshot(path=os.path.join(args.out, "httprp-bulk-modal.png"))
                    pg.evaluate("$('#bulkModal').modal('hide')")
                    pg.wait_for_timeout(400)
                    pg.click("#bulkBar button[data-act=clear]")
            # per rule ops editor (error pages, static responses, CORS, bandwidth)
            current["page"] = "opseditor"
            pg.goto(args.url + "/snippet/opsEditor.html#" + "%7B%22ept%22%3A%22host%22%2C%22ep%22%3A%22smoke-test.invalid%22%7D", wait_until="networkidle")
            pg.wait_for_timeout(600)
            pg.screenshot(path=os.path.join(args.out, "ops-editor.png"))
            # platform features: Lua script editor (with a test run) and Sablier editor
            hash_ = "#%7B%22ept%22%3A%22host%22%2C%22ep%22%3A%22smoke-test.invalid%22%7D"
            current["page"] = "script-editor"
            pg.goto(args.url + "/snippet/scriptEditor.html" + hash_, wait_until="networkidle")
            pg.wait_for_timeout(500)
            pg.click("button:has-text('Insert robots.txt sample')")
            pg.fill("#tPath", "/robots.txt")
            pg.click("button:has-text('Test run')")
            pg.wait_for_selector("#tOut", state="visible", timeout=5000)
            if "Disallow" not in pg.inner_text("#tBodyOut"):
                fail("script", "test run did not return the script output: " + pg.inner_text("#tOut")[:200])
            pg.screenshot(path=os.path.join(args.out, "script-editor.png"))
            current["page"] = "sablier-editor"
            pg.goto(args.url + "/snippet/sablierEditor.html" + hash_, wait_until="networkidle")
            pg.wait_for_timeout(500)
            pg.select_option("#sbStrategy", "blocking")
            pg.screenshot(path=os.path.join(args.out, "sablier-editor.png"))
            pg.goto(args.url + "/snippet/globalErrorPages.html", wait_until="networkidle")
            pg.wait_for_timeout(400)
            pg.goto(args.url + "/", wait_until="networkidle")
            pg.evaluate("openTabById('httprp')")
            settle(pg)
            current["page"] = "editor"
            pg.click("#httpProxyList .editBtn")
            pg.wait_for_selector("#httprpEditModal", state="visible", timeout=5000)
            settle(pg, 800)
            pg.screenshot(path=os.path.join(args.out, "httprp-editor.png"))
            pg.click("#httprpEditModalWrapper .httpProxyEditClosePC")  # clean: closes at once
            pg.wait_for_selector("#httprpEditModal", state="hidden", timeout=5000)
            pg.click("#httpProxyList .editBtn")
            pg.wait_for_selector("#httprpEditModal", state="visible", timeout=5000)
            settle(pg, 800)
            inp = pg.locator("#httprpEditModalWrapper input[type=text]:visible").first
            inp.press("x")  # real keystroke = user edit
            pg.click("#httprpEditModalWrapper .httpProxyEditClosePC")
            pg.wait_for_timeout(400)
            if not pg.is_visible("#confirmBox"):
                fail("editor", "closing a modified editor did not ask for confirmation")
            elif not pg.is_visible("#httprpEditModal"):
                fail("editor", "editor closed before the confirmation was answered")
            else:
                pg.screenshot(path=os.path.join(args.out, "httprp-editor-unsaved.png"))
                pg.click("#confirmBox .ui.red.button")  # keep editing
                pg.wait_for_timeout(300)
                if not pg.is_visible("#httprpEditModal"):
                    fail("editor", "editor closed although 'keep editing' was chosen")
                pg.click("#httprpEditModalWrapper .httpProxyEditClosePC")
                pg.wait_for_timeout(300)
                pg.click("#confirmBox .ui.green.button")  # discard
                pg.wait_for_selector("#httprpEditModal", state="hidden", timeout=5000)
        except Exception as ex:
            fail("editor", f"editor flow failed: {" ".join(str(ex).split()[:30])}"); pg.screenshot(path=os.path.join(args.out, "editor-failure.png"))
        finally:
            pg.evaluate("""host => new Promise(res => $.cjax({url: '/api/proxy/del', method: 'POST', data: {ep: host}, success: res, error: res}))""", host)
            pg.evaluate("listProxyEndpoints()")

        # ---- Quick Start tour: the "subdomain" walkthrough goes through HTTP Proxy + the New proxy rule dialog ----
        current["page"] = "quickstart-tour"
        try:
            pg.evaluate("openTabById('qstart')")
            settle(pg)
            pg.evaluate("currentQuickSetupClass = 'subdomain'; startQuickStartTour();")
            total = pg.evaluate("tourSteps['subdomain'].length")
            if total < 8:
                fail("tour", f"subdomain tour has only {total} steps")
            focus_expected = ("Domain", "Upstream (where the app runs)", "Upstream uses HTTPS", "Ignore Certificate", "Template", "More Options", "Save New Proxy Rule", "Create New Proxy Rule")
            for i in range(total):
                pg.wait_for_timeout(1900)
                info = pg.evaluate("""() => ({title: $('#tourModal .tourStepTitle').text(), focus: $('.tourFocusObject').length,
                    overlay: $('#tourModalOverlay').is(':visible') ? $('#tourModalOverlay').width() : 0,
                    dialog: $('#newRuleModal').hasClass('visible'), tab: location.hash})""")
                t = info["title"]
                print("  tour step", i + 1, t, info)
                if any(t.endswith(k) for k in focus_expected):
                    if info["focus"] != 1 or info["overlay"] <= 0:
                        fail("tour", f"step '{t}' highlights nothing: {info}")
                if any(t.endswith(k) for k in focus_expected[:7]) and "Create New Proxy Rule" not in t and not info["dialog"]:
                    fail("tour", f"step '{t}' expects the New proxy rule dialog to be open")
                if i in (3, total - 4):
                    pg.screenshot(path=os.path.join(args.out, f"tour-step-{i + 1}.png"))
                if i < total - 1:
                    pg.evaluate("nextTourStep()")
            pg.evaluate("endTourFocus()")
            pg.wait_for_timeout(800)
            if pg.evaluate("$('#newRuleModal').hasClass('visible')"):
                fail("tour", "the New proxy rule dialog stayed open after the tour ended")
        except Exception as ex:
            fail("tour", f"tour check failed: {' '.join(str(ex).split()[:30])}")
            pg.screenshot(path=os.path.join(args.out, "tour-failure.png"))
            pg.evaluate("endTourFocus()")
        pg.evaluate("openTabById('status')")

        # ---- Rule template manager: create, validation errors, live preview, picker, clone, delete ----
        current["page"] = "rule-templates"
        try:
            pg.evaluate("openTabById('httprp')")
            settle(pg)
            pg.click("#ptTemplates")
            pg.wait_for_selector("#ruleTplModal .rtTable", timeout=5000)
            if "Secure web app" not in pg.inner_text("#ruleTplModal"):
                fail("templates", "built in templates are not listed")
            pg.click("#rtNew")
            pg.wait_for_selector("#rtForm", timeout=5000)
            # an invalid name is reported by the server and blocks saving
            pg.fill("#rtName", "-bad name")
            pg.wait_for_timeout(900)
            if "template name must be" not in pg.inner_text("#rtPreview") or "disabled" not in (pg.get_attribute("#rtSave", "class") or ""):
                fail("templates", "an invalid name is not reported / Save is not disabled")
            pg.fill("#rtName", "Smoke template")
            pg.fill("#rtDesc", "Created by the UI smoke test")
            pg.check("#rtHstsOn")
            pg.fill("#rtHsts", "31536000")
            pg.check("#rtRateOn")
            pg.fill("#rtRate", "20")
            pg.fill("#rtTags", "smoke, tpl")
            pg.select_option("#rtWaf", "block")
            pg.click("#rtAddHdr")
            pg.fill("#rtHdrs .rtHKey", "X-Smoke")
            pg.fill("#rtHdrs .rtHVal", "1")
            pg.wait_for_timeout(1100)
            prev = pg.inner_text("#rtPreview")
            for want in ("HSTS max age", "Rate limit (req/s)", "Tags", "WAF source", "Header X-Smoke"):
                if want not in prev:
                    fail("templates", f"live preview lacks '{want}': {prev[:200]}")
            pg.screenshot(path=os.path.join(args.out, "template-editor.png"), full_page=True)
            pg.click("#rtSave")
            pg.wait_for_selector("#ruleTplModal .rtTable", timeout=5000)
            if "Smoke template" not in pg.inner_text("#ruleTplModal"):
                fail("templates", "the saved template is not listed")
            # clone, then delete the clone
            pg.click("#ruleTplModal tr:has-text('Smoke template') .rtCloneBtn")
            pg.wait_for_selector("#rtForm", timeout=5000)
            if pg.input_value("#rtName") != "Smoke template copy":
                fail("templates", "clone did not pre-fill the name")
            pg.click("#rtSave")
            pg.wait_for_selector("#ruleTplModal .rtTable", timeout=5000)
            pg.screenshot(path=os.path.join(args.out, "template-list.png"), full_page=True)
            pg.click("#rtClose")
            pg.wait_for_timeout(600)
            # the new rule dialog offers the custom template
            pg.evaluate("openNewRuleDialog()")
            pg.wait_for_selector("#nrTplGrid .nrTpl", timeout=5000)
            pg.wait_for_timeout(600)
            if "Smoke template" not in pg.inner_text("#nrTplGrid"):
                fail("templates", "the New proxy rule dialog does not list the custom template")
            pg.click("#nrCancel")
            pg.wait_for_timeout(500)
            pg.click("#ptTemplates")
            pg.wait_for_selector("#ruleTplModal .rtTable", timeout=5000)
            for name in ("Smoke template copy", "Smoke template"):
                row = f"#ruleTplModal tr:has-text('{name}') .rtDelBtn"
                pg.click(row)
                pg.click(row)
                pg.wait_for_timeout(700)
            if "Smoke template" in pg.inner_text("#ruleTplModal"):
                fail("templates", "deleting the templates did not remove them")
            pg.click("#rtClose")
        except Exception as ex:
            fail("templates", f"template manager flow failed: {' '.join(str(ex).split()[:30])}")
            pg.screenshot(path=os.path.join(args.out, "templates-failure.png"))
        pg.wait_for_timeout(500)

        # ---- Status page visitor map must not be created while hidden (jsVectorMap logs scale(NaN)) ----
        current["page"] = "status-map"
        try:
            pg.route("**/api/stats/countries", lambda route: route.fulfill(status=200, content_type="application/json", body='{"US": 5, "DE": 2, "JP": 1}'))
            pg.evaluate("openTabById('seccenter')")
            settle(pg)
            pg.evaluate("updateVisitorLocations()")
            pg.wait_for_timeout(600)
            if pg.evaluate("typeof worldMap !== 'undefined' && worldMap !== undefined"):
                fail("status-map", "the world map was created while the Status tab was hidden")
            pg.evaluate("openTabById('status')")
            pg.wait_for_timeout(1200)
            if not pg.evaluate("typeof worldMap !== 'undefined' && worldMap !== undefined"):
                fail("status-map", "the world map was not created once the Status tab became visible")
            if pg.evaluate("document.querySelectorAll('#worldMap svg').length") < 1:
                fail("status-map", "the world map has no SVG")
            pg.screenshot(path=os.path.join(args.out, "status-map.png"), full_page=True)
        except Exception as ex:
            fail("status-map", f"status map check failed: {' '.join(str(ex).split()[:30])}")
        finally:
            pg.unroute("**/api/stats/countries")
            pg.evaluate("updateVisitorLocations()")

        # ---- CAPTCHA / Bot check page ----
        current["page"] = "captcha-page"
        host = "smoke-captcha.invalid"
        try:
            pg.evaluate("""host => new Promise(res => $.cjax({url: '/api/proxy/add', method: 'POST',
                data: {type: 'host', rootname: host, ep: '127.0.0.1:9', tls: false, tlsval: false, bypassGlobalTLS: false}, success: res, error: res}))""", host)
            pg.evaluate("openTabById('captcha')")
            settle(pg, 900)
            row = f"#cpRows tr[data-ep='{host}']"
            pg.wait_for_selector(row, timeout=5000)
            pg.click(row + " .cpEdit")
            pg.wait_for_selector("#cpEditor", state="visible", timeout=5000)
            pg.check("#cpEnable") if not pg.is_checked("#cpEnable") else None
            # public Turnstile test keys through the helper button
            pg.click("#cpTestKeys")
            if pg.input_value("#cpSiteKey") != "1x00000000000000000000AA":
                fail("captcha", "test keys button did not fill the Turnstile test site key")
            pg.fill("#cpForm [data-cp=captchaHeading]", "Smoke heading")
            pg.wait_for_timeout(1500)  # debounced live preview
            frame = next((f for f in pg.frames if f.name == "cpPreviewFrame"), None)
            if frame is None or "Smoke heading" not in frame.content():
                fail("captcha", "live preview did not show the edited heading")
            pg.click("#cpPageBtns [data-page=blocked]")
            pg.wait_for_timeout(1000)
            pg.click("#cpWidthBtns [data-w=mobile]")
            pg.screenshot(path=os.path.join(args.out, "captcha-editor.png"), full_page=True)
            pg.click("#cpSave")
            pg.wait_for_timeout(1200)
            saved = pg.evaluate("""host => fetch('/api/proxy/detail?type=host&epname=' + host).then(r => r.json())""", host)
            if not saved.get("RequireCaptcha") or (saved.get("CaptchaConfig") or {}).get("Branding", {}).get("Heading") != "Smoke heading":
                fail("captcha", "saving the CAPTCHA page did not persist the settings")
            # Friendly Captcha: provider option, endpoint select, provider dependent sections, save, reopen, preview
            pg.click("div.ui.dropdown:has(> #cpProvider)")
            pg.click("div.ui.dropdown:has(> #cpProvider) .menu .item[data-value='3']")
            if not pg.is_visible(".cpProviderFriendly") or pg.is_visible(".cpTurnstileSeg") or pg.is_visible(".cpProviderRecaptcha"):
                fail("captcha", "provider sections are wrong for Friendly Captcha")
            pg.click("div.ui.dropdown:has(> #cpFriendlyEndpoint)")
            pg.click("div.ui.dropdown:has(> #cpFriendlyEndpoint) .menu .item[data-value='eu']")
            pg.fill("#cpSiteKey", "FCMSMOKESITEKEY")
            pg.fill("#cpSecretKey", "A1SMOKEAPIKEY")
            pg.click("#cpPageBtns [data-page=challenge]")
            pg.wait_for_timeout(1800)
            frame = next((f for f in pg.frames if f.name == "cpPreviewFrame"), None)
            html = frame.content().lower() if frame is not None else ""
            if "friendly" not in html:
                fail("captcha", "the preview does not render the Friendly Captcha widget page")
            open(os.path.join(args.out, "captcha-friendly-preview.html"), "w").write(html)
            pg.screenshot(path=os.path.join(args.out, "captcha-friendly.png"), full_page=True)
            pg.click("#cpSave")
            pg.wait_for_timeout(1200)
            saved = pg.evaluate("""host => fetch('/api/proxy/detail?type=host&epname=' + host).then(r => r.json())""", host)
            cc = saved.get("CaptchaConfig") or {}
            if cc.get("Provider") != 3 or cc.get("FriendlyEndpoint") != "eu" or cc.get("SiteKey") != "FCMSMOKESITEKEY":
                fail("captcha", f"Friendly Captcha settings were not persisted: {cc.get('Provider')} {cc.get('FriendlyEndpoint')}")
            pg.click("#cpBack")
            pg.wait_for_selector("#cpOverview", state="visible", timeout=5000)
            if "Friendly Captcha" not in pg.inner_text(row):
                fail("captcha", "overview does not name the Friendly Captcha provider")
            pg.click(row + " .cpEdit")
            pg.wait_for_selector("#cpEditor", state="visible", timeout=5000)
            shown = pg.inner_text("div.ui.dropdown:has(> #cpProvider) > .text") + "|" + pg.inner_text("div.ui.dropdown:has(> #cpFriendlyEndpoint) > .text")
            if pg.input_value("#cpProvider") != "3" or pg.input_value("#cpFriendlyEndpoint") != "eu" or not pg.is_visible(".cpProviderFriendly") \
                    or "Friendly" not in shown or "EU" not in shown:
                fail("captcha", "reopened editor did not restore the Friendly Captcha settings")
            pg.click("#cpBack")
            pg.wait_for_selector("#cpOverview", state="visible", timeout=5000)
            pg.click("#cpGlobalBtn")
            pg.wait_for_selector("#cpEditor", state="visible", timeout=5000)
            pg.screenshot(path=os.path.join(args.out, "captcha-global.png"), full_page=True)
            pg.click("#cpBack")
        except Exception as ex:
            fail("captcha", f"captcha page flow failed: {' '.join(str(ex).split()[:30])}")
            pg.screenshot(path=os.path.join(args.out, "captcha-failure.png"))
        finally:
            pg.evaluate("""host => new Promise(res => $.cjax({url: '/api/proxy/del', method: 'POST', data: {ep: host}, success: res, error: res}))""", host)

        # ---- WAF page: tabs, mode cards, exclusions list ----
        current["page"] = "waf-page"
        try:
            pg.evaluate("openTabById('waf')")
            settle(pg, 900)
            if pg.locator("#wafModeCards .wafCard").count() != 3:
                fail("waf", "mode selector does not show three modes")
            for t in ("events", "coverage", "policy", "profiles", "exclusions", "rules"):
                pg.click(f"#wafTabs .item[data-tab=waf-{t}]")
                settle(pg, 700)
                pg.screenshot(path=os.path.join(args.out, f"waf-{t}.png"), full_page=True)
            pg.click("#wafTabs .item[data-tab=waf-exclusions]")
            pg.fill("#wafxRule", "942999")
            pg.click("#wafxAdd")
            pg.wait_for_timeout(1200)
            if "942999" not in pg.inner_text("#wafxBody"):
                fail("waf", "added exclusion is not listed")
            pg.fill("#wafxFilter", "942999")
            pg.click("#wafxBody .wafxDel")
            pg.wait_for_timeout(1200)
            if "942999" in pg.inner_text("#wafxBody"):
                fail("waf", "removed exclusion is still listed")
            pg.fill("#wafxFilter", "")
        except Exception as ex:
            fail("waf", f"waf page flow failed: {' '.join(str(ex).split()[:30])}")

        # ---- SSO: OAuth2 provider manager and per-rule provider selection ----
        # Two fake OIDC providers (discovery only) are started here; two proxy rules are bound to them and
        # the sign-in redirect of each rule must lead to its own provider.
        current["page"] = "sso-providers"
        idps = [FakeOIDC(0), FakeOIDC(0)]
        hostA, hostB = "sso-a.smoke.invalid", "sso-b.smoke.invalid"
        api = lambda path, data: pg.evaluate("""([p, d]) => new Promise(res => $.cjax({url: p, method: 'POST', data: d,
            success: r => res(r), error: e => res({error: 'http ' + e.status})}))""", [path, data])
        try:
            pg.goto(args.url + "/", wait_until="networkidle")
            pg.evaluate("openTabById('sso')")
            settle(pg)
            pg.click(".ssoTabs .item[data-tab='oauth2_tab']")
            pg.wait_for_selector("#oauth2ProviderList", state="visible")
            for i, (pid, idp) in enumerate(zip(("idpa", "idpb"), idps)):
                pg.click("#oauth2NewProvider")
                pg.fill("#oauth2ProviderId", pid)
                pg.fill("#oauth2ProviderName", "Fake IdP " + pid[-1].upper())
                pg.fill("#oauth2Issuer", idp.issuer)
                pg.fill("#oauth2ClientId", "client-" + pid)
                pg.fill("#oauth2ClientSecret", "secret-" + pid + "-0123456789")
                pg.click("#oauth2TestDiscovery")
                pg.wait_for_selector("#oauth2DiscoveryResult .message", timeout=8000)
                txt = pg.inner_text("#oauth2DiscoveryResult")
                if idp.issuer not in txt:
                    fail("sso-providers", "discovery test did not report the issuer: " + txt[:120])
                if i == 0:
                    pg.screenshot(path=os.path.join(args.out, "sso-provider-editor.png"), full_page=True)
                pg.click("#oauth2Settings button[type=submit]")
                pg.wait_for_selector(f"#oauth2ProviderList tr[data-id='{pid}']", timeout=8000)
            pg.screenshot(path=os.path.join(args.out, "sso-providers.png"), full_page=True)
            # the secret is never sent back to the browser
            listing = pg.evaluate("fetch('/api/sso/OAuth2/providers').then(r => r.text())")
            if "secret-idp" in listing:
                fail("sso-providers", "provider list leaks a client secret")
            # editing keeps the stored secret when the field is left empty
            pg.click("#oauth2ProviderList tr[data-id='idpa'] .oauth2EditBtn")
            if pg.input_value("#oauth2ClientSecret") != "":
                fail("sso-providers", "secret field is not empty when editing")
            pg.fill("#oauth2ProviderName", "Fake IdP A (edited)")
            pg.click("#oauth2Settings button[type=submit]")
            pg.wait_for_function("document.querySelector(\"#oauth2ProviderList tr[data-id='idpa']\").innerText.includes('edited')", timeout=8000)

            # two rules, bound to the two providers
            for host, pid in ((hostA, "idpa"), (hostB, "idpb")):
                r = api("/api/proxy/add", {"type": "host", "rootname": host, "ep": "127.0.0.1:9", "tls": False, "tlsval": False, "bypassGlobalTLS": True})
                r = r if isinstance(r, dict) else {}
            api("/api/proxy/edit", {"rootname": hostA, "authprovider": 3, "oauth2provider": "idpa"})

            # rule B is assigned through the rule editor
            pg.evaluate("openTabById('httprp')")
            settle(pg)
            pg.evaluate("listProxyEndpoints()")
            settle(pg, 900)
            pg.evaluate("h => { const b = [...document.querySelectorAll('#httpProxyList .editBtn')].find(e => e.getAttribute('rootname') === h || e.closest('tr').innerText.includes(h)); b.click(); }", hostB)
            pg.wait_for_selector("#httprpEditModal", state="visible", timeout=5000)
            settle(pg, 800)
            pg.click(".hrpedit_menu_item[cfgpage='security']")
            pg.click(".authProviderPicker input[value='3']", force=True)
            pg.wait_for_selector(".oauth2RuleSettings", state="visible", timeout=5000)
            settle(pg, 600)
            opts = pg.eval_on_selector_all(".oauth2ProviderSelect option", "els => els.map(e => e.value)")
            if "idpa" not in opts or "idpb" not in opts:
                fail("rule-provider", f"provider dropdown lacks the configured providers: {opts}")
            pg.select_option(".oauth2ProviderSelect", "idpb")  # change event = inline save, the editor re-renders afterwards
            settle(pg, 1200)
            pg.fill(".oauth2RuleGroups", "staff")
            pg.press(".oauth2RuleGroups", "Tab")  # blur = change event = inline save
            settle(pg, 900)
            pg.screenshot(path=os.path.join(args.out, "rule-oauth2-provider.png"))
            pg.evaluate("closeHttpRuleEditor()")
            detail = pg.evaluate("h => fetch('/api/proxy/detail?type=host&epname=' + encodeURIComponent(h)).then(r => r.json())", hostB)
            ap = (detail or {}).get("AuthenticationProvider") or {}
            if ap.get("AuthMethod") != 3 or ap.get("OAuth2ProviderID") != "idpb":
                # fall back to the API when the inline save button differs, so the routing check below still runs
                api("/api/proxy/edit", {"rootname": hostB, "authprovider": 3, "oauth2provider": "idpb", "oauth2groups": "staff"})
                detail = pg.evaluate("h => fetch('/api/proxy/detail?type=host&epname=' + encodeURIComponent(h)).then(r => r.json())", hostB)
                ap = (detail or {}).get("AuthenticationProvider") or {}
                fail("rule-provider", "rule editor did not persist the provider by itself (API fallback used)")
            if ap.get("OAuth2AllowedGroups") != "staff":
                fail("rule-provider", f"per rule group list not stored: {ap}")

            # a provider that rules use cannot be deleted
            pg.evaluate("openTabById('sso')")
            settle(pg)
            pg.click(".ssoTabs .item[data-tab='oauth2_tab']")
            pg.click("#oauth2ProviderList tr[data-id='idpa'] .oauth2EditBtn")
            pg.click("#oauth2Clear")
            pg.wait_for_timeout(900)
            if pg.locator("#oauth2ProviderList tr[data-id='idpa']").count() != 1:
                fail("sso-providers", "a provider in use was deleted")
            pg.screenshot(path=os.path.join(args.out, "sso-provider-delete-refused.png"))
            used = pg.evaluate("fetch('/api/sso/OAuth2/providers').then(r => r.json())")
            if not any(p["id"] == "idpa" and hostA in (p.get("usedBy") or []) for p in used):
                fail("sso-providers", "usedBy does not list the rule that uses the provider")

            # real routing: plain HTTP listener on loopback, each Host must be sent to its own provider
            import socket
            _s = socket.socket(); _s.bind(("127.0.0.1", 0)); proxy_port = _s.getsockname()[1]; _s.close()
            api("/api/proxy/httpListenAddr", {"addr": f"127.0.0.1:{proxy_port}"})
            api("/api/proxy/useHttpsRedirect", {"set": False})
            api("/api/proxy/listenPort80", {"enable": True})
            pg.wait_for_timeout(1500)
            import http.client
            def first_hop(host, path="/private"):
                for attempt in range(40):  # the listener starts asynchronously; a loaded machine needs more than the fixed wait above
                    c = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=8)
                    try:
                        c.request("GET", path, headers={"Host": host})
                        break
                    except ConnectionRefusedError:
                        if attempt == 39:
                            raise
                        pg.wait_for_timeout(500)
                resp = c.getresponse()
                resp.read(200)
                return resp.status, resp.getheader("Location") or ""
            for host, idp, pid in ((hostA, idps[0], "idpa"), (hostB, idps[1], "idpb")):
                st, loc = first_hop(host)
                if st != 302 or not loc.startswith(idp.base + "/authorize"):
                    fail("rule-routing", f"{host}: expected a redirect to {idp.base}/authorize, got {st} {loc[:100]}")
                elif f"%2Finternal%2Foauth2%2Fp%2F{pid}" not in loc:
                    fail("rule-routing", f"{host}: redirect_uri does not carry the provider callback path: {loc[:160]}")
                else:
                    print(f"  {host} -> {loc.split('?')[0]} (ok)")
            # an exempt path works for both providers
            for host in (hostA, hostB):
                added = api("/api/proxy/auth/sso/exceptions/add", {"ep": host, "type": 0, "pattern": "/webhook", "mode": "prefix"})
                pg.wait_for_timeout(500)
                st, loc = first_hop(host, "/webhook/x")
                if st == 302 and "authorize" in loc:
                    fail("rule-routing", f"{host}: exempt path was sent to sign-in (add result {added})")
        except Exception as ex:
            fail("sso-providers", f"flow failed: {' '.join(str(ex).split()[:40])}")
            pg.screenshot(path=os.path.join(args.out, "sso-providers-failure.png"))
        finally:
            for host in (hostA, hostB):
                api("/api/proxy/del", {"ep": host})
            api("/api/proxy/listenPort80", {"enable": False})
            for idp in idps:
                idp.stop()
            for pid in ("idpa", "idpb"):
                pg.evaluate("p => new Promise(res => $.cjax({url: '/api/sso/OAuth2/providers?id=' + p, method: 'DELETE', success: res, error: res}))", pid)

        # ---- Status board: skeletons resolved, empty states, traffic map controls ----
        current["page"] = "status-board"
        pg.set_viewport_size({"width": 1366, "height": 800})
        pg.evaluate("openTabById('status')")
        settle(pg, 1500)
        if pg.evaluate("document.querySelectorAll('#glancePanel .kpiCard.skel').length") > 0:
            fail("status", "KPI cards are still in the loading (skeleton) state")
        for sel in ("#upstreamList", "#certList", "#alertList", "#latestVisitors"):
            st = pg.evaluate("sel => { const e = document.querySelector(sel); return {skel: e.querySelectorAll('.healthSkel').length, text: e.innerText.trim().length} }", sel)
            if st["skel"] or st["text"] < 5:
                fail("status", f"{sel} did not render (skeleton {st['skel']}, text {st['text']})")
        pg.click("#diagramHideBtn")
        if pg.evaluate("!!document.getElementById('trafficFlowDiagram').getAttribute('src')"):
            fail("status", "hiding the traffic map did not unload the iframe")
        pg.click("#diagramHideBtn")
        pg.wait_for_timeout(500)
        if not pg.evaluate("!!document.getElementById('trafficFlowDiagram').getAttribute('src')"):
            fail("status", "showing the traffic map did not reload the iframe")
        pg.click("#diagramAnimBtn")
        pg.wait_for_timeout(300)
        if "Resume" not in pg.inner_text("#diagramAnimBtn"):
            fail("status", "pause animation button did not switch to Resume")
        pg.click("#diagramAnimBtn")
        pg.screenshot(path=os.path.join(args.out, "status-board.png"), full_page=True)

        # ---- Visitors page ----
        current["page"] = "visitors"
        pg.evaluate("openTabById('visitors')")
        settle(pg, 1200)
        if pg.evaluate("document.querySelectorAll('#vBody .vSkel').length") > 0:
            fail("visitors", "table is still showing the loading skeleton")
        if pg.evaluate("document.getElementById('vBody').innerText.trim().length") < 10:
            fail("visitors", "table shows neither rows nor the empty state")
        api = pg.evaluate("""async () => { const o = {}; for (const u of ['/api/visitors/list?sort=password', '/api/visitors/list?via=evil', '/api/visitors/detail?ip=nope', '/api/visitors/export?format=xml'])
            o[u] = (await (await fetch(u)).json()).error || ''; return o }""")
        for u, err in api.items():
            if not err:
                fail("visitors", f"{u} was accepted")
        ex = pg.evaluate("""async () => { const r = await fetch('/api/visitors/export?format=csv'); return [r.status, r.headers.get('content-disposition') || '', (await r.text()).split('\\n')[0]] }""")
        if ex[0] != 200 or "attachment" not in ex[1] or not ex[2].startswith("ip,country"):
            fail("visitors", f"CSV export wrong: {ex}")
        pg.click("#vTabs .item[data-vtab=recent]")
        settle(pg, 800)
        for _ in range(12):
            if pg.evaluate("document.getElementById('vrBody').innerText.trim().length") >= 10:
                break
            pg.wait_for_timeout(500)
        if pg.evaluate("document.getElementById('vrBody').innerText.trim().length") < 10:
            fail("visitors", "recent visits tab shows neither rows nor the empty state")
        pg.click("#vTabs .item[data-vtab=settings]")
        settle(pg, 500)
        pg.fill("#vsAge", "45")
        pg.click("#vsSave")
        pg.wait_for_timeout(700)
        if "Saved" not in pg.inner_text("#vsMsg"):
            fail("visitors", "saving the settings did not confirm")
        pg.screenshot(path=os.path.join(args.out, "visitors-settings.png"), full_page=True)
        pg.click("#vsPurge")
        if not pg.is_visible("#vsPurgeYes"):
            fail("visitors", "purge needs a second confirmation click")
        pg.click("#vsPurgeNo")
        pg.click("#vTabs .item[data-vtab=list]")

        proxy_ux(pg, ctx)

        ech_zrok_ui(pg, ctx)

        # ---- narrow / mobile layout ----
        current["page"] = "mobile"
        pg.set_viewport_size({"width": 390, "height": 700})
        pg.reload(wait_until="networkidle")
        pg.wait_for_timeout(600)
        pg.screenshot(path=os.path.join(args.out, "mobile-closed.png"))
        pg.click("#sidemenuBtn")
        pg.wait_for_timeout(600)
        pg.evaluate("document.querySelectorAll('#mainmenu .menugroup-items').forEach(e => e.style.display='block')")
        m = pg.evaluate("""() => { const n = document.querySelector('.toolbar'); const r = n.getBoundingClientRect();
            return {sh: n.scrollHeight, ch: n.clientHeight, bottom: r.bottom, ih: innerHeight, shown: r.width > 0} }""")
        print("mobile nav metrics", m)
        if not m["shown"]:
            fail("mobile-nav", "drawer did not open")
        if m["bottom"] > m["ih"] + 1:
            fail("mobile-nav", f"drawer extends below viewport ({m['bottom']} > {m['ih']})")
        pt = hoverpoint(pg, ".toolbar")
        pg.mouse.move(pt["x"], pt["y"])
        y0 = pg.evaluate("window.scrollY")
        pg.mouse.wheel(0, 400)
        pg.wait_for_timeout(500)
        s = pg.evaluate("[document.querySelector('.toolbar').scrollTop, window.scrollY]")
        if s[0] <= 0 or s[1] != y0:
            fail("mobile-nav", f"drawer wheel scroll wrong: nav scrollTop {s[0]}, page scrollY {s[1]}")
        pg.screenshot(path=os.path.join(args.out, "mobile-open.png"))
        for t in tabs:
            current["page"] = f"mobile/{t}"
            pg.evaluate("t => openTabById(t)", t)
            settle(pg, 500)
            check_horizontal(pg, "mobile")
            pg.screenshot(path=os.path.join(args.out, f"mobile-{t}.png"))
        blocked_view(pg)
        i18n_checks(pg, ctx)
        b.close()


main()
print()
if failures:
    print(f"{len(failures)} FAILURE(S)")
    sys.exit(1)
print("OK, screenshots in", args.out)
