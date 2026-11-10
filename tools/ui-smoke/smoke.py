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
import json
import os
import re
import sys

from playwright.sync_api import sync_playwright

ap = argparse.ArgumentParser()
ap.add_argument("--url", default=os.environ.get("ZORAXY_URL", "http://127.0.0.1:8000"))
ap.add_argument("--out", default=os.environ.get("SMOKE_OUT", os.path.expanduser("~/ui-smoke-shots")))
ap.add_argument("--no-page-sweep", action="store_true", help="skip the per-tab screenshot sweep (faster; for focused runs on a busy machine)")
ap.add_argument("--i18n-only", action="store_true", help="run only the multi-language scenario")
ap.add_argument("--posture-only", action="store_true", help="run only the Security overview scenario")
ap.add_argument("--waf-tuning-only", action="store_true", help="run only the WAF Tuning tab scenario")
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

# Every tab id of the menu before the navigation redesign: all of them must keep opening their page (deep links, openTabById calls
# in the components, bookmarks). Value = the breadcrumb "Group > Page" the new menu shows for it.
OLD_TABS = {
    "qstart": ("Overview", "Quick Start"), "status": ("Overview", "Status"),
    "httprp": ("Sites", "HTTP Proxy"), "setroot": ("Sites", "Default Site"), "redirectset": ("Sites", "Redirection"),
    "vdir": ("Sites", "Path routes"), "streamproxy": ("Sites", "Stream Proxy"), "rules": ("Sites", "Raw rule form"), "webserv": ("Sites", "Static Web Server"),
    "seccenter": ("Security", "Security Center"), "waf": ("Security", "WAF"), "access": ("Security", "Access Rules"),
    "sso": ("Security", "SSO / OAuth2"), "captcha": ("Security", "CAPTCHA"),
    "cert": ("Certificates", "TLS / SSL Certificates"), "acme": ("Certificates", "ACME Client"),
    "stats": ("Traffic", "Statistics"), "visitors": ("Traffic", "Visitors"), "utm": ("Traffic", "Uptime Monitor"),
    "globalsettings": ("Network", "Listeners"), "trustproxy": ("Network", "Trusted Proxies"), "zrok": ("Network", "Tunnels (zrok)"),
    "ech": ("Network", "Encrypted Client Hello"), "iface": ("Network", "Network Interfaces"), "networktool": ("Network", "Network Tools"),
    "fleet": ("Fleet & HA", "Fleet"), "cluster": ("Fleet & HA", "Cluster / HA"),
    "updater": ("System", "Update"), "apitokens": ("System", "API Tokens"), "plugins": ("System", "Plugin Manager"),
    "appstore": ("System", "App Store"), "utils": ("System", "Utilities"), "settings": ("System", "Settings"),
}


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
    if groups != ["overview", "sites", "security", "certs", "traffic", "network", "ha", "system"]:
        fail("nav", f"unexpected nav groups {groups}")
    missing = pg.evaluate("""() => [...document.querySelectorAll('#mainmenu a.item[tag]')].filter(a => {
        const i = a.querySelector(':scope > i.icon'); if (!i) return true;
        const c = getComputedStyle(i, '::before').content; return !c || c === 'none' || c === 'normal' || c === '""'; }).map(a => a.getAttribute('tag'))""")
    if missing:
        fail("nav", f"menu items without a rendered icon: {missing}")
    gicons = pg.evaluate("""() => [...document.querySelectorAll('#mainmenu .menugroup-header[data-group] > i.icon:first-child')].filter(i => {
        const c = getComputedStyle(i, '::before').content; return !c || c === 'none' || c === 'normal' || c === '""'; }).map(i => i.parentElement.dataset.group)""")
    if gicons:
        fail("nav", f"menu groups without a rendered icon: {gicons}")
    for tab in OLD_TABS:
        if pg.locator(f"#mainmenu a.item[tag='{tab}']").count() != 1:
            fail("nav", f"menu item for tab {tab} missing or duplicated")
    heads = pg.evaluate("""() => [...document.querySelectorAll('#mainmenu .menugroup-header[data-group]')].map(h => [h.getAttribute('role'), h.getAttribute('aria-controls'),
        h.getAttribute('aria-expanded'), h.tabIndex])""")
    if any(h[0] != "button" or not h[1] or h[2] not in ("true", "false") or h[3] < 0 for h in heads):
        fail("a11y", f"menu group headers need role=button, aria-controls, aria-expanded and to be focusable: {heads}")
    if pg.locator("#mainmenu a.item[aria-current=page]").count() != 1:
        fail("a11y", "exactly one menu item must carry aria-current=page")
    pg.evaluate("if ($('#group-network').is(':hidden')) toggleMenuGroup('network')")
    pg.wait_for_timeout(400)
    pg.click("#mainmenu .menugroup-header[data-group=network]")
    pg.wait_for_timeout(450)
    if pg.is_visible("#group-network"):
        fail("nav", "clicking a group header did not collapse the group")
    if pg.evaluate("JSON.parse(localStorage.getItem('zoraxy_menu_groups')).network") is not False:
        fail("nav", "collapsed state not saved")
    if pg.get_attribute("#mainmenu .menugroup-header[data-group=network]", "aria-expanded") != "false":
        fail("a11y", "aria-expanded not updated after collapsing")
    pg.click("#mainmenu .menugroup-header[data-group=network]")
    pg.wait_for_timeout(450)
    if not pg.is_visible("#group-network"):
        fail("nav", "clicking the header again did not expand the group")
    # keyboard: Enter on a focused header toggles it, ArrowDown moves to the next entry
    pg.focus("#mainmenu .menugroup-header[data-group=network]")
    pg.keyboard.press("ArrowDown")
    if pg.evaluate("document.activeElement.getAttribute('tag')") != "globalsettings":
        fail("a11y", "ArrowDown from a group header should focus its first item")
    pg.keyboard.press("ArrowLeft")
    if pg.evaluate("document.activeElement.dataset.group") != "network":
        fail("a11y", "ArrowLeft on an item should focus its group header")
    pg.keyboard.press("Enter")
    pg.wait_for_timeout(450)
    if pg.is_visible("#group-network"):
        fail("a11y", "Enter on a group header did not collapse it")
    pg.keyboard.press("Enter")
    pg.wait_for_timeout(450)
    # opening a page expands its group and leaves the other groups alone
    pg.evaluate("localStorage.setItem('zoraxy_menu_groups', JSON.stringify({_v: 3, overview: true, sites: true, system: false}))")
    pg.reload(wait_until="networkidle")
    pg.wait_for_timeout(900)
    pg.evaluate("openTabById('cert')")
    pg.wait_for_timeout(500)
    if not pg.is_visible("#group-certs") or not pg.is_visible("#group-sites") or pg.is_visible("#group-system"):
        fail("nav", "opening a page must expand its group only (sites stays open, system stays closed)")
    # state saved by the previous menus (old group ids) is carried over to the groups that replaced them
    pg.evaluate("localStorage.setItem('zoraxy_menu_groups', JSON.stringify({_v: 2, proxy: false, tools: false, observe: true, system: false, security: true}))")
    pg.reload(wait_until="networkidle")
    pg.wait_for_timeout(900)
    st = pg.evaluate("JSON.parse(localStorage.getItem('zoraxy_menu_groups'))")
    if st.get("sites") is not False or st.get("network") is not False or st.get("traffic") is not True or st.get("system") is not False or st.get("_v") != 3 or "proxy" in st or "tools" in st:
        fail("nav", f"menu state migration v2 -> v3 wrong: {st}")
    pg.evaluate("localStorage.setItem('zoraxy_menu_groups', JSON.stringify({reverseproxy:false, others:false, security:true, accessconn:true}))")
    pg.reload(wait_until="networkidle")
    pg.wait_for_timeout(900)
    st = pg.evaluate("JSON.parse(localStorage.getItem('zoraxy_menu_groups'))")
    if st.get("sites") is not False or st.get("system") is not False or st.get("_v") != 3 or "reverseproxy" in st:
        fail("nav", f"menu state migration v1 -> v3 wrong: {st}")
    pg.evaluate("localStorage.removeItem('zoraxy_menu_groups')")
    pg.reload(wait_until="networkidle")
    pg.wait_for_timeout(900)
    if not pg.is_visible("#group-overview"):
        fail("nav", "first visit: the Overview group should be open")
    pg.evaluate("openTabById('status')")
    pg.wait_for_timeout(300)
    pg.screenshot(path=out("nav-groups.png"))

    # ---- Quick Start: dismiss, stays away after a reload, comes back from Settings ----
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
    pg.evaluate("openTabById('settings')")
    settle(pg, 500)
    if not pg.is_visible(".quickStartShowAgain"):
        fail("quickstart", "'Show Quick Start again' is missing in Settings")
    else:
        pg.click(".quickStartShowAgain button")
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
        pg.click("#bulkBar button[data-act=access]")
        pg.wait_for_selector("#bulkAccess", state="visible", timeout=5000)
        pg.click("#bulkModal .actions button:has-text('Preview')")
        pg.wait_for_function("document.querySelector('#bulkModal .content').innerText.indexOf('rule(s)') > -1", timeout=8000)
        pg.screenshot(path=out("httprp-bulk-access.png"))
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


def nav_palette(pg, ctx):
    """Navigation redesign: every legacy tab id still opens its page with the right breadcrumb, deep links, command palette
    (Ctrl+K: page, host, setting, XSS safety, keyboard), the settings index anchors, the UI kit page, and the save bar on
    Listeners and Settings."""
    out = lambda n: os.path.join(args.out, n)
    pg.set_viewport_size({"width": 1366, "height": 900})
    api = lambda path, data: pg.evaluate(API, [path, data, "POST"])
    host = "palette-host.smoke.invalid"
    evil = "x<img src=x onerror=window.__xss=1>.smoke.invalid"
    pg.evaluate("localStorage.removeItem('zoraxy_palette_recent')")
    pg.reload(wait_until="networkidle")
    pg.wait_for_timeout(800)
    api("/api/proxy/add", {"type": "host", "rootname": host, "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false"})

    # ---- every legacy tab id: opens, component loaded, breadcrumb "Group / Page", aria-current ----
    for tab, (group, label) in OLD_TABS.items():
        current["page"] = f"legacy-tab/{tab}"
        pg.evaluate("t => openTabById(t)", tab)
        settle(pg, 450)
        vis = pg.evaluate("""t => { const e = document.getElementById(t); return e && e.offsetParent !== null ? e.innerText.trim().length : -1 }""", tab)
        if vis <= 0:
            fail("legacy-tab", f"#{tab} did not open or is empty ({vis})")
        crumbs = pg.evaluate("""() => { const vis = [...document.querySelectorAll('.zx-crumbs')].filter(c => c.offsetParent !== null)[0];
            return vis ? [...vis.querySelectorAll('li')].map(li => li.textContent.trim()) : null }""")
        if crumbs != [group, label]:
            fail("breadcrumb", f"{tab}: expected {[group, label]}, got {crumbs}")
        if pg.evaluate("location.hash") != "#" + tab:
            fail("legacy-tab", f"{tab}: location.hash is {pg.evaluate('location.hash')}")
        if pg.evaluate("document.querySelector('#mainmenu a.item[aria-current=page]').getAttribute('tag')") != tab:
            fail("a11y", f"{tab}: aria-current is not on its menu item")
        if label.replace(" ", "") not in pg.evaluate("document.title").replace(" ", ""):
            fail("legacy-tab", f"{tab}: document title {pg.evaluate('document.title')!r} lacks {label}")
    # deep links by URL hash
    for tab in ("httprp", "cert", "globalsettings", "settings", "waf", "fleet"):
        current["page"] = f"deeplink/{tab}"
        pg.goto(args.url + "/#" + tab, wait_until="networkidle")
        pg.reload(wait_until="networkidle")
        pg.wait_for_timeout(700)
        if not pg.is_visible("#" + tab):
            fail("deeplink", f"#{tab} did not open from the URL hash")

    # ---- command palette ----
    current["page"] = "palette"
    pg.goto(args.url + "/#status", wait_until="networkidle")
    pg.wait_for_timeout(800)
    pg.keyboard.press("Control+k")
    pg.wait_for_selector("#zxPalette:not([hidden])", timeout=3000)
    if pg.evaluate("document.activeElement.className") != "zx-palette__input":
        fail("palette", "the search input is not focused after Ctrl+K")
    pg.keyboard.type("firewall")
    pg.wait_for_timeout(250)
    first = pg.inner_text("#zxPalette [role=option] >> nth=0").replace("\n", " ")
    if "WAF" not in first:
        fail("palette", f"'firewall' should find the WAF first, got {first!r}")
    pg.screenshot(path=out("palette-light.png"))
    pg.fill("#zxPalette input", "ssl")
    pg.wait_for_timeout(200)
    if "TLS / SSL Certificates" not in pg.inner_text("#zxPalette [role=option] >> nth=0"):
        fail("palette", "'ssl' should find Certificates")
    pg.fill("#zxPalette input", "ban")
    pg.wait_for_timeout(200)
    txt = pg.inner_text("#zxPalette")
    if "Access Rules" not in txt or "Auto-ban" not in txt:
        fail("palette", "'ban' should find Access Rules and Auto-ban")
    # a proxy host
    pg.fill("#zxPalette input", "palette-host")
    pg.wait_for_function("document.querySelector('#zxPalette .zx-palette__label') && document.querySelector('#zxPalette .zx-palette__label').textContent.includes('palette-host')", timeout=4000)
    if "Sites" not in pg.eval_on_selector_all("#zxPalette .zx-palette__group", "els => els.map(e => e.textContent)"):
        fail("palette", "hosts should be listed under 'Sites'")
    pg.keyboard.press("Enter")
    pg.wait_for_timeout(900)
    if pg.evaluate("document.querySelector('#zxPalette').hidden") is not True:
        fail("palette", "Enter did not close the palette")
    if not pg.is_visible("#httprp"):
        fail("palette", "choosing a host did not open the HTTP Proxy page")
    # a setting inside a closed accordion
    pg.keyboard.press("Control+k")
    pg.keyboard.type("minimum tls")
    pg.wait_for_timeout(250)
    if "Minimum TLS version" not in pg.inner_text("#zxPalette [role=option] >> nth=0"):
        fail("palette", "'minimum tls' should find the setting first")
    pg.keyboard.press("Enter")
    pg.wait_for_timeout(1800)
    if not pg.is_visible("#globalsettings"):
        fail("palette", "choosing a setting did not open its page")
    if not pg.is_visible("#tlsVersionSlider"):
        fail("palette", "the setting's accordion was not opened / anchor not visible")
    # arrow keys + recent + Escape
    pg.keyboard.press("Control+k")
    pg.wait_for_timeout(200)
    if "Minimum TLS version" not in pg.inner_text("#zxPalette"):
        fail("palette", "recent items are not listed when the query is empty")
    pg.keyboard.type("stat")
    pg.keyboard.press("ArrowDown")
    if pg.evaluate("document.querySelectorAll('#zxPalette [aria-selected=true]').length") != 1:
        fail("palette", "exactly one result must be selected")
    pg.keyboard.press("Escape")
    pg.wait_for_timeout(150)
    if pg.evaluate("document.querySelector('#zxPalette').hidden") is not True:
        fail("palette", "Escape did not close the palette")
    pg.keyboard.press("Control+k")
    pg.keyboard.press("Control+k")
    if pg.evaluate("document.querySelector('#zxPalette').hidden") is not True:
        fail("palette", "Ctrl+K again should close it")
    # the header button, and the old "/" menu filter next to it
    pg.click("#zxSearchBtn")
    pg.wait_for_selector("#zxPalette:not([hidden])", timeout=3000)
    pg.keyboard.press("Escape")
    pg.keyboard.press("/")
    if pg.evaluate("document.activeElement.id") != "navFilterInput":
        fail("palette", "'/' no longer focuses the menu filter")
    pg.keyboard.press("Escape")
    # XSS: a host name that is HTML must be shown as text and must not run. The hostile rule exists only for this check
    # (other pages of the UI render rule names too).
    evil_res = api("/api/proxy/add", {"type": "host", "rootname": evil, "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false"})
    if not (isinstance(evil_res, dict) and evil_res.get("error")):
        pg.keyboard.press("Control+k")
        pg.keyboard.type("smoke.invalid")
        pg.wait_for_function("document.querySelectorAll('#zxPalette [role=option]').length >= 2", timeout=4000)
        pg.wait_for_timeout(400)
        if pg.evaluate("window.__xss") is not None:
            fail("palette", "XSS: markup in a host name was executed")
        if pg.locator("#zxPalette img").count():
            fail("palette", "XSS: markup in a host name was rendered as an element")
        if "<img" not in pg.inner_text("#zxPalette"):
            fail("palette", "the hostile host name should be shown literally as text")
        pg.keyboard.press("Escape")
        api("/api/proxy/del", {"ep": evil})
    else:
        print("  note: the server refused the hostile host name, XSS check limited to static review:", evil_res.get("error"))
    # palette on a phone and in the dark theme
    pg.set_viewport_size({"width": 390, "height": 700})
    pg.keyboard.press("Control+k")
    pg.keyboard.type("waf")
    pg.wait_for_timeout(300)
    check_horizontal(pg, "palette mobile")
    pg.screenshot(path=out("palette-mobile.png"))
    pg.keyboard.press("Escape")
    pg.set_viewport_size({"width": 1366, "height": 900})
    if not pg.evaluate("document.body.classList.contains('darkTheme')"):
        pg.evaluate("toggleTheme()")
    pg.keyboard.press("Control+k")
    pg.keyboard.type("ssl")
    pg.wait_for_timeout(300)
    pg.screenshot(path=out("palette-dark.png"))
    pg.keyboard.press("Escape")
    pg.evaluate("toggleTheme()")
    api("/api/proxy/del", {"ep": host})

    # ---- the settings index: every anchor resolves ----
    entries = pg.evaluate("ZxPalette.settings.map(s => ({label: s.label, page: s.page, pre: s.pre || '', at: s.at || '', text: s.text || ''}))")
    if len(entries) < 40:
        fail("palette", f"settings index has only {len(entries)} entries (need at least 40)")
    for e in entries:
        current["page"] = f"settings-index/{e['label']}"
        pg.evaluate("t => openTabById(t)", e["page"])
        settle(pg, 350)
        if e["pre"]:
            pg.evaluate("([p, sel]) => { const el = document.querySelector('#' + p + ' ' + sel); if (el) el.click(); }", [e["page"], e["pre"]])
            pg.wait_for_timeout(450)
        found = pg.evaluate("""([p, at, text]) => { const root = document.getElementById(p);
            if (at && root.querySelector(at)) return true;
            if (text) return [...root.querySelectorAll('h1,h2,h3,h4,label,.title,button,b')].some(n => n.textContent.includes(text));
            return false }""", [e["page"], e["at"], e["text"]])
        if not found:
            fail("palette", f"settings index entry {e['label']!r}: anchor {e['at'] or e['text']!r} not found on #{e['page']}")

    # ---- UI kit page (served only with -dev; this test server runs with -dev) ----
    current["page"] = "kit"
    kp = ctx.new_page()
    kp.on("pageerror", lambda e: fail("pageerror", str(e)))
    kp.on("console", lambda m: m.type == "error" and fail("console.error", m.text + " " + m.location.get("url", "")))
    kp.on("response", lambda r: r.status >= 400 and fail("http", f"{r.status} {r.url}"))
    kp.goto(args.url + "/ui/kit.html", wait_until="networkidle")
    kp.wait_for_function("window.__kitReady === true", timeout=5000)
    if kp.locator(".kit-pane").count() < 28:
        fail("kit", f"kit page shows only {kp.locator('.kit-pane').count()} panes")
    if kp.locator(".kit-fail").count():
        fail("kit", "contrast table of the kit has failing pairs")
    dups = kp.evaluate("(() => { const a = [...document.querySelectorAll('[id]')].map(e => e.id); return a.filter((x, i) => a.indexOf(x) !== i) })()")
    if dups:
        fail("kit", f"duplicate ids on the kit page: {dups[:5]}")
    kp.screenshot(path=out("kit-light.png"), full_page=True)
    kp.evaluate("setDarkTheme(true)")
    kp.wait_for_timeout(300)
    kp.screenshot(path=out("kit-dark.png"), full_page=True)
    kp.set_viewport_size({"width": 390, "height": 800})
    kp.wait_for_timeout(300)
    check_horizontal(kp, "kit 390px")
    kp.screenshot(path=out("kit-mobile.png"), full_page=True)
    kp.evaluate("setDarkTheme(false)")
    kp.close()
    if pg.locator("#mainmenu a.item[href='ui/kit.html']").count() != 1 or not pg.evaluate("[...document.querySelectorAll('#mainmenu a.item[href=\"ui/kit.html\"]')].every(a => a.style.display !== 'none')"):
        fail("kit", "the UI kit menu entry is not visible on a -dev server")

    # ---- Listeners: one Save bar instead of Apply buttons ----
    current["page"] = "listeners-savebar"
    pg.evaluate("openTabById('globalsettings')")
    settle(pg, 1200)
    if pg.locator("#globalsettings button:has-text('Apply')").count():
        fail("listeners", "per-field Apply buttons are still on the Listeners page")
    for gone in ("#uiLanguageSetting", ".quickStartShowAgain", "#defaultErrorPagesBtn"):
        if pg.locator("#globalsettings " + gone).count():
            fail("listeners", f"{gone} must live on the Settings page only")
    if pg.evaluate("document.querySelector('#globalsettings .zx-savebar').hidden") is not True:
        fail("listeners", "the save bar must be hidden while nothing changed")
    if not pg.is_visible("#readHeaderTimeoutInput"):
        pg.click("#statusAdvanceSettings > .title")   # the timeouts sit in the Advance Settings accordion
        pg.wait_for_timeout(500)
    old = pg.evaluate("$.get('/api/proxy/timeouts')")
    pg.fill("#readHeaderTimeoutInput", str(int(old["readHeaderTimeout"]) + 7))
    pg.fill("#idleTimeoutInput", str(int(old["idleTimeout"]) + 3))
    pg.wait_for_timeout(300)
    bar_txt = pg.inner_text("#globalsettings .zx-savebar")
    if "2 unsaved changes" not in bar_txt or "Read Header Timeout" not in bar_txt:
        fail("listeners", f"save bar should count and name the two changed fields: {bar_txt!r}")
    pg.screenshot(path=out("listeners-savebar-light.png"))
    pg.click("#globalsettings [data-zx-save]")
    pg.wait_for_function("document.querySelector('#globalsettings .zx-savebar').classList.contains('is-success')", timeout=8000)
    new = pg.evaluate("$.get('/api/proxy/timeouts')")
    if int(new["readHeaderTimeout"]) != int(old["readHeaderTimeout"]) + 7 or int(new["idleTimeout"]) != int(old["idleTimeout"]) + 3:
        fail("listeners", f"the save bar did not apply the timeouts: {old} -> {new}")
    pg.wait_for_function("document.querySelector('#globalsettings .zx-savebar').hidden", timeout=6000)
    # programmatic changes (page code filling the form) must not make it dirty; a failing save keeps the bar and the values
    pg.evaluate("$('#readHeaderTimeoutInput').val('55').trigger('input').trigger('change')")
    pg.wait_for_timeout(300)
    if pg.evaluate("document.querySelector('#globalsettings .zx-savebar').hidden") is not True:
        fail("listeners", "a programmatic change marked the form dirty")
    pg.evaluate("$('#readHeaderTimeoutInput').val(" + str(int(new["readHeaderTimeout"])) + ")")
    pg.fill("#incomingPort", "99999")
    pg.click("#globalsettings [data-zx-save]")
    pg.wait_for_function("document.querySelector('#globalsettings .zx-savebar').classList.contains('is-error')", timeout=5000)
    if "Invalid incoming port value" not in pg.inner_text("#globalsettings .zx-savebar"):
        fail("listeners", "the save bar should show the validation message of the port")
    pg.screenshot(path=out("listeners-savebar-error.png"))
    # leaving the page asks first; Discard puts the old value back
    pg.evaluate("openTabById('status')")
    pg.wait_for_selector(".zx-dialog", timeout=3000)
    pg.click(".zx-dialog [data-zx-cancel]")
    if not pg.is_visible("#globalsettings"):
        fail("listeners", "'Stay on this page' must keep the Listeners page open")
    pg.click("#globalsettings [data-zx-discard]")
    pg.wait_for_timeout(300)
    if pg.evaluate("document.querySelector('#globalsettings .zx-savebar').hidden") is not True or pg.input_value("#incomingPort") == "99999":
        fail("listeners", "Discard did not restore the saved values")
    # put the timeouts back through the bar
    pg.fill("#readHeaderTimeoutInput", str(old["readHeaderTimeout"]))
    pg.fill("#idleTimeoutInput", str(old["idleTimeout"]))
    pg.click("#globalsettings [data-zx-save]")
    pg.wait_for_function("document.querySelector('#globalsettings .zx-savebar').classList.contains('is-success')", timeout=8000)
    back = pg.evaluate("$.get('/api/proxy/timeouts')")
    if int(back["readHeaderTimeout"]) != int(old["readHeaderTimeout"]):
        fail("listeners", f"restoring the timeouts failed: {back}")

    # ---- Settings: language and default error pages live here ----
    current["page"] = "settings-savebar"
    pg.evaluate("openTabById('settings')")
    settle(pg, 700)
    pg.screenshot(path=out("settings-light.png"))
    pg.focus("#uiLanguageSetting")
    pg.keyboard.type("Deutsch")   # a real (trusted) change event; select_option would fire a synthetic one, which the dirty tracker ignores by design
    pg.wait_for_timeout(250)
    if pg.evaluate("document.querySelector('#settings .zx-savebar').hidden") is not False:
        fail("settings", "choosing a language should show the save bar")
    if pg.evaluate("i18n.lang") != "en":
        fail("settings", "the language must only change when the bar is saved")
    pg.click("#settings [data-zx-save]")
    pg.wait_for_function("i18n.lang === 'de'", timeout=6000)
    pg.wait_for_timeout(600)
    if pg.input_value(".menubar select.i18n-picker") != "de":
        fail("settings", "the picker in the top bar did not follow")
    saved = pg.evaluate("fetch('/api/i18n/language').then(r => r.json())")
    if saved.get("language") != "de":
        fail("settings", f"language not stored on the server: {saved}")
    pg.evaluate("i18n.setLanguage('en')")
    pg.wait_for_function("i18n.lang === 'en'", timeout=5000)
    pg.evaluate("$.cjax({url: '/api/i18n/language', method: 'POST', data: {language: ''}})")
    pg.evaluate("localStorage.removeItem('zoraxy.lang')")
    pg.wait_for_timeout(300)
    pg.click("#defaultErrorPagesBtn")
    pg.wait_for_timeout(900)
    if not pg.is_visible(".sideWrapper"):
        fail("settings", "'Default error pages' did not open the side panel")
    pg.evaluate("hideSideWrapper(true)")
    pg.wait_for_timeout(500)


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
        for tab in ("seccenter", "waf", "cert", "globalsettings", "settings"):
            pg.evaluate("t => openTabById(t)", tab)
            settle(pg, 900)
        pg.evaluate("openTabById('settings')")
        settle(pg, 900)
        if "界面语言" not in pg.inner_text("#settings"):
            fail("i18n", "Settings page not translated (language label)")
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
def waf_graduated_ui(pg):
    """WAF > Policy > Graduated response (log / challenge / block): band visual, validation, save, provider warning;
    profile editor fields; Events filter. Light, dark and 390px screenshots."""
    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=True)

    def theme(want_dark):
        if pg.evaluate("document.body.classList.contains('darkTheme')") != want_dark:
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(300)

    def api(path, data=None):
        return pg.evaluate("""([p, d]) => new Promise(res => (d ? $.cjax({url: p, method: 'POST', data: d, success: r => res(r), error: e => res({error: 'http ' + e.status})})
            : $.getJSON(p, r => res(r)).fail(e => res({error: 'http ' + e.status}))))""", [path, data])

    theme(False)
    pg.set_viewport_size({"width": 1366, "height": 900})
    orig = api("/api/waf/policy")
    try:
        pg.click("#wafTabs .item[data-tab=waf-policy]")
        settle(pg, 600)
        for sel in ("#wafpChallenge", "#wafpChallengeTTL", "#wafpBands"):
            if not pg.is_visible(sel):
                fail("waf-bands", f"{sel} is not visible on the policy tab")
        if pg.locator("#wafpBands .wafBand").count() != 2:
            fail("waf-bands", "with the challenge band off the bar must show log and block only")
        pg.fill("#wafpChallenge", "3")
        pg.wait_for_timeout(200)
        labels = pg.inner_text("#wafpBands")
        if pg.locator("#wafpBands .wafBand").count() != 3 or "Challenge" not in labels or "3 - 4" not in labels:
            fail("waf-bands", f"band bar does not show log | challenge | block for 3/5: {labels!r}")
        # invalid: not below the block threshold
        pg.fill("#wafpChallenge", "5")
        pg.wait_for_timeout(200)
        if "must be lower" not in pg.inner_text("#wafpBandWarn"):
            fail("waf-bands", "challenge >= block shows no warning")
        pg.click("#wafpSave")
        pg.wait_for_timeout(1200)
        if (api("/api/waf/policy") or {}).get("ChallengeThreshold", 0) != 0:
            fail("waf-bands", "an invalid challenge threshold was saved")
        # valid save; then the policy is enabled in block mode so the root rule shows the missing-provider warning
        pg.fill("#wafpChallenge", "3")
        pg.fill("#wafpChallengeTTL", "45")
        pg.click("#wafpSave")
        pg.wait_for_timeout(1500)
        pol = api("/api/waf/policy") or {}
        if pol.get("ChallengeThreshold") != 3 or pol.get("ChallengeTTLMinutes") != 45:
            fail("waf-bands", f"challenge settings were not saved: {pol.get('ChallengeThreshold')}/{pol.get('ChallengeTTLMinutes')}")
        r = api("/api/waf/policy", {"policy": json.dumps(dict(pol, Enabled=True, DefaultMode="block"))})
        if isinstance(r, dict) and r.get("error"):
            fail("waf-bands", f"could not enable the policy: {r['error']}")
        pg.click("#wafTabs .item[data-tab=waf-coverage]")
        settle(pg, 900)
        pg.click("#wafTabs .item[data-tab=waf-policy]")
        settle(pg, 600)
        if not pg.is_visible("#wafpBandWarn") or "CAPTCHA provider" not in pg.inner_text("#wafpBandWarn"):
            fail("waf-bands", "no provider warning although a Block rule has no CAPTCHA provider")
        pg.click("#wafTabs .item[data-tab=waf-overview]")
        settle(pg, 900)
        if "CAPTCHA provider" not in pg.inner_text("#wafNeeds"):
            fail("waf-bands", "the overview does not flag the challenge band without a provider")
        pg.click("#wafTabs .item[data-tab=waf-policy]")
        settle(pg, 500)
        pg.locator("#wafpBandBox").scroll_into_view_if_needed()
        shot("waf-bands-light.png")
        theme(True)
        pg.locator("#wafpBandBox").scroll_into_view_if_needed()
        shot("waf-bands-dark.png")
        pg.set_viewport_size({"width": 390, "height": 800})
        settle(pg, 400)
        pg.locator("#wafpBandBox").scroll_into_view_if_needed()
        shot("waf-bands-390-dark.png")
        if pg.evaluate("document.documentElement.scrollWidth > innerWidth + 2"):
            fail("waf-bands", "the policy tab scrolls horizontally at 390px")
        theme(False)
        settle(pg, 300)
        shot("waf-bands-390-light.png")
        pg.set_viewport_size({"width": 1366, "height": 900})

        # profile editor fields
        pg.click("#wafTabs .item[data-tab=waf-profiles]")
        settle(pg, 500)
        pg.click("#wafPrNew")
        pg.wait_for_timeout(300)
        if not pg.is_visible("#wafprChallenge") or not pg.is_visible("#wafprChallengeTTL"):
            fail("waf-bands", "profile editor has no challenge fields")
        shot("waf-bands-profile.png")
        pg.click("#wafprClose")
        # events filter
        pg.click("#wafTabs .item[data-tab=waf-events]")
        settle(pg, 500)
        opts = pg.evaluate("[...document.querySelectorAll('#wafevAction option')].map(o => o.value)")
        if "challenged" not in opts or "challenge_passed" not in opts:
            fail("waf-bands", f"events filter lacks the challenge results: {opts}")
    finally:
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 900})
        if isinstance(orig, dict) and "error" not in orig:
            api("/api/waf/policy", {"policy": json.dumps(orig)})


def waf_tuning_ui(pg):
    """WAF > Tuning tab (suggestion cards, confirmation dialog, ignore), the Events drawer button for one variable and
    the variable exclusions in the Exclusions list. The suggestions and events are served from fixtures (a fresh instance has
    no traffic); the exclusion list round trip uses the real API."""
    import json as _json
    out = lambda n: os.path.join(args.out, n)
    posted = []

    def theme(want_dark):
        if pg.evaluate("document.body.classList.contains('darkTheme')") != want_dark:
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(300)

    now = "2026-01-05T10:00:00Z"

    def item(rule, msg, sev, ep, var, coll, sug, risk, note, attack=False, count=7, clients=3, data="", path="/", paths=None):
        return {"key": f"{ep}|{rule}|{var}", "rule_id": rule, "message": msg, "severity": sev, "category": "x", "endpoint": ep, "variable": var,
                "collection": coll, "count": count, "clients": clients, "would_block": count - 1, "first_seen": now, "last_seen": now,
                "paths": paths or [path], "path_count": len(paths or [path]), "payload_shapes": 1,
                "sample": {"time": now, "txid": "abc", "path": path, "variable": var, "data": data},
                "suggestion": sug, "risk": risk, "risk_note": note, "looksLikeAttack": attack}

    longpath = "/api/very/long/path/that/keeps/going/and/going/to/test/wrapping/on/narrow/screens/editor"
    items = [
        item(942290, "Finds basic MongoDB SQL injection attempt", "critical", "app.smoke.example.com", "REQUEST_COOKIES:ph_*_posthog", "REQUEST_COOKIES",
             {"kind": "variable", "rule_ids": ["942290"], "target": "REQUEST_COOKIES:/^ph_.+_posthog$/", "summary": "Rule 942290 stops inspecting REQUEST_COOKIES:/^ph_.+_posthog$/ on every path"},
             "low", "only this variable is excluded; the rule still inspects everything else", data='{"distinct_id":"anonymous_x.example.com","$sesid":[null,null,null]',
             paths=["/", "/blog", "/shop"], count=48, clients=9),
        item(942100, "SQL Injection Attack Detected via libinjection", "critical", "api.smoke.example.com", "ARGS:json.items.*.description", "ARGS",
             {"kind": "variable", "rule_ids": ["942100"], "target": "ARGS:/^json\\.items\\.\\d+\\.description$/", "path": longpath, "exact": True,
              "summary": "Rule 942100 stops inspecting ARGS:/^json\\.items\\.\\d+\\.description$/ on " + longpath},
             "low", "only this variable is excluded; the rule still inspects everything else", data="Tom & Jerry's: select a 'name' from -- the menu", path=longpath, count=3, clients=1),
        item(920420, "Request content type is not allowed by policy", "critical", "app.smoke.example.com", "REQUEST_HEADERS:content-type", "REQUEST_HEADERS",
             {"kind": "variable", "rule_ids": ["920420"], "target": "REQUEST_HEADERS:content-type", "summary": "Rule 920420 stops inspecting REQUEST_HEADERS:content-type on every path"},
             "medium", "only 2 hit(s): make sure it was your own traffic", data="application/x-weird", count=2, clients=2),
        item(932100, "Remote Command Execution: Unix Command Injection", "critical", "app.smoke.example.com", "ARGS:cmd", "ARGS",
             {"kind": "variable", "rule_ids": ["932100"], "target": "ARGS:cmd", "path": "/run", "exact": True, "summary": "Rule 932100 stops inspecting ARGS:cmd on /run"},
             "high", "Probably a real attack. rule family: remote command execution (rarely a false positive)", attack=True, data="; cat /etc/passwd", path="/run", count=12, clients=5),
    ]
    rep = {"hours": 24, "events_scanned": 72, "items": items}

    def tuning_route(route):
        route.fulfill(status=200, content_type="application/json", body=_json.dumps(rep))

    def apply_route(route):
        posted.append(route.request.post_data or "")
        route.fulfill(status=200, content_type="application/json", body='"OK"')

    ev = {"time": now, "txid": "tx1", "endpoint": "app.smoke.example.com", "client_ip": "198.51.100.5", "method": "GET", "host": "app.smoke.example.com", "path": "/blog",
          "uri": "/blog", "action": "detected", "would_block": True, "mode": "detection_only", "source": "global",
          "rules": [{"id": 942290, "msg": "Finds basic MongoDB SQL injection attempt", "severity": "critical", "data": "{\"distinct_id\":\"x\"",
                     "variable": "REQUEST_COOKIES:ph_phc_abc_posthog", "var_norm": "REQUEST_COOKIES:ph_phc_abc_posthog"},
                    {"id": 949110, "msg": "Inbound Anomaly Score Exceeded", "severity": "critical"}]}

    re_tuning, re_apply, re_events = re.compile(r"/api/waf/tuning\?"), re.compile(r"/api/waf/tuning/apply"), re.compile(r"/api/waf/events")
    pg.route(re_tuning, tuning_route)
    pg.route(re_apply, apply_route)
    pg.route(re_events, lambda route: route.fulfill(status=200, content_type="application/json", body=_json.dumps([ev])))
    try:
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.evaluate("openTabById('waf')")
        settle(pg, 900)
        pg.click("#wafTabs .item[data-tab=waf-tuning]")
        pg.wait_for_selector("#wafTuneList .wafTuneCard", timeout=8000)
        if pg.locator("#wafTuneList .wafTuneCard").count() != 4:
            fail("waf-tuning", "expected 4 suggestion cards")
        txt = pg.inner_text("#wafTuneList")
        for want in ("942290", "REQUEST_COOKIES:ph_*_posthog", "Probably an attack", "Low risk", "Check first", "Apply to this proxy rule", "Apply globally", "Ignore"):
            if want not in txt:
                fail("waf-tuning", f"card text misses {want!r}")
        pg.screenshot(path=out("waf-tuning-light.png"), full_page=True)

        # confirmation dialog shows exactly what is excluded
        pg.click("#wafTuneList .wafTuneCard:nth-child(1) .wafTuneApply[data-scope=global]")
        pg.wait_for_selector("#wafTuneDlg .wafTuneEffect", timeout=4000)
        dlg = pg.inner_text("#wafTuneDlg")
        for want in ("942290", "REQUEST_COOKIES:/^ph_.+_posthog$/", "every proxy rule", "every path", "no longer inspect this variable"):
            if want not in dlg:
                fail("waf-tuning", f"confirmation misses {want!r}: {dlg[:200]!r}")
        pg.screenshot(path=out("waf-tuning-confirm-light.png"))
        theme(True)
        pg.screenshot(path=out("waf-tuning-confirm-dark.png"))
        pg.set_viewport_size({"width": 390, "height": 800})
        pg.wait_for_timeout(300)
        box = pg.evaluate("(() => { const r = document.querySelector('#wafTuneDlg').getBoundingClientRect(); return {l: r.left, r: r.right, w: innerWidth}; })()")
        if box["l"] < -1 or box["r"] > box["w"] + 1:
            fail("layout", f"tuning dialog does not fit a 390px screen: {box}")
        pg.screenshot(path=out("waf-tuning-confirm-390-dark.png"))
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.click("#wafTuneCancel")
        if posted:
            fail("waf-tuning", "cancel must not apply anything")
        pg.click("#wafTuneList .wafTuneCard:nth-child(1) .wafTuneApply[data-scope=global]")
        pg.wait_for_selector("#wafTuneOk", timeout=4000)
        pg.click("#wafTuneOk")
        pg.wait_for_timeout(600)
        if len(posted) != 1 or "scope=global" not in posted[0] or "REQUEST_COOKIES" not in posted[0] or "942290" not in posted[0]:
            fail("waf-tuning", f"apply request wrong: {posted}")
        if pg.is_visible("#wafTuneDlg"):
            fail("waf-tuning", "dialog still open after applying")

        # an attack-like suggestion warns before it applies; the endpoint scope names the proxy rule
        pg.click("#wafTuneList .wafTuneCard:nth-child(4) .wafTuneApply[data-scope=endpoint]")
        pg.wait_for_selector("#wafTuneDlg .wafTuneWarn", timeout=4000)
        d2 = pg.inner_text("#wafTuneDlg")
        if "app.smoke.example.com" not in d2 or "real attack" not in d2:
            fail("waf-tuning", f"attack confirmation wrong: {d2[:200]!r}")
        pg.click("#wafTuneCancel")

        # ignore hides, "show ignored" brings it back
        pg.click("#wafTuneList .wafTuneCard:nth-child(3) .wafTuneIgnore")
        if pg.locator("#wafTuneList .wafTuneCard").count() != 3:
            fail("waf-tuning", "ignored suggestion is still listed")
        pg.click("label[for=wafTuneShowIgnored]")
        if pg.locator("#wafTuneList .wafTuneCard").count() != 4:
            fail("waf-tuning", "show ignored does not list it")
        pg.click("#wafTuneList .wafTuneCard.ignored .wafTuneIgnore")
        pg.click("label[for=wafTuneShowIgnored]")

        # dark and phone layouts of the tab itself
        theme(True)
        pg.screenshot(path=out("waf-tuning-dark.png"), full_page=True)
        pg.set_viewport_size({"width": 390, "height": 800})
        pg.wait_for_timeout(400)
        check_horizontal(pg, "waf tuning 390px")
        wide = pg.evaluate("""() => [...document.querySelectorAll('#wafTuneList *')].filter(e => e.getBoundingClientRect().right > innerWidth + 1).map(e => e.className).slice(0, 3)""")
        if wide:
            fail("layout", f"tuning cards overflow a 390px screen: {wide}")
        pg.screenshot(path=out("waf-tuning-390-dark.png"), full_page=True)
        theme(False)
        pg.screenshot(path=out("waf-tuning-390-light.png"), full_page=True)
        pg.set_viewport_size({"width": 1366, "height": 900})

        # Events drawer: exclude only this variable
        posted.clear()
        pg.click("#wafTabs .item[data-tab=waf-events]")
        pg.wait_for_selector("#wafEventsBody tr.wafEvRow", timeout=8000)
        pg.click("#wafEventsBody tr.wafEvRow")
        pg.wait_for_selector("#wafDrawer .wafDxVar", timeout=4000)
        pg.screenshot(path=out("waf-event-drawer-variable.png"))
        pg.click("#wafDrawer .wafDxVar")
        pg.wait_for_selector("#wafTuneDlg input[name=wafTuneScope]", timeout=4000)
        pg.check("#wafTunePathOnly")
        pg.screenshot(path=out("waf-tuning-event-confirm.png"))
        pg.click("#wafTuneOk")
        pg.wait_for_timeout(600)
        if len(posted) != 1 or "variable=REQUEST_COOKIES" not in posted[0] or "scope=endpoint" not in posted[0] or "rootname=app.smoke.example.com" not in posted[0]:
            fail("waf-tuning", f"event variable apply request wrong: {posted}")
        pg.click("#wafDrawerClose")
    except Exception as ex:
        fail("waf-tuning", f"tuning flow failed: {' '.join(str(ex).split()[:30])}")
        pg.screenshot(path=out("waf-tuning-failure.png"))
    finally:
        pg.unroute(re_tuning)
        pg.unroute(re_apply)
        pg.unroute(re_events)
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 900})

    # variable exclusions in the global list: real API, add, show, remove
    current["page"] = "waf-tuning-exclusions"
    api = lambda path, data: pg.evaluate("""([p, d]) => new Promise(res => $.cjax({url: p, method: 'POST', data: d,
        success: r => res(r), error: e => res({error: 'http ' + e.status + ' ' + (e.responseText || '').slice(0, 120)})}))""", [path, data])
    try:
        sug = _json.dumps({"kind": "variable", "rule_ids": ["942290"], "target": "REQUEST_COOKIES:/^ph_.+_posthog$/"})
        r = api("/api/waf/tuning/apply", {"scope": "global", "suggestion": sug})
        if r != "OK":
            fail("waf-tuning", f"real apply failed: {r}")
        pg.click("#wafTabs .item[data-tab=waf-exclusions]")
        pg.wait_for_timeout(1200)
        if "REQUEST_COOKIES:/^ph_.+_posthog$/" not in pg.inner_text("#wafxBody"):
            fail("waf-tuning", "variable exclusion is not listed in the Exclusions tab")
        pg.screenshot(path=out("waf-tuning-exclusions-light.png"), full_page=True)
        pg.click("#wafxBody .wafxDelVar")
        pg.wait_for_timeout(1200)
        if "ph_" in pg.inner_text("#wafxBody"):
            fail("waf-tuning", "removed variable exclusion is still listed")
        hostile = _json.dumps({"kind": "variable", "rule_ids": ["1"], "target": 'ARGS:x" "id:1,pass'})
        bad = api("/api/waf/tuning/apply", {"scope": "global", "suggestion": hostile})
        if not (isinstance(bad, dict) and bad.get("error")):
            fail("waf-tuning", f"hostile target accepted by the real API: {bad}")
    except Exception as ex:
        fail("waf-tuning", f"variable exclusion list flow failed: {' '.join(str(ex).split()[:30])}")


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


def history_ui(pg, ctx):
    """System > History: timeline, diff viewer, restore preview (dry run, typed confirmation for the whole configuration),
    scoped restore enabling, ZxHistory.undoLast(), light/dark/390px. The restore itself restarts the instance and is
    covered by the Go tests and the manual end-to-end run, not here."""
    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=True)

    def theme(want_dark):
        if pg.evaluate("document.body.classList.contains('darkTheme')") != want_dark:
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(300)

    dialogs = []
    pg.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    theme(False)
    pg.set_viewport_size({"width": 1366, "height": 900})
    current["page"] = "history-flow"
    host = "hist-smoke.example.com"
    pg.wait_for_timeout(3000)  # let earlier flows' changes close their own history burst first
    pg.evaluate("""host => new Promise(res => $.cjax({url: '/api/proxy/add', method: 'POST',
        data: {type: 'host', rootname: host, ep: '127.0.0.1:9', tls: false, tlsval: false, bypassGlobalTLS: false}, success: res, error: res}))""", host)
    pg.wait_for_timeout(2800)  # the debounce window of the history capture is 2 s
    pg.evaluate("""host => new Promise(res => $.cjax({url: '/api/proxy/del', method: 'POST', data: {ep: host}, success: res, error: res}))""", host)
    pg.wait_for_timeout(2800)
    pg.evaluate("openTabById('history')")
    settle(pg, 900)
    pg.wait_for_function("document.querySelectorAll('#hxTimeline .hx-item').length >= 2", timeout=10000)
    pg.fill("#hxFilterObject", host)
    pg.click("#hxFilterBtn")
    pg.wait_for_function("document.querySelectorAll('#hxTimeline .hx-item').length == 2", timeout=10000)
    deleted = pg.locator("#hxTimeline .hx-item", has_text="Proxy rule deleted: " + host).first
    added = pg.locator("#hxTimeline .hx-item", has_text="Proxy rule added: " + host).first
    if deleted.count() == 0 or added.count() == 0:
        fail("history", "versions for the added and the deleted smoke rule are missing: " + " | ".join(pg.eval_on_selector_all("#hxTimeline .hx-summary", "e => e.map(x => x.textContent)")))
    deleted.locator(".hx-show").click()
    pg.wait_for_selector("#hxTimeline .hx-diff details", timeout=8000)
    if host not in deleted.locator(".hx-diff").inner_text():
        fail("history", "diff of the deletion should show the removed rule")
    shot("history-light.png")
    # the version that still had the rule: dry run preview, typed confirmation
    added.locator(".hx-restore").click()
    pg.wait_for_selector("#hxRestoreModal.visible", timeout=5000)
    pg.wait_for_function("document.getElementById('hxPreview').innerText.includes('would change')", timeout=8000)
    if "Nothing has been changed yet" not in pg.inner_text("#hxPreview"):
        fail("history", "preview should say nothing was changed yet")
    if not pg.locator("#hxRestoreGo").evaluate("e => e.classList.contains('disabled')"):
        fail("history", "whole-configuration restore must stay disabled until RESTORE is typed")
    pg.fill("#hxConfirmWord", "restore")
    if not pg.locator("#hxRestoreGo").evaluate("e => e.classList.contains('disabled')"):
        fail("history", "confirmation word is case sensitive")
    pg.fill("#hxConfirmWord", "RESTORE")
    if pg.locator("#hxRestoreGo").evaluate("e => e.classList.contains('disabled')"):
        fail("history", "typing RESTORE should enable the button")
    shot("history-restore-light.png")
    pg.select_option("#hxScope", "proxy")
    pg.wait_for_function("document.getElementById('hxConfirmWrap').style.display == 'none'", timeout=8000)
    pg.wait_for_function("!document.getElementById('hxRestoreGo').classList.contains('disabled')", timeout=8000)
    theme(True)
    shot("history-restore-dark.png")
    pg.set_viewport_size({"width": 390, "height": 800})
    pg.wait_for_timeout(400)
    check_horizontal(pg, "history restore 390px")
    shot("history-restore-390-dark.png")
    pg.click("#hxRestoreCancel")
    pg.wait_for_timeout(500)
    check_horizontal(pg, "history 390px")
    shot("history-390-dark.png")
    theme(False)
    shot("history-390-light.png")
    pg.set_viewport_size({"width": 1366, "height": 900})
    shot("history-light-2.png")
    # the global helper opens the same preview for the state before the last change
    current["page"] = "history-undo-helper"
    pg.evaluate("openTabById('status')")
    settle(pg, 400)
    res = pg.evaluate("window.ZxHistory.undoLast()")
    if res.get("target", 0) <= 0 or res["target"] >= res["latest"]:
        fail("history", f"undoLast returned {res}")
    pg.wait_for_selector("#hxRestoreModal.visible", timeout=8000)
    pg.wait_for_function("document.getElementById('hxPreview').innerText.includes('would change')", timeout=8000)
    pg.click("#hxRestoreCancel")
    # list API filters
    flt = pg.evaluate("window.ZxHistory.list({object: 'hist-smoke'})")
    if flt.get("total", 0) < 2:
        fail("history", f"object filter should find the two smoke versions: {flt.get('total')}")
    if dialogs:
        fail("dialog", f"native dialogs used: {dialogs}")


def posture_ui(pg, ctx):
    """Security overview: score, evidence, preview -> apply of the WAF fix (detection-only) with the WAF page and the
    Status tile following, undo, empty state, dark and 390px."""
    out = lambda n: os.path.join(args.out, n)

    def shot(name, full=True):
        pg.screenshot(path=out(name), full_page=full)

    def theme(want_dark):
        if pg.evaluate("document.body.classList.contains('darkTheme')") != want_dark:
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(300)

    def get(path):
        return pg.evaluate("p => new Promise(res => $.getJSON(p, r => res(r)).fail(e => res({error: 'http ' + e.status})))", path)

    def post(path, data):
        return pg.evaluate("""([p, d]) => new Promise(res => $.cjax({url: p, method: 'POST', data: d, success: r => res(r), error: e => res({error: 'http ' + e.status})}))""", [path, data])

    def jpost(path, obj):
        return pg.evaluate("""([p, o]) => new Promise(res => $.cjax({url: p, method: 'POST', contentType: 'application/json', data: JSON.stringify(o), dataType: 'json',
            success: r => res(r), error: e => res({error: 'http ' + e.status})}))""", [path, obj])

    def score_text():
        return pg.inner_text("#soScoreBox .soRing .num b").strip()

    theme(False)
    pg.set_viewport_size({"width": 1366, "height": 900})
    hosts = ["posture-a.example.com", "posture-b.example.com"]
    orig_pol = get("/api/waf/policy")

    # ---- empty / first run state ----
    current["page"] = "posture-empty"
    pg.evaluate("openTabById('secoverview')")
    settle(pg, 900)
    pg.wait_for_selector("#soScoreBox .soRing", timeout=8000)
    if pg.locator("#soCats .soCat").count() != 6:
        fail("posture", f"expected 6 category sections, got {pg.locator('#soCats .soCat').count()}")
    first = get("/api/security/posture")
    if first.get("error") or first["score"]["value"] != int(score_text()):
        fail("posture", f"the ring shows {score_text()} but the API says {first.get('score')}")
    if any(not c["evidence"] for c in first["checks"]):
        fail("posture", "a check has no evidence")
    if next(c for c in first["checks"] if c["id"] == "tls.enabled")["status"] == "not-applicable" and "Welcome" not in pg.inner_text("#soBanner"):
        fail("posture", "no friendly first-run note although there are no proxy rules")
    shot("posture-empty-light.png")

    # ---- two proxy rules without any protection ----
    for h in hosts:
        post("/api/proxy/add", {"type": "host", "rootname": h, "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false"})
    try:
        current["page"] = "posture-overview"
        pg.click("#soRecheck")
        settle(pg, 900)
        before = get("/api/security/posture?refresh=1")
        waf_before = next(c for c in before["checks"] if c["id"] == "waf.active")
        if waf_before["status"] != "fail" or "2 of 2" not in " ".join(waf_before["evidence"]):
            fail("posture", f"WAF check before the fix: {waf_before}")
        if not pg.is_visible("#soFirstBox .soItem"):
            fail("posture", "no 'Fix these first' list")
        n_first = pg.locator("#soFirstBox .soItem").count()
        if n_first < 1 or n_first > 5:
            fail("posture", f"'Fix these first' has {n_first} items")
        # evidence is expandable
        pg.click(".soRow[data-id='waf.active'] .soRowHead")
        body = pg.inner_text(".soRow[data-id='waf.active'] .soRowBody")
        if "2 of 2" not in body or "why it matters" not in body.lower():
            fail("posture", "the evidence of the WAF check is not shown when expanded")
        if not pg.locator(".soCat[data-cat='Authentication'].open").count():
            pg.click(".soCat[data-cat='Authentication'] .soCatHead")
        if pg.locator(".soRow[data-id='auth.admin_ui_exposed'] .soHeur").count() != 1:
            fail("posture", "the admin UI check is not labelled as a heuristic")
        if "not a penetration test" not in pg.inner_text("#soDisclaimer"):
            fail("posture", "the disclaimer is missing")
        if "points lost" not in pg.inner_text("#soScoreBox"):
            fail("posture", "the score does not say how many points were lost")
        shot("posture-light.png")

        # ---- single fix: preview only, nothing changes ----
        current["page"] = "posture-fix"
        if pg.locator(".soFix[data-act='uptime.enable']").count():
            pg.locator(".soFix[data-act='uptime.enable']").first.click()
            pg.wait_for_selector("#secOvDlg .sdAct", timeout=5000)
            if pg.locator("#secOvDlg .sdAct").count() != 1 or "Uptime monitor" not in pg.inner_text("#secOvDlg"):
                fail("posture", "single fix preview is wrong")
            pg.click("#sdCancel")
        # ---- recommended protection: dialog ----
        pg.evaluate("window.scrollTo(0, 0)")
        pg.click("#soRecBtn")
        pg.wait_for_selector("#secOvDlg .sdAct", timeout=5000)
        settle(pg, 300)
        checked = pg.eval_on_selector_all("#secOvDlg .sdAct", "els => els.map(e => [e.getAttribute('data-id'), e.querySelector('.sdChk').checked, e.querySelector('.sdChk').disabled])")
        state = {k: (c, d) for k, c, d in checked}
        if not state.get("waf.baseline", (False, True))[0]:
            fail("posture", f"the WAF fix is not pre-selected: {state}")
        if state.get("autoban.enable", (True, False))[0] or state.get("hsts.enable", (True, False))[0]:
            fail("posture", f"a fix that can block visitors or is sticky is pre-selected: {state}")
        dlg = pg.inner_text("#secOvDlg")
        for want in ("can block visitors", "cannot block visitors", "Nothing runs until you press the button"):
            if want not in dlg:
                fail("posture", f"dialog lacks {want!r}")
        if get("/api/waf/policy").get("Enabled"):
            fail("posture", "opening the preview already changed the WAF")
        shot("posture-dialog-light.png", full=False)
        theme(True)
        shot("posture-dialog-dark.png", full=False)
        theme(False)
        pg.set_viewport_size({"width": 390, "height": 800})
        pg.wait_for_timeout(300)
        shot("posture-dialog-390.png", full=False)
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.wait_for_timeout(200)

        # ---- apply ----
        current["page"] = "posture-apply"
        pg.click("#sdApply")
        try:
            pg.wait_for_selector("#sdDone", timeout=120000)  # one admin call per proxy rule for the uptime fix, slow on a loaded machine
        except Exception:
            fail("posture", f"apply did not finish: {pg.inner_text('#secOvDlg')[:300]!r}")
            return
        res_txt = pg.inner_text("#secOvDlg")
        if "Applied" not in res_txt or "audit log" not in res_txt:
            fail("posture", f"apply result not shown: {res_txt[:200]}")
        shot("posture-result-light.png", full=False)
        pol = get("/api/waf/policy")
        if not pol.get("Enabled") or pol.get("DefaultMode") != "detection_only" or pol.get("ParanoiaLevel") != 1:
            fail("posture", f"WAF policy after the fix: {pol}")
        pg.click("#sdDone")
        settle(pg, 900)
        after = get("/api/security/posture?refresh=1")
        if after["score"]["value"] <= before["score"]["value"]:
            fail("posture", f"score did not improve: {before['score']['value']} -> {after['score']['value']}")
        if next(c for c in after["checks"] if c["id"] == "waf.active")["status"] != "ok":
            fail("posture", "waf.active is not ok after the fix")
        if score_text() != str(after["score"]["value"]):
            fail("posture", f"the ring shows {score_text()}, expected {after['score']['value']}")
        wafa = next(a for a in after["actions"] if a["id"] == "waf.baseline")
        if wafa["state"] != "done" or not wafa["undoable"]:
            fail("posture", f"waf.baseline action state after apply: {wafa}")
        print(f"  posture score {before['score']['value']} -> {after['score']['value']} after the WAF fix")
        shot("posture-after-light.png")
        # the WAF page shows the new mode
        pg.evaluate("openTabById('waf')")
        settle(pg, 1200)
        if "Detection only" not in pg.inner_text("#wafStatus"):
            fail("posture", f"the WAF page does not show detection-only: {pg.inner_text('#wafStatus')!r}")
        # the Status page tile links back
        pg.evaluate("openTabById('status')")
        settle(pg, 1500)
        tile = pg.inner_text("#glancePosture")
        if "/ 100" not in tile:
            fail("posture", f"Status tile shows {tile!r}")
        pg.click("#kpiPosture")
        settle(pg, 700)
        if not pg.is_visible("#secoverview"):
            fail("posture", "the Status tile does not open the overview")

        # ---- undo through the API restores the WAF ----
        current["page"] = "posture-undo"
        r = jpost("/api/security/posture/undo", {"action": "waf.baseline"})
        if r.get("error") or r["results"][0]["status"] != "undone":
            fail("posture", f"undo: {r}")
        if get("/api/waf/policy").get("Enabled"):
            fail("posture", "undo left the WAF enabled")
        # a refused apply (no hash) changes nothing
        r = jpost("/api/security/posture/apply", {"actions": [{"id": "waf.baseline"}]})
        if not r.get("error") or get("/api/waf/policy").get("Enabled"):
            fail("posture", f"apply without a hash was not refused: {r}")

        # ---- dark, 390px ----
        current["page"] = "posture-themes"
        pg.evaluate("openTabById('secoverview')")
        pg.click("#soRecheck")
        settle(pg, 900)
        theme(True)
        pg.wait_for_timeout(300)
        shot("posture-dark.png")
        pg.set_viewport_size({"width": 390, "height": 800})
        pg.reload(wait_until="networkidle")
        pg.wait_for_timeout(900)
        pg.evaluate("openTabById('secoverview')")
        settle(pg, 900)
        check_horizontal(pg, "security overview 390px")
        shot("posture-390-dark.png")
        theme(False)
        pg.wait_for_timeout(300)
        shot("posture-390-light.png")
        if pg.locator("#soRecBtn").count():
            pg.click("#soRecBtn")
            pg.wait_for_selector("#secOvDlg .sdAct", timeout=5000)
            check_horizontal(pg, "security overview dialog 390px")
            pg.click("#sdCancel")
    finally:
        pg.set_viewport_size({"width": 1366, "height": 900})
        for h in hosts:
            post("/api/proxy/del", {"ep": h})
        post("/api/waf/policy", {"policy": json.dumps(orig_pol)})
        jpost("/api/security/posture/undo", {"action": "uptime.enable"})


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
        if args.posture_only:
            current["page"] = "posture"
            posture_ui(pg, ctx)
            b.close()
            return
        if args.waf_tuning_only:
            current["page"] = "waf-tuning"
            waf_tuning_ui(pg)
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
        if len(set(recent)) != len(recent):
            fail("nav", f"Recent lists an entry twice: {recent}")
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
            # the WAF tab of the rule editor carries the sections of every WAF feature (bands, response, API, variable exclusions)
            current["page"] = "editor-waf"
            pg.click("#httpProxyList .editBtn")
            pg.wait_for_selector("#httprpEditModal", state="visible", timeout=5000)
            settle(pg, 600)
            pg.click("#httprpEditModal .hrpedit_menu_item[cfgpage=waf]")
            settle(pg, 900)
            for sel, what in (("#httprpEditModal .wafRespEditor", "response protection"), ("#httprpEditModal .wafApiEditor", "API protection")):
                if not pg.locator(sel).first.is_visible():
                    fail("editor-waf", f"the {what} section is not visible in the rule editor WAF tab")
            pg.evaluate("$('#httprpEditModal .wafSource').dropdown('set selected', 'inherit')")
            settle(pg, 500)
            if not pg.locator("#httprpEditModal .wafChallengeOverride").first.is_visible():
                fail("editor-waf", "the challenge band override is not shown for a rule that follows the global policy")
            pg.screenshot(path=os.path.join(args.out, "httprp-editor-waf-light.png"))
            pg.evaluate("$('#httprpEditModal .wafSource').dropdown('set selected', 'block')")
            settle(pg, 500)
            for sel, what in (("#httprpEditModal .wafChallenge", "challenge threshold"), ("#httprpEditModal .wafIgnoreCookies", "analytics cookie option")):
                if pg.locator(sel).count() != 1:
                    fail("editor-waf", f"expected exactly one {what} field in the rule editor")
            pg.evaluate("document.body.classList.add('darkTheme')")
            settle(pg, 400)
            pg.screenshot(path=os.path.join(args.out, "httprp-editor-waf-dark.png"))
            pg.evaluate("document.body.classList.remove('darkTheme')")
            pg.click("#httprpEditModalWrapper .httpProxyEditClosePC")
            pg.wait_for_timeout(400)
            if pg.is_visible("#confirmBox"):
                pg.evaluate("$('#confirmBox').hide()")
                pg.evaluate("window.resetEditorDirty && window.resetEditorDirty()")
                pg.click("#httprpEditModalWrapper .httpProxyEditClosePC")
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
            waf_graduated_ui(pg)
        except Exception as ex:
            fail("waf", f"waf page flow failed: {' '.join(str(ex).split()[:30])}")
        current["page"] = "waf-tuning"
        waf_tuning_ui(pg)

        # ---- WAF page: response protection (outbound leak detection) ----
        current["page"] = "waf-response"
        try:
            def resp_theme(want_dark):
                if pg.evaluate("document.body.classList.contains('darkTheme')") != want_dark:
                    pg.evaluate("toggleTheme()")
                    pg.wait_for_timeout(300)
            pg.evaluate("openTabById('waf')")
            settle(pg, 700)
            pg.click("#wafTabs .item[data-tab=waf-response]")
            settle(pg, 900)
            if pg.locator("#wafRespPolicyBox .wafRespSel").count() != 5:
                fail("waf-response", "response protection tab does not show the five groups")
            pg.select_option("#wafRespPolicyBox .wafRespSel[data-g=stacktrace]", "log")
            pg.select_option("#wafRespPolicyBox .wafRespSel[data-g=headers]", "strip")
            pg.fill("#wafRespPolicyBoxWin", "32")
            pg.click("#wafRespSave")
            pg.wait_for_timeout(1500)
            pol = pg.evaluate("() => fetch('/api/waf/policy').then(r => r.json())")
            rc = pol.get("Response") or {}
            if (rc.get("Groups") or {}).get("stacktrace") != "log" or (rc.get("Groups") or {}).get("headers") != "strip" or rc.get("WindowKiB") != 32:
                fail("waf-response", f"policy response settings were not saved: {rc}")
            pg.click("#wafTabs .item[data-tab=waf-events]")
            settle(pg, 500)
            pg.click("#wafTabs .item[data-tab=waf-response]")
            settle(pg, 700)
            if pg.input_value("#wafRespPolicyBox .wafRespSel[data-g=stacktrace]") != "log" or pg.input_value("#wafRespPolicyBoxWin") != "32":
                fail("waf-response", "saved response settings were not shown again")
            pg.click("#wafRespSigTitle")
            pg.wait_for_selector("#wafRespSigBody tr td code", timeout=5000)
            if pg.locator("#wafRespSigBody tr").count() < 25:
                fail("waf-response", "signature reference is too short")
            if pg.locator("#wafevKind").count() != 1:
                fail("waf-response", "events tab has no kind filter")
            pg.screenshot(path=os.path.join(args.out, "waf-response-light.png"), full_page=True)
            resp_theme(True)
            pg.screenshot(path=os.path.join(args.out, "waf-response-dark.png"), full_page=True)
            pg.set_viewport_size({"width": 390, "height": 800})
            pg.wait_for_timeout(300)
            check_horizontal(pg, "waf response mobile")
            pg.screenshot(path=os.path.join(args.out, "waf-response-dark-390.png"), full_page=True)
            resp_theme(False)
            pg.screenshot(path=os.path.join(args.out, "waf-response-light-390.png"), full_page=True)
            # the profile editor carries the same section, with an Inherit choice
            pg.click("#wafTabs .item[data-tab=waf-profiles]")
            settle(pg, 600)
            pg.click("#wafPrNew")
            settle(pg, 400)
            if pg.locator("#wafprRespBox .wafRespSel").count() != 5 or pg.input_value("#wafprRespBox .wafRespSel[data-g=secrets]") != "":
                fail("waf-response", "profile editor does not offer the response protection groups with Inherit")
            pg.screenshot(path=os.path.join(args.out, "waf-profile-response-390.png"), full_page=True)
            pg.set_viewport_size({"width": 1366, "height": 900})
            pg.wait_for_timeout(300)
            pg.screenshot(path=os.path.join(args.out, "waf-profile-response.png"), full_page=True)
            # put the policy back
            pg.evaluate("""() => fetch('/api/waf/policy').then(r => r.json()).then(p => { delete p.Response;
                return new Promise(res => $.cjax({url: '/api/waf/policy', method: 'POST', data: {policy: JSON.stringify(p)}, success: res, error: res})) })""")
        except Exception as ex:
            fail("waf-response", f"response protection flow failed: {' '.join(str(ex).split()[:30])}")
            pg.set_viewport_size({"width": 1366, "height": 900})

        # ---- WAF page: API protection (policy defaults, profile picker, per-rule editor), light / dark / 390px ----
        current["page"] = "waf-api"
        api_host = "smoke-api.invalid"
        api_get = lambda q: pg.evaluate("q => fetch('/api/waf/api/get?' + q).then(r => r.json())", q)
        smoke_spec = "openapi: 3.0.0\\ninfo: {title: Smoke, version: '1'}\\npaths:\\n  /a:\\n    get: {responses: {'200': {description: ok}}}\\n  /b:\\n    post: {responses: {'200': {description: ok}}}\\n"
        try:
            pg.set_viewport_size({"width": 1366, "height": 900})
            pg.evaluate("""host => new Promise(res => $.cjax({url: '/api/proxy/add', method: 'POST',
                data: {type: 'host', rootname: host, ep: '127.0.0.1:9', tls: false, tlsval: false, bypassGlobalTLS: false}, success: res, error: res}))""", api_host)
            pg.evaluate("openTabById('waf')")
            settle(pg, 900)
            pg.click("#wafTabs .item[data-tab=waf-api]")
            pg.wait_for_selector("#wafApiPolicy .wfa", timeout=5000)
            settle(pg, 700)
            if pg.locator("#wafApiPolicy .wfaN").count() < 12:
                fail("waf-api", "limits form is incomplete")
            if pg.get_attribute("#wafApiPolicy .wfaN[data-k=JSONMaxDepth]", "placeholder") != "20":
                fail("waf-api", "default JSON depth (20) is not shown")
            pg.select_option("#wafApiPolicy .wfaMode", "log")
            pg.locator("#wafApiPolicy .wfaCustom").check(force=True)
            pg.fill("#wafApiPolicy .wfaN[data-k=JSONMaxDepth]", "7")
            pg.click("#wafApiPolicy .wfaAddRule")
            pg.fill("#wafApiPolicy .wfaAllowBody tr:last-child .wfaP", "/api")
            pg.fill("#wafApiPolicy .wfaAllowBody tr:last-child .wfaM", "get, post")
            pg.click("#wafApiPolicy .wfaSave")
            pg.wait_for_timeout(1500)
            v = api_get("scope=policy")
            c = v.get("config") or {}
            if c.get("Mode") != "log" or (c.get("Limits") or {}).get("JSONMaxDepth") != 7 or (c.get("AllowList") or [{}])[0].get("Methods") != ["GET", "POST"]:
                fail("waf-api", "policy API protection was not saved as entered: " + str(c)[:200])
            # an invalid value is refused with a message and nothing is saved
            pg.fill("#wafApiPolicy .wfaN[data-k=JSONMaxKeys]", "-7")
            pg.click("#wafApiPolicy .wfaSave")
            pg.wait_for_timeout(1200)
            if (api_get("scope=policy").get("config") or {}).get("Limits", {}).get("JSONMaxKeys"):
                fail("waf-api", "an invalid limit was saved")
            pg.fill("#wafApiPolicy .wfaN[data-k=JSONMaxKeys]", "")
            # profile picker: built-in profiles are read-only
            pg.select_option("#wafApiProfileSel", "Strict")
            pg.wait_for_timeout(500)
            if "read-only" not in pg.inner_text("#wafApiProfileMsg"):
                fail("waf-api", "built-in profile did not show the read-only note")
            pg.screenshot(path=os.path.join(args.out, "waf-api-policy.png"), full_page=True)

            # per-rule editor with an OpenAPI spec
            pg.evaluate("openTabById('httprp')")
            settle(pg, 900)
            pg.click(f"#httpProxyList tr.ptRow[data-ep='{api_host}'] .editBtn")
            pg.wait_for_selector("#httprpEditModal", state="visible", timeout=5000)
            settle(pg, 600)
            pg.click("#httprpEditModal .hrpedit_menu_item[cfgpage=waf]")
            pg.wait_for_selector("#httprpEditModal .wafApiMount .wfa", timeout=5000)
            settle(pg, 600)
            pg.select_option("#httprpEditModal .wafApiMount .wfaMode", "block")
            pg.fill("#httprpEditModal .wafApiMount .wfaSpec", "this is not a spec")
            pg.click("#httprpEditModal .wafApiMount .wfaCheckSpec")
            pg.wait_for_selector("#httprpEditModal .wafApiMount .wfaResult.bad", timeout=5000)
            pg.fill("#httprpEditModal .wafApiMount .wfaSpec", smoke_spec.replace("\\n", "\n"))
            pg.click("#httprpEditModal .wafApiMount .wfaCheckSpec")
            pg.wait_for_selector("#httprpEditModal .wafApiMount .wfaResult.ok", timeout=5000)
            summary = pg.inner_text("#httprpEditModal .wafApiMount .wfaResult")
            if "2 paths" not in summary or "2 operations" not in summary:
                fail("waf-api", "spec summary is wrong: " + summary)
            pg.click("#httprpEditModal .wafApiMount .wfaSave")
            pg.wait_for_timeout(1500)
            v = api_get("scope=endpoint&name=" + api_host)
            if (v.get("config") or {}).get("Mode") != "block" or not v.get("spec") or v["spec"].get("paths") != 2:
                fail("waf-api", "rule API protection / spec not saved: " + str(v)[:200])
            pg.screenshot(path=os.path.join(args.out, "waf-api-rule-light.png"), full_page=True)
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(300)
            pg.screenshot(path=os.path.join(args.out, "waf-api-rule-dark.png"), full_page=True)
            pg.set_viewport_size({"width": 390, "height": 800})
            pg.wait_for_timeout(400)
            pg.evaluate("document.querySelector('#httprpEditModal .wafApiMount').scrollIntoView()")
            pg.screenshot(path=os.path.join(args.out, "waf-api-rule-390-dark.png"))
            check_horizontal(pg, "waf-api rule editor 390px")
            pg.evaluate("toggleTheme()")
            pg.set_viewport_size({"width": 1366, "height": 900})
            pg.click("#httprpEditModalWrapper .httpProxyEditClosePC")
            pg.wait_for_timeout(500)

            # events tab has the type filter; 390px view of the policy tab in both themes
            pg.evaluate("openTabById('waf')")
            settle(pg, 700)
            pg.click("#wafTabs .item[data-tab=waf-events]")
            settle(pg, 500)
            if not pg.is_visible("div.ui.dropdown:has(> #wafevKind)"):
                fail("waf-api", "events type filter is missing")
            pg.evaluate("$('#wafevKind').dropdown('set selected', 'api')")
            settle(pg, 500)
            pg.evaluate("$('#wafevKind').dropdown('set selected', '')")
            pg.click("#wafTabs .item[data-tab=waf-api]")
            settle(pg, 500)
            pg.set_viewport_size({"width": 390, "height": 800})
            pg.wait_for_timeout(400)
            pg.screenshot(path=os.path.join(args.out, "waf-api-policy-390-light.png"), full_page=True)
            check_horizontal(pg, "waf-api tab 390px")
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(300)
            pg.screenshot(path=os.path.join(args.out, "waf-api-policy-390-dark.png"), full_page=True)
            pg.evaluate("toggleTheme()")
            pg.set_viewport_size({"width": 1366, "height": 900})
        except Exception as ex:
            fail("waf-api", f"API protection flow failed: {' '.join(str(ex).split()[:30])}")
            pg.screenshot(path=os.path.join(args.out, "waf-api-failure.png"))
        finally:
            pg.evaluate("""host => new Promise(res => $.cjax({url: '/api/proxy/del', method: 'POST', data: {ep: host}, success: res, error: res}))""", api_host)
            pg.evaluate("""() => new Promise(res => $.cjax({url: '/api/waf/api/set', method: 'POST', data: {scope: 'policy', name: '', config: ''}, success: res, error: res}))""")

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

        nav_palette(pg, ctx)

        proxy_ux(pg, ctx)

        ech_zrok_ui(pg, ctx)

        posture_ui(pg, ctx)

        history_ui(pg, ctx)

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
