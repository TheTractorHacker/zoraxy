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
ap.add_argument("--allow", action="append", default=[], help="regex of messages whose failure is tolerated")
args = ap.parse_args()
os.makedirs(args.out, exist_ok=True)

# Offline-tolerant: external fetches (plugin store, update check, ...) may fail in a sandbox.
allow = [re.compile(a) for a in args.allow] + [
    re.compile(r"favicon"),
    re.compile(r"ERR_ABORTED"),  # a request cancelled by a reload / page switch is not a failure
    re.compile(r"ERR_(NAME_NOT_RESOLVED|INTERNET_DISCONNECTED|CONNECTION)"),
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
        pg.wait_for_selector("#newRuleModal", state="visible", timeout=5000)
        pg.wait_for_timeout(800)  # let the open animation finish
        pg.keyboard.press("Escape")
        pg.wait_for_selector("#newRuleModal", state="hidden", timeout=5000)
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

        tabs = pg.eval_on_selector_all("#mainmenu .item[tag]", "els => els.map(e => e.getAttribute('tag'))")
        tabs = list(dict.fromkeys(tabs))
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

        proxy_ux(pg, ctx)

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
        b.close()


main()
print()
if failures:
    print(f"{len(failures)} FAILURE(S)")
    sys.exit(1)
print("OK, screenshots in", args.out)
