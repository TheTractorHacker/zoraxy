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
ap.add_argument("--allow", action="append", default=[], help="regex of messages whose failure is tolerated")
args = ap.parse_args()
os.makedirs(args.out, exist_ok=True)

# Offline-tolerant: external fetches (plugin store, update check, ...) may fail in a sandbox.
allow = [re.compile(a) for a in args.allow] + [
    re.compile(r"favicon"),
    re.compile(r"ERR_ABORTED"),  # a navigation cancelled the in-flight polling requests of the previous page
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
                c = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=8)
                c.request("GET", path, headers={"Host": host})
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
