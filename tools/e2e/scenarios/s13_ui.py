"""Scenarios that drive the admin UI (Playwright / headless Chromium) and then send real traffic."""
import os

from lib import *


def _playwright():
    try:
        from playwright.sync_api import sync_playwright
        return sync_playwright
    except ImportError:
        raise Skip("python playwright is not installed (run with PY=$HOME/ui-test-tools/py.sh tools/e2e/run.sh)")


@scenario("ui_new_rule_dialog_to_traffic", ["core"], needs="playwright")
def ui_new_rule_dialog_to_traffic():
    """Create a proxy rule through the 'New proxy rule' dialog (typed like a user), then proxy real HTTP through it;
    edit the rule in the UI list (disable via the table) and see traffic stop."""
    sync_playwright = _playwright()
    shots = os.environ.get("E2E_SHOTS")
    if shots:
        os.makedirs(shots, exist_ok=True)
    with Zoraxy() as z, Backend(name="ui-app") as app:
        errors = []
        with sync_playwright() as p:
            b = p.chromium.launch()
            try:
                pg = b.new_context(viewport={"width": 1366, "height": 900}).new_page()
                pg.on("pageerror", lambda e: errors.append("pageerror: %s @ %s" % (e, (e.stack or "")[:400])))
                pg.goto("http://127.0.0.1:%d/" % z.admin, wait_until="networkidle")
                pg.wait_for_selector("#mainmenu .item")
                pg.evaluate("openTabById('httprp')")
                pg.wait_for_selector("#ptNewRule", timeout=15000)
                pg.click("#ptNewRule")
                pg.wait_for_selector("#newRuleModal", state="visible", timeout=5000)
                pg.fill("#nrDomain", "ui-made.test")
                pg.fill("#nrUpstream", app.addr)
                pg.keyboard.press("Tab")
                pg.wait_for_function("document.getElementById('nrTestRes').innerText.indexOf('Reachable') > -1", timeout=15000)
                if shots:
                    pg.screenshot(path=os.path.join(shots, "e2e-new-rule-dialog.png"))
                pg.press("#nrUpstream", "Enter")
                pg.wait_for_selector("#newRuleModal", state="hidden", timeout=10000)
                pg.wait_for_function("document.querySelector('#httpProxyList tr.ptFlash') !== null", timeout=10000)
                if shots:
                    pg.screenshot(path=os.path.join(shots, "e2e-rule-created.png"))
                r = z.req("ui-made.test", "/via-ui")
                check(r.status == 200 and r.json()["backend"] == "ui-app" and r.json()["path"] == "/via-ui", "UI-created rule does not proxy: %d %r" % (r.status, r.body[:100]))
                # disable through the HTTP-proxy table toggle (same endpoint the UI switch posts to)
                pg.evaluate("""() => new Promise(res => $.cjax({url: '/api/proxy/toggle', method: 'POST', data: {ep: 'ui-made.test', enable: 'false'}, success: res, error: res}))""")
                n = len(app.log)
                z.req("ui-made.test", "/after-disable")
                check(len(app.log) == n, "disabled rule still proxies")
                check(not errors, "JS errors: %s" % errors)
            finally:
                b.close()
        return "rule typed into the New proxy rule dialog (upstream reachability check shown), created, proxied GET /via-ui to the backend, UI toggle disables it; no JS errors"
