"""Smoke scenario of the Visitors drawer feedback (Blacklist / Whitelist / Ban 24h / Exclude): the page toast must sit ABOVE the
drawer, the drawer must show its own inline status, the pressed button must change state, and Undo must revert. exec()'d by
smoke.py (namespace: fail, current, args, os); run alone with --visitors-drawer-only. Needs the instance's proxy port at UI port + 1
(as tools/ui-smoke/run.sh starts it). It makes its own rule and removes every list entry / ban it adds."""

import json
import ssl
import urllib.error
import urllib.request

VD_HOST = "vdrawer.demo.test"


def visitors_drawer_ui(pg, ctx):
    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: x => res({error: 'HTTP ' + x.status}), dataType: 'json'}))""", [url, data])

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=False)

    def hit():
        port = int(args.url.rsplit(":", 1)[1].split("/")[0]) + 1
        tls = ssl.create_default_context()
        tls.check_hostname = False
        tls.verify_mode = ssl.CERT_NONE
        for scheme in ("http", "https"):
            r = urllib.request.Request("%s://127.0.0.1:%d/" % (scheme, port), headers={"Host": VD_HOST, "User-Agent": "vdrawer-smoke/1.0"})
            try:
                urllib.request.urlopen(r, timeout=5, context=tls)
                return True
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", "replace")
                if e.code == 400 and "HTTPS server" in body:
                    continue
                return True  # any answer from the proxy records the visit
            except Exception:
                return False
        return False

    def topmost_is_toast():
        # the toast must be what the user sees at its own centre, not the drawer (the original bug: toast z-index 1001 < drawer 1100)
        return js("""() => { const t = document.getElementById('messageBox'); if (!t) return 'no toast element';
            const r = t.getBoundingClientRect(); if (getComputedStyle(t).display === 'none' || r.width < 10 || r.height < 10) return 'toast not visible'; const e = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
            return (e && (e === t || t.contains(e))) ? 'ok' : 'covered by ' + (e ? (e.id || e.className || e.tagName) : 'nothing'); }""")

    current["page"] = "visitors-drawer"
    pg.set_viewport_size({"width": 1366, "height": 900})
    base = {"type": "host", "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false", "bpgtls": "false", "cred": "", "ssl": "false"}
    post("/api/proxy/del", {"ep": VD_HOST})
    if post("/api/proxy/add", dict(base, rootname=VD_HOST)) != "OK":
        fail("visitors-drawer", "could not add " + VD_HOST)
        return
    ip = "127.0.0.1"
    try:
        if not hit():
            fail("visitors-drawer", "proxy port not reachable, scenario cannot record a visit")
            return
        pg.wait_for_timeout(1500)  # the visitor store flushes asynchronously
        js("openTabById('visitors')")
        pg.wait_for_selector("#vBody tr[data-ip], #vrBody tr[data-ip]", timeout=15000)
        row = pg.locator('#vBody tr[data-ip="%s"], #vrBody tr[data-ip="%s"]' % (ip, ip)).first
        row.click()
        pg.wait_for_selector("#visitorDrawer.open [data-act=whitelist]", timeout=8000)

        for act, done, undoes in (("whitelist", "Whitelisted", "/api/whitelist/ip/remove"), ("blacklist", "Blacklisted", "/api/blacklist/ip/remove"), ("ban", "Banned", "/api/abuse/unban")):
            sel = "#visitorDrawer [data-act=%s]" % act
            pg.click(sel)
            pg.wait_for_selector("#vdStatus.show.ok", timeout=8000)
            txt = js("document.getElementById('vdStatus').textContent")
            if done.lower() not in txt.lower() or ip not in txt:
                fail("visitors-drawer", "%s: the inline status must say what happened, got %r" % (act, txt))
            if "vdDone" not in (js("document.querySelector('%s').className" % sel) or ""):
                fail("visitors-drawer", "%s: the pressed button must change to a done state" % act)
            if js("document.querySelector('#visitorDrawer [data-act=%s]').disabled" % act) is True:
                fail("visitors-drawer", "%s: the button must not stay disabled after success" % act)
            cover = topmost_is_toast()
            if cover != "ok":
                fail("visitors-drawer", "%s: the page toast is not visible on top of the drawer: %s" % (act, cover))
            if act == "whitelist":
                shot("visitors-drawer-whitelisted.png")
            # Undo from the inline status
            pg.click("#vdStatus a")
            pg.wait_for_function("document.getElementById('vdStatus').textContent.trim().indexOf('Undone') === 0", timeout=8000)
            if "vdDone" in (js("document.querySelector('#visitorDrawer [data-act=%s]').className" % act) or ""):
                fail("visitors-drawer", "%s: Undo must restore the button" % act)
        shot("visitors-drawer-after-undo.png")
    finally:
        for url, data in (("/api/whitelist/ip/remove", {"ip": ip}), ("/api/blacklist/ip/remove", {"ip": ip}), ("/api/abuse/unban", {"ip": ip})):
            post(url, data)
        post("/api/proxy/del", {"ep": VD_HOST})
