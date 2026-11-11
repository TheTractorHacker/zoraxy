"""Smoke scenario of Statistics > Blocked "why was this blocked" (Reference ID search, User-Agent column, row drawer, fix preview,
Undo toast, palette jump, Status tile, bot rules note). exec()'d by smoke.py (namespace: fail, current, args, os); run alone with
--blocked-only. Needs the instance's proxy port at UI port + 1 (as tools/ui-smoke/run.sh starts it); it makes its own rules and
undoes every change it makes."""

import json
import ssl
import urllib.error
import urllib.request

BLK_HOSTS = ["blkwhy-a.demo.test", "blkwhy-b.demo.test"]


def blocked_ui(pg, ctx):
    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: x => res({error: 'HTTP ' + x.status}), dataType: 'json'}))""", [url, data])

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=False)

    def hit(host, ua):
        port = int(args.url.rsplit(":", 1)[1].split("/")[0]) + 1
        ctx_tls = ssl.create_default_context()
        ctx_tls.check_hostname = False
        ctx_tls.verify_mode = ssl.CERT_NONE
        for scheme in ("http", "https"):  # the inbound port serves TLS when the instance has it on by default
            r = urllib.request.Request("%s://127.0.0.1:%d/" % (scheme, port), headers={"Host": host, "User-Agent": ua})
            try:
                x = urllib.request.urlopen(r, timeout=5, context=ctx_tls)
                return x.status, x.headers.get("X-Zoraxy-Ref"), x.read().decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", "replace")
                if e.code == 400 and "HTTPS server" in body:
                    continue
                return e.code, e.headers.get("X-Zoraxy-Ref"), body
            except Exception as e:  # proxy port not where we expect it
                return 0, None, str(e)
        return 0, None, "no answer"

    current["page"] = "blocked-why"
    pg.set_viewport_size({"width": 1366, "height": 900})
    base = {"type": "host", "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false", "bpgtls": "false", "cred": "", "ssl": "false"}
    for h in BLK_HOSTS:
        post("/api/proxy/del", {"ep": h})
        if post("/api/proxy/add", dict(base, rootname=h)) != "OK":
            fail("blocked", "could not add " + h)
    cfg0 = js("fetch('/api/botrules/get').then(r => r.json())")
    c = json.loads(json.dumps(cfg0["Config"]))
    c["Enabled"] = True
    c.setdefault("Categories", {})["http_library"] = {"Enabled": True, "Action": "challenge"}
    post("/api/botrules/set", {"config": json.dumps(c)})
    try:
        st, ref, body = hit(BLK_HOSTS[0], "curl/8.18.0")
        if st == 0:
            fail("blocked", "proxy port not reachable, scenario cannot generate a block: " + body)
            return
        if st != 403 or not ref or ref not in body:
            fail("blocked", "403 page must carry the Reference ID in the body and X-Zoraxy-Ref: %r %r" % (st, ref))
            return

        # ---- table: columns, row, no horizontal page scroll
        js("openTabById('stats')")
        pg.wait_for_timeout(800)
        js("statsOpenBlocked({})")
        pg.wait_for_selector("#sbBody tr.sbRow")
        if not pg.is_visible("#sbTable th.sbcUa"):
            fail("blocked", "User-Agent column must be visible at 1366px")
        if js("document.querySelector('#sbBody td.sbcUa .sbUa').textContent") != "curl/8.18.0":
            fail("blocked", "User-Agent cell must show the UA")
        if "ZX-" not in js("document.querySelector('#sbBody tr.sbRow td').textContent"):
            fail("blocked", "the Reference ID must be shown in the first cell (and survive the 10 s refresh)")
        if js("document.querySelector('#sbTopIpsCard').offsetParent !== null"):
            fail("blocked", "the Top IPs card must be hidden when only one address is listed")
        pg.set_viewport_size({"width": 800, "height": 900})
        pg.wait_for_timeout(300)
        if pg.is_visible("#sbTable th.sbcUa"):
            fail("blocked", "User-Agent column must be hidden under 900px")
        if js("document.documentElement.scrollWidth > document.documentElement.clientWidth"):
            fail("blocked", "page scrolls horizontally at 800px")
        pg.set_viewport_size({"width": 1366, "height": 900})

        # ---- search by Reference ID: filter tag + drawer with the fix
        pg.fill("#sbSearch", ref)
        pg.keyboard.press("Enter")
        pg.wait_for_selector(".zx-drawer", timeout=8000)
        pg.wait_for_selector("[data-bw-apply]")
        if js("document.activeElement.closest('.zx-drawer') === null"):
            fail("blocked", "focus must move into the drawer")
        if ref not in js("document.querySelector('.zx-drawer').textContent"):
            fail("blocked", "drawer must show the Reference ID")
        if js("document.querySelectorAll('.zx-drawer input[type=radio]').length") < 1:
            fail("blocked", "drawer must offer a fix")
        if "After this" not in js("document.querySelector('.bwPreview').textContent"):
            fail("blocked", "live preview line missing")
        if js("document.querySelector('.bwAll') && !document.querySelector('.bwAll').hidden"):
            fail("blocked", "the all-sites confirmation must stay hidden for a site fix")
        shot("blocked-drawer.png")
        # focus trap: Tab cycles inside
        for _ in range(12):
            pg.keyboard.press("Tab")
            if js("document.activeElement.closest('.zx-drawer') === null"):
                fail("blocked", "Tab left the drawer (focus trap)")
                break
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(300)
        if pg.locator(".zx-drawer").count():
            fail("blocked", "Esc must close the drawer")
        # a click on the row: Esc gives the focus back to the row's chevron, not to <body>
        pg.click("#sbBody tr.sbRow td.sbcUa")
        pg.wait_for_selector(".zx-drawer", timeout=8000)
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(300)
        if not js("document.activeElement && document.activeElement.hasAttribute('data-why')"):
            fail("blocked", "after Esc the focus must return to the row's chevron button")
        # leaving the page (browser Back) must not leave the drawer open over another page
        pg.click("#sbBody tr.sbRow td.sbcUa")
        pg.wait_for_selector(".zx-drawer", timeout=8000)
        pg.go_back()
        pg.wait_for_timeout(500)
        if pg.locator(".zx-drawer").count():
            fail("blocked", "the drawer must close when the page changes (Back)")
        pg.go_forward()
        pg.wait_for_selector("#sbBody tr.sbRow", timeout=8000)
        # bottom sheet at 390px
        pg.set_viewport_size({"width": 390, "height": 844})
        pg.fill("#sbSearch", ref)
        pg.keyboard.press("Enter")
        pg.wait_for_selector(".zx-drawer")
        pg.wait_for_timeout(400)
        box = js("(() => { const r = document.querySelector('.zx-drawer').getBoundingClientRect(); return [r.left, r.width, r.bottom, innerHeight]; })()")
        if box[0] > 1 or box[1] < 380 or abs(box[2] - box[3]) > 2:
            fail("blocked", "drawer must be a bottom sheet at 390px: %r" % (box,))
        shot("blocked-sheet.png")
        pg.keyboard.press("Escape")
        pg.set_viewport_size({"width": 1366, "height": 900})

        # ---- not found
        pg.fill("#sbSearch", "ZX-0000-0000")
        pg.keyboard.press("Enter")
        pg.wait_for_selector("#sbNotFound", state="visible")
        if "No block with this ID" not in js("document.getElementById('sbNotFound').textContent"):
            fail("blocked", "not-found state text missing")
        shot("blocked-notfound.png")
        pg.click("#sbNfClear")
        pg.wait_for_selector("#sbBody tr.sbRow")

        # ---- apply, verify, undo
        pg.fill("#sbSearch", ref)
        pg.keyboard.press("Enter")
        pg.wait_for_selector("[data-bw-apply]")
        pg.click("[data-bw-apply]")
        pg.wait_for_selector(".zx-toast")
        pg.wait_for_timeout(800)
        if hit(BLK_HOSTS[0], "curl/8.18.0")[0] in (0, 403):  # 502: the request passed the bot rule, the dummy upstream is closed
            fail("blocked", "after Apply the same request must pass the bot rule on the site (toast: %r)" % js("document.querySelector('.zx-toast') && document.querySelector('.zx-toast').textContent"))
        if hit(BLK_HOSTS[1], "curl/8.18.0")[0] != 403:
            fail("blocked", "the fix must not change the other site")
        pg.click(".zx-toast__undo >> text=Undo")
        pg.wait_for_timeout(1500)
        if hit(BLK_HOSTS[0], "curl/8.18.0")[0] != 403:
            fail("blocked", "Undo must restore the block")

        # ---- Ctrl+K jump
        pg.keyboard.press("Control+k")
        pg.fill(".zx-palette__input", ref)
        pg.wait_for_timeout(300)
        if "Reference ID" not in js("document.querySelector('.zx-palette__list').textContent"):
            fail("blocked", "palette must offer to find a typed Reference ID")
        pg.keyboard.press("Escape")

        # ---- Status tile and bot rules note
        js("openTabById('status')")
        pg.wait_for_timeout(2000)
        if "See why" not in js("document.getElementById('kpiBlocked').textContent"):
            fail("blocked", "Status tile must say See why")
        js("openTabById('seccenter')")
        pg.wait_for_timeout(600)
        pg.click("#secTabs .item[data-sec='bots']")
        pg.wait_for_timeout(1000)
        if not pg.is_visible("#brChallengeNote"):
            fail("blocked", "bot rules must warn that challenge without a CAPTCHA blocks")
    finally:
        post("/api/botrules/set", {"config": json.dumps(cfg0["Config"])})
        for h in BLK_HOSTS:
            post("/api/proxy/del", {"ep": h})
        post("/api/blocked/clear", {"confirm": "yes"})
