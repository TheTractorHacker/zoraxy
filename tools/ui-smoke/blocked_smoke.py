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

        # ---- bot-ua-allow: the narrow fix (this site only, User-Agent product token), editable pattern, screenshots
        def theme(want_dark):
            if js("document.body.classList.contains('darkTheme')") != want_dark:
                js("toggleTheme()")
                pg.wait_for_timeout(300)

        def open_drawer():
            pg.fill("#sbSearch", ref)
            pg.keyboard.press("Enter")
            pg.wait_for_selector("[data-bw-apply]")
            pg.wait_for_timeout(300)

        open_drawer()
        if js("document.querySelector('.zx-drawer input[type=radio]:checked').value") != "bot-ua-allow":
            fail("blocked", "the narrow User-Agent fix must be the preselected choice")
        want = 'requests whose User-Agent contains "curl/" skip the bot rules on %s only. Other sites unchanged.' % BLK_HOSTS[0]
        if want not in js("document.querySelector('.bwPreview').textContent"):
            fail("blocked", "bot-ua-allow preview text wrong: %r" % js("document.querySelector('.bwPreview').textContent"))
        if js("document.querySelector('.bwPat input').value") != "curl/":
            fail("blocked", "the pattern must be prefilled with the product token only")
        if "spoofable" not in js("document.querySelector('.bwWarn') ? document.querySelector('.bwWarn').textContent : ''"):
            fail("blocked", "the spoofing warning is missing")
        if js("document.querySelector('.bwAll').hidden") is not True:
            fail("blocked", "site fix must not ask for the all-sites confirmation")
        # invalid edits: an error under the field, Apply disabled; a valid edit brings the preview back
        for bad, frag in (("mozilla", "mozilla"), ("cur", "at least 4"), ("chrome/", "chrome/")):
            pg.fill(".bwPat input", bad)
            pg.wait_for_function("f => document.querySelector('.bwPat .zx-error').textContent.indexOf(f) >= 0", arg=frag, timeout=4000)
            if not js("document.querySelector('[data-bw-apply]').disabled"):
                fail("blocked", "Apply must be disabled for the pattern %r" % bad)
        shot("blocked-ua-error.png")
        pg.fill(".bwPat input", "curl/")
        pg.wait_for_function("document.querySelector('.bwPat .zx-error').textContent.length == 0 && !document.querySelector('[data-bw-apply]').disabled", timeout=4000)
        for dark in (False, True):
            theme(dark)
            shot("blocked-ua-drawer-%s.png" % ("dark" if dark else "light"))
        theme(False)
        pg.keyboard.press("Escape")
        pg.set_viewport_size({"width": 390, "height": 844})
        open_drawer()
        shot("blocked-ua-drawer-390.png")
        if js("document.documentElement.scrollWidth > document.documentElement.clientWidth"):
            fail("blocked", "page scrolls horizontally at 390px with the UA fix drawer")
        pg.keyboard.press("Escape")
        pg.set_viewport_size({"width": 1366, "height": 900})

        # ---- apply, verify, undo (the preselected fix: User-Agent allow on this site)
        open_drawer()
        pg.click("[data-bw-apply]")
        pg.wait_for_selector(".zx-toast")
        pg.wait_for_timeout(800)
        if hit(BLK_HOSTS[0], "curl/8.18.0")[0] in (0, 403):  # 502: the request passed the bot rule, the dummy upstream is closed
            fail("blocked", "after Apply the same request must pass the bot rule on the site (toast: %r)" % js("document.querySelector('.zx-toast') && document.querySelector('.zx-toast').textContent"))
        if hit(BLK_HOSTS[0], "CURL/7.0")[0] in (0, 403):
            fail("blocked", "the User-Agent match must be case-insensitive")
        if hit(BLK_HOSTS[0], "python-requests/2.31")[0] != 403:
            fail("blocked", "another HTTP library must still be blocked on the same site")
        if hit(BLK_HOSTS[1], "curl/8.18.0")[0] != 403:
            fail("blocked", "the fix must not change the other site")
        # the site editor lists the entry with a remove button, and Easy mode shows the card
        js("openTabById('httprp')")
        pg.wait_for_timeout(900)
        js("""h => fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => { initHttpProxyRuleEditorModal(l.filter(x => x.RootOrMatchingDomain === h)[0]); })""", BLK_HOSTS[0])
        pg.wait_for_selector("#httprpEditModalWrapper .hrp-main", state="visible", timeout=8000)
        pg.wait_for_timeout(800)
        if not pg.is_visible("#httprpEditModalWrapper .hrpBotAllow"):
            fail("blocked", "the site editor must list the allowed User-Agent in the Security section")
        if js("[...document.querySelectorAll('#httprpEditModalWrapper .hrpBotAllowItem')].map(e => e.textContent).join()") != "curl/":
            fail("blocked", "site editor list content wrong")
        for dark in (False, True):
            theme(dark)
            js("document.querySelector('#httprpEditModalWrapper .hrpBotAllow').scrollIntoView({block: 'center'})")
            pg.wait_for_timeout(200)
            shot("blocked-ua-site-%s.png" % ("dark" if dark else "light"))
        theme(False)
        pg.set_viewport_size({"width": 390, "height": 844})
        pg.wait_for_timeout(300)
        js("document.querySelector('#httprpEditModalWrapper .hrpBotAllow').scrollIntoView({block: 'center'})")
        pg.wait_for_timeout(200)
        shot("blocked-ua-site-390.png")
        pg.set_viewport_size({"width": 1366, "height": 900})
        # remove through the list: the block is back; then re-add through undo of nothing: use the drawer again
        pg.click("#httprpEditModalWrapper [data-ua-remove]")
        pg.wait_for_timeout(1200)
        if pg.is_visible("#httprpEditModalWrapper .hrpBotAllow"):
            fail("blocked", "the list must disappear after the last entry is removed")
        if hit(BLK_HOSTS[0], "curl/8.18.0")[0] != 403:
            fail("blocked", "removing the entry must restore the block")
        js("openTabById('stats')")
        pg.wait_for_timeout(600)
        js("statsOpenBlocked({})")
        pg.wait_for_selector("#sbBody tr.sbRow")
        open_drawer()
        pg.click("[data-bw-apply]")
        pg.wait_for_selector(".zx-toast")
        pg.wait_for_timeout(800)
        if hit(BLK_HOSTS[0], "curl/8.18.0")[0] in (0, 403):
            fail("blocked", "second apply failed")
        pg.click(".zx-toast__undo >> text=Undo")
        pg.wait_for_timeout(1500)
        if hit(BLK_HOSTS[0], "curl/8.18.0")[0] != 403:
            fail("blocked", "Undo must restore the block")
        # the blunt fix is still there for those who want it
        open_drawer()
        if js("document.querySelectorAll('.zx-drawer input[value=bot-site-off]').length") != 1:
            fail("blocked", "the existing fixes must still be offered")
        pg.keyboard.press("Escape")

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
