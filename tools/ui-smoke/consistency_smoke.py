"""Smoke scenario of the consistency pass (docs/ux/changes.md): Certificates page sections, Related boxes, the Auto-ban save bar,
the "View history" toast action, a hostile host name that must never become markup, and tag / deep link compatibility of the
renamed pages. Loaded by smoke.py (exec in its namespace: fail, current, settle, check_horizontal, args, os)."""

HOSTILE = '"><img src=x onerror=window.__xss=1>.smoke-xss.example.com'
PLAIN = "nocert-smoke.example.com"


def consistency_ui(pg, ctx):
    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: () => res('error')}))""", [url, data])

    def visible_tab():
        return js("[...document.querySelectorAll('.functiontab')].filter(e => e.offsetParent !== null).map(e => e.id)[0]")

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=True)

    pg.set_viewport_size({"width": 1366, "height": 900})
    theme(False)
    current["page"] = "consistency-seed"
    for host in (HOSTILE, PLAIN):
        r = post("/api/proxy/add", {"type": "host", "rootname": host, "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false",
                                    "bypassGlobalTLS": "false", "bpgtls": "false", "cred": "", "ssl": "false"})
        if r != "OK":
            fail("consistency", f"could not add test rule {host!r}: {r}")
    try:
        # ---- Certificates page: stats, expiring / missing panels, collapsible add card, ACME tab ----
        current["page"] = "cert-sections"
        js("openTabById('cert')")
        pg.wait_for_selector("#certStats .zx-stat", timeout=8000)
        for sel in ("#certStats", "#certifiedDomainList", "#certAddCard", "#certMissingBox", "#certExpiringBox"):
            if not js("sel => !!document.querySelector('#certPage ' + sel)", sel):
                fail("cert", f"missing section {sel}")
        pg.wait_for_function("!document.getElementById('certMissingBox').hidden", timeout=8000)
        missing = js("document.getElementById('certMissingList').innerText")
        if PLAIN not in missing:
            fail("cert", f"'Hosts without a certificate' does not list {PLAIN}: {missing!r}")
        if js("document.getElementById('certMissingList').querySelectorAll('img').length"):
            fail("cert", "hostile host name became markup in the missing-certificate list")
        if not js("document.getElementById('certAddBody').hidden"):
            fail("cert", "the Add a certificate card should start collapsed")
        pg.click("#certAddToggle")
        if js("document.getElementById('certAddBody').hidden") or js("document.getElementById('certAddToggle').getAttribute('aria-expanded')") != "true":
            fail("cert", "the Add a certificate toggle did not open the card")
        for sel in ("#certdomain", "#pubkeySelector", "#prikeySelector", "#certUploadBtn", "#certPasteBtn"):
            if not pg.is_visible(sel):
                fail("cert", f"upload control {sel} not visible in the open card")
        if not js("[...document.querySelectorAll('#certPage input, #certPage textarea')].filter(i => i.offsetParent && !i.labels.length && !i.getAttribute('aria-label')).length == 0"):
            fail("a11y", "an input of the Certificates page has no label")
        pg.click("#certAddToggle")
        for theme_dark, name in ((False, "cert-sections-light.png"), (True, "cert-sections-dark.png")):
            theme(theme_dark)
            pg.wait_for_timeout(300)
            check_horizontal(pg, "cert " + name)
            shot(name)
        theme(False)
        pg.click("#certPage .zx-pagetabs a[data-nav-open=acme]")
        settle(pg, 500)
        if visible_tab() != "acme" or not pg.is_visible("#acmePage .zx-pagetabs a[aria-current=page]"):
            fail("cert", "the ACME tab of the Certificates page did not open the ACME page")
        pg.click("#acmePage .zx-pagetabs a[data-nav-open=cert]")
        settle(pg, 500)
        if visible_tab() != "cert":
            fail("cert", "the Certificates tab of the ACME page did not return")
        pg.set_viewport_size({"width": 390, "height": 800})
        pg.wait_for_timeout(300)
        check_horizontal(pg, "cert mobile")
        shot("cert-sections-mobile.png")
        pg.set_viewport_size({"width": 1366, "height": 900})

        # ---- Related boxes and header History shortcuts ----
        current["page"] = "related-boxes"
        for tab in ("access", "trustproxy", "seccenter", "sso", "captcha", "waf", "cert", "acme", "vdir"):
            js("t => openTabById(t)", tab)
            pg.wait_for_timeout(500)
            n = js("t => document.querySelectorAll('#' + t + ' .zx-related a[data-nav-open]').length", tab)
            if n < 2:
                fail("related", f"{tab}: Related box has {n} links")
            if not js("t => !!document.querySelector('#' + t + ' [data-zx-history]')", tab):
                fail("related", f"{tab}: no History shortcut in the page header")
            if not js("t => !!document.querySelector('#' + t + ' [data-zx-crumbs]')", tab):
                fail("related", f"{tab}: no kit page header with breadcrumbs")
            target = js("t => document.querySelector('#' + t + ' .zx-related a[data-nav-open]').getAttribute('data-nav-open')", tab)
            pg.click(f"#{tab} .zx-related a[data-nav-open] >> nth=0")
            pg.wait_for_timeout(400)
            if visible_tab() != target:
                fail("related", f"{tab}: first Related link opened {visible_tab()}, expected {target}")

        # ---- Auto-ban save bar and the "View history" toast action ----
        current["page"] = "savebar-history"
        js("openTabById('seccenter')")
        pg.wait_for_selector("#abBan", timeout=8000)
        pg.wait_for_function("document.getElementById('abBan').value !== ''", timeout=8000)
        orig = int(js("document.getElementById('abBan').value"))
        pg.wait_for_timeout(300)
        if js("document.querySelectorAll('#seccenter .zx-savebar:not([hidden])').length"):
            fail("savebar", "the save bar is visible before any change")
        pg.fill("#abBan", str(orig + 7))
        pg.wait_for_selector("#seccenter .zx-savebar:not([hidden])", timeout=4000)
        pg.click("#seccenter [data-zx-save]")
        pg.wait_for_selector(".zx-toast .zx-toast__undo", timeout=8000)
        label = js("[...document.querySelectorAll('.zx-toast button')].map(b => b.textContent.trim())")
        if "View history" not in label:
            fail("history-toast", f"save toast has no View history action: {label}")
        else:
            pg.click(".zx-toast button:has-text('View history')")
            pg.wait_for_function("document.getElementById('history') && document.getElementById('history').offsetParent !== null", timeout=8000)
            pg.wait_for_function("document.getElementById('hxFilterObject') && document.getElementById('hxFilterObject').value === 'Auto-ban'", timeout=8000)
            shot("history-from-toast.png")
        js("openTabById('seccenter')")
        pg.wait_for_selector("#abBan", timeout=8000)
        pg.wait_for_function(f"document.getElementById('abBan').value === '{orig + 7}'", timeout=8000)
        pg.fill("#abBan", str(orig))
        pg.wait_for_selector("#seccenter .zx-savebar:not([hidden])", timeout=4000)
        pg.click("#seccenter [data-zx-save]")
        pg.wait_for_function(f"document.getElementById('abBan').value === '{orig}'", timeout=8000)
        # discard returns the field to the saved value
        pg.fill("#abBan", str(orig + 3))
        pg.wait_for_selector("#seccenter .zx-savebar:not([hidden])", timeout=4000)
        pg.click("#seccenter [data-zx-discard]")
        if js("document.getElementById('abBan').value") != str(orig):
            fail("savebar", "Discard did not restore the Auto-ban field")

        # ---- hostile host name: never markup, on every page that lists hosts ----
        current["page"] = "hostile-host"
        js("window.__xss = 0")
        for tab in ("status", "httprp", "vdir", "cert", "utm", "redirectset", "access", "waf", "captcha", "seccenter", "trustproxy",
                    "stats", "visitors", "sso", "rules", "globalsettings", "setroot", "streamproxy"):
            js("t => openTabById(t)", tab)
            pg.wait_for_timeout(700)
        js("openTabById('vdir')")
        pg.wait_for_timeout(500)
        js("""h => { $("#vdirBaseRoutingRule").val(h).trigger("change"); }""", HOSTILE)
        pg.wait_for_timeout(900)
        if js("document.querySelectorAll('img[src=\"x\"]').length") or js("window.__xss"):
            where = js("[...document.querySelectorAll('img[src=\"x\"]')].map(i => (i.closest('.functiontab') || {}).id)")
            fail("xss", f"a hostile host name was rendered as markup in: {where}")
        if HOSTILE not in js("document.getElementById('hostDomainList').innerText"):
            fail("xss", "the hostile host name is not shown as plain text in the Path routes host list")

        # ---- tags, deep links and labels of the renamed pages ----
        current["page"] = "renamed-pages"
        for tag, label, h2 in (("globalsettings", "Listeners", "Listeners"), ("vdir", "Path routes", "Path routes"), ("rules", "Raw rule form", "Raw rule form")):
            pg.goto("about:blank")
            pg.goto(args.url + "/#" + tag, wait_until="networkidle")
            pg.wait_for_selector("#mainmenu .item")
            pg.wait_for_timeout(900)
            if visible_tab() != tag:
                fail("compat", f"deep link #{tag} opened {visible_tab()}")
            text = js("t => document.getElementById(t).innerText", tag)
            if h2 not in text:
                fail("compat", f"#{tag} page does not show '{h2}'")
            if label not in js("document.querySelector('#mainmenu a.item[aria-current=page]').innerText"):
                fail("compat", f"menu label for #{tag} is not '{label}'")
        for tag in ("cert", "acme"):
            pg.goto("about:blank")
            pg.goto(args.url + "/#" + tag, wait_until="networkidle")
            pg.wait_for_selector("#mainmenu .item")
            pg.wait_for_timeout(800)
            if visible_tab() != tag:
                fail("compat", f"deep link #{tag} opened {visible_tab()}")
        # no old term is left in the menu
        menu = js("document.getElementById('mainmenu').innerText")
        for old in ("Ingress", "Virtual Directories", "Advanced Rule Form"):
            if old in menu:
                fail("terminology", f"menu still says {old}")

        # ---- Get started card on Status ----
        current["page"] = "get-started"
        js("openTabById('status')")
        pg.wait_for_function("!document.getElementById('getStartedPanel').hidden", timeout=10000)
        steps = js("document.querySelectorAll('#getStartedList li').length")
        if steps < 2:
            fail("get-started", f"Get started lists {steps} steps")
        if not js("!!document.getElementById('kpiPosture')"):
            fail("get-started", "the security score tile is gone from Status")
        shot("status-get-started.png")
    finally:
        current["page"] = "consistency-cleanup"
        for host in (HOSTILE, PLAIN):
            post("/api/proxy/del", {"ep": host})
        pg.goto(args.url + "/", wait_until="networkidle")
        pg.wait_for_selector("#mainmenu .item")
