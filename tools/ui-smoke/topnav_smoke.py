# exec()'d by smoke.py (shares args, fail, current, settle, check_horizontal): defines topnav_ui(pg, ctx) and topnav_auth_ui(br, url).
#
# Top bar scenario (--topnav-only; --topnav-auth-url URL adds the signed-in checks against an instance WITH authentication, see
# topnav_run.sh): control sizes, no overflow / collisions at 2000, 1366, 1024, 768 and 390 px in light and dark, status pills (mocked
# glance / proxy answers: every pill must link to a real page), language and theme menus (mouse + keyboard), persistence, the phone
# "More" menu, a very long language list, and the account menu / log out (auth instance only). Screenshots go to --out (topnav-*.png).

TN_WIDTHS = [2000, 1366, 1024, 768, 390]
TN_GLANCE = {"Upstreams": [], "CertList": [], "Rates": {"Minutes": 5, "RequestsPerMin": 0, "ErrorsPerMin": 0, "BlockedPerMin": 0, "ErrorRate": 0, "Series": [], "ErrorSeries": [], "BlockedSeries": []},
             "BandwidthRx": 0, "BandwidthTx": 0, "BlockedToday": 1234, "UpstreamsTotal": 3,
             "UpstreamsDown": [{"Name": "app.example.com", "URL": "http://10.0.0.5", "StatusCode": 502}], "CertsTotal": 2,
             "CertsExpiring": [{"Name": "www.example.com", "DaysLeft": 5}], "AlertsFailed": 0, "AlertsRecent": [], "WarnDays": 30}

TN_MEASURE = """() => {
    const bar = document.querySelector('.menubar'); const br = bar.getBoundingClientRect();
    const vis = e => { const r = e.getBoundingClientRect(); const cs = getComputedStyle(e); return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none'; };
    const els = [...bar.querySelectorAll('.zx-top-logo, .zx-topbtn, .zx-pill')].filter(vis);
    const rects = els.map(e => { const r = e.getBoundingClientRect(); return {id: e.id || e.getAttribute('data-pill') || e.className.split(' ')[0], l: r.left, t: r.top, r: r.right, b: r.bottom, w: r.width, h: r.height, btn: e.classList.contains('zx-topbtn'), pill: e.classList.contains('zx-pill')}; });
    const overlaps = [];
    for (let i = 0; i < rects.length; i++) for (let j = i + 1; j < rects.length; j++) {
        const a = rects[i], b = rects[j];
        if (a.l < b.r - 0.5 && b.l < a.r - 0.5 && a.t < b.b - 0.5 && b.t < a.b - 0.5) overlaps.push(a.id + '/' + b.id);
    }
    const outside = rects.filter(r => r.l < -0.5 || r.r > innerWidth + 0.5 || r.t < -0.5 || r.b > br.bottom + 0.5).map(r => r.id);
    const title = document.querySelector('#status .zx-page-header__title');
    return {barH: br.height, barBottom: br.bottom, rects, overlaps, outside, scrollW: document.documentElement.scrollWidth, clientW: document.documentElement.clientWidth,
            titleTop: title ? title.getBoundingClientRect().top : null, crumbTop: null};
}"""

TN_CONTRAST = """() => {
    const parse = c => { const m = c.match(/rgba?\\(([^)]+)\\)/); return m ? m[1].split(',').map(Number) : [0, 0, 0, 1]; };
    const bgOf = el => { for (; el; el = el.parentElement) { const p = parse(getComputedStyle(el).backgroundColor); if (p.length < 4 || p[3] > 0.9) return p; } return [255, 255, 255]; };
    const lum = p => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(p[0]) + 0.7152 * f(p[1]) + 0.0722 * f(p[2]); };
    const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
    return [...document.querySelectorAll('.menubar .zx-topbtn, .menubar .zx-pill')].filter(e => e.getBoundingClientRect().width > 0).map(e => {
        const cs = getComputedStyle(e); const bg = bgOf(e);
        const bd = parse(cs.borderTopColor), surface = bgOf(e.parentElement);
        return {id: e.id || e.getAttribute('data-pill'), text: ratio(parse(cs.color), bg), border: cs.borderTopWidth === '0px' ? 99 : ratio(bd, surface), pill: e.classList.contains('zx-pill')};
    });
}"""


def topnav_ui(pg, ctx):
    out = lambda n: os.path.join(args.out, n)
    base = args.url + "/index.html"

    def ev(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def goto(width=1366, height=800, theme="light", hash_="#status", mocks=True, storage=None):
        pg.set_viewport_size({"width": width, "height": height})
        pg.evaluate("t => { try { localStorage.setItem('theme', t); } catch (e) {} }", theme)
        for k, v in (storage or {}).items():
            pg.evaluate("([k, v]) => localStorage.setItem(k, v)", [k, v])
        pg.goto(base + hash_, wait_until="domcontentloaded", timeout=60000)
        pg.reload(wait_until="domcontentloaded", timeout=60000)
        pg.wait_for_function("document.querySelector('#zxTopStatus a') !== null", timeout=15000)
        pg.wait_for_timeout(400)

    def mock_all(page):
        page.unroute_all()
        page.route("**/api/stats/glance", lambda rt: rt.fulfill(status=200, content_type="application/json", body=json.dumps(TN_GLANCE)))

    def open_menu(btn, keyboard=False):
        if keyboard:
            pg.focus(btn)
            pg.keyboard.press("Enter")
        else:
            pg.click(btn)
        pg.wait_for_selector(".zx-menu", timeout=3000)

    pg.on("dialog", lambda d: d.dismiss())
    current["page"] = "topnav"

    # ---- sizes, overflow, collisions, contrast at every width, light and dark; screenshots ----
    for theme in ("light", "dark"):
        for w in TN_WIDTHS:
            current["page"] = f"topnav/{theme}/{w}"
            mock_all(pg)
            goto(w, 800, theme, storage={"zoraxy.topbar.update": json.dumps({"available": True, "latest": "v9.9.9", "host": "", "at": int(__import__("time").time() * 1000)})})
            m = ev(TN_MEASURE)
            if abs(m["barH"] - 52) > 1:
                fail("topnav", f"{w}px {theme}: bar height {m['barH']} (expected 52)")
            if m["scrollW"] - m["clientW"] > 1:
                fail("topnav", f"{w}px {theme}: page overflows horizontally by {m['scrollW'] - m['clientW']}px")
            if m["overlaps"]:
                fail("topnav", f"{w}px {theme}: controls overlap: {m['overlaps']}")
            if m["outside"]:
                fail("topnav", f"{w}px {theme}: controls outside the bar / viewport: {m['outside']}")
            need = 40 if w <= 748 else 32
            for r in m["rects"]:
                if (r["btn"] or r["pill"]) and r["h"] < need - 0.5:
                    fail("topnav", f"{w}px {theme}: {r['id']} is only {r['h']:.0f}px high (need {need})")
                if (r["btn"]) and r["w"] < 32:
                    fail("topnav", f"{w}px {theme}: {r['id']} is only {r['w']:.0f}px wide")
            if m["titleTop"] is not None and m["titleTop"] < m["barBottom"] - 1:
                fail("topnav", f"{w}px {theme}: the page title starts under the bar ({m['titleTop']} < {m['barBottom']})")
            vis = {r["id"] for r in m["rects"]}
            if w > 748 and not {"zxSearchBtn", "zxThemeBtn", "zxLangBtn"} <= vis:
                fail("topnav", f"{w}px {theme}: search / theme / language not all visible: {sorted(vis)}")
            if w <= 748 and not {"zxSearchBtn", "zxMoreBtn", "sidemenuBtn"} <= vis:
                fail("topnav", f"{w}px {theme}: search / More / hamburger not all visible: {sorted(vis)}")
            if w <= 748 and ({"zxThemeBtn", "zxLangBtn"} & vis or any(r["pill"] for r in m["rects"])):
                fail("topnav", f"{w}px {theme}: theme / language / pills must fold into the More menu on a phone")
            if "zxUserBtn" in vis:
                fail("topnav", "the account button is visible although authentication is off")
            if w > 748 and sum(1 for r in m["rects"] if r["pill"]) < 4:
                fail("topnav", f"{w}px {theme}: expected 5 mocked pills (online, site down, certificate, update, blocked), got {sum(1 for r in m['rects'] if r['pill'])}")
            for c in ev(TN_CONTRAST):
                if c["text"] < 4.5:
                    fail("topnav", f"{w}px {theme}: {c['id']} text contrast {c['text']:.2f} < 4.5")
                if not c["pill"] and c["border"] < 3 and w == 1366:
                    fail("topnav", f"{w}px {theme}: {c['id']} border contrast {c['border']:.2f} < 3")
            pg.screenshot(path=out(f"topnav-{theme}-{w}.png"), clip={"x": 0, "y": 0, "width": w, "height": 260})

    # ---- pills link to real pages ----
    current["page"] = "topnav/pills"
    mock_all(pg)
    goto(1366, 800, "light", storage={"zoraxy.topbar.update": json.dumps({"available": True, "latest": "v9.9.9", "host": "", "at": int(__import__("time").time() * 1000)})})
    pills = ev("""() => [...document.querySelectorAll('#zxTopStatus a.zx-pill')].map(a => ({pill: a.getAttribute('data-pill'), tag: a.getAttribute('data-tag'), href: a.getAttribute('href'),
        title: a.title, label: a.getAttribute('aria-label'), real: !!(window.getTabButtonById && getTabButtonById(a.getAttribute('data-tag')))}))""")
    ids = [p["pill"] for p in pills]
    if ids != ["health", "down", "cert", "update", "blocked"]:
        fail("topnav", f"pill order/content {ids}")
    for p in pills:
        if not p["real"] or p["href"] != "#" + p["tag"]:
            fail("topnav", f"pill {p['pill']} does not link to a real page: {p}")
        if not p["title"] or not p["label"]:
            fail("topnav", f"pill {p['pill']} has no tooltip / aria-label")
    for pid, tag in (("down", "utm"), ("cert", "cert"), ("update", "updater"), ("health", "status")):
        try:
            pg.click(f"#zxTopStatus a[data-pill={pid}]", timeout=8000)
        except Exception:
            fail("topnav", f"pill {pid} cannot be clicked; the bar shows {ev('document.getElementById(\"zxTopStatus\").innerText')!r} (hash {ev('location.hash')})")
            continue
        pg.wait_for_timeout(500)
        if ev("location.hash") != "#" + tag or not pg.is_visible("#" + tag):
            fail("topnav", f"pill {pid} did not open #{tag} (hash {ev('location.hash')})")
    pg.click("#zxTopStatus a[data-pill=blocked]")
    pg.wait_for_timeout(1500)
    if ev("location.hash") != "#stats" or not pg.is_visible("#sBlocked"):
        fail("topnav", "the blocked counter must open Statistics > Blocked")
    if "1,234" not in ev("document.querySelector('#zxTopStatus a[data-pill=blocked]').innerText") and "1234" not in ev("document.querySelector('#zxTopStatus a[data-pill=blocked]').innerText"):
        fail("topnav", "the blocked counter does not show the number")
    pg.route("**/api/proxy/status", lambda rt: rt.fulfill(status=200, content_type="application/json", body=json.dumps({"Running": False, "Option": {"Port": 443, "UseTls": True, "HostVersion": "x"}})))
    goto(1366, 800, "light")
    if "zx-pill--danger" not in (ev("document.querySelector('#zxTopStatus a[data-pill=health]').className") or ""):
        fail("topnav", "a stopped proxy must show a danger health pill")
    pg.unroute_all()

    # ---- data unavailable: one neutral pill, no spinner ----
    current["page"] = "topnav/unavailable"
    up = ctx.new_page()
    up.route("**/api/stats/glance", lambda rt: rt.abort())
    up.route("**/api/proxy/status", lambda rt: rt.abort())
    up.set_viewport_size({"width": 1366, "height": 700})
    up.goto(base + "#status", wait_until="domcontentloaded", timeout=60000)
    up.wait_for_function("document.querySelector('#zxTopStatus a') !== null", timeout=15000)
    txt = up.evaluate("document.getElementById('zxTopStatus').innerText.trim()")
    if "unavailable" not in txt.lower() or up.evaluate("document.querySelectorAll('#zxTopStatus .loading, #zxTopStatus .spinner').length") != 0:
        fail("topnav", f"failed status requests must show a neutral 'Status unavailable' pill, got {txt!r}")
    up.close()

    # ---- polling is light: one glance + one proxy/status request per poll, nothing at all in a quiet 4 s ----
    current["page"] = "topnav/poll"
    pp = ctx.new_page()
    hits = []
    pp.on("request", lambda r: hits.append(r.url) if any(x in r.url for x in ("/api/stats/glance", "/api/proxy/status", "/api/updater")) else None)
    pp.goto(base + "#qstart", wait_until="domcontentloaded", timeout=60000)
    pp.wait_for_function("document.querySelector('#zxTopStatus a') !== null", timeout=15000)
    n0 = len(hits)
    pp.wait_for_timeout(4000)
    if len(hits) - n0 > 0:
        fail("topnav", f"the bar polls too often: {len(hits) - n0} requests in 4 s")
    if any("/api/updater" in h for h in hits):
        fail("topnav", "the bar must not call the updater (no automatic GitHub request)")
    pp.close()

    # ---- language: mouse ----
    current["page"] = "topnav/language"
    goto(1366, 800, "light")
    pg.evaluate("localStorage.removeItem('zoraxy.lang'); i18n.setLanguage('en', {persist: false})")
    open_menu("#zxLangBtn")
    langs = ev("[...document.querySelectorAll('.zx-menu [data-lang]')].map(b => b.getAttribute('data-lang'))")
    if len(langs) < 9 or "en" not in langs or "de" not in langs:
        fail("topnav", f"language menu lacks languages: {langs}")
    if ev("document.querySelector('.zx-menu [aria-checked=true]').getAttribute('data-lang')") != "en":
        fail("topnav", "the current language is not marked")
    pg.screenshot(path=out("topnav-menu-lang-light.png"), clip={"x": 900, "y": 0, "width": 466, "height": 460})
    pg.click(".zx-menu [data-lang=de]")
    pg.wait_for_timeout(1200)
    if ev("document.documentElement.lang") != "de" or "DE" not in ev("document.getElementById('zxLangBtn').innerText"):
        fail("topnav", f"language did not switch to German (lang {ev('document.documentElement.lang')}, button {ev('document.getElementById(\"zxLangBtn\").innerText')!r})")
    if ev("localStorage.getItem('zoraxy.lang')") != "de":
        fail("topnav", "the language choice is not stored")
    if ev("document.getElementById('zxMoreBtn').getAttribute('aria-label')") == "Status and account menu":
        pass  # hidden on this width; checked below on the phone
    if not ev("document.activeElement && document.activeElement.id") == "zxLangBtn":
        fail("topnav", "focus must return to the language button after a choice")
    pg.screenshot(path=out("topnav-german-1366.png"), clip={"x": 0, "y": 0, "width": 1366, "height": 120})
    m = ev(TN_MEASURE)
    if m["overlaps"] or m["outside"] or m["scrollW"] > m["clientW"]:
        fail("topnav", f"German top bar collides: {m['overlaps']} {m['outside']}")
    pg.evaluate("i18n.setLanguage('en')")
    pg.wait_for_timeout(600)

    # ---- keyboard: tab order, Enter/arrows/Esc ----
    current["page"] = "topnav/keyboard"
    mock_all(pg)
    goto(1366, 800, "light", storage={"zoraxy.topbar.update": json.dumps({"available": True, "latest": "v9.9.9", "host": "", "at": int(__import__("time").time() * 1000)})})
    pg.focus(".zx-top-logo")
    order = []
    for _ in range(14):
        pg.keyboard.press("Tab")
        order.append(ev("(() => { const a = document.activeElement; return a ? (a.id || a.getAttribute('data-pill') || a.className.split(' ')[0] || a.tagName) + '|' + !!a.closest('.menubar') : ''; })()"))
        if order[-1].endswith("|false"):
            break
    ids = [o.split("|")[0] for o in order if o.endswith("|true")]
    want = ["health", "down", "cert", "update", "blocked", "zxSearchBtn", "zxThemeBtn", "zxLangBtn"]
    if ids[:len(want)] != want:
        fail("topnav", f"Tab order inside the bar is {ids}, expected {want}")
    pg.focus("#zxLangBtn")
    pg.keyboard.press("Enter")
    pg.wait_for_selector(".zx-menu", timeout=3000)
    first = ev("document.activeElement.getAttribute('data-lang')")
    if first != "en":
        fail("topnav", f"opening with Enter must focus the current language, focus is on {first}")
    pg.keyboard.press("ArrowDown")
    if ev("document.activeElement.getAttribute('data-lang')") == "en":
        fail("topnav", "ArrowDown did not move inside the menu")
    pg.keyboard.press("End")
    pg.keyboard.press("Home")
    pg.keyboard.press("Escape")
    pg.wait_for_timeout(200)
    if ev("document.querySelectorAll('.zx-menu').length") != 0 or ev("document.activeElement.id") != "zxLangBtn":
        fail("topnav", "Esc must close the menu and return focus to its button")
    pg.keyboard.press("ArrowDown")
    pg.wait_for_selector(".zx-menu", timeout=3000)
    pg.keyboard.press("Tab")
    pg.wait_for_timeout(200)
    if ev("document.querySelectorAll('.zx-menu').length") != 0:
        fail("topnav", "Tab must close the menu")
    # choose with the keyboard: Dark via the theme menu
    pg.focus("#zxThemeBtn")
    pg.keyboard.press("Enter")
    pg.wait_for_selector(".zx-menu", timeout=3000)
    pg.keyboard.press("ArrowDown")
    pg.keyboard.press("Enter")
    pg.wait_for_timeout(500)
    if not ev("document.body.classList.contains('darkTheme')") or ev("localStorage.getItem('theme')") != "dark":
        fail("topnav", "choosing Dark with the keyboard did not switch the theme")
    # outside click closes
    open_menu("#zxLangBtn")
    pg.mouse.click(300, 400)
    pg.wait_for_timeout(200)
    if ev("document.querySelectorAll('.zx-menu').length") != 0:
        fail("topnav", "a click outside must close the menu")

    # ---- theme: shows the mode, persists, system ----
    current["page"] = "topnav/theme"
    goto(1366, 800, "light")
    if "Light" not in ev("document.getElementById('zxThemeBtn').getAttribute('aria-label')"):
        fail("topnav", "the theme button does not say it is Light")
    open_menu("#zxThemeBtn")
    pg.screenshot(path=out("topnav-menu-theme-light.png"), clip={"x": 900, "y": 0, "width": 466, "height": 260})
    pg.click(".zx-menu [data-theme=dark]")
    pg.wait_for_timeout(500)
    if not ev("document.body.classList.contains('darkTheme')") or "Dark" not in ev("document.getElementById('zxThemeBtn').getAttribute('aria-label')"):
        fail("topnav", "the Dark choice did not apply / the button does not show it")
    pg.screenshot(path=out("topnav-dark-1366-after-toggle.png"), clip={"x": 0, "y": 0, "width": 1366, "height": 260})
    pg.reload(wait_until="domcontentloaded", timeout=60000)
    pg.wait_for_timeout(800)
    if not ev("document.body.classList.contains('darkTheme')") or ev("localStorage.getItem('theme')") != "dark":
        fail("topnav", "the Dark choice did not persist across a reload")
    open_menu("#zxThemeBtn")
    pg.screenshot(path=out("topnav-menu-theme-dark.png"), clip={"x": 900, "y": 0, "width": 466, "height": 260})
    pg.click(".zx-menu [data-theme=system]")
    pg.wait_for_timeout(400)
    if ev("localStorage.getItem('theme')") is not None or "System" not in ev("document.getElementById('zxThemeBtn').getAttribute('aria-label')"):
        fail("topnav", "System must remove the stored choice and say so")
    ev("toggleTheme()")   # the palette / old toggle still works and becomes an explicit choice
    pg.wait_for_timeout(300)
    if ev("localStorage.getItem('theme')") is None or "System" in ev("document.getElementById('zxThemeBtn').getAttribute('aria-label')"):
        fail("topnav", "toggleTheme() must still work and be reflected by the button")
    pg.evaluate("localStorage.setItem('theme','light')")

    # ---- a very long language list scrolls inside the menu and stays on screen ----
    current["page"] = "topnav/longlist"
    goto(1366, 500, "light")
    ev("(() => { for (let i = 0; i < 30; i++) i18n.languages.push(['xx-' + i, 'Language number ' + i]); })()")
    open_menu("#zxLangBtn")
    r = ev("(() => { const m = document.querySelector('.zx-menu'); const b = m.getBoundingClientRect(); return {sh: m.scrollHeight, ch: m.clientHeight, top: b.top, bottom: b.bottom, ih: innerHeight}; })()")
    if r["sh"] <= r["ch"] or r["bottom"] > r["ih"] + 1 or r["top"] < 0:
        fail("topnav", f"a long language list must scroll inside the menu and stay in the viewport: {r}")
    pg.screenshot(path=out("topnav-menu-lang-long.png"), clip={"x": 900, "y": 0, "width": 466, "height": 500})
    ev("i18n.languages.splice(9, 30)")
    pg.keyboard.press("Escape")

    # ---- phone: the More menu ----
    current["page"] = "topnav/phone"
    for theme in ("light", "dark"):
        mock_all(pg)
        goto(390, 844, theme)
        pg.click("#zxMoreBtn")
        pg.wait_for_selector(".zx-menu", timeout=3000)
        mm = ev("""() => { const m = document.querySelector('.zx-menu'); const r = m.getBoundingClientRect();
            return {l: r.left, r: r.right, t: r.top, b: r.bottom, iw: innerWidth, ih: innerHeight, status: m.querySelectorAll('a[data-tag]').length, themes: m.querySelectorAll('[data-theme]').length,
                    langs: m.querySelectorAll('[data-lang]').length, sh: m.scrollHeight, ch: m.clientHeight, minH: Math.min(...[...m.querySelectorAll('[role^=menuitem]')].map(e => e.getBoundingClientRect().height))}; }""")
        if mm["l"] < 0 or mm["r"] > mm["iw"] or mm["b"] > mm["ih"] + 1:
            fail("topnav", f"the More menu leaves the phone viewport: {mm}")
        if mm["status"] < 4 or mm["themes"] != 3 or mm["langs"] < 9:
            fail("topnav", f"the More menu lacks status / theme / language entries: {mm}")
        if mm["minH"] < 36:
            fail("topnav", f"More menu items are too small to tap: {mm['minH']}px")
        pg.screenshot(path=out(f"topnav-more-{theme}-390.png"), clip={"x": 0, "y": 0, "width": 390, "height": 844})
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(200)
        if ev("document.querySelectorAll('.zx-menu').length") != 0:
            fail("topnav", "Esc must close the More menu")
    pg.click("#zxMoreBtn")
    pg.wait_for_selector(".zx-menu")
    pg.click(".zx-menu a[data-pill], .zx-menu a[data-tag=cert]")
    pg.wait_for_timeout(600)
    if ev("location.hash") != "#cert" or ev("document.querySelectorAll('.zx-menu').length") != 0:
        fail("topnav", f"a status entry in the More menu must open its page and close the menu (hash {ev('location.hash')})")
    # the page menu (hamburger) keeps working and sits below the bar
    pg.click("#sidemenuBtn")
    pg.wait_for_timeout(600)
    t = ev("(() => { const n = document.querySelector('.toolbar').getBoundingClientRect(); return {top: n.top, shown: n.width > 0}; })()")
    if not t["shown"] or t["top"] < 51:
        fail("topnav", f"the hamburger menu is not shown below the bar: {t}")
    if ev("document.getElementById('sidemenuBtn').getAttribute('aria-expanded')") != "true":
        fail("topnav", "the hamburger button must report aria-expanded=true while the menu is open")
    pg.screenshot(path=out("topnav-burger-390.png"), clip={"x": 0, "y": 0, "width": 390, "height": 400})
    pg.click("#sidemenuBtn")
    pg.wait_for_timeout(500)
    pg.unroute_all()

    # ---- noauth: no account button / logout anywhere ----
    current["page"] = "topnav/noauth"
    goto(1366, 800, "light")
    if ev("document.getElementById('zxUserBtn').hidden") is not True or pg.is_visible("#zxUserBtn"):
        fail("topnav", "without authentication the account menu must be hidden")
    if ev("document.body.innerText.indexOf('Log out')") != -1:
        fail("topnav", "without authentication there must be no Log out")
    # old deep links keep working
    for tag in ("status", "httprp", "stats", "updater", "settings"):
        pg.goto(base + "#" + tag, wait_until="domcontentloaded", timeout=60000)
        pg.wait_for_timeout(700)
        if not pg.is_visible("#" + tag):
            fail("topnav", f"deep link #{tag} no longer opens its page")
    pg.evaluate("localStorage.setItem('theme','light'); localStorage.removeItem('zoraxy.topbar.update')")


def topnav_auth_ui(br, url):
    """Signed-in checks against an instance WITH authentication (topnav_run.sh starts one): account menu, role, Log out."""
    out = lambda n: os.path.join(args.out, n)
    USER, PW = os.environ.get("TOPNAV_USER", "navadmin"), os.environ.get("TOPNAV_PW", "throwaway-Pass-123")
    for theme, w in (("light", 1366), ("dark", 1366), ("light", 390)):
        current["page"] = f"topnav-auth/{theme}/{w}"
        c = br.new_context(viewport={"width": w, "height": 844}, color_scheme=theme)
        p = c.new_page()
        p.goto(url + "/login.html")
        p.wait_for_timeout(1500)
        if p.is_visible("#regsiterbtn"):
            p.fill("#username", USER); p.fill("#magic", PW); p.fill("#repeatMagic", PW)
            p.press("#repeatMagic", "Enter")
            p.wait_for_function("document.querySelector('#loginbtn') && document.querySelector('#loginbtn').offsetParent !== null", timeout=15000)
        p.fill("#username", USER); p.fill("#magic", PW); p.press("#magic", "Enter")
        p.wait_for_url(lambda u: "login.html" not in u, timeout=30000)
        p.evaluate("t => localStorage.setItem('theme', t)", theme)
        p.goto(url + "/index.html#status", wait_until="domcontentloaded", timeout=60000)
        p.wait_for_function("!document.getElementById('zxUserBtn').hidden || document.getElementById('zxMoreBtn').offsetParent !== null", timeout=15000)
        p.wait_for_timeout(800)
        if w > 748:
            p.wait_for_function("!document.getElementById('zxUserBtn').hidden", timeout=10000)
            h = p.evaluate("document.getElementById('zxUserBtn').getBoundingClientRect().height")
            if h < 32:
                fail("topnav", f"account button only {h}px high")
            if USER not in p.evaluate("document.getElementById('zxUserBtn').innerText") or USER not in p.evaluate("document.getElementById('zxUserBtn').getAttribute('aria-label')"):
                fail("topnav", "the account button does not show the user name")
            p.click("#zxUserBtn")
            p.wait_for_selector(".zx-menu")
            txt = p.evaluate("document.querySelector('.zx-menu').innerText")
            if USER not in txt or "Administrator" not in txt or "Log out" not in txt:
                fail("topnav", f"the account menu lacks name / role / Log out: {txt!r}")
            p.screenshot(path=out(f"topnav-user-menu-{theme}.png"), clip={"x": 900, "y": 0, "width": 466, "height": 300})
            m = p.evaluate(TN_MEASURE)
            if m["overlaps"] or m["scrollW"] > m["clientW"]:
                fail("topnav", f"signed-in bar collides: {m['overlaps']}")
            p.keyboard.press("Escape")
            p.wait_for_timeout(200)
            if p.evaluate("document.activeElement.id") != "zxUserBtn":
                fail("topnav", "Esc in the account menu must return focus to the account button")
            if theme == "light":
                p.click("#zxUserBtn")
                p.wait_for_selector(".zx-menu")
                p.click(".zx-menu [data-act=logout]")
                p.wait_for_url(lambda u: "login.html" in u, timeout=15000)
                if p.evaluate("fetch('/api/auth/checkLogin').then(r => r.text())") .strip().strip('"') == "true":
                    fail("topnav", "Log out did not end the session")
        else:
            p.click("#zxMoreBtn")
            p.wait_for_selector(".zx-menu")
            txt = p.evaluate("document.querySelector('.zx-menu').innerText")
            if USER not in txt or "Log out" not in txt:
                fail("topnav", f"the phone More menu lacks the account section: {txt!r}")
            p.screenshot(path=out("topnav-more-user-light-390.png"), clip={"x": 0, "y": 0, "width": 390, "height": 844})
        c.close()
