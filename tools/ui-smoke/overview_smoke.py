# exec()'d by smoke.py (shares args, fail, current, settle, check_horizontal): defines overview_ui(pg, ctx).
#
# Regression checks for the Status / Security overview / History / palette / navigation audit (docs/ux/audit-2026-11.md,
# "ux-fix-overview"): each block says which audit finding it keeps fixed.


def overview_ui(pg, ctx):
    out = lambda n: os.path.join(args.out, n)

    def get(path):
        return pg.evaluate("p => new Promise(res => $.getJSON(p, r => res(r)).fail(e => res({error: 'http ' + e.status})))", path)

    def post(path, data):
        return pg.evaluate("""([p, d]) => new Promise(res => $.cjax({url: p, method: 'POST', data: d, success: r => res(r), error: e => res({error: 'http ' + e.status})}))""", [path, data])

    def jpost(path, obj):
        return pg.evaluate("""([p, o]) => new Promise(res => $.cjax({url: p, method: 'POST', contentType: 'application/json', data: JSON.stringify(o), dataType: 'json',
            success: r => res(r), error: e => res({error: 'http ' + e.status})}))""", [path, obj])

    def theme(want_dark):
        if pg.evaluate("document.body.classList.contains('darkTheme')") != want_dark:
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(300)

    theme(False)
    pg.set_viewport_size({"width": 1366, "height": 900})
    host = "ovw-smoke.example.com"
    uhost = "münchen-büro.example.de"
    seeded = [host, uhost] + ["ovw-map-%d.example.com" % i for i in range(8)]
    qs_before = get("/api/quickstart")

    # ---- certificates: file names, listing and the Status tile (audit: double dot "www.example.com..pem") ----
    current["page"] = "overview/certs"
    post("/api/cert/delete", {"domain": host})
    glance0 = get("/api/stats/glance")
    r = post("/api/cert/selfsign?cn=" + host, {})
    if isinstance(r, dict) and r.get("error"):
        fail("certs", f"self-signed certificate could not be created: {r}")
    names = get("/api/cert/list")
    if not isinstance(names, list) or host not in names:
        fail("certs", f"the certificate list should contain {host!r}: {names}")
    if any(isinstance(n, str) and n.endswith(".") for n in names if isinstance(names, list)):
        fail("certs", f"a certificate name ends with a dot (double dot in the file name): {names}")
    glance1 = get("/api/stats/glance")
    if glance1.get("CertsTotal", 0) != glance0.get("CertsTotal", 0) + 1:
        fail("certs", f"the Status certificate tile must see a new certificate at once (cache): {glance0.get('CertsTotal')} -> {glance1.get('CertsTotal')}")
    for h in seeded[:2] + seeded[2:]:
        post("/api/proxy/add", {"type": "host", "rootname": h, "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false"})
    pv = jpost("/api/security/posture/preview", {"actions": ["hsts.enable", "waf.baseline", "autoban.enable"]})
    notes = " ".join(sum([p.get("notes") or [] for p in pv.get("previews", [])], []))
    if "could not be read" in notes:
        fail("posture", f"the HSTS fix must find a rule with a unicode host name: {notes}")
    if re.search(r"certificate is (mismatch|fallback|missing)", notes):
        fail("posture", f"raw certificate state in a note: {notes}")
    for p in pv.get("previews", []):
        for c in p.get("changes", []):
            if re.search(r"\b[a-z]+_[a-z_]+\b", c.get("label", "")):
                fail("posture", f"raw id in the change label {c.get('label')!r}")
    cert_check = next((c for c in get("/api/security/posture?refresh=1").get("checks", []) if c["id"] == "tls.https_redirect"), None)
    if cert_check is None:
        fail("posture", "no tls.https_redirect check")

    # ---- navigation: Back button, manual hash, unknown hash (audit: URL changed, page did not) ----
    current["page"] = "overview/navigation"
    pg.evaluate("openTabById('status')")
    settle(pg, 500)
    pg.evaluate("openTabById('history')")
    settle(pg, 500)
    pg.evaluate("openTabById('secoverview')")
    settle(pg, 500)
    pg.go_back()
    pg.wait_for_timeout(900)
    if pg.evaluate("location.hash") != "#history" or not pg.is_visible("#history"):
        fail("navigation", f"Back from the Security overview must show History (hash {pg.evaluate('location.hash')}, history visible {pg.is_visible('#history')})")
    if pg.evaluate("document.querySelector('#mainmenu .item.active') && document.querySelector('#mainmenu .item.active').getAttribute('tag')") != "history":
        fail("navigation", "the menu item of the page shown after Back is not active")
    pg.evaluate("location.hash = '#waf'")
    pg.wait_for_timeout(900)
    if not pg.is_visible("#waf"):
        fail("navigation", "editing the hash by hand to #waf did not open the WAF page")
    pg.evaluate("location.hash = '#nonexistent-page'")
    pg.wait_for_timeout(900)
    toast = pg.evaluate("(document.getElementById('messageBox') || {}).innerText || ''")
    if "Invalid tabid" in toast:
        fail("navigation", "an unknown hash shows a developer error toast")
    if pg.evaluate("location.hash") != "#status" or not pg.is_visible("#status"):
        fail("navigation", f"an unknown hash must fall back to Status (hash {pg.evaluate('location.hash')})")
    if not pg.evaluate("!!document.querySelector('#mainmenu .item.active')"):
        fail("navigation", "after an unknown hash no menu item is active")

    # ---- every fresh page load is free of console warnings and errors; #qstart when Quick Start is hidden (audit: scale(NaN)) ----
    post("/api/quickstart", {"dismissed": "true"})
    for h in ("#status", "#qstart", "#nonexistent", "#history"):
        current["page"] = "overview/console" + h
        fp = ctx.new_page()
        seen = []
        fp.on("console", lambda m: seen.append(f"{m.type}: {m.text}") if m.type in ("error", "warning") else None)
        fp.on("pageerror", lambda e: seen.append("pageerror: " + str(e)))
        fp.on("requestfailed", lambda r: seen.append(f"requestfailed: {r.url} {r.failure}") if "ERR_ABORTED" not in str(r.failure) else None)
        fp.on("response", lambda r: seen.append(f"http {r.status}: {r.url}") if r.status >= 400 and "favicon" not in r.url else None)
        fp.route("**/api/stats/countries", lambda rt: rt.fulfill(status=200, content_type="application/json", body='{"US": 5, "DE": 2}'))
        fp.goto(args.url + "/index.html" + h, wait_until="networkidle")
        fp.wait_for_timeout(1800)
        if seen:
            fail("console", f"{h}: {seen}")
        fp.close()
    post("/api/quickstart", {"dismissed": "true" if qs_before.get("dismissed") else "false"})

    # ---- Status page: title, tiles, checklist, 390px header, traffic map ----
    current["page"] = "overview/status"
    pg.evaluate("openTabById('status')")
    settle(pg, 1500)
    pg.wait_for_function("!document.querySelector('#glancePanel .kpiCard.skel')", timeout=15000)
    if pg.inner_text("#status .zx-page-header__title").strip() != "Status":
        fail("status", "the Status page has no page title like the other pages")
    if pg.locator("#status h1").count() != 0:
        fail("status", "the hero banner must not be a second h1")
    tiles = pg.evaluate("""() => [...document.querySelectorAll('#glancePanel .kpiCard')].map(e => ({top: Math.round(e.getBoundingClientRect().top), w: e.getBoundingClientRect().width,
        v: e.querySelector('.kpiValue').textContent.trim()}))""")
    rows = {}
    for t in tiles:
        rows.setdefault(t["top"], []).append(t)
    if len(tiles) >= 5 and min(len(v) for v in rows.values()) < 2:
        fail("status", f"a tile sits alone on its row at 1366px: {[len(v) for v in rows.values()]}")
    for t in tiles:
        if t["v"][:1].islower():
            fail("status", f"tile value starts lower case: {t['v']!r}")
    steps = pg.evaluate("""() => [...document.querySelectorAll('#getStartedList li')].map(li => ({done: !!li.querySelector('.zx-badge--ok'),
        text: li.querySelector('.zx-steps__text').innerText, btn: (li.querySelector('button') || {}).title || ''}))""")
    for s in steps:
        if s["done"] and "off until you enable" in s["text"]:
            fail("status", f"a finished step still shows its instruction: {s['text']!r}")
    # the traffic map: every node inside the frame, none under the zoom bar or the legend
    current["page"] = "overview/trafficmap"
    try:
        pg.wait_for_function("(() => { const f = document.getElementById('trafficFlowDiagram'); try { return f && f.contentDocument.querySelectorAll('.proxy-node').length >= 8; } catch (e) { return false; } })()", timeout=20000)
    except Exception:
        print("map debug", pg.evaluate("""() => { const f = document.getElementById('trafficFlowDiagram'); const d = f.contentDocument; return {src: f.getAttribute('src'), vis: f.offsetParent !== null, nodes: d && d.querySelectorAll('.proxy-node').length, ls: localStorage.getItem('zoraxy_status_diagram'), body: d && d.body.innerText.slice(0, 100)} }"""))
        raise
    pg.wait_for_timeout(600)
    bad = pg.evaluate("""() => {
        const d = document.getElementById('trafficFlowDiagram').contentDocument, w = d.getElementById('diagram-wrapper').getBoundingClientRect();
        const hit = [d.getElementById('zoom-controls').getBoundingClientRect(), d.getElementById('legend-overlay').getBoundingClientRect()];
        const out = [];
        d.querySelectorAll('.proxy-node, .upstream-node, .internet-node').forEach(n => {
            const r = n.getBoundingClientRect();
            if (r.left < w.left - 1 || r.right > w.right + 1 || r.top < w.top - 1 || r.bottom > w.bottom + 1) out.push('outside ' + (n.textContent || '').slice(0, 20));
            hit.forEach(h => { if (r.left < h.right && r.right > h.left && r.top < h.bottom && r.bottom > h.top) out.push('under controls ' + (n.textContent || '').slice(0, 20)); });
        });
        return out;
    }""")
    if bad:
        fail("trafficmap", f"nodes clipped or covered: {bad[:5]}")
    pg.screenshot(path=out("overview-status-1366.png"), full_page=True)
    # phone width: the Start / Stop buttons must not sit on the title, the language picker must show its longest name
    current["page"] = "overview/status-390"
    pg.set_viewport_size({"width": 390, "height": 800})
    pg.wait_for_timeout(600)
    ov = pg.evaluate("""() => { const b = document.querySelector('#serverstatus .poweroptions').getBoundingClientRect(), t = document.getElementById('statusTitle').getBoundingClientRect();
        return {btnBottom: b.bottom, btnTop: b.top, titleTop: t.top, titleBottom: t.bottom, btnLeft: b.left, btnRight: b.right, titleLeft: t.left, titleRight: t.right} }""")
    overlap = ov["btnBottom"] > ov["titleTop"] + 1 and ov["btnTop"] < ov["titleBottom"] - 1 and ov["btnLeft"] < ov["titleRight"] and ov["btnRight"] > ov["titleLeft"]
    if overlap:
        fail("status", f"Start / Stop buttons overlap the title at 390px: {ov}")
    clipped = pg.evaluate("""() => { const s = document.querySelector('.menubar select.i18n-picker'), cs = getComputedStyle(s), c = document.createElement('canvas').getContext('2d');
        c.font = cs.fontWeight + ' ' + cs.fontSize + ' ' + cs.fontFamily;
        const room = s.getBoundingClientRect().width - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight) - 18;
        const bad = []; [...s.options].forEach(o => { if (c.measureText(o.textContent).width > room) bad.push(o.textContent) }); return bad; }""")
    if clipped:
        fail("status", f"the language picker clips these names at 390px: {clipped}")
    check_horizontal(pg, "status 390px")
    for dark in (False, True):
        theme(dark)
        pg.screenshot(path=out("overview-status-390-%s.png" % ("dark" if dark else "light")), full_page=True)
    theme(False)
    pg.set_viewport_size({"width": 1366, "height": 900})

    # ---- Security overview: wording of the fixes ----
    current["page"] = "overview/secoverview"
    prev = jpost("/api/security/posture/preview", {"actions": ["waf.baseline"]})
    pol = get("/api/waf/policy")
    if isinstance(pol, dict) and not pol.get("Enabled"):
        # switch the WAF on in block mode through the page's own API, then the fix must not claim detection-only
        orig = dict(pol)
        pol2 = dict(pol, Enabled=True, DefaultMode="block")
        post("/api/waf/policy", {"policy": json.dumps(pol2)})
        p2 = jpost("/api/security/posture/preview", {"actions": ["waf.baseline"]})["previews"][0]
        if "detection-only" in p2["title"].lower():
            fail("posture", f"the WAF is already on in block mode but the fix is called {p2['title']!r}")
        post("/api/waf/policy", {"policy": json.dumps(orig)})

    # ---- History: summaries, counters, date range, restore dialog ----
    current["page"] = "overview/history"
    pg.wait_for_timeout(2800)
    pg.evaluate("openTabById('history')")
    settle(pg, 1200)
    pg.wait_for_function("document.querySelectorAll('#hxTimeline .hx-item').length >= 1", timeout=10000)
    summaries = pg.eval_on_selector_all("#hxTimeline .hx-summary", "e => e.map(x => x.textContent)")
    if any("/api/" in s for s in summaries):
        fail("history", f"a version summary shows a raw API path: {summaries}")
    if "0.0 MiB" in pg.inner_text("#hxStats"):
        fail("history", f"the size line rounds to 0.0 MiB: {pg.inner_text('#hxStats')}")
    pg.fill("#hxFilterObject", "no-such-object-anywhere")
    pg.click("#hxFilterBtn")
    pg.wait_for_function("document.querySelectorAll('#hxTimeline .hx-item').length == 0", timeout=8000)
    stats = pg.inner_text("#hxStats")
    if not re.search(r"0 of \d+ versions match", stats):
        fail("history", f"a filter without matches must show how many versions exist: {stats!r}")
    if pg.locator("#hxUndoBtn.disabled").count():
        fail("history", "Undo must not be disabled just because the filter matches nothing")
    pg.click("#hxFilterClear")
    pg.wait_for_function("document.querySelectorAll('#hxTimeline .hx-item').length >= 1", timeout=8000)
    pg.fill("#hxFilterFrom", "2030-01-01")
    pg.fill("#hxFilterTo", "2020-01-01")
    pg.click("#hxFilterBtn")
    if not pg.is_visible("#hxFilterError") or "after" not in pg.inner_text("#hxFilterError"):
        fail("history", "a reversed date range must show a message")
    pg.click("#hxFilterClear")
    pg.wait_for_timeout(500)
    if pg.is_visible("#hxFilterError"):
        fail("history", "Clear must remove the date range message")
    pg.set_viewport_size({"width": 1366, "height": 700})
    pg.locator("#hxTimeline .hx-item .hx-restore").first.click()
    pg.wait_for_selector("#hxRestoreModal.visible", timeout=5000)
    pg.wait_for_function("document.getElementById('hxPreview').innerText.includes('would change') || document.getElementById('hxPreview').innerText.includes('Nothing to restore')", timeout=8000)
    pg.wait_for_timeout(400)
    nested = pg.evaluate("""() => [...document.querySelectorAll('#hxRestoreModal .hx-diff')].filter(e => e.scrollHeight > e.clientHeight + 2 && getComputedStyle(e).overflowY !== 'visible').length""")
    if nested:
        fail("history", "the restore diff is a scroll box inside the scrolling dialog")
    if pg.locator("#hxConfirmWrap").evaluate("e => getComputedStyle(e).display") != "none":
        if pg.locator("label[for=hxConfirmWord]").count() == 0:
            fail("history", "the RESTORE confirmation field has no label")
    pg.screenshot(path=out("overview-history-restore.png"))
    pg.click("#hxRestoreCancel")
    pg.wait_for_timeout(500)
    pg.set_viewport_size({"width": 1366, "height": 900})

    # ---- command palette: plurals, duplicates, other kinds of objects, stale actions ----
    current["page"] = "overview/palette"
    post("/api/redirect/add", {"redirectUrl": "ovw-old.example.com", "destUrl": "https://ovw-new.example.com", "forwardChildpath": "true", "requireExactMatch": "false", "redirectType": "307", "deviceType": "all"})
    pg.evaluate("openTabById('status')")
    settle(pg, 400)
    pg.keyboard.press("Control+k")
    pg.wait_for_selector("#zxPalette:not([hidden]) input", timeout=3000)
    pg.fill("#zxPalette input", "ovw-old")
    pg.wait_for_function("document.querySelectorAll('#zxPalette [role=option]').length >= 1", timeout=5000)
    if "ovw-old.example.com" not in pg.inner_text("#zxPalette .zx-palette__list"):
        fail("palette", "a redirect rule is not found by the palette")
    pg.fill("#zxPalette input", "upd")
    pg.wait_for_timeout(300)
    labels = pg.eval_on_selector_all("#zxPalette [role=option] .zx-palette__label", "e => e.map(x => x.textContent.trim().toLowerCase())")
    if labels.count("check for updates") > 1:
        fail("palette", f"'Check for updates' is listed twice: {labels}")
    pg.fill("#zxPalette input", "toggle dark")
    pg.wait_for_timeout(300)
    if pg.locator("#zxPalette [role=option]").count() == 1 and "1 results" in pg.inner_text("#zxPaletteStatus"):
        fail("palette", "the result count says '1 results'")
    waf = (pg.evaluate("fetch('/api/waf/policy').then(r => r.json())") or {}).get("Enabled")
    pg.fill("#zxPalette input", "waf")
    pg.wait_for_timeout(400)
    actions = pg.eval_on_selector_all("#zxPalette [role=option] .zx-palette__label", "e => e.map(x => x.textContent.trim())")
    if waf and "Enable WAF" in actions:
        fail("palette", "'Enable WAF' is offered while the WAF is on")
    # a group heading must not be the last thing in the visible list without its items
    orphan = pg.evaluate("""() => { const l = document.querySelector('#zxPalette .zx-palette__list'); const lr = l.getBoundingClientRect(); let bad = 0;
        l.querySelectorAll('[role=group]').forEach(g => { const h = g.querySelector('.zx-palette__group').getBoundingClientRect(), first = g.querySelector('[role=option]');
            if (first && h.bottom <= lr.bottom && first.getBoundingClientRect().top >= lr.bottom) bad++; }); return bad; }""")
    if orphan:
        fail("palette", "a group heading is visible at the bottom of the list but its items are cut off")
    pg.keyboard.press("Escape")
    post("/api/redirect/delete", {"redirectUrl": "ovw-old.example.com"})

    # ---- Quick Start: no error toast for Start without a card ----
    current["page"] = "overview/quickstart"
    pg.evaluate("openTabById('qstart')")
    settle(pg, 800)
    if not pg.locator("#qsStartBtn.disabled").count():
        fail("quickstart", "Start Walkthrough must be disabled until a card is selected")
    pg.click("#quickstart .serviceOption.homepage")
    if pg.locator("#qsStartBtn.disabled").count():
        fail("quickstart", "selecting a card must enable Start Walkthrough")

    # ---- clean up what this scenario created ----
    for h in seeded:
        post("/api/proxy/del", {"ep": h})
    post("/api/cert/delete", {"domain": host})
    pg.evaluate("openTabById('status')")
    settle(pg, 500)
