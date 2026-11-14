"""Smoke scenario of the Edit site window layout: (1) the window must clear the top bar (a gap above it) on short and tall screens, and
(2) the embedded editors (aliases, tags, header rules, access rule) must size to their content: no scrollbar of their own inside the
scrolling window. exec()'d by smoke.py (namespace: fail, current, args, os); run alone with --editor-layout-only. It makes its own rule and
removes it."""

import json

EL_HOST = "layout.demo.test"


def editor_layout_ui(pg, ctx):
    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: x => res({error: 'HTTP ' + x.status}), dataType: 'json'}))""", [url, data])

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=False)

    current["page"] = "editor-layout"
    base = {"type": "host", "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false", "bpgtls": "false", "cred": "", "ssl": "false"}
    post("/api/proxy/del", {"ep": EL_HOST})
    if post("/api/proxy/add", dict(base, rootname=EL_HOST)) != "OK":
        fail("editor-layout", "could not add " + EL_HOST)
        return
    try:
        for layout in ("sections", "tabs"):
            js("localStorage.setItem('zoraxy_site_editor_layout', %s)" % json.dumps(layout))
            for (w, h) in ((1366, 600), (1366, 900), (800, 560)):
                pg.set_viewport_size({"width": w, "height": h})
                js("openTabById('httprp')")
                pg.wait_for_timeout(700)
                js("""x => fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => { initHttpProxyRuleEditorModal(l.filter(e => e.RootOrMatchingDomain === x)[0]); })""", EL_HOST)
                pg.wait_for_selector("#httprpEditModalWrapper .hrp-main", state="visible", timeout=10000)
                pg.wait_for_timeout(1500)
                tag = "%s-%dx%d" % (layout, w, h)

                # 1. the window clears the top bar and the bottom edge
                r = js("""() => { const m = document.getElementById('httprpEditModal').getBoundingClientRect();
                    const bb = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--zx-topbar-h')) || 52;
                    return {top: m.top, bottom: m.bottom, barBottom: bb, vh: window.innerHeight, left: m.left, right: m.right, vw: window.innerWidth}; }""")
                if r["top"] < r["barBottom"] + 8:
                    fail("editor-layout", "%s: the Edit site window touches the top bar (window top %.0f, bar bottom %.0f)" % (tag, r["top"], r["barBottom"]))
                if r["bottom"] > r["vh"] - 8:
                    fail("editor-layout", "%s: the Edit site window runs to the bottom edge (bottom %.0f of %d)" % (tag, r["bottom"], r["vh"]))
                if r["left"] < 0 or r["right"] > r["vw"]:
                    fail("editor-layout", "%s: the Edit site window is wider than the screen" % tag)

                # 2. embedded editors: no scrollbar of their own. Every section / tab is visited, in Easy and Advanced mode, and every
                # embedded editor that is visible in it is measured (content height against the frame's height).
                seen = set()
                seen_easy = set()
                modes = ["Easy", "Advanced"] if layout == "sections" else [None]
                for mode in modes:
                    if mode:
                        js("(m) => { const b = [...document.querySelectorAll('#httprpEditModal button')].find(e => e.textContent.trim() === m); if (b) b.click(); }", mode)
                        pg.wait_for_timeout(700)
                    ntab = js("document.querySelectorAll('#hrpNav button[role=tab]').length")
                    for i in range(ntab):
                        js("(i) => { const t = document.querySelectorAll('#hrpNav button[role=tab]')[i]; if (t && t.offsetParent !== null) t.click(); }", i)
                        pg.wait_for_timeout(1300)  # the embedded pages load and report their height
                        frames = js("""() => [...document.querySelectorAll("#httprpEditModal [data-hrp-card] .zx-card__body > .wrapper_frame")].map(f => {
                            const card = f.closest('[data-hrp-card]').getAttribute('data-hrp-card'); const vis = f.offsetParent !== null && f.offsetHeight > 0;
                            let doc = 0; try { doc = f.contentDocument.body.scrollHeight; } catch (e) { doc = -1; }
                            return {card, vis, doc, shown: f.clientHeight}; })""")
                        for f in frames:
                            if not f["vis"] or f["doc"] < 0:
                                continue
                            seen.add(f["card"])
                            if mode == "Easy":
                                seen_easy.add(f["card"])
                            print("editor-layout %s %s tab%d: %s content %dpx in a %dpx frame" % (tag, mode or "", i, f["card"], f["doc"], f["shown"]))
                            if f["doc"] > f["shown"] + 4:
                                fail("editor-layout", "%s %s: the %s editor has its own scrollbar (content %dpx in a %dpx frame)" % (tag, mode or "", f["card"], f["doc"], f["shown"]))
                        if layout == "sections" and (w, h) == (1366, 600) and mode == "Advanced" and any(f["card"] == "headers" and f["vis"] for f in frames):
                            js("""() => { const c = document.querySelector("#httprpEditModal [data-hrp-card='headers']"); if (c) c.scrollIntoView({block: 'start'}); }""")
                            pg.wait_for_timeout(600)
                            shot("editor-layout-headers-1366x600.png")
                if layout == "sections" and "headers" not in seen_easy:
                    fail("editor-layout", "%s: the Header rewrite rules card must be available in Easy mode for every rule (a rule with no custom header, HSTS or permission policy looked as if the section was missing)" % tag)
                if "headers" not in seen:
                    fail("editor-layout", "%s: the Headers editor was never visible, so it could not be measured" % tag)
                js("""() => { const b = document.querySelector('#httprpEditModal .hrp-head button:last-child'); if (b) b.click(); }""")
                try:
                    pg.wait_for_selector("#httprpEditModalWrapper", state="hidden", timeout=4000)
                except Exception:
                    js("() => { if (typeof hideHttpProxyRuleEditorModal === 'function') hideHttpProxyRuleEditorModal(); }")
                    pg.wait_for_timeout(500)
        # the Header rewrite rules editor itself, light and dark, desktop and phone width (Easy mode: it is always there)
        js("localStorage.setItem('zoraxy_site_editor_layout', 'sections'); localStorage.setItem('zoraxy_site_editor_mode', 'easy')")
        for theme in ("light", "dark"):
            for (w, h) in ((1366, 720), (390, 780)):
                js("setDarkTheme(%s)" % ("true" if theme == "dark" else "false"))
                pg.set_viewport_size({"width": w, "height": h})
                js("openTabById('httprp')")
                pg.wait_for_timeout(700)
                js("""x => fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => { initHttpProxyRuleEditorModal(l.filter(e => e.RootOrMatchingDomain === x)[0]); })""", EL_HOST)
                pg.wait_for_selector("#httprpEditModalWrapper .hrp-main", state="visible", timeout=10000)
                pg.wait_for_timeout(1800)
                # the mode lives in memory once changed in this page, so switch it the way a user does
                js("() => { const b = [...document.querySelectorAll('#httprpEditModal button')].find(e => e.textContent.trim() === 'Easy'); if (b) b.click(); }")
                pg.wait_for_timeout(900)
                js("""() => { const c = document.querySelector("#httprpEditModal [data-hrp-card='headers']"); if (c) c.scrollIntoView({block: 'start'}); }""")
                pg.wait_for_timeout(700)
                shot("headers-editor-%s-%d.png" % (theme, w))
                bad = js("""() => { const f = document.querySelector("#httprpEditModal [data-hrp-card='headers'] .wrapper_frame"); if (!f) return 'no frame';
                    if (f.offsetParent === null || f.clientWidth < 100) return 'the Headers card is not on screen in Easy mode';
                    const d = f.contentDocument; const o = d.documentElement; return o.scrollWidth > o.clientWidth + 1 ? 'the editor page scrolls sideways (' + o.scrollWidth + ' > ' + o.clientWidth + ')' : ''; }""")
                if bad:
                    fail("editor-layout", "headers editor %s %dpx: %s" % (theme, w, bad))
                js("() => { if (typeof hideHttpProxyRuleEditorModal === 'function') hideHttpProxyRuleEditorModal(); }")
                pg.wait_for_timeout(500)
    finally:
        js("localStorage.removeItem('theme'); localStorage.removeItem('zoraxy_site_editor_mode')")
        js("localStorage.removeItem('zoraxy_site_editor_layout')")
        post("/api/proxy/del", {"ep": EL_HOST})
