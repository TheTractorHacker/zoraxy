"""Smoke scenario of the classic tabs of the proxy rule editor (docs/ux/site-editor.md, "Layouts"). Loaded by smoke.py (exec in its
namespace: fail, current, settle, args, os, json, API). Run alone with --editor-tabs-only.

Checks: Tabs (classic) is the default for a browser without a stored choice; the 11 tabs with their old labels and cfgpage names;
every control of the old editor (siteeditor_inventory.json) exists exactly once and shows on its old tab and only there; the
Easy / Advanced switch is gone in Tabs and its stored preference is untouched; tablist / tab / tabpanel, roving tabindex and arrow keys;
legacy deep links; the Layout switch and its memory; one Save bar over several tabs; the preset dialog; a hostile host name; no overflow
and a scroll cue at 390px; light, dark and 390px screenshots.

smoke.py runs every other scenario with the Sections layout stored (an init script) so their selectors keep working; this scenario
opts out of that (localStorage zx_smoke_default_layout) to see the real default."""

TAB_LABELS = [("downstream", "Host"), ("upstream", "Destinations"), ("vdirs", "Virtual Directory"), ("websocket", "WebSocket"),
              ("alias", "Alias"), ("ssl", "TLS / SSL"), ("headers", "Headers"), ("accessrule", "Access Rules"),
              ("security", "Security"), ("waf", "WAF"), ("tags", "Tags")]
RETIRED = (".wafSourceSaveBtn", ".wafChallengeSaveBtn", ".wafSaveBtn")


def editortabs_ui(pg, ctx):
    out = lambda n: os.path.join(args.out, n)
    api = lambda path, data: pg.evaluate(API, [path, data, "POST"])
    get = lambda path: pg.evaluate("p => fetch(p).then(r => r.json())", path)
    host = "et-app.smoke.invalid"
    evil = "et<img src=x onerror=window.__xss=3>.smoke.invalid"
    LK, MK = "zoraxy_site_editor_layout", "zoraxy_site_editor_mode"

    def ls(expr):
        return pg.evaluate(expr)

    def editor_open(h, wait=900):
        pg.evaluate("openTabById('httprp')")
        pg.evaluate("listProxyEndpoints()")
        settle(pg, 700)
        pg.evaluate("h => { const b = [...document.querySelectorAll('#httpProxyList .editBtn')].find(e => e.closest('tr').dataset.ep === h); b.click(); }", h)
        pg.wait_for_selector("#httprpEditModal", state="visible", timeout=6000)
        pg.wait_for_timeout(wait)

    def editor_close():
        pg.evaluate("closeHttpRuleEditor()")
        pg.wait_for_selector("#httprpEditModal", state="hidden", timeout=5000)

    def tab(name):
        pg.click(f"#httprpEditModal .hrpedit_menu_item[cfgpage={name}]")
        pg.wait_for_timeout(120)

    def shown_cards():
        return pg.evaluate("[...document.querySelectorAll('#httprpEditModal .hrp-card')].filter(c => c.offsetParent !== null).map(c => c.dataset.hrpCard)")

    def layout():
        return pg.evaluate("document.querySelector('#httprpEditModal').dataset.layout")

    def modal_overflow(label):
        ov = pg.evaluate("""() => { const m = document.querySelector('#httprpEditModal .hrp-main'); const r = document.querySelector('#httprpEditModal').getBoundingClientRect();
            const n = document.querySelector('#hrpNav'); return [m.scrollWidth - m.clientWidth, Math.round(r.right - innerWidth), Math.round(-r.left), n.scrollWidth - n.clientWidth, document.documentElement.scrollWidth - innerWidth] }""")
        if ov[0] > 2 or ov[1] > 1 or ov[2] > 1 or ov[4] > 1:
            fail("editor-tabs", f"{label}: the editor overflows (main {ov[0]}px, right {ov[1]}px, left {ov[2]}px, page {ov[4]}px)")
        return ov

    def theme(dark):
        if pg.evaluate("document.body.classList.contains('darkTheme')") != dark:
            pg.evaluate("toggleTheme()")
        pg.wait_for_timeout(300)

    pg.set_viewport_size({"width": 1366, "height": 900})
    # a browser with no stored choice: this scenario sees the real default (smoke.py stores Sections for the other scenarios)
    pg.evaluate("localStorage.setItem('zx_smoke_default_layout', '1'); localStorage.removeItem('%s'); localStorage.setItem('%s', 'easy')" % (LK, MK))
    pg.reload(wait_until="networkidle")
    pg.wait_for_timeout(600)
    for h in (host, evil):
        api("/api/proxy/del", {"ep": h})
    r = api("/api/proxy/add", {"type": "host", "rootname": host, "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false"})
    if isinstance(r, dict) and r.get("error"):
        fail("editor-tabs", "could not create the test rule: " + str(r))
    try:
        # ---------------------------------------------------------------- 1. default and labels
        current["page"] = "editor-tabs/default"
        editor_open(host)
        if layout() != "tabs":
            fail("editor-tabs", f"the default layout must be Tabs (classic), got {layout()!r}")
        if ls("localStorage.getItem('%s')" % LK) is not None:
            fail("editor-tabs", "opening the editor must not store a layout choice by itself")
        if pg.evaluate("document.querySelector('#httprpEditModal').dataset.mode") != "advanced":
            fail("editor-tabs", "the Tabs layout shows everything (data-mode advanced)")
        if pg.is_visible("#hrpMode"):
            fail("editor-tabs", "the Easy / Advanced switch must not show in the Tabs layout")
        if pg.is_visible("#hrpShowAdv") or pg.is_visible("#hrpAdvNote"):
            fail("editor-tabs", "'Show advanced settings' and the non-default note do not apply in the Tabs layout")
        if not pg.is_visible("#hrpLayout"):
            fail("editor-tabs", "the Layout switch must be visible")
        got = pg.evaluate("[...document.querySelectorAll('#hrpNav [role=tab]')].map(t => [t.getAttribute('cfgpage'), t.innerText.trim()])")
        if [tuple(x) for x in got] != TAB_LABELS:
            fail("editor-tabs", f"tabs are not the classic 11 in order: {got}")
        if pg.evaluate("document.querySelector('#hrpNav .active').getAttribute('cfgpage')") != "downstream":
            fail("editor-tabs", "the editor must open on the Host tab")
        if ls("localStorage.getItem('%s')" % MK) != "easy":
            fail("editor-tabs", "the Easy / Advanced preference must be untouched by the Tabs layout")

        # ---------------------------------------------------------------- 2. inventory, every control on its old tab
        current["page"] = "editor-tabs/inventory"
        inv = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "siteeditor_inventory.json"), encoding="utf-8"))
        bad = pg.evaluate("(inv) => inv.filter(e => document.querySelectorAll('#httprpEditModal ' + e.selector).length !== 1).map(e => e.selector)", inv)
        if bad:
            fail("editor-tabs", f"{len(bad)} control(s) missing or duplicated: {bad[:6]}")
        tabs_known = [t for t, _ in TAB_LABELS]
        checked = 0
        for name in tabs_known:
            tab(name)
            ents = [e for e in inv if e["oldTab"] == name]
            res = pg.evaluate("""([ents, name, retired]) => ents.filter(e => !retired.some(r => e.selector.includes(r.slice(1)))).map(e => {
                const el = document.querySelector('#httprpEditModal ' + e.selector); const card = el && el.closest('[data-hrp-card]');
                return [e.selector, !!card, card && card.dataset.hrpCard === e.card, card && card.dataset.hrpTab === name, card && card.offsetParent !== null] })""", [ents, name, list(RETIRED)])
            checked += len(res)
            for sel, has, samecard, sametab, vis in res:
                if not (has and samecard and sametab and vis):
                    fail("editor-tabs", f"tab {name}: {sel} is not on its old tab (card {has}, same card {samecard}, tab attr {sametab}, shown {vis})")
            # nothing else is shown on this tab: the visible cards are exactly the cards of the tab
            want = pg.evaluate("n => [...document.querySelectorAll('#httprpEditModal .hrp-card[data-hrp-tab=\"' + n + '\"]')].map(c => c.dataset.hrpCard)", name)
            if sorted(shown_cards()) != sorted(want):
                fail("editor-tabs", f"tab {name} shows {shown_cards()} but holds {want}")
        if checked < 100:
            fail("editor-tabs", f"only {checked} inventory controls were checked on their tab")
        # menu controls (Close) are reachable on every tab
        for sel in ("button.httpProxyEditClosePC", ".editor_back_button"):
            if pg.evaluate("s => document.querySelectorAll('#httprpEditModal ' + s).length", sel) != 1:
                fail("editor-tabs", f"{sel} must exist once")
        # the card order inside a tab follows the old editor (Host: hostname, plain HTTP, forwarding, logging, ports)
        tab("downstream")
        order = pg.evaluate("[...document.querySelectorAll('#httprpEditModal .hrp-card')].filter(c => c.offsetParent !== null).sort((a, b) => a.getBoundingClientRect().top - b.getBoundingClientRect().top).map(c => c.dataset.hrpCard)")
        if order != ["host", "plainhttp", "forwarding", "logging", "ports"]:
            fail("editor-tabs", f"Host tab order is {order}")
        tab("waf")
        if "protection" not in shown_cards() or "waf" not in shown_cards():
            fail("editor-tabs", f"the WAF tab must show the protection summary and the WAF card: {shown_cards()}")

        # ---------------------------------------------------------------- 3. aria and keyboard
        current["page"] = "editor-tabs/a11y"
        aria = pg.evaluate("""() => { const nav = document.querySelector('#hrpNav'); const tabs = [...nav.querySelectorAll('[role=tab]')];
            const p = document.getElementById('hrpSections');
            return {role: nav.getAttribute('role'), n: tabs.length, selected: tabs.filter(t => t.getAttribute('aria-selected') === 'true').length,
                    tabbable: tabs.filter(t => t.tabIndex === 0).length,
                    panel: p.getAttribute('role'), labelled: p.getAttribute('aria-labelledby'), active: tabs.filter(t => t.getAttribute('aria-selected') === 'true').map(t => t.id)[0],
                    controls: tabs.every(t => t.getAttribute('aria-controls') === 'hrpSections'),
                    secRoles: [...document.querySelectorAll('#httprpEditModal .hrp-sec')].map(s => s.getAttribute('role')).join(',') } }""")
        if aria["role"] != "tablist" or aria["n"] != 11 or aria["selected"] != 1 or aria["tabbable"] != 1 or aria["panel"] != "tabpanel" \
                or aria["labelled"] != aria["active"] or not aria["controls"] or set(aria["secRoles"].split(",")) != {"presentation"}:
            fail("editor-tabs", f"tablist / tabpanel aria is wrong: {aria}")
        tab("downstream")
        pg.keyboard.press("ArrowDown")
        if pg.evaluate("document.activeElement.getAttribute('cfgpage')") != "upstream" or "upstream" not in shown_cards():
            fail("editor-tabs", "ArrowDown must move focus and selection to the next tab")
        pg.keyboard.press("End")
        if pg.evaluate("document.activeElement.getAttribute('cfgpage')") != "tags" or shown_cards() != ["tags"]:
            fail("editor-tabs", f"End must go to the last tab (shows {shown_cards()})")
        pg.keyboard.press("ArrowRight")
        if pg.evaluate("document.activeElement.getAttribute('cfgpage')") != "downstream":
            fail("editor-tabs", "the arrow keys must wrap around")
        pg.keyboard.press("Home")
        if pg.evaluate("document.querySelector('#hrpNav [aria-selected=true]').getAttribute('cfgpage')") != "downstream":
            fail("editor-tabs", "Home must go to the first tab")
        for _ in range(90):  # focus stays in the dialog
            pg.keyboard.press("Tab")
            if not pg.evaluate("document.querySelector('#httprpEditModal').contains(document.activeElement)"):
                fail("editor-tabs", "Tab left the dialog")
                break

        # ---------------------------------------------------------------- 4. deep links
        current["page"] = "editor-tabs/links"
        for name in tabs_known:
            pg.evaluate("n => HrpEditor.show(n)", name)
            if pg.evaluate("document.querySelector('#hrpNav .active').getAttribute('cfgpage')") != name:
                fail("editor-tabs", f"HrpEditor.show({name!r}) does not open that tab")
        for sec, want in (("general", "downstream"), ("routing", "vdirs"), ("security", "security"), ("tls", "ssl"), ("advanced", "downstream")):
            pg.evaluate("n => HrpEditor.show(n)", sec)
            if pg.evaluate("document.querySelector('#hrpNav .active').getAttribute('cfgpage')") != want:
                fail("editor-tabs", f"the section name {sec} must open the tab {want}")
        if pg.evaluate("document.querySelectorAll('#hrpNav .hrpedit_menu_item').length") != 11:
            fail("editor-tabs", "the tab buttons keep the class hrpedit_menu_item")

        # ---------------------------------------------------------------- 5. one Save bar across tabs, presets
        current["page"] = "editor-tabs/save"
        tab("websocket")
        pg.evaluate("document.querySelector('#httprpEditModal .EnableWebSocket').click()")
        tab("upstream")
        pg.fill("#httprpEditModal .UptimeMonitorURI", "/et-health")
        pg.wait_for_timeout(400)
        txt = pg.inner_text("#httprpEditModal .zx-savebar")
        if "2" not in txt or pg.locator("#httprpEditModal .zx-savebar").count() != 1:
            fail("editor-tabs", f"one Save bar must count the edits of two tabs: {txt!r}")
        pg.click("#httprpEditModal [data-zx-save]")
        pg.wait_for_function("() => { const b = document.querySelector('#httprpEditModal .zx-savebar'); return b && !b.hidden && b.classList.contains('is-success'); }", timeout=15000, polling=50)
        d = get("/api/proxy/detail?type=host&epname=" + host)
        if d.get("UptimeMonitorURI") != "/et-health":
            fail("editor-tabs", f"the Save bar did not save the edit of the second tab: {d.get('UptimeMonitorURI')!r}")
        pg.click("#hrpPresetBtn")
        pg.wait_for_selector("#hrpPresetModal .zxp-card", timeout=5000)
        pg.click("#hrpPresetModal .zxp-card >> nth=0")
        pg.wait_for_selector("#hrpPresetModal .zx-table", timeout=8000)
        pg.click("#hrpPresetCancel")
        pg.wait_for_selector("#hrpPresetModal", state="hidden", timeout=4000)

        # ---------------------------------------------------------------- 6. Layout switch and memory
        current["page"] = "editor-tabs/layout"
        pg.evaluate("n => HrpEditor.show(n)", "waf")
        pg.click("#hrpLayout [data-value=sections]")
        if layout() != "sections" or ls("localStorage.getItem('%s')" % LK) != "sections":
            fail("editor-tabs", "the Layout switch must change the layout and remember it")
        if pg.evaluate("document.querySelectorAll('#hrpNav [role=tab]').length") != 5 or pg.evaluate("document.querySelector('#hrpNav .active').getAttribute('cfgpage')") != "security":
            fail("editor-tabs", "switching from the WAF tab must open the Security section")
        if pg.evaluate("document.querySelector('#httprpEditModal').dataset.mode") != "easy" or not pg.is_visible("#hrpMode"):
            fail("editor-tabs", "the Sections layout must bring back the Easy / Advanced switch with the stored preference")
        if ls("localStorage.getItem('%s')" % MK) != "easy":
            fail("editor-tabs", "the stored Easy / Advanced preference changed")
        bad = pg.evaluate("(inv) => inv.filter(e => document.querySelectorAll('#httprpEditModal ' + e.selector).length !== 1).map(e => e.selector)", inv)
        if bad:
            fail("editor-tabs", f"after a layout switch controls are missing or duplicated: {bad[:6]}")
        pg.click("#hrpMode [data-value=advanced]")
        pg.click("#hrpLayout [data-value=tabs]")
        if layout() != "tabs" or ls("localStorage.getItem('%s')" % MK) != "advanced":
            fail("editor-tabs", "back to Tabs: layout or the Easy / Advanced preference is wrong")
        editor_close()
        pg.evaluate("HrpEditor.setLayout('sections')")
        pg.reload(wait_until="networkidle")
        editor_open(host, 600)
        if layout() != "sections":
            fail("editor-tabs", "the layout choice must be remembered per browser")
        pg.evaluate("HrpEditor.setLayout('tabs')")
        pg.evaluate("localStorage.setItem('%s', 'broken')" % LK)
        editor_close()
        pg.reload(wait_until="networkidle")
        editor_open(host, 600)
        if layout() != "tabs":
            fail("editor-tabs", "an unknown stored layout must fall back to Tabs")
        pg.evaluate("localStorage.removeItem('%s')" % LK)

        # ---------------------------------------------------------------- 7. hostile host name
        current["page"] = "editor-tabs/xss"
        editor_close()
        r = api("/api/proxy/add", {"type": "host", "rootname": evil, "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false"})
        if isinstance(r, dict) and r.get("error"):
            pass  # the API refuses hostile names now; the consistency scenario covers the legacy file
        else:
            pg.evaluate("window.__xss = undefined")
            editor_open(evil, 1200)
            for name in tabs_known:
                tab(name)
            if pg.evaluate("window.__xss") is not None or pg.locator("#httprpEditModal img").count():
                fail("editor-tabs", "XSS: markup in a host name was executed or rendered")
            editor_close()
            api("/api/proxy/del", {"ep": evil})

        # ---------------------------------------------------------------- 8. screenshots, 390px
        current["page"] = "editor-tabs/shots"
        editor_open(host)
        for dark in (False, True):
            theme(dark)
            tag = "dark" if dark else "light"
            for name in ("downstream", "security", "waf", "ssl"):
                tab(name)
                pg.screenshot(path=out(f"editor-tabs-{name}-{tag}.png"))
                modal_overflow(f"tab {name} {tag}")
        theme(False)
        pg.set_viewport_size({"width": 390, "height": 800})
        pg.wait_for_timeout(500)
        for name in ("downstream", "waf"):
            tab(name)
            ov = modal_overflow(f"tab {name} 390px")
            pg.screenshot(path=out(f"editor-tabs-{name}-mobile.png"))
        pg.evaluate("document.querySelector('#hrpNav').scrollLeft = 0")
        pg.wait_for_timeout(300)
        nav = pg.evaluate("""() => { const n = document.querySelector('#hrpNav'); const cs = getComputedStyle(n);
            return {scrolls: n.scrollWidth > n.clientWidth + 2, ox: cs.overflowX, cue: n.classList.contains('zx-scroll-end'), items: n.querySelectorAll('[role=tab]').length,
                    maxw: Math.max(...[...n.querySelectorAll('[role=tab]')].map(t => t.getBoundingClientRect().width)), vw: innerWidth} }""")
        if not nav["scrolls"] or nav["ox"] not in ("auto", "scroll"):
            fail("editor-tabs", f"at 390px the tab strip must scroll sideways instead of overflowing the page: {nav}")
        if not nav["cue"]:
            fail("editor-tabs", f"at 390px the scrollable tab strip must show the scroll cue (zx-scroll-end): {nav}")
        # the last tab can be reached by scrolling the strip, and selecting it works by touch-size buttons
        pg.evaluate("document.querySelector('#hrpNav [cfgpage=tags]').scrollIntoView({inline: 'center'})")
        pg.click("#httprpEditModal .hrpedit_menu_item[cfgpage=tags]")
        if shown_cards() != ["tags"]:
            fail("editor-tabs", "the last tab must be reachable at 390px")
        pg.wait_for_timeout(250)
        if not pg.evaluate("document.querySelector('#hrpNav').classList.contains('zx-scroll-start')"):
            fail("editor-tabs", "after scrolling the strip the start cue must show")
        modal_overflow("tags 390px")
        if pg.evaluate("document.querySelector('#httprpEditModal .httpProxyEditCloseMobile').offsetParent === null"):
            fail("editor-tabs", "the close button must be visible on a phone")
        pg.set_viewport_size({"width": 1366, "height": 900})
        editor_close()
    except Exception as ex:
        fail("editor-tabs", f"scenario failed: {' '.join(str(ex).split()[:40])}")
        pg.screenshot(path=out("editor-tabs-failure.png"))
    finally:
        for h in (host, evil):
            api("/api/proxy/del", {"ep": h})
        # the other scenarios run with the Sections layout (see smoke.py): put it back, in the page and in storage
        pg.evaluate("localStorage.removeItem('zx_smoke_default_layout'); localStorage.removeItem('%s'); if (window.HrpEditor) { HrpEditor.setLayout('sections'); }" % MK)
        try:
            pg.evaluate("window.resetEditorDirty && window.resetEditorDirty()")
            pg.evaluate("$('#confirmBox').hide()")
        except Exception:
            pass
