"""Smoke scenario of the security-page fixes found by the UI audit (docs/ux/audit-2026-11.md follow-up): Trusted Proxies validation,
Auto-ban manual ban / range checks / token confirmation / phone layout, toasts versus the Save bar, Basic auth label, Access Rules empty
whitelist warning, AI assistant gating, SSO discovery wording, WAF policy validation, Security overview contrast and the plugin iframe.
Loaded by smoke.py (exec in its namespace: fail, current, settle, check_horizontal, args, os, json, re)."""


def securityfix_ui(pg, ctx):
    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, success: r => res(r), error: () => res('error')}))""", [url, data])

    def get(url):
        return js("u => fetch(u).then(r => r.json())", url)

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    def invalid(sel):
        return js("sel => { const f = document.querySelector(sel).closest('.zx-field'); return !!f && f.classList.contains('is-invalid') && getComputedStyle(f.querySelector('.zx-error')).display !== 'none' && f.querySelector('.zx-error').textContent.trim().length > 0 }", sel)

    def dialog_open():
        return pg.locator(".zx-dialog").count() > 0 and pg.locator(".zx-dialog").first.is_visible()

    native = []
    on_dialog = lambda d: (native.append(d.message), d.dismiss())
    pg.on("dialog", on_dialog)
    pg.set_viewport_size({"width": 1366, "height": 900})
    theme(False)

    # ================================================================ Trusted Proxies
    current["page"] = "securityfix-trustedproxy"
    js("openTabById('trustproxy')")
    pg.wait_for_selector("#trustedProxyTable tr", timeout=8000)
    before = get("/api/trustedproxy/list")
    for bad in ("abc", "999.1.1.1", "1.2.3.4/99", "0.0.0.0/0", "::/0"):
        pg.fill("#trustedProxyIpInput", bad)
        pg.click("#trustedProxyAddForm .ui.form > button")
        pg.wait_for_timeout(250)
        if not invalid("#trustedProxyIpInput"):
            fail("trustedproxy", f"{bad!r} must show an inline error next to the field")
        if js("document.getElementById('trustedProxyIpInput').getAttribute('aria-invalid')") != "true":
            fail("a11y", f"{bad!r}: the field must be aria-invalid")
        if len(get("/api/trustedproxy/list")) != len(before):
            fail("trustedproxy", f"{bad!r} was stored")
        # the server refuses it too (an API client, or an old page)
        r = post("/api/trustedproxy/add", {"ip": bad, "desc": ""})
        if not (isinstance(r, dict) and r.get("error")):
            fail("trustedproxy", f"the API accepted {bad!r}: {r}")
    if len(get("/api/trustedproxy/list")) != len(before):
        fail("trustedproxy", "an invalid entry reached the stored list")
    pg.fill("#trustedProxyIpInput", "")
    # Edit as Text: garbage must be refused as a whole and the list must stay
    pg.click("#toggleTextEditBtn")
    pg.wait_for_function("document.getElementById('trustedProxyTextArea').value.length > 0", timeout=5000)
    pg.fill("#trustedProxyTextArea", "garbage line\n999.9.9.9/8")
    pg.click("#trustedProxyTextView button:has-text('Save')")
    pg.wait_for_timeout(300)
    err = js("document.getElementById('trustedProxyTextError').textContent")
    if "Line 1" not in err or "Nothing was saved" not in err or js("document.getElementById('trustedProxyTextError').hidden"):
        fail("trustedproxy", f"the text editor must name the bad line and say nothing was saved: {err!r}")
    r = post("/api/trustedproxy/bulkUpdate", {"csv": "10.0.0.0/8, ok\nnot-an-ip, bad"})
    if not (isinstance(r, dict) and "line 2" in str(r.get("error", ""))):
        fail("trustedproxy", f"bulkUpdate must refuse the whole text and name the line: {r}")
    if len(get("/api/trustedproxy/list")) != len(before):
        fail("trustedproxy", "garbage text replaced the trusted proxy list")
    pg.screenshot(path=os.path.join(args.out, "securityfix-trustedproxy-text-error.png"))
    # Reset to Default uses the kit dialog, not a native confirm; cancel keeps the list
    pg.click("#trustedProxyTextView button:has-text('Reset to Default')")
    pg.wait_for_selector(".zx-dialog", timeout=3000)
    pg.click(".zx-dialog [data-zx-cancel]")
    pg.wait_for_timeout(300)
    if len(get("/api/trustedproxy/list")) != len(before):
        fail("trustedproxy", "cancelling Reset to Default changed the list")
    pg.click("#trustedProxyTextView button:has-text('Cancel')")
    if native:
        fail("trustedproxy", f"a native dialog was used: {native}")
    # list order: IPv4 before IPv6, ascending
    rows = js("[...document.querySelectorAll('#trustedProxyTable .proxy-ip-display')].map(e => e.textContent)")
    v4 = [i for i, x in enumerate(rows) if ":" not in x]
    v6 = [i for i, x in enumerate(rows) if ":" in x]
    if v4 and v6 and max(v4) > min(v6):
        fail("trustedproxy", "IPv4 entries must be listed before IPv6 entries")
    # a valid entry still works, and removing it asks with the kit dialog
    pg.fill("#trustedProxyIpInput", "203.0.113.77")
    pg.click("#trustedProxyAddForm .ui.form > button")
    pg.wait_for_function("[...document.querySelectorAll('#trustedProxyTable .proxy-ip-display')].some(e => e.textContent === '203.0.113.77')", timeout=5000)
    pg.click("#trustedProxyTable tr[data-ip='203.0.113.77'] button[title=Delete]")
    pg.wait_for_selector(".zx-dialog", timeout=3000)
    pg.click(".zx-dialog [data-zx-ok]")
    pg.wait_for_function("![...document.querySelectorAll('#trustedProxyTable .proxy-ip-display')].some(e => e.textContent === '203.0.113.77')", timeout=5000)
    check_horizontal(pg, "trusted proxies")

    # ================================================================ Auto-ban
    current["page"] = "securityfix-abuse"
    js("openTabById('seccenter')")
    pg.wait_for_function("document.getElementById('abBan') && document.getElementById('abBan').value !== ''", timeout=8000)
    slots = js("document.querySelectorAll('.zx-savebar-slot').length")
    for _ in range(3):  # revisiting sections must not pile up Save bars
        for s in ("bots", "abuse"):
            pg.click(f"#secTabs .item[data-sec={s}]")
            pg.wait_for_timeout(350)
        js("openTabById('status')")
        js("openTabById('seccenter')")
        pg.wait_for_timeout(300)
    pg.wait_for_function("document.getElementById('abBan') && document.getElementById('abBan').value !== ''", timeout=8000)
    if js("document.querySelectorAll('.zx-savebar-slot').length") != slots:
        fail("savebar", f"Save bars accumulate when a section is revisited ({slots} -> {js('document.querySelectorAll(`.zx-savebar-slot`).length')})")

    def bans():
        return get("/api/abuse/list").get("Bans") or []

    IP = "198.51.100.77"
    post("/api/abuse/unban", {"ip": IP, "scope": ""})
    # a negative duration must not become a permanent ban
    pg.fill("#abNewIp", IP)
    pg.fill("#abNewSecs", "-5")
    pg.click("#abAdd")
    pg.wait_for_timeout(400)
    if not invalid("#abNewSecs"):
        fail("abuse", "a negative ban duration must show an inline error")
    if any(b["IP"] == IP for b in bans()):
        fail("abuse", "a negative ban duration created a ban")
    r = post("/api/abuse/ban", {"ip": IP, "seconds": "-5", "reason": "x"})
    if not (isinstance(r, dict) and r.get("error")) or any(b["IP"] == IP for b in bans()):
        fail("abuse", f"the API must refuse negative seconds: {r}")
    # an invalid address marks the field, not only a toast
    pg.fill("#abNewSecs", "")
    pg.fill("#abNewIp", "999.1.1.1")
    pg.click("#abAdd")
    pg.wait_for_timeout(500)
    if not invalid("#abNewIp"):
        fail("abuse", "an invalid IP must mark the field with an inline error")
    pg.fill("#abNewIp", "")
    pg.click("#abAdd")
    if not invalid("#abNewIp"):
        fail("abuse", "an empty IP must mark the field")
    pg.fill("#abNewIp", IP)
    pg.fill("#abNewSecs", "120")
    pg.click("#abAdd")
    pg.wait_for_function("[...document.querySelectorAll('#abBans tr')].some(r => r.textContent.indexOf('" + IP + "') >= 0)", timeout=5000)
    mine = [b for b in bans() if b["IP"] == IP]
    if not mine or not mine[0].get("Expires"):
        fail("abuse", f"a ban with 120 seconds must expire: {mine}")
    post("/api/abuse/unban", {"ip": IP, "scope": ""})
    pg.click("#abRefresh")
    # a long hostile reason must not stretch the table
    long_reason = "<b>" + "A" * 460 + "</b>"
    post("/api/abuse/ban", {"ip": IP, "seconds": "60", "reason": long_reason})
    pg.click("#abRefresh")
    pg.wait_for_function("[...document.querySelectorAll('#abBans tr')].some(r => r.textContent.indexOf('" + IP + "') >= 0)", timeout=5000)
    check_horizontal(pg, "auto-ban long reason")
    if js("document.querySelectorAll('#abBans b').length"):
        fail("abuse", "a ban reason was rendered as HTML")
    post("/api/abuse/unban", {"ip": IP, "scope": ""})
    pg.click("#abRefresh")

    # out-of-range numbers are refused next to the field; the form is not silently rewritten
    cfg = get("/api/abuse/config")
    posts = []
    pg.on("request", lambda rq: "/api/abuse/setConfig" in rq.url and posts.append(rq.url))
    saved = lambda: "#seccenter .zx-savebar:not([hidden]) [data-zx-save]"
    for sel, val, label in (("#abBan", "-1", "ban duration"), ("#abEsc", "0", "escalation factor"), ("#abV6", "200", "IPv6 prefix")):
        pg.fill(sel, val)
        pg.wait_for_selector(saved(), timeout=3000)
        pg.click(saved())
        pg.wait_for_function("document.querySelector('#seccenter .zx-savebar.is-error')", timeout=3000)
        if not invalid(sel):
            fail("abuse", f"{label} {val}: the field must show an inline error")
        txt = pg.inner_text("#seccenter .zx-savebar")
        if "IPv6Prefix" in txt or "Saved" in txt:
            fail("abuse", f"{label} {val}: the Save bar shows {txt!r}")
        if js("sel => document.querySelector(sel).value", sel) != val:
            fail("abuse", f"{label}: the typed value was rewritten")
        pg.click("#seccenter .zx-savebar [data-zx-discard]")
        pg.wait_for_timeout(250)
    pg.fill("#abBan", "100")
    pg.fill("#abMax", "5")
    pg.click(saved())
    pg.wait_for_function("document.querySelector('#seccenter .zx-savebar.is-error')", timeout=3000)
    if not invalid("#abMax"):
        fail("abuse", "a max ban below the ban duration must show an inline error")
    pg.click("#seccenter .zx-savebar [data-zx-discard]")
    if posts:
        fail("abuse", f"invalid numbers were sent to the server: {posts}")
    if get("/api/abuse/config")["BanSeconds"] != cfg["BanSeconds"]:
        fail("abuse", "the stored ban duration changed")

    # a toast must never cover the Save bar buttons, and the same toast does not pile up
    pg.fill("#abBan", str(cfg["BanSeconds"] + 1))
    pg.wait_for_selector(saved(), timeout=3000)
    js("msgbox('Invalid IP address', false, 6000)")
    js("ZxUI.toast('Saved'); ZxUI.toast('Saved'); ZxUI.toast('Saved')")
    pg.wait_for_timeout(500)
    over = js("""() => { const bar = document.querySelector('#seccenter .zx-savebar:not([hidden])').getBoundingClientRect();
        const hit = [...document.querySelectorAll('#messageBox, .zx-toast')].filter(e => e.offsetParent !== null || getComputedStyle(e).position === 'fixed').filter(e => {
            const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && r.left < bar.right && r.right > bar.left && r.top < bar.bottom && r.bottom > bar.top; });
        return hit.map(e => e.id || e.className); }""")
    if over:
        fail("layout", f"toasts cover the Save bar: {over}")
    if js("[...document.querySelectorAll('.zx-toast__msg')].filter(e => e.textContent === 'Saved').length") != 1:
        fail("toast", "the same toast message must replace the earlier one")
    pg.screenshot(path=os.path.join(args.out, "securityfix-abuse-savebar.png"))
    pg.click("#seccenter .zx-savebar [data-zx-discard]")

    # remote API token: revoke and replace ask first
    post("/api/abuse/token", {"action": "generate"})
    pg.click("#secTabs .item[data-sec=bots]")
    pg.click("#secTabs .item[data-sec=abuse]")
    pg.wait_for_function("document.getElementById('abTokenState') && document.getElementById('abTokenState').textContent.indexOf('A token is set') >= 0", timeout=5000)
    pg.click("#abTokRevoke")
    pg.wait_for_selector(".zx-dialog", timeout=3000)
    pg.screenshot(path=os.path.join(args.out, "securityfix-abuse-token-confirm.png"))
    pg.click(".zx-dialog [data-zx-cancel]")
    pg.wait_for_timeout(300)
    if "A token is set" not in js("document.getElementById('abTokenState').textContent"):
        fail("abuse", "cancelling the revoke dialog revoked the token")
    pg.click("#abTokGen")
    pg.wait_for_selector(".zx-dialog", timeout=3000)
    pg.click(".zx-dialog [data-zx-cancel]")
    pg.wait_for_timeout(300)
    if js("document.getElementById('abTokShow').style.display") not in ("none", ""):
        fail("abuse", "cancelling the replace dialog generated a token")
    pg.click("#abTokRevoke")
    pg.wait_for_selector(".zx-dialog", timeout=3000)
    pg.click(".zx-dialog [data-zx-ok]")
    pg.wait_for_function("document.getElementById('abTokenState').textContent.indexOf('No token set') >= 0", timeout=5000)

    # Basic auth: the Users textarea has a name
    pg.click("#secTabs .item[data-sec=basicauth]")
    pg.wait_for_selector("#baUsers", timeout=5000)
    if not js("document.getElementById('baUsers').labels.length") or not js("document.getElementById('baName').labels.length"):
        fail("a11y", "the Basic auth fields must have labels")

    # phone width: the detector table fits (cards) and nothing overflows
    pg.click("#secTabs .item[data-sec=abuse]")
    pg.wait_for_selector("#abDetectors tr", timeout=5000)
    pg.set_viewport_size({"width": 390, "height": 800})
    pg.wait_for_timeout(400)
    ov = js("(() => { const w = document.getElementById('abDetectors').closest('.zx-table-wrap'); return w.scrollWidth - w.clientWidth })()")
    if ov > 2:
        fail("layout", f"the detector table is cut off at 390px by {ov}px")
    check_horizontal(pg, "auto-ban 390")
    pg.screenshot(path=os.path.join(args.out, "securityfix-abuse-390.png"), full_page=True)
    pg.set_viewport_size({"width": 1366, "height": 900})

    # ================================================================ Access Rules: empty whitelist asks first
    current["page"] = "securityfix-access"
    js("openTabById('access')")
    pg.wait_for_selector("#enableWhitelist", state="attached", timeout=8000)
    pg.wait_for_timeout(800)
    was = get("/api/whitelist/enable?id=default")
    wl = get("/api/whitelist/list?type=country&id=default") or []
    wi = get("/api/whitelist/list?type=ip&id=default") or []
    if not was and not wl and not wi:
        pg.click(".accesscontrol.item[data-tab=tab_whitelist]")
        pg.click("label[for='enableWhitelist'], #enableWhitelist ~ label")
        pg.wait_for_selector(".zx-dialog", timeout=3000)
        pg.screenshot(path=os.path.join(args.out, "securityfix-access-empty-whitelist.png"))
        pg.click(".zx-dialog [data-zx-cancel]")
        pg.wait_for_timeout(500)
        if get("/api/whitelist/enable?id=default"):
            fail("access", "an empty whitelist was enabled although the warning was cancelled")
        if js("document.getElementById('enableWhitelist').checked"):
            fail("access", "the whitelist switch must go back off after cancelling")
    pg.click(".accesscontrol.item[data-tab=tab_blacklist]")
    pg.click("#blacklist-btn, button:has-text('Blacklist Country')")
    pg.wait_for_timeout(400)
    if "Select at least one country" not in js("document.getElementById('messageBox').innerText"):
        fail("access", "Blacklist Country without a selection must say what is missing")
    if js("getComputedStyle(document.documentElement).scrollPaddingTop") in ("auto", "0px"):
        fail("layout", "the page needs scroll-padding below the fixed top bar")
    bg = js("getComputedStyle(document.getElementById('currentEditingAccessRule')).backgroundColor")
    if "gradient" in js("getComputedStyle(document.getElementById('currentEditingAccessRule')).backgroundImage"):
        fail("contrast", f"the Access Rules banner keeps its low contrast gradient ({bg})")

    # ================================================================ SSO discovery wording
    current["page"] = "securityfix-sso"
    js("openTabById('sso')")
    pg.wait_for_timeout(800)
    src = js("fetch('/components/sso.html').then(r => r.text())")
    if "replace(/^discovery failed:" not in src:
        fail("sso", "the discovery failure text must not repeat its own prefix")

    # ================================================================ AI assistant: no dialog when the call cannot go out
    current["page"] = "securityfix-ai"
    js("openTabById('aiassist')")
    settle(pg, 700)
    if not pg.is_checked("#aiEnabled"):
        pg.click("#aiSuggest")
        pg.wait_for_timeout(500)
        if pg.locator(".ui.modal.visible").count():
            fail("ai", "the preview and send dialog must not open while the assistant is off")
        if "turned off" not in pg.inner_text("#aiResult"):
            fail("ai", f"Suggest rules while off must explain what to do: {pg.inner_text('#aiResult')!r}")
        pg.fill("#aiRuleText", "")
        pg.click("#aiRule")
        if "Describe the rule" not in pg.inner_text("#aiResult"):
            fail("ai", "an empty rule description must ask for a description")
        pg.screenshot(path=os.path.join(args.out, "securityfix-ai-off.png"))
        pg.fill("#aiBudget", "99999999999")
        pg.click("#aiSave")
        pg.wait_for_selector("#aiMsg.err", timeout=3000)
        if "monthly token budget" not in pg.inner_text("#aiMsg").lower():
            fail("ai", f"an invalid budget must be explained: {pg.inner_text('#aiMsg')!r}")
        pg.reload(wait_until="networkidle")
        pg.wait_for_timeout(500)

    # ================================================================ WAF: policy validation and tab strip
    current["page"] = "securityfix-waf"
    js("openTabById('waf')")
    settle(pg, 800)
    pg.click("#wafTabs .item[data-tab=waf-policy]") if pg.locator("#wafTabs .item[data-tab=waf-policy]").count() else None
    pol = get("/api/waf/policy")
    if pg.locator("#wafpThreshold").count() and pg.is_visible("#wafpThreshold"):
        pg.fill("#wafpThreshold", "-3")
        pg.click("#wafpSave")
        pg.wait_for_timeout(1200)
        if get("/api/waf/policy").get("InboundThreshold") != pol.get("InboundThreshold"):
            fail("waf", "a negative anomaly threshold was saved")
        if "whole number of 1 or more" not in js("document.getElementById('messageBox').innerText"):
            fail("waf", "a negative anomaly threshold must be explained")
        if js("document.getElementById('wafpSave').innerText.trim().length") == 0:
            fail("waf", "the Save policy button must keep its label")
    if js("getComputedStyle(document.getElementById('wafTabs')).backgroundImage").count("gradient") < 2:
        fail("waf", "the sideways scrolling tab strip needs a scroll hint")

    # ================================================================ Security overview: contrast tokens, plugin iframe
    current["page"] = "securityfix-overview"
    js("openTabById('secoverview')")
    settle(pg, 900)
    for dark in (False, True):
        theme(dark)
        pg.wait_for_timeout(200)
        lows = js("""() => {
            const lum = c => { const m = c.match(/[\\d.]+/g).map(Number); const f = v => { v /= 255; return v <= .03928 ? v / 12.92 : Math.pow((v + .055) / 1.055, 2.4) }; return .2126 * f(m[0]) + .7152 * f(m[1]) + .0722 * f(m[2]) };
            const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + .05) / (Math.min(x, y) + .05) };
            return [...document.querySelectorAll('#secoverview .ui.primary.button, #secoverview .soDot.s-ok, #secoverview .soDot.s-warn, #secoverview .soDot.s-fail')]
                .filter(e => e.offsetParent).map(e => { const cs = getComputedStyle(e); return [e.className, ratio(cs.color, cs.backgroundColor)] }).filter(x => x[1] < 4.5) }""")
        if lows:
            fail("contrast", f"{'dark' if dark else 'light'}: text on filled elements below 4.5:1: {lows}")
    theme(False)
    ifr = js("document.getElementById('pluginContextLoader') ? document.getElementById('pluginContextLoader').getAttribute('allow') : 'none'")
    if ifr not in (None, "none"):
        fail("console", f"the plugin iframe still carries an invalid allow attribute: {ifr!r}")
    pg.remove_listener("dialog", on_dialog)
