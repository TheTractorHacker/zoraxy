"""Smoke scenario of the AI crawlers page (Security > AI crawlers, mod/aicrawler): menu entry and page chrome, off by default and
unchanged traffic, defaults form with the Save bar, data-plane effect of block / verified-only, per-site override with generated
robots.txt and llms.txt (hostile text stays text), test box, posture notes, blocked-request log entry, light / dark / 390px.
Never touches the network: the Refresh ranges button is only checked for existence (it is the one thing that would contact the
operators' servers). Loaded by smoke.py (exec in its namespace: fail, current, settle, check_horizontal, args, os)."""

import http.client
import ssl
import urllib.parse

AIC_SITE = "aic-smoke.example.com"
AIC_HOSTILE_TEXT = "# Docs <img src=x onerror=window.__xss=1> & \"quotes\"\n> summary line"
AIC_GPT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"
AIC_BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"


def aicrawlers_ui(pg, ctx):
    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js("""([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d, dataType: 'json', success: r => res(r), error: x => res({error: 'http ' + x.status})}))""", [url, data])

    def get_cfg():
        return js("fetch('/api/aicrawler/get').then(r => r.json())")

    def visible_tab():
        return js("[...document.querySelectorAll('.functiontab')].filter(e => e.offsetParent !== null).map(e => e.id)[0]")

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=True)

    # the proxy (TLS) listener of the throw-away instance: a request for the test host with a chosen User-Agent
    port = int(urllib.parse.urlparse(args.url).port) + 1

    def data_plane(path, ua, host=AIC_SITE):
        c = http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=ssl._create_unverified_context())
        try:
            c.request("GET", path, headers={"Host": host, "User-Agent": ua})
            r = c.getresponse()
            return r.status, r.read().decode("utf-8", "replace"), r.getheader("Content-Type") or ""
        finally:
            c.close()

    pg.set_viewport_size({"width": 1366, "height": 900})
    theme(False)
    current["page"] = "aicrawlers-seed"
    r = post("/api/proxy/add", {"type": "host", "rootname": AIC_SITE, "ep": "127.0.0.1:9", "tls": "false", "tlsval": "false",
                                "bypassGlobalTLS": "false", "bpgtls": "false", "cred": "", "ssl": "false"})
    if r != "OK":
        fail("aicrawlers", f"could not add the test rule {AIC_SITE}: {r}")
    try:
        # ---- default: off, nothing loaded, traffic unchanged ----
        current["page"] = "aicrawlers-default"
        d = get_cfg()
        if d["Config"]["Enabled"]:
            fail("aicrawlers", "the AI crawler policy must be off by default")
        if any(x["loaded"] for x in d["Ranges"]):
            fail("aicrawlers", "an address range list is loaded before the admin pressed Refresh")
        if len(d["Registry"]) < 20 or not d["RegistryVersion"]:
            fail("aicrawlers", "the registry is empty or has no version")
        st, _, _ = data_plane("/", AIC_GPT)
        if st == 403:
            fail("aicrawlers", "GPTBot was blocked although the policy is off (behaviour must be unchanged)")

        js("openTabById('aicrawlers')")
        pg.wait_for_selector("#aicRegRows tr[data-id]", timeout=10000)
        if visible_tab() != "aicrawlers":
            fail("aicrawlers", f"the AI crawlers page did not open, visible tab is {visible_tab()}")
        if "AI crawlers" not in js("document.querySelector('#mainmenu a.item[aria-current=page]').innerText"):
            fail("aicrawlers", "the menu entry AI crawlers is not the current page")
        group = js("document.querySelector('#mainmenu a.item[aria-current=page]').closest('.menugroup-container').getAttribute('data-group')")
        if group != "security":
            fail("aicrawlers", f"the AI crawlers entry is in menu group {group}, expected security")
        if "AI crawlers" not in js("document.querySelector('#aiCrawlersPage [data-zx-crumbs]').innerText"):
            fail("aicrawlers", "no breadcrumb on the AI crawlers page")
        if js("document.querySelectorAll('#aiCrawlersPage .zx-related a[data-nav-open]').length") < 3:
            fail("aicrawlers", "the Related box has fewer than 3 links")
        if not js("!!document.querySelector('#aiCrawlersPage [data-zx-history]')"):
            fail("aicrawlers", "no History shortcut in the page header")
        if js("document.getElementById('aicEnabled').checked"):
            fail("aicrawlers", "the policy switch starts on")
        if "Off" not in js("document.getElementById('aicStateBadge').innerText"):
            fail("aicrawlers", "the state badge does not say Off")
        if not pg.is_visible("#aicRefresh"):
            fail("aicrawlers", "the Refresh ranges button is missing")
        if js("document.querySelectorAll('#aicRegRows tr[data-id]').length") < 20:
            fail("aicrawlers", "the crawler table has fewer than 20 rows")
        tok = js("[...document.querySelectorAll('#aic-c-google-extended option')].map(o => o.value).join(',')")
        if tok != ",allow,block":
            fail("aicrawlers", f"a robots.txt-only token must offer only Allow / Block, got {tok!r}")
        if js("document.querySelectorAll('#aiCrawlersPage select:not([aria-label]):not([id])').length"):
            fail("a11y", "a select on the AI crawlers page has neither an id nor an aria-label")
        if not js("[...document.querySelectorAll('#aiCrawlersPage input, #aiCrawlersPage select, #aiCrawlersPage textarea')].filter(i => i.offsetParent && !i.labels.length && !i.getAttribute('aria-label')).length == 0"):
            bad = js("[...document.querySelectorAll('#aiCrawlersPage input, #aiCrawlersPage select, #aiCrawlersPage textarea')].filter(i => i.offsetParent && !i.labels.length && !i.getAttribute('aria-label')).map(i => i.id)")
            fail("a11y", f"a control of the AI crawlers page has no label: {bad}")
        if js("document.querySelector('#aicRangeRows').innerText").count("Not loaded") < 5:
            fail("aicrawlers", "the ranges table does not show the lists as not loaded")
        shot("aicrawlers-default-light.png")

        # ---- the defaults form: Save bar, nothing saved until Save ----
        current["page"] = "aicrawlers-form"
        if js("document.querySelectorAll('#aiCrawlersPage .zx-savebar:not([hidden])').length"):
            fail("aicrawlers", "the Save bar is visible before any change")
        pg.check("#aicEnabled")
        pg.select_option("#aic-g-training", "block")
        pg.wait_for_selector("#aiCrawlersPage .zx-savebar:not([hidden])", timeout=4000)
        if get_cfg()["Config"]["Enabled"]:
            fail("aicrawlers", "a change was saved before pressing Save")
        pg.fill("#aicRate", "0")
        pg.click("#aiCrawlersPage [data-zx-save]")
        pg.wait_for_timeout(500)
        if not js("document.getElementById('aicRate').getAttribute('aria-invalid') === 'true'"):
            fail("aicrawlers", "an invalid rate limit is not flagged")
        if get_cfg()["Config"]["Enabled"]:
            fail("aicrawlers", "an invalid form was saved")
        pg.fill("#aicRate", "30")
        pg.click("#aiCrawlersPage [data-zx-save]")
        pg.wait_for_function("!document.querySelector('#aiCrawlersPage .zx-savebar:not([hidden])') || document.querySelector('#aiCrawlersPage .zx-savebar').innerText.includes('Saved')", timeout=8000)
        pg.wait_for_function("document.getElementById('aicStateBadge').innerText.trim() === 'On'", timeout=8000)
        c = get_cfg()["Config"]
        if not c["Enabled"] or c["Global"]["Groups"].get("training") != "block":
            fail("aicrawlers", f"the saved configuration is wrong: {c}")
        # a reload of the page keeps what was saved
        js("openTabById('status')")
        js("openTabById('aicrawlers')")
        pg.click("#aicReload")
        pg.wait_for_function("document.getElementById('aic-g-training').value === 'block'", timeout=8000)

        # ---- data plane ----
        current["page"] = "aicrawlers-dataplane"
        st, _, _ = data_plane("/", AIC_GPT)
        if st != 403:
            fail("aicrawlers", f"GPTBot (training: block) got HTTP {st}, expected 403")
        st, _, _ = data_plane("/", AIC_BROWSER)
        if st == 403:
            fail("aicrawlers", "a normal browser was blocked by the AI crawler policy")
        st, _, _ = data_plane("/", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
        if st == 403:
            fail("aicrawlers", "Googlebot is not an AI crawler but was blocked")
        st, _, _ = data_plane("/", "Mozilla/5.0 (compatible; PerplexityBot/1.0)")
        if st == 403:
            fail("aicrawlers", "PerplexityBot has no policy (search group) but was blocked")

        # verified only: nothing is loaded, so an allowed-but-unverifiable crawler is treated as spoofed (fails closed)
        pg.select_option("#aic-g-agent", "allow")
        pg.check("#aicVerified")
        pg.click("#aiCrawlersPage [data-zx-save]")
        pg.wait_for_timeout(800)
        st, _, _ = data_plane("/", "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)")
        if st != 403:
            fail("aicrawlers", f"ChatGPT-User allowed with verification but no ranges loaded must fail closed, got HTTP {st}")
        pg.uncheck("#aicVerified")
        pg.click("#aiCrawlersPage [data-zx-save]")
        pg.wait_for_timeout(800)
        st, _, _ = data_plane("/", "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)")
        if st == 403:
            fail("aicrawlers", "an allowed crawler without the verification option must not be blocked")

        # blocked requests carry the crawler name
        pg.wait_for_timeout(500)
        items = js("fetch('/api/blocked/list?limit=50').then(r => r.json())")
        text = str(items)
        if "ai-crawler" not in text or "GPTBot" not in text:
            fail("aicrawlers", f"the blocked-request log has no AI crawler entry naming GPTBot: {text[:300]}")

        # ---- test box ----
        current["page"] = "aicrawlers-testbox"
        pg.fill("#aicTestUA", AIC_GPT)
        pg.click("#aicTestBtn")
        pg.wait_for_function("document.getElementById('aicTestOut').innerText.includes('GPTBot')", timeout=6000)
        if "Block" not in js("document.getElementById('aicTestOut').innerText"):
            fail("aicrawlers", "the test box does not show the Block action")
        pg.fill("#aicTestUA", AIC_BROWSER)
        pg.click("#aicTestBtn")
        pg.wait_for_function("document.getElementById('aicTestOut').innerText.includes('Not a known AI crawler')", timeout=6000)

        # ---- per site: custom policy, robots.txt, llms.txt (hostile text stays text) ----
        current["page"] = "aicrawlers-site"
        js("window.__xss = 0")
        pg.click(f"#aicSiteRows .aicEditSite[data-site='{AIC_SITE}']")
        pg.wait_for_selector("#aicSMode", timeout=4000)
        pg.select_option("#aicSMode", "custom")
        pg.select_option("#aicSAddC", "gptbot")
        pg.select_option("#aicSAddA", "allow")
        pg.click("#aicSAdd")
        pg.select_option("#aicSRobots", "serve")
        pg.select_option("#aicSLlms", "serve")
        pg.fill("#aicSLlmsText", AIC_HOSTILE_TEXT)
        pg.click("#aicSSave")
        pg.wait_for_function("document.getElementById('aicSPre') && !document.getElementById('aicSPre').hidden", timeout=8000)
        pre = js("document.getElementById('aicSPre').innerText")
        if "User-agent: GPTBot" not in pre:
            fail("aicrawlers", "the robots.txt preview does not list GPTBot")
        st, body, ct = data_plane("/", AIC_GPT)
        if st == 403:
            fail("aicrawlers", "the site override (GPTBot: allow) did not take effect")
        st, body, ct = data_plane("/robots.txt", AIC_BROWSER)
        if st != 200 or "text/plain" not in ct or "advisory" not in body or "User-agent: *" not in body:
            fail("aicrawlers", f"/robots.txt of the site is wrong: {st} {ct!r} {body[:200]!r}")
        allow_part = body[body.rfind("Disallow: /\n\n"):] if "Disallow: /\n\n" in body else body
        if "User-agent: GPTBot" not in allow_part:
            fail("aicrawlers", f"the site override must list GPTBot in the Allow group of its robots.txt: {body[:400]!r}")
        st, body, ct = data_plane("/llms.txt", AIC_BROWSER)
        if st != 200 or body.strip() != AIC_HOSTILE_TEXT.strip() or "text/plain" not in ct:
            fail("aicrawlers", f"/llms.txt of the site is wrong: {st} {ct!r} {body[:200]!r}")
        if js("window.__xss") or js("document.querySelectorAll('#aiCrawlersPage img[src=\"x\"]').length"):
            fail("xss", "llms.txt text became markup on the AI crawlers page")
        if "<img" not in js("document.getElementById('aicSLlmsText').value"):
            fail("aicrawlers", "the llms.txt text was not kept as typed")
        shot("aicrawlers-site-light.png")

        # ---- hostile host name (legacy config seeded by run.sh) is listed as text ----
        current["page"] = "aicrawlers-hostile"
        js("window.__xss = 0")
        pg.click("#aicReload")
        pg.wait_for_timeout(900)
        if js("document.querySelectorAll('#aiCrawlersPage img[src=\"x\"]').length") or js("window.__xss"):
            fail("xss", "a hostile host name became markup on the AI crawlers page")
        seeded = js("fetch('/api/proxy/list?type=host').then(r => r.json()).then(l => l.some(x => x.RootOrMatchingDomain.includes('smoke-xss.example.com')))")
        if seeded and "smoke-xss.example.com" not in js("document.getElementById('aicSiteRows').innerText"):
            fail("aicrawlers", "the legacy hostile host name is not listed as plain text in the Sites table")

        # ---- posture notes are informational ----
        if not js("document.querySelectorAll('#aicPosture li').length"):
            fail("aicrawlers", "no posture notes")
        if "Informational" not in js("document.getElementById('aicT8').closest('section').innerText"):
            fail("aicrawlers", "the posture card is not labelled informational")

        # ---- light / dark / 390px ----
        current["page"] = "aicrawlers-looks"
        for dark, name in ((False, "aicrawlers-light.png"), (True, "aicrawlers-dark.png")):
            theme(dark)
            pg.wait_for_timeout(300)
            check_horizontal(pg, "aicrawlers " + name)
            shot(name)
        theme(False)
        pg.set_viewport_size({"width": 390, "height": 800})
        pg.wait_for_timeout(300)
        check_horizontal(pg, "aicrawlers mobile")
        shot("aicrawlers-mobile.png")
        theme(True)
        pg.wait_for_timeout(300)
        check_horizontal(pg, "aicrawlers mobile dark")
        shot("aicrawlers-mobile-dark.png")
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 900})

        # ---- deep link and palette ----
        current["page"] = "aicrawlers-compat"
        pg.goto("about:blank")
        pg.goto(args.url + "/#aicrawlers", wait_until="networkidle")
        pg.wait_for_selector("#mainmenu .item")
        pg.wait_for_timeout(900)
        if visible_tab() != "aicrawlers":
            fail("aicrawlers", f"deep link #aicrawlers opened {visible_tab()}")
    finally:
        # leave the instance as found: policy off, no site settings, test rule removed
        post("/api/aicrawler/set", {"config": '{"Version":1,"Enabled":false,"Global":{},"Robots":{"Mode":""},"Sites":{}}'})
        post("/api/proxy/del", {"ep": AIC_SITE})
        post("/api/blocked/clear", {"confirm": "yes"})  # the later blocked-requests scenario expects a fresh log
        try:
            pg.evaluate("window.zxAICBar && window.zxAICBar.discard && window.zxAICBar.discard()")
        except Exception:
            pass
