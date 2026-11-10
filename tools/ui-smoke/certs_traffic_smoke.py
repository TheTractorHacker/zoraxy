"""Smoke scenario of the Certificates / ACME / Traffic pages audit (docs/ux/audit-2026-11.md follow-up): certificate upload result handling
and double submit, the side drawer (Close button, Escape), toast de-duplication, renew wording, the certificate table (no hidden rows, mobile
card layout), CSR messages, ACME email feedback and expired highlighting, Statistics (chart colours after the theme switch, date picker Escape,
Blocked recording note), Visitors (tabs at 390px, settings validation), Uptime Monitor (error reason, empty state, long host names) and the
absence of browser warnings from the plugin iframe sandbox. Loaded by smoke.py (exec in its namespace: fail, current, settle,
check_horizontal, args, os, allow, re)."""
import subprocess
import tempfile

LONG_HOST = "very-long-hostname-for-testing-layout-" + "x" * 50 + ".example-internal-network.corp.example.com"


def certs_traffic_ui(pg, ctx):
    tmp = tempfile.mkdtemp()

    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def openssl_cert(cn, extra):
        key, crt = os.path.join(tmp, cn + ".key"), os.path.join(tmp, cn + ".pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-subj", "/CN=" + cn,
                        "-addext", "subjectAltName=DNS:" + cn] + extra, check=True, capture_output=True)
        return open(crt).read(), open(key).read()

    def upload(cn, pem, key):
        return js("""async ([cn, pem, key]) => {
            const tok = document.querySelector('meta[name="zoraxy.csrf.Token"]').content, out = [];
            for (const [kt, body] of [['pub', pem], ['pri', key]]) {
                const f = new FormData(); f.append('file', new Blob([body]), kt);
                const r = await fetch('/api/cert/upload?ktype=' + kt + '&domain=' + cn, {method: 'POST', headers: {'X-CSRF-Token': tok}, body: f});
                out.push(r.status);
            }
            return out; }""", [cn, pem, key])

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
            pg.wait_for_timeout(300)

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=True)

    def toasts():
        return js("[...document.querySelectorAll('.zx-toast__msg, #messageBox')].filter(e => e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden').map(e => e.innerText.trim()).filter(Boolean)")

    def clear_toasts():
        js("document.querySelectorAll('.zx-toast').forEach(e => e.remove())")

    def drawer_open():
        return js("$('.sideWrapper').is(':visible') && $('.sideWrapper .content').is(':visible')")

    def wait_drawer(open_):
        pg.wait_for_function("o => ($('.sideWrapper').is(':visible') && !$('.sideWrapper .content').transition('is animating')) === o", arg=open_, timeout=6000)

    # a little traffic so the Statistics charts exist (a rule that answers 502, requests through the inbound port)
    host = "ct-traffic.smoke.test"
    r = js("""h => new Promise(res => $.cjax({url: '/api/proxy/add', method: 'POST', data: {type: 'host', rootname: h, ep: '127.0.0.1:9', tls: 'false', tlsval: 'false', bypassGlobalTLS: 'false', bpgtls: 'false', cred: '', ssl: 'false'}, success: r => res(r), error: () => res('error')}))""", host)
    inbound = int(re.search(r":(\d+)$", args.url).group(1)) + 1
    import http.client
    import ssl
    for ua in ("curl/8.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"):
        for _ in range(3):
            for mk in (lambda: http.client.HTTPSConnection("127.0.0.1", inbound, timeout=5, context=ssl._create_unverified_context()),
                       lambda: http.client.HTTPConnection("127.0.0.1", inbound, timeout=5)):
                try:   # the inbound listener is TLS or plain depending on the instance
                    c = mk()
                    c.request("GET", "/x", headers={"Host": host, "User-Agent": ua})
                    c.getresponse().read()
                    c.close()
                    break
                except Exception:
                    pass
    posts = []
    pg.on("request", lambda r: posts.append(r.url) if "/api/cert/upload" in r.url else None)
    warnings = []
    pg.on("console", lambda m: warnings.append(m.text) if m.type == "warning" else None)
    pg.set_viewport_size({"width": 1366, "height": 900})
    theme(False)
    current["page"] = "ct-seed"
    good_pem, good_key = openssl_cert("up.smoke.test", ["-days", "200"])
    soon_pem, soon_key = openssl_cert("soon.smoke.test", ["-days", "9"])
    old_pem, old_key = openssl_cert("old.smoke.test", ["-not_before", "20250101000000Z", "-not_after", "20250201000000Z"])
    for cn, pem, key in (("soon.smoke.test", soon_pem, soon_key), ("old.smoke.test", old_pem, old_key)):
        if upload(cn, pem, key) != [200, 200]:
            fail("cert-upload", f"could not seed {cn}")
    # the server itself refuses what is not a PEM certificate / key (a bad upload is an error, not a stored file)
    allow.append(re.compile(r"400 .*api/cert/upload"))
    allow.append(re.compile(r"Failed to load resource.*400"))
    st = js("""async () => { const tok = document.querySelector('meta[name="zoraxy.csrf.Token"]').content; const f = new FormData(); f.append('file', new Blob(['garbage']), 'x');
        const r = await fetch('/api/cert/upload?ktype=pub&domain=garbage.smoke.test', {method: 'POST', headers: {'X-CSRF-Token': tok}, body: f}); return [r.status, await r.text()]; }""")
    if st[0] != 400 or "PEM" not in st[1]:
        fail("cert-upload", f"the server accepted a garbage certificate upload: {st}")
    try:
        # ---- Certificates ----
        current["page"] = "ct-cert"
        js("openTabById('cert')")
        pg.wait_for_selector("#certifiedDomainList tr", timeout=8000)
        pg.wait_for_function("document.querySelectorAll('#certifiedDomainList tr').length >= 2", timeout=8000)
        wrap = js("(() => { const w = document.querySelector('#certPage .zx-table-wrap'); return [w.scrollHeight, w.clientHeight]; })()")
        if wrap[0] > wrap[1] + 2:
            fail("cert-table", f"the certificate table hides rows in a nested scroll box (scrollHeight {wrap[0]} > {wrap[1]})")
        titles = js("[...document.querySelectorAll('#certExpiringList button.renewButton')].map(b => b.title)")
        if titles and any("uploaded" not in t.lower() and "issued with" not in t.lower() for t in titles):
            fail("cert-renew", f"Renew now has no explanation: {titles}")
        if js("document.querySelectorAll('#certExpiringList button.renewButton').length") and "replace" not in js("document.getElementById('certExpiringText').innerText").lower():
            fail("cert-renew", "the Expiring soon text does not say what Renew now does for non-ACME certificates")
        pg.click("#certAddToggle")
        pg.click("#certPasteBtn")
        # garbage: nothing is posted, no success box, one error toast
        before = len(posts)
        pg.fill("#certdomain", "a b/../c" + "x" * 240)
        pg.fill("#pubkeyPasteContent", "garbage pem")
        pg.fill("#prikeyPasteContent", "garbage key")
        clear_toasts()
        pg.dblclick("#certPasteArea .ui.button >> nth=0")
        pg.wait_for_timeout(600)
        if len(posts) != before:
            fail("cert-upload", f"garbage input was posted to the server ({len(posts) - before} requests)")
        if js("$('#certUploadSuccMsg').is(':visible')"):
            fail("cert-upload", "garbage input shows the green 'uploaded' box")
        if any("uploaded" in t.lower() and "not" not in t.lower() for t in toasts()):
            fail("cert-upload", f"garbage input shows an 'uploaded' toast: {toasts()}")
        if not toasts():
            fail("cert-upload", "garbage input gives no error message")
        shot("ct-cert-garbage.png")
        # a valid pair is uploaded exactly once even on a double click
        pg.fill("#certdomain", "up.smoke.test")
        pg.fill("#pubkeyPasteContent", good_pem)
        pg.fill("#prikeyPasteContent", good_key)
        before = len(posts)
        clear_toasts()
        pg.dblclick("#certPasteArea .ui.button >> nth=0")
        pg.wait_for_function("$('#certUploadSuccMsg').is(':visible')", timeout=8000)
        pg.wait_for_timeout(500)
        if len(posts) - before != 2:
            fail("cert-upload", f"a double click sent {len(posts) - before} upload requests (expected 2: public + private key)")
        n_up = len([t for t in toasts() if "Certificate uploaded" in t])
        if n_up != 1:
            fail("toast", f"{n_up} 'Certificate uploaded' toasts after one upload")
        ov = js("(() => { const m = document.getElementById('certUploadSuccMsg'); return m.scrollWidth - m.clientWidth; })()")
        if ov > 2:
            fail("layout", f"the upload success box overflows by {ov}px")
        # toast de-duplication
        clear_toasts()
        js("ZxUI.toast('same message'); ZxUI.toast('same message'); ZxUI.toast('same message')")
        if js("document.querySelectorAll('.zx-toast').length") != 1:
            fail("toast", "the same toast message is stacked instead of shown once")
        clear_toasts()
        # side drawer: Close button and Escape
        current["page"] = "ct-drawer"
        for label in ("CSR, certificate folder", "ACME profiles"):
            pg.click(f"#certPage button:has-text('{label}')")
            wait_drawer(True)
            pg.wait_for_timeout(500)
            if not pg.is_visible(".sideWrapper .sideWrapperClose"):
                fail("a11y", f"the drawer '{label}' has no visible Close button")
            pg.keyboard.press("Escape")
            try:
                wait_drawer(False)
            except Exception:
                fail("a11y", f"Escape does not close the drawer '{label}' (focus on the page)")
                js("hideSideWrapper()")
                pg.wait_for_timeout(600)
            pg.click(f"#certPage button:has-text('{label}')")
            wait_drawer(True)
            pg.wait_for_timeout(500)
            fr = [f for f in pg.frames if "snippet/" in f.url and "placeholder" not in f.url]
            if fr:
                fr[0].locator("body").click(position={"x": 5, "y": 5})
            pg.keyboard.press("Escape")
            try:
                wait_drawer(False)
            except Exception:
                fail("a11y", f"Escape inside the drawer '{label}' does not close it")
                js("hideSideWrapper()")
                pg.wait_for_timeout(600)
            pg.click(f"#certPage button:has-text('{label}')")
            wait_drawer(True)
            pg.click(".sideWrapper .sideWrapperClose")
            try:
                wait_drawer(False)
            except Exception:
                fail("a11y", f"the Close button does not close the drawer '{label}'")
        # CSR: the field named in the message, empty submit marks the field
        pg.click("#certPage button:has-text('CSR, certificate folder')")
        wait_drawer(True)
        pg.wait_for_timeout(600)
        fr = [f for f in pg.frames if "certtools" in f.url][0]
        fr.fill("#csrCN", "not a domain!! " + "x" * 200)
        clear_toasts()
        fr.click("button:has-text('Generate key and CSR')")
        pg.wait_for_timeout(800)
        msg = " ".join(toasts())
        if "common name" not in msg.lower() or "alternative" in msg.lower():
            fail("csr", f"an invalid common name is reported as: {msg!r}")
        if len(msg) > 200:
            fail("csr", "the CSR error repeats the whole (long) value")
        if js("(() => { const m = document.getElementById('messageBox'); return m.scrollWidth - m.clientWidth; })()") > 2:
            fail("layout", "the error toast overflows its box")
        fr.fill("#csrCN", "")
        fr.click("button:has-text('Generate key and CSR')")
        pg.wait_for_timeout(300)
        if not fr.evaluate("document.getElementById('csrCN').closest('.field').classList.contains('error')"):
            fail("csr", "an empty common name does not mark the field")
        js("hideSideWrapper()")
        pg.wait_for_timeout(600)
        # 390px: tab strip of the drawer scrolls, table cards do not clip, empty cell centered
        pg.set_viewport_size({"width": 390, "height": 800})
        current["page"] = "ct-mobile"
        pg.wait_for_timeout(300)
        check_horizontal(pg, "cert 390")
        cell = js("""(() => { const td = document.querySelector('#certifiedDomainList td[data-label=Status]'); const r = td.getBoundingClientRect();
            return {right: r.right, vw: innerWidth, kids: [...td.querySelectorAll('.zx-sub, .zx-badge')].map(e => { const b = e.getBoundingClientRect(); return b.right <= innerWidth + 1; })}; })()""")
        if not all(cell["kids"]) or cell["right"] > cell["vw"] + 1:
            fail("layout", f"the Status cell is clipped at 390px: {cell}")
        empty = js("""(() => { const tb = document.getElementById('certifiedDomainList'); const tr = document.createElement('tr'); tr.id = 'zxProbe';
            tr.innerHTML = '<td colspan="6"><div class="zx-empty"><div class="zx-empty__title">probe</div></div></td>'; tb.appendChild(tr);
            const td = tr.firstChild, cs = getComputedStyle(td), b = tr.getBoundingClientRect(), e = td.querySelector('.zx-empty').getBoundingClientRect();
            const out = {display: cs.display, left: e.left - b.left, right: b.right - e.right}; tr.remove(); return out; })()""")
        if empty["display"] != "block" or abs(empty["left"] - empty["right"]) > 4:
            fail("layout", f"an empty-state cell is not centered in the card layout at 390px: {empty}")
        shot("ct-cert-390.png")
        pg.click("#certPage button:has-text('CSR, certificate folder')")
        wait_drawer(True)
        pg.wait_for_timeout(600)
        fr = [f for f in pg.frames if "certtools" in f.url][0]
        tabs = fr.evaluate("(() => { const m = document.querySelector('.ui.tabular.menu'); return [getComputedStyle(m).overflowX, m.scrollWidth, m.clientWidth]; })()")
        if tabs[0] not in ("auto", "scroll") and tabs[1] > tabs[2]:
            fail("layout", f"the drawer tab strip is clipped at 390px: {tabs}")
        js("hideSideWrapper()")
        pg.wait_for_timeout(600)
        pg.set_viewport_size({"width": 1366, "height": 900})

        # ---- ACME ----
        current["page"] = "ct-acme"
        js("openTabById('acme')")
        pg.wait_for_selector("#acmeDomainTableBody tr", timeout=8000)
        pg.wait_for_timeout(1200)
        exp = js("[...document.querySelectorAll('#acmeDomainTableBody tr')].filter(r => r.innerText.includes('old.smoke.test')).map(r => r.querySelector('td').className)")
        if exp and "expiredDomain" not in exp[0]:
            fail("acme", f"an expired certificate is not marked expired in the auto-renew table: {exp}")
        pg.fill("#prefACMEEmail", "")
        if js("document.getElementById('acmeAutoRenewCheckbox').classList.contains('disabled')"):
            clear_toasts()
            pg.click("#acmeToggleRow", position={"x": 20, "y": 10})
            pg.wait_for_timeout(300)
            if "email" not in " ".join(toasts()).lower() or not pg.is_visible("#acmeEmailRequiredHint"):
                fail("acme", f"enabling auto renew without an email gives no feedback: {toasts()}")
        for bad in ("not-an-email", ""):
            pg.fill("#prefACMEEmail", bad)
            clear_toasts()
            pg.click("button[onclick='saveDefaultCA();']")
            pg.wait_for_timeout(500)
            text = " ".join(toasts())
            if "mail:" in text.lower() or "valid email" not in text.lower() and "required" not in text.lower():
                fail("acme", f"saving the email {bad!r} reports: {text!r}")
        r = js("""async () => { const tok = document.querySelector('meta[name="zoraxy.csrf.Token"]').content;
            const x = await fetch('/api/acme/autoRenew/email', {method: 'POST', headers: {'X-CSRF-Token': tok, 'Content-Type': 'application/x-www-form-urlencoded'}, body: 'set=not-an-email'}); return await x.json(); }""")
        if "Mail:" in str(r) or "missing '@'" in str(r):
            fail("acme", f"the API still returns the raw parser error: {r}")
        shot("ct-acme.png")

        # ---- Statistics ----
        current["page"] = "ct-stats"
        js("openTabById('stats')")
        pg.wait_for_timeout(1200)
        js("document.querySelector('#sRange button[data-range=custom]').click()")
        pg.click("#statsRangeStart")
        pg.wait_for_function("document.querySelector('.picker-wrap.popup.show') !== null", timeout=10000)
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(200)
        if js("document.querySelector('.picker-wrap.popup.show') !== null"):
            fail("stats", "Escape does not close the date picker")
        js("document.querySelector('#sRange button[data-range=\"7\"]').click()")
        pg.click("#sAdvanced") if pg.is_visible("#sAdvanced") else None
        if drawer_open():
            pg.wait_for_timeout(700)
            fr = [f for f in pg.frames if "advanceStatsOprs" in f.url]
            if fr:
                body = fr[0].evaluate("document.body.innerText")
                if "Advance Statistics" in body or "RESET STATISTICS" in body or "Cancel" in body:
                    fail("stats", "the Advanced operations drawer still has the old wording (Advance / RESET / Cancel)")
                fr[0].click("button:has-text('Reset statistics')")
                pg.wait_for_selector(".zx-dialog-backdrop", timeout=3000)
                pg.keyboard.press("Escape")
            pg.wait_for_timeout(300)
            js("hideSideWrapper()")
            pg.wait_for_timeout(600)
        # chart colours follow the theme switch (a doughnut or bar chart needs data: draw one straight into the page's own helper)
        js("document.querySelector('#sRange button[data-range=today]').click()")
        try:
            pg.wait_for_function("typeof Chart !== 'undefined' && !!Chart.getChart(document.getElementById('stats_device'))", timeout=8000)
        except Exception:
            pass
        has_chart = js("typeof Chart !== 'undefined' && !!Chart.getChart && !!Chart.getChart(document.getElementById('stats_device'))")
        if not has_chart:
            fail("stats", "no chart was drawn for the generated traffic (the theme check could not run)")
        else:
            theme(True)
            pg.wait_for_timeout(300)
            col = js("Chart.getChart(document.getElementById('stats_device')).options.plugins.legend.labels.color")
            theme(False)
            if col == "#475569":
                fail("stats", "chart legends keep the light-theme colour after switching to the dark theme")
        # Blocked tab: recording off is stated on the page, the search box has a length limit
        js("document.querySelector('#statsPage .sTabs button[data-stab=blocked]').click()")
        pg.wait_for_timeout(800)
        if js("document.getElementById('sbSearch').maxLength") != 300:
            fail("stats", "the Blocked search box has no maxlength")
        was = js("document.getElementById('sbEnabled').checked")
        pg.set_checked("#sbEnabled", False)
        pg.wait_for_timeout(1200)
        if not pg.is_visible("#sbRecordingOff"):
            fail("stats", "switching recording off is not shown on the page")
        if was:
            pg.set_checked("#sbEnabled", True)
            pg.wait_for_timeout(800)
        pg.click("#statsPage .sTabs button[data-stab=overview]")

        # ---- Visitors ----
        current["page"] = "ct-visitors"
        js("openTabById('visitors')")
        pg.wait_for_timeout(1000)
        pg.set_viewport_size({"width": 390, "height": 800})
        pg.wait_for_timeout(300)
        check_horizontal(pg, "visitors 390")
        pg.click("#vTabs [data-vtab=settings]")
        pg.wait_for_timeout(300)
        if not pg.locator("#vTabs [data-vtab=settings]").evaluate("e => { e.scrollIntoView({inline: 'nearest'}); const r = e.getBoundingClientRect(); return r.right <= innerWidth + 1 && r.width > 90; }"):
            fail("layout", "the Settings & privacy tab is cut off at 390px")
        pg.set_viewport_size({"width": 1366, "height": 900})
        pg.click("#vTabs [data-vtab=recent]")
        pg.wait_for_timeout(400)
        pg.click("#vTabs [data-vtab=settings]")
        pg.wait_for_selector("#vsAge", timeout=10000)
        saves = []
        pg.on("request", lambda r: saves.append(r.url) if "visitors/settings" in r.url and r.method == "POST" else None)
        for age, ips, ring, word in (("-5", "100", "5000", "whole number"), ("30", "5", "5000", "whole number"), ("30", "100", "99999999", "whole number"), ("", "100", "5000", "whole number")):
            pg.fill("#vsAge", age)
            pg.fill("#vsIps", ips)
            pg.fill("#vsRing", ring)
            pg.click("#vsSave")
            pg.wait_for_timeout(300)
            msg = js("document.getElementById('vsMsg').innerText")
            if word not in msg or "Saved" in msg:
                fail("visitors", f"invalid settings ({age!r}, {ips!r}, {ring!r}) give: {msg!r}")
        if saves:
            fail("visitors", "out-of-range settings were posted to the server")
        pg.fill("#vsAge", "90")
        pg.fill("#vsIps", "20000")
        pg.fill("#vsRing", "5000")
        pg.click("#vsSave")
        pg.wait_for_function("document.getElementById('vsMsg').innerText.includes('Saved')", timeout=10000)
        if js("document.querySelector('#vTabs [data-vtab=recent] i.icon') && getComputedStyle(document.querySelector('#vTabs [data-vtab=recent] i.icon'), '::before').content") in ("none", "normal", '""'):
            fail("visitors", "the Recent visits tab has no icon")
        shot("ct-visitors.png")

        # ---- Uptime Monitor ----
        current["page"] = "ct-utm"
        js("openTabById('utm')")
        pg.wait_for_selector("#utmHealthyStatus", timeout=6000)
        pg.wait_for_timeout(800)
        for bad in ("abc", "999-1", "200-", "6xx"):
            pg.fill("#utmHealthyStatus", bad)
            clear_toasts()
            pg.click("#utmHealthyStatusSave")
            pg.wait_for_timeout(500)
            text = " ".join(toasts())
            if "request failed" in text.lower() or "invalid status" not in text.lower():
                fail("utm", f"status list {bad!r} reports {text!r} instead of the server's reason")
        pg.fill("#utmHealthyStatus", "")
        if js("document.getElementById('utmEmpty') !== null") and js("document.querySelector('#utmEmpty .green.check') !== null"):
            fail("utm", "the empty state shows a green check mark")
        if js("document.getElementById('utmEmpty') !== null") and "refresh this page" in js("document.getElementById('utmrender').innerText"):
            fail("utm", "the empty state still tells the user to refresh the page")
        pg.set_viewport_size({"width": 390, "height": 800})
        js("""h => { const now = Math.floor(Date.now() / 1000); renderUptimeData(h, [{ID: 'x', Name: h, URL: 'http://' + h, Protocol: 'http', Online: true, StatusCode: 200, Latency: 5, Timestamp: now}]); }""", LONG_HOST)
        pg.wait_for_timeout(300)
        check_horizontal(pg, "uptime long host 390")
        shot("ct-utm-390.png")
        js("reloadUptimeList()")
        pg.set_viewport_size({"width": 1366, "height": 900})

        # ---- no iframe sandbox warnings on a plain page load ----
        current["page"] = "ct-warnings"
        warnings.clear()
        pg.goto("about:blank")
        pg.goto(args.url + "/", wait_until="networkidle")
        pg.wait_for_selector("#mainmenu .item")
        pg.wait_for_timeout(800)
        bad = [w for w in warnings if "sandbox" in w.lower() or "Unrecognized feature" in w]
        if bad:
            fail("console", f"the page load logs iframe sandbox warnings: {bad}")
    finally:
        current["page"] = "ct-cleanup"
        # the generated traffic must not leak into later scenarios (the Status page draws its map from today's statistics)
        js("""() => { const tok = document.querySelector('meta[name="zoraxy.csrf.Token"]').content, d = new Date(), p = n => String(n).padStart(2, '0');
            const day = d.getFullYear() + '_' + p(d.getMonth() + 1) + '_' + p(d.getDate());
            return fetch('/api/analytic/resetRange?start=' + day + '&end=' + day, {method: 'DELETE', headers: {'X-CSRF-Token': tok}})
                .then(() => fetch('/api/visitors/delete', {method: 'POST', headers: {'X-CSRF-Token': tok, 'Content-Type': 'application/x-www-form-urlencoded'}, body: 'ip=127.0.0.1'})); }""")
        js("""h => new Promise(res => $.cjax({url: '/api/proxy/del', method: 'POST', data: {ep: h}, success: r => res(r), error: () => res('error')}))""", host)
        js("""async () => { const tok = document.querySelector('meta[name="zoraxy.csrf.Token"]').content;
            for (const d of ['up.smoke.test', 'soon.smoke.test', 'old.smoke.test']) { await fetch('/api/cert/delete', {method: 'POST', headers: {'X-CSRF-Token': tok, 'Content-Type': 'application/x-www-form-urlencoded'}, body: 'domain=' + d}); } }""")
