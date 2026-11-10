"""Smoke scenario of the rate limit guidance (docs/ux/rate-limits.md): per-minute unit in the API and the site editor, the self-contained
rate limit editor (key, trusted monitoring, WebSockets, path limits), a real per-minute limit against a throw-away upstream (counted,
keyed, exempt, WebSocket handshakes), presets with a diff, old API clients, the informational Security overview check, hostile
path text, and light / dark / 390px screenshots. Loaded by smoke.py (exec in its namespace: fail, current, settle, check_horizontal,
args, os, serve_upstream, API); run alone with --ratelimit-only."""

RL_HOST = "rl-smoke.example.test"
WS_HOST_A = "rl-ws-a.example.test"
WS_HOST_B = "rl-ws-b.example.test"
RL_HOSTILE_PATH = "/<img src=x onerror=window.__xss=3>"


def ratelimit_ui(pg, ctx):
    import http.client
    import json as _json
    import re as _re
    import ssl as _ssl

    def js(expr, arg=None):
        return pg.evaluate(expr, arg) if arg is not None else pg.evaluate(expr)

    def post(url, data):
        return js(API, [url, data, "POST"])

    def get(url):
        return js("p => fetch(p).then(r => r.json())", url)

    def is_err(r):
        return isinstance(r, dict) and bool(r.get("error"))

    def detail(h=RL_HOST):
        return get("/api/proxy/detail?type=host&epname=" + h)

    def networking(h=RL_HOST):
        return get("/api/proxy/networking/get?ep=" + h)

    def shot(name):
        pg.screenshot(path=os.path.join(args.out, name), full_page=False)

    def theme(dark):
        if js("document.body.classList.contains('darkTheme')") != dark:
            js("toggleTheme()")
        pg.wait_for_timeout(300)

    posts = []
    pg.on("request", lambda r: posts.append((r.method, r.url, r.post_data or "")) if r.method == "POST" else None)
    inbound = int(_re.search(r":(\d+)$", args.url).group(1)) + 1

    def hit(path="/x", headers=None, count=1, host=RL_HOST):
        """Requests through the inbound listener (TLS or plain depending on the instance); returns the status codes and last headers."""
        codes, last = [], {}
        for _ in range(count):
            h = {"Host": host, "User-Agent": "ratelimit-smoke"}
            h.update(headers or {})
            got = None
            for mk in (lambda: http.client.HTTPSConnection("127.0.0.1", inbound, timeout=5, context=_ssl._create_unverified_context()),
                       lambda: http.client.HTTPConnection("127.0.0.1", inbound, timeout=5)):  # TLS first: a TLS listener answers plain HTTP with a 400
                try:
                    c = mk()
                    c.request("GET", path, headers=h)
                    r = c.getresponse()
                    r.read()
                    got = (r.status, dict(r.getheaders()))
                    c.close()
                    break
                except Exception:
                    continue
            if got is None:
                fail("ratelimit", f"the inbound listener on {inbound} did not answer {path}")
                codes.append(0)
            else:
                codes.append(got[0])
                last = got[1]
        return codes, last

    up = serve_upstream()
    upstream = f"127.0.0.1:{up.server_address[1]}"
    pg.set_viewport_size({"width": 1366, "height": 900})
    theme(False)
    current["page"] = "ratelimit-seed"
    post("/api/proxy/del", {"ep": RL_HOST})
    r = post("/api/proxy/add", {"type": "host", "rootname": RL_HOST, "ep": upstream, "tls": "false", "tlsval": "false",
                                "bypassGlobalTLS": "true", "bpgtls": "true", "cred": "", "ssl": "false",
                                "rate": "true", "ratenum": "120", "rateunit": "minute"})
    if is_err(r):
        fail("ratelimit", f"could not create the test rule: {r}")
    try:
        # ---------------------------------------------------------------- API: unit, old clients, validation
        current["page"] = "ratelimit-api"
        d = detail()
        if d.get("RateLimit") != 120 or d.get("RateUnit") != "minute" or not d.get("RequireRateLimit"):
            fail("ratelimit", f"a rule created with rateunit=minute must store 120 per minute: {d.get('RateLimit')} {d.get('RateUnit')}")
        r = post("/api/proxy/edit", {"rootname": RL_HOST, "rate": "true", "ratenum": "5"})
        d = detail()
        if is_err(r) or d.get("RateLimit") != 5 or d.get("RateUnit"):
            fail("ratelimit", f"an old client that sends ratenum without rateunit means per second: {r} {d.get('RateLimit')!r} {d.get('RateUnit')!r}")
        r = post("/api/proxy/edit", {"rootname": RL_HOST, "rate": "true", "ratenum": "3", "rateunit": "minute"})
        d = detail()
        if is_err(r) or d.get("RateLimit") != 3 or d.get("RateUnit") != "minute":
            fail("ratelimit", f"edit with rateunit=minute must store the number as typed: {r} {d.get('RateLimit')} {d.get('RateUnit')}")
        r = post("/api/proxy/edit", {"rootname": RL_HOST, "rate": "true", "ratenum": "3", "rateunit": "hour"})
        if not is_err(r):
            fail("ratelimit", f"an unknown unit must be refused: {r!r}")
        r = post("/api/proxy/edit", {"rootname": RL_HOST})  # a save that does not mention the limit keeps it
        if detail().get("RateUnit") != "minute":
            fail("ratelimit", "an edit that does not send the rate fields must keep the stored unit")
        # options
        for bad, why in (({"WSExempt": True}, "WebSocket exemption without a cap"), ({"KeyBy": "header"}, "header key without a name"),
                         ({"ExemptCIDRs": ["300.1.1.1"]}, "invalid exempt address"), ({"ExemptHeader": "X-Mon"}, "exempt header without a value")):
            r = post("/api/proxy/networking/ratelimit", {"ep": RL_HOST, "options": _json.dumps(bad)})
            if not is_err(r):
                fail("ratelimit", f"{why} must be refused: {r!r}")
        r = post("/api/proxy/networking/pathrules", {"ep": RL_HOST, "rules": _json.dumps([{"Pattern": "/a", "Action": "rate_limit", "RateLimit": 1, "RateUnit": "week"}])})
        if not is_err(r):
            fail("ratelimit", "a path limit with an unknown unit must be refused")

        # ---------------------------------------------------------------- real traffic: per minute, counted per IP
        current["page"] = "ratelimit-traffic"
        post("/api/proxy/edit", {"rootname": RL_HOST, "rate": "true", "ratenum": "3", "rateunit": "minute"})
        pg.wait_for_timeout(300)
        codes, last = hit(count=6)
        if codes[:3] != [200, 200, 200] or codes[3:] != [429, 429, 429]:
            fail("ratelimit", f"3 requests per minute must pass 3 and refuse the rest: {codes}")
        if last.get("Retry-After") != "20":
            fail("ratelimit", f"a 3 per minute limit refills one request per 20 s, Retry-After was {last.get('Retry-After')!r}")
        # keyed by the Authorization header: every key has its own budget, a request without it falls back to the IP bucket
        r = post("/api/proxy/networking/ratelimit", {"ep": RL_HOST, "options": _json.dumps({"KeyBy": "authorization"})})
        if is_err(r):
            fail("ratelimit", f"could not set the key: {r}")
        pg.wait_for_timeout(300)
        a, _ = hit(headers={"Authorization": "Bearer smoke-key-a"}, count=5)
        b, _ = hit(headers={"Authorization": "Bearer smoke-key-b"}, count=5)
        if a != [200, 200, 200, 429, 429] or b != [200, 200, 200, 429, 429]:
            fail("ratelimit", f"each Authorization value must have its own per minute budget: a={a} b={b}")
        # trusted monitoring: the local address is exempt, so nothing is limited
        r = post("/api/proxy/networking/ratelimit", {"ep": RL_HOST, "options": _json.dumps({"ExemptCIDRs": ["127.0.0.0/8", "::1"]})})
        pg.wait_for_timeout(300)
        codes, _ = hit(count=8)
        if any(c == 429 for c in codes):
            fail("ratelimit", f"an exempt address must never be limited: {codes}")
        # WebSocket handshakes: counted by default, not counted when exempt (with a connection cap). Fresh rules: the
        # bucket of the rule above is empty for another 20 seconds.
        ws = {"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="}
        for wh, opts in ((WS_HOST_A, None), (WS_HOST_B, {"WSExempt": True, "WSMaxConnsPerIP": 5})):
            post("/api/proxy/del", {"ep": wh})
            r = post("/api/proxy/add", {"type": "host", "rootname": wh, "ep": upstream, "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false",
                                        "bpgtls": "false", "cred": "", "ssl": "false", "rate": "true", "ratenum": "3", "rateunit": "minute"})
            if is_err(r):
                fail("ratelimit", f"could not create {wh}: {r}")
            if opts:
                post("/api/proxy/networking/ratelimit", {"ep": wh, "options": _json.dumps(opts)})
        pg.wait_for_timeout(400)
        codes, _ = hit(path="/ws", headers=ws, count=6, host=WS_HOST_A)
        if codes.count(429) != 3:
            fail("ratelimit", f"by default a WebSocket handshake counts like any request (3 pass, 3 refused): {codes}")
        codes, _ = hit(path="/ws", headers=ws, count=8, host=WS_HOST_B)
        if 429 in codes:
            fail("ratelimit", f"WebSocket handshakes must not be counted when exempt: {codes}")
        codes, _ = hit(path="/plain", count=5, host=WS_HOST_B)
        if codes.count(429) != 2:
            fail("ratelimit", f"normal requests keep their limit next to exempt handshakes (3 pass, 2 refused): {codes}")
        for wh in (WS_HOST_A, WS_HOST_B):
            post("/api/proxy/del", {"ep": wh})

        # ---------------------------------------------------------------- presets: preview diff, apply, never lowering, idempotent
        current["page"] = "ratelimit-presets"
        post("/api/proxy/edit", {"rootname": RL_HOST, "rate": "false"})
        tpl = {t["Name"]: t for t in get("/api/proxy/templates/list")}
        for name in ("Public website", "Login page", "Admin dashboard", "Odoo ERP", "REST API per key", "Webhook receiver", "File upload", "WebSocket app limits", "Monitoring-friendly"):
            if name not in tpl:
                fail("ratelimit", f"preset {name!r} is missing from the template list")
            elif not tpl[name].get("Note", "").startswith("A starting point, review it"):
                fail("ratelimit", f"preset {name!r} lacks the review note")
        if tpl.get("Login page"):
            pv = post("/api/proxy/templates/preview", {"template": _json.dumps(tpl["Login page"]), "rule": RL_HOST})
            fields = [c["Field"] for c in (pv.get("changes") or [])]
            if "Path limit /login" not in fields or "Path limit /wp-login.php" not in fields:
                fail("ratelimit", f"the Login page preview must list the path limits: {fields}")
            if detail().get("PathRules"):
                fail("ratelimit", "previewing a preset must not change the rule")
        pv = post("/api/proxy/templates/preview", {"template": _json.dumps(tpl["Public website"]), "rule": RL_HOST})
        if not any(c["Field"] == "Rate limit" and c["New"] == "120 req/min" for c in (pv.get("changes") or [])):
            fail("ratelimit", f"the Public website preview must say 120 req/min: {pv}")
        # the Login page preset is applied through the bulk API (what the Apply button calls)
        r = post("/api/proxy/bulk", {"rules": _json.dumps([RL_HOST]), "action": "apply_template", "params": "{}", "dryrun": "false", "template": "Login page"})
        rules = detail().get("PathRules") or []
        if len(rules) != 4 or any(x.get("Action") != "rate_limit" or x.get("RateUnit") != "minute" or x.get("RateLimit") != 5 for x in rules):
            fail("ratelimit", f"applying Login page must add four 5 per minute path limits: {r} {rules}")
        pv = post("/api/proxy/templates/preview", {"template": _json.dumps(tpl["Login page"]), "rule": RL_HOST})
        if pv.get("changes"):
            fail("ratelimit", f"applying a preset twice must change nothing: {pv}")
        # a stricter limit the operator has is never lowered (1 per second = 60 per minute is stricter than 120 per minute)
        post("/api/proxy/edit", {"rootname": RL_HOST, "rate": "true", "ratenum": "1"})
        post("/api/proxy/bulk", {"rules": _json.dumps([RL_HOST]), "action": "apply_template", "params": "{}", "dryrun": "false", "template": "Public website"})
        d = detail()
        if d.get("RateLimit") != 1 or d.get("RateUnit"):
            fail("ratelimit", f"a preset must not replace a stricter limit: {d.get('RateLimit')} {d.get('RateUnit')!r}")
        post("/api/proxy/networking/pathrules", {"ep": RL_HOST, "rules": "[]"})

        # ---------------------------------------------------------------- Security overview: informational, never scored
        current["page"] = "ratelimit-posture"
        post("/api/proxy/edit", {"rootname": RL_HOST, "rate": "false"})
        p1 = get("/api/security/posture?refresh=1")
        chk = next((c for c in p1.get("checks", []) if c["id"] == "abuse.ratelimit_login_paths"), None)
        if not chk:
            fail("ratelimit", "the Security overview lacks the login path rate limit check")
        else:
            if chk["status"] != "info" or chk.get("lostPoints") or (chk.get("remediation") or {}).get("action"):
                fail("ratelimit", f"the login path check must be informational (no points, no fix): {chk}")
            if RL_HOST not in " ".join(chk.get("evidence") or []):
                fail("ratelimit", f"the login path check must name the rule: {chk.get('evidence')}")
        post("/api/proxy/networking/pathrules", {"ep": RL_HOST, "rules": _json.dumps([{"Pattern": "/login", "Action": "rate_limit", "RateLimit": 5, "RateUnit": "minute"}])})
        p2 = get("/api/security/posture?refresh=1")
        chk2 = next((c for c in p2.get("checks", []) if c["id"] == "abuse.ratelimit_login_paths"), None)
        # (other rules of the instance, such as the legacy test rule seeded by run.sh, may still be listed)
        if not chk2 or RL_HOST in " ".join(chk2.get("evidence") or []) and "no rate limit at all" in " ".join(chk2.get("evidence") or []):
            fail("ratelimit", f"a rate limit on /login must satisfy the check for that rule: {chk2}")
        post("/api/proxy/networking/pathrules", {"ep": RL_HOST, "rules": "[]"})

        # ---------------------------------------------------------------- the editor
        current["page"] = "ratelimit-editor"
        post("/api/proxy/networking/pathrules", {"ep": RL_HOST, "rules": _json.dumps([{"Pattern": RL_HOSTILE_PATH, "Action": "rate_limit", "RateLimit": 7, "RateUnit": "minute"}])})
        js("localStorage.setItem('zoraxy_site_editor_mode', 'advanced')")
        js("openTabById('httprp')")
        js("listProxyEndpoints()")
        settle(pg, 700)
        js("h => { const b = [...document.querySelectorAll('#httpProxyList .editBtn')].find(e => e.closest('tr').dataset.ep === h); b.click(); }", RL_HOST)
        pg.wait_for_selector("#httprpEditModal", state="visible", timeout=6000)
        pg.wait_for_timeout(900)
        pg.click("#httprpEditModal .hrpedit_menu_item[cfgpage=security]")
        pg.wait_for_timeout(300)
        card = "#httprpEditModal [data-hrp-card=ratelimit]"
        if not pg.is_visible(card + " #hrpRateUnit"):
            fail("ratelimit", "the Rate limit card must have the unit select")
        fr = pg.frame_locator(card + " .ratelimit_frame")
        try:
            fr.locator("#rlRoot").wait_for(state="visible", timeout=8000)
            fr.locator("#rlPathList tr").first.wait_for(state="visible", timeout=8000)
        except Exception:
            fail("ratelimit", "the rate limit editor did not load inside the card")
        guide = fr.locator("#rlGuide").inner_text()
        for word in ("Public website", "120 req/min", "Odoo ERP", "300 req/min", "Webhook", "File upload", "WebSocket", "Monitoring", "VPN"):
            if word not in guide:
                fail("ratelimit", f"the guidance table lacks {word!r}")
        if "not account protection" not in fr.locator("#rlRoot").inner_text():
            fail("ratelimit", "the editor must say that rate limiting is not account protection")
        # hostile path text is shown as text, never as markup
        if fr.locator("#rlPathList img").count() or any(f.evaluate("window.__xss") for f in pg.frames):
            fail("xss", "a hostile path pattern became markup in the rate limit editor")
        if RL_HOSTILE_PATH not in fr.locator("#rlPathList").inner_text():
            fail("ratelimit", "the hostile path must be listed literally")
        pg.screenshot(path=os.path.join(args.out, "ratelimit-editor-light.png"))
        # unit select of the main card: real user edits, saved by the Save bar
        pg.evaluate("document.querySelector('#httprpEditModal [data-hrp-card=ratelimit]').scrollIntoView()")
        pg.click(card + " .ui.checkbox:has(.RequireRateLimit)")
        pg.select_option("#hrpRateUnit", "minute")
        pg.fill(card + " .RateLimit", "120")
        pg.wait_for_selector("#httprpEditModal .zx-savebar:visible", timeout=3000)
        if "min" not in pg.inner_text(card + " .RateUnitLabel"):
            fail("ratelimit", "the number label must follow the unit")
        n0 = len([p for p in posts if "/api/proxy/edit" in p[1]])
        pg.click("#httprpEditModal [data-zx-save]")
        pg.wait_for_function("() => { const b = document.querySelector('#httprpEditModal .zx-savebar'); return b && !b.hidden && b.classList.contains('is-success'); }", timeout=15000, polling=50)
        d = detail()
        if d.get("RateLimit") != 120 or d.get("RateUnit") != "minute" or not d.get("RequireRateLimit"):
            fail("ratelimit", f"the Save bar must save 120 per minute: {d.get('RateLimit')} {d.get('RateUnit')}")
        if not any("rateunit=minute" in p[2] for p in posts[n0:]):
            fail("ratelimit", "the editor must send rateunit with the limit")
        # key, trusted monitoring and WebSockets save by themselves
        fr.locator("#rlKeyBy").select_option("header")
        fr.locator("#rlKeyHeaderField").wait_for(state="visible")
        fr.locator("#rlSaveOptions").click()
        if "name of the header" not in fr.locator("#rlOptError").inner_text():
            fail("ratelimit", "a header key without a name must be refused with a message")
        fr.locator("#rlKeyHeader").fill("X-API-Key")
        fr.locator("#rlExemptCidrs").fill("192.0.2.10\n10.0.0.0/8")
        fr.locator("#rlExemptHeader").fill("X-Monitor-Token")
        fr.locator("#rlWsExempt").check()
        fr.locator("#rlSaveOptions").click()
        if "connection cap" not in fr.locator("#rlOptError").inner_text() and "secret value" not in fr.locator("#rlOptError").inner_text():
            fail("ratelimit", "an exempt header without a value / a WebSocket exemption without a cap must be refused: " + fr.locator("#rlOptError").inner_text())
        fr.locator("#rlExemptValue").fill("a-long-secret-value")
        fr.locator("#rlWsMax").fill("20")
        fr.locator("#rlSaveOptions").click()
        pg.wait_for_timeout(700)
        o = networking().get("RateOptions") or {}
        if o.get("KeyBy") != "header" or o.get("KeyHeader") != "X-API-Key" or o.get("ExemptCIDRs") != ["192.0.2.10", "10.0.0.0/8"] \
                or o.get("ExemptHeader") != "X-Monitor-Token" or not o.get("WSExempt") or o.get("WSMaxConnsPerIP") != 20:
            fail("ratelimit", f"the editor did not save the options: {o}")
        # path limits: add (appended at the end), save, remove
        fr.locator("#rlPPath").fill("/login")
        fr.locator("#rlPRate").fill("5")
        fr.locator("#rlPBurst").fill("5")
        fr.locator("#rlPAdd").click()
        fr.locator("#rlPSave").click()
        pg.wait_for_timeout(900)
        rules = networking().get("PathRules") or []
        if [x["Pattern"] for x in rules] != [RL_HOSTILE_PATH, "/login"] or rules[1].get("RateUnit") != "minute" or rules[1].get("RateLimit") != 5 or rules[1].get("RateBurst") != 5:
            fail("ratelimit", f"a new path limit must be appended after the existing rules: {rules}")
        fr.locator("#rlPPath").fill("nope")
        fr.locator("#rlPAdd").click()
        if "must start with /" not in fr.locator("#rlPathError").inner_text():
            fail("ratelimit", "a path without a leading slash must be refused with a message")
        fr.locator("#rlPathList .rlDel").nth(1).click()
        fr.locator("#rlPSave").click()
        pg.wait_for_timeout(900)
        rules = networking().get("PathRules") or []
        if [x["Pattern"] for x in rules] != [RL_HOSTILE_PATH]:
            fail("ratelimit", f"removing a path limit must keep the other rules: {rules}")
        # layout: light, dark and 390px
        pg.evaluate("document.querySelector('#httprpEditModal [data-hrp-card=ratelimit]').scrollIntoView()")
        for dark, name in ((False, "ratelimit-editor-light.png"), (True, "ratelimit-editor-dark.png")):
            theme(dark)
            pg.wait_for_timeout(300)
            pg.screenshot(path=os.path.join(args.out, name))
        theme(False)
        js("closeHttpRuleEditor()")
        pg.wait_for_selector("#httprpEditModal", state="hidden", timeout=5000)
        pg.set_viewport_size({"width": 390, "height": 800})
        js("h => { const b = [...document.querySelectorAll('#httpProxyList .editBtn')].find(e => e.closest('tr').dataset.ep === h); b.click(); }", RL_HOST)
        pg.wait_for_selector("#httprpEditModal", state="visible", timeout=6000)
        pg.wait_for_timeout(900)
        js("HrpEditor.show('security')")
        pg.wait_for_timeout(300)
        pg.evaluate("document.querySelector('#httprpEditModal [data-hrp-card=ratelimit] .ratelimit_frame').scrollIntoView()")
        try:
            pg.frame_locator(card + " .ratelimit_frame").locator("#rlRoot").wait_for(state="visible", timeout=8000)
        except Exception:
            fail("ratelimit", "the rate limit editor did not load at 390px")
        ov = pg.evaluate("""() => { const f = document.querySelector('#httprpEditModal .ratelimit_frame'); const d = f.contentDocument.documentElement;
            return [d.scrollWidth - d.clientWidth, f.getBoundingClientRect().right - innerWidth]; }""")
        if ov[0] > 2 or ov[1] > 1:
            fail("ratelimit", f"the rate limit editor overflows horizontally at 390px: {ov}")
        pg.screenshot(path=os.path.join(args.out, "ratelimit-editor-mobile.png"))
        js("closeHttpRuleEditor()")
        pg.wait_for_selector("#httprpEditModal", state="hidden", timeout=5000)
        pg.set_viewport_size({"width": 1366, "height": 900})
    finally:
        for h_ in (RL_HOST, WS_HOST_A, WS_HOST_B):
            post("/api/proxy/del", {"ep": h_})
        js("localStorage.removeItem('zoraxy_site_editor_mode')")
        try:
            up.shutdown()
        except Exception:
            pass
