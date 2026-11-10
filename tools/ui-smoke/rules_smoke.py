"""Security rules page scenario (Rules builder). Called from smoke.py: rules_ui(pg, ctx, h) with h = dict of the smoke helpers
(fail, current, settle, check_horizontal, out). Everything is built through the UI; the API is only used to read back what
the server stored and to prepare fixtures (a list, a hostile rule)."""
import json
import os
import http.server
import threading


def rules_ui(pg, ctx, h):
    fail, current, settle, check_horizontal, out = h["fail"], h["current"], h["settle"], h["check_horizontal"], h["out"]
    current["page"] = "rules"
    pg.set_viewport_size({"width": 1366, "height": 900})

    def post(url, body):
        return pg.evaluate("""([u, b]) => new Promise(res => $.cjax({url: u, method: 'POST', contentType: 'application/json', data: JSON.stringify(b), dataType: 'json',
            success: d => res(d), error: x => res({status: x.status, error: (x.responseJSON || {}).error || 'http'})}))""", [url, body])

    def get(url):
        return pg.evaluate("u => fetch(u).then(r => r.json())", url)

    def rules(site=""):
        return get("/api/ruleset/rules?site=" + site)

    def shot(name):
        pg.screenshot(path=os.path.join(out, name), full_page=True)

    def savebar_click():
        pg.click("#rbEditor .zx-savebar [data-zx-save]")

    def valid():
        pg.wait_for_selector("#rbEditor .rb-status.is-ok", timeout=8000)

    # clean slate (the instance is shared with other scenarios)
    for r in rules():
        post("/api/ruleset/rule/delete", {"site": "", "id": r["id"]})

    for l in get("/api/ruleset/lists"):
        post("/api/ruleset/list/delete", {"name": l["name"]})
    pg.evaluate("openTabById('ruleset')")
    pg.wait_for_selector("#rbList .zx-empty", timeout=8000)
    if pg.locator("#rbTemplates .rb-tpl").count() != 7:
        fail("rules", "the template gallery must show 7 templates")
    shot("rules-empty.png")

    # ---- template opens the builder pre-filled and log-only ----
    pg.click("#rbTemplates .rb-tpl[data-tpl=block-country]")
    pg.wait_for_selector("#rbEditor .rb-group")
    if pg.locator("#rbEditor .zx-segmented__item[aria-checked=true]").inner_text().strip() != "Log-only":
        fail("rules", "a template must open in log-only mode")
    pg.click("#rbBack")  # new rule counts as unsaved: confirm dialog
    pg.wait_for_selector(".zx-dialog", timeout=3000)
    pg.click(".zx-dialog [data-zx-ok], .zx-dialog .zx-btn--danger")
    pg.wait_for_selector("#rbList", state="visible")

    # ---- build a rule only through the UI ----
    pg.click("#rbNew")
    pg.wait_for_selector("#rbEditor .rb-group")
    pg.locator("#rbEditor input.zx-input").first.fill("Smoke admin rule")
    row0 = pg.locator("#rbEditor .rb-row").nth(0)
    row0.locator(".rb-val input").fill("/admin")
    pg.click("#rbEditor .rb-group.is-root > .rb-ghead [data-act=addc]")
    row1 = pg.locator("#rbEditor .rb-row").nth(1)
    row1.locator(".rb-field").select_option("ip.country")
    row1.locator(".rb-op").select_option("not_in")
    row1.locator(".rb-picker input").fill("US")
    row1.locator(".rb-picker input").press("Enter")
    # nested group (OR) with two conditions
    pg.click("#rbEditor .rb-group.is-root > .rb-ghead [data-act=addg]")
    pg.wait_for_selector("#rbEditor .rb-group .rb-group")
    inner = pg.locator("#rbEditor .rb-group .rb-group")
    inner.locator(".rb-gop").select_option("or")
    inner.locator(".rb-row").nth(0).locator(".rb-val input").fill("/api")
    inner.locator("> .rb-ghead [data-act=addc]").click()
    r2 = inner.locator(".rb-row").nth(1)
    r2.locator(".rb-field").select_option("http.header")
    r2.locator(".rb-key").fill("x-api-key")
    r2.locator(".rb-op").select_option("not_exists")
    valid()
    sent = pg.inner_text("#rbEditor .rb-sentence")
    if "the path starts with /admin" not in sent or "United States (US)" not in sent or "block with status 403" not in sent or "(" not in sent:
        fail("rules", f"plain-English sentence wrong: {sent!r}")
    expr = pg.inner_text("#rbEditor .rb-expr")
    if 'http.path starts_with "/admin"' not in expr or "x-api-key" not in expr or " or " not in expr:
        fail("rules", f"expression view wrong: {expr!r}")
    shot("rules-editor-light.png")

    # ---- text view round trip and validation error display ----
    pg.check("#rbAdv")
    pg.wait_for_selector("#rbEditor textarea.rb-text")
    text = pg.input_value("#rbEditor textarea.rb-text")
    if text.strip() != expr.strip():
        fail("rules", f"text view must show the canonical expression, got {text!r} vs {expr!r}")
    pg.fill("#rbEditor textarea.rb-text", 'http.path starts_with')
    pg.wait_for_selector("#rbEditor .rb-caret", timeout=8000)
    if "Line 1, column" not in pg.inner_text("#rbEditor .rb-when"):
        fail("rules", "text errors must show line and column")
    shot("rules-text-error.png")
    pg.fill("#rbEditor textarea.rb-text", 'http.path starts_with "/admin" and ip.country not in ["US"]')
    valid()
    pg.uncheck("#rbAdv")
    pg.wait_for_selector("#rbEditor .rb-row")
    if pg.locator("#rbEditor .rb-row").count() != 2 or pg.locator("#rbEditor .rb-row").nth(0).locator(".rb-val input").input_value() != "/admin":
        fail("rules", "switching back from text must restore the visual tree")

    # ---- save as log-only ----
    savebar_click()
    pg.wait_for_function("document.querySelector('#rbEdTitle').textContent.indexOf('Edit rule') === 0", timeout=8000)
    rs = rules()
    if len(rs) != 1 or not rs[0]["dry_run"] or rs[0]["name"] != "Smoke admin rule" or "/admin" not in rs[0]["expression"]:
        fail("rules", f"saved rule wrong: {rs}")

    # ---- tester inside the editor shows the rule matching ----
    ti = pg.locator("#rbEditor .rb-tform input[type=text]")
    ti.nth(0).fill("https://example.com/admin/users")
    ti.nth(2).fill("DE")
    pg.click("#rbEditor .rb-tform button:has-text('Run the test')")
    pg.wait_for_selector("#rbEditor .rb-testres .rb-verdict", timeout=8000)
    if "This rule matches the request" not in pg.inner_text("#rbEditor .rb-testres") or "nothing was performed" not in pg.inner_text("#rbEditor .rb-testres").lower():
        fail("rules", "tester must show the match and say nothing was performed")
    ti.nth(2).fill("US")
    pg.click("#rbEditor .rb-tform button:has-text('Run the test')")
    pg.wait_for_function("document.querySelector('#rbEditor .rb-testres').textContent.indexOf('does not match') >= 0", timeout=8000)
    shot("rules-tester.png")
    pg.click("#rbBack")
    pg.wait_for_selector("#rbList tr[data-id]")
    row = pg.locator("#rbList tr[data-id]").first
    if "Log-only" not in row.inner_text() or "Smoke admin rule" not in row.inner_text():
        fail("rules", "list row must show the name and the log-only badge")

    # ---- enable / disable ----
    row.locator("input[data-act=enable]").uncheck()
    pg.wait_for_function("1", timeout=500)
    pg.wait_for_timeout(500)
    if rules()[0]["enabled"]:
        fail("rules", "disable did not reach the server")
    row.locator("input[data-act=enable]").check()
    pg.wait_for_timeout(500)
    if not rules()[0]["enabled"]:
        fail("rules", "enable did not reach the server")

    # ---- reorder ----
    post("/api/ruleset/rule/create", {"site": "", "rule": {"name": "Second", "expression": 'http.path == "/two"', "action": {"type": "log"}}})
    pg.evaluate("RB.refresh()")
    pg.wait_for_selector("#rbList tr[data-id] >> nth=1")
    pg.locator("#rbList tr[data-id]").nth(1).locator("button[data-act=up]").click()
    pg.wait_for_function("document.querySelector('#rbList tr[data-id] b').textContent === 'Second'", timeout=5000)
    if [r["name"] for r in rules()] != ["Second", "Smoke admin rule"]:
        fail("rules", "reorder did not reach the server")
    if pg.evaluate("document.activeElement && document.activeElement.getAttribute('data-act')") not in ("up", "down"):
        fail("rules", "focus must stay on the move button after a move")

    # ---- enforce confirmation with the tester, cancel then confirm ----
    pg.locator("#rbList tr[data-id]").nth(0).locator("button[data-act=mode]").click()
    pg.wait_for_selector(".zx-dialog .rb-testres", timeout=8000)
    shot("rules-enforce-dialog.png")
    pg.keyboard.press("Escape")
    if not rules()[0]["dry_run"]:
        fail("rules", "cancelling the enforce dialog must keep the rule log-only")
    pg.locator("#rbList tr[data-id]").nth(0).locator("button[data-act=mode]").click()
    pg.wait_for_selector(".zx-dialog .rb-testres", timeout=8000)
    pg.click(".zx-dialog .zx-btn--danger")
    pg.wait_for_function("document.querySelector('#rbList tr[data-id] .rb-modebtn').textContent.trim() === 'Enforcing'", timeout=5000)
    if rules()[0]["dry_run"]:
        fail("rules", "enforce did not reach the server")

    # ---- lock-out warning: a broad block rule that names the admin host ----
    pg.click("#rbNew")
    pg.wait_for_selector("#rbEditor .rb-group")
    pg.locator("#rbEditor input.zx-input").first.fill("Broad block")
    pg.locator("#rbEditor .rb-row").nth(0).locator(".rb-val input").fill("/")
    valid()
    pg.wait_for_selector("#rbEditor .zx-callout:has-text('lock you out')", timeout=8000)
    shot("rules-lockout.png")
    pg.click("#rbBack")
    pg.click(".zx-dialog .zx-btn--danger")
    pg.wait_for_selector("#rbList tr[data-id]")

    # ---- delete with confirmation ----
    pg.locator("#rbList tr[data-id]").nth(1).locator("button[data-act=del]").click()
    pg.wait_for_selector(".zx-dialog")
    pg.click(".zx-dialog .zx-btn--danger")
    pg.wait_for_function("document.querySelectorAll('#rbList tr[data-id]').length === 1", timeout=5000)
    if len(rules()) != 1:
        fail("rules", "delete did not reach the server")

    # ---- lists ----
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelLists]")
    pg.click("#rbNewList")
    pg.wait_for_selector("#rbListForm input")
    pg.locator("#rbListForm input").nth(0).fill("office")
    pg.locator("#rbListForm select").select_option("ip")
    pg.locator("#rbListForm textarea").fill("203.0.113.0/24\n198.51.100.7")
    pg.click("#rbListForm button:has-text('Create list')")
    pg.wait_for_selector("#rbListsBody tr[data-list=office]")
    pg.click("#rbListsBody tr[data-list=office] button[aria-label^='Edit list']")
    pg.wait_for_selector("#rbListForm textarea")
    pg.locator("#rbListForm textarea").fill("203.0.113.0/24")
    pg.click("#rbListForm button:has-text('Save list')")
    pg.wait_for_function("document.querySelector('#rbListsBody tr[data-list=office] td[data-label=Entries]').textContent === '1'", timeout=5000)
    ok = post("/api/ruleset/rule/create", {"site": "", "rule": {"name": "Uses office", "expression": "ip.src in $office", "action": {"type": "log"}}})
    pg.evaluate("RB.refresh()")
    pg.wait_for_function("document.querySelector('#rbListsBody tr[data-list=office]').textContent.indexOf('1 rule') >= 0", timeout=5000)
    pg.click("#rbListsBody tr[data-list=office] button[aria-label^='Delete list']", force=True)
    pg.wait_for_timeout(500)
    if pg.locator(".zx-dialog").count():
        fail("rules", "a list in use must not offer deletion")
    allow = h.get("allow")
    if allow is not None:
        import re
        allow.append(re.compile(r"400.*/api/ruleset/list/delete"))
    refused = post("/api/ruleset/list/delete", {"name": "office"})
    if "error" not in refused:
        fail("rules", "the API must refuse to delete a list in use")
    shot("rules-lists.png")
    post("/api/ruleset/rule/delete", {"site": "", "id": ok["id"]})
    pg.evaluate("RB.refresh()")
    pg.wait_for_function("document.querySelector('#rbListsBody tr[data-list=office]').textContent.indexOf('not used') >= 0", timeout=5000)
    pg.click("#rbListsBody tr[data-list=office] button[aria-label^='Delete list']")
    pg.wait_for_selector(".zx-dialog")
    pg.click(".zx-dialog .zx-btn--danger")
    pg.wait_for_function("!document.querySelector('#rbListsBody tr[data-list=office]')", timeout=5000)

    # ---- import from /api/ruleset/migrate (response mocked with one proposal; creation is real) ----
    mock = {"statement": "Read-only: nothing was created.", "proposals": [
        {"source": "path_rule", "source_ref": "app.example.com /legacy", "site": "", "exact": False, "notes": ["differs: trailing slash"], "valid": True,
         "rule": {"name": "Imported legacy", "expression": 'http.path starts_with "/legacy"', "dry_run": True, "enabled": True, "action": {"type": "block", "status": 403}}}],
        "not_converted": [{"source": "bot_rule", "source_ref": "weird bot", "reason": "uses a feature the rules cannot express"}]}
    pg.route("**/api/ruleset/migrate", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps(mock)))
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelImport]")
    pg.click("#rbImportScan")
    pg.wait_for_selector("#rbImportBody .rb-prop")
    t = pg.inner_text("#rbImportBody")
    if "approximate" not in t or "differs: trailing slash" not in t or "cannot be converted" not in t.lower() or "weird bot" not in t:
        fail("rules", f"import view incomplete: {t[:300]!r}")
    pg.click("#rbImportBody button:has-text('Create selected')")
    pg.wait_for_function("document.querySelector('#rbImportBody').textContent.indexOf('1 rule(s) created as log-only') >= 0", timeout=8000)
    pg.unroute("**/api/ruleset/migrate")
    imp = [r for r in rules() if r["name"] == "Imported legacy"]
    if len(imp) != 1 or not imp[0]["dry_run"]:
        fail("rules", "imported rule must exist and be log-only")

    # ---- hostile content stays text ----
    bad = "<img src=x onerror=window.__pwn=1>"
    post("/api/ruleset/rule/create", {"site": "", "rule": {"name": bad, "description": "<script>window.__pwn=2</script>", "expression": 'http.path == "<b>x</b>"', "action": {"type": "tag", "tag": "x"}}})
    post("/api/ruleset/list/save", {"name": "hostile", "type": "string", "description": bad, "items": [bad, "<script>window.__pwn=3</script>"]})
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelRules]")
    pg.evaluate("RB.refresh()")
    pg.wait_for_selector("#rbList tr[data-id]:has-text('onerror')")
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelLists]")
    pg.wait_for_selector("#rbListsBody tr[data-list=hostile]")
    pg.click("#rbListsBody tr[data-list=hostile] button[aria-label^='Edit list']")
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelTest]")
    pg.locator("#rbTesterMount input[type=text]").nth(0).fill("https://example.com/<b>x</b>")
    pg.locator("#rbTesterMount textarea").fill("X-Evil: <img src=x onerror=window.__pwn=4>")
    pg.click("#rbTesterMount button:has-text('Run the test')")
    pg.wait_for_selector("#rbTesterMount .rb-testres")
    pg.wait_for_timeout(300)
    if pg.evaluate("window.__pwn") or pg.locator("#rbPage img, #rbPage script:not([src])").count():
        fail("rules", "hostile rule / list / tester content was interpreted as HTML")
    post("/api/ruleset/list/delete", {"name": "hostile"})
    for r in rules():
        if r["name"] == bad:
            post("/api/ruleset/rule/delete", {"site": "", "id": r["id"]})

    # ---- AI proposal -> log-only rule (mock provider; every step is a human click) ----
    class Mock(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            name = body.get("response_format", {}).get("json_schema", {}).get("name", "")
            res = {"propose_rules": {"proposals": [
                {"name": "AI wp-login", "description": "Log wp-login probes", "reason": "120 hits", "expression": 'http.path contains "/wp-login.php"', "action": "block"},
                {"name": "AI invented", "description": "d", "reason": "r", "expression": '(http.request.uri.path contains "/x")', "action": "block"}]}}.get(name, {})
            if name == "propose_rules":
                res["proposals"] = res["proposals"][:1]
            data = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(res)}}], "usage": {"prompt_tokens": 50, "completion_tokens": 20}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Mock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ep = "http://127.0.0.1:%d/v1" % srv.server_address[1]
        pg.evaluate("openTabById('aiassist')")
        settle(pg, 700)
        pg.evaluate("""ep => { $('#aiEnabled').prop('checked', true); $('#aiProvider').val('openai_compatible').trigger('change');
            $('#aiEndpoint').val(ep); $('#aiModel').val('mock-model'); $('#aiLocal').prop('checked', true); $('#aiKey').val('sk-fake-rules-0000ABCD'); }""", ep)
        pg.click("#aiSave")
        pg.wait_for_selector("#aiMsg.ok", timeout=5000)
        before = len(rules())
        pg.click("#aiSuggest")
        pg.wait_for_selector(".ui.modal.visible .approve.button", timeout=5000)
        pg.click(".ui.modal.visible .approve.button")
        pg.wait_for_selector("#aiResult .aiProposal .aiAddRule", timeout=10000)
        if len(rules()) != before:
            fail("ai-rules", "showing a proposal must never create a rule")
        pg.click("#aiResult .aiAddRule")
        pg.wait_for_selector(".ui.modal.visible .approve.button", timeout=5000)
        if "log-only" not in pg.inner_text(".ui.modal.visible").lower():
            fail("ai-rules", "the add dialog must say log-only")
        pg.click(".ui.modal.visible .approve.button")
        pg.wait_for_function("1", timeout=300)
        pg.wait_for_timeout(1000)
        ai = [r for r in rules() if r["name"] == "AI wp-login"]
        if len(ai) != 1 or not ai[0]["dry_run"] or not ai[0]["description"].startswith("[AI proposal]"):
            fail("ai-rules", f"AI rule must exist, log-only and marked: {ai}")
        pg.click("#aiResult .aiOpenBuilder")
        pg.wait_for_selector("#rbEditor .rb-group", timeout=8000)
        valid()
        if "wp-login.php" not in pg.inner_text("#rbEditor .rb-sentence") or "proposed by the AI" not in pg.inner_text("#rbEditor"):
            fail("ai-rules", "open in builder must show the proposal and the AI notice")
        shot("rules-ai-builder.png")
        pg.click("#rbBack")
        pg.click(".zx-dialog .zx-btn--danger")
        pg.evaluate("""() => new Promise(res => $.cjax({url: './api/ai/settings/save', method: 'POST', data: {settings: JSON.stringify({enabled: false, provider: 'anthropic', endpoint: 'https://api.anthropic.com', model: 'claude-sonnet-5-5',
            feature_explain: true, feature_suggest: true, feature_audit: true, send_paths: true, monthly_token_budget: 500000, rate_per_minute: 6, clear_key: true})}, success: res, error: res}))""")
    finally:
        srv.shutdown()

    # ---- 500 rules: the list must stay responsive ----
    for r in rules():
        post("/api/ruleset/rule/delete", {"site": "", "id": r["id"]})
    batch = [{"name": f"Bulk {i}", "expression": f'http.path == "/bulk/{i}"', "action": {"type": "log"}} for i in range(500)]
    pg.evaluate("""async (b) => { for (const r of b) await new Promise(res => $.cjax({url: './api/ruleset/rule/create', method: 'POST', contentType: 'application/json', data: JSON.stringify({site: 'x'.slice(1), rule: r}), success: () => res(), error: () => res()})); }""", batch)
    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelRules]")
    pg.evaluate("RB.refresh()")
    pg.wait_for_selector("#rbList .rb-more", timeout=10000)
    if pg.locator("#rbList tr[data-id]").count() != 100:
        fail("rules", "the list must render 100 rows and offer 'Show more'")
    pg.fill("#rbSearch", "Bulk 119")
    pg.wait_for_function("document.querySelectorAll('#rbList tr[data-id]').length === 1", timeout=5000)
    pg.fill("#rbSearch", "")
    for r in rules():
        post("/api/ruleset/rule/delete", {"site": "", "id": r["id"]})

    # ---- failure / edge cases (second session, API failure, model rules) ----
    from rules_edge_smoke import rules_edge
    rules_edge(pg, h, post, rules, valid, savebar_click)

    # ---- visual checks: dark and 390px ----
    pg.evaluate("RB.refresh()")
    post("/api/ruleset/rule/create", {"site": "", "rule": {"name": "Sample", "expression": 'http.path starts_with "/admin" and ip.country != "US"', "action": {"type": "block", "status": 403}}})
    pg.evaluate("RB.refresh()")
    pg.wait_for_selector("#rbList tr[data-id]")
    check_horizontal(pg, "rules desktop")
    was_dark = pg.evaluate("document.body.classList.contains('darkTheme')")
    if not was_dark:
        pg.evaluate("toggleTheme()")
    settle(pg, 400)
    shot("rules-list-dark.png")
    pg.click("#rbList tr[data-id] button[data-act=edit]")
    pg.wait_for_selector("#rbEditor .rb-group")
    settle(pg, 400)
    shot("rules-editor-dark.png")
    pg.click("#rbBack")
    if not was_dark:
        pg.evaluate("toggleTheme()")
    pg.set_viewport_size({"width": 390, "height": 844})
    settle(pg, 400)
    check_horizontal(pg, "rules mobile list")
    shot("rules-list-mobile.png")
    nw = pg.evaluate("(() => { const b = document.querySelector('#rbList tr[data-id] .rb-name'); const r = b.getBoundingClientRect(); return [r.width, document.querySelector('#rbList tr[data-id] .rb-name b').getBoundingClientRect().height]; })()")
    if nw[0] < 200 or nw[1] > 30:
        fail("rules", f"the rule name must have its own full-width row in the stacked mobile list (width/height {nw})")
    pg.click("#rbList tr[data-id] button[data-act=edit]")
    pg.wait_for_selector("#rbEditor .rb-group")
    settle(pg, 400)
    check_horizontal(pg, "rules mobile editor")
    shot("rules-editor-mobile.png")
    pg.click("#rbBack")
    pg.set_viewport_size({"width": 1366, "height": 900})
    for r in rules():
        post("/api/ruleset/rule/delete", {"site": "", "id": r["id"]})
