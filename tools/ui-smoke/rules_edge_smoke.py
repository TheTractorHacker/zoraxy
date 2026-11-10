"""Failure and edge cases of the Security rules page: model rules (operator matrix, NOT folding, ip.is_private with "is not",
Ignore case), a second admin session changing rules underneath (stale update, stale enable, reorder after another session added a
rule), enforcing confirmation on an edited rule, and a failed first load of the engine metadata that must recover.
Called from rules_smoke.rules_ui: rules_edge(pg, h, post, rules, valid, savebar_click)."""
import re


def rules_edge(pg, h, post, rules, valid, savebar_click):
    fail, settle = h["fail"], h["settle"]
    # the refused requests below are the point of the test
    mine = [re.compile(r"ruleset/rule/(reorder|disable|update)"), re.compile(r"ruleset/meta|ERR_FAILED")]
    h["allow"].extend(mine)

    # ---- model (no DOM): the same code the editor uses ----
    res = pg.evaluate("""async () => {
        const M = RBModel, meta = await (await fetch('./api/ruleset/meta')).json();
        M.setMeta(meta);
        const mk = (f, o) => Object.assign({kind: 'cond', id: 'x', not: false, field: f, key: '', lower: false, op: 'eq', value: '', items: [], ref: '', useRef: false}, o);
        const a = mk('http.path', {op: 'contains', value: 'a'}), b = mk('http.method', {value: 'GET'});
        a.not = true;
        const root = M.newGroup('and', [a, b]);
        return {
            neTrue: M.condSentence(mk('ip.is_private', {op: 'ne', value: 'true'})),
            neFalse: M.condSentence(mk('ip.is_private', {op: 'ne', value: 'false'})),
            eqTrue: M.condSentence(mk('ip.is_private', {op: 'eq', value: 'true'})),
            eqFalse: M.condSentence(mk('ip.is_private', {op: 'eq', value: 'false'})),
            regexLower: M.toTree(mk('http.path', {op: 'matches', value: '^/Admin', lower: true})),
            countryLower: M.toTree(mk('ip.country', {op: 'in', items: ['DE'], lower: true})),
            plainLower: M.toTree(mk('http.path', {op: 'contains', value: 'Foo', lower: true})),
            privOps: M.opsFor(meta, 'ip.is_private'),
            pathOps: M.opsFor(meta, 'http.path'),
            notFirst: M.byPath(root, 'children[0].children[0]') === a,
            second: M.byPath(root, 'children[1]') === b,
            rootHit: M.byPath(root, '') === root,
            folded: M.toTree(root).children[0].type
        };
    }""")
    if "not on a private" not in res["neTrue"] or "not on a private" not in res["eqFalse"]:
        fail("rules-edge", f"ip.is_private sentence ignores the operator: {res}")
    if "not on a private" in res["neFalse"] or "not on a private" in res["eqTrue"]:
        fail("rules-edge", f"ip.is_private sentence wrong for the positive case: {res}")
    if "transform" in res["regexLower"] or "transform" in res["countryLower"] or res["countryLower"]["value"] != ["DE"]:
        fail("rules-edge", f"Ignore case must not apply to regexes or country codes: {res}")
    if res["plainLower"].get("transform") != "lower" or res["plainLower"]["value"] != "foo":
        fail("rules-edge", f"Ignore case on a plain string comparison broke: {res}")
    if "ne" not in res["privOps"] or "eq" not in res["privOps"] or "matches" not in res["pathOps"] or "matches" in res["privOps"]:
        fail("rules-edge", f"operator matrix wrong: {res}")
    if not (res["notFirst"] and res["second"] and res["rootHit"] and res["folded"] == "not"):
        fail("rules-edge", f"byPath / NOT folding wrong: {res}")

    for r in rules():
        post("/api/ruleset/rule/delete", {"site": "", "id": r["id"]})
    base = {"enabled": True, "dry_run": False, "action": {"type": "block", "status": 403}}
    ids = {}
    for n, p in (("A", "/zz"), ("B", "/yy")):
        ids[n] = post("/api/ruleset/rule/create", {"site": "", "rule": dict(base, name="Rule " + n, expression='http.path starts_with "%s"' % p)})["id"]

    def update(n, name):
        return post("/api/ruleset/rule/update", {"site": "", "id": ids[n], "rule": dict(base, name=name, expression='http.path starts_with "/zz"')})

    def server_rule(n):
        return [r for r in rules() if r["id"] == ids[n]][0]

    pg.click("#rbTabs .zx-tab[data-zx-panel=rbPanelRules]")
    pg.evaluate("RB.refresh()")
    pg.wait_for_selector("#rbList tr[data-id]")

    # ---- reorder after another session added a rule: error, then the list reloads and the next move works ----
    ids["C"] = post("/api/ruleset/rule/create", {"site": "", "rule": dict(base, name="Rule C", expression='http.path starts_with "/xx"')})["id"]
    pg.locator("#rbList tr[data-id] [data-act=down]").first.click()
    pg.wait_for_function("document.querySelectorAll('#rbList tr[data-id]').length === 3", timeout=8000)
    pg.locator("#rbList tr[data-id] [data-act=down]").first.click()
    pg.wait_for_function("(() => { const t = document.querySelector('#rbLive'); return t && t.textContent.indexOf('moved to position') >= 0; })()", timeout=8000)
    if [r["name"] for r in rules()][1] != "Rule A":
        fail("rules-edge", "the move after the reload must reach the server")

    # ---- stale enable: another session changed the rule; the switch reverts and the list reloads ----
    update("A", "Rule A2")
    pg.evaluate("id => document.querySelector('#rbList tr[data-id=\"' + id + '\"] [data-act=enable]').click()", ids["A"])
    pg.wait_for_function("id => document.querySelector('#rbList tr[data-id=\"' + id + '\"]').textContent.indexOf('Rule A2') >= 0", arg=ids["A"], timeout=8000)
    if not server_rule("A")["enabled"]:
        fail("rules-edge", "a stale disable must be refused, the rule must stay enabled")
    if not pg.evaluate("id => document.querySelector('#rbList tr[data-id=\"' + id + '\"] [data-act=enable]').checked", ids["A"]):
        fail("rules-edge", "after a refused disable the switch must show the real state")

    # ---- stale save: a second session edited the rule after the editor was opened ----
    pg.locator("#rbList tr[data-id=\"%s\"] button[data-act=edit]" % ids["A"]).click()
    pg.wait_for_selector("#rbEditor .rb-group")
    valid()
    update("A", "Rule A by other")
    pg.locator("#rbEditor input.zx-input").first.fill("Rule A mine")
    savebar_click()
    pg.wait_for_function("document.querySelector('#rbEditor').textContent.indexOf('changed in another session') >= 0", timeout=8000)
    if server_rule("A")["name"] != "Rule A by other":
        fail("rules-edge", "a stale save must not overwrite the newer rule")
    pg.click("#rbBack")
    pg.click(".zx-dialog .zx-btn--danger")
    pg.wait_for_selector("#rbList", state="visible")

    # ---- an edited enforcing rule is confirmed before it is saved ----
    pg.locator("#rbList tr[data-id=\"%s\"] button[data-act=edit]" % ids["A"]).click()
    pg.wait_for_selector("#rbEditor .rb-group")
    valid()
    pg.locator("#rbEditor .rb-row").nth(0).locator(".rb-val input").fill("/")
    valid()
    savebar_click()
    pg.wait_for_selector(".zx-dialog", timeout=10000)
    pg.click(".zx-dialog .zx-dialog__foot .zx-btn--secondary")
    settle(pg, 300)
    if server_rule("A")["expression"] != 'http.path starts_with "/zz"':
        fail("rules-edge", "declining the enforce confirmation must not save the change")
    pg.click("#rbBack")
    pg.click(".zx-dialog .zx-btn--danger")
    pg.wait_for_selector("#rbList", state="visible")

    # ---- a failed first load of the metadata recovers on Refresh ----
    pg.route("**/api/ruleset/meta*", lambda route: route.abort())
    pg.reload()
    pg.wait_for_function("typeof openTabById === 'function' && typeof RB !== 'undefined'", timeout=15000)
    pg.evaluate("openTabById('ruleset')")
    pg.wait_for_function("document.body.textContent.indexOf('Request failed') >= 0", timeout=8000)
    pg.unroute("**/api/ruleset/meta*")
    pg.click("#rbRefresh")
    pg.wait_for_selector("#rbList tr[data-id]", timeout=10000)
    pg.click("#rbNew")
    pg.wait_for_selector("#rbEditor .rb-group", timeout=8000)
    pg.click("#rbBack")
    pg.click(".zx-dialog .zx-btn--danger")
    pg.wait_for_selector("#rbList", state="visible")

    for r in rules():
        post("/api/ruleset/rule/delete", {"site": "", "id": r["id"]})
    for m in mine:
        h["allow"].remove(m)
