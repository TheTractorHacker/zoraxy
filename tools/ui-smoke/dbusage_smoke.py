"""Smoke scenario of the Database card (System > Settings). exec()'d by smoke.py (namespace: fail, current, args, os, re, settle,
check_horizontal); run alone with --db-usage-only.

Checks, against the REAL instance: the card shows, the numbers match GET /api/system/dbusage, tables are sorted by size, the known
tables have their one-line explanation, the compaction help names the exact commands with the absolute database path, and the card
only reads (the endpoint refuses POST). Then, with the endpoint answered by a mock (so a 250 MB file, an unknown table, a table that
was not counted and a 403 can be shown without such a file): the large-file hint, the truncated note, the viewer case (card hidden).
Layout checks (no horizontal overflow, nothing leaves the card, no two tiles overlap) at 1366px and 390px. Screenshots (light, dark,
390px) are written to --out as dbusage-*.png."""

import json


def dbusage_ui(pg, ctx):
    out = lambda n: os.path.join(args.out, n)

    def theme(want_dark):
        if pg.evaluate("document.body.classList.contains('darkTheme')") != want_dark:
            pg.evaluate("toggleTheme()")
            pg.wait_for_timeout(300)

    def layout(label):
        """nothing overflows the page or its card, tiles and table cells do not overlap"""
        check_horizontal(pg, label)
        bad = pg.evaluate("""() => {
            const card = document.getElementById('dbUsageCard'), cr = card.getBoundingClientRect(), msgs = [];
            const inside = (el, name) => { const r = el.getBoundingClientRect(); if (r.width && (r.left < cr.left - 1 || r.right > cr.right + 1)) msgs.push(name + ' leaves the card: ' + Math.round(r.left) + '..' + Math.round(r.right) + ' vs ' + Math.round(cr.left) + '..' + Math.round(cr.right)); };
            card.querySelectorAll('.zx-stat, .zx-callout, table, pre, .zx-table-wrap, .zx-card__head > *').forEach(el => { if (el.offsetParent !== null) inside(el, el.className || el.tagName); });
            const tiles = [...card.querySelectorAll('.db-stats .zx-stat')].filter(e => e.offsetParent !== null).map(e => e.getBoundingClientRect());
            for (let i = 0; i < tiles.length; i++) for (let j = i + 1; j < tiles.length; j++) {
                const a = tiles[i], b = tiles[j];
                if (a.left < b.right - 1 && b.left < a.right - 1 && a.top < b.bottom - 1 && b.top < a.bottom - 1) msgs.push('stat tiles ' + i + ' and ' + j + ' overlap');
            }
            // a cell's text must not run into the next cell (desktop table layout)
            card.querySelectorAll('tbody tr').forEach(tr => {
                const cells = [...tr.children].filter(c => c.offsetParent !== null);
                for (let i = 0; i + 1 < cells.length; i++) {
                    const a = cells[i].getBoundingClientRect(), b = cells[i + 1].getBoundingClientRect();
                    if (a.top === b.top && a.right > b.left + 1) msgs.push('table cells overlap in ' + tr.children[0].innerText.slice(0, 20));
                }
            });
            return msgs;
        }""")
        for m in bad:
            fail("layout", f"{label}: {m}")

    def shots(name, sel="#dbUsageCard"):
        for label, dark, w in (("light", False, 1366), ("dark", True, 1366), ("390", False, 390)):
            theme(dark)
            pg.set_viewport_size({"width": w, "height": 900 if w > 500 else 1100})
            pg.wait_for_timeout(400)
            pg.locator(sel).scroll_into_view_if_needed()
            layout(f"{name}/{label}")
            pg.locator(sel).screenshot(path=out(f"dbusage-{name}-{label}.png"))
        theme(False)
        pg.set_viewport_size({"width": 1366, "height": 900})

    # ---- the real instance ----
    current["page"] = "dbusage/real"
    theme(False)
    pg.set_viewport_size({"width": 1366, "height": 900})
    pg.evaluate("openTabById('settings')")
    settle(pg, 900)
    pg.wait_for_selector("#dbUsageCard:not([hidden]) #dbUsageMain:not([hidden])", timeout=8000)
    allow.append(re.compile(r"(405|403).*api/system/dbusage"))  # the refusals this scenario provokes on purpose
    pg.click("#dbUsageRefresh")  # re-read, so the rows and the API answer are from the same moment
    pg.wait_for_timeout(600)
    api = pg.evaluate("fetch('/api/system/dbusage').then(r => r.json())")
    if not api.get("supported") or api.get("backend") != "BoltDB" or not api.get("usage"):
        fail("dbusage", f"unexpected API answer {api}")
        return
    u = api["usage"]
    names = [t["name"] for t in u["tables"]]
    sizes = [t["bytes"] for t in u["tables"]]
    if sizes != sorted(sizes, reverse=True):
        fail("dbusage", f"tables are not sorted by size: {list(zip(names, sizes))}")
    for must in ("settings", "auth"):
        if must not in names:
            fail("dbusage", f"table {must!r} missing from {names}")
    rows = pg.eval_on_selector_all("#dbTables tr", "els => els.map(e => e.textContent)")
    if len(rows) != len(names):
        fail("dbusage", f"{len(rows)} rows for {len(names)} tables")
    shown = pg.eval_on_selector_all("#dbTables tr:not([hidden])", "els => els.length")
    if len(names) > 8 and (shown != 8 or not pg.is_visible("#dbMore")):
        fail("dbusage", f"{shown} rows shown of {len(names)}, the 'show all' button must appear (visible={pg.is_visible('#dbMore')})")
    if len(names) > 8:
        pg.click("#dbMore")
        if pg.eval_on_selector_all("#dbTables tr:not([hidden])", "els => els.length") != len(names):
            fail("dbusage", "'Show all' did not show every table")
        shots("real-all")
        pg.click("#dbMore")
    if not any("auth" in r and "Admin accounts" in r for r in rows):
        fail("dbusage", f"the auth row lacks its explanation: {rows}")
    if not re.search(r"\d", pg.inner_text("#dbStatFile")):
        fail("dbusage", "file size tile empty")
    cmd = pg.text_content("#dbCompactCmd")
    if "sudo systemctl stop zoraxy" not in cmd or ("-compact-db -dbpath " + api["path"]) not in cmd or not api["path"].startswith("/"):
        fail("dbusage", f"compaction commands wrong: {cmd!r}")
    if pg.is_visible("#dbLargeHint"):
        fail("dbusage", "the large-file hint shows for a tiny database")
    r = pg.evaluate("fetch('/api/system/dbusage', {method: 'POST', headers: {'X-CSRF-Token': document.querySelector('meta[name=\"zoraxy.csrf.Token\"]').content}}).then(r => r.status)")
    if r not in (403, 405):
        fail("dbusage", f"POST to the read only endpoint answered {r}")
    pg.locator("#dbCompactHelp summary").click()
    shots("real")

    # ---- mocked answers ----
    state = {"body": None, "status": 200}

    def handler(route):
        route.fulfill(status=state["status"], content_type="application/json", body=json.dumps(state["body"]) if state["body"] is not None else "forbidden")

    pg.route("**/api/system/dbusage*", handler)
    MB = 1 << 20
    state["body"] = {
        "supported": True, "backend": "BoltDB", "path": "/opt/zoraxy/config/some/very/long/path/to/the/database/folder/sys.db", "largeBytes": 200 * MB,
        "usage": {
            "backend": "BoltDB", "path": "sys.db", "fileBytes": 856 * MB, "pageSize": 4096, "freePages": 90000, "pendingPages": 10, "freeBytes": 351 * MB,
            "freelistBytes": 1000, "totalTables": 7, "payloadBytes": 500 * MB, "truncated": True, "elapsedMs": 5001,
            "tables": [
                {"name": "stats", "keys": 1234, "nestedBuckets": 0, "bytes": 497 * MB, "truncated": True},
                {"name": "oauth2_sessions", "keys": 5000, "nestedBuckets": 0, "bytes": 2 * MB},
                {"name": "auth", "keys": 12, "nestedBuckets": 0, "bytes": 3000},
                {"name": "settings", "keys": 40, "nestedBuckets": 0, "bytes": 900},
                {"name": "plugin_made_up_table_with_a_rather_long_name_for_wrapping", "keys": 3, "nestedBuckets": 1, "bytes": 120},
                {"name": "acme", "keys": 0, "nestedBuckets": 0, "bytes": 0, "truncated": True},
                {"name": "zorxauth_gateway_sessions", "keys": 0, "nestedBuckets": 0, "bytes": 0, "truncated": True},
            ]}}
    current["page"] = "dbusage/large"
    pg.click("#dbUsageRefresh")
    pg.wait_for_selector("#dbLargeHint:not([hidden])", timeout=5000)
    if not pg.is_visible("#dbTruncated"):
        fail("dbusage", "the truncated note is missing")
    if not pg.evaluate("document.getElementById('dbCompactHelp').open"):
        fail("dbusage", "the compaction help should be open for a large file")
    hint = pg.inner_text("#dbLargeHint")
    if "never shrinks" not in hint or "offline" not in hint:
        fail("dbusage", f"large file hint: {hint!r}")
    txt = pg.inner_text("#dbTables")
    for want in ("497 MB+", "not counted", "Not a table Zoraxy knows"):
        if want not in txt:
            fail("dbusage", f"table text lacks {want!r}: {txt!r}")
    cmd = pg.text_content("#dbCompactCmd")
    if "/opt/zoraxy/config/some/very/long/path/to/the/database/folder/sys.db" not in cmd:
        fail("dbusage", f"commands should use the reported path: {cmd!r}")
    shots("large")

    current["page"] = "dbusage/viewer"
    state["status"], state["body"] = 403, None
    pg.click("#dbUsageRefresh")
    pg.wait_for_function("document.getElementById('dbUsageCard').hidden === true", timeout=5000)

    current["page"] = "dbusage/other-backend"
    state["status"], state["body"] = 200, {"supported": False, "backend": "LevelDB", "path": "/x/sys.db", "largeBytes": 200 * MB}
    pg.evaluate("document.getElementById('dbUsageCard').hidden = false")
    pg.click("#dbUsageRefresh")
    pg.wait_for_selector("#dbUsageError:not([hidden])", timeout=5000)
    if "LevelDB" not in pg.inner_text("#dbUsageErrorText"):
        fail("dbusage", "other backend message should name the backend")
    shots("otherbackend")
    pg.unroute("**/api/system/dbusage*")
    print("dbusage scenario done")
