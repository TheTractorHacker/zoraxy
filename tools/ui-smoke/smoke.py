#!/usr/bin/env python3
"""Zoraxy admin UI smoke test (Playwright, headless Chromium).

Opens every menu page of the admin UI (light and dark theme), fails on
JavaScript errors, console errors, failed or 4xx/5xx requests and pages whose
component did not load, takes a screenshot per page, and checks that the left
navigation scrolls on its own (mouse wheel over the nav must scroll the nav,
not the page) on a short desktop viewport and on a phone-sized viewport.

Usage:  smoke.py [--url http://127.0.0.1:8000] [--out DIR] [--allow REGEX ...]
Run it against a throw-away instance started with -noauth (see run.sh).
Exit code 0 = pass, 1 = failures.
"""
import argparse
import os
import re
import sys

from playwright.sync_api import sync_playwright

ap = argparse.ArgumentParser()
ap.add_argument("--url", default=os.environ.get("ZORAXY_URL", "http://127.0.0.1:8000"))
ap.add_argument("--out", default=os.environ.get("SMOKE_OUT", os.path.expanduser("~/ui-smoke-shots")))
ap.add_argument("--allow", action="append", default=[], help="regex of messages whose failure is tolerated")
args = ap.parse_args()
os.makedirs(args.out, exist_ok=True)

# Offline-tolerant: external fetches (plugin store, update check, ...) may fail in a sandbox.
allow = [re.compile(a) for a in args.allow] + [
    re.compile(r"favicon"),
    re.compile(r"ERR_(NAME_NOT_RESOLVED|INTERNET_DISCONNECTED|CONNECTION)"),
]
failures = []
current = {"page": "init"}


def fail(kind, msg):
    s = f"[{current['page']}] {kind}: {msg}"
    if any(a.search(s) for a in allow):
        print("  (tolerated) " + s)
        return
    if s not in failures:
        failures.append(s)
        print("  FAIL " + s)


def settle(pg, ms=700):
    pg.wait_for_timeout(ms)
    try:
        pg.wait_for_load_state("networkidle", timeout=5000)
    except Exception:
        pass


def hoverpoint(pg, sel="#mainmenu"):
    return pg.evaluate("""sel => { const r = document.querySelector(sel).getBoundingClientRect();
        const top = Math.max(r.top, 60), bot = Math.min(r.bottom, innerHeight);
        return {x: r.left + Math.min(r.width, 200) / 2, y: (top + bot) / 2} }""", sel)


def check_horizontal(pg, label):
    ov = pg.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    if ov > 2:
        fail("layout", f"{label}: page overflows horizontally by {ov}px")


def main():
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context(viewport={"width": 1366, "height": 800})
        pg = ctx.new_page()
        pg.on("pageerror", lambda e: fail("pageerror", str(e) + " @ " + " | ".join((e.stack or "").splitlines()[1:3])))
        pg.on("console", lambda m: m.type == "error" and fail("console.error", m.text + " " + m.location.get("url", "")))
        pg.on("requestfailed", lambda r: fail("requestfailed", f"{r.url} {r.failure}"))
        pg.on("response", lambda r: r.status >= 400 and fail("http", f"{r.status} {r.url}"))
        pg.goto(args.url + "/", wait_until="networkidle")
        pg.wait_for_selector("#mainmenu .item")

        tabs = pg.eval_on_selector_all("#mainmenu .item[tag]", "els => els.map(e => e.getAttribute('tag'))")
        tabs = list(dict.fromkeys(tabs))
        print(f"{len(tabs)} tabs: {tabs}")
        for theme in ("light", "dark"):
            is_dark = pg.evaluate("document.body.classList.contains('darkTheme')")
            if (theme == "dark") != is_dark:
                pg.evaluate("toggleTheme()")
            for t in tabs:
                current["page"] = f"{t}/{theme}"
                print("page", current["page"])
                pg.evaluate("t => openTabById(t)", t)
                settle(pg)
                vis = pg.evaluate("""t => { const e = document.getElementById(t); if (!e) return 'missing';
                    return (e.offsetParent !== null ? 'visible' : 'hidden') + ':' + e.innerText.trim().length }""", t)
                if vis.startswith("missing") or vis.startswith("hidden"):
                    fail("tab", f"container #{t} is {vis}")
                elif vis.endswith(":0"):
                    fail("tab", f"container #{t} is empty (component not loaded?)")
                check_horizontal(pg, "desktop")
                pg.screenshot(path=os.path.join(args.out, f"{t}-{theme}.png"))

        # ---- nav scroll behaviour at a short viewport ----
        current["page"] = "nav-scroll"
        if pg.evaluate("document.body.classList.contains('darkTheme')"):
            pg.evaluate("toggleTheme()")
        pg.set_viewport_size({"width": 1366, "height": 420})
        pg.evaluate("openTabById('httprp')")  # a long page, so the page itself can scroll too
        settle(pg)
        pg.evaluate("document.querySelectorAll('#mainmenu .menugroup-items').forEach(e => e.style.display='block')")
        info = pg.evaluate("""() => { const n = document.querySelector('.toolbar'); const r = n.getBoundingClientRect();
            return {sh: n.scrollHeight, ch: n.clientHeight, bottom: r.bottom, ih: innerHeight,
                    pageScrollable: document.documentElement.scrollHeight > innerHeight} }""")
        print("nav metrics", info)
        if info["sh"] <= info["ch"]:
            fail("nav", "nav is not taller than its box, cannot scroll (box not limited to the viewport?)")
        if info["bottom"] > info["ih"] + 1:
            fail("nav", f"nav box extends below the viewport ({info['bottom']} > {info['ih']})")
        if not info["pageScrollable"]:
            fail("nav", "test precondition: page is not scrollable")
        pt = hoverpoint(pg, ".toolbar")
        pg.mouse.move(pt["x"], pt["y"])
        before = pg.evaluate("[document.querySelector('.toolbar').scrollTop, window.scrollY]")
        pg.mouse.wheel(0, 300)
        pg.wait_for_timeout(500)
        after = pg.evaluate("[document.querySelector('.toolbar').scrollTop, window.scrollY]")
        print("nav scrollTop/page scrollY before", before, "after", after)
        if after[0] <= before[0]:
            fail("nav", "mouse wheel over the nav did not scroll the nav")
        if after[1] != before[1]:
            fail("nav", "mouse wheel over the nav scrolled the page")
        for _ in range(15):  # past the end of the nav: must not chain into the page
            pg.mouse.wheel(0, 600)
            pg.wait_for_timeout(30)
        pg.wait_for_timeout(400)
        if pg.evaluate("window.scrollY") != before[1]:
            fail("nav", "scroll chaining: page scrolled once the nav hit its end")
        pg.screenshot(path=os.path.join(args.out, "nav-scrolled-short.png"))

        # ---- narrow / mobile layout ----
        current["page"] = "mobile"
        pg.set_viewport_size({"width": 390, "height": 700})
        pg.reload(wait_until="networkidle")
        pg.wait_for_timeout(600)
        pg.screenshot(path=os.path.join(args.out, "mobile-closed.png"))
        pg.click("#sidemenuBtn")
        pg.wait_for_timeout(600)
        pg.evaluate("document.querySelectorAll('#mainmenu .menugroup-items').forEach(e => e.style.display='block')")
        m = pg.evaluate("""() => { const n = document.querySelector('.toolbar'); const r = n.getBoundingClientRect();
            return {sh: n.scrollHeight, ch: n.clientHeight, bottom: r.bottom, ih: innerHeight, shown: r.width > 0} }""")
        print("mobile nav metrics", m)
        if not m["shown"]:
            fail("mobile-nav", "drawer did not open")
        if m["bottom"] > m["ih"] + 1:
            fail("mobile-nav", f"drawer extends below viewport ({m['bottom']} > {m['ih']})")
        pt = hoverpoint(pg, ".toolbar")
        pg.mouse.move(pt["x"], pt["y"])
        y0 = pg.evaluate("window.scrollY")
        pg.mouse.wheel(0, 400)
        pg.wait_for_timeout(500)
        s = pg.evaluate("[document.querySelector('.toolbar').scrollTop, window.scrollY]")
        if s[0] <= 0 or s[1] != y0:
            fail("mobile-nav", f"drawer wheel scroll wrong: nav scrollTop {s[0]}, page scrollY {s[1]}")
        pg.screenshot(path=os.path.join(args.out, "mobile-open.png"))
        for t in tabs:
            current["page"] = f"mobile/{t}"
            pg.evaluate("t => openTabById(t)", t)
            settle(pg, 500)
            check_horizontal(pg, "mobile")
            pg.screenshot(path=os.path.join(args.out, f"mobile-{t}.png"))
        b.close()


main()
print()
if failures:
    print(f"{len(failures)} FAILURE(S)")
    sys.exit(1)
print("OK, screenshots in", args.out)
