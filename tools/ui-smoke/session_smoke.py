#!/usr/bin/env python3
"""Admin session lifetime scenario (Playwright). Needs an instance WITH authentication (see session_run.sh).

Registers a throw-away account through the login page, then checks: default cookie lifetimes (1 hour / 7 days), the settings card
(Security Center > Admin accounts) with validation and the Save bar, a 5 minute setting applied to the next login (cookie
Max-Age) without a restart, and the "Your session expired" banner (shown once, no stream of error toasts) when the session ends
while the page is open. Screenshots light / dark / 390px of the card and the banner go to --out.
Exit code 0 = pass, 1 = failures."""
import argparse
import os
import sys
import time

from playwright.sync_api import sync_playwright

ap = argparse.ArgumentParser()
ap.add_argument("--url", default="http://127.0.0.1:18790")
ap.add_argument("--out", default=os.path.expanduser("~/session-smoke-shots"))
args = ap.parse_args()
os.makedirs(args.out, exist_ok=True)
USER, PW = "smokeadmin", "throwaway-Pass-123"
failures = []


def check(cond, what, detail=""):
    if cond:
        print("ok  ", what)
    else:
        failures.append(f"{what}: {detail}")
        print("FAIL", what, detail)


def session_cookie(ctx):
    for c in ctx.cookies():
        if c["name"] != "zoraxy_csrf" and c["expires"] and c["expires"] > 0:
            return c
    return None


def login(pg, remember=False):
    pg.goto(args.url + "/login.html")
    pg.wait_for_selector("#loginbtn", state="visible", timeout=8000)
    pg.fill("#username", USER)
    pg.fill("#magic", PW)
    if remember:
        pg.click("#rmbme + label")
    pg.click("#loginbtn")
    pg.wait_for_url(lambda u: "login.html" not in u, timeout=8000)


def lifetime(ctx):
    c = session_cookie(ctx)
    return None if c is None else c["expires"] - time.time()


with sync_playwright() as p:
    br = p.chromium.launch()
    errors = []

    # ---- register + default lifetimes
    ctx = br.new_context()
    pg = ctx.new_page()
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.goto(args.url + "/login.html")
    pg.wait_for_selector("#regsiterbtn", state="visible", timeout=8000)
    pg.fill("#username", USER)
    pg.fill("#magic", PW)
    pg.fill("#repeatMagic", PW)
    pg.click("#regsiterbtn")
    pg.wait_for_selector("#loginbtn", state="visible", timeout=8000)
    login(pg)
    l = lifetime(ctx)
    check(l and 3500 < l <= 3601, "default lifetime is 1 hour", f"{l}")
    ctx.clear_cookies()
    login(pg, remember=True)
    l = lifetime(ctx)
    check(l and 7 * 86400 - 100 < l <= 7 * 86400 + 1, "default remember me is 7 days", f"{l}")
    ctx.close()

    # ---- settings card
    for label, vp, dark in (("light", {"width": 1366, "height": 900}, False), ("dark", {"width": 1366, "height": 900}, True), ("mobile", {"width": 390, "height": 844}, False)):
        ctx = br.new_context(viewport=vp)
        pg = ctx.new_page()
        pg.on("pageerror", lambda e: errors.append(str(e)))
        login(pg)
        pg.wait_for_load_state("networkidle")
        if dark and not pg.evaluate("document.body.classList.contains('darkTheme')"):
            pg.evaluate("toggleTheme()")
        pg.evaluate("openTabById('seccenter')")
        pg.click("#secTabs .item[data-sec='users']")
        pg.wait_for_selector("#sesCard:not([hidden])", timeout=8000)
        pg.wait_for_function("document.querySelector('#sesMin').value !== ''")
        vals = pg.evaluate("[$('#sesMin').val(), $('#sesDays').val(), $('#sesSlide').prop('checked')]")
        saved = label != "light"  # the light run changes the settings, the next runs see the saved ones
        check(vals == (["5", "30", True] if saved else ["60", "7", False]), f"{label}: card shows the {'saved values' if saved else 'defaults'}", str(vals))
        now = pg.inner_text("#sesNow")
        check(("5 minutes" in now) if saved else ("1 hour" in now and "7 days" in now), f"{label}: effective values text", now)
        if label == "light":
            # validation: out of range is refused with a message next to the field and nothing is saved
            pg.fill("#sesMin", "3")
            pg.wait_for_selector(".zx-savebar:not([hidden]) [data-zx-save]")
            pg.click(".zx-savebar [data-zx-save]")
            pg.wait_for_function("document.querySelector('#sesMin').closest('.zx-field').classList.contains('is-invalid')", timeout=4000)
            check(True, "light: 3 minutes refused with a field message")
            pg.fill("#sesMin", "5")
            pg.fill("#sesDays", "30")
            pg.check("#sesSlide")
            pg.click(".zx-savebar [data-zx-save]")
            pg.wait_for_function("document.querySelector('#sesNow').textContent.includes('5 minutes')", timeout=6000)
            check(True, "light: saved 5 minutes / 30 days / sliding, effective text updated")
            pg.wait_for_timeout(2600)  # the "Saved" bar fades out
        pg.locator("#sesCard").scroll_into_view_if_needed()
        check(not pg.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth + 1"), f"{label}: no sideways scroll")
        pg.screenshot(path=f"{args.out}/session-card-{label}.png")
        ctx.close()

    # ---- new login uses 5 minutes without restart
    ctx = br.new_context()
    pg = ctx.new_page()
    pg.on("pageerror", lambda e: errors.append(str(e)))
    login(pg)
    l = lifetime(ctx)
    check(l and 250 < l <= 301, "next login lifetime is 5 minutes (no restart)", f"{l}")
    ctx.clear_cookies()
    login(pg, remember=True)
    l = lifetime(ctx)
    check(l and 30 * 86400 - 100 < l <= 30 * 86400 + 1, "remember me is 30 days", f"{l}")

    # ---- session ends while the page is open
    pg.goto(args.url + "/")
    pg.wait_for_load_state("networkidle")
    ctx.clear_cookies()  # what an expired cookie looks like to the server: no session
    for _ in range(3):
        pg.evaluate("() => new Promise(r => $.get('/api/proxy/list').always(r))")
        pg.evaluate("() => new Promise(r => $.get('/components/status.html').always(r))")
    pg.wait_for_selector(".zx-session-banner", timeout=4000)
    n = pg.locator(".zx-session-banner").count()
    check(n == 1, "exactly one session-expired banner after several failing calls", str(n))
    href = pg.get_attribute(".zx-session-banner a", "href")
    check(href == "/login.html", "banner links to the login page", str(href))
    pg.wait_for_timeout(600)
    bad = pg.evaluate("document.body.innerText").count("Request failed")
    check(bad == 0, "no stream of 'Request failed' toasts", str(bad))
    for label, vp, dark in (("light", {"width": 1366, "height": 800}, False), ("dark", {"width": 1366, "height": 800}, True), ("mobile", {"width": 390, "height": 800}, False)):
        pg.set_viewport_size(vp)
        if pg.evaluate("document.body.classList.contains('darkTheme')") != dark:
            pg.evaluate("toggleTheme()")
        pg.wait_for_timeout(300)
        pg.screenshot(path=f"{args.out}/session-expired-{label}.png")
        check(not pg.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth + 1"), f"expired banner {label}: no sideways scroll")
    # the link works: the login page opens, signing in again works
    pg.click(".zx-session-banner a")
    pg.wait_for_url("**/login.html")
    login(pg)
    pg.wait_for_load_state("networkidle")
    n = pg.locator(".zx-session-banner").count()
    check(n == 0, "no banner after signing in again", str(n))
    ctx.close()

    check(not errors, "no JavaScript errors", "; ".join(errors[:3]))
    br.close()

print("FAILURES:", len(failures))
sys.exit(1 if failures else 0)
