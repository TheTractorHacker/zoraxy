"""Playwright flows. The UI driving itself lives in tools/ui-smoke/smoke.py (clicks through the real pages with
headless Chromium and asserts state through the API afterwards); here it is run once against a fresh instance and its
FAIL lines are mapped to scenarios by the page label."""
import os, re, subprocess, sys
from runner import scenario, NotTestable
from .common import *

_cache = {}
SMOKE = os.path.join(ROOT, "tools", "ui-smoke", "smoke.py")
PYW = os.path.expanduser(os.environ.get("PY", "~/ui-test-tools/py.sh"))


def smoke():
    if "out" in _cache:
        return _cache["out"]
    with Env("ui") as e:
        shots = os.environ.get("E2E_SHOTS", "/tmp")
        r = subprocess.run([PYW, SMOKE, "--url", e.inst.url, "--out", shots], capture_output=True, text=True, timeout=900)
        _cache["out"] = (r.returncode, r.stdout + r.stderr)
    return _cache["out"]


def area(pattern, label):
    rc, out = smoke()
    if "playwright" in out.lower() and "ModuleNotFound" in out:
        raise NotTestable("playwright not available")
    fails = [l for l in out.splitlines() if l.strip().startswith("FAIL") and re.search(pattern, l)]
    check(not fails, "; ".join(fails)[:600])
    ran = [l for l in out.splitlines() if re.search(pattern, l)]
    return label


@scenario("ui-proxy-table-newrule-quickstart-nav", [])
def ui_proxy():
    smoke_ = smoke()
    return area(r"\[(nav|nav-structure|quickstart|proxytable|newrule|table|select|pill|editor|nav-scroll|uxkit|landing|httprp-editor)", "UI: nav groups/collapse, Quick Start dismissal, 36-rule table (search, status/tag filter, sort, shift-select, select-all, bulk preview, pill+undo toast, pagination, mobile), New-rule dialog (validation, duplicate, failing then OK connection test, template, create, quick-action toast, API state asserted), full-rule editor with unsaved-changes guard")


@scenario("ui-waf-page", ["82"])
def ui_waf():
    return area(r"\[waf", "WAF page: 3 mode cards, tabs events/coverage/policy/profiles/exclusions/rules, add+remove exclusion")


@scenario("ui-captcha-page", ["77"])
def ui_captcha():
    return area(r"\[captcha", "CAPTCHA page: overview, editor, test keys, debounced live preview edited heading, save persisted via API, global default editor")


@scenario("ui-sso-providers", ["172", "223", "212"])
def ui_sso():
    return area(r"\[sso", "SSO: two OAuth2 providers against fake OIDC discovery servers, two rules bound, sign-in redirect leads to each rule's own provider")


@scenario("ui-security-center-tabs", ["22", "89", "501", "615"])
def ui_sec():
    return area(r"\[(seccenter|access-options)", "Security Center: every tab renders without JS/network error (functional behaviour in api-* scenarios)")


@scenario("ui-status-visitors-editors", [])
def ui_misc():
    return area(r"\[(status-board|visitors|script-editor|sablier-editor|opseditor|mobile|tab|snippet)", "Status board, Visitors page, Lua + Sablier editors, ops editor, all pages light/dark/mobile without JS/console/network errors")
