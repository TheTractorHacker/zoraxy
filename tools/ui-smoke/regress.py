#!/usr/bin/env python3
"""Targeted UI regression scenarios (Playwright, headless Chromium) with mocked API answers.

Scenarios (each maps to an upstream issue):
  docker-picker-null   #954  "Pick from Docker Containers" crashed with "Cannot read properties of null (reading 'map')"
                              when Docker returned null Ports / a rule without origins
  cert-multi-domain    #611  "Filename cannot be empty for certs containing multiple domains"
  updater-early-access #969  release candidates are labelled early access in the updater

Usage: regress.py [--url http://127.0.0.1:28784]    (run it with tools/ui-smoke/regress.sh)
"""
import argparse
import json
import os
import sys
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright

ap = argparse.ArgumentParser()
ap.add_argument("--url", default=os.environ.get("ZORAXY_URL", "http://127.0.0.1:28784"))
args = ap.parse_args()
failures = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def json_route(pg, pattern, body):
    pg.route(pattern, lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps(body)))


def docker_picker(b):
    pg = b.new_context(viewport={"width": 1200, "height": 900}).new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.add_init_script("window.msgbox = function(m){ window.__msg = m; };")  # the snippet reports errors via parent.msgbox
    container = {
        "Id": "abc123", "Names": ["/web1"], "State": "running", "Labels": None,
        "Ports": None,  # Docker returns null for containers without published ports
        "HostConfig": {"NetworkMode": "bridge"},
        "NetworkSettings": {"Networks": {"bridge": {"NetworkID": "n1", "IPAddress": "172.17.0.5"}}},
    }
    json_route(pg, "**/api/proxy/list?type=host", [{"ActiveOrigins": None}, {"ActiveOrigins": [{"OriginIpOrDomain": "x:80"}]}])
    json_route(pg, "**/api/docker/containers", {"containers": [container]})
    pg.goto(args.url + "/snippet/dockerContainersList.html", wait_until="networkidle")
    pg.wait_for_timeout(800)
    check(not errors and not pg.evaluate("window.__msg"), "docker picker: no error with null Ports / null ActiveOrigins " + str(errors) + str(pg.evaluate("window.__msg")))
    text = pg.inner_text("body")
    check("web1" in text, "docker picker: the container is listed")
    # an empty Docker (containers: null) must not crash either
    errors.clear()
    pg.evaluate("window.__msg = null")
    json_route(pg, "**/api/docker/containers", {"containers": None})
    pg.reload(wait_until="networkidle")
    pg.wait_for_timeout(500)
    check(not errors and not pg.evaluate("window.__msg"), "docker picker: no error when Docker returns containers=null " + str(errors) + str(pg.evaluate("window.__msg")))


def cert_multi_domain(b):
    pg = b.new_context(viewport={"width": 1366, "height": 800}).new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    seen = {}

    def obtain(route):
        seen.update({k: v[0] for k, v in parse_qs(urlparse(route.request.url).query).items()})
        route.fulfill(status=200, content_type="application/json", body='{"error": null}')

    pg.route("**/api/acme/obtainCert*", obtain)
    pg.route("**/api/acme/autoRenew/email", lambda r: r.fulfill(status=200, content_type="application/json", body='"admin@example.com"'))
    pg.goto(args.url + "/", wait_until="networkidle")
    pg.evaluate("openTabById('cert')")
    pg.wait_for_timeout(1500)
    done = pg.evaluate("""() => new Promise(res => {
        obtainCertificate("a.example.com,b.example.com", false, "Let's Encrypt", ok => res(ok));
        setTimeout(() => res('timeout'), 5000); })""")
    check(done is True, f"cert dialog: multi-domain request accepted (callback={done})")
    check(seen.get("filename") == "a.example.com", f"cert dialog: file named after the first domain (got {seen.get('filename')!r})")
    check(seen.get("domains") == "a.example.com,b.example.com", "cert dialog: all domains sent")
    check(not errors, "cert dialog: no JavaScript errors " + str(errors))


def updater_early_access(b):
    pg = b.new_context(viewport={"width": 1366, "height": 800}).new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.goto(args.url + "/", wait_until="networkidle")
    pg.evaluate("openTabById('updater')")
    pg.wait_for_timeout(1500)
    res = {"update_available": True, "asset_name": "zoraxy_linux_amd64", "asset_size": 1000,
           "latest": {"tag": "v3.3.6-rc1.2", "prerelease": False, "early_access": True, "published": "2026-01-01T00:00:00Z", "notes": ""}}
    json_route(pg, "**/api/updater/check*", {"result": res, "preflight": {}})
    pg.evaluate("upCheck(false)")
    pg.wait_for_timeout(800)
    detail = pg.inner_text("#upLatestDetail")
    check("early access" in detail.lower(), f"updater: rc release labelled early access ({detail!r})")
    res["latest"].update({"tag": "v3.3.6.1", "early_access": False})
    json_route(pg, "**/api/updater/check*", {"result": res, "preflight": {}})
    pg.evaluate("upCheck(false)")
    pg.wait_for_timeout(800)
    check("early access" not in pg.inner_text("#upLatestDetail").lower(), "updater: stable release not labelled")
    check(not errors, "updater: no JavaScript errors " + str(errors))


with sync_playwright() as p:
    b = p.chromium.launch()
    for name, fn in (("docker-picker-null", docker_picker), ("cert-multi-domain", cert_multi_domain), ("updater-early-access", updater_early_access)):
        print("scenario", name)
        try:
            fn(b)
        except Exception as e:  # noqa
            check(False, f"{name} raised {e!r}")
    b.close()
print("FAILED" if failures else "PASS")
sys.exit(1 if failures else 0)
