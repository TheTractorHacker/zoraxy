#!/usr/bin/env python3
"""Zoraxy admin UI performance probe (Playwright + CDP, headless Chromium).

Seeds a THROW-AWAY instance with realistic data (many proxy rules, a few hundred
proxied requests) and then measures, for every menu page:

  * main-thread busy time over an idle window (TaskDuration, % of one core)
  * long tasks (> 50 ms) via PerformanceObserver, JS heap growth, DOM node count
  * layout / style recalculations (Performance.getMetrics)
  * timers per second (setInterval/setTimeout callbacks that actually ran)
  * network requests per 10 s (polling), requestAnimationFrame callbacks per second
and for typical interactions the click-to-next-paint latency, plus the frame rate
while dragging the traffic diagram.

Usage:
  perf.py --spawn ./zoraxy --web ../../src/web --port 28781 [--json out.json]   # start a scratch instance itself
  perf.py --url http://127.0.0.1:28781 --proxy-port 28782                        # use one you started (-noauth -dev)

Only run it against a scratch instance (-noauth -dev with temp -conf/-dbpath): it
creates ~30 proxy rules and changes the inbound proxy port / TLS setting.
"""
import argparse
import http.server
import json
import math
import os
import shutil
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

from playwright.sync_api import sync_playwright

ap = argparse.ArgumentParser()
ap.add_argument("--url", default="http://127.0.0.1:28781")
ap.add_argument("--proxy-port", type=int, default=0, help="inbound proxy port of the scratch instance (0 = pick a free one)")
ap.add_argument("--upstream-port", type=int, default=0, help="port of the fake upstream (0 = pick a free one)")
ap.add_argument("--rules", type=int, default=30)
ap.add_argument("--requests", type=int, default=600)
ap.add_argument("--idle", type=float, default=5.0, help="idle measurement window per page (s)")
ap.add_argument("--json", help="write the raw result to this file")
ap.add_argument("--spawn", help="zoraxy binary to start as a scratch instance")
ap.add_argument("--web", help="web dir for --spawn (symlinked next to the binary)")
ap.add_argument("--port", type=int, default=28781, help="management port for --spawn")
ap.add_argument("--only", help="comma separated page tags to measure")
ap.add_argument("--no-seed", action="store_true")
ap.add_argument("--prep", help="JavaScript evaluated in the page before measuring (experiments, e.g. disabling a suspect)")
ap.add_argument("--profile", type=float, default=0, help="also CPU-profile the page named by --only for this many seconds and print the hottest functions")
args = ap.parse_args()


def free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


args.proxy_port = args.proxy_port or free_port()
args.upstream_port = args.upstream_port or free_port()

INIT = r"""
(() => {
  if (window.__perfInit) return; window.__perfInit = true;
  window.__lt = []; window.__timers = 0; window.__raf = 0;
  try { new PerformanceObserver(l => { for (const e of l.getEntries()) window.__lt.push(Math.round(e.duration)); })
        .observe({entryTypes: ['longtask']}); } catch (e) {}
  const si = window.setInterval, st = window.setTimeout, raf = window.requestAnimationFrame;
  window.setInterval = function (f, ms, ...a) {
    if (typeof f !== 'function') return si(f, ms, ...a);
    return si(function () { window.__timers++; return f.apply(this, arguments); }, ms, ...a); };
  window.setTimeout = function (f, ms, ...a) {
    if (typeof f !== 'function') return st(f, ms, ...a);
    return st(function () { window.__timers++; return f.apply(this, arguments); }, ms, ...a); };
  window.requestAnimationFrame = function (f) {
    return raf(function (t) { window.__raf++; return f(t); }); };
})();
"""


class Upstream(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok " + self.path.encode()[:50]
        self.send_response(500 if "err" in self.path else 200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def log_message(self, *a):
        pass


def start_upstream():
    class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
    S.handle_error = lambda self, request, client_address: None  # clients hang up mid-response, ignore
    srv = S(("127.0.0.1", args.upstream_port), Upstream)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def cdp_metrics(cdp):
    return {m["name"]: m["value"] for m in cdp.send("Performance.getMetrics")["metrics"]}


def collect(pg):
    """sum the page-level counters over all frames (the diagram lives in an iframe)"""
    tot = {"timers": 0, "raf": 0, "lt": []}
    for fr in pg.frames:
        try:
            r = fr.evaluate("({t: window.__timers|0, r: window.__raf|0, l: (window.__lt||[]).slice()})")
            tot["timers"] += r["t"]
            tot["raf"] += r["r"]
            tot["lt"] += r["l"]
        except Exception:
            pass
    return tot


def reset_counters(pg):
    for fr in pg.frames:
        try:
            fr.evaluate("window.__timers = 0; window.__raf = 0; window.__lt = []")
        except Exception:
            pass


def measure_idle(pg, cdp, window_s):
    reqs = []

    def on_req(r):
        if r.resource_type in ("xhr", "fetch", "document", "script", "stylesheet"):
            reqs.append(r.url)

    pg.on("request", on_req)
    reset_counters(pg)
    a = cdp_metrics(cdp)
    t0 = time.time()
    pg.wait_for_timeout(int(window_s * 1000))
    dt = time.time() - t0
    b = cdp_metrics(cdp)
    c = collect(pg)
    pg.remove_listener("request", on_req)

    def d(k):
        return b.get(k, 0) - a.get(k, 0)

    return {
        # ThreadTime = CPU time of the main thread (immune to the machine being busy); TaskDuration is wall time
        "busy_pct": round(100 * (d("ThreadTime") if "ThreadTime" in b else d("TaskDuration")) / dt, 2),
        "wall_pct": round(100 * d("TaskDuration") / dt, 2),
        "script_pct": round(100 * d("ScriptDuration") / dt, 2),
        "layout_per_s": round(d("LayoutCount") / dt, 2),
        "style_per_s": round(d("RecalcStyleCount") / dt, 2),
        "heap_growth_kb": round(d("JSHeapUsedSize") / 1024),
        "heap_mb": round(b.get("JSHeapUsedSize", 0) / 1048576, 1),
        "dom_nodes": int(b.get("Nodes", 0)),
        "timers_per_s": round(c["timers"] / dt, 1),
        "raf_per_s": round(c["raf"] / dt, 1),
        "req_per_10s": round(len(reqs) * 10 / dt, 1),
        "longtasks": len(c["lt"]),
        "longest_ms": max(c["lt"]) if c["lt"] else 0,
        "polled": sorted({u.split("?")[0].replace(args.url, "") for u in reqs})[:12],
    }


def cpu_profile(pg, cdp, tab, seconds):
    """sample the JS of the whole renderer for `seconds` while the tab is idle; print self time per function"""
    pg.evaluate("t => openTabById(t)", tab)
    pg.wait_for_timeout(1500)
    cdp.send("Profiler.enable")
    cdp.send("Profiler.setSamplingInterval", {"interval": 500})
    cdp.send("Profiler.start")
    pg.wait_for_timeout(int(seconds * 1000))
    prof = cdp.send("Profiler.stop")["profile"]
    nodes = {n["id"]: n for n in prof["nodes"]}
    selft = {}
    for nid, dt in zip(prof["samples"], prof["timeDeltas"]):
        cf = nodes[nid]["callFrame"]
        key = f"{cf['functionName'] or '(anon)'} {cf['url'].split('/')[-1]}:{cf['lineNumber'] + 1}"
        selft[key] = selft.get(key, 0) + dt
    total = sum(selft.values()) or 1
    print(f"CPU profile of '{tab}' over {seconds}s (self time, ms):")
    for k, v in sorted(selft.items(), key=lambda kv: -kv[1])[:18]:
        if k.startswith("(idle)"):
            continue
        print(f"  {v / 1000:8.1f}  {k}")
    return selft


def latency(pg, js, arg=None):
    """run `js` (clicks something) and return ms until two animation frames have painted"""
    return pg.evaluate("""async ([js, arg]) => {
        const t0 = performance.now();
        await (new Function('arg', 'return (async () => {' + js + '})()'))(arg);
        await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
        return Math.round(performance.now() - t0); }""", [js, arg])


def seed(pg):
    print("seeding ...")

    def cj(url, data):
        return pg.evaluate(
            """([u, d]) => new Promise(res => $.cjax({url: u, method: 'POST', data: d,
                success: r => res(r), error: e => res({error: e.status})}))""", [url, data])

    print(" tls off:", cj("/api/cert/tls", {"set": "false"}))
    for i in range(args.rules):
        cj("/api/proxy/add", {"type": "host", "rootname": f"site{i:02d}.perf.test", "ep": f"127.0.0.1:{args.upstream_port}",
                              "tls": "false", "tlsval": "false", "bypassGlobalTLS": "false"})
    print(" setIncoming:", cj("/api/proxy/setIncoming", {"incoming": str(args.proxy_port)}))
    pg.wait_for_timeout(1500)
    print(" enable:", cj("/api/proxy/enable", {"enable": "true"}))
    pg.wait_for_timeout(1000)
    # behave like a proxy behind Cloudflare: trust the local peer, so CF-Connecting-IP / X-Forwarded-For are honoured
    cj("/api/trustedproxy/add", {"ip": "127.0.0.1", "desc": "perf seed"})
    cj("/api/whitelist/trustProxy", {"enable": "true"})
    paths = ["/", "/index.html", "/api/items", "/api/items/42", "/static/app.js", "/login", "/err/x", "/health", "/a/b/c/d"]
    pool = [f"{a}.{b}.{c}.{d}" for a, b, c, d in
            [(8, 8, 8, 8), (1, 1, 1, 1), (81, 2, 69, 142), (217, 160, 0, 1), (202, 108, 22, 5), (200, 221, 11, 100), (91, 198, 174, 192),
             (45, 33, 32, 156), (185, 199, 108, 153), (151, 101, 1, 69), (104, 18, 12, 1), (13, 107, 21, 200), (176, 9, 12, 59)]]
    pool += [f"203.0.113.{i}" for i in range(1, 60)] + [f"198.51.100.{i}" for i in range(1, 40)]
    ok = 0
    for i in range(args.requests):
        host = f"site{i % args.rules:02d}.perf.test"
        hdr = {"Host": host, "User-Agent": ["Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0", "curl/8.4.0", "Googlebot/2.1", "Mozilla/5.0 (iPhone) Safari/604.1"][i % 4]}
        ip = pool[(i * 7) % len(pool)]
        if i % 5 == 0:
            hdr["X-Forwarded-For"] = ip
        elif i % 5 != 4:
            hdr["CF-Connecting-IP"] = ip
        req = urllib.request.Request(f"http://127.0.0.1:{args.proxy_port}{paths[i % len(paths)]}", headers=hdr)
        try:
            urllib.request.urlopen(req, timeout=3).read()
            ok += 1
        except urllib.error.HTTPError:
            ok += 1
        except Exception:
            pass
    print(f" sent {args.requests} proxied requests ({ok} answered)")
    pg.wait_for_timeout(1500)


def measure_drag(pg, cdp, box):
    cx, cy = box["x"] + box["w"] / 2, box["y"] + box["h"] / 2
    frames = [f for f in pg.frames]
    for f in frames:
        try:
            f.evaluate("window.__frames = 0; (function loop(){ window.__frames++; requestAnimationFrame(loop) })()")
        except Exception:
            pass
    pg.mouse.move(cx, cy)
    pg.mouse.down()
    a = cdp_metrics(cdp)
    t0 = time.time()
    steps = 0
    while time.time() - t0 < 3:
        steps += 1
        ang = steps / 10.0
        pg.mouse.move(cx + 120 * math.cos(ang), cy + 80 * math.sin(ang))
    dt = time.time() - t0
    pg.mouse.up()
    b = cdp_metrics(cdp)
    fps = pg.evaluate("window.__frames") / dt
    key = "ThreadTime" if "ThreadTime" in b else "TaskDuration"
    return {"fps": round(fps, 1), "busy_pct": round(100 * (b[key] - a[key]) / dt, 1), "mouse_events": steps}


def main():
    proc = None
    tmp = None
    if args.spawn:
        tmp = tempfile.mkdtemp(prefix="zoraxy-perf-")
        os.symlink(os.path.abspath(args.web), os.path.join(tmp, "web"))
        proc = subprocess.Popen([os.path.abspath(args.spawn), "-noauth", "-dev", "-port", f":{args.port}", "-conf", "./conf", "-dbpath", "./sys.db"],
                                cwd=tmp, stdout=open(os.path.join(tmp, "z.log"), "w"), stderr=subprocess.STDOUT)
        args.url = f"http://127.0.0.1:{args.port}"
        for _ in range(60):
            try:
                urllib.request.urlopen(args.url + "/", timeout=1)
                break
            except Exception:
                time.sleep(0.5)
    start_upstream()
    results = {"pages": {}, "interactions": {}}
    try:
        with sync_playwright() as p:
            b = p.chromium.launch()
            ctx = b.new_context(viewport={"width": 1366, "height": 800})
            ctx.add_init_script(INIT)
            pg = ctx.new_page()
            errs = []
            pg.on("pageerror", lambda e: errs.append(str(e)))
            pg.goto(args.url + "/", wait_until="networkidle")
            pg.wait_for_selector("#mainmenu .item")
            if not args.no_seed:
                seed(pg)
                pg.reload(wait_until="networkidle")
                pg.wait_for_selector("#mainmenu .item")
            cdp = ctx.new_cdp_session(pg)
            cdp.send("Performance.enable")
            tabs = list(dict.fromkeys(pg.eval_on_selector_all("#mainmenu .item[tag]", "els => els.map(e => e.getAttribute('tag'))")))
            if args.only:
                tabs = [t for t in tabs if t in args.only.split(",")]
            if args.prep:
                pg.evaluate(args.prep)
            pg.wait_for_timeout(2000)
            if args.profile and tabs:
                cpu_profile(pg, cdp, tabs[0], args.profile)
                return
            print(f"{'page':14}{'busy%':>7}{'script%':>8}{'lay/s':>7}{'sty/s':>7}{'tmr/s':>7}{'raf/s':>7}{'req/10s':>8}{'LT':>4}{'maxLT':>6}{'heapKB':>8}{'nodes':>7}")
            for t in tabs:
                pg.evaluate("t => openTabById(t)", t)
                pg.wait_for_timeout(1200)
                r = measure_idle(pg, cdp, args.idle)
                results["pages"][t] = r
                print(f"{t:14}{r['busy_pct']:7}{r['script_pct']:8}{r['layout_per_s']:7}{r['style_per_s']:7}{r['timers_per_s']:7}{r['raf_per_s']:7}{r['req_per_10s']:8}{r['longtasks']:4}{r['longest_ms']:6}{r['heap_growth_kb']:8}{r['dom_nodes']:7}")

            print("interactions (click -> second paint, ms)")
            inter = results["interactions"]
            for t in tabs:
                inter["open:" + t] = latency(pg, "openTabById(arg)", t)
            pg.evaluate("openTabById('httprp')")
            pg.wait_for_timeout(1500)
            inter["menu-group-toggle"] = latency(pg, "document.querySelector('#mainmenu .menugroup-header').click()")
            inter["menu-group-toggle-back"] = latency(pg, "document.querySelector('#mainmenu .menugroup-header').click()")
            inter["menu-filter-type"] = latency(pg, "const i=document.getElementById('navFilterInput'); i.value='cert'; i.dispatchEvent(new Event('input',{bubbles:true}))")
            latency(pg, "const i=document.getElementById('navFilterInput'); i.value=''; i.dispatchEvent(new Event('input',{bubbles:true}))")
            # the helper below resolves when all ajax calls started by the click finished and two frames painted
            settle_js = "await new Promise(r => { let n = 0; const t = setInterval(() => { if (jQuery.active === 0 && ++n > 2) { clearInterval(t); r(); } }, 16); });"
            inter["rule-list-reload (to settled)"] = latency(pg, "listProxyEndpoints();" + settle_js)
            inter["editor-open (to settled)"] = latency(pg, "const b=document.querySelector('#httpProxyList .editBtn, #httpProxyList [onclick*=editEndpoint]'); if(b) b.click();" + settle_js)
            inter["editor-close"] = latency(pg, "const c=document.querySelector('#httprpEditDarkenLayer'); if(c) c.click();")
            for k, v in inter.items():
                print(f"  {k:28}{v:6}")

            pg.evaluate("openTabById('status')")
            pg.wait_for_timeout(2500)
            box = pg.evaluate("(() => { const r = document.getElementById('trafficFlowDiagram'); if (!r) return null; const b = r.getBoundingClientRect(); return {x:b.x,y:b.y,w:b.width,h:b.height}; })()")
            if box:
                results["drag"] = measure_drag(pg, cdp, box)
                print("diagram drag:", results["drag"])
            results["errors"] = errs[:10]
            b.close()
    finally:
        if proc:
            proc.terminate()
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=1)
    worst = max((r["busy_pct"] for r in results["pages"].values()), default=0)
    print(f"worst idle busy% = {worst}")


main()
