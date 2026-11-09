"""In-app updater against a local fake GitHub Releases server and a THROWAWAY signing key.

The test binary is the product built with `go build -overlay`: only two things differ from the shipped build, the
embedded release public key (replaced by a throwaway one) and the updater source's API base / http permission (to reach
127.0.0.1). The real release key is never read."""
import hashlib, json, os, re, shutil, subprocess, tempfile, threading, http.server
from runner import scenario, NotTestable
import lib
from .common import *

SRC = os.path.join(ROOT, "src")
_ctx = {}


def run(*a, **k):
    return subprocess.run(list(a), check=True, capture_output=True, text=True, **k)


def setup():
    if _ctx:
        return _ctx
    # cached under .build (ignored by VCS): the throwaway key and the two overlay builds survive between runs
    d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".build", "updater")
    os.makedirs(d, exist_ok=True)
    priv, pub = os.path.join(d, "priv.pem"), os.path.join(d, "pub.pem")
    api_port = lib.PORT_MAX  # baked into the test binary; reserved for the fake release server
    lib._ports_used.add(api_port)
    old, new = os.path.join(d, "zoraxy-old"), os.path.join(d, "zoraxy-new")
    if all(os.path.exists(x) for x in (priv, pub, old, new)):
        _ctx.update(dir=d, priv=priv, pub=pub, old=old, new=new, api_port=api_port)
        return _ctx
    for x in (priv, pub, old, new):
        if os.path.exists(x):
            os.remove(x)
    run("go", "run", os.path.join(ROOT, "tools", "sign_release.go"), "-genkey", priv, pub)
    # overlay: replacement pubkey + source.go with local API base and http allowed
    src = open(os.path.join(SRC, "mod", "updater", "source.go")).read()
    src2 = src.replace('const DefaultAPIBase = "https://api.github.com"', f'const DefaultAPIBase = "http://127.0.0.1:{api_port}"')
    src2 = src2.replace('u.Scheme != "https" && !(s.allowHTTP && u.Scheme == "http")', 'u.Scheme != "https" && u.Scheme != "http"')
    check(src2 != src, "overlay patterns did not match source.go")
    ov = {"Replace": {os.path.join(SRC, "mod", "updater", "release_pubkey.pem"): pub,
                      os.path.join(SRC, "mod", "updater", "source.go"): os.path.join(d, "source.go")}}
    open(os.path.join(d, "source.go"), "w").write(src2)
    open(os.path.join(d, "overlay.json"), "w").write(json.dumps(ov))
    env = dict(os.environ, GOTMPDIR=os.path.expanduser("~/.cache/go-tmp"), CGO_ENABLED="0")
    subprocess.run(["go", "build", "-overlay", os.path.join(d, "overlay.json"), "-o", old, "."], cwd=SRC, check=True, env=env, capture_output=True)
    subprocess.run(["go", "build", "-overlay", os.path.join(d, "overlay.json"), "-trimpath", "-ldflags", "-s -w", "-o", new, "."], cwd=SRC, check=True, env=env, capture_output=True)
    _ctx.update(dir=d, priv=priv, pub=pub, old=old, new=new, api_port=api_port)
    return _ctx


def make_release(ctx, tag, build, binary, name, mutate=None, prerelease=False):
    dist = os.path.join(ctx["dir"], "dist-" + name)
    os.makedirs(dist, exist_ok=True)
    shutil.copy(binary, os.path.join(dist, "zoraxy_linux_amd64"))
    os.chmod(os.path.join(dist, "zoraxy_linux_amd64"), 0o755)
    run("go", "run", os.path.join(ROOT, "tools", "sign_release.go"), "-dist", dist, "-key", ctx["priv"], "-pub", ctx["pub"], "-tag", tag, "-build", str(build))
    if mutate:
        mutate(dist)
    return dist


class FakeGH:
    def __init__(self, port):
        self.releases = []   # list of dicts {tag, dist, published}
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path.startswith("/repos/") and "/releases" in self.path:
                    out = []
                    for r in outer.releases:
                        base = f"http://127.0.0.1:{port}/dl/{r['tag']}/"
                        out.append({"tag_name": r["tag"], "name": r["tag"], "body": "e2e", "html_url": "http://x", "draft": False, "prerelease": False,
                                    "published_at": r["published"], "assets": [{"name": n, "size": os.path.getsize(os.path.join(r["dist"], n)), "browser_download_url": base + n}
                                                                              for n in os.listdir(r["dist"])]})
                    b = json.dumps(out).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(b)))
                    self.end_headers()
                    self.wfile.write(b)
                    return
                m = re.match(r"/dl/([^/]+)/(.+)", self.path)
                if m:
                    for r in outer.releases:
                        if r["tag"] == m.group(1) and os.path.exists(os.path.join(r["dist"], m.group(2))):
                            b = open(os.path.join(r["dist"], m.group(2)), "rb").read()
                            self.send_response(200)
                            self.send_header("Content-Length", str(len(b)))
                            self.end_headers()
                            self.wfile.write(b)
                            return
                self.send_response(404)
                self.end_headers()

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def status_wait(c, want, timeout=60):
    def f():
        s = c.get("/api/updater/status")[1]
        return s if isinstance(s, dict) and (s.get("state") in want or s.get("State") in want) else None
    return wait_until(f, timeout, 0.5)


def start_inst(ctx, name):
    d = tempfile.mkdtemp(prefix=f"e2e-{name}-")
    exe = os.path.join(d, "zoraxy")
    shutil.copy(ctx["old"], exe)
    os.chmod(exe, 0o755)
    inst = Instance(name, workdir=d, binary=exe, flags=["-update_repo", "e2e/zoraxy"])
    inst.start()
    return inst, exe


def wait_restart(inst, old_pid_alive=True, timeout=60):
    """in-place exec keeps the PID; wait until the admin API answers again"""
    time.sleep(2)
    return wait_until(lambda: inst.client.get("/api/updater/info")[0] == 200, timeout, 0.5)


@scenario("updater-full-flow", ["110"])
def updater_flow():
    ctx = setup()
    gh = FakeGH(ctx["api_port"])
    inst = None
    try:
        # releases: good (build 100), plus a tampered-binary variant and a downgrade (build 50) published later
        good = make_release(ctx, "v3.3.5-e2e.1", 100, ctx["new"], "good")
        gh.releases = [{"tag": "v3.3.5-e2e.1", "dist": good, "published": "2099-01-01T00:00:00Z"}]
        inst, exe = start_inst(ctx, "upd")
        c = inst.client
        before = sha(exe)
        info = c.get("/api/updater/info")[1]
        check(info.get("preflight") is not None, f"info {str(info)[:200]}")
        chk = c.get("/api/updater/check", force="true")[1]
        check(isinstance(chk, dict) and (chk.get("update_available") or chk.get("UpdateAvailable") or "v3.3.5-e2e.1" in json.dumps(chk)), f"check: {str(chk)[:300]}")
        pid = inst.proc.pid
        st, js = c.post("/api/updater/start", action="app", backup="true", confirm="true")
        check(st in (200, 202) and not (isinstance(js, dict) and js.get("error")), f"start: {st} {js}")
        ok = wait_until(lambda: sha(exe) == sha(ctx["new"]), 60)
        check(ok, f"binary was not swapped; log: {inst.tail(600)}")
        check(os.path.exists(exe + ".prev") and sha(exe + ".prev") == before, "zoraxy.prev is not the previous binary")
        # restart in place, health confirmation clears the marker, history records success
        check(wait_restart(inst), "admin API did not come back after the restart")
        check(inst.proc.poll() is None, "process died")
        gone = wait_until(lambda: not os.path.exists(os.path.join(inst.dir, "conf", "updater", "pending.json")), 30)
        check(gone, "pending marker not cleared (health not confirmed)")
        hist = c.get("/api/updater/history")[1]
        check("success" in json.dumps(hist) and "v3.3.5-e2e.1" in json.dumps(hist), f"history: {json.dumps(hist)[:300]}")
        backups = [f for f in os.listdir(os.path.join(inst.dir, "backups")) if "pre-update" in f] if os.path.isdir(os.path.join(inst.dir, "backups")) else []
        check(backups, "no pre-update backup zip")
        installed = json.load(open(os.path.join(inst.dir, "conf", "updater", "installed.json")))
        check("e2e.1" in json.dumps(installed), f"installed.json: {installed}")
        # same release again: nothing to offer (forward only)
        chk = c.get("/api/updater/check", force="true")[1]
        check("v3.3.5-e2e.1" not in json.dumps({k: v for k, v in chk.items() if "latest" not in k.lower()}) or not (chk.get("update_available") or chk.get("UpdateAvailable")), f"re-offered the installed release: {chk}")
        # downgrade: build 50 signed, later publish date, must be refused
        down = make_release(ctx, "v3.3.5-e2e.2", 50, ctx["new"], "down")
        gh.releases.append({"tag": "v3.3.5-e2e.2", "dist": down, "published": "2099-02-01T00:00:00Z"})
        c.get("/api/updater/check", force="true")
        st, js = c.post("/api/updater/start", action="app", backup="false", confirm="true")
        s = status_wait(c, ("failed", "error", "idle", "done"), 40)
        txt = json.dumps([js, c.get("/api/updater/status")[1], c.get("/api/updater/history")[1]]).lower()
        check(sha(exe) == sha(ctx["new"]) and ("build" in txt or "downgrade" in txt or "replay" in txt or "older" in txt), f"downgrade not refused: {txt[:500]}")
        # explicit rollback to the saved previous binary
        st, js = c.post("/api/updater/rollback", confirm="true")
        check(st in (200, 202) and not (isinstance(js, dict) and js.get("error")), f"rollback: {js}")
        check(wait_until(lambda: sha(exe) == before, 30), "rollback did not restore the previous binary")
        check(wait_restart(inst), "admin API did not come back after rollback")
        return ("local fake GitHub + throwaway ed25519 key (go build -overlay swaps only the embedded pubkey and API base): check offers the signed release, update takes a pre-update backup, "
                "downloads, verifies signature + sha256, swaps (zoraxy.prev kept), restarts via in-place exec (same PID), health confirmation clears the pending marker, history/installed.json updated, "
                "the installed release is not re-offered, a lower-build (downgrade) release is refused, explicit rollback restores the previous binary and restarts")
    finally:
        gh.stop()
        if inst:
            inst.cleanup()
            subprocess.run(["pkill", "-f", inst.dir], check=False)


@scenario("updater-tampered-and-unsigned-refused", ["110"])
def updater_tamper():
    ctx = setup()
    gh = FakeGH(ctx["api_port"])
    inst = None
    try:
        def tamper_bin(dist):
            with open(os.path.join(dist, "zoraxy_linux_amd64"), "ab") as f:
                f.write(b"\0tampered")

        def tamper_sums(dist):
            p = os.path.join(dist, "SHA256SUMS")
            t = open(p).read().replace("e2e.5", "e2e.5")  # same text...
            open(p, "w").write(t + "# extra\n")

        def wrong_sig(dist):
            b = bytearray(open(os.path.join(dist, "SHA256SUMS.sig"), "rb").read())
            b[0] ^= 0xFF
            open(os.path.join(dist, "SHA256SUMS.sig"), "wb").write(bytes(b))
        d1 = make_release(ctx, "v3.3.5-e2e.5", 300, ctx["new"], "t-bin", tamper_bin)
        d2 = make_release(ctx, "v3.3.5-e2e.6", 301, ctx["new"], "t-sums", tamper_sums)
        d3 = make_release(ctx, "v3.3.5-e2e.7", 302, ctx["new"], "t-sig", wrong_sig)
        inst, exe = start_inst(ctx, "updt")
        c = inst.client
        before = sha(exe)
        for tag, dist, pub in (("v3.3.5-e2e.5", d1, "2099-01-01T00:00:00Z"), ("v3.3.5-e2e.6", d2, "2099-01-02T00:00:00Z"), ("v3.3.5-e2e.7", d3, "2099-01-03T00:00:00Z")):
            gh.releases = [{"tag": tag, "dist": dist, "published": pub}]
            c.get("/api/updater/check", force="true")
            st, js = c.post("/api/updater/start", action="app", backup="false", confirm="true")
            time.sleep(4)
            wait_until(lambda: (c.get("/api/updater/status")[1] or {}).get("state") not in ("running", "downloading"), 30)
            check(sha(exe) == before, f"{tag}: binary changed although release was tampered")
            check(not os.path.exists(os.path.join(inst.dir, "conf", "updater", "pending.json")), f"{tag}: pending marker left")
            hist = json.dumps([js, c.get("/api/updater/status")[1], c.get("/api/updater/history")[1]]).lower()
            check("signature" in hist or "sha" in hist or "mismatch" in hist or "verif" in hist or "failed" in hist or "error" in hist, f"{tag}: no failure recorded: {hist[:300]}")
        return "tampered binary (sha mismatch), tampered SHA256SUMS and corrupted signature each refused; running binary untouched, no pending marker, failure recorded"
    finally:
        gh.stop()
        if inst:
            inst.cleanup()


@scenario("updater-bad-release-auto-rollback", ["110"])
def updater_autorollback():
    ctx = setup()
    gh = FakeGH(ctx["api_port"])
    inst = None
    try:
        bad = os.path.join(ctx["dir"], "zoraxy-bad")
        # passes the `-version` smoke test and the upstream version check, then exits immediately
        open(bad, "w").write('#!/bin/sh\nif [ "$1" = "-version" ]; then echo "Zoraxy - Version 3.3.5"; exit 0; fi\nexit 1\n')
        os.chmod(bad, 0o755)
        rel = make_release(ctx, "v3.3.5-e2e.9", 900, bad, "bad")
        gh.releases = [{"tag": "v3.3.5-e2e.9", "dist": rel, "published": "2099-03-01T00:00:00Z"}]
        inst, exe = start_inst(ctx, "updb")
        c = inst.client
        before = sha(exe)
        c.get("/api/updater/check", force="true")
        st, js = c.post("/api/updater/start", action="app", backup="false", confirm="true")
        check(st in (200, 202) and not (isinstance(js, dict) and js.get("error")), f"start {js}")
        check(wait_until(lambda: sha(exe) == sha(bad), 60), "bad release was not installed")
        # the process is now a script that exits; the watchdog (old binary) rolls back after deadline + grace
        restored = wait_until(lambda: sha(exe) == before, 200, 2)
        check(restored, f"no automatic rollback within 200s; watchdog log: {open(os.path.join(inst.dir, 'conf', 'updater', 'watchdog.log')).read()[-300:] if os.path.exists(os.path.join(inst.dir, 'conf', 'updater', 'watchdog.log')) else 'none'}")
        up = wait_until(lambda: c.get("/api/updater/info")[0] == 200, 60, 1)
        check(up, "restored binary was not started again")
        hist = json.dumps(c.get("/api/updater/history")[1])
        check("auto_rollback" in hist, f"history lacks auto_rollback: {hist[:300]}")
        return "release whose binary passes -version but exits at start: installed, then the out-of-process watchdog restored the previous binary after the 90s deadline + grace, restarted it, history records auto_rollback"
    finally:
        gh.stop()
        if inst:
            inst.cleanup()
            subprocess.run(["pkill", "-f", inst.dir], check=False)
