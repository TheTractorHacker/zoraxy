#!/usr/bin/env python3
"""Admin end-to-end runner.  run.sh --only name[,name]  /  --list
Each scenario lives in scenarios/*.py and is registered with @scenario(name, issues). It returns an evidence
string, or raises lib.Check (FAIL) / NotTestable.  Results go to docs/verification/e2e-admin.json (+ .md)."""
import argparse, importlib, json, os, pkgutil, sys, time, traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import lib  # noqa: E402

REG = []


class NotTestable(Exception):
    pass


def scenario(name, issues=(), rerun=None):
    def deco(fn):
        REG.append({"name": name, "issues": list(issues), "fn": fn, "rerun": rerun or f"tools/e2e-admin/run.sh --only {name}"})
        return fn
    return deco


def load():
    sys.modules["runner"] = sys.modules[__name__]
    import scenarios
    for m in pkgutil.iter_modules(scenarios.__path__):
        importlib.import_module("scenarios." + m.name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--out", default=os.path.join(HERE, "..", "..", "docs", "verification", "e2e-admin.run.json"))
    ap.add_argument("--shots", default=os.path.expanduser("~/ui-test-tools/shots-e2e2"))
    a = ap.parse_args()
    os.environ["E2E_SHOTS"] = a.shots
    os.makedirs(a.shots, exist_ok=True)
    load()
    if a.list:
        for s in REG:
            print(s["name"], s["issues"])
        return 0
    only = [x for x in a.only.split(",") if x]
    res = []
    for s in REG:
        if only and not any(s["name"] == o or s["name"].startswith(o) for o in only):
            continue
        t = time.time()
        try:
            ev = s["fn"]()
            st = "PASS"
        except NotTestable as e:
            st, ev = "NOT-TESTABLE", str(e)
        except lib.Check as e:
            st, ev = "FAIL", str(e)
        except Exception as e:
            st, ev = "FAIL", "exception: " + "".join(traceback.format_exception_only(type(e), e)).strip() + " | " + traceback.format_exc()[-600:]
        print(f"[{st}] {s['name']} ({time.time() - t:.1f}s): {ev}"[:600], flush=True)
        res.append({"scenario": s["name"], "issues": s["issues"], "status": st, "evidence": f"{ev} (rerun: {s['rerun']})", "commits": [], "notes": ""})
    lib.kill_all()
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1)
    cnt = {}
    for r in res:
        cnt[r["status"]] = cnt.get(r["status"], 0) + 1
    print("SUMMARY", cnt)
    return 1 if cnt.get("FAIL") else 0


if __name__ == "__main__":
    sys.exit(main())
