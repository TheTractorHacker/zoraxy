#!/usr/bin/env python3
"""Zoraxy data-plane end-to-end runner.

  run.py [--only name[,name...]] [--list] [--results FILE] [--keep-going]

Each scenario starts its own throw-away Zoraxy (own conf/db/ports in a temp dir, ports 28810-28999)
plus local backends, drives it through the admin API (the same calls the UI makes) and sends real
HTTP traffic to the proxy listener. Result per scenario: PASS, FAIL, NOT-TESTABLE (reason printed).
"""
import argparse
import importlib
import json
import os
import pkgutil
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib  # noqa: E402


def load_scenarios():
    pkg = importlib.import_module("scenarios")
    for m in pkgutil.iter_modules(pkg.__path__):
        importlib.import_module("scenarios." + m.name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="comma separated scenario names (prefix match)")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--results", default=os.path.join(lib.HERE, "results.json"))
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args()
    load_scenarios()
    names = sorted(lib.SCENARIOS)
    if args.list:
        for n in names:
            s = lib.SCENARIOS[n]
            print("%-28s issues=%s  %s" % (n, s["issues"], s["doc"].split("\n")[0]))
        return 0
    if args.only:
        want = [w.strip() for w in args.only.split(",") if w.strip()]
        names = [n for n in names if any(n == w or n.startswith(w) for w in want)]
    if not args.no_build:
        print("building zoraxy ...", flush=True)
        lib.build()
    results = []
    counts = {"PASS": 0, "FAIL": 0, "NOT-TESTABLE": 0}
    for n in names:
        s = lib.SCENARIOS[n]
        t0 = time.time()
        try:
            ev = s["fn"]()
            st, msg = "PASS", ev or ""
        except lib.Skip as e:
            st, msg = "NOT-TESTABLE", str(e)
        except Exception as e:  # noqa: BLE001
            st = "FAIL"
            msg = "%s: %s" % (type(e).__name__, e)
            if not isinstance(e, lib.Fail):
                msg += "\n" + traceback.format_exc()[-1500:]
        dt = time.time() - t0
        counts[st] += 1
        print("%-13s %-28s %5.1fs  %s" % (st, n, dt, msg.replace("\n", "\n    ")), flush=True)
        results.append(dict(scenario=n, issues=s["issues"], status=st, evidence=msg, seconds=round(dt, 1)))
    with open(args.results, "w") as f:
        json.dump(results, f, indent=1)
    print("SUMMARY: %d scenarios, PASS=%d FAIL=%d NOT-TESTABLE=%d" % (
        len(results), counts["PASS"], counts["FAIL"], counts["NOT-TESTABLE"]))
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
