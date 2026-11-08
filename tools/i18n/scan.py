#!/usr/bin/env python3
"""i18n coverage scan (Playwright, headless Chromium).

Opens every admin UI page / Security Center tab (and with --snippets every snippet page) with a locale
enabled and lists the *visible* text that is still English, so strings that only exist at runtime
(built in JavaScript) are found too.  Use it to drive coverage:

    PY=$HOME/ui-test-tools/py.sh
    $PY tools/i18n/scan.py --url http://127.0.0.1:28801 --lang zh-CN [--snippets] [--json out.json] [--emit-extra extra.txt]

A text node counts as untranslated English when
  * its normalised text is a key of locales/en.json (the engine had nothing to translate it to), or
  * for non-Latin locales (zh, ja, ru): it contains a run of 3+ Latin letters and no character of the target script.
Brand / protocol names are ignored (see IGNORE).  --emit-extra writes the runtime-only strings (not in en.json
yet) in the format of tools/i18n/extra_keys.txt so extract.py can add them to the catalogue.
Run it against a throw-away instance started with -noauth (tools/ui-smoke/run.sh shows how).
"""
import argparse, json, os, re, sys
from playwright.sync_api import sync_playwright

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ap = argparse.ArgumentParser()
ap.add_argument("--url", default=os.environ.get("ZORAXY_URL", "http://127.0.0.1:8000"))
ap.add_argument("--lang", required=True)
ap.add_argument("--snippets", action="store_true", help="also open every snippet page standalone")
ap.add_argument("--json")
ap.add_argument("--emit-extra")
ap.add_argument("--limit", type=int, default=60, help="lines printed per page")
args = ap.parse_args()

EN = set(json.load(open(os.path.join(ROOT, "src/web/locales/en.json"), encoding="utf-8"))["strings"])
SCRIPT = {"zh-CN": r"[一-鿿]", "zh-TW": r"[一-鿿]", "ja": r"[぀-ヿ一-鿿]", "ru": r"[Ѐ-ӿ]"}
IGNORE = re.compile(r"^(Zoraxy|ACME|TLS|HTTPS?|OIDC|OAuth2?|WAF|CAPTCHA|TCP|UDP|DNS|IP|CIDR|SSO|API|JSON|YAML|Lua|Docker|"
                    r"Cloudflare|Turnstile|reCAPTCHA|Altcha|Friendly Captcha|GeoIP|zrok|Sablier|ECH|mTLS|Prometheus|"
                    r"Let's Encrypt|Authentik|[A-Za-z0-9_.:/\-]+)$")

COLLECT = r"""
() => {
  const out = [];
  const tw = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let n;
  while ((n = tw.nextNode())) {
    const t = n.nodeValue.replace(/\s+/g, ' ').trim();
    if (t.length < 2) continue;
    const p = n.parentElement;
    if (!p || ['SCRIPT', 'STYLE', 'CODE', 'PRE', 'TEXTAREA', 'NOSCRIPT'].includes(p.tagName) || p.closest('[data-i18n-skip],svg')) continue;
    const r = p.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    const cs = getComputedStyle(p);
    if (cs.visibility === 'hidden' || cs.display === 'none') continue;
    out.push(t);
  }
  for (const e of document.querySelectorAll('[placeholder],[title],[aria-label]')) {
    const r = e.getBoundingClientRect();
    if (!r.width || !r.height || e.closest('[data-i18n-skip]')) continue;
    for (const a of ['placeholder', 'title', 'aria-label']) { const v = e.getAttribute(a); if (v && v.trim().length > 1) out.push(v.replace(/\s+/g, ' ').trim()); }
  }
  return out;
}
"""

found = {}  # page -> [text]
runtime_only = set()
script_re = re.compile(SCRIPT.get(args.lang, "(?!)"))


def judge(page, texts):
    seen = set()
    for t in texts:
        if t in seen or IGNORE.match(t):
            continue
        seen.add(t)
        bad = t in EN
        if not bad and args.lang in SCRIPT and re.search(r"[A-Za-z]{3,}", t) and not script_re.search(t):
            bad = True
            runtime_only.add(t)
        if bad:
            found.setdefault(page, []).append(t)


def settle(pg, ms=900):
    pg.wait_for_timeout(ms)
    try:
        pg.wait_for_load_state("networkidle", timeout=5000)
    except Exception:
        pass


with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": 1366, "height": 900})
    ctx.add_init_script("try{localStorage.setItem('zoraxy.lang',%s)}catch(e){}" % json.dumps(args.lang))
    pg = ctx.new_page()
    pg.goto(args.url + "/", wait_until="networkidle")
    pg.wait_for_selector("#mainmenu .item")
    settle(pg, 1500)
    judge("index", pg.evaluate(COLLECT))
    tabs = list(dict.fromkeys(pg.eval_on_selector_all("#mainmenu .item[tag]", "els => els.map(e => e.getAttribute('tag'))")))
    for t in tabs:
        pg.evaluate("t => openTabById(t)", t)
        settle(pg)
        judge(t, pg.evaluate(COLLECT))
        if t == "seccenter":
            for sec in pg.eval_on_selector_all("#secTabs .item", "els => els.map(e => e.getAttribute('data-sec'))"):
                pg.click(f"#secTabs .item[data-sec='{sec}']")
                settle(pg, 1000)
                judge("seccenter/" + sec, pg.evaluate(COLLECT))
    if args.snippets:
        d = os.path.join(ROOT, "src/web/snippet")
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".html"):
                continue
            sp = ctx.new_page()
            try:
                sp.goto(args.url + "/snippet/" + fn, wait_until="networkidle", timeout=15000)
                sp.wait_for_timeout(900)
                judge("snippet/" + fn, sp.evaluate(COLLECT))
            except Exception as e:
                print("snippet", fn, "failed:", str(e)[:80])
            sp.close()
    b.close()

total = 0
for page, items in found.items():
    print(f"== {page}: {len(items)} untranslated")
    for t in items[: args.limit]:
        print("   ", t[:140])
    total += len(items)
print(f"TOTAL untranslated visible strings: {total} on {len(found)} pages")
if args.json:
    json.dump(found, open(args.json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
if args.emit_extra:
    with open(args.emit_extra, "w", encoding="utf-8") as f:
        for t in sorted(runtime_only):
            f.write(t + "\n")
