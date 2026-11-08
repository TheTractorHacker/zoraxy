#!/usr/bin/env python3
"""Zoraxy admin UI audit bot (Playwright, headless Chromium).

Opens every menu page and every sub tab of the admin UI in light and dark theme at a desktop and a phone width and
reports, per page / tab / selector:

  icon         <i class="... icon"> whose ::before/::after draw nothing (icon name missing in the bundled Fomantic/Semantic UI)
  empty-label  buttons / links / menu items without text, aria-label or title
  overflow     elements sticking out of the viewport outside a scroll container, or a horizontally scrolling page
  clipped      text cut off by overflow:hidden (or an ellipsis without a title)
  small-target click targets smaller than 24x24 CSS px
  contrast     text with a WCAG contrast ratio below 4.5:1 (3:1 for large text), sampled
  table-header tables without header cells
  img-alt      images without an alt attribute
  console      console.error / uncaught exceptions
  request      failed requests and HTTP >= 400 answers

and writes a full-page screenshot of every state. Output (outside the repo, give --out):
  audit-report.json   every finding with page, tab, theme, viewport, selector, issue, severity
  audit-report.md     summary by type plus the findings grouped by page
  shots/<viewport>-<theme>/<page>[__<tab>].png

Usage:  audit.py --url http://127.0.0.1:8000 --out DIR [--themes light,dark] [--viewports desktop,mobile]
                 [--pages status,waf] [--lang zh-CN] [--no-shots] [--allow REGEX ...]
Run it against a throw-away instance started with -noauth (see DEVELOPMENT.md, "UI audit bot"). Exit 1 when a finding of
severity "major" or higher exists (use --report-only to always exit 0).
"""
import argparse
import json
import os
import re
import sys
import time
from collections import OrderedDict, defaultdict

from playwright.sync_api import sync_playwright

ap = argparse.ArgumentParser()
ap.add_argument("--url", default=os.environ.get("ZORAXY_URL", "http://127.0.0.1:8000"))
ap.add_argument("--out", required=True, help="output directory (outside the repository)")
ap.add_argument("--themes", default="light,dark")
ap.add_argument("--viewports", default="desktop,mobile")
ap.add_argument("--pages", default="", help="comma separated nav tags to audit (default: all)")
ap.add_argument("--lang", default="", help="UI language code to run the audit in (e.g. zh-CN, de); default English")
ap.add_argument("--no-shots", action="store_true")
ap.add_argument("--allow", action="append", default=[], help="regex of console / request messages to ignore")
ap.add_argument("--report-only", action="store_true", help="exit 0 even when there are major findings")
ap.add_argument("--max-contrast", type=int, default=250, help="text elements sampled per state for the contrast check")
args = ap.parse_args()

VIEWPORTS = {"desktop": {"width": 1366, "height": 900}, "mobile": {"width": 390, "height": 800}}
SEVERITY_ORDER = {"critical": 0, "major": 1, "minor": 2, "info": 3}
allow = [re.compile(a) for a in args.allow] + [
    re.compile(r"favicon"),
    re.compile(r"ERR_(NAME_NOT_RESOLVED|INTERNET_DISCONNECTED|CONNECTION|ABORTED|BLOCKED_BY)"),
]
os.makedirs(args.out, exist_ok=True)

# ----------------------------------------------------------------------------------------------------------------
# in-page checks. Returns a list of {type, severity, selector, detail}
# ----------------------------------------------------------------------------------------------------------------
CHECK_JS = r"""
(opts) => {
  const out = [];
  const seen = new Set();
  const vw = document.documentElement.clientWidth;
  const root = document.querySelector(opts.root) || document.body;
  const isVisible = (el) => {
    if (!el.isConnected) return false;
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return false;
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) {
      const cs = getComputedStyle(e);
      if (cs.display === 'none' || cs.visibility === 'hidden') return false;
      if (parseFloat(cs.opacity) === 0) return false;
    }
    return true;
  };
  const sel = (el) => {
    const parts = [];
    for (let e = el; e && e.nodeType === 1 && parts.length < 4; e = e.parentElement) {
      let s = e.tagName.toLowerCase();
      if (e.id) { s += '#' + e.id; parts.unshift(s); break; }
      const cls = [...e.classList].filter(c => !/^(ui|active|visible|transition|hidden)$/.test(c)).slice(0, 3);
      if (cls.length) s += '.' + cls.join('.');
      const p = e.parentElement;
      if (p) {
        const same = [...p.children].filter(c => c.tagName === e.tagName);
        if (same.length > 1) s += ':nth-of-type(' + (same.indexOf(e) + 1) + ')';
      }
      parts.unshift(s);
    }
    return parts.join(' > ');
  };
  const add = (type, severity, el, detail) => {
    const key = type + '|' + sel(el) + '|' + detail;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({type, severity, selector: sel(el), detail});
  };
  const inScroller = (el) => {
    for (let e = el.parentElement; e && e !== document.body; e = e.parentElement) {
      const o = getComputedStyle(e).overflowX;
      if ((o === 'auto' || o === 'scroll') && e.scrollWidth > e.clientWidth) return true;
      if (o === 'hidden' && e.getBoundingClientRect().right <= vw + 1) return true;
    }
    return false;
  };
  const text = (el) => (el.textContent || '').replace(/\s+/g, ' ').trim();
  const all = [...root.querySelectorAll('*')];
  const vis = new Map();
  const V = (el) => { if (!vis.has(el)) vis.set(el, isVisible(el)); return vis.get(el); };

  /* 1. icons that draw nothing */
  for (const el of root.querySelectorAll('i.icon, i[class*="icon"]')) {
    if (!el.classList.contains('icon')) continue;
    if (el.classList.contains('dropdown') || el.classList.contains('loading')) { /* still checked below */ }
    const b = getComputedStyle(el, '::before'), a = getComputedStyle(el, '::after'), cs = getComputedStyle(el);
    const bad = (c) => !c || c === 'none' || c === 'normal' || c === '""' || c === "''";
    const hasMask = (cs.webkitMaskImage && cs.webkitMaskImage !== 'none') || (cs.maskImage && cs.maskImage !== 'none');
    const hasBg = cs.backgroundImage && cs.backgroundImage !== 'none';
    if (bad(b.content) && bad(a.content) && !hasMask && !hasBg) {
      if (el.querySelector('i') ) continue;                 // composite <i class="icons"> wrapper
      if (el.parentElement && el.parentElement.classList.contains('icons')) continue;
      const names = [...el.classList].filter(c => !['icon','simplistic','ui','small','tiny','mini','large','big','huge','massive','fitted','link','circular','bordered','inverted','loading','disabled','flipped','rotated','left','right','red','orange','yellow','olive','green','teal','blue','violet','purple','pink','brown','grey','black','white'].includes(c));
      add('icon', 'major', el, 'icon class "' + names.join(' ') + '" draws nothing (not in the bundled icon font)' + (V(el) ? '' : ' [hidden element]'));
    }
  }

  /* 2. controls without an accessible name */
  const ctl = 'button, a.button, a.item, [role=button], a[href], input[type=button], input[type=submit], .ui.button';
  for (const el of root.querySelectorAll(ctl)) {
    if (!V(el)) continue;
    if (text(el) || el.getAttribute('aria-label') || el.getAttribute('title') || el.getAttribute('aria-labelledby')) continue;
    if (el.value && /button|submit/.test(el.type)) continue;
    if (el.querySelector('img[alt]:not([alt=""])')) continue;
    add('empty-label', 'major', el, 'visible control without text, aria-label or title: ' + el.outerHTML.slice(0, 100));
  }
  for (const el of root.querySelectorAll('input:not([type=hidden]):not([type=button]):not([type=submit]), select, textarea')) {
    if (!V(el)) continue;
    if (el.getAttribute('aria-label') || el.getAttribute('title') || el.getAttribute('placeholder') || el.getAttribute('aria-labelledby')) continue;
    if (el.id && document.querySelector('label[for="' + CSS.escape(el.id) + '"]')) continue;
    if (el.closest('label') || (el.parentElement && el.parentElement.querySelector('label')) ) continue;
    if (el.closest('.ui.checkbox, .ui.radio, .ui.dropdown, .ui.search')) continue;
    add('empty-label', 'minor', el, 'form field without label, placeholder or aria-label');
  }

  /* 3. overflow */
  const de = document.documentElement;
  if (de.scrollWidth - de.clientWidth > 2) {
    add('overflow', 'major', de, 'page scrolls horizontally by ' + (de.scrollWidth - de.clientWidth) + 'px');
  }
  for (const el of all) {
    if (!V(el)) continue;
    const r = el.getBoundingClientRect();
    if (r.right > vw + 2 && !inScroller(el) && !el.closest('.toolbar, .ui.modal, .ui.dimmer, #messageBox, .editor_side_wrapper')) {
      // only report the outermost offender
      const p = el.parentElement;
      if (p && V(p) && p.getBoundingClientRect().right > vw + 2 && !inScroller(p)) continue;
      add('overflow', 'major', el, 'extends ' + Math.round(r.right - vw) + 'px beyond the viewport (' + Math.round(r.width) + 'px wide)');
    }
  }

  /* 4. clipped text */
  for (const el of all) {
    if (!V(el)) continue;
    const cs = getComputedStyle(el);
    if (el.scrollWidth <= el.clientWidth + 1 || el.clientWidth < 8) continue;
    if (!(cs.overflowX === 'hidden' || cs.overflowX === 'clip')) continue;
    if (cs.display === 'inline') continue;
    const own = [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    if (!own && !el.matches('button, a, .item, .label, td, th')) continue;
    if (el.matches('.ui.dropdown, .ui.dropdown *, .ui.modal, .ui.dimmer, textarea, select, input')) continue;
    if (cs.textOverflow === 'ellipsis') {
      if (!el.getAttribute('title') && !el.closest('[title]')) add('clipped', 'minor', el, 'text truncated with an ellipsis and no title tooltip: "' + text(el).slice(0, 50) + '"');
    } else {
      add('clipped', 'major', el, 'text cut off (content ' + el.scrollWidth + 'px in a ' + el.clientWidth + 'px box): "' + text(el).slice(0, 50) + '"');
    }
  }

  /* 5. small click targets */
  const tgt = 'button, a.button, a.item, input:not([type=hidden]), select, [role=button], i.icon[onclick], i.icon.link, td > a, th > a';
  for (const el of root.querySelectorAll(tgt)) {
    if (!V(el)) continue;
    if (el.matches('input[type=checkbox], input[type=radio]')) {
      // semantic ui hides the real input and draws the box with the label
      const lab = el.closest('.ui.checkbox, .ui.radio');
      if (lab) continue;
    }
    if (el.matches('input[type=file], input[type=color]') ) continue;
    if (el.closest('.ui.dropdown, .ui.search') && !el.matches('.ui.dropdown')) continue;
    const r = el.getBoundingClientRect();
    if (r.width < 24 || r.height < 24) {
      // an inline link inside running text is exempt (WCAG 2.5.8)
      if (el.tagName === 'A' && getComputedStyle(el).display === 'inline' && el.parentElement && text(el.parentElement).length > text(el).length + 10) continue;
      add('small-target', 'minor', el, 'click target ' + Math.round(r.width) + 'x' + Math.round(r.height) + 'px (< 24x24): "' + text(el).slice(0, 30) + '"');
    }
  }

  /* 6. contrast (sampled) */
  const parse = (c) => { const m = c.match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(/[ ,\/]+/).filter(Boolean).map(parseFloat); return {r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1}; };
  const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const over = (top, bot) => { const a = top.a + bot.a * (1 - top.a); if (a === 0) return {r: 0, g: 0, b: 0, a: 0}; return {r: (top.r * top.a + bot.r * bot.a * (1 - top.a)) / a, g: (top.g * top.a + bot.g * bot.a * (1 - top.a)) / a, b: (top.b * top.a + bot.b * bot.a * (1 - top.a)) / a, a}; };
  const bgOf = (el) => {
    const layers = [];
    let skip = false;
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) {
      const cs = getComputedStyle(e);
      if (cs.backgroundImage && cs.backgroundImage !== 'none') { skip = true; break; }
      const c = parse(cs.backgroundColor);
      if (c && c.a > 0) { layers.push(c); if (c.a >= 1) break; }
    }
    if (skip) return null;
    let base = {r: 255, g: 255, b: 255, a: 1};
    if (document.body.classList.contains('darkTheme')) base = {r: 27, g: 28, b: 29, a: 1};
    const bodyBg = parse(getComputedStyle(document.body).backgroundColor);
    if (bodyBg && bodyBg.a > 0) base = bodyBg;
    let acc = base;
    for (let i = layers.length - 1; i >= 0; i--) acc = over(layers[i], acc);
    return acc;
  };
  const opacityOf = (el) => { let o = 1; for (let e = el; e && e.nodeType === 1; e = e.parentElement) o *= parseFloat(getComputedStyle(e).opacity); return o; };
  let sampled = 0;
  const contrastSeen = new Set();
  for (const el of all) {
    if (sampled >= opts.maxContrast) break;
    if (!V(el)) continue;
    if (!([...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim().length > 1))) continue;
    if (el.matches('script, style, option, textarea, input, select') || el.closest('.disabled, [disabled], .ui.disabled')) continue;
    const cs = getComputedStyle(el);
    const fg = parse(cs.color);
    if (!fg) continue;
    const bg = bgOf(el);
    if (!bg) continue;
    const op = opacityOf(el);
    const fgEff = over({r: fg.r, g: fg.g, b: fg.b, a: fg.a * op}, bg);
    const L1 = lum(fgEff), L2 = lum(bg);
    const ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
    const size = parseFloat(cs.fontSize), bold = parseInt(cs.fontWeight, 10) >= 700;
    const large = size >= 24 || (size >= 18.66 && bold);
    const need = large ? 3 : 4.5;
    sampled++;
    if (ratio < need) {
      const k = cs.color + '|' + (bg.r|0) + ',' + (bg.g|0) + ',' + (bg.b|0) + '|' + op;
      if (contrastSeen.has(k + sel(el))) continue;
      contrastSeen.add(k + sel(el));
      add('contrast', ratio < 3 ? 'major' : 'minor', el, 'contrast ' + ratio.toFixed(2) + ':1 (needs ' + need + ':1), color ' + cs.color + (op < 1 ? ' at opacity ' + op.toFixed(2) : '') + ': "' + text(el).slice(0, 40) + '"');
    }
  }

  /* 7. tables without header cells, 8. images without alt */
  for (const t of root.querySelectorAll('table')) {
    if (!V(t)) continue;
    if (!t.querySelector('th')) add('table-header', 'minor', t, 'table has no header cells (<th>)');
  }
  for (const im of root.querySelectorAll('img:not([alt])')) {
    if (V(im)) add('img-alt', 'minor', im, 'image without alt attribute: ' + (im.getAttribute('src') || '').slice(0, 60));
  }
  return out;
}
"""

SUBTAB_JS = r"""
(rootSel) => {
  const root = document.querySelector(rootSel);
  if (!root) return [];
  const sel = 'a.item[data-tab], .item[data-sec], .ui.tabular.menu > .item, .ui.pointing.menu > .item, .ui.secondary.pointing.menu > .item, .ui.top.attached.tabular.menu > .item, .menu .accesscontrol.item';
  const items = [...root.querySelectorAll(sel)].filter(e => e.offsetParent !== null && !e.closest('#mainmenu'));
  return items.map((e, i) => ({idx: i, label: (e.textContent || '').replace(/\s+/g, ' ').trim() || e.getAttribute('data-tab') || e.getAttribute('data-sec') || ('tab' + i)}));
}
"""

findings = []          # list of dicts
ctx_label = {"page": "init", "tab": "", "theme": "", "viewport": ""}


def record(typ, severity, selector, detail):
    findings.append(OrderedDict(page=ctx_label["page"], tab=ctx_label["tab"], theme=ctx_label["theme"],
                                viewport=ctx_label["viewport"], type=typ, severity=severity, selector=selector, detail=detail))


def settle(pg, ms=650):
    pg.wait_for_timeout(ms)
    try:
        pg.wait_for_load_state("networkidle", timeout=4000)
    except Exception:
        pass


def slug(s):
    return re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower() or "x"


def run_checks(pg, root, shot):
    t_chk = time.time()
    try:
        res = pg.evaluate(CHECK_JS, {"root": root, "maxContrast": args.max_contrast})
        if time.time() - t_chk > 3:
            print(f"   slow checks ({time.time() - t_chk:.1f}s): {ctx_label['page']} / {ctx_label['tab']}", flush=True)
    except Exception as ex:
        record("audit", "major", root, "checks crashed: " + str(ex)[:200])
        res = []
    for r in res:
        record(r["type"], r["severity"], r["selector"], r["detail"])
    if shot and not args.no_shots:
        d = os.path.join(args.out, "shots", f"{ctx_label['viewport']}-{ctx_label['theme']}")
        os.makedirs(d, exist_ok=True)
        name = slug(ctx_label["page"]) + (("__" + slug(ctx_label["tab"])) if ctx_label["tab"] else "")
        try:
            pg.screenshot(path=os.path.join(d, name + ".png"), full_page=True)
        except Exception as ex:
            record("audit", "minor", "", "screenshot failed: " + str(ex)[:100])


def audit_page(pg, tag):
    ctx_label["page"] = tag
    ctx_label["tab"] = ""
    pg.evaluate("t => openTabById(t)", tag)
    settle(pg)
    root = "#" + tag
    run_checks(pg, root, True)
    items = pg.evaluate(SUBTAB_JS, root)
    sel = ('a.item[data-tab], .item[data-sec], .ui.tabular.menu > .item, .ui.pointing.menu > .item, '
           '.ui.secondary.pointing.menu > .item, .ui.top.attached.tabular.menu > .item, .menu .accesscontrol.item')
    for it in items:
        ctx_label["tab"] = it["label"][:40]
        try:
            # indexes are computed on visible items only, so look them up the same way
            handle = pg.evaluate_handle("""([rootSel, sel, idx]) => [...document.querySelector(rootSel).querySelectorAll(sel)]
                .filter(e => e.offsetParent !== null && !e.closest('#mainmenu'))[idx]""", [root, sel, it["idx"]])
            el = handle.as_element()
            if el is None:
                continue
            el.scroll_into_view_if_needed(timeout=2000)
            el.click(timeout=3000)
            settle(pg, 800)
            run_checks(pg, root, True)
        except Exception as ex:
            record("audit", "minor", root, f"could not open sub tab '{it['label']}': {str(ex).splitlines()[0][:120]}")
    ctx_label["tab"] = ""


def audit_nav(pg):
    """The menu itself: every icon must exist."""
    ctx_label["page"] = "navigation"
    ctx_label["tab"] = ""
    pg.evaluate("document.querySelectorAll('#mainmenu .menugroup-items').forEach(e => e.style.display='block')")
    run_checks(pg, "#mainmenu", False)


def main():
    t_start = time.time()
    try:
        _run()
    finally:
        write_reports(time.time() - t_start)


def _run():
    pages_filter = [p for p in args.pages.split(",") if p]
    with sync_playwright() as p:
        b = p.chromium.launch()
        for vpname in args.viewports.split(","):
            for theme in args.themes.split(","):
                ctx = b.new_context(viewport=VIEWPORTS[vpname])
                if args.lang:
                    ctx.add_init_script("try{localStorage.setItem('zoraxy.lang',%s)}catch(e){}" % json.dumps(args.lang))
                pg = ctx.new_page()
                ctx_label.update(viewport=vpname, theme=theme, page="init", tab="")

                def on_console(m):
                    if m.type == "error":
                        msg = m.text + " " + m.location.get("url", "")
                        if not any(a.search(msg) for a in allow):
                            record("console", "major", "", msg[:300])

                pg.on("console", on_console)
                pg.on("pageerror", lambda e: record("console", "critical", "", "uncaught: " + str(e)[:300]))

                def on_failed(r):
                    msg = f"{r.url} {r.failure}"
                    if not any(a.search(msg) for a in allow):
                        record("request", "major", "", "failed: " + msg[:300])

                def on_resp(r):
                    if r.status >= 400:
                        msg = f"{r.status} {r.url}"
                        if not any(a.search(msg) for a in allow):
                            record("request", "major", "", "HTTP " + msg[:300])

                pg.on("requestfailed", on_failed)
                pg.on("response", on_resp)
                pg.goto(args.url + "/", wait_until="networkidle")
                pg.wait_for_selector("#mainmenu .item", state="attached")
                is_dark = pg.evaluate("document.body.classList.contains('darkTheme')")
                if (theme == "dark") != is_dark:
                    pg.evaluate("toggleTheme()")
                    pg.wait_for_timeout(300)
                tabs = list(dict.fromkeys(pg.eval_on_selector_all("#mainmenu .item[tag]", "els => els.map(e => e.getAttribute('tag'))")))
                if vpname == "desktop":
                    audit_nav(pg)
                for t in tabs:
                    if pages_filter and t not in pages_filter:
                        continue
                    print(f"[{vpname}/{theme}] {t}", flush=True)
                    try:
                        audit_page(pg, t)
                    except Exception as ex:
                        ctx_label["page"] = t
                        record("audit", "major", "#" + t, "page audit crashed: " + str(ex).splitlines()[0][:200])
                ctx.close()
        b.close()


def write_reports(secs):
    # merge identical findings seen in several themes / viewports
    merged = OrderedDict()
    # look-alikes (same page, tab, type, selector without list positions, detail without numbers / quoted text) collapse to one row
    for f in findings:
        sig_sel = re.sub(r":nth-of-type\(\d+\)", "", f["selector"])
        sig_detail = re.sub(r'"[^"]*"', '""', f["detail"])
        sig_detail = re.sub(r"[0-9.]+(:1|px)", "#", sig_detail)
        key = (f["page"], f["tab"], f["type"], sig_sel, sig_detail)
        m = merged.get(key)
        if m is None:
            m = merged[key] = dict(f, contexts=[], count=0, _seen=set())
        ident = (f["selector"], f["detail"])
        if ident not in m["_seen"]:
            m["_seen"].add(ident)
            m["count"] += 1
        c = f["viewport"] + "/" + f["theme"]
        if c not in m["contexts"]:
            m["contexts"].append(c)
    rows = list(merged.values())
    for r in rows:
        r.pop("theme", None)
        r.pop("viewport", None)
        r.pop("_seen", None)
    rows.sort(key=lambda r: (SEVERITY_ORDER.get(r["severity"], 9), r["type"], r["page"], r["tab"]))
    with open(os.path.join(args.out, "audit-report.json"), "w") as fh:
        json.dump({"url": args.url, "seconds": round(secs), "count": len(rows), "findings": rows}, fh, indent=1)
    by_type = defaultdict(lambda: defaultdict(int))
    for r in rows:
        by_type[r["type"]][r["severity"]] += 1
    lines = ["# Zoraxy UI audit", "", f"Instance: `{args.url}`, {len(rows)} findings, {round(secs)} s.", "",
             "| type | critical | major | minor | total |", "|---|---|---|---|---|"]
    for typ in sorted(by_type):
        d = by_type[typ]
        lines.append(f"| {typ} | {d['critical']} | {d['major']} | {d['minor']} | {sum(d.values())} |")
    lines.append("")
    grouped = OrderedDict()
    for r in rows:
        grouped.setdefault((r["page"], r["tab"]), []).append(r)
    for (page, tab), rs in sorted(grouped.items(), key=lambda kv: kv[0]):
        lines.append(f"## {page}" + (f" / {tab}" if tab else ""))
        for r in rs:
            more = f" [+{r['count'] - 1} similar]" if r["count"] > 1 else ""
            lines.append(f"- **{r['severity']}** `{r['type']}` `{r['selector']}`: {r['detail']}{more} ({', '.join(r['contexts'])})")
        lines.append("")
    with open(os.path.join(args.out, "audit-report.md"), "w") as fh:
        fh.write("\n".join(lines))
    majors = sum(1 for r in rows if SEVERITY_ORDER.get(r["severity"], 9) <= 1)
    print(f"\n{len(rows)} findings ({majors} major or worse). Report: {args.out}/audit-report.md")
    if majors and not args.report_only:
        sys.exit(1)


main()
