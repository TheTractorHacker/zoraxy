#!/usr/bin/env python3
"""Control inventory of the proxy rule editor.

Reads the OLD editor markup (the 11-tab httprp.html, e.g. from `git show origin/dev~N:...` or any saved copy, see
docs/ux/site-editor.md) and lists every control of it (input, select, textarea, button, iframe and the back link) with a CSS
selector, its old tab and a label.  The result is the checked-in `siteeditor_inventory.json`; smoke.py (--site-editor-only,
part of the full run) opens the new editor and checks that every selector still exists exactly once in it and that its
card is reachable from the section navigation.

  siteeditor_inventory.py OLD_HTTPRP_HTML  > siteeditor_inventory.raw.json     (selectors + old tab)
  siteeditor_inventory.py --fill http://127.0.0.1:PORT siteeditor_inventory.raw.json > siteeditor_inventory.json
        (opens the new editor in a browser and records the section / card each selector lives in; also prints
         the mapping table of docs/ux/site-editor.md with --markdown)
"""
import json
import re
import sys
from html.parser import HTMLParser

GENERIC = {"ui", "small", "mini", "tiny", "basic", "button", "icon", "green", "red", "blue", "yellow", "orange", "purple", "teal",
           "fluid", "compact", "labeled", "right", "left", "action", "circular", "floated", "selection", "dropdown", "checkbox",
           "toggle", "input", "form", "fields", "field", "radio", "disabled", "buttons", "two", "three", "search", "grey"}
VOID = {"input", "br", "img", "hr", "meta", "link", "col"}
CONTROLS = {"input", "select", "textarea", "button", "iframe"}


class Parse(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []  # (tag, attrs)
        self.items = []
        self.last_label = ""
        self.collect = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag not in VOID:
            self.stack.append((tag, a))
        if tag in CONTROLS or (tag == "a" and "editor_back_button" in a.get("class", "")):
            self.items.append({"tag": tag, "attrs": a, "anc": [x for x in self.stack[:-1] if True] if tag not in VOID else list(self.stack), "label": self.last_label})
        if tag == "label":
            self.collect = []

    def handle_endtag(self, tag):
        if tag == "label" and self.collect is not None:
            self.last_label = re.sub(r"\s+", " ", "".join(self.collect)).strip()
            self.collect = None
        if tag in VOID:
            return
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, d):
        if self.collect is not None:
            self.collect.append(d)


def tokens(cls):
    return [c for c in (cls or "").split() if c not in GENERIC]


def selector(it):
    t, a = it["tag"], it["attrs"]
    if a.get("id"):
        return "#" + a["id"]
    if a.get("data-cp"):
        s = '%s[data-cp="%s"]' % (t, a["data-cp"])
        return s
    if t == "iframe":  # the embedded sub editors: scoped by the old tab name, which the cards keep as rpcfg
        tab = old_tab(it)
        return ".editor_side_wrapper iframe.wrapper_frame" if tab == "sidewrapper" else '[rpcfg="%s"] iframe.wrapper_frame' % tab
    toks = tokens(a.get("class"))
    attr = ""
    if a.get("data-page"):
        attr += '[data-page="%s"]' % a["data-page"]
    if t == "input" and a.get("type") == "radio":
        return 'input[name="%s"][value="%s"]' % (a.get("name"), a.get("value"))
    if toks:
        if t == "select" and "dropdown" in (a.get("class") or "").split():
            t = ""  # Fomantic turns it into a div.ui.dropdown that carries the classes
        return t + "." + ".".join(toks) + attr
    if a.get("name"):
        return '%s[name="%s"]' % (t, a["name"]) + attr
    # nothing distinguishing: scope it by the closest ancestor with a specific class
    for tg, aa in reversed(it["anc"]):
        tk = tokens(aa.get("class"))
        if tk:
            return "." + ".".join(tk) + " " + t
    return t


def old_tab(it):
    for tg, aa in reversed(it["anc"]):
        if "rpcfg" in aa:
            return aa["rpcfg"]
        if "editor_side_wrapper" in aa.get("class", ""):
            return "sidewrapper"
    return "menu"


def main():
    if sys.argv[1] == "--fill":
        return fill(sys.argv[2], sys.argv[3], "--markdown" in sys.argv)
    src = open(sys.argv[1], encoding="utf-8").read()
    a = src.index('id="httprpEditModalWrapper"')
    b = src.index("<script>", a)
    p = Parse()
    p.feed(src[a:b])
    out, seen = [], {}
    for it in p.items:
        sel = selector(it)
        lab = it["label"] if it["tag"] in ("input", "select", "textarea") else ""
        a_ = it["attrs"]
        txt = a_.get("aria-label") or a_.get("title") or a_.get("placeholder") or lab or a_.get("name") or ""
        key = (sel, old_tab(it))
        if sel.endswith(" input") and key in seen:
            continue
        seen[key] = 1
        out.append({"selector": sel, "tag": it["tag"], "oldTab": old_tab(it), "label": txt[:80]})
    json.dump(out, sys.stdout, indent=1, ensure_ascii=False)


def fill(url, raw, markdown):
    from playwright.sync_api import sync_playwright
    entries = json.load(open(raw, encoding="utf-8"))
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1366, "height": 850})
        pg.goto(url + "/", wait_until="networkidle")
        pg.wait_for_selector("#mainmenu .item")
        pg.evaluate("openTabById('httprp')")
        pg.wait_for_selector("#httprpEditModal", state="attached")
        res = pg.evaluate("""(sels) => sels.map(s => { const els = document.querySelectorAll('#httprpEditModal ' + s);
            const e = els[0]; const sec = e && e.closest('[data-hrp-sec]'); const card = e && e.closest('[data-hrp-card]');
            return {count: els.length, section: sec ? sec.getAttribute('data-hrp-sec') : '', card: card ? card.getAttribute('data-hrp-card') : ''}; })""",
                          [e["selector"] for e in entries])
        b.close()
    for e, r in zip(entries, res):
        e.update(r)
    if markdown:
        rows = {}
        for e in entries:
            rows.setdefault((e["oldTab"], e["section"], e["card"]), []).append(e)
        print("| Old tab | Control | New section | Card |\n|---|---|---|---|")
        for (tab, sec, card), es in rows.items():
            names = ", ".join("`%s`" % x["selector"] for x in es)
            print("| %s | %s | %s | %s |" % (tab, names, sec, card))
    else:
        json.dump(entries, sys.stdout, indent=1, ensure_ascii=False)


if __name__ == "__main__":
    main()
