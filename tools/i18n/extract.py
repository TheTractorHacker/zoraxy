#!/usr/bin/env python3
"""Zoraxy i18n catalogue extractor / checker.

Scans src/web/**/*.html and src/web/script/*.js for user-visible English text and
writes src/web/locales/en.json (the source catalogue).  Translations live in
src/web/locales/<code>.json and map the *exact normalised English text* to the
translation (see docs/translating.md).

  extract.py              update en.json and print per-locale coverage
  extract.py --check      CI mode: exit 1 if a locale has keys that are not in the
                          catalogue, placeholder mismatches ({0} parity), bad rules,
                          bad JSON or a missing _meta block; en.json must be up to date
  extract.py --missing zh-CN [--core]   list untranslated keys (optionally core pages only)
  extract.py --write-meta               refresh "coverage" in every locale _meta

Normalisation (must match src/web/script/i18n.js): trim, collapse runs of whitespace
to one space.  Placeholders: {0} {1} ... stand for dynamic parts ("Deleted {0} rules");
at runtime such keys act as patterns.  Strings only discovered at runtime (by scan.py)
are listed in tools/i18n/extra_keys.txt.
"""
import argparse, json, os, re, sys
from html.parser import HTMLParser

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WEB = os.path.join(ROOT, "src", "web")
LOC = os.path.join(WEB, "locales")
EXTRA = os.path.join(os.path.dirname(__file__), "extra_keys.txt")

SKIP_JS = {"aos.js", "chart.js", "countryCode.js", "useragent.js", "i18n.js", "tablesort.js", "perfkit.js",
           "jquery-3.6.0.min.js"}
SKIP_DIRS = {"semantic", "jsvectormap", "datepicker", "locales", "img"}
SKIP_HTML = {"apidocs.html"}
# files whose strings count towards "core" coverage
CORE = ["index.html", "login.html", "components/status.html", "components/httprp.html", "components/security.html",
        "components/security/", "components/waf.html", "components/captcha.html", "components/cert.html",
        "components/globalsettings.html", "components/quickstart.html",
        "script/newrule.js", "script/proxytable.js", "script/quicksetup.js", "script/proxybulk.js", "script/uxkit.js",
        "snippet/upstreams.html", "snippet/accessRuleEditor.html", "snippet/notifications.html"]
SKIP_TAGS = {"script", "style", "code", "pre", "textarea", "noscript", "svg"}
TEXT_ATTRS = ("placeholder", "title", "aria-label", "alt")
HELPERS = r"(?:msgbox|confirmBox|alert|confirm|prompt|showToast|setStatus|t)"


def norm(s):
    return re.sub(r"\s+", " ", s).strip()


def keep(k):
    if len(k) < 2 or len(k) > 600:
        return False
    stripped = re.sub(r"\{\d+\}", "", k)
    if not re.search(r"[A-Za-z]{2}", stripped):
        return False
    if re.fullmatch(r"[\w./:@#%+=-]*[./_][\w./:@#%+=-]*", k) and " " not in k:  # urls, ids, file names
        return False
    if re.search(r"[{}]\s*$", k) and ";" in k:
        return False
    if "${" in k or "{{" in k or "<%" in k or k.startswith("function") or "=>" in k or "&&" in k:
        return False
    return True


# ---- JS scanning -----------------------------------------------------------------

def lex_literal(src, i):
    """src[i] is a quote. Returns (text with \\x00 for ${...}, end_index) or (None, idx)."""
    q = src[i]
    j = i + 1
    out = []
    while j < len(src):
        c = src[j]
        if c == "\\" and j + 1 < len(src):
            n = src[j + 1]
            out.append({"n": " ", "t": " ", "r": ""}.get(n, n))
            j += 2
            continue
        if c == q:
            return "".join(out), j + 1
        if q == "`" and c == "$" and src[j + 1:j + 2] == "{":
            depth, k = 1, j + 2
            while k < len(src) and depth:
                if src[k] == "{":
                    depth += 1
                elif src[k] == "}":
                    depth -= 1
                k += 1
            out.append("\x00")
            j = k
            continue
        if q != "`" and c == "\n":
            return None, j
        out.append(c)
        j += 1
    return None, j


def js_strings(src):
    """Yield (merged_string, start, end) for string literals; '+' chains are merged and
    non-literal operands become a \\x00 marker."""
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and src[i + 1:i + 2] == "/":
            i = src.find("\n", i)
            if i < 0:
                return
            continue
        if c == "/" and src[i + 1:i + 2] == "*":
            e = src.find("*/", i + 2)
            i = n if e < 0 else e + 2
            continue
        if c in "'\"`":
            start = i
            txt, i = lex_literal(src, i)
            if txt is None:
                i += 1
                continue
            while True:
                m = re.match(r"\s*\+\s*", src[i:])
                if not m:
                    break
                k = i + m.end()
                if k < n and src[k] in "'\"`":
                    t2, k2 = lex_literal(src, k)
                    if t2 is None:
                        break
                    txt += t2
                    i = k2
                else:
                    depth, k2 = 0, k
                    while k2 < n:
                        ch = src[k2]
                        if ch in "([{":
                            depth += 1
                        elif ch in ")]}":
                            if depth == 0:
                                break
                            depth -= 1
                        elif depth == 0 and ch in ",;+\n" and not (ch == "+" and src[k2 + 1:k2 + 2] == "+"):
                            break
                        elif ch in "'\"`":
                            _, k2 = lex_literal(src, k2)
                            continue
                        k2 += 1
                    nxt = re.match(r"\s*\+\s*['\"`]", src[k2:])
                    if k2 > k:
                        txt += "\x00"
                        i = k2
                    if not nxt:
                        break
            yield txt, start, i
            continue
        i += 1


def number_placeholders(s):
    idx = [0]

    def rep(_):
        v = "{%d}" % idx[0]
        idx[0] += 1
        return v
    return re.sub("\x00", rep, s)


TAG_TEXT = re.compile(r">([^<>]+)<|>([^<>]+)$|^([^<>]+)<")


def from_js_literal(txt, direct):
    out = []
    s = number_placeholders(txt)
    if "<" in s and ">" in s:
        for m in TAG_TEXT.finditer(s):
            out.append(m.group(1) or m.group(2) or m.group(3))
        for m in re.finditer(r"""\b(?:placeholder|title|aria-label|alt)\s*=\s*(?:\\?["'])([^"'<>]*)""", s):
            out.append(m.group(1))
    elif direct:
        out.append(s)
    return out


def scan_js(src, add):
    for txt, st, en in js_strings(src):
        before = src[max(0, st - 40):st]
        direct = bool(re.search(r"(?:\b" + HELPERS + r"|\.parent\.msgbox|\.text|\.html|\.placeholder|\.title)\s*\(\s*$", before)) or \
            bool(re.search(r"\.(?:attr|prop)\(\s*['\"](?:placeholder|title|aria-label)['\"]\s*,\s*$", before)) or \
            (bool(re.search(r"\b(?:message|msg|title|label|text|header|description|error|err)\s*[:=]\s*$", before))
             and re.search(r"\s[A-Za-z]{3,}\s", txt) is not None)
        for k in from_js_literal(txt, direct):
            add(k)


# ---- HTML scanning ---------------------------------------------------------------

VOID = ("br", "img", "input", "meta", "link", "hr", "source", "area", "base", "col", "embed", "param", "track", "wbr")


class P(HTMLParser):
    def __init__(self, add):
        super().__init__(convert_charrefs=True)
        self.add = add
        self.stack = []
        self.script = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        self._attrs(tag, d)
        if tag in VOID:
            return
        self.stack.append((tag, "data-i18n-skip" in d))
        if tag == "script" and not d.get("src"):
            self.script = []

    def handle_startendtag(self, tag, attrs):
        self._attrs(tag, dict(attrs))

    def _attrs(self, tag, d):
        if "data-i18n-skip" in d or any(sk for _, sk in self.stack):
            return
        for a in TEXT_ATTRS:
            if d.get(a):
                self.add(d[a])
        if tag == "input" and (d.get("type") or "").lower() in ("button", "submit", "reset") and d.get("value"):
            self.add(d["value"])
        for a, v in d.items():
            if a.startswith("on") and v:
                scan_js(v, self.add)

    def handle_endtag(self, tag):
        if tag == "script" and self.script is not None:
            scan_js("".join(self.script), self.add)
            self.script = None
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if self.script is not None:
            self.script.append(data)
            return
        if any(t in SKIP_TAGS or sk for t, sk in self.stack):
            return
        self.add(data)


def collect():
    """returns {key: set(files)}"""
    keys = {}

    def run(rel, path):
        def add(s):
            k = norm(s)
            if keep(k):
                keys.setdefault(k, set()).add(rel)
        with open(path, encoding="utf-8", errors="replace") as f:
            src = f.read()
        if path.endswith(".js"):
            scan_js(src, add)
        else:
            p = P(add)
            try:
                p.feed(src)
            except Exception as e:
                print("warn: %s: %s" % (rel, e), file=sys.stderr)

    for base, dirs, files in os.walk(WEB):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in sorted(files):
            rel = os.path.relpath(os.path.join(base, fn), WEB).replace(os.sep, "/")
            if fn in SKIP_HTML or fn in SKIP_JS:
                continue
            if fn.endswith(".html") or (fn.endswith(".js") and os.path.basename(base) == "script"):
                run(rel, os.path.join(base, fn))
    if os.path.exists(EXTRA):
        for line in open(EXTRA, encoding="utf-8"):
            k = norm(line)
            if k and not k.startswith("#"):
                keys.setdefault(k, set()).add("extra")
    return keys


def is_core(files):
    return any(f == c or (c.endswith("/") and f.startswith(c)) for f in files for c in CORE)


def ph(s):
    return sorted(re.findall(r"\{\d+\}", s))


def load_locales():
    out = {}
    for fn in sorted(os.listdir(LOC)):
        if fn.endswith(".json") and fn != "en.json":
            out[fn[:-5]] = (fn, json.load(open(os.path.join(LOC, fn), encoding="utf-8")))
    return out


def dumps(d):
    return json.dumps(d, ensure_ascii=False, indent=1) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--missing")
    ap.add_argument("--core", action="store_true")
    ap.add_argument("--write-meta", action="store_true")
    a = ap.parse_args()
    os.makedirs(LOC, exist_ok=True)
    keys = collect()
    ordered = sorted(keys, key=lambda k: (k.lower(), k))
    core = {k for k in keys if is_core(keys[k])}
    en = {"_meta": {"language": "English", "note": "generated by tools/i18n/extract.py; do not edit by hand"},
          "strings": {k: k for k in ordered}}
    locs = load_locales()
    problems = []
    enpath = os.path.join(LOC, "en.json")
    if a.check:
        cur = open(enpath, encoding="utf-8").read() if os.path.exists(enpath) else ""
        if cur != dumps(en):
            problems.append("en.json is out of date: run tools/i18n/extract.py and commit the result")
    else:
        with open(enpath, "w", encoding="utf-8") as f:
            f.write(dumps(en))
    rows = []
    for code, (fn, d) in locs.items():
        s = d.get("strings", {})
        if not isinstance(d.get("_meta"), dict) or "reviewed" not in d["_meta"]:
            problems.append("%s: missing _meta block with reviewed flag" % fn)
        for k, v in s.items():
            if k not in keys:
                problems.append("%s: key not in catalogue (stale?): %r" % (fn, k))
            elif not isinstance(v, str) or not v.strip():
                problems.append("%s: empty translation for %r" % (fn, k))
            elif ph(k) != ph(v):
                problems.append("%s: placeholder mismatch %r -> %r" % (fn, k, v))
        for r in d.get("rules", []):
            try:
                rx = re.compile(r["re"])
                for g in re.findall(r"\$(\d+)", r["to"]):
                    if int(g) > rx.groups:
                        problems.append("%s: rule %r uses $%s but has %d groups" % (fn, r["re"], g, rx.groups))
            except Exception as e:
                problems.append("%s: bad rule %r: %s" % (fn, r, e))
        done = sum(1 for k in keys if k in s)
        cdone = sum(1 for k in core if k in s)
        pct = round(100.0 * done / max(1, len(keys)), 1)
        cpct = round(100.0 * cdone / max(1, len(core)), 1)
        rows.append((code, done, pct, cdone, cpct, d.get("_meta", {})))
        if a.write_meta and not a.check:
            d["_meta"]["coverage"] = pct
            d["_meta"]["coreCoverage"] = cpct
            with open(os.path.join(LOC, fn), "w", encoding="utf-8") as f:
                f.write(dumps(d))
    if a.missing:
        s = locs[a.missing][1].get("strings", {})
        for k in ordered:
            if k not in s and (not a.core or k in core):
                print(k)
        return
    print("catalogue: %d strings (%d core)" % (len(keys), len(core)))
    for code, done, pct, cdone, cpct, meta in rows:
        print("  %-6s %5d strings  %5.1f%% all   %5.1f%% core   reviewed=%s" % (code, done, pct, cpct, meta.get("reviewed")))
    if a.check:
        for p in problems:
            print("ERROR " + p)
        sys.exit(1 if problems else 0)
    for p in problems[:50]:
        print("warn " + p)


if __name__ == "__main__":
    main()
