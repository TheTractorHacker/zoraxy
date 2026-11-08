/*
    i18n.js - runtime translation layer for the Zoraxy admin UI

    There is no build step and the UI text is plain English in the HTML, so translation is done
    at runtime: locales/<code>.json maps the exact English text (trimmed, whitespace collapsed)
    to its translation.  This script translates text nodes and a few attributes, follows the DOM
    with ONE MutationObserver that only looks at added/changed nodes (batched, time-sliced), and
    does nothing at all while the language is English (no observer, no work).

    Public API (window.i18n, plus the globals t() and tf()):
        i18n.lang                       current language code
        i18n.languages                  [[code, native name], ...]
        i18n.setLanguage(code, opts)    switch language without reload (opts.persist=false to not save)
        i18n.apply(root)                translate a subtree now (rarely needed, the observer does it)
        t("English text")               translated text (or the input when unknown)
        tf("Deleted {0} rules", n)      t() + {0}-style placeholder substitution
    Markup: data-i18n-skip on an element keeps its subtree untouched.
    Locale file: {"_meta":{...}, "strings":{"English":"..."}, "rules":[{"re":"^Deleted (\\d+) rules$","to":"... $1 ..."}]}
    Keys containing {0}, {1}... act as patterns ("Deleted {0} rules" also matches "Deleted 5 rules").
*/
(function () {
    "use strict";
    if (window.i18n) return;

    var LANGS = [["zh-CN", "简体中文"], ["zh-TW", "繁體中文"], ["es", "Español"], ["de", "Deutsch"], ["fr", "Français"],
        ["ja", "日本語"], ["pt-BR", "Português"], ["ru", "Русский"], ["en", "English"]];
    var RTL = { ar: 1, he: 1, fa: 1, ur: 1 };
    var STORE_KEY = "zoraxy.lang";
    var ATTRS = ["placeholder", "title", "aria-label", "alt", "label", "data-content", "data-tooltip"];
    var SKIP_TAGS = { SCRIPT: 1, STYLE: 1, CODE: 1, PRE: 1, TEXTAREA: 1, NOSCRIPT: 1, SVG: 1, svg: 1, TITLE: 1 };
    var BUTTON_INPUT = { button: 1, submit: 1, reset: 1 };

    var SELF = document.currentScript && document.currentScript.src;
    function rel(path) { try { return new URL(path, SELF || location.href).href; } catch (e) { return path; } }

    var lang = "en";
    var dict = null;          // Map english -> translation
    var patterns = [];        // [{re, groups:[n...], to}]
    var rules = [];           // [{re, to}]
    var miss = new Map();     // negative cache for dynamic strings
    var textRec = new WeakMap();
    var attrRec = new WeakMap();
    var observer = null;
    var queue = new Set();
    var scheduled = false;
    var supported = {};
    LANGS.forEach(function (l) { supported[l[0]] = l[1]; });

    function norm(s) { return s.replace(/\s+/g, " ").trim(); }
    function store(k, v) { try { if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch (e) { } }
    function load(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }

    // "zh-Hans-CN" -> "zh-CN", "pt" -> "pt-BR" ... null when not shipped
    function match(code) {
        if (!code) return null;
        code = String(code).replace("_", "-");
        if (supported[code]) return code;
        var lc = code.toLowerCase();
        if (/^zh/.test(lc)) return /(tw|hk|mo|hant)/.test(lc) ? "zh-TW" : "zh-CN";
        var p = lc.split("-")[0];
        if (p === "pt") return "pt-BR";
        for (var c in supported) if (c.toLowerCase() === p) return c;
        return null;
    }
    function detect() {
        var saved = match(load(STORE_KEY));
        if (saved) return saved;
        var nl = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language];
        for (var i = 0; i < nl.length; i++) { var m = match(nl[i]); if (m) return m; }
        return "en";
    }

    // ---- lookup ------------------------------------------------------------------
    function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

    function compile(data) {
        var m = new Map(), pats = [];
        var s = data.strings || {};
        Object.keys(s).forEach(function (k) {
            m.set(k, s[k]);
            if (/\{\d+\}/.test(k)) {
                var groups = [];
                var src = k.split(/(\{\d+\})/).map(function (part) {
                    var g = /^\{(\d+)\}$/.exec(part);
                    if (g) { groups.push(+g[1]); return "([\\s\\S]+?)"; }
                    return escapeRe(part);
                }).join("");
                try { pats.push({ re: new RegExp("^" + src + "$"), groups: groups, to: s[k], len: k.length }); } catch (e) { }
            }
        });
        pats.sort(function (a, b) { return b.len - a.len; });
        var rs = [];
        (data.rules || []).forEach(function (r) { try { rs.push({ re: new RegExp(r.re), to: r.to }); } catch (e) { } });
        return { dict: m, patterns: pats, rules: rs };
    }

    // translate a normalised key, returns null when there is nothing to do
    function lookup(key, depth) {
        var v = dict.get(key);
        if (v !== undefined) return v;
        if (miss.has(key)) return null;
        var i, out = null;
        for (i = 0; i < patterns.length && out === null; i++) {
            var m = patterns[i].re.exec(key);
            if (m) {
                var p = patterns[i];
                out = p.to.replace(/\{(\d+)\}/g, function (_, n) {
                    var gi = p.groups.indexOf(+n);
                    if (gi < 0) return "{" + n + "}";
                    var cap = m[gi + 1];
                    if (!depth) { var sub = lookup(norm(cap), 1); if (sub !== null) return sub; }
                    return cap;
                });
            }
        }
        for (i = 0; i < rules.length && out === null; i++) {
            if (rules[i].re.test(key)) out = key.replace(rules[i].re, rules[i].to);
        }
        if (out === null) {
            if (miss.size > 4000) miss.clear();
            miss.set(key, 1);
        }
        return out;
    }

    function tr(raw) {
        var key = norm(raw);
        if (key.length < 2 || !/[A-Za-z]/.test(key)) return null;
        var t = lookup(key, 0);
        if (t === null) return null;
        var lead = /^\s*/.exec(raw)[0], trail = /\s*$/.exec(raw)[0];
        return lead + t + trail;
    }

    // ---- DOM ---------------------------------------------------------------------
    function skipped(el) {
        for (; el && el.nodeType === 1; el = el.parentNode) {
            if (SKIP_TAGS[el.nodeName] || el.hasAttribute("data-i18n-skip")) return true;
        }
        return false;
    }

    function doText(node) {
        var rec = textRec.get(node), cur = node.nodeValue, base;
        if (rec && rec.w === cur) {
            if (rec.l === lang) return;
            base = rec.o;
        } else base = cur;
        var out = lang === "en" || !dict ? null : tr(base);
        var w = out === null ? base : out;
        if (w !== cur) node.nodeValue = w;
        textRec.set(node, { o: base, w: w, l: lang });
    }

    function doAttr(el, name) {
        var v = el.getAttribute(name);
        if (v === null) return;
        var recs = attrRec.get(el);
        if (!recs) { recs = {}; attrRec.set(el, recs); }
        var rec = recs[name], base;
        if (rec && rec.w === v) {
            if (rec.l === lang) return;
            base = rec.o;
        } else base = v;
        var out = lang === "en" || !dict ? null : tr(base);
        var w = out === null ? base : out;
        if (w !== v) el.setAttribute(name, w);
        recs[name] = { o: base, w: w, l: lang };
    }

    function doElement(el) {
        if (!el.hasAttributes()) return;
        for (var i = 0; i < ATTRS.length; i++) if (el.hasAttribute(ATTRS[i])) doAttr(el, ATTRS[i]);
        if (el.nodeName === "INPUT" && BUTTON_INPUT[(el.getAttribute("type") || "").toLowerCase()]) doAttr(el, "value");
    }

    function walk(root) {
        if (root.nodeType === 3) { if (!skipped(root.parentNode)) doText(root); return; }
        if (root.nodeType !== 1 || skipped(root)) return;
        var tw = document.createTreeWalker(root, 1 | 4, {
            acceptNode: function (n) {
                if (n.nodeType === 1 && (SKIP_TAGS[n.nodeName] || n.hasAttribute("data-i18n-skip"))) return 2; // reject subtree
                return 1;
            }
        });
        var n;
        doElement(root);
        while ((n = tw.nextNode())) {
            if (n.nodeType === 3) doText(n); else doElement(n);
        }
    }

    function translateTitle() {
        if (!document.title) return;
        var base = document.documentElement.getAttribute("data-i18n-title") || document.title;
        if (!document.documentElement.getAttribute("data-i18n-title")) document.documentElement.setAttribute("data-i18n-title", base);
        if (lang === "en" || !dict) { if (document.title !== base) document.title = base; return; }
        var t = lookup(norm(base), 0);
        if (t === null) {
            var parts = base.split(" | "), any = false;
            parts = parts.map(function (p) { var x = lookup(norm(p), 0); if (x !== null) { any = true; return x; } return p; });
            if (any) t = parts.join(" | ");
        }
        document.title = t === null ? base : t;
    }

    function flush() {
        scheduled = false;
        if (!dict || lang === "en") { queue.clear(); return; }
        var deadline = performance.now() + 10;
        var list = Array.from(queue);
        queue.clear();
        for (var i = 0; i < list.length; i++) {
            if (i > 0 && performance.now() > deadline) { for (var j = i; j < list.length; j++) queue.add(list[j]); break; }
            if (list[i].isConnected) walk(list[i]);
        }
        if (observer) observer.takeRecords(); // our own writes must not wake us again
        if (queue.size) schedule();
    }
    function schedule() {
        if (scheduled) return;
        scheduled = true;
        if (window.requestIdleCallback) requestIdleCallback(flush, { timeout: 120 });
        else requestAnimationFrame(flush);
    }

    function onMutations(recs) {
        for (var i = 0; i < recs.length; i++) {
            var r = recs[i];
            if (r.type === "childList") {
                for (var j = 0; j < r.addedNodes.length; j++) { var a = r.addedNodes[j]; if (a.nodeType === 1 || a.nodeType === 3) queue.add(a); }
            } else if (r.type === "characterData") queue.add(r.target);
            else if (r.type === "attributes") queue.add(r.target);
        }
        if (queue.size) schedule();
    }
    function startObserver() {
        if (observer || !window.MutationObserver) return;
        observer = new MutationObserver(onMutations);
        observer.observe(document.documentElement, {
            childList: true, subtree: true, characterData: true,
            attributes: true, attributeFilter: ATTRS.concat(["value"])
        });
    }
    function stopObserver() { if (observer) { observer.disconnect(); observer = null; } queue.clear(); }

    function applyAll() {
        var root = document.documentElement;
        if (!root) return;
        walk(root);
        translateTitle();
        if (observer) observer.takeRecords();
    }

    // ---- language switching -------------------------------------------------------
    function fetchDict(code, cb) {
        // snippets share the parent's compiled dictionary (same origin), saving a fetch+parse
        try {
            var p = window.parent;
            if (p && p !== window && p.i18n && p.i18n._c && p.i18n.lang === code) return cb(p.i18n._c);
        } catch (e) { }
        var x = new XMLHttpRequest();
        x.open("GET", rel("../locales/" + code + ".json"), true);
        x.onload = function () {
            if (x.status !== 200) return cb(null);
            try { cb(compile(JSON.parse(x.responseText))); } catch (e) { cb(null); }
        };
        x.onerror = function () { cb(null); };
        x.send();
    }

    var compiled = null;
    function setLanguage(code, opts) {
        opts = opts || {};
        code = match(code) || "en";
        if (opts.persist !== false) { store(STORE_KEY, code); }
        if (opts.persist !== false && opts.server !== false) saveServer(code);
        if (code === lang && (code === "en" || dict)) { syncUI(); return; }
        var finish = function (c) {
            lang = code;
            miss.clear();
            compiled = c;
            dict = c ? c.dict : null; patterns = c ? c.patterns : []; rules = c ? c.rules : [];
            if (!c) lang = "en";
            document.documentElement.lang = lang;
            document.documentElement.dir = RTL[lang.split("-")[0]] ? "rtl" : "ltr";
            if (lang === "en") { applyAll(); stopObserver(); }
            else { startObserver(); applyAll(); }
            syncUI();
            api._c = compiled;
            try { document.dispatchEvent(new CustomEvent("zoraxy:i18n", { detail: { lang: lang } })); } catch (e) { }
            forwardToFrames();
        };
        if (code === "en") finish(null); else fetchDict(code, finish);
    }

    function forwardToFrames() {
        var fr = document.getElementsByTagName("iframe");
        for (var i = 0; i < fr.length; i++) {
            try { fr[i].contentWindow.postMessage({ zoraxyI18n: lang }, location.origin); } catch (e) { }
        }
    }

    function saveServer(code) {
        if (window.parent !== window) return;
        try {
            var meta = document.getElementsByTagName("meta")["zoraxy.csrf.Token"];
            var h = { "Content-Type": "application/x-www-form-urlencoded" };
            if (meta) h["X-CSRF-Token"] = meta.getAttribute("content");
            fetch(rel("../api/i18n/language"), { method: "POST", headers: h, body: "language=" + encodeURIComponent(code), credentials: "same-origin" }).catch(function () { });
        } catch (e) { }
    }
    function loadServer() {
        if (window.parent !== window || load(STORE_KEY)) return;
        try {
            fetch(rel("../api/i18n/language"), { credentials: "same-origin" }).then(function (r) { return r.ok ? r.json() : null; }).then(function (j) {
                var m = j && match(j.language);
                if (m && m !== lang && !load(STORE_KEY)) setLanguage(m, { persist: false });
            }).catch(function () { });
        } catch (e) { }
    }

    // keep language pickers in sync
    function syncUI() {
        var sel = document.querySelectorAll("select.i18n-picker");
        for (var i = 0; i < sel.length; i++) { if (sel[i].value !== lang) sel[i].value = lang; }
    }
    function mountPickers() {
        var sel = document.querySelectorAll("select.i18n-picker");
        for (var i = 0; i < sel.length; i++) {
            var s = sel[i];
            if (s.getAttribute("data-i18n-mounted")) continue;
            s.setAttribute("data-i18n-mounted", "1");
            LANGS.forEach(function (l) { var o = document.createElement("option"); o.value = l[0]; o.textContent = l[1]; o.setAttribute("data-i18n-skip", ""); s.appendChild(o); });
            s.value = lang;
            s.addEventListener("change", function (e) { setLanguage(e.target.value); });
        }
    }

    window.addEventListener("storage", function (e) {
        if (e.key === STORE_KEY) { var m = match(e.newValue) || "en"; if (m !== lang) setLanguage(m, { persist: false }); }
    });
    window.addEventListener("message", function (e) {
        if (e.origin !== location.origin || !e.data || typeof e.data.zoraxyI18n !== "string") return;
        var m = match(e.data.zoraxyI18n) || "en";
        if (m !== lang) setLanguage(m, { persist: false });
    });

    // ---- helpers for code -----------------------------------------------------------
    function t(s) {
        if (lang === "en" || !dict || typeof s !== "string") return s;
        var r = tr(s);
        return r === null ? s : r;
    }
    function tf(s) {
        var args = Array.prototype.slice.call(arguments, 1);
        return t(s).replace(/\{(\d+)\}/g, function (m, n) { return args[+n] !== undefined ? args[+n] : m; });
    }

    var api = {
        languages: LANGS, setLanguage: setLanguage, mountPickers: mountPickers, apply: function (root) { if (lang !== "en") walk(root || document.documentElement); },
        t: t, tf: tf, match: match, _c: null
    };
    Object.defineProperty(api, "lang", { get: function () { return lang; }, enumerable: true });
    window.i18n = api;
    if (typeof window.t === "undefined") window.t = t;
    if (typeof window.tf === "undefined") window.tf = tf;

    // wrap the native dialogs so their text is translated too (msgbox/confirmBox text goes through the DOM observer)
    ["alert", "confirm", "prompt"].forEach(function (fn) {
        var orig = window[fn];
        if (typeof orig !== "function") return;
        window[fn] = function (m) { var a = Array.prototype.slice.call(arguments); if (typeof m === "string") a[0] = t(m); return orig.apply(window, a); };
    });

    // ---- boot -------------------------------------------------------------------------
    var initial = detect();
    document.documentElement.lang = initial === "en" ? (document.documentElement.lang || "en") : initial;
    if (initial !== "en") setLanguage(initial, { persist: false });
    document.addEventListener("DOMContentLoaded", function () { mountPickers(); loadServer(); });
})();
