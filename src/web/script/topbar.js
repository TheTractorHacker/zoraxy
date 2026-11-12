/*
    Top bar (window.ZxTopbar): status pills, theme / language / account menus and the phone "More" menu.
    Markup: the .menubar block of index.html.  Styles: ui/topbar.css.  Docs: docs/ux/components.md (section Top bar).

    Data (nothing new on the server; one light poll, only while the tab is visible):
      GET /api/stats/glance       blocked today, upstreams down, certificates that expire within 30 days (the Status page tiles)
      GET /api/proxy/status       Running + listening port (the Status page banner)      -> both every 45 s, paused while the tab is hidden
      update badge                no request of its own (Zoraxy never contacts GitHub by itself): it shows the result of the last check
                                  made on the Update page in this browser (ZxTopbar.setUpdate, kept 14 days, dropped once the version changes)
      GET /api/auth/authEnabled, /api/auth/username, /api/auth/role   once, for the account menu (hidden when authentication is off)
    Every pill is a link to a real page or shows nothing.  When a request fails the bar shows one neutral "Status unavailable"
    pill instead of spinning.

    Menus: role=menu popovers, Up/Down/Home/End move, Enter/Space choose, Esc closes and returns focus, Tab closes.
    Theme modes: Light / Dark / System.  "System" = no stored choice (what darktheme.js already does on first visit).
    All text is plain English, translated by script/i18n.js (tr / trf below); user names are marked data-i18n-skip.
*/
(function () {
    "use strict";
    if (window.ZxTopbar) { return; }
    var ZxTopbar = window.ZxTopbar = { version: 1 };
    function N_(s) { return s; }
    function tr(s) { return typeof window.t === "function" ? window.t(s) : s; }
    function trf(s) { var a = Array.prototype.slice.call(arguments, 1); return tr(s).replace(/\{(\d+)\}/g, function (m, n) { return a[+n] !== undefined ? a[+n] : m; }); }
    function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return "&#" + c.charCodeAt(0) + ";"; }); }
    function $id(id) { return document.getElementById(id); }
    function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
    function lsSet(k, v) { try { if (v === null) { localStorage.removeItem(k); } else { localStorage.setItem(k, v); } } catch (e) { /* storage blocked */ } }

    var POLL_MS = 45000;
    var UPDATE_TTL_MS = 14 * 24 * 3600 * 1000, UPDATE_KEY = "zoraxy.topbar.update";

    /* ---------------------------------------------------------------- icons (inline, stroke = currentColor) */
    function svg(body, cls) { return "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\" focusable=\"false\"" + (cls ? " class=\"" + cls + "\"" : "") + ">" + body + "</svg>"; }
    var ICON = {
        sun: svg("<circle cx=\"12\" cy=\"12\" r=\"4\"/><path d=\"M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4\"/>"),
        moon: svg("<path d=\"M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z\"/>"),
        system: svg("<rect x=\"3\" y=\"4\" width=\"18\" height=\"12\" rx=\"2\"/><path d=\"M8 20h8M12 16v4\"/>"),
        globe: svg("<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M3 12h18M12 3c2.6 2.6 3.8 5.6 3.8 9s-1.2 6.4-3.8 9c-2.6-2.6-3.8-5.6-3.8-9S9.4 5.6 12 3z\"/>"),
        search: svg("<circle cx=\"11\" cy=\"11\" r=\"7\"/><path d=\"M20 20l-3.5-3.5\"/>"),
        chev: svg("<path d=\"M6 9l6 6 6-6\"/>", "zx-chev"),
        check: svg("<path d=\"M5 12.5l4.5 4.5L19 7.5\"/>", "zx-mi__check"),
        out: svg("<path d=\"M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9\"/>"),
        key: svg("<circle cx=\"8\" cy=\"15\" r=\"4\"/><path d=\"M11 12l9-9M16 7l3 3\"/>"),
        down: svg("<path d=\"M12 3v12M7 11l5 5 5-5M5 21h14\"/>"),
        cert: svg("<circle cx=\"12\" cy=\"9\" r=\"6\"/><path d=\"M8.5 14L7 22l5-3 5 3-1.5-8\"/>"),
        ban: svg("<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M5.6 5.6l12.8 12.8\"/>"),
        server: svg("<rect x=\"3\" y=\"4\" width=\"18\" height=\"7\" rx=\"2\"/><rect x=\"3\" y=\"13\" width=\"18\" height=\"7\" rx=\"2\"/><path d=\"M7 7.5h.01M7 16.5h.01\"/>"),
        dots: svg("<circle cx=\"5\" cy=\"12\" r=\"1.2\"/><circle cx=\"12\" cy=\"12\" r=\"1.2\"/><circle cx=\"19\" cy=\"12\" r=\"1.2\"/>"),
        burger: svg("<path d=\"M4 6h16M4 12h16M4 18h16\"/>")
    };

    /* ---------------------------------------------------------------- state */
    var S = {
        data: null,            // {glance, proxy}   null until the first answer
        failed: false,         // the last poll failed completely
        update: null,          // {available, latest, host, at}
        host: "",              // running version, from /api/proxy/status
        auth: null             // null = unknown / off, {user, role}
    };

    /* ---------------------------------------------------------------- pills */
    function plural(n, one, many) { return n === 1 ? one : many; }

    // One descriptor per pill: {id, state, icon, n, text, label, href, tag, kind}.  label = the sentence for tooltip + aria-label.
    function pills() {
        var out = [];
        if (S.data) {
            var g = S.data.glance, p = S.data.proxy;
            if (p) {
                if (p.Running === false) {
                    out.push({ id: "health", state: "danger", dot: true, text: tr(N_("Proxy stopped")), label: tr(N_("The proxy is stopped. Open Status to start it.")), tag: "status" });
                } else {
                    var ports = p.Port ? trf(N_("Listening on port {0}"), p.Port) + (p.UseTls ? " (HTTPS)" : " (HTTP)") : tr(N_("The proxy is running."));
                    if (p.ListenOnPort80) {
                        var plain = trf(N_("plain HTTP on {0}"), p.HttpListenAddr || ":80");
                        ports += ", " + plain;
                    }
                    out.push({ id: "health", state: "ok", dot: true, text: tr(N_("Online")), label: tr(N_("The proxy is running.")) + " " + ports + ".", tag: "status" });
                }
            }
            var down = g && g.UpstreamsDown ? g.UpstreamsDown.length : 0;
            if (g && down > 0) {
                var names = g.UpstreamsDown.slice(0, 3).map(function (d) { return d.Name || d.URL; }).join(", ");
                out.push({ id: "down", state: "danger", icon: "server", n: down, text: tr(plural(down, N_("site down"), N_("sites down"))),
                    label: trf(N_("{0} monitored upstream(s) are not answering: {1}. Open Uptime Monitor."), down, names), tag: "utm" });
            }
            var exp = g && g.CertsExpiring ? g.CertsExpiring : [];
            if (exp.length) {
                var soon = exp[0].DaysLeft <= 7;
                var certList = exp.slice(0, 3).map(function (c) {
                    var days = trf(N_("{0} days"), c.DaysLeft);
                    return c.Name + " (" + days + ")";
                }).join(", ");
                out.push({ id: "cert", state: soon ? "danger" : "warn", icon: "cert", n: exp.length, text: tr(plural(exp.length, N_("certificate expiring"), N_("certificates expiring"))),
                    label: trf(N_("Expires soon: {0}. Open Certificates."), certList), tag: "cert" });
            }
        }
        if (S.update && S.update.available) {
            out.push({ id: "update", state: "info", icon: "down", text: trf(N_("Update {0}"), S.update.latest || ""), label: trf(N_("An update is available: {0}. Open Update."), S.update.latest || ""), tag: "updater" });
        }
        if (S.data && S.data.glance) {
            var b = S.data.glance.BlockedToday || 0;
            out.push({ id: "blocked", state: "neutral", icon: "ban", n: b.toLocaleString(), text: tr(N_("blocked today")), more: tr(N_("See why")),
                label: trf(N_("Blocked today: {0}. See why, in Statistics > Blocked."), b), tag: "stats", kind: "blocked" });
        }
        if (S.failed) {
            out.push({ id: "unknown", state: "neutral", dot: true, text: tr(N_("Status unavailable")), label: tr(N_("The status could not be read. It is retried every 45 seconds.")), tag: "status" });
        }
        return out;
    }

    function pillHtml(d, inMenu) {
        var lead = d.dot ? "<span class=\"zx-pill__dot\"></span>" : (d.icon ? ICON[d.icon] : "");
        var href = "#" + d.tag;
        if (inMenu) {
            return "<a class=\"zx-mi zx-mi--" + d.state + "\" role=\"menuitem\" href=\"" + esc(href) + "\" data-tag=\"" + esc(d.tag) + "\" data-kind=\"" + esc(d.kind || "") + "\" title=\"" + esc(d.label) + "\">" +
                (d.dot ? "<span class=\"zx-pill__dot\"></span>" : lead) + "<span class=\"zx-mi__t\">" + (d.n !== undefined ? esc(d.n) + " " : "") + esc(d.text) + "</span></a>";
        }
        return "<a class=\"zx-pill zx-pill--" + d.state + "\" href=\"" + esc(href) + "\" data-tag=\"" + esc(d.tag) + "\" data-kind=\"" + esc(d.kind || "") + "\" data-pill=\"" + d.id + "\" title=\"" + esc(d.label) + "\" aria-label=\"" + esc(d.label) + "\">" +
            lead + (d.n !== undefined ? "<span class=\"zx-pill__n\">" + esc(d.n) + "</span>" : "") + "<span class=\"zx-pill__t\">" + esc(d.text) + "</span>" +
            (d.more ? "<span class=\"zx-pill__t zx-pill__more\">" + esc(d.more) + "</span>" : "") + "</a>";
    }

    function renderPills() {
        var box = $id("zxTopStatus");
        var list = pills();
        if (box) { box.innerHTML = list.map(function (d) { return pillHtml(d, false); }).join(""); }
        // attention marker on the phone "More" button: anything that is not ok / neutral
        var more = $id("zxMoreBtn"), dot = more && more.querySelector(".zx-more-dot");
        var worst = list.reduce(function (w, d) { return d.state === "danger" ? "danger" : (w !== "danger" && (d.state === "warn" || d.state === "info") ? "warn" : w); }, "");
        if (more) {
            if (dot) { dot.parentNode.removeChild(dot); }
            if (worst) { more.insertAdjacentHTML("beforeend", "<span class=\"zx-more-dot" + (worst === "danger" ? " is-danger" : "") + "\"></span>"); }
            var moreLabel = tr(N_("Status and account menu"));
            if (worst) {
                var attention = tr(N_("needs attention"));
                moreLabel += " (" + attention + ")";
            }
            more.setAttribute("aria-label", moreLabel);
        }
    }

    function go(tag, kind) {
        if (kind === "blocked") {
            if (typeof window.openTabById === "function") { window.openTabById("stats"); }
            var t0 = Date.now();
            (function wait() {
                if (typeof window.statsOpenBlocked === "function" && $id("stats") && $id("stats").offsetParent !== null) { setTimeout(function () { window.statsOpenBlocked({}); }, 120); return; }
                if (Date.now() - t0 < 4000) { setTimeout(wait, 100); }
            })();
            return;
        }
        if (typeof window.openTabById === "function") { window.openTabById(tag); } else { location.hash = "#" + tag; }
    }

    /* ---------------------------------------------------------------- polling */
    var timer = null, lastAt = 0, inflight = false;
    function getJSON(url, ms) {
        var ctl = window.AbortController ? new AbortController() : null;
        var to = ctl ? setTimeout(function () { ctl.abort(); }, ms || 8000) : null;
        return fetch(url, { credentials: "same-origin", cache: "no-store", signal: ctl ? ctl.signal : undefined }).then(function (r) {
            if (to) { clearTimeout(to); }
            if (!r.ok) { throw new Error("http " + r.status); }
            return r.json();
        }, function (e) { if (to) { clearTimeout(to); } throw e; });
    }
    function poll() {
        if (document.hidden || inflight) { return; }
        inflight = true;
        Promise.all([getJSON("./api/stats/glance").catch(function () { return null; }), getJSON("./api/proxy/status").catch(function () { return null; })]).then(function (r) {
            inflight = false;
            lastAt = Date.now();
            var g = r[0], p = r[1];
            S.failed = !g && !p;
            if (!S.failed) {
                var prev = S.data || {};
                S.data = { glance: g || prev.glance || null, proxy: p ? { Running: p.Running, Port: p.Option && p.Option.Port, UseTls: p.Option && p.Option.UseTls,
                    ListenOnPort80: p.Option && p.Option.ListenOnPort80, HttpListenAddr: p.Option && p.Option.HttpListenAddr } : (prev.proxy || null) };
                if (p && p.Option && p.Option.HostVersion) { S.host = p.Option.HostVersion; }
            }
            renderPills();
        });
    }
    function startPolling() {
        poll();
        timer = setInterval(poll, POLL_MS);
        document.addEventListener("visibilitychange", function () { if (!document.hidden && Date.now() - lastAt > 30000) { poll(); } });
    }
    ZxTopbar.refresh = function () { lastAt = 0; poll(); };

    /* ---------------------------------------------------------------- update badge */
    function storeUpdate(u) { S.update = u; lsSet(UPDATE_KEY, JSON.stringify(u)); renderPills(); }
    ZxTopbar.setUpdate = function (res) {   // called by the Update page after its own check
        if (!res) { return; }
        storeUpdate({ available: !!res.update_available, latest: res.latest && res.latest.tag || "", host: S.host, at: Date.now() });
    };
    function initUpdate() {
        // No automatic request to GitHub: the badge shows the result of the last check made on the Update page in this browser
        var u = null;
        try { u = JSON.parse(lsGet(UPDATE_KEY) || "null"); } catch (e) { u = null; }
        if (u && u.available && Date.now() - (u.at || 0) < UPDATE_TTL_MS && (!u.host || !S.host || u.host === S.host)) { S.update = u; renderPills(); }
    }

    /* ---------------------------------------------------------------- theme */
    function themeMode() { var v = lsGet("theme"); return v === "dark" || v === "light" ? v : "system"; }
    function isDark() { return document.body.classList.contains("darkTheme"); }
    function systemDark() { try { return window.matchMedia("(prefers-color-scheme: dark)").matches; } catch (e) { return false; } }
    function setThemeMode(mode) {
        var wantDark = mode === "dark" || (mode === "system" && systemDark());
        if (isDark() !== wantDark && typeof window.toggleTheme === "function") { window.toggleTheme(); }
        lsSet("theme", mode === "system" ? null : mode);
        renderTheme();
    }
    var THEMES = [["light", N_("Light"), "sun"], ["dark", N_("Dark"), "moon"], ["system", N_("System"), "system"]];
    function renderTheme() {
        var b = $id("zxThemeBtn");
        if (!b) { return; }
        var m = themeMode(), cur = THEMES.filter(function (x) { return x[0] === m; })[0];
        b.innerHTML = ICON[cur[2]] + "<span class=\"zx-top-label\">" + esc(tr(cur[1])) + "</span>" + ICON.chev;
        var name = tr(N_("Theme")) + ": " + tr(cur[1]) + (m === "system" ? " (" + (isDark() ? tr(N_("Dark")) : tr(N_("Light"))) + ")" : "");
        b.setAttribute("aria-label", name);
        b.title = name;
    }
    try {
        var mq = window.matchMedia("(prefers-color-scheme: dark)");
        var onSys = function () { if (themeMode() === "system") { setThemeMode("system"); } };
        if (mq.addEventListener) { mq.addEventListener("change", onSys); } else if (mq.addListener) { mq.addListener(onSys); }
    } catch (e) { /* no matchMedia */ }
    document.addEventListener("zoraxy:theme", renderTheme);

    /* ---------------------------------------------------------------- language */
    function langCode() { return window.i18n ? window.i18n.lang : (document.documentElement.lang || "en"); }
    function langShort(c) { return c.toUpperCase(); }
    function langName(c) { var l = (window.i18n ? window.i18n.languages : []).filter(function (x) { return x[0] === c; })[0]; return l ? l[1] : c; }
    function renderLang() {
        var b = $id("zxLangBtn");
        if (!b) { return; }
        var c = langCode();
        b.innerHTML = ICON.globe + "<span class=\"zx-top-label\" data-i18n-skip>" + esc(langShort(c)) + "</span>" + ICON.chev;
        var name = tr(N_("Language")) + ": " + langName(c);
        b.setAttribute("aria-label", name);
        b.title = name;
    }
    document.addEventListener("zoraxy:i18n", function () { renderLang(); renderTheme(); renderAccount(); renderPills(); closeMenu(); });

    /* ---------------------------------------------------------------- account */
    function roleLabel(r) { return r === "viewer" ? tr(N_("Viewer (read-only)")) : tr(N_("Administrator")); }
    function renderAccount() {
        var b = $id("zxUserBtn");
        if (!b) { return; }
        if (!S.auth) { b.hidden = true; return; }
        b.hidden = false;
        b.innerHTML = "<span class=\"zx-avatar\" data-i18n-skip>" + esc((S.auth.user || "?").charAt(0)) + "</span><span class=\"zx-top-label zx-user-name\" data-i18n-skip>" + esc(S.auth.user || "") + "</span>" + ICON.chev;
        var name = tr(N_("Account")) + ": " + S.auth.user + " (" + roleLabel(S.auth.role) + ")";
        b.setAttribute("aria-label", name);
        b.title = name;
    }
    function initAccount() {
        getJSON("./api/auth/authEnabled").then(function (on) {
            if (on !== true) { return; }
            return Promise.all([getJSON("./api/auth/username").catch(function () { return ""; }), getJSON("./api/auth/role").catch(function () { return "admin"; })]).then(function (r) {
                S.auth = { user: typeof r[0] === "string" ? r[0] : "", role: r[1] || "admin" };
                renderAccount();
            });
        }).catch(function () { /* unknown: no account menu */ });
    }

    /* ---------------------------------------------------------------- menus */
    var open = null;   // {anchor, el}
    function closeMenu(focusBack) {
        if (!open) { return; }
        var o = open; open = null;
        o.anchor.setAttribute("aria-expanded", "false");
        if (o.el.parentNode) { o.el.parentNode.removeChild(o.el); }
        if (focusBack) { o.anchor.focus(); }
    }
    function itemsOf(el) { return Array.prototype.slice.call(el.querySelectorAll("[role^=menuitem]")).filter(function (x) { return x.offsetParent !== null || x.getClientRects().length; }); }

    // builders return html
    function themeItems(seg) {
        var m = themeMode();
        var html = THEMES.map(function (t) {
            return "<button type=\"button\" class=\"zx-mi" + (seg ? " zx-mi--seg" : "") + "\" role=\"menuitemradio\" aria-checked=\"" + (t[0] === m) + "\" data-theme=\"" + t[0] + "\">" + ICON[t[2]] + "<span class=\"zx-mi__t\">" + esc(tr(t[1])) + "</span>" + (seg ? "" : (t[0] === m ? ICON.check : "")) + "</button>";
        }).join("");
        return seg ? "<div class=\"zx-menu__row\">" + html + "</div>" : html;
    }
    function langItems(grid) {
        var c = langCode();
        var html = (window.i18n ? window.i18n.languages : []).map(function (l) {
            return "<button type=\"button\" class=\"zx-mi\" role=\"menuitemradio\" aria-checked=\"" + (l[0] === c) + "\" data-lang=\"" + esc(l[0]) + "\" lang=\"" + esc(l[0]) + "\" data-i18n-skip><span class=\"zx-mi__t\">" + esc(l[1]) + "</span>" + (l[0] === c ? ICON.check : "") + "</button>";
        }).join("");
        return grid ? "<div class=\"zx-menu__grid\">" + html + "</div>" : html;
    }
    function accountItems() {
        if (!S.auth) { return ""; }
        var changePw = tr(N_("Change password")), logOut = tr(N_("Log out"));
        return "<div class=\"zx-menu__head\" data-i18n-skip><b>" + esc(S.auth.user) + "</b><span>" + esc(roleLabel(S.auth.role)) + "</span></div>" +
            "<a class=\"zx-mi\" role=\"menuitem\" href=\"#utils\" data-tag=\"utils\">" + ICON.key + "<span class=\"zx-mi__t\">" + esc(changePw) + "</span></a>" +
            "<button type=\"button\" class=\"zx-mi zx-mi--danger\" role=\"menuitem\" data-act=\"logout\">" + ICON.out + "<span class=\"zx-mi__t\">" + esc(logOut) + "</span></button>";
    }
    function sec(t) { return "<div class=\"zx-menu__sec\" role=\"presentation\">" + esc(tr(t)) + "</div>"; }
    var BUILD = {
        theme: function () { return themeItems(false); },
        lang: function () { return langItems(false); },
        user: function () { return accountItems(); },
        more: function () {
            var l = pills();
            var html = "";
            if (l.length) { html += sec(N_("Status")) + l.map(function (d) { return pillHtml(d, true); }).join("") + "<div class=\"zx-menu__sep\" role=\"separator\"></div>"; }
            html += sec(N_("Theme")) + themeItems(true) + sec(N_("Language")) + langItems(true);
            if (S.auth) { html += "<div class=\"zx-menu__sep\" role=\"separator\"></div>" + accountItems(); }
            return html;
        }
    };

    function position(anchor, el) {
        var r = anchor.getBoundingClientRect(), vw = document.documentElement.clientWidth;
        el.style.top = Math.round(r.bottom + 6) + "px";
        if (vw > 748) {
            var w = el.offsetWidth, left = Math.min(Math.max(8, r.right - w), vw - w - 8);
            el.style.left = Math.round(left) + "px"; el.style.right = "auto";
        }
    }
    function openMenu(anchor, kind, focusFirst) {
        closeMenu();
        var el = document.createElement("div");
        el.className = "zx-menu"; el.setAttribute("role", "menu"); el.setAttribute("aria-label", anchor.getAttribute("aria-label") || "");
        el.setAttribute("data-menu", kind);
        el.innerHTML = BUILD[kind]();
        document.body.appendChild(el);
        anchor.setAttribute("aria-expanded", "true");
        open = { anchor: anchor, el: el, kind: kind };
        position(anchor, el);
        if (focusFirst !== false) {
            var items = itemsOf(el);
            var pick = el.querySelector("[aria-checked=true]") || items[0];
            if (pick) { pick.focus(); }
        }
    }
    function toggleMenu(anchor, kind, focusFirst) {
        if (open && open.anchor === anchor) { closeMenu(true); } else { openMenu(anchor, kind, focusFirst); }
    }

    function onMenuClick(e) {
        var t = e.target.closest && e.target.closest("[role^=menuitem]");
        if (!t || !open) { return; }
        var th = t.getAttribute("data-theme"), lg = t.getAttribute("data-lang"), act = t.getAttribute("data-act"), tag = t.getAttribute("data-tag");
        if (th) { setThemeMode(th); }
        else if (lg) { if (window.i18n) { window.i18n.setLanguage(lg); } }
        else if (act === "logout") { closeMenu(); if (typeof window.logout === "function") { window.logout(); } return; }
        else if (tag) { e.preventDefault(); closeMenu(); go(tag, t.getAttribute("data-kind")); return; }
        closeMenu(true);   // a choice closes the menu and returns focus to its button (the button shows the new value)
    }

    function onMenuKey(e) {
        if (!open) { return; }
        var inMenu = open.el.contains(document.activeElement);
        if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); closeMenu(true); return; }
        if (e.key === "Tab") { closeMenu(true); e.preventDefault(); return; }
        if (!inMenu) { return; }
        var items = itemsOf(open.el), i = items.indexOf(document.activeElement), n = items.length;
        if (!n) { return; }
        var next = -1;
        if (e.key === "ArrowDown" || e.key === "ArrowRight") { next = (i + 1) % n; }
        else if (e.key === "ArrowUp" || e.key === "ArrowLeft") { next = (i - 1 + n) % n; }
        else if (e.key === "Home") { next = 0; }
        else if (e.key === "End") { next = n - 1; }
        if (next >= 0) { e.preventDefault(); items[next].focus(); }
    }

    function bindButton(id, kind) {
        var b = $id(id);
        if (!b) { return; }
        b.setAttribute("aria-haspopup", "menu"); b.setAttribute("aria-expanded", "false");
        b.addEventListener("click", function (e) { e.preventDefault(); toggleMenu(b, kind, e.detail === 0); });
        b.addEventListener("keydown", function (e) {
            if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); openMenu(b, kind, true); }
        });
    }

    /* ---------------------------------------------------------------- boot */
    function init() {
        var bar = document.querySelector(".menubar");
        if (!bar) { return; }
        bindButton("zxThemeBtn", "theme"); bindButton("zxLangBtn", "lang"); bindButton("zxUserBtn", "user"); bindButton("zxMoreBtn", "more");
        var more = $id("zxMoreBtn");
        if (more) { more.innerHTML = ICON.dots; }
        var sb = $id("zxSearchBtn");
        if (sb && !sb.querySelector("svg")) { sb.insertAdjacentHTML("afterbegin", ICON.search); }
        var burger = $id("sidemenuBtn");
        if (burger) {
            burger.innerHTML = ICON.burger;
            burger.setAttribute("aria-controls", "mainmenu"); burger.setAttribute("aria-expanded", "false");
            burger.addEventListener("click", function () { setTimeout(function () { burger.setAttribute("aria-expanded", String(window.jQuery ? window.jQuery(".toolbar").is(":visible") : false)); }, 260); });
        }
        document.addEventListener("click", function (e) {
            if (open && open.el.contains(e.target)) { onMenuClick(e); return; }
            if (open && !(open.anchor.contains(e.target))) { closeMenu(); }
            var a = e.target.closest && e.target.closest("#zxTopStatus a[data-tag]");
            if (a) { e.preventDefault(); go(a.getAttribute("data-tag"), a.getAttribute("data-kind")); }
        }, true);
        document.addEventListener("keydown", onMenuKey, true);
        window.addEventListener("resize", function () { closeMenu(); });
        window.addEventListener("scroll", function (e) { if (open && !open.el.contains(e.target)) { closeMenu(); } }, true);
        window.addEventListener("hashchange", function () { closeMenu(); });
        renderTheme(); renderLang(); renderAccount();
        initAccount();
        startPolling();
        initUpdate();
    }
    if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", init); } else { init(); }
})();
