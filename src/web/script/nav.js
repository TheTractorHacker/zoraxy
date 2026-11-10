/*
    Zoraxy admin UI navigation (window.ZxNav)

    THE MENU IS DEFINED HERE, in the NAV array below, and rendered into #navTree of index.html.
    Breadcrumbs and the command palette (script/palette.js) are derived from the same array.

    To add a page to the menu (one line, in the group it belongs to):
        1. index.html: add the component container      <div id="mypage" class="functiontab" target="mypage.html"></div>
        2. this file:  add one entry to the `items` of a group
               {tag: "mypage", label: N_("My page"), icon: "star", kw: "synonyms people may type"},
    That is all: menu entry, breadcrumb "Group > My page", palette result, deep link (#mypage), saved group state.
    Entry fields
        tag     id of the .functiontab container (also the URL hash). Never rename an existing one.
        label   English label wrapped in N_() so tools/i18n/extract.py finds it; translated by the DOM translator.
        icon    Fomantic UI (Font Awesome 5 free) icon name.
        kw      optional extra search words for the command palette ("firewall" finds the WAF).
        id      optional DOM id of the menu link (Quick Start uses it to show/hide itself).
        hidden  start hidden (the page shows the entry itself).
        dev     only shown when the server runs with -dev.
        href    instead of a tab: a link that opens in a new browser tab (used by the UI kit page).
    Group fields: id (suffix of #group-ID, saved in localStorage), label, icon, items, optional home (a tag the
    breadcrumb of the group links to, for groups that get an overview page).

    Old tag ids, group ids of the saved menu state (see MENU_GROUP_MIGRATION in index.html) and #hash deep links keep working.
*/
(function () {
    "use strict";
    if (window.ZxNav) { return; }

    // Marks a string for the i18n extractor; the text is translated in the DOM like all other UI text.
    function N_(s) { return s; }

    var NAV = [
        { id: "overview", label: N_("Overview"), icon: "home", items: [
            { tag: "status", label: N_("Status"), icon: "info circle", kw: "dashboard home health overview summary" },
            { tag: "qstart", label: N_("Quick Start"), icon: "magic", id: "qstartNavItem", hidden: true, kw: "setup wizard first run tour getting started" }
        ] },
        { id: "sites", label: N_("Sites"), icon: "sitemap", items: [
            { tag: "httprp", label: N_("HTTP Proxy"), icon: "sitemap", kw: "reverse proxy hosts domains upstream rules websites" },
            { tag: "setroot", label: N_("Default Site"), icon: "home", kw: "fallback catch all root unknown host" },
            { tag: "redirectset", label: N_("Redirection"), icon: "level up alternate", kw: "redirect 301 302 forward" },
            { tag: "vdir", label: N_("Path routes"), icon: "folder", kw: "virtual directory vdir path prefix subpath" },
            { tag: "streamproxy", label: N_("Stream Proxy"), icon: "exchange", kw: "tcp udp port forward stream" },
            { tag: "webserv", label: N_("Static Web Server"), icon: "globe", kw: "static files webdav web server hosting" },
            { tag: "rules", label: N_("Raw rule form"), icon: "plus square", kw: "advanced rule form create proxy rule manual" }
        ] },
        { id: "security", label: N_("Security"), icon: "shield alternate", items: [
            { tag: "secoverview", label: N_("Security Overview"), icon: "tachometer alternate", kw: "score posture overview protected recommendations fix harden checklist" },
            { tag: "seccenter", label: N_("Security Center"), icon: "user secret", kw: "auto ban autoban abuse bots header rules basic auth audit admin accounts users" },
            { tag: "waf", label: N_("WAF"), icon: "shield alternate", kw: "firewall web application owasp coraza crs attacks sql injection xss" },
            { tag: "access", label: N_("Access Rules"), icon: "ban", kw: "ban block blacklist whitelist allow deny ip country geo blocklist" },
            { tag: "sso", label: N_("SSO / OAuth2"), icon: "user circle", kw: "login oidc oauth authentication forward auth authentik single sign on" },
            { tag: "captcha", label: N_("CAPTCHA"), icon: "check square", kw: "challenge turnstile recaptcha bot human verification" }
        ] },
        { id: "certs", label: N_("Certificates"), icon: "certificate", items: [
            { tag: "cert", label: N_("TLS / SSL Certificates"), icon: "lock", kw: "ssl https certificate pem upload sni expire fallback" },
            { tag: "acme", label: N_("ACME Client"), icon: "asterisk", kw: "lets encrypt letsencrypt auto renew certificate authority dns challenge zerossl" }
        ] },
        { id: "traffic", label: N_("Traffic"), icon: "chart line", items: [
            { tag: "stats", label: N_("Statistics"), icon: "chart bar", kw: "analytics requests graphs countries top" },
            { tag: "visitors", label: N_("Visitors"), icon: "users", kw: "clients ips who visited logs" },
            { tag: "utm", label: N_("Uptime Monitor"), icon: "time", kw: "health check up down monitor ping availability" }
        ] },
        { id: "network", label: N_("Network"), icon: "random", items: [
            { tag: "globalsettings", label: N_("Listeners"), icon: "arrow alternate circle right", kw: "ingress port 443 80 listen tls http3 quic timeouts proxy protocol bind" },
            { tag: "trustproxy", label: N_("Trusted Proxies"), icon: "handshake", kw: "cdn cloudflare x-forwarded-for real ip proxy list" },
            { tag: "zrok", label: N_("Tunnels (zrok)"), icon: "plug", kw: "tunnel zrok openziti share expose" },
            { tag: "ech", label: N_("Encrypted Client Hello"), icon: "user secret", kw: "ech privacy sni encrypt" },
            { tag: "iface", label: N_("Network Interfaces"), icon: "wifi", kw: "adapters nic addresses ip" },
            { tag: "networktool", label: N_("Network Tools"), icon: "terminal", kw: "ping traceroute whois port scan mdns wake on lan wol ssh" }
        ] },
        { id: "ha", label: N_("Fleet & HA"), icon: "server", items: [
            { tag: "fleet", label: N_("Fleet"), icon: "cubes", kw: "hub nodes central management groups rollout sync" },
            { tag: "cluster", label: N_("Cluster / HA"), icon: "server", kw: "high availability primary follower failover replicate" }
        ] },
        { id: "system", label: N_("System"), icon: "cog", items: [
            { tag: "updater", label: N_("Update"), icon: "download", kw: "upgrade version release rollback" },
            { tag: "aiassist", label: N_("AI assistant"), icon: "lightbulb outline", kw: "claude llm model explain suggest rules ai assistant anthropic ollama" },
            { tag: "history", label: N_("History"), icon: "history", kw: "undo revert restore versions changes diff rollback snapshot backup" },
            { tag: "apitokens", label: N_("API Tokens"), icon: "key", kw: "api key automation bearer" },
            { tag: "plugins", label: N_("Plugin Manager"), icon: "puzzle piece", kw: "extensions addons plugins" },
            { tag: "appstore", label: N_("App Store"), icon: "shopping bag", kw: "plugin store marketplace" },
            { tag: "utils", label: N_("Utilities"), icon: "paperclip", kw: "password change backup restore logs geoip cidr tools" },
            { tag: "settings", label: N_("Settings"), icon: "cog", kw: "language interface locale error pages preferences" },
            { tag: "kit", label: N_("UI kit"), icon: "paint brush", dev: true, href: "ui/kit.html", kw: "components design tokens styleguide" }
        ] }
    ];

    var devMode = false;      // set by the /api/info/x answer
    var byTag = {};

    function index() {
        byTag = {};
        NAV.forEach(function (g) { g.items.forEach(function (it) { if (it.tag) { byTag[it.tag] = { group: g, item: it }; } }); });
    }
    index();

    function esc(s) { return window.ZxUI ? ZxUI.esc(s) : String(s).replace(/[&<>"']/g, function (c) { return "&#" + c.charCodeAt(0) + ";"; }); }

    /* ---------------------------------------------------------------- rendering */
    function itemHtml(g, it) {
        var attrs = it.tag && !it.href ? " tag=\"" + esc(it.tag) + "\" tab_group=\"" + esc(g.id) + "\" href=\"#" + esc(it.tag) + "\"" : "";
        if (it.href) { attrs = " data-nav-tag=\"" + esc(it.tag) + "\" tab_group=\"" + esc(g.id) + "\" href=\"" + esc(it.href) + "\" target=\"_blank\" rel=\"noopener\""; }
        if (it.id) { attrs += " id=\"" + esc(it.id) + "\""; }
        if (it.hidden || (it.dev && !devMode)) { attrs += " style=\"display:none;\""; }
        return "<a class=\"item" + (it.dev ? " nav-dev" : "") + "\"" + attrs + "><i class=\"simplistic " + esc(it.icon) + " icon\"></i> " + esc(it.label) + "</a>";
    }

    function render() {
        var host = document.getElementById("navTree");
        if (!host) { return; }
        var html = "";
        NAV.forEach(function (g) {
            var items = g.items.map(function (it) { return itemHtml(g, it); }).join("");
            if (!items) { return; }
            html += "<div class=\"menugroup-container\" data-group=\"" + esc(g.id) + "\">" +
                "<div class=\"menugroup-header\" role=\"button\" tabindex=\"0\" aria-expanded=\"true\" aria-controls=\"group-" + esc(g.id) + "\" data-group=\"" + esc(g.id) + "\">" +
                "<i class=\"" + esc(g.icon) + " icon menugroup-icon-i\" aria-hidden=\"true\"></i><span>" + esc(g.label) + "</span>" +
                "<i class=\"chevron down icon menugroup-chevron\" id=\"chevron-" + esc(g.id) + "\" aria-hidden=\"true\"></i></div>" +
                "<div class=\"menugroup-items\" id=\"group-" + esc(g.id) + "\" role=\"group\" aria-label=\"" + esc(g.label) + "\">" + items + "</div></div>";
        });
        host.innerHTML = html;
    }
    render();

    /* ---------------------------------------------------------------- lookups */
    function crumbsFor(tag) {
        var hit = byTag[tag];
        if (hit) {
            var c = [{ label: hit.group.label, tag: hit.group.home || null }];
            c.push({ label: hit.item.label, tag: tag, current: true });
            return c;
        }
        if (tag === "pluginContextWindow") { return [{ label: N_("Plugins"), tag: "plugins" }, { label: "", current: true, plugin: true }]; }
        return [{ label: tag || "", current: true }];
    }

    function crumbsHtml(list) {
        return "<ol>" + list.map(function (c) {
            if (c.current) { return "<li><span class=\"zx-crumb\" aria-current=\"page\">" + esc(c.label) + "</span></li>"; }
            if (c.tag) { return "<li><a href=\"#" + esc(c.tag) + "\" data-nav-open=\"" + esc(c.tag) + "\">" + esc(c.label) + "</a></li>"; }
            return "<li><span class=\"zx-crumb\">" + esc(c.label) + "</span></li>";
        }).join("") + "</ol>";
    }

    /* ---------------------------------------------------------------- breadcrumbs */
    var strip = null;
    function ensureStrip() {
        if (strip && strip.isConnected) { return strip; }
        strip = document.createElement("div");
        strip.id = "zxCrumbStrip";
        strip.className = "zx-crumbstrip";
        strip.innerHTML = "<nav class=\"zx-crumbs\" aria-label=\"Breadcrumb\"></nav>";
        var first = document.querySelector(".contentWindow .functiontab");
        if (first && first.parentNode) { first.parentNode.insertBefore(strip, first); }
        return strip;
    }

    function updateCrumbs(tag, btn) {
        var list = crumbsFor(tag);
        if (tag === "pluginContextWindow") {
            var name = btn && btn.length ? btn.text().replace(/\s+/g, " ").trim() : "";
            list[1].label = name || N_("Plugin");
        }
        var html = crumbsHtml(list);
        var s = ensureStrip();
        var slot = document.querySelector("#" + tag + " [data-zx-crumbs]");   // a page that renders its own page header
        if (slot) {
            slot.classList.add("zx-crumbs");
            slot.setAttribute("aria-label", "Breadcrumb");
            slot.innerHTML = html;
            s.hidden = true;
        } else {
            s.hidden = false;
            s.firstChild.innerHTML = html;
        }
    }

    /* ---------------------------------------------------------------- state on tab change (called by openTabById) */
    function onOpen(tag, btn) {
        try {
            var $ = window.jQuery;
            $("#mainmenu a.item[aria-current]").removeAttr("aria-current");
            $(btn).attr("aria-current", "page");
            updateCrumbs(tag, $(btn));
            document.dispatchEvent(new CustomEvent("zx:tabopen", { detail: { tag: tag } }));
        } catch (e) { console.error("ZxNav.onOpen", e); }
    }

    /* ---------------------------------------------------------------- keyboard: arrows move through the menu */
    function visibleFocusables() {
        var menu = document.getElementById("mainmenu");
        if (!menu) { return []; }
        return Array.prototype.filter.call(menu.querySelectorAll(".menugroup-header, a.item[tag], a.item[href], .recent-section-header, .recent-item, #navFilterInput"), function (n) {
            return n.offsetParent !== null && !n.classList.contains("navHidden");
        });
    }
    function initKeyboard() {
        var menu = document.getElementById("mainmenu");
        if (!menu) { return; }
        menu.addEventListener("keydown", function (e) {
            var t = e.target;
            if (t.tagName === "INPUT" && e.key !== "ArrowDown") { return; }
            var list = visibleFocusables(), i = list.indexOf(t);
            if (i < 0) { return; }
            if (e.key === "ArrowDown") { e.preventDefault(); (list[i + 1] || list[0]).focus(); }
            else if (e.key === "ArrowUp") { e.preventDefault(); (list[i - 1] || list[list.length - 1]).focus(); }
            else if (e.key === "Home") { e.preventDefault(); list[0].focus(); }
            else if (e.key === "End") { e.preventDefault(); list[list.length - 1].focus(); }
            else if ((e.key === "ArrowRight" || e.key === "ArrowLeft") && t.classList.contains("menugroup-header")) {
                var open = t.getAttribute("aria-expanded") !== "false";
                if ((e.key === "ArrowRight" && !open) || (e.key === "ArrowLeft" && open)) { e.preventDefault(); t.click(); }
                else if (e.key === "ArrowRight" && open) { e.preventDefault(); (list[i + 1] || t).focus(); }
            } else if (e.key === "ArrowLeft" && t.matches("a.item[tab_group]")) {
                var hdr = menu.querySelector(".menugroup-header[data-group='" + t.getAttribute("tab_group") + "']");
                if (hdr) { e.preventDefault(); hdr.focus(); }
            }
        });
        // group headers toggle their group (toggleMenuGroup lives in index.html and remembers the state)
        menu.addEventListener("click", function (e) {
            var h = e.target.closest && e.target.closest(".menugroup-header[data-group]");
            if (h && typeof window.toggleMenuGroup === "function") { window.toggleMenuGroup(h.getAttribute("data-group")); }
        });
        // links: a normal click opens the page in this app (the default navigation to #tag would jump the scroll position)
        menu.addEventListener("click", function (e) {
            var a = e.target.closest && e.target.closest("a.item[tag]");
            if (a) { e.preventDefault(); }
        });
        document.addEventListener("click", function (e) {
            var a = e.target.closest && e.target.closest("[data-nav-open]");
            if (a) { e.preventDefault(); if (typeof window.openTabById === "function") { window.openTabById(a.getAttribute("data-nav-open")); } }
        });
    }

    // keeps aria-expanded of the group headers in step with the real state (called by index.html after every toggle)
    function syncAria() {
        document.querySelectorAll("#mainmenu .menugroup-header[data-group]").forEach(function (h) {
            var items = document.getElementById("group-" + h.getAttribute("data-group"));
            var hidden = !items || items.style.display === "none" || getComputedStyle(items).display === "none";
            h.setAttribute("aria-expanded", hidden ? "false" : "true");
        });
    }

    /* ---------------------------------------------------------------- dev-only entries */
    function applyDevMode(dev) {
        if (!!dev === devMode) { return; }
        devMode = !!dev;
        document.querySelectorAll("#navTree .nav-dev").forEach(function (a) { a.style.display = devMode ? "" : "none"; });
    }

    window.ZxNav = {
        NAV: NAV,
        find: function (tag) { return byTag[tag] || null; },
        crumbsFor: crumbsFor,
        pages: function () {
            var out = [];
            NAV.forEach(function (g) { g.items.forEach(function (it) { if (it.tag && !it.href && !(it.dev && !devMode)) { out.push({ tag: it.tag, label: it.label, group: g.label, groupId: g.id, icon: it.icon, kw: it.kw || "" }); } }); });
            return out;
        },
        groupIds: function () { return NAV.map(function (g) { return g.id; }); },
        onOpen: onOpen,
        syncAria: syncAria,
        isDev: function () { return devMode; }
    };

    if (window.jQuery) {
        jQuery(function () {
            initKeyboard();
            ensureStrip();
            jQuery.get("./api/info/x", function (info) { if (info && info.Development) { applyDevMode(true); } });
        });
    }
})();
