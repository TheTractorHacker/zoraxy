/*
    Command palette (window.ZxPalette): Ctrl+K / Cmd+K or the Search button in the header.

    Searches, all locally (nothing is sent anywhere except the existing GET /api/proxy/list the proxy page uses anyway):
      * pages        from the NAV array of nav.js (labels + synonyms)
      * sites        proxy hosts, fetched when the palette opens (cached, refreshed on every open)
      * settings     SETTINGS below: a static index of important settings -> page + anchor
      * actions      ACTIONS below
    Results are grouped, fuzzy matched, fully keyboard operated (type, Up/Down, Enter, Esc) and remembered as "Recent".

    Adding to the index:  one line in SETTINGS ({label, page, at, pre, kw}) or ACTIONS ({id, label, kw, run}).
      page  tag of the page (see nav.js)     at   CSS selector (inside the page) the palette scrolls to and highlights
      pre   optional selector clicked first (a tab or accordion that holds the setting)   text  fallback: text of a heading
    Every inserted piece of text goes through textContent (hosts and rule names are user data).
*/
(function () {
    "use strict";
    if (window.ZxPalette) { return; }
    function N_(s) { return s; }
    function tr(s) { return typeof window.t === "function" ? window.t(s) : s; }
    function trf(s) { var a = Array.prototype.slice.call(arguments, 1); return typeof window.tf === "function" ? window.tf.apply(window, [s].concat(a)) : s.replace(/\{(\d+)\}/g, function (m, n) { return a[+n] !== undefined ? a[+n] : m; }); }

    /* ----------------------------------------------------------------- static index of settings */
    var SETTINGS = [
        // Network > Listeners
        { label: N_("Listening port"), page: "globalsettings", at: "#incomingPort", kw: "inbound proxy port 443 80 bind" },
        { label: N_("Use TLS (HTTPS mode)"), page: "globalsettings", at: "#tls", kw: "https ssl serve encrypted" },
        { label: N_("HTTP server on port 80"), page: "globalsettings", at: "#listenP80", kw: "plain http listener" },
        { label: N_("HTTP listener address"), page: "globalsettings", at: "#httpListenAddrInput", kw: "port 80 bind address 8080" },
        { label: N_("Force redirect HTTP to HTTPS"), page: "globalsettings", at: "#redirect", kw: "ssl redirect upgrade insecure" },
        { label: N_("Minimum TLS version"), page: "globalsettings", pre: "#statusAdvanceSettings .title:not(.active)", at: "#tlsVersionSlider", kw: "tls 1.2 1.3 protocol legacy" },
        { label: N_("TLS cipher profile"), page: "globalsettings", pre: "#statusAdvanceSettings .title:not(.active)", at: "#tlsCipherProfileSelect", kw: "ciphers mozilla intermediate modern cbc" },
        { label: N_("PROXY protocol"), page: "globalsettings", pre: "#statusAdvanceSettings .title:not(.active)", at: "#proxyProtocol", kw: "haproxy real ip load balancer" },
        { label: N_("HTTP/3 (QUIC)"), page: "globalsettings", pre: "#statusAdvanceSettings .title:not(.active)", at: "#enableQuic", kw: "udp http3 quic" },
        { label: N_("Read header timeout"), page: "globalsettings", pre: "#statusAdvanceSettings .title:not(.active)", at: "#readHeaderTimeoutInput", kw: "slowloris timeouts idle write" },
        { label: N_("Sanitise client IP headers"), page: "globalsettings", pre: "#statusAdvanceSettings .title:not(.active)", at: "#sanitiseClientIP", kw: "x-forwarded-for spoof real ip" },
        { label: N_("Development mode"), page: "globalsettings", pre: "#statusAdvanceSettings .title:not(.active)", at: "#developmentMode", kw: "no-store cache-control" },
        { label: N_("Trusted proxy list"), page: "trustproxy", at: "#trustedProxyIpInput", kw: "cdn cloudflare add ip cidr" },
        // System > Settings
        { label: N_("Interface language"), page: "settings", at: "#uiLanguageSetting", kw: "locale translation english german chinese" },
        { label: N_("Default error pages"), page: "settings", at: "#defaultErrorPagesBtn", kw: "404 403 502 custom error html" },
        // Security
        { label: N_("Auto-ban"), page: "seccenter", pre: "#secTabs .item[data-sec='abuse']", at: "#abEnabled", kw: "ban abuse detectors automatic block ip" },
        { label: N_("Ban duration"), page: "seccenter", pre: "#secTabs .item[data-sec='abuse']", at: "#abBan", kw: "ban time seconds escalate" },
        { label: N_("Ban allowlist"), page: "seccenter", pre: "#secTabs .item[data-sec='abuse']", at: "#abAllow", kw: "never ban exclude ip" },
        { label: N_("Bot rules"), page: "seccenter", pre: "#secTabs .item[data-sec='bots']", at: "#brEnabled", kw: "crawler scraper user agent bad bots 403 blocked challenge" },
        { label: N_("Header rules"), page: "seccenter", pre: "#secTabs .item[data-sec='headers']", at: "#secTabs .item[data-sec='headers']", kw: "block request header" },
        { label: N_("Basic auth"), page: "seccenter", pre: "#secTabs .item[data-sec='basicauth']", at: "#secTabs .item[data-sec='basicauth']", kw: "password htaccess username" },
        { label: N_("Admin accounts"), page: "seccenter", pre: "#secTabs .item[data-sec='users']", at: "#secTabs .item[data-sec='users']", kw: "users viewer role management login" },
        { label: N_("Auth audit"), page: "seccenter", pre: "#secTabs .item[data-sec='authaudit']", at: "#secTabs .item[data-sec='authaudit']", kw: "failed logins log" },
        { label: N_("WAF mode"), page: "waf", pre: "#wafTabs .item[data-tab='waf-overview']", at: "#wafModeCards", kw: "firewall detect block off blocking detection only" },
        { label: N_("WAF paranoia level"), page: "waf", pre: "#wafTabs .item[data-tab='waf-policy']", at: "#wafpParanoia", kw: "firewall strictness crs level" },
        { label: N_("WAF anomaly threshold"), page: "waf", pre: "#wafTabs .item[data-tab='waf-policy']", at: "#wafpThreshold", kw: "firewall score sensitivity" },
        { label: N_("WAF request body limit"), page: "waf", pre: "#wafTabs .item[data-tab='waf-policy']", at: "#wafpBodyLimit", kw: "firewall upload size inspect" },
        { label: N_("WAF exclusions"), page: "waf", pre: "#wafTabs .item[data-tab='waf-exclusions']", at: "#wafTabs .item[data-tab='waf-exclusions']", kw: "firewall false positive ignore rule" },
        { label: N_("WAF events"), page: "waf", pre: "#wafTabs .item[data-tab='waf-events']", at: "#wafevEndpoint", kw: "firewall blocked requests log" },
        { label: N_("Country blacklist"), page: "access", at: "#enableBlacklist", kw: "geo ban block country deny" },
        { label: N_("IP blacklist"), page: "access", at: "#ipAddressInput", kw: "ban block address deny" },
        { label: N_("Whitelist mode"), page: "access", pre: ".accesscontrol.item[data-tab='tab_whitelist']", at: "#enableWhitelist", kw: "allow only ip country" },
        { label: N_("Quick ban list"), page: "access", pre: ".accesscontrol.item[data-tab='tab_quickban']", at: "#ipTable", kw: "ban ip temporary" },
        { label: N_("CAPTCHA challenge"), page: "captcha", at: "#cpGlobalBtn", kw: "turnstile recaptcha global default" },
        { label: N_("Forward authentication"), page: "sso", text: "Forward Auth", kw: "authentik authelia sso" },
        // Certificates
        { label: N_("Upload a certificate"), page: "cert", pre: "#certAddOpenBtn", at: "#certdomain", kw: "pem key import ssl" },
        { label: N_("Auto renew certificates"), page: "acme", at: "#enableCertAutoRenew", kw: "acme lets encrypt renewal" },
        { label: N_("ACME email"), page: "acme", at: "#prefACMEEmail", kw: "lets encrypt contact" },
        { label: N_("Preferred certificate authority"), page: "acme", at: "#defaultCA", kw: "ca lets encrypt zerossl buypass" },
        { label: N_("Renew certificates now"), page: "acme", at: "#acmeRenewNowBtn", kw: "acme force renew" },
        // Sites
        { label: N_("Search proxy rules"), page: "httprp", at: "#searchInput", kw: "find host domain filter" },
        { label: N_("Default site"), page: "setroot", at: "#proxyRoot", kw: "fallback unknown host root" },
        { label: N_("Static web server"), page: "webserv", at: "#webserv_enable", kw: "files directory listing" },
        { label: N_("WebDAV server"), page: "webserv", at: "#webdav_enable", kw: "webdav files share" },
        // System
        { label: N_("Check for updates"), page: "updater", at: "#upCheckBtn", kw: "upgrade version" },
        { label: N_("Update channel"), page: "updater", at: "#upChannel", kw: "stable beta release" },
        { label: N_("Create an API token"), page: "apitokens", at: "#atName", kw: "api key automation" },
        { label: N_("Change admin password"), page: "utils", text: "Change Password", kw: "login credentials" },
        { label: N_("Log rotation"), page: "utils", at: "#logRotationEnabled", kw: "logs size backups compress" },
        { label: N_("GeoIP database update"), page: "utils", at: "#geodbUpdateNowBtn", kw: "country database maxmind" },
        { label: N_("Backup and restore"), page: "utils", text: "System Backup & Restore", kw: "export import config" },
        { label: N_("Cluster primary URL"), page: "cluster", at: "#clPrimaryUrl", kw: "follower ha high availability" },
        { label: N_("Cluster secret"), page: "cluster", at: "#clGenBtn", kw: "ha shared key generate" },
        // Security > Rules (RULES-BUILDER)
        { label: N_("Create a security rule"), page: "ruleset", at: "#rbNew", kw: "rule builder when then block allow redirect log only condition" },
        { label: N_("Rule templates"), page: "ruleset", at: "#rbToggleTpl", kw: "quick start block country admin ip user agent rate limit redirect header" },
        { label: N_("Test a request against the rules"), page: "ruleset", pre: "#rbTabs .zx-tab[data-zx-panel='rbPanelTest']", at: "#rbTesterMount", kw: "request tester simulate dry run which rules match" },
        { label: N_("Named lists (IP, country, text)"), page: "ruleset", pre: "#rbTabs .zx-tab[data-zx-panel='rbPanelLists']", at: "#rbNewList", kw: "list office networks cidr countries allowlist blocklist" },
        { label: N_("Import existing rules as security rules"), page: "ruleset", pre: "#rbTabs .zx-tab[data-zx-panel='rbPanelImport']", at: "#rbImportScan", kw: "migrate convert path rules header rules bot rules access" }
    ];

    /* ----------------------------------------------------------------- actions */
    function goPage(tag, then) {
        if (typeof window.openTabById !== "function") { return; }
        window.openTabById(tag);
        if (then) { whenVisible("#" + tag, then, 4000); }
    }
    var wafOn = false;   // from GET /api/waf/policy when the palette opens: "Enable WAF" is not offered for a WAF that is on
    var ACTIONS = [
        { id: "newrule", label: N_("New proxy rule"), kw: "add create host site website", icon: "plus",
          run: function () { goPage("httprp", function () { if (typeof window.openNewRuleDialog === "function") { window.openNewRuleDialog(); } }); } },
        { id: "waf", label: N_("Enable WAF"), labelOn: N_("Review WAF mode"), isOn: function () { return wafOn; }, kw: "firewall protect start safely detection mode", icon: "shield alternate",
          run: function () { goPage("waf", function () { reveal("#wafQuickStart, #wafModeCards"); }); } },
        { id: "newsecrule", label: N_("New security rule"), kw: "add create rule builder when then block allow log only", icon: "filter",
          run: function () { goPage("ruleset", function () { var b = document.getElementById("rbNew"); if (b) { b.click(); } }); } },
        { id: "blocked", label: N_("Blocked requests"), kw: "403 blocked forbidden denied why reference id ref block log bot", icon: "ban",
          run: function () { goPage("stats", function () { if (typeof window.statsOpenBlocked === "function") { window.statsOpenBlocked({}); } }); } },
        { id: "update", label: N_("Check for updates"), kw: "upgrade new version release", icon: "download",
          run: function () { goPage("updater", function () { if (typeof window.upCheck === "function") { window.upCheck(true); } }); } },
        { id: "theme", label: N_("Toggle dark mode"), kw: "light theme night appearance", icon: "adjust",
          run: function () { if (typeof window.toggleTheme === "function") { window.toggleTheme(); } } },
        { id: "language", label: N_("Change language"), kw: "locale translation interface", icon: "language",
          run: function () { goPage("settings", function () { reveal("#uiLanguageSetting", true); }); } },
        { id: "autoban", label: N_("Set up auto-ban"), kw: "abuse block attackers", icon: "ban",
          run: function () { goSetting({ page: "seccenter", pre: "#secTabs .item[data-sec='abuse']", at: "#abEnabled" }); } }
    ];

    /* ----------------------------------------------------------------- navigation helpers */
    function whenVisible(sel, fn, timeout) {
        var t0 = Date.now();
        (function poll() {
            var el = document.querySelector(sel);
            if (el && el.offsetParent !== null && el.children.length) { setTimeout(function () { fn(el); }, 120); return; }
            if (Date.now() - t0 < (timeout || 3000)) { setTimeout(poll, 100); }
        })();
    }

    function findAnchor(page, spec) {
        var root = document.getElementById(page);
        if (!root) { return null; }
        if (spec.at) { var el = root.querySelector(spec.at); if (el) { return el; } }
        if (spec.text) {
            var cands = root.querySelectorAll("h1,h2,h3,h4,label,.title,button,b");
            for (var i = 0; i < cands.length; i++) { if (cands[i].textContent.indexOf(spec.text) >= 0 && cands[i].offsetParent !== null) { return cands[i]; } }
        }
        return null;
    }

    // scroll to an element and flash it
    function reveal(sel, focus) {
        var el = typeof sel === "string" ? document.querySelector(sel) : sel;
        if (!el) { return; }
        var box = el.closest(".field, .ui.checkbox, .ui.input, .ui.dropdown, .zx-field, .zx-toggle-row") || el;
        try { box.scrollIntoView({ block: "center", behavior: "smooth" }); } catch (e) { box.scrollIntoView(); }
        box.classList.add("zx-flash");
        setTimeout(function () { box.classList.remove("zx-flash"); }, 2200);
        if (focus && el.focus) { try { el.focus({ preventScroll: true }); } catch (e) { /* not focusable */ } }
    }

    function goSetting(s) {
        goPage(s.page);
        var t0 = Date.now(), clicked = false;
        (function poll() {
            var root = document.getElementById(s.page);
            if (!root || root.offsetParent === null || !root.children.length) { if (Date.now() - t0 < 5000) { setTimeout(poll, 120); } return; }
            if (s.pre && !clicked) {
                var pre = root.querySelector(s.pre);
                if (pre) { pre.click(); clicked = true; setTimeout(poll, 350); return; }
            }
            var el = findAnchor(s.page, s);
            if (el) { setTimeout(function () { reveal(el, /^(INPUT|SELECT|TEXTAREA|BUTTON)$/.test(el.tagName)); }, 150); return; }
            if (Date.now() - t0 < 5000) { setTimeout(poll, 150); }
        })();
    }

    function goHost(host) {
        goPage("httprp");
        whenVisible("#httpProxyList", function () {
            if (window.ProxyTable && typeof window.ProxyTable.highlight === "function") { window.ProxyTable.highlight(host); }
        }, 5000);
    }

    /* ----------------------------------------------------------------- matching */
    function norm(s) {
        s = String(s === undefined || s === null ? "" : s).toLowerCase();
        try { s = s.normalize("NFKD").replace(/[̀-ͯ]/g, ""); } catch (e) { /* old browser */ }
        return s;
    }
    function scoreWord(w, text, fuzzy) {
        var idx = text.indexOf(w);
        if (idx === 0) { return 100; }
        if (idx > 0) { return /[^a-z0-9]/.test(text.charAt(idx - 1)) ? 85 : Math.max(35, 60 - idx * 0.5); }
        if (fuzzy && w.length >= 4) {                 // fuzzy (labels only): characters in order, not too spread out
            var pos = -1, first = -1, i;
            for (i = 0; i < w.length; i++) {
                pos = text.indexOf(w.charAt(i), pos + 1);
                if (pos < 0) { return 0; }
                if (first < 0) { first = pos; }
            }
            var span = pos - first + 1;
            if (span <= w.length + 2) { return 25 - (span - w.length); }
        }
        return 0;
    }
    // returns 0 when any query word does not match
    function match(words, primary, secondary) {
        var total = 0;
        for (var i = 0; i < words.length; i++) {
            var s = Math.max(scoreWord(words[i], primary, true), 0.55 * scoreWord(words[i], secondary, false));
            if (s <= 0) { return 0; }
            total += s;
        }
        return total / words.length;
    }

    /* ----------------------------------------------------------------- data */
    var hosts = [], hostsAt = 0, hostsLoading = false;
    function loadHosts(done) {
        if (!window.jQuery || hostsLoading) { return; }
        hostsLoading = true;
        jQuery.getJSON("./api/proxy/list", { type: "host" }).done(function (list) {
            if (Array.isArray(list)) {
                hosts = list.filter(function (r) { return r && r.RootOrMatchingDomain; }).map(function (r) {
                    var ups = (r.ActiveOrigins || []).map(function (u) { return u && u.OriginIpOrDomain; }).filter(Boolean);
                    return { host: String(r.RootOrMatchingDomain), alias: (r.MatchingDomainAlias || []).map(String), tags: (r.Tags || []).map(String), upstreams: ups.map(String), disabled: !!r.Disabled };
                });
                hostsAt = Date.now();
            }
        }).always(function () { hostsLoading = false; if (done) { done(); } });
    }

    // Redirects, stream proxies, access rules and security rules. Names are user data: shown as text only.
    var objects = [];
    function loadObjects() {
        if (!window.jQuery) { return; }
        var next = [], pending = 4;
        function done() { if (--pending === 0) { objects = next; if (root && !root.hidden) { render(); } } }
        function get(url, fn) {
            jQuery.getJSON(url).done(function (d) { try { if (Array.isArray(d)) { d.forEach(fn); } } catch (e) { /* odd answer */ } }).always(done);
        }
        get("./api/redirect/list", function (r) {
            if (r && r.RedirectURL) { next.push({ type: "redirect", label: String(r.RedirectURL), sub: "→ " + String(r.TargetURL || ""), icon: "level up alternate", page: "redirectset", extra: String(r.TargetURL || "") }); }
        });
        get("./api/streamprox/config/list", function (r) {
            if (r && (r.Name || r.ListeningAddr)) { next.push({ type: "stream", label: String(r.Name || r.ListeningAddr), sub: String(r.ListeningAddr || "") + " → " + String(r.ProxyAddr || ""), icon: "exchange", page: "streamproxy", extra: String(r.ListeningAddr || "") + " " + String(r.ProxyAddr || "") }); }
        });
        get("./api/access/list", function (r) {
            if (r && r.Name) { next.push({ type: "access", label: String(r.Name), sub: String(r.Desc || ""), icon: "ban", page: "access", extra: String(r.Desc || "") }); }
        });
        get("./api/ruleset/rules", function (r) {
            if (r && r.name) { next.push({ type: "rule", label: String(r.name), sub: String(r.description || ""), icon: "filter", page: "ruleset", extra: String(r.description || "") + " " + String(r.expression || "") }); }
        });
    }
    function loadWafState() {
        if (!window.jQuery) { return; }
        jQuery.getJSON("./api/waf/policy").done(function (p) { wafOn = !!(p && p.Enabled); if (root && !root.hidden) { render(); } });
    }

    function allItems() {
        var items = [];
        (window.ZxNav ? ZxNav.pages() : []).forEach(function (p) {
            items.push({ type: "page", key: "page:" + p.tag, label: p.label, sub: p.group, icon: p.icon, extra: p.kw + " " + p.group + " " + p.tag, run: function () { window.openTabById(p.tag); } });
        });
        hosts.forEach(function (h) {
            items.push({ type: "site", key: "site:" + h.host, label: h.host, sub: (h.upstreams[0] ? "→ " + h.upstreams[0] : "") + (h.disabled ? " (disabled)" : ""), icon: "sitemap", raw: true,
                extra: h.alias.join(" ") + " " + h.tags.join(" ") + " " + h.upstreams.join(" "), run: function () { goHost(h.host); } });
        });
        SETTINGS.forEach(function (s, i) {
            var pg = window.ZxNav && ZxNav.find(s.page);
            items.push({ type: "setting", key: "setting:" + i + ":" + s.label, label: s.label, sub: pg ? pg.group.label + " › " + pg.item.label : s.page, icon: "sliders horizontal", extra: s.kw + " " + s.page, run: function () { goSetting(s); } });
        });
        objects.forEach(function (o) {
            items.push({ type: o.type, key: o.type + ":" + o.label, label: o.label, sub: o.sub, icon: o.icon, raw: true, extra: o.extra, run: function () { goPage(o.page); } });
        });
        ACTIONS.forEach(function (a) {
            var on = a.isOn && a.isOn();
            items.push({ type: "action", key: "action:" + a.id, label: on ? a.labelOn : a.label, sub: "", icon: a.icon, extra: a.kw, run: a.run });
        });
        return items;
    }

    var GROUPS = [["page", N_("Pages"), 8], ["site", N_("Sites"), 6], ["redirect", N_("Redirects"), 4], ["stream", N_("Stream proxies"), 4],
        ["access", N_("Access rules"), 4], ["rule", N_("Rules"), 5], ["setting", N_("Settings"), 8], ["action", N_("Actions"), 5]];
    var TYPE_BIAS = { page: 6, action: 4, setting: 0, site: 2, redirect: 2, stream: 2, access: 2, rule: 2 };

    function search(q) {
        var items = allItems();
        var words = norm(q).split(/\s+/).filter(Boolean);
        var out = [];
        if (!words.length) { return out; }
        items.forEach(function (it) {
            var lbl = it.raw ? it.label : tr(it.label);
            var primary = norm(lbl) + " " + (it.raw ? "" : norm(it.label));
            var s = match(words, primary, norm(it.extra + " " + it.sub));
            if (s > 0) {
                it.score = s + TYPE_BIAS[it.type] + (norm(lbl) === words.join(" ") ? 40 : 0) - lbl.length * 0.02;   // shorter labels are the more specific hit
                it.text = lbl;
                out.push(it);
            }
        });
        out.sort(function (a, b) { return b.score - a.score || a.text.localeCompare(b.text); });
        var actionNames = {};
        out.forEach(function (it) { if (it.type === "action") { actionNames[norm(it.text)] = true; } });
        return out.filter(function (it) { return !(it.type === "setting" && actionNames[norm(it.text)]); });
    }

    /* ----------------------------------------------------------------- recent */
    var RECENT_KEY = "zoraxy_palette_recent";
    function getRecent() { try { return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]") || []; } catch (e) { return []; } }
    function pushRecent(key) {
        var r = getRecent().filter(function (k) { return k !== key; });
        r.unshift(key);
        try { localStorage.setItem(RECENT_KEY, JSON.stringify(r.slice(0, 8))); } catch (e) { /* storage blocked */ }
    }

    /* A Reference ID (ZX-XXXX-XXXX, from a visitor's 403 page) or an IP address typed in the palette finds the block in Statistics > Blocked. */
    var REF_Q = /^zx[-\s]?[0-9a-z]{4}[-\s]?[0-9a-z]{4}$/i, IP_Q = /^(\d{1,3}\.){3}\d{1,3}$|^(?=[0-9a-f:.]*:)[0-9a-f:.]{3,45}$/i;
    function blockedJump(q) {
        var v = String(q || "").trim();
        var isRef = REF_Q.test(v);
        if (!isRef && !IP_Q.test(v)) { return null; }
        return { type: "blockedq", key: "blockedq:" + v, raw: true, icon: "ban", label: v, sub: isRef ? tr(N_("Find this block (Reference ID)")) : tr(N_("Blocked requests from this address")),
            run: function () { goPage("stats", function () { if (typeof window.statsOpenBlocked === "function") { window.statsOpenBlocked({ search: v }); } }); } };
    }

    /* ----------------------------------------------------------------- UI */
    var root = null, input = null, list = null, status = null, rows = [], active = -1, lastFocus = null, results = [];

    function build() {
        root = document.createElement("div");
        root.id = "zxPalette";
        root.className = "zx-palette-backdrop";
        root.hidden = true;
        root.innerHTML =
            "<div class=\"zx-palette\" role=\"dialog\" aria-modal=\"true\" aria-label=\"Command palette\">" +
            "<div class=\"zx-palette__search\"><i class=\"search icon\" aria-hidden=\"true\"></i>" +
            "<input type=\"text\" class=\"zx-palette__input\" role=\"combobox\" aria-expanded=\"true\" aria-controls=\"zxPaletteList\" aria-autocomplete=\"list\" autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\" placeholder=\"Search pages, sites, settings and actions\" aria-label=\"Search pages, sites, settings and actions\">" +
            "<button type=\"button\" class=\"zx-palette__close\" aria-label=\"Close\"><span>Esc</span></button></div>" +
            "<div id=\"zxPaletteList\" class=\"zx-palette__list\" role=\"listbox\" aria-label=\"Results\"></div>" +
            "<div class=\"zx-palette__foot\" aria-hidden=\"true\"><span><kbd>↑</kbd><kbd>↓</kbd> <span>to move</span></span><span><kbd>Enter</kbd> <span>to open</span></span><span><kbd>Esc</kbd> <span>to close</span></span></div>" +
            "<div class=\"zx-sr-only\" role=\"status\" aria-live=\"polite\" id=\"zxPaletteStatus\"></div></div>";
        document.body.appendChild(root);
        input = root.querySelector("input");
        list = root.querySelector(".zx-palette__list");
        status = root.querySelector("#zxPaletteStatus");
        input.addEventListener("input", render);
        input.addEventListener("keydown", onKey);
        root.addEventListener("mousedown", function (e) { if (e.target === root) { close(); } });
        root.querySelector(".zx-palette__close").addEventListener("click", close);
        list.addEventListener("mousemove", function (e) {
            var r = e.target.closest && e.target.closest("[role=option]");
            if (r) { setActive(rows.indexOf(r), false); }
        });
        list.addEventListener("click", function (e) {
            var r = e.target.closest && e.target.closest("[role=option]");
            if (r) { choose(rows.indexOf(r)); }
        });
        root.addEventListener("keydown", function (e) {
            if (e.key === "Tab") { e.preventDefault(); input.focus(); }
        });
    }

    function highlight(el, text, words) {
        if (!words.length) { el.textContent = text; return; }
        var low = norm(text), marks = new Array(text.length + 1).join("0").split("");
        if (low.length === text.length) {
            words.forEach(function (w) {
                var i = low.indexOf(w);
                if (i >= 0) { for (var k = i; k < i + w.length; k++) { marks[k] = "1"; } }
            });
        }
        var buf = "", on = false;
        function flush() {
            if (!buf) { return; }
            if (on) { var m = document.createElement("mark"); m.textContent = buf; el.appendChild(m); }
            else { el.appendChild(document.createTextNode(buf)); }
            buf = "";
        }
        for (var i = 0; i < text.length; i++) {
            var m1 = marks[i] === "1";
            if (m1 !== on) { flush(); on = m1; }
            buf += text.charAt(i);
        }
        flush();
    }

    function makeRow(it, idx, words) {
        var r = document.createElement("div");
        r.className = "zx-palette__item";
        r.setAttribute("role", "option");
        r.id = "zxPaletteOpt" + idx;
        r.setAttribute("aria-selected", "false");
        var ic = document.createElement("i");
        ic.className = (it.icon || "angle right") + " icon";
        ic.setAttribute("aria-hidden", "true");
        var tx = document.createElement("span");
        tx.className = "zx-palette__label";
        highlight(tx, it.raw ? it.label : (it.text || tr(it.label)), words);
        r.appendChild(ic);
        r.appendChild(tx);
        if (it.sub) {
            var sub = document.createElement("span");
            sub.className = "zx-palette__sub";
            sub.textContent = it.sub;
            r.appendChild(sub);
        }
        return r;
    }

    function render() {
        var q = input.value;
        var words = norm(q).split(/\s+/).filter(Boolean);
        list.textContent = "";
        rows = []; results = [];
        var groups = [];
        if (!words.length) {
            var all = allItems(), byKey = {};
            all.forEach(function (i) { byKey[i.key] = i; });
            var rec = getRecent().map(function (k) { return byKey[k]; }).filter(Boolean).slice(0, 6);
            if (rec.length) { groups.push([N_("Recent"), rec]); }
            groups.push([N_("Actions"), all.filter(function (i) { return i.type === "action"; }).slice(0, 5)]);
        } else {
            var res = search(q);
            var jump = blockedJump(q);   // a Reference ID or an IP address: offered first, it opens Statistics > Blocked with that search
            if (jump) { jump.score = 1000; groups.push([N_("Blocked requests"), [jump]]); }
            GROUPS.forEach(function (g) {
                var sel = res.filter(function (i) { return i.type === g[0]; }).slice(0, g[2]);
                if (sel.length) { groups.push([g[1], sel]); }
            });
            // best group first
            groups.sort(function (a, b) { return b[1][0].score - a[1][0].score; });
        }
        var n = 0;
        groups.forEach(function (g) {
            var grp = document.createElement("div");
            grp.setAttribute("role", "group");
            var head = document.createElement("div");
            head.className = "zx-palette__group";
            head.id = "zxPaletteG" + n;
            head.textContent = tr(g[0]);
            grp.setAttribute("aria-labelledby", head.id);
            grp.appendChild(head);
            g[1].forEach(function (it) {
                var row = makeRow(it, rows.length, words);
                grp.appendChild(row);
                rows.push(row);
                results.push(it);
            });
            list.appendChild(grp);
            n++;
        });
        if (!rows.length) {
            var none = document.createElement("div");
            none.className = "zx-palette__empty";
            none.textContent = words.length ? trf(N_("No results for \"{0}\""), q.trim()) : tr(N_("Type to search"));
            list.appendChild(none);
        }
        status.textContent = rows.length === 1 ? tr(N_("1 result")) : rows.length ? trf(N_("{0} results"), rows.length) : tr(N_("No results"));
        setActive(rows.length ? 0 : -1, true);
    }

    function setActive(i, scroll) {
        if (active >= 0 && rows[active]) { rows[active].setAttribute("aria-selected", "false"); rows[active].classList.remove("is-active"); }
        active = i;
        if (i >= 0 && rows[i]) {
            rows[i].setAttribute("aria-selected", "true");
            rows[i].classList.add("is-active");
            input.setAttribute("aria-activedescendant", rows[i].id);
            if (scroll) { rows[i].scrollIntoView({ block: "nearest" }); }
        } else { input.removeAttribute("aria-activedescendant"); }
    }

    function choose(i) {
        var it = results[i];
        if (!it) { return; }
        pushRecent(it.key);
        close(true);
        setTimeout(function () { try { it.run(); } catch (e) { console.error("palette action failed", e); } }, 0);
    }

    function onKey(e) {
        if (e.key === "ArrowDown") { e.preventDefault(); if (rows.length) { setActive((active + 1) % rows.length, true); } }
        else if (e.key === "ArrowUp") { e.preventDefault(); if (rows.length) { setActive((active - 1 + rows.length) % rows.length, true); } }
        else if (e.key === "Enter") { e.preventDefault(); choose(active); }
        else if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(); }
    }

    function open() {
        if (!root) { build(); }
        if (!root.hidden) { input.focus(); return; }
        lastFocus = document.activeElement;
        root.hidden = false;
        document.body.classList.add("zx-palette-open");
        input.value = "";
        loadHosts(function () { if (!root.hidden) { render(); } });
        loadObjects();
        loadWafState();
        render();
        input.focus();
        if (window.i18n && i18n.apply) { i18n.apply(root); }
    }
    function close(skipFocus) {
        if (!root || root.hidden) { return; }
        root.hidden = true;
        document.body.classList.remove("zx-palette-open");
        if (skipFocus !== true && lastFocus && lastFocus.focus) { try { lastFocus.focus(); } catch (e) { /* gone */ } }
    }

    document.addEventListener("keydown", function (e) {
        if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && (e.key === "k" || e.key === "K")) {
            e.preventDefault();
            if (root && !root.hidden) { close(); } else { open(); }
        }
    }, true);
    document.addEventListener("click", function (e) {
        if (e.target.closest && e.target.closest("#zxSearchBtn")) { open(); }
    });

    window.ZxPalette = {
        open: open, close: close, search: search, settings: SETTINGS, actions: ACTIONS,
        isOpen: function () { return !!root && !root.hidden; },
        hostCount: function () { return hosts.length; }
    };
})();
