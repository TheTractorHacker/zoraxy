/*
    aicrawlers.js: logic of the AI crawlers page (components/aicrawlers.html, API /api/aicrawler/*, package mod/aicrawler).

    Rules for this file:
      - everything that comes from the server or the configuration is escaped with ZxUI.esc before it becomes markup
      - the defaults (policy switch, purposes, crawlers) are one form with a Save bar; the per-site editor below is
        self-contained and saves with its own button, so the two never overwrite each other (each posts the last saved
        configuration with only its own part changed)
      - nothing is fetched from the internet by this page except when the Refresh ranges button is pressed
*/
(function () {
    "use strict";
    var root = document.getElementById("aiCrawlersPage");
    if (!root || !window.jQuery) { return; }
    var $ = window.jQuery;

    function t(s) { return typeof window.t === "function" ? window.t(s) : s; }
    function tf(s) {
        var a = Array.prototype.slice.call(arguments, 1);
        if (typeof window.tf === "function") { return window.tf.apply(null, [s].concat(a)); }
        return s.replace(/\{(\d+)\}/g, function (m, n) { return a[+n] !== undefined ? a[+n] : m; });
    }
    function esc(s) { return window.ZxUI ? ZxUI.esc(s == null ? "" : String(s)) : String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return "&#" + c.charCodeAt(0) + ";"; }); }
    function clone(o) { return JSON.parse(JSON.stringify(o)); }
    function q(sel) { return $(root).find(sel); }

    var state = { data: null, cfg: null, editing: null, edit: null };
    var bar = null;

    /* ---------------------------------------------------------------- labels */
    function actionLabel(a) {
        switch (a) {
            case "allow": return t("Allow");
            case "block": return t("Block");
            case "challenge": return t("Challenge (CAPTCHA)");
            case "ratelimit": return t("Rate limit");
            case "log": return t("Log only");
        }
        return t("No policy (unchanged)");
    }
    var ACTIONS = ["allow", "block", "challenge", "ratelimit", "log"];
    function decisionLabel(d) {
        switch (d) {
            case "allow": return t("Allowed");
            case "block": return t("Blocked");
            case "challenge": return t("Challenged");
            case "ratelimited": return t("Rate limited");
            case "spoofed": return t("Spoofed claim");
            case "log": return t("Logged only");
            case "default": return t("No policy (unchanged)");
        }
        return d;
    }
    function badge(kind, text) { return "<span class=\"zx-badge" + (kind ? " zx-badge--" + kind : "") + "\">" + esc(text) + "</span>"; }
    function groupTitle(id) {
        var g = (state.data.Groups || []).filter(function (x) { return x.id === id; })[0];
        return g ? g.title : id;
    }
    function options(list, selected, firstLabel) {
        var h = firstLabel === null ? "" : "<option value=\"\">" + esc(firstLabel) + "</option>";
        list.forEach(function (a) { h += "<option value=\"" + esc(a) + "\"" + (a === selected ? " selected" : "") + ">" + esc(actionLabel(a)) + "</option>"; });
        return h;
    }
    function fail(msg) { if (window.ZxUI) { ZxUI.toast(msg, { type: "error" }); } }
    function ok(msg) { if (window.ZxUI) { ZxUI.toast(msg, { type: "success" }); } }

    /* ---------------------------------------------------------------- load */
    function load(done) {
        $.ajax({ url: "/api/aicrawler/get", method: "GET", dataType: "json" }).done(function (d) {
            if (!d || d.error) { fail((d && d.error) || t("Request failed")); return; }
            state.data = d;
            state.cfg = d.Config;
            state.cfg.Global = state.cfg.Global || {};
            state.cfg.Sites = state.cfg.Sites || {};
            render();
            if (done) { done(); }
        }).fail(function () { fail(t("Request failed")); });
    }

    function render() {
        var d = state.data, c = state.cfg;
        var dirty = bar && bar.isDirty();
        q("#aicStateBadge").attr("class", "zx-badge " + (c.Enabled ? "zx-badge--ok" : "")).text(c.Enabled ? t("On") : t("Off"));
        q("#aicRegVersion").text(tf("List version {0}", d.RegistryVersion));
        if (!dirty) {
            renderGroups();
            renderRegistry();
            fillForm();
            if (bar) { bar.reset(); }
        }
        updateVerifyBadges();
        renderRanges();
        renderSites();
        renderTestSites();
        renderStats();
        renderPosture();
        var defMode = c.Robots && c.Robots.Mode ? c.Robots.Mode : "off";
        q("#aicRobotsDefault").val(defMode);
    }

    /* ---------------------------------------------------------------- defaults form */
    function renderGroups() {
        var h = "";
        (state.data.Groups || []).forEach(function (g) {
            h += "<div class=\"aic-grouprow\"><div><b>" + esc(g.title) + "</b><span class=\"aic-sub\">" + esc(g.text) + "</span></div>" +
                "<select class=\"zx-select\" id=\"aic-g-" + esc(g.id) + "\" data-group=\"" + esc(g.id) + "\" aria-label=\"" + esc(g.title) + "\" data-zx-label=\"" + esc(g.title) + "\">" +
                options(ACTIONS, "", t("No policy (unchanged)")) + "</select></div>";
        });
        q("#aicGroups").html(h);
    }

    function verifyInfo(e) {
        if (e.tokenOnly) { return { kind: "", text: t("robots.txt only") }; }
        if (!e.verifiable) { return { kind: "", text: t("Cannot be verified") }; }
        var hasRanges = (e.verify.rangeSources || []).length > 0, hasDNS = (e.verify.rdnsSuffixes || []).length > 0;
        if (hasDNS && !hasRanges) { return { kind: "ok", text: t("Reverse DNS") }; }
        if (e.rangesLoaded) { return { kind: "ok", text: t("Address ranges loaded") }; }
        return { kind: "warn", text: hasDNS ? t("Reverse DNS (ranges not loaded)") : t("Ranges not loaded") };
    }

    function renderRegistry() {
        var h = "";
        (state.data.Registry || []).forEach(function (e) {
            var acts = e.tokenOnly ? ["allow", "block"] : ACTIONS;
            h += "<tr data-id=\"" + esc(e.id) + "\">" +
                "<td data-label=\"" + esc(t("Crawler")) + "\" class=\"aic-name\"><b>" + esc(e.name) + "</b> <span class=\"aic-sub\">" + esc(e.operator) + "</span>" +
                (e.note ? "<div class=\"aic-sub\">" + esc(e.note) + "</div>" : "") + "</td>" +
                "<td data-label=\"" + esc(t("Purpose")) + "\">" + badge("info", groupTitle(e.group)) + " <span class=\"aic-sub\">" + esc(e.purpose) + "</span></td>" +
                "<td data-label=\"" + esc(t("Can it be verified?")) + "\"><span class=\"aic-vbadge\" data-id=\"" + esc(e.id) + "\"></span></td>" +
                "<td data-label=\"" + esc(t("Action")) + "\"><select class=\"zx-select\" id=\"aic-c-" + esc(e.id) + "\" data-crawler=\"" + esc(e.id) + "\" aria-label=\"" + esc(e.name) + "\" data-zx-label=\"" + esc(e.name) + "\">" +
                options(acts, "", t("Same as purpose")) + "</select></td></tr>";
        });
        q("#aicRegRows").html(h);
    }

    function updateVerifyBadges() {
        var by = {};
        (state.data.Registry || []).forEach(function (e) { by[e.id] = e; });
        q(".aic-vbadge").each(function () {
            var e = by[$(this).attr("data-id")];
            if (!e) { return; }
            var v = verifyInfo(e);
            $(this).html(badge(v.kind, v.text));
        });
    }

    function fillForm() {
        var g = state.cfg.Global;
        q("#aicEnabled").prop("checked", !!state.cfg.Enabled);
        q("#aicVerified").prop("checked", !!g.VerifiedOnly);
        q("#aicSpoof").val(g.SpoofAction || "block");
        q("#aicRate").val(g.RateLimitPerMinute || state.data.DefaultRateLimit || 30);
        q("#aicBypass").prop("checked", !!g.BypassWAF);
        q("select[data-group]").each(function () { $(this).val((g.Groups || {})[$(this).attr("data-group")] || ""); });
        q("select[data-crawler]").each(function () { $(this).val((g.Crawlers || {})[$(this).attr("data-crawler")] || ""); });
    }

    function readForm() {
        var c = clone(state.cfg);
        var rate = q("#aicRate").val().trim();
        var f = ZxUI.field("#aicRate");
        f.clearError();
        if (!/^\d+$/.test(rate) || +rate < 1 || +rate > 100000) {
            f.setError(t("Enter a whole number from 1 to 100000"));
            q("#aicRate").focus();
            return null;
        }
        c.Enabled = q("#aicEnabled").prop("checked");
        c.Global = c.Global || {};
        c.Global.Groups = {};
        c.Global.Crawlers = {};
        q("select[data-group]").each(function () { if ($(this).val()) { c.Global.Groups[$(this).attr("data-group")] = $(this).val(); } });
        q("select[data-crawler]").each(function () { if ($(this).val()) { c.Global.Crawlers[$(this).attr("data-crawler")] = $(this).val(); } });
        c.Global.VerifiedOnly = q("#aicVerified").prop("checked");
        c.Global.SpoofAction = q("#aicSpoof").val() || "block";
        c.Global.RateLimitPerMinute = +rate;
        c.Global.BypassWAF = q("#aicBypass").prop("checked");
        return c;
    }

    function post(cfg) {
        return $.cjax({ url: "/api/aicrawler/set", method: "POST", dataType: "json", data: { config: JSON.stringify(cfg) } }).then(function (res) {
            if (res && res.error) { return res; }
            state.cfg = cfg;
            return res;
        });
    }

    function saveForm() {
        var c = readForm();
        if (!c) { return { error: t("Some values are out of range. Fix the highlighted fields and save again.") }; }
        return post(c).then(function (res) {
            if (!(res && res.error)) { load(); }
            return res;
        });
    }

    /* ---------------------------------------------------------------- ranges */
    function renderRanges() {
        var h = "";
        (state.data.Ranges || []).forEach(function (r) {
            var status = r.loaded ? badge("ok", tf("{0} ranges", r.count)) + " <span class=\"aic-sub\">" + esc(new Date(r.fetched * 1000).toLocaleString()) + "</span>" : badge("", t("Not loaded"));
            h += "<tr><td data-label=\"" + esc(t("List")) + "\"><span class=\"aic-mono\">" + esc(r.url) + "</span></td>" +
                "<td data-label=\"" + esc(t("Used for")) + "\">" + esc((r.usedBy || []).join(", ")) + "</td>" +
                "<td data-label=\"" + esc(t("Loaded")) + "\">" + status + "</td></tr>";
        });
        q("#aicRangeRows").html(h);
    }

    q("#aicRefresh").on("click", function () {
        var btn = this;
        ZxUI.setLoading(btn, true);
        q("#aicRefreshMsg").text(t("Fetching..."));
        $.cjax({ url: "/api/aicrawler/ranges/refresh", method: "POST", dataType: "json", data: {} }).done(function (res) {
            if (res && res.error) { q("#aicRefreshMsg").text(res.error); fail(res.error); return; }
            var okN = 0, bad = [];
            (res.Results || []).forEach(function (r) { if (r.ok) { okN++; } else { bad.push(r.id + ": " + r.error); } });
            q("#aicRefreshMsg").text(tf("{0} of {1} lists refreshed", okN, (res.Results || []).length) + (bad.length ? " (" + bad.join("; ") + ")" : ""));
            if (okN) { ok(tf("{0} lists refreshed", okN)); }
            if (bad.length && !okN) { fail(t("No list could be refreshed")); }
            load();
        }).fail(function () { q("#aicRefreshMsg").text(t("Request failed")); }).always(function () { ZxUI.setLoading(btn, false); });
    });

    /* ---------------------------------------------------------------- sites */
    function siteKeys() {
        var seen = {}, list = [];
        (state.data.Sites || []).forEach(function (s) { seen[s.key] = s; list.push(s.key); });
        Object.keys(state.cfg.Sites || {}).forEach(function (k) { if (!seen[k]) { list.push(k); } });
        return { keys: list, info: seen };
    }

    function robotsText(mode, isDefault) {
        switch (mode) {
            case "merge": return t("Add to the site's file");
            case "serve": return t("Serve instead");
        }
        return isDefault ? t("Off") : t("Off");
    }

    function renderSites() {
        var sk = siteKeys(), h = "";
        var defMode = (state.cfg.Robots && state.cfg.Robots.Mode) || "off";
        if (!sk.keys.length) {
            q("#aicSiteRows").html("<tr><td colspan=\"5\"><div class=\"zx-empty\"><div class=\"zx-empty__title\">" + esc(t("No sites yet")) + "</div><div class=\"zx-empty__text\">" +
                esc(t("Add a proxy rule on the HTTP Proxy page, then set a policy for it here.")) + "</div></div></td></tr>");
            return;
        }
        sk.keys.forEach(function (k) {
            var s = (state.cfg.Sites || {})[k] || {}, info = sk.info[k];
            var pol;
            if (s.Mode === "off") { pol = badge("warn", t("Off for this site")); }
            else if (s.Mode === "custom") { pol = badge("info", t("Custom")); }
            else { pol = badge("", t("Follows the defaults")); }
            if (info && info.legacyBlock) { pol += " " + badge("", t("AI crawlers switch on")); }
            if (!info) { pol += " " + badge("warn", t("Rule removed")); }
            var rm = s.Robots && s.Robots.Mode ? s.Robots.Mode : "";
            var rtxt = rm ? robotsText(rm) : tf("Follows the default ({0})", robotsText(defMode, true));
            var lm = s.LLMS && s.LLMS.Mode && s.LLMS.Text ? s.LLMS.Mode : "off";
            var ltxt = lm === "serve" ? t("Serve instead") : (lm === "fallback" ? t("Only if the site has none") : t("Off"));
            h += "<tr><td data-label=\"" + esc(t("Site")) + "\"><span class=\"aic-mono\">" + esc(k) + "</span></td>" +
                "<td data-label=\"" + esc(t("Policy")) + "\">" + pol + "</td>" +
                "<td data-label=\"" + esc(t("robots.txt")) + "\">" + esc(rtxt) + "</td>" +
                "<td data-label=\"" + esc(t("llms.txt")) + "\">" + esc(ltxt) + "</td>" +
                "<td class=\"zx-actions\"><button type=\"button\" class=\"zx-btn zx-btn--secondary zx-btn--sm aicEditSite\" data-site=\"" + esc(k) + "\" aria-label=\"" + esc(tf("Edit {0}", k)) + "\">" + esc(t("Edit")) + "</button></td></tr>";
        });
        q("#aicSiteRows").html(h);
    }

    q("#aicSiteRows").on("click", ".aicEditSite", function () { openEditor($(this).attr("data-site")); });

    function blankSite() { return { Mode: "", Custom: { Groups: {}, Crawlers: {} }, Robots: { Mode: "" }, LLMS: { Mode: "off", Text: "" } }; }
    function triOptions(val) {
        return "<option value=\"\"" + (val == null ? " selected" : "") + ">" + esc(t("Same as the defaults")) + "</option>" +
            "<option value=\"on\"" + (val === true ? " selected" : "") + ">" + esc(t("On")) + "</option>" +
            "<option value=\"off\"" + (val === false ? " selected" : "") + ">" + esc(t("Off")) + "</option>";
    }
    function tri(sel) { var v = q(sel).val(); return v === "on" ? true : (v === "off" ? false : undefined); }

    function openEditor(key) {
        state.editing = key;
        var s = clone((state.cfg.Sites || {})[key] || blankSite());
        s.Custom = s.Custom || {};
        s.Custom.Groups = s.Custom.Groups || {};
        s.Custom.Crawlers = s.Custom.Crawlers || {};
        s.Robots = s.Robots || { Mode: "" };
        s.LLMS = s.LLMS || { Mode: "off", Text: "" };
        state.edit = s;
        var h = "<div class=\"zx-card__head\"><h3 class=\"zx-card__title\">" + esc(t("Site")) + ": <span class=\"aic-mono\">" + esc(key) + "</span></h3>" +
            "<button type=\"button\" class=\"zx-btn zx-btn--ghost zx-btn--sm\" id=\"aicSClose\">" + esc(t("Close")) + "</button></div><div class=\"zx-card__body aic-stack\">";
        h += "<div class=\"zx-field\"><div class=\"zx-field__label-row\"><label class=\"zx-field__label\" for=\"aicSMode\">" + esc(t("Policy for this site")) + "</label></div>" +
            "<div class=\"zx-field__control\"><select class=\"zx-select\" id=\"aicSMode\" style=\"max-width:28rem\">" +
            "<option value=\"\">" + esc(t("Follow the defaults")) + "</option><option value=\"custom\">" + esc(t("Custom: the defaults with my changes")) + "</option>" +
            "<option value=\"off\">" + esc(t("Off for this site (behaves as before)")) + "</option></select></div></div>";
        h += "<div id=\"aicSCustom\" class=\"aic-stack\"><div class=\"aic-fields\">";
        (state.data.Groups || []).forEach(function (g) {
            h += "<div class=\"zx-field\"><div class=\"zx-field__label-row\"><label class=\"zx-field__label\" for=\"aicSg-" + esc(g.id) + "\">" + esc(g.title) + "</label></div>" +
                "<div class=\"zx-field__control\"><select class=\"zx-select aicSG\" id=\"aicSg-" + esc(g.id) + "\" data-group=\"" + esc(g.id) + "\">" + options(ACTIONS, s.Custom.Groups[g.id] || "", t("Same as the defaults")) + "</select></div></div>";
        });
        h += "</div><div><b>" + esc(t("Single crawlers on this site")) + "</b><div id=\"aicSOver\"></div>" +
            "<div class=\"aic-over\"><select class=\"zx-select\" id=\"aicSAddC\" style=\"width:auto\" aria-label=\"" + esc(t("Crawler")) + "\">";
        (state.data.Registry || []).forEach(function (e) { h += "<option value=\"" + esc(e.id) + "\">" + esc(e.name) + "</option>"; });
        h += "</select><select class=\"zx-select\" id=\"aicSAddA\" style=\"width:auto\" aria-label=\"" + esc(t("Action")) + "\">" + options(ACTIONS, "", null) + "</select>" +
            "<button type=\"button\" class=\"zx-btn zx-btn--secondary zx-btn--sm\" id=\"aicSAdd\">" + esc(t("Add")) + "</button></div></div>";
        h += "<div class=\"aic-fields\">" +
            "<div class=\"zx-field\"><div class=\"zx-field__label-row\"><label class=\"zx-field__label\" for=\"aicSVer\">" + esc(t("Verified crawlers only")) + "</label></div><div class=\"zx-field__control\"><select class=\"zx-select\" id=\"aicSVer\">" + triOptions(s.Custom.VerifiedOnly) + "</select></div></div>" +
            "<div class=\"zx-field\"><div class=\"zx-field__label-row\"><label class=\"zx-field__label\" for=\"aicSSpoof\">" + esc(t("When the check fails (spoofed)")) + "</label></div><div class=\"zx-field__control\"><select class=\"zx-select\" id=\"aicSSpoof\">" +
            "<option value=\"\">" + esc(t("Same as the defaults")) + "</option><option value=\"block\">" + esc(t("Block")) + "</option><option value=\"challenge\">" + esc(t("Challenge (CAPTCHA)")) + "</option><option value=\"log\">" + esc(t("Log only")) + "</option></select></div></div>" +
            "<div class=\"zx-field\"><div class=\"zx-field__label-row\"><label class=\"zx-field__label\" for=\"aicSRate\">" + esc(t("Rate limit (requests per minute)")) + "</label></div><div class=\"zx-field__control\"><input class=\"zx-input zx-input--short\" type=\"number\" min=\"1\" max=\"100000\" id=\"aicSRate\" placeholder=\"" + esc(t("same as the defaults")) + "\"></div></div>" +
            "<div class=\"zx-field\"><div class=\"zx-field__label-row\"><label class=\"zx-field__label\" for=\"aicSBypass\">" + esc(t("Skip the WAF for verified, allowed crawlers")) + "</label></div><div class=\"zx-field__control\"><select class=\"zx-select\" id=\"aicSBypass\">" + triOptions(s.Custom.BypassWAF) + "</select></div></div>" +
            "</div></div>";
        h += "<div class=\"aic-fields\"><div class=\"zx-field\"><div class=\"zx-field__label-row\"><label class=\"zx-field__label\" for=\"aicSRobots\">robots.txt</label></div><div class=\"zx-field__control\"><select class=\"zx-select\" id=\"aicSRobots\">" +
            "<option value=\"\">" + esc(t("Follow the default")) + "</option><option value=\"off\">" + esc(t("Off (do not touch robots.txt)")) + "</option><option value=\"merge\">" + esc(t("Add to the site's own file")) + "</option><option value=\"serve\">" + esc(t("Serve instead of the site's own file")) + "</option></select></div>" +
            "<p class=\"zx-help\">" + esc(t("Advisory only: a crawler can ignore it. Blocking is done by the actions above.")) + "</p></div>" +
            "<div class=\"zx-field\"><div class=\"zx-field__label-row\"><label class=\"zx-field__label\" for=\"aicSLlms\">llms.txt</label></div><div class=\"zx-field__control\"><select class=\"zx-select\" id=\"aicSLlms\">" +
            "<option value=\"off\">" + esc(t("Off")) + "</option><option value=\"serve\">" + esc(t("Serve instead of the site's own file")) + "</option><option value=\"fallback\">" + esc(t("Only when the site has none")) + "</option></select></div></div></div>";
        h += "<div class=\"zx-field\"><div class=\"zx-field__label-row\"><label class=\"zx-field__label\" for=\"aicSLlmsText\">" + esc(t("llms.txt text")) + "</label></div><div class=\"zx-field__control\"><textarea class=\"zx-textarea\" id=\"aicSLlmsText\" rows=\"6\" maxlength=\"65536\" spellcheck=\"false\"></textarea></div>" +
            "<p class=\"zx-help\">" + esc(t("Plain text or Markdown that describes the site for AI tools. Served as text/plain. Used only when llms.txt is not off.")) + "</p></div>";
        h += "<div class=\"zx-row\"><button type=\"button\" class=\"zx-btn zx-btn--primary\" id=\"aicSSave\">" + esc(t("Save site")) + "</button>" +
            "<button type=\"button\" class=\"zx-btn zx-btn--secondary\" id=\"aicSPreview\">" + esc(t("Preview saved robots.txt")) + "</button>" +
            "<button type=\"button\" class=\"zx-btn zx-btn--danger-outline\" id=\"aicSReset\">" + esc(t("Remove this site's settings")) + "</button></div>" +
            "<pre class=\"aic-pre\" id=\"aicSPre\" hidden></pre></div>";
        var box = q("#aicSiteEditor");
        box.html(h).prop("hidden", false);
        q("#aicSMode").val(s.Mode || "");
        q("#aicSVer").val(s.Custom.VerifiedOnly == null ? "" : (s.Custom.VerifiedOnly ? "on" : "off"));
        q("#aicSSpoof").val(s.Custom.SpoofAction || "");
        q("#aicSRate").val(s.Custom.RateLimitPerMinute || "");
        q("#aicSBypass").val(s.Custom.BypassWAF == null ? "" : (s.Custom.BypassWAF ? "on" : "off"));
        q("#aicSRobots").val(s.Robots.Mode || "");
        q("#aicSLlms").val(s.LLMS.Mode || "off");
        q("#aicSLlmsText").val(s.LLMS.Text || "");
        renderOverrides();
        syncCustom();
        box[0].scrollIntoView({ block: "nearest", behavior: "smooth" });
        q("#aicSMode").focus();
    }

    function syncCustom() { q("#aicSCustom").prop("hidden", q("#aicSMode").val() !== "custom"); }

    function renderOverrides() {
        var names = {};
        (state.data.Registry || []).forEach(function (e) { names[e.id] = e.name; });
        var cr = state.edit.Custom.Crawlers, ids = Object.keys(cr), h = "";
        if (!ids.length) { h = "<p class=\"aic-sub\">" + esc(t("None: every crawler follows its purpose.")) + "</p>"; }
        ids.forEach(function (id) {
            h += "<div class=\"aic-over\"><span><b>" + esc(names[id] || id) + "</b>: " + esc(actionLabel(cr[id])) + "</span>" +
                "<button type=\"button\" class=\"zx-btn zx-btn--ghost zx-btn--sm aicSDel\" data-id=\"" + esc(id) + "\" aria-label=\"" + esc(tf("Remove the setting for {0}", names[id] || id)) + "\">" + esc(t("Remove")) + "</button></div>";
        });
        q("#aicSOver").html(h);
    }

    q("#aicSiteEditor").on("change", "#aicSMode", syncCustom);
    q("#aicSiteEditor").on("click", "#aicSClose", function () { q("#aicSiteEditor").prop("hidden", true).empty(); state.editing = null; });
    q("#aicSiteEditor").on("click", "#aicSAdd", function () {
        var id = q("#aicSAddC").val(), a = q("#aicSAddA").val();
        var e = (state.data.Registry || []).filter(function (x) { return x.id === id; })[0];
        if (e && e.tokenOnly && a !== "allow" && a !== "block") { fail(tf("{0} is a robots.txt token: only Allow or Block make sense.", e.name)); return; }
        state.edit.Custom.Crawlers[id] = a;
        renderOverrides();
    });
    q("#aicSiteEditor").on("click", ".aicSDel", function () { delete state.edit.Custom.Crawlers[$(this).attr("data-id")]; renderOverrides(); });

    function collectSite() {
        var s = state.edit;
        s.Mode = q("#aicSMode").val();
        s.Custom.Groups = {};
        q(".aicSG").each(function () { if ($(this).val()) { s.Custom.Groups[$(this).attr("data-group")] = $(this).val(); } });
        var v = tri("#aicSVer"), b = tri("#aicSBypass");
        if (v === undefined) { delete s.Custom.VerifiedOnly; } else { s.Custom.VerifiedOnly = v; }
        if (b === undefined) { delete s.Custom.BypassWAF; } else { s.Custom.BypassWAF = b; }
        s.Custom.SpoofAction = q("#aicSSpoof").val() || "";
        var rate = q("#aicSRate").val().trim();
        var f = ZxUI.field("#aicSRate");
        f.clearError();
        if (rate !== "" && (!/^\d+$/.test(rate) || +rate < 1 || +rate > 100000)) {
            f.setError(t("Enter a whole number from 1 to 100000, or leave empty"));
            q("#aicSRate").focus();
            return null;
        }
        s.Custom.RateLimitPerMinute = rate === "" ? 0 : +rate;
        s.Robots = { Mode: q("#aicSRobots").val() };
        s.LLMS = { Mode: q("#aicSLlms").val(), Text: q("#aicSLlmsText").val() };
        return s;
    }

    function isEmptySite(s) {
        var c = s.Custom || {};
        return !s.Mode && !(s.Robots && s.Robots.Mode) && !(s.LLMS && s.LLMS.Text) && !Object.keys(c.Groups || {}).length && !Object.keys(c.Crawlers || {}).length &&
            c.VerifiedOnly == null && !c.SpoofAction && !c.RateLimitPerMinute && c.BypassWAF == null;
    }

    q("#aicSiteEditor").on("click", "#aicSSave", function () {
        var s = collectSite();
        if (!s) { return; }
        var key = state.editing, btn = this;
        var cfg = clone(state.cfg);
        cfg.Sites = cfg.Sites || {};
        if (isEmptySite(s)) { delete cfg.Sites[key]; } else { cfg.Sites[key] = s; }
        ZxUI.setLoading(btn, true);
        post(cfg).done(function (res) {
            if (res && res.error) { fail(res.error); return; }
            ok(tf("Saved the settings of {0}", key));
            load(function () { showPreview(key); });
        }).fail(function () { fail(t("Request failed")); }).always(function () { ZxUI.setLoading(btn, false); });
    });

    q("#aicSiteEditor").on("click", "#aicSReset", function () {
        var key = state.editing;
        ZxUI.confirm({ title: t("Remove the settings of this site?"), message: tf("{0} will follow the defaults again.", key), confirmLabel: t("Remove"), danger: true }).then(function (yes) {
            if (!yes) { return; }
            var cfg = clone(state.cfg);
            delete (cfg.Sites || {})[key];
            post(cfg).done(function (res) {
                if (res && res.error) { fail(res.error); return; }
                ok(tf("Removed the settings of {0}", key));
                q("#aicSiteEditor").prop("hidden", true).empty();
                state.editing = null;
                load();
            });
        });
    });

    function showPreview(key) {
        $.ajax({ url: "/api/aicrawler/preview", data: { site: key }, method: "GET", dataType: "json" }).done(function (d) {
            var pre = q("#aicSPre");
            if (!pre.length || !d) { return; }
            var mode = (state.cfg.Sites[key] && state.cfg.Sites[key].Robots && state.cfg.Sites[key].Robots.Mode) || (state.cfg.Robots && state.cfg.Robots.Mode) || "off";
            var head = !state.cfg.Enabled ? t("The policy is off, so nothing is served. The text below is what would be generated:") :
                (mode === "serve" ? t("Served instead of the site's own file:") : (mode === "merge" ? t("Added after the site's own file:") : t("robots.txt is off for this site. The text below is what would be generated:")));
            pre.text(head + "\n\n" + (mode === "merge" ? (d.RobotsAppend || t("(nothing to add: no crawler is blocked or allowed)")) : d.Robots)).prop("hidden", false);
        });
    }
    q("#aicSiteEditor").on("click", "#aicSPreview", function () { showPreview(state.editing); });

    q("#aicRobotsDefaultSave").on("click", function () {
        var cfg = clone(state.cfg);
        cfg.Robots = { Mode: q("#aicRobotsDefault").val() };
        var btn = this;
        ZxUI.setLoading(btn, true);
        post(cfg).done(function (res) {
            if (res && res.error) { fail(res.error); return; }
            ok(t("Saved the default robots.txt setting"));
            load();
        }).fail(function () { fail(t("Request failed")); }).always(function () { ZxUI.setLoading(btn, false); });
    });

    /* ---------------------------------------------------------------- test box */
    function renderTestSites() {
        var sel = q("#aicTestSite"), cur = sel.val(), h = "<option value=\"\">" + esc(t("(any site, the defaults)")) + "</option>";
        siteKeys().keys.forEach(function (k) { h += "<option value=\"" + esc(k) + "\">" + esc(k) + "</option>"; });
        sel.html(h);
        if (cur) { sel.val(cur); }
    }

    q("#aicTestBtn").on("click", function () {
        var ua = q("#aicTestUA").val(), out = q("#aicTestOut");
        if (!ua.trim()) { out.html("<div class=\"aic-sub\">" + esc(t("Type or paste a User-Agent first.")) + "</div>"); q("#aicTestUA").focus(); return; }
        $.ajax({ url: "/api/aicrawler/preview", method: "GET", dataType: "json", data: { ua: ua, site: q("#aicTestSite").val() } }).done(function (d) {
            if (!d || d.error) { out.html(badge("danger", (d && d.error) || t("Request failed"))); return; }
            if (!d.Match) {
                out.html(badge("", t("Not a known AI crawler")) + " <span class=\"aic-sub\">" + esc(t("The AI crawler policy does not apply to this User-Agent.")) + "</span>");
                return;
            }
            var m = d.Match, h = badge("info", m.name) + " " + badge("", groupTitle(m.group)) + " ";
            if (!state.cfg.Enabled) { h += badge("warn", t("Policy is off")) + " <span class=\"aic-sub\">" + esc(t("Nothing would change.")) + "</span>"; }
            else if (!m.action) { h += badge("", t("No policy (unchanged)")) + " <span class=\"aic-sub\">" + esc(t("It is handled exactly as before.")) + "</span>"; }
            else { h += badge(m.action === "allow" ? "ok" : (m.action === "log" ? "" : "warn"), actionLabel(m.action)); }
            h += " <span class=\"aic-sub\">" + esc(m.verifiable ? t("Its identity can be verified.") : t("Its identity cannot be verified.")) + "</span>";
            out.html(h);
        }).fail(function () { out.html(badge("danger", t("Request failed"))); });
    });
    q("#aicTestUA").on("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); q("#aicTestBtn").click(); } });

    /* ---------------------------------------------------------------- stats and posture */
    function renderStats() {
        var rows = state.data.Stats || [], h = "";
        q("#aicStatsEmpty").prop("hidden", rows.length > 0);
        q("#aicStatsWrap").prop("hidden", rows.length === 0);
        var names = {};
        (state.data.Registry || []).forEach(function (e) { names[e.id] = e.name; });
        rows.slice(0, 200).forEach(function (r) {
            var kind = r.decision === "allow" ? "ok" : (r.decision === "default" || r.decision === "log" ? "" : "warn");
            h += "<tr><td data-label=\"" + esc(t("Crawler")) + "\">" + esc(names[r.crawler] || r.crawler) + "</td><td data-label=\"" + esc(t("Site")) + "\"><span class=\"aic-mono\">" + esc(r.site) + "</span></td>" +
                "<td data-label=\"" + esc(t("Decision")) + "\">" + badge(kind, decisionLabel(r.decision)) + "</td><td class=\"zx-num\" data-label=\"" + esc(t("Requests")) + "\">" + esc(r.count) + "</td>" +
                "<td data-label=\"" + esc(t("Last seen")) + "\">" + esc(new Date(r.last * 1000).toLocaleString()) + "</td></tr>";
        });
        q("#aicStatRows").html(h);
    }

    function renderPosture() {
        var h = "";
        (state.data.Posture || []).forEach(function (f) {
            var kind = f.level === "ok" ? "ok" : (f.level === "attention" ? "warn" : "info");
            var label = f.level === "ok" ? t("Good") : (f.level === "attention" ? t("Look at this") : t("Note"));
            h += "<li>" + badge(kind, label) + "<span>" + esc(f.text) + "</span></li>";
        });
        q("#aicPosture").html(h || "<li><span class=\"aic-sub\">" + esc(t("Nothing to report.")) + "</span></li>");
    }

    /* ---------------------------------------------------------------- start */
    q("#aicReload").on("click", function () {
        if (bar && bar.isDirty()) {
            ZxUI.confirm({ title: t("Discard unsaved changes?"), message: t("Reloading puts the defaults back to what is saved."), confirmLabel: t("Discard and reload"), danger: true }).then(function (yes) {
                if (yes) { bar.discard(); load(); }
            });
            return;
        }
        load();
    });

    if (window.zxAICBar) { window.zxAICBar.destroy(); }
    bar = window.zxAICBar = ZxUI.saveBar({ form: "#aicForm", id: "aicrawlers", historyObject: "AI crawler policy", onSave: saveForm, mount: "#aiCrawlersPage" });
    load();
})();
