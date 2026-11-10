/*
    siteeditor.js

    Logic of the proxy rule editor (markup: components/httprp.html, styles: ui/siteeditor.css,
    design notes and the old tab -> new section table: docs/ux/site-editor.md).

      * five sections (General, Routing, Security, TLS, Advanced) and an Easy / Advanced switch
        that is remembered per browser; Easy shows a few cards, Advanced one section at a time
      * a card whose setting is not at its default is shown in Easy mode too, and listed in a note
      * one save model: a Save bar (ZxUI.saveBar) collects the edits of the whole editor; only the
        inherently live switches (logging) save at once, with a toast
      * focus management, Escape, Tab trap, aria for the section navigation
      * the "Protection" control and the access rule picker of Easy mode

    httprp.html calls the hooks below (populating, populated, show, opened, closing, closed, edited,
    settled). Nothing here changes an API call: the Save bar calls the same functions and endpoints
    the controls used before (saveProxyInlineEdit, saveTlsConfigs, /api/waf/endpoint/set, /api/waf/set,
    /api/access/attach, /api/cert/setPreferredCertificate).
*/
(function () {
    "use strict";
    if (window.HrpEditor) { return; }
    var $ = window.jQuery;

    function t(s) { return typeof window.t === "function" ? window.t(s) : s; }
    function tf(s) {
        var a = Array.prototype.slice.call(arguments, 1);
        return typeof window.tf === "function" ? window.tf.apply(window, [s].concat(a)) :
            s.replace(/\{(\d+)\}/g, function (m, n) { return a[+n] !== undefined ? a[+n] : m; });
    }

    var MODE_KEY = "zoraxy_site_editor_mode";
    var SECTIONS = ["general", "routing", "security", "tls", "advanced"];
    // old tab names (cfgpage / rpcfg) -> section
    var LEGACY = { downstream: "general", upstream: "general", alias: "general", tags: "general", vdirs: "routing", websocket: "routing",
        headers: "routing", accessrule: "security", security: "security", waf: "security", ssl: "tls" };
    var st = { inited: false, bar: null, subd: null, mode: "easy", section: "general", touched: false, opener: null, pending: null,
        accessSeq: 0, certSeq: 0, settleTimer: null, nd: [] };

    /*
        Fomantic turns a <select class="ui dropdown"> into a <div class="ui dropdown"> that carries the classes and holds
        the select; .val() on that div is a plain expando, not the choice. These helpers work on both forms (the WAF source,
        profile, mode and paranoia selects of the rule editor are such dropdowns).
    */
    var hrpSel = {
        el: function ($w) { $w = $($w); return $w.is("select") ? $w : ($w.find("select").first().length ? $w.find("select").first() : $w); },
        val: function ($w) { return hrpSel.el($w).val(); },
        set: function ($w, v) {
            $w = $($w);
            hrpSel.el($w).val(v);
            if (!$w.is("select") && $w.is(".ui.dropdown")) { try { $w.dropdown("set selected", v); } catch (e) { /* not initialised */ } }
        },
        options: function ($w, items) {
            $w = $($w);
            var $s = hrpSel.el($w);
            $s.empty();
            items.forEach(function (o) { $s.append($("<option>").val(o.value).text(o.text)); });
            if (!$w.is("select") && $w.is(".ui.dropdown")) {
                try { $w.dropdown("change values", items.map(function (o) { return { value: o.value, name: ZxUI.esc(o.text), text: ZxUI.esc(o.text) }; })); } catch (e) { /* not initialised */ }
            }
        }
    };
    window.hrpSel = hrpSel;

    function $m() { return $("#httprpEditModal"); }
    function visible() { return $("#httprpEditModalWrapper").is(":visible"); }
    function storeGet() { try { return localStorage.getItem(MODE_KEY); } catch (e) { return null; } }
    function storeSet(v) { try { localStorage.setItem(MODE_KEY, v); } catch (e) { /* storage blocked */ } }

    /* ------------------------------------------------------------------ init */
    // Controls without a name or id get a stable one so the dirty tracker keys do not depend on their position,
    // and a label for the Save bar ("3 unsaved changes: WebSocket, ...")
    function prepareControls() {
        var seen = {};
        $m().find(".hrp-main").find("input, select, textarea").each(function () {
            var el = this, $el = $(el), type = (el.type || "").toLowerCase();
            if (type === "file" || type === "button") { return; }
            var card = $el.closest("[data-hrp-card]").attr("data-hrp-card") || "x";
            if (!el.name && !el.id) {
                var cls = (el.className || "").split(/\s+/).filter(function (c) { return c && !/^(ui|hrp-|zx-)/.test(c); })[0] || el.getAttribute("data-cp") || type || el.tagName.toLowerCase();
                var base = "hrp:" + card + ":" + cls;
                seen[base] = (seen[base] || 0) + 1;
                el.name = base + (seen[base] > 1 ? ":" + seen[base] : "");
            }
            if (!el.getAttribute("data-zx-label") && !$el.attr("aria-label")) {
                var lbl = "";
                var sib = $el.siblings("label").first();
                if (!sib.length) { sib = $el.closest(".field, .zx-field").find("> label").first(); }
                if (sib.length) { lbl = $.trim(sib.clone().children().remove().end().text()); }
                if (!lbl) { lbl = $el.attr("placeholder") || ""; }
                if (!lbl) { lbl = $.trim($el.closest("[data-hrp-card]").find(".zx-card__title").first().text()); }
                if (lbl) { el.setAttribute("data-zx-label", lbl); }
            }
        });
    }

    function init() {
        if (st.inited || !$m().length) { return; }
        st.inited = true;
        var $root = $m();
        // controls that are actions on their own, not form state
        $root.find(".downstream_primary_hostname_edit_input, .new_listening_port_input").attr("data-zx-ignore", "");
        $root.find("[data-hrp-card='logging']").attr("data-hrp-live", "");
        // The "Apply" buttons of the WAF source, challenge override and custom settings are retired: the Save bar calls the same
        // functions. They stay in the DOM (and keep working when triggered) so existing references do not break.
        $root.find(".wafSourceSaveBtn, .wafChallengeSaveBtn, .wafSaveBtn").attr({ "data-hrp-retired": "", "aria-hidden": "true", tabindex: "-1" });
        prepareControls();

        st.mode = storeGet() === "advanced" ? "advanced" : "easy";
        ZxUI.segmented("#hrpMode", { onChange: function (v) { setMode(v, true); } });

        // section navigation (kept class name and cfgpage attribute of the old side menu)
        var $nav = $root.find(".hrpedit_menu_item");
        $nav.on("click", function () { showSection($(this).attr("cfgpage")); });
        $nav.on("keydown", function (e) {
            var i = $nav.index(this), n = $nav.length, j = -1;
            if (e.key === "ArrowDown" || e.key === "ArrowRight") { j = (i + 1) % n; }
            else if (e.key === "ArrowUp" || e.key === "ArrowLeft") { j = (i + n - 1) % n; }
            else if (e.key === "Home") { j = 0; }
            else if (e.key === "End") { j = n - 1; }
            if (j < 0) { return; }
            e.preventDefault();
            $nav.eq(j).trigger("focus").trigger("click");
        });
        $("#hrpShowAdv").on("click", function () { setMode("advanced", true); $m().find(".hrpedit_menu_item.active").trigger("focus"); });
        $("#hrpPresetBtn").on("click", function () { if (window.ZxPresets) { ZxPresets.openForRule(st.subd, { dirty: isDirty() }); } });
        $root.find(".editor_back_button").on("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); this.click(); } });
        $("#hrpAdvNoteList").on("click", "button[data-sec]", function () { setMode("advanced", true); showSection($(this).attr("data-sec")); });

        // Protection (Easy) mirrors the WAF source select of the Security section, the single source of truth
        $("#hrpProt").on("change", function () {
            var v = this.value;
            var $src = $root.find(".wafSource");
            if (hrpSel.el($src).find("option[value='" + v + "']").length) { hrpSel.set($src, v); }
            syncProt();
            if (st.bar) { st.bar.tracker.commit([]); } //refresh the bar: the mirrored select changed by script
        });
        $root.on("change", ".wafSource", syncProt);

        // the iframe access picker (Advanced) saves at once; keep the Easy picker in step
        var orig = window.updateAccessRuleNameUnderHost;
        window.updateAccessRuleNameUnderHost = function (ep, id) {
            if (typeof orig === "function") { orig.apply(this, arguments); }
            if (st.subd && ep === st.subd.RootOrMatchingDomain) { st.subd.AccessFilterUUID = id; $("#hrpAccess").val(id); rebaseAccess(); }
        };

        // a real user edit stops the automatic re-baselining after late loaded fields
        var main = $root.find(".hrp-main")[0];
        ["pointerdown", "keydown"].forEach(function (n) {
            main.addEventListener(n, function (e) {
                if (e.key === "Tab") { return; }
                if ($(e.target).closest("input, select, textarea, .ui.dropdown, .ui.checkbox, label").length) { st.touched = true; }
            }, true);
        });
        $(document).on("ajaxStop.hrpeditor", function () {
            if (!visible() || st.touched) { return; }
            clearTimeout(st.settleTimer);
            st.settleTimer = setTimeout(function () { if (!st.touched && visible()) { rebase(); } }, 150);
        });

        document.addEventListener("keydown", onKey, false);
        // focus that ends up behind the dialog (for example after the last control of an embedded editor) comes back in
        document.addEventListener("focusin", function (e) {
            if (!visible() || otherDialogOpen() || $m()[0].contains(e.target)) { return; }
            var h = document.getElementById("hrpTitle");
            if (h) { h.focus({ preventScroll: true }); }
        }, false);

        st.bar = ZxUI.saveBar({
            id: "proxy-editor", form: $root.find(".hrp-main"), mount: $root.find(".hrp-main"), ignore: "[data-zx-ignore]",
            saveLabel: t("Save changes"), onSave: save, onDiscard: afterDiscard
        });
        window.HrpEditor.bar = st.bar;
        applyMode();
    }

    /* ------------------------------------------------------------------ mode and sections */
    function setMode(mode, remember) {
        st.mode = mode === "advanced" ? "advanced" : "easy";
        if (remember) { storeSet(st.mode); }
        applyMode();
    }

    function applyMode() {
        var adv = st.mode === "advanced";
        $m().attr("data-mode", st.mode);
        $("#hrpMode .zx-segmented__item").each(function () {
            var on = $(this).attr("data-value") === st.mode;
            this.setAttribute("aria-checked", on ? "true" : "false");
            this.tabIndex = on ? 0 : -1;
        });
        showSection(st.section, true);
        updateNote();
    }

    function showSection(name, quiet) {
        if (!name) { return; }
        var sec = SECTIONS.indexOf(name) >= 0 ? name : (LEGACY[name] || "general");
        st.section = sec;
        $m().find(".hrp-sec").each(function () { $(this).toggleClass("is-active", $(this).attr("data-hrp-sec") === sec); });
        $m().find(".hrpedit_menu_item").each(function () {
            var on = $(this).attr("cfgpage") === sec;
            $(this).toggleClass("active", on).attr({ "aria-selected": on ? "true" : "false", tabindex: on ? "0" : "-1" });
        });
        if (!quiet) {
            $m().find(".hrp-main").scrollTop(0);
            $m().find(".wrapper_frame").each(function () { try { $(this).contents().scrollTop(0); } catch (e) { /* cross origin */ } });
            if (typeof hideEditorSideWrapper === "function") { hideEditorSideWrapper(); } //a section change always closes the side editor
        }
    }

    // Open a settings area by its old tab name or a section name. Jumps to Advanced when the area is not part of Easy.
    function show(name, opts) {
        init();
        var sec = SECTIONS.indexOf(name) >= 0 ? name : (LEGACY[name] || "general");
        if (opts && opts.mode) { setMode(opts.mode, false); }
        showSection(sec, !(opts && opts.reset === false) ? false : true);
        if (opts && opts.advanced && st.mode !== "advanced") { setMode("advanced", false); }
    }

    /* ------------------------------------------------------------------ non default settings */
    function nonEmpty(o) {
        if (!o || typeof o !== "object") { return !!o; }
        return Object.keys(o).some(function (k) {
            var v = o[k];
            if (Array.isArray(v)) { return v.length > 0; }
            if (v && typeof v === "object") { return nonEmpty(v); }
            return !!v;
        });
    }

    // Which cards hold a setting that is not at its default. Keys are the data-hrp-nd of the cards.
    function nonDefaults(s) {
        var out = [];
        function add(key, label, sec) { out.push({ key: key, label: label, sec: sec }); }
        var ap = s.AuthenticationProvider || {}, hr = s.HeaderRewriteRules || {}, to = s.TlsOptions;
        var n;
        if ((n = (s.MatchingDomainAlias || []).length)) { add("alias", tf("Aliases ({0})", n), "general"); }
        if ((n = (s.Tags || []).length)) { add("tags", tf("Tags ({0})", n), "general"); }
        if (s.UseStickySession) { add("lb", t("Sticky sessions"), "general"); }
        if (s.DisableUptimeMonitor || s.UptimeMonitorURI) { add("health", t("Health check"), "general"); }
        if (s.WebsocketTimeout > 0 || s.EnableTimeoutRefreshOnActivity) { add("wsopts", t("WebSocket timing"), "routing"); }
        if ((n = (s.VirtualDirectories || []).length)) { add("vdirs", tf("Path routes ({0})", n), "routing"); }
        if ((hr.UserDefinedHeaders || []).length || hr.HSTSMaxAge > 0 || hr.EnablePermissionPolicyHeader) { add("headers", t("Header rewrite rules"), "routing"); }
        if ((n = (s.ListeningPorts || []).length)) { add("ports", tf("Extra listening ports ({0})", n), "routing"); }
        if (s.Ops || (s.PathRules || []).length || (s.HeaderRules || []).length) { add("ops", t("Path rules, error pages and responses"), "routing"); }
        if (ap.AuthMethod) { add("auth", t("Authentication"), "security"); }
        if (s.RequireRateLimit || s.RateOptions) { add("ratelimit", t("Rate limit"), "security"); }
        if (s.RequireCaptcha) { add("captcha", t("CAPTCHA challenge"), "security"); }
        if (s.BlockCommonExploits || s.BlockAICrawlers || s.MitigationAction) { add("exploits", t("Exploit and crawler blocking"), "security"); }
        var source = s.WAFSource || (s.WAF ? "custom" : "inherit");
        if (source === "profile" || source === "custom" || nonEmpty(s.WAFExtra)) { add("waf", t("Firewall settings"), "security"); }
        if (nonEmpty((s.WAF || {}).Response) || nonEmpty((s.WAFExtra || {}).Response)) { add("wafresp", t("Response protection"), "security"); }
        if (nonEmpty(s.WAFAPI)) { add("wafapi", t("API protection"), "security"); }
        if (to && (to.DisableSNI || to.DisableLegacyCertificateMatching || to.EnableAutoHTTPS)) { add("tls", t("TLS options"), "tls"); }
        if (s.BypassGlobalTLS) { add("plainhttp", t("Plain HTTP allowed"), "tls"); }
        if (s.ClientCert || (s.AllowedPeerCIDRs || []).length || s.SecondaryPortsTLS || s.BotPolicy) { add("net", t("Client certificates, peers and secondary TLS"), "tls"); }
        if (s.DisableChunkedTransferEncoding || s.ForceHTTP11 || s.SanitiseClientIPHeaders) { add("compat", t("Compatibility"), "advanced"); }
        if (s.EnableConnectSupport || s.EnableUpgradeForwarding) { add("forwarding", t("Tunnels and protocol upgrades"), "advanced"); }
        if (s.UptimeHealthyStatus) { add("uptimeopts", t("Uptime monitor options"), "advanced"); }
        if (s.DisableLogging || s.DisableStatisticCollection) { add("logging", t("Logging and statistics"), "advanced"); }
        if (s.Script || s.Sablier) { add("scripts", t("Scripts and scale to zero"), "advanced"); }
        return out;
    }

    function applyForced(list) {
        var keys = {};
        list.forEach(function (x) { keys[x.key] = true; });
        $m().find("[data-hrp-nd]").each(function () { $(this).toggleClass("is-forced", !!keys[$(this).attr("data-hrp-nd")]); });
    }

    function updateNote() {
        var list = st.nd || [];
        var show = st.mode === "easy" && list.length > 0;
        var $note = $("#hrpAdvNote");
        $note.prop("hidden", !show);
        var $ul = $("#hrpAdvNoteList").empty();
        if (!show) { return; }
        $("#hrpAdvNoteText").text(" " + t("These settings are not at their defaults, so Easy mode shows them below:"));
        list.forEach(function (x) {
            var $li = $("<li>").append($("<span>").text(x.label + " "));
            $li.append($("<button type=\"button\" class=\"hrp-linkbtn\">").attr("data-sec", x.sec).text(t("Open in Advanced")));
            $ul.append($li);
        });
    }

    /* ------------------------------------------------------------------ Protection (WAF source) */
    // The global WAF state decides what "Follow the global policy" means right now (it used to say "off" whatever the state was)
    var globalWaf = null;
    function globalWafHelp() {
        var base = t("Follows the global policy on the WAF page");
        if (!globalWaf) { return base + "."; }
        if (!globalWaf.Enabled) { return base + " " + t("(currently off, enable it on the WAF page)."); }
        return base + " " + (globalWaf.DefaultMode === "block" ? t("(currently blocking).") : t("(currently detection only)."));
    }
    function loadGlobalWaf() {
        $.getJSON("/api/waf/policy", function (p) {
            if (p && !p.error) { globalWaf = p; if (hrpSel.val($m().find(".wafSource")) === "inherit") { syncProt(); } }
        });
    }

    function syncProt() {
        var $src = $m().find(".wafSource");
        var v = hrpSel.val($src) || "inherit";
        var $p = $("#hrpProt");
        $p.find("option[data-temp]").remove();
        if (!$p.find("option[value='" + v + "']").length) {
            $("<option>").attr({ value: v, "data-temp": "1" }).text(v === "profile" ? t("Profile (change it in Advanced)") : t("Custom setup (change it in Advanced)")).appendTo($p);
        }
        $p.val(v);
        var help = {
            off: t("No firewall inspection for this site."),
            detection_only: t("The firewall logs what it would block but lets everything through. A safe way to start."),
            block: t("The firewall refuses requests that look like attacks."),
            inherit: globalWafHelp(),
            profile: t("Uses a firewall profile. Choosing another option here replaces it."),
            custom: t("This site has its own complete firewall setup. Choosing another option here replaces it.")
        };
        $("#hrpProtHelp").text(help[v] || "");
    }

    /* ------------------------------------------------------------------ Easy: access rule picker, certificate status */
    function loadAccess(subd) {
        var seq = ++st.accessSeq, $sel = $("#hrpAccess");
        $sel.prop("disabled", true);
        $.get("/api/access/list", function (data) {
            if (seq !== st.accessSeq || !$.isArray(data)) { return; }
            $sel.empty();
            data.forEach(function (r) { $sel.append($("<option>").val(r.ID).text(r.Name)); });
            var cur = subd.AccessFilterUUID || "default";
            if (!$sel.find("option").filter(function () { return this.value === cur; }).length) { $sel.append($("<option>").val(cur).text(cur)); }
            $sel.val(cur).prop("disabled", false);
            rebaseAccess();
        });
    }

    function loadCertStatus(subd) {
        var seq = ++st.certSeq, $box = $("#hrpCertStatus");
        $box.empty().text(t("Checking the certificate..."));
        function render(name, list) {
            if (seq !== st.certSeq) { return; }
            var fallback = !name || /fallback/i.test(name);
            var hit = null;
            (list || []).forEach(function (c) {
                if (c && ((c.Filename || "").replace(/\.[^.]+$/, "") === name || c.Domain === name)) { hit = c; }
            });
            $box.empty();
            var $b = $("<span class=\"zx-badge zx-badge--dot\">");
            var msg;
            if (fallback) {
                $b.addClass("zx-badge--warn").text(t("Fallback certificate"));
                msg = t("No certificate matches this name, so visitors get the fallback certificate and may see a browser warning.");
            } else if (hit && typeof hit.RemainingDays === "number") {
                var d = hit.RemainingDays;
                $b.addClass(d < 14 ? "zx-badge--warn" : "zx-badge--ok").text(d < 0 ? t("Expired") : (d < 14 ? t("Expires soon") : t("Valid")));
                msg = d < 0 ? tf("Certificate {0} has expired.", name) : tf("Certificate {0} expires in {1} days.", name, d);
            } else {
                $b.addClass("zx-badge--info").text(t("In use"));
                msg = tf("Certificate {0} is served for this name.", name);
            }
            $box.append($b).append($("<span class=\"hrp-certstatus__text\">").text(" " + msg));
            var $link = $("<button type=\"button\" class=\"hrp-linkbtn\">").text(t("Manage certificates"));
            $link.on("click", function () { setMode("advanced", true); showSection("tls"); });
            $box.append($("<div>").append($link));
        }
        $.get("/api/cert/resolve", { domain: subd.RootOrMatchingDomain }).done(function (r) {
            var name = r && r.domain_key_pair ? r.domain_key_pair[r.domain] : "";
            $.get("/api/cert/list", { date: true }).done(function (list) { render(name, $.isArray(list) ? list : []); })
                .fail(function () { render(name, []); });
        }).fail(function () {
            if (seq === st.certSeq) { $box.empty().text(t("The certificate status could not be loaded.")); }
        });
    }

    /* ------------------------------------------------------------------ dirty state and saving */
    function isDirty() { return !!(st.bar && st.bar.isDirty()); }
    function rebase() { if (st.bar) { st.bar.reset(); } }
    // only the access field was saved elsewhere (the picker saves at once): other unsaved edits stay pending
    function rebaseAccess() { if (st.bar) { st.bar.tracker.commit(["hrpAccess"]); } }

    // A setting changed. Live switches (inside [data-hrp-live]) save at once when nothing else is pending.
    function edited(el) {
        if (!st.bar || !st.subd) { return; }
        var $el = $(el);
        if (!$el.closest("[data-hrp-live]").length) { return; }
        var ch = st.bar.tracker.changes();
        if (ch.length !== 1 || !$el.closest("[data-hrp-live]").has(ch[0].el).length) { return; }
        if (typeof saveProxyInlineEdit !== "function") { return; }
        Promise.resolve(saveProxyInlineEdit(st.subd.RootOrMatchingDomain, { silent: true })).then(function (r) {
            if (r && r.error !== undefined) { return; }
            ZxUI.toast(t("Saved. This switch takes effect at once."), { type: "success" });
            rebase();
        });
    }

    function groupOf(el) {
        var $e = $(el);
        var g = $e.closest("[data-hrp-save]").attr("data-hrp-save");
        if (g) { return g; }
        if ($e.closest(".certificateDropdown").length) { return "certs"; }
        if ($e.closest(".wafSourceForm").length) { return "wafsource"; }
        if ($e.closest(".wafCustomOnly").length) { return "wafcustom"; }
        return "proxy";
    }

    function chain(steps) {
        return steps.reduce(function (p, fn) {
            return p.then(function () {
                return Promise.resolve(fn()).then(function (r) {
                    if (r === null) { throw { error: t("Check the highlighted settings and try again.") }; }
                    if (r && r.error !== undefined && r.error !== null && r.error !== false) { throw r; }
                    return r;
                });
            });
        }, Promise.resolve());
    }

    function save(ctx) {
        var subd = st.subd, host = subd.RootOrMatchingDomain, editor = $("#httprpEditModalWrapper");
        var groups = {};
        var challengeTouched = false;
        ctx.changes.forEach(function (c) {
            groups[groupOf(c.el)] = true;
            if ($(c.el).is(".wafXChallenge, .wafXChallengeTTL")) { challengeTouched = true; }
        });
        var steps = [];
        if (groups.proxy) { steps.push(function () { return saveProxyInlineEdit(host, { silent: true }); }); }
        if (groups.tlsopts) { steps.push(function () { return saveTlsConfigs(host, { silent: true }); }); }
        if (groups.certs) {
            steps.push(function () {
                var calls = [];
                ctx.changes.forEach(function (c) {
                    if (groupOf(c.el) !== "certs") { return; }
                    var domain = $(c.el).closest(".certificateDropdown").attr("domain");
                    if (!domain || !c.to) { return; }
                    calls.push($.cjax({ url: "/api/cert/setPreferredCertificate", method: "POST", data: { domain: domain, certname: c.to } }));
                });
                return Promise.all(calls).then(function (rs) {
                    var bad = rs.filter(function (r) { return r && r.error !== undefined; })[0];
                    if (bad) { throw bad; }
                });
            });
        }
        var customSource = hrpSel.val($m().find(".wafSource")) === "custom";
        if (groups.wafsource && !customSource) {
            steps.push(function () { return (challengeTouched ? editor.data("wafSaveChallenge") : editor.data("wafSaveSource"))(); });
        }
        if ((groups.wafcustom || (groups.wafsource && customSource)) && customSource) {
            steps.push(function () { return editor.data("wafSaveCustom")(); });
        }
        if (groups.access) {
            steps.push(function () {
                return $.cjax({ url: "/api/access/attach", method: "POST", data: { id: $("#hrpAccess").val(), host: host } });
            });
        }
        return chain(steps).then(function () {
            ZxUI.toast(t("Changes saved"), { type: "success" });
            afterSave(groups);
            return true;
        });
    }

    // refresh what depends on the saved values: the cached rule, the notes and the sub editors that show the same data
    function afterSave(groups) {
        var host = st.subd && st.subd.RootOrMatchingDomain;
        $.get("/api/proxy/list?type=host", function (list) {
            var s = (list || []).filter(function (x) { return x.RootOrMatchingDomain === host; })[0];
            if (!s) { return; }
            st.subd = JSON.parse(JSON.stringify(s));
            st.nd = nonDefaults(st.subd);
            applyForced(st.nd);
            updateNote();
            if (groups && (groups.certs || groups.tlsopts)) { loadCertStatus(st.subd); }
            if (groups && groups.access) {
                var f = $m().find("[data-hrp-card='accessrule'] .wrapper_frame");
                if (f.length && f.attr("src")) { f.attr("src", f.attr("src").replace(/t=\d+/, "t=" + Date.now())); }
            }
        });
    }

    function afterDiscard() {
        // discard puts the fields back through change events: keep the dependent bits of the form in step
        syncProt();
    }

    /* ------------------------------------------------------------------ hooks called by httprp.html */
    function populating(subd) {
        init();
        st.pending = null;
        if (st.bar && visible() && st.subd && st.subd.RootOrMatchingDomain === subd.RootOrMatchingDomain && st.bar.isDirty()) {
            // the form is filled again while it holds unsaved edits (a side editor was closed): keep them
            st.pending = st.bar.tracker.changes().map(function (c) { return { el: c.el, to: c.to }; });
        } else {
            st.touched = false;
            var ae = document.activeElement;
            if (!visible()) { st.opener = ae && ae !== document.body && ae !== document.documentElement && !$.contains($m()[0], ae) ? ae : null; }
        }
    }

    function populated(subd) {
        init();
        st.subd = JSON.parse(JSON.stringify(subd));
        $("#hrpTitleHost").text(subd.RootOrMatchingDomain);
        st.nd = nonDefaults(st.subd);
        applyForced(st.nd);
        updateNote();
        syncProt();
        loadAccess(st.subd);
        loadGlobalWaf();
        loadCertStatus(st.subd);
        rebase();
        if (st.pending) {
            st.pending.forEach(function (p) {
                var $e = $(p.el), type = (p.el.type || "").toLowerCase();
                if (type === "checkbox") { p.el.checked = !!p.to; }
                else if (type === "radio") { p.el.checked = p.el.value === p.to; }
                else {
                    p.el.value = p.to;
                    var dd = $e.closest(".ui.dropdown");
                    if (dd.length) { try { dd.dropdown("set selected", p.to); } catch (e) { /* not a dropdown module */ } }
                }
            });
            st.pending = null;
            $m().find(".wafSource").trigger("change");
            $m().find(".hrp-main")[0].dispatchEvent(new Event("change", { bubbles: true }));
        }
    }

    function opened() {
        init();
        var h = document.getElementById("hrpTitle");
        if (h) { h.focus({ preventScroll: true }); }
    }

    function closing() { $(".ui.modal.visible.active#hrpPresetModal").modal("hide"); }

    function closed() {
        rebase();
        st.touched = false;
        st.pending = null;
        var o = st.opener;
        st.opener = null;
        setTimeout(function () {
            var target = o && document.contains(o) && o.offsetParent !== null ? o : document.getElementById("ptNewRule");
            if (target && target.focus) { target.focus({ preventScroll: true }); }
        }, 60);
    }

    /* ------------------------------------------------------------------ keyboard: Escape, Tab trap */
    function otherDialogOpen() {
        return $(".ui.modals.visible, .ui.dimmer.visible.active, #confirmBox:visible, .zx-confirm:visible, .zx-palette:visible").length > 0;
    }

    function onKey(e) {
        if (!visible()) { return; }
        var root = $m()[0];
        if (e.key === "Escape") {
            if (otherDialogOpen() || $(".ui.dropdown.active.visible, .ui.dropdown.active").length) { return; }
            e.preventDefault();
            if ($m().find(".editor_side_wrapper").is(":visible")) {
                if (typeof hideEditorSideWrapperViaBtn === "function") { hideEditorSideWrapperViaBtn(); }
                return;
            }
            var btn = $m().find(".httpProxyEditClosePC:visible, .httpProxyEditCloseMobile:visible")[0];
            if (btn) { btn.click(); }
            return;
        }
        if (e.key !== "Tab" || otherDialogOpen()) { return; }
        var items = $(root).find("a[href], button, input, select, textarea, iframe, [tabindex]").filter(function () {
            if (this.disabled || this.tabIndex < 0 || this.type === "hidden") { return false; }
            if ($(this).closest(".editor_side_wrapper").length && !$(root).find(".editor_side_wrapper").is(":visible")) { return false; }
            return this.offsetParent !== null || this === document.activeElement;
        }).toArray();
        if (!items.length) { return; }
        var first = items[0], last = items[items.length - 1], active = document.activeElement;
        if (!root.contains(active)) { e.preventDefault(); first.focus(); }
        else if (e.shiftKey && (active === first || active === document.getElementById("hrpTitle"))) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && active === last) { e.preventDefault(); first.focus(); }
    }

    window.HrpEditor = {
        mode: function () { return st.mode; },
        setMode: function (m) { init(); setMode(m, true); },
        show: show,
        populating: populating,
        populated: populated,
        opened: opened,
        closing: closing,
        closed: closed,
        edited: edited,
        settled: function () { if (!st.touched && visible()) { rebase(); } },
        isDirty: isDirty,
        nonDefaults: nonDefaults,
        current: function () { return st.subd; },
        bar: null
    };
})();
