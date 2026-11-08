/*
    ruletemplates.js

    Manager for custom proxy rule templates: list, create, edit, clone and delete, with a live
    "what this template changes" preview and the server's validation errors shown next to the form.
    Built in templates are read only (clone them to start from one). Uses the template API:

        GET  /api/proxy/templates/list
        POST /api/proxy/templates/save      template (JSON)
        POST /api/proxy/templates/delete    name
        POST /api/proxy/templates/preview   template (JSON), rule (optional)   (nothing is saved)

    openRuleTemplateManager()   opened from the HTTP Proxy page ("Templates") and from the New proxy rule dialog.

    A template only lists what it wants to set; "Leave unchanged" fields are simply left out of the JSON.
*/
(function () {
    "use strict";

    var $m = null;
    var st = { list: [], editing: null, original: "", previewTimer: null, previewSeq: 0, rules: null, error: "" };

    var CSS = [
        "#ruleTplModal.ui.modal{ max-width:62em; }",
        "#ruleTplModal .rtHead h2{ margin:0 0 0.15em; }",
        "#ruleTplModal .rtHead p{ margin:0 0 1em; opacity:0.7; }",
        "#ruleTplModal table.rtTable{ width:100%; border-collapse:collapse; }",
        "#ruleTplModal table.rtTable th{ text-align:left; padding:0.4em 0.6em; border-bottom:2px solid var(--divider_color); }",
        "#ruleTplModal table.rtTable td{ padding:0.5em 0.6em; border-bottom:1px solid var(--divider_color); vertical-align:top; }",
        "#ruleTplModal .rtBadge{ font-size:0.75em; padding:0.1em 0.55em; border-radius:2em; background:rgba(127,127,127,0.2); margin-left:0.4em; }",
        "#ruleTplModal .rtSum{ opacity:0.75; font-size:0.9em; }",
        "#ruleTplModal .rtActs{ white-space:nowrap; text-align:right; }",
        "#ruleTplModal .rtLayout{ display:grid; grid-template-columns:minmax(0,3fr) minmax(0,2fr); gap:1.4em; }",
        "#ruleTplModal .rtSection{ border:1px solid var(--divider_color); border-radius:0.6em; padding:0.5em 0.9em 0.7em; margin-bottom:0.8em; }",
        "#ruleTplModal .rtSection > h4{ margin:0.2em 0 0.5em; }",
        "#ruleTplModal .rtRow{ display:flex; gap:0.6em; align-items:center; flex-wrap:wrap; margin:0.3em 0; }",
        "#ruleTplModal .rtRow > label{ min-width:8.5em; }",
        "#ruleTplModal input[type=text], #ruleTplModal input[type=number], #ruleTplModal select, #ruleTplModal textarea{ background:var(--input_color); color:var(--text_color); border:1px solid rgba(127,127,127,0.4); border-radius:0.28em; padding:0.5em 0.7em; font:inherit; max-width:100%; box-sizing:border-box; }",
        "#ruleTplModal textarea{ width:100%; }",
        "#ruleTplModal .rtHdrRow{ display:grid; grid-template-columns:9em 1fr 1.4fr auto auto; gap:0.4em; align-items:center; margin:0.3em 0; }",
        "#ruleTplModal .rtHdrRow > *{ min-width:0; }",
        "#ruleTplModal .rtPreview{ position:sticky; top:0; border:1px solid var(--divider_color); border-radius:0.6em; padding:0.7em 0.9em; min-height:8em; }",
        "#ruleTplModal .rtPreview h4{ margin:0 0 0.4em; }",
        "#ruleTplModal .rtChange{ display:block; padding:0.3em 0; border-bottom:1px dashed var(--divider_color); font-size:0.93em; }",
        "#ruleTplModal .rtChange b{ display:block; }",
        "#ruleTplModal .rtChange .rtOld{ text-decoration:line-through; opacity:0.6; }",
        "#ruleTplModal .rtErr{ color:#db2828; }",
        "#ruleTplModal .rtOk{ color:#21ba45; }",
        "#ruleTplModal .rtHint{ font-size:0.85em; opacity:0.7; }",
        "@media screen and (max-width:900px){ #ruleTplModal .rtLayout{ grid-template-columns:1fr; } #ruleTplModal .rtHdrRow{ grid-template-columns:1fr 1fr; } }"
    ].join("\n");

    function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]; }); }
    function $f(id) { return $("#" + id); }
    function note(msg, ok) { if (typeof msgbox === "function") { msgbox(msg, ok); } }

    /* ---------------------------------------------------------------- summary of a template */
    function secs(n) {
        if (n === 0) { return "off"; }
        if (n % 31536000 === 0) { return (n / 31536000) + " year(s)"; }
        if (n % 86400 === 0) { return (n / 86400) + " day(s)"; }
        return n + " s";
    }
    function summarize(t) {
        var b = [];
        if (t.HSTSMaxAge != null) { b.push("HSTS " + secs(t.HSTSMaxAge)); }
        if (t.SecurityHeaders) { b.push("hardening headers"); }
        if (t.Headers && t.Headers.length) { b.push(t.Headers.length + " header(s)"); }
        if (t.UptimeMonitor != null) { b.push("uptime monitor " + (t.UptimeMonitor ? "on" : "off")); }
        if (t.WAFSource != null) { b.push("WAF " + t.WAFSource + (t.WAFSource === "profile" ? ": " + (t.WAFProfile || "") : "")); }
        if (t.RateLimit != null) { b.push(t.RateLimit > 0 ? "rate limit " + t.RateLimit + "/s" + (t.RateLimitBurst ? " (burst " + t.RateLimitBurst + ")" : "") : "no rate limit"); }
        if (t.BlockExploits != null) { b.push("exploit blocking " + (t.BlockExploits ? "on" : "off")); }
        if (t.DisableWebSocket != null) { b.push("WebSocket " + (t.DisableWebSocket ? "off" : "on")); }
        if (t.WebsocketTimeout != null) { b.push("WebSocket timeout " + t.WebsocketTimeout + " s"); }
        if (t.ExposeRequestID != null) { b.push("request id header " + (t.ExposeRequestID ? "on" : "off")); }
        if (t.Tags && t.Tags.length) { b.push("tags: " + t.Tags.join(", ")); }
        return b.length ? b.join(", ") : "changes nothing";
    }

    /* ---------------------------------------------------------------- markup */
    var HTML =
        '<div class="ui modal" id="ruleTplModal" role="dialog" aria-labelledby="rtTitle">' +
        '<div class="content">' +
        '<div class="rtHead"><h2 id="rtTitle">Rule templates</h2><p>A template is a named set of defaults for proxy rules. It only sets what you fill in; upstreams, domains and authentication are never touched.</p></div>' +
        '<div id="rtList"></div><div id="rtEdit" style="display:none;"></div>' +
        '</div>' +
        '<div class="actions" id="rtActs"></div>' +
        '</div>';

    function triSelect(id, labels) {
        return '<select id="' + id + '"><option value="">Leave unchanged</option><option value="1">' + labels[0] + '</option><option value="0">' + labels[1] + '</option></select>';
    }

    var FORM =
        '<form id="rtForm" class="ui form" novalidate autocomplete="off"><div class="rtLayout"><div>' +
        '<div class="rtSection"><h4>Template</h4>' +
        '<div class="rtRow"><label for="rtName">Name</label><input type="text" id="rtName" maxlength="64" style="flex:1;min-width:12em;" placeholder="My web app"></div>' +
        '<div class="rtRow" style="align-items:flex-start;"><label for="rtDesc">Description</label><textarea id="rtDesc" rows="2" maxlength="500" style="flex:1;min-width:12em;" placeholder="What is this template for?"></textarea></div></div>' +
        '<div class="rtSection"><h4>Transport security</h4>' +
        '<div class="rtRow"><label><input type="checkbox" id="rtHstsOn"> Set HSTS</label><input type="number" id="rtHsts" min="0" max="63072000" value="31536000" style="width:11em;"> <span class="rtHint">max age in seconds, 0 turns it off</span></div>' +
        '<div class="rtRow"><label><input type="checkbox" id="rtSecHdr"> Hardening headers</label><span class="rtHint">X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Cross-Origin-Opener-Policy</span></div></div>' +
        '<div class="rtSection"><h4>Custom headers</h4><div id="rtHdrs"></div>' +
        '<button type="button" class="ui mini basic button" id="rtAddHdr"><i class="plus icon"></i> Add header</button> <span class="rtHint">Merged by direction and name.</span></div>' +
        '<div class="rtSection"><h4>Protection</h4>' +
        '<div class="rtRow"><label for="rtWaf">WAF</label><select id="rtWaf"><option value="">Leave unchanged</option><option value="inherit">Inherit global</option><option value="off">Off</option><option value="detection_only">Detection only</option><option value="block">Block</option><option value="profile">Use profile</option></select>' +
        '<input type="text" id="rtWafProfile" placeholder="Profile name" style="display:none;width:12em;"></div>' +
        '<div class="rtRow"><label><input type="checkbox" id="rtRateOn"> Rate limit</label><input type="number" id="rtRate" min="0" max="1000000" value="100" style="width:7em;"> req/s <input type="number" id="rtBurst" min="0" max="10000000" value="" placeholder="burst" style="width:7em;"> <span class="rtHint">0 turns the limit off</span></div>' +
        '<div class="rtRow"><label for="rtExploit">Block exploits</label>' + triSelect("rtExploit", ["On", "Off"]) + '</div></div>' +
        '<div class="rtSection"><h4>Behaviour</h4>' +
        '<div class="rtRow"><label for="rtUptime">Uptime monitor</label>' + triSelect("rtUptime", ["On", "Off"]) + '<input type="text" id="rtUptimeUri" placeholder="/healthz (optional)" style="width:12em;"></div>' +
        '<div class="rtRow"><label for="rtWs">WebSocket</label>' + triSelect("rtWs", ["Enabled", "Disabled"]) + '<label><input type="checkbox" id="rtWsTimeoutOn"> timeout</label><input type="number" id="rtWsTimeout" min="0" max="604800" value="3600" style="width:8em;"> s</div>' +
        '<div class="rtRow"><label for="rtReqId">Request id header</label>' + triSelect("rtReqId", ["On", "Off"]) + '</div>' +
        '<div class="rtRow"><label for="rtTags">Tags</label><input type="text" id="rtTags" style="flex:1;min-width:12em;" placeholder="web, internal"></div></div>' +
        '</div><div>' +
        '<div class="rtSection"><h4>Preview against</h4><select id="rtAgainst" style="width:100%;"><option value="">A new rule with the default settings</option></select></div>' +
        '<div class="rtPreview" id="rtPreview" aria-live="polite"></div>' +
        '</div></div></form>';

    /* ---------------------------------------------------------------- build */
    function build() {
        if ($m) { return; }
        if (!document.getElementById("rtStyle")) { $("head").append('<style id="rtStyle">' + CSS + "</style>"); }
        $m = $(HTML).appendTo("body");
        $m.modal({ closable: true, autofocus: false, allowMultiple: false, onHidden: function () { clearTimeout(st.previewTimer); st.previewSeq++; } });
    }

    function refreshPickers() {
        if (typeof window.resetNewRuleTemplates === "function") { window.resetNewRuleTemplates(); }
    }

    /* ---------------------------------------------------------------- list view */
    function loadList(cb) {
        $.get("/api/proxy/templates/list", function (list) {
            st.list = (list && list.forEach) ? list : [];
            if (cb) { cb(); }
        }).fail(function () { note("Unable to load the templates", false); });
    }

    function showList() {
        st.editing = null;
        clearTimeout(st.previewTimer);
        $f("rtEdit").hide().empty();
        var h = '<table class="rtTable"><thead><tr><th>Template</th><th>Sets</th><th></th></tr></thead><tbody>';
        st.list.forEach(function (t, i) {
            h += '<tr data-i="' + i + '"><td><b>' + esc(t.Name) + '</b>' + (t.Builtin ? '<span class="rtBadge">built in</span>' : "") +
                '<div class="rtSum">' + esc(t.Description || "") + '</div></td>' +
                '<td class="rtSum">' + esc(summarize(t)) + '</td><td class="rtActs">' +
                (t.Builtin ? "" : '<button type="button" class="ui mini basic button rtEditBtn"><i class="pencil icon"></i> Edit</button>') +
                '<button type="button" class="ui mini basic button rtCloneBtn"><i class="clone icon"></i> Clone</button>' +
                (t.Builtin ? "" : '<button type="button" class="ui mini basic red button rtDelBtn"><i class="trash icon"></i> Delete</button>') +
                '</td></tr>';
        });
        h += '</tbody></table><div class="rtHint" style="margin-top:0.8em;">Templates are offered in the New proxy rule dialog and can be applied to existing rules from the bulk actions of the HTTP Proxy table.</div>';
        $f("rtList").html(h).show();
        $f("rtActs").html('<button type="button" class="ui primary button" id="rtNew"><i class="plus icon"></i> New template</button><button type="button" class="ui basic button" id="rtClose">Close</button>');
        $f("rtNew").on("click", function () { edit(null, false); });
        $f("rtClose").on("click", function () { $m.modal("hide"); });
        $f("rtList").find(".rtEditBtn").on("click", function () { edit(st.list[$(this).closest("tr").data("i")], false); });
        $f("rtList").find(".rtCloneBtn").on("click", function () { edit(st.list[$(this).closest("tr").data("i")], true); });
        $f("rtList").find(".rtDelBtn").on("click", function () {
            var $b = $(this), t = st.list[$b.closest("tr").data("i")];
            if (!$b.data("sure")) { $b.data("sure", true).addClass("red").removeClass("basic").text("Click again to delete"); setTimeout(function () { $b.data("sure", false).addClass("basic").html('<i class="trash icon"></i> Delete'); }, 3500); return; }
            $.cjax({ url: "/api/proxy/templates/delete", method: "POST", data: { name: t.Name }, success: function (r) {
                if (r && r.error) { note(r.error, false); return; }
                note("Template deleted", true);
                refreshPickers();
                loadList(showList);
            }, error: function () { note("Request failed", false); } });
        });
    }

    /* ---------------------------------------------------------------- editor */
    function headerRow(h) {
        h = h || { Direction: 1, Key: "", Value: "", IsRemove: false };
        return '<div class="rtHdrRow"><select class="rtHDir"><option value="0"' + (h.Direction === 0 ? " selected" : "") + '>To the server</option><option value="1"' + (h.Direction !== 0 ? " selected" : "") + '>To the client</option></select>' +
            '<input type="text" class="rtHKey" placeholder="X-Header" value="' + esc(h.Key) + '"><input type="text" class="rtHVal" placeholder="value" value="' + esc(h.Value) + '"' + (h.IsRemove ? " disabled" : "") + '>' +
            '<label><input type="checkbox" class="rtHRem"' + (h.IsRemove ? " checked" : "") + '> remove</label><button type="button" class="ui mini basic icon button rtHDel" aria-label="Remove this header"><i class="times icon"></i></button></div>';
    }

    function fill(t) {
        t = t || {};
        $f("rtName").val(t.Name || "");
        $f("rtDesc").val(t.Description || "");
        $f("rtHstsOn").prop("checked", t.HSTSMaxAge != null);
        $f("rtHsts").val(t.HSTSMaxAge != null ? t.HSTSMaxAge : 31536000);
        $f("rtSecHdr").prop("checked", !!t.SecurityHeaders);
        $f("rtHdrs").html((t.Headers || []).map(headerRow).join(""));
        $f("rtWaf").val(t.WAFSource || "");
        $f("rtWafProfile").val(t.WAFProfile || "");
        $f("rtRateOn").prop("checked", t.RateLimit != null);
        $f("rtRate").val(t.RateLimit != null ? t.RateLimit : 100);
        $f("rtBurst").val(t.RateLimitBurst != null ? t.RateLimitBurst : "");
        var tri = function (id, v, invert) { $f(id).val(v == null ? "" : ((invert ? !v : !!v) ? "1" : "0")); };
        tri("rtExploit", t.BlockExploits);
        tri("rtUptime", t.UptimeMonitor);
        $f("rtUptimeUri").val(t.UptimeMonitorURI || "");
        tri("rtWs", t.DisableWebSocket, true);
        $f("rtWsTimeoutOn").prop("checked", t.WebsocketTimeout != null);
        $f("rtWsTimeout").val(t.WebsocketTimeout != null ? t.WebsocketTimeout : 3600);
        tri("rtReqId", t.ExposeRequestID);
        $f("rtTags").val((t.Tags || []).join(", "));
        syncEnabled();
    }

    function syncEnabled() {
        $f("rtHsts").prop("disabled", !$f("rtHstsOn").is(":checked"));
        $f("rtRate").prop("disabled", !$f("rtRateOn").is(":checked"));
        $f("rtBurst").prop("disabled", !$f("rtRateOn").is(":checked"));
        $f("rtWsTimeout").prop("disabled", !$f("rtWsTimeoutOn").is(":checked"));
        $f("rtWafProfile").toggle($f("rtWaf").val() === "profile");
    }

    // The template JSON from the form: only fields that were set are included
    function collect() {
        var t = { Name: $.trim($f("rtName").val()), Description: $.trim($f("rtDesc").val()) };
        var num = function (id) { var v = $.trim($f(id).val()); return v === "" ? null : Number(v); };
        var tri = function (id, key, invert) { var v = $f(id).val(); if (v !== "") { t[key] = invert ? v === "0" : v === "1"; } };
        if ($f("rtHstsOn").is(":checked")) { var v = num("rtHsts"); t.HSTSMaxAge = (v == null || isNaN(v)) ? -1 : v; }
        if ($f("rtSecHdr").is(":checked")) { t.SecurityHeaders = true; }
        var headers = [];
        $f("rtHdrs").find(".rtHdrRow").each(function () {
            var $r = $(this), key = $.trim($r.find(".rtHKey").val());
            if (key === "" && $.trim($r.find(".rtHVal").val()) === "") { return; }
            headers.push({ Direction: Number($r.find(".rtHDir").val()), Key: key, Value: $r.find(".rtHVal").val(), IsRemove: $r.find(".rtHRem").is(":checked") });
        });
        if (headers.length) { t.Headers = headers; }
        if ($f("rtWaf").val() !== "") { t.WAFSource = $f("rtWaf").val(); if (t.WAFSource === "profile") { t.WAFProfile = $.trim($f("rtWafProfile").val()); } }
        if ($f("rtRateOn").is(":checked")) {
            var r = num("rtRate"); t.RateLimit = (r == null || isNaN(r)) ? -1 : r;
            var b = num("rtBurst"); if (b != null && !isNaN(b)) { t.RateLimitBurst = b; }
        }
        tri("rtExploit", "BlockExploits");
        tri("rtUptime", "UptimeMonitor");
        if ($.trim($f("rtUptimeUri").val()) !== "") { t.UptimeMonitorURI = $.trim($f("rtUptimeUri").val()); }
        tri("rtWs", "DisableWebSocket", true);
        if ($f("rtWsTimeoutOn").is(":checked")) { var w = num("rtWsTimeout"); t.WebsocketTimeout = (w == null || isNaN(w)) ? -1 : w; }
        tri("rtReqId", "ExposeRequestID");
        var tags = $.trim($f("rtTags").val()).split(",").map(function (x) { return $.trim(x); }).filter(Boolean);
        if (tags.length) { t.Tags = tags; }
        return t;
    }

    function edit(src, clone) {
        st.editing = true;
        st.original = (src && !clone && !src.Builtin) ? src.Name : "";
        $f("rtList").hide();
        $f("rtEdit").html(FORM).show();
        $f("rtTitle").text(src ? (clone ? "Clone template" : "Edit template") : "New template");
        var base = src ? $.extend(true, {}, src) : {};
        if (clone) { base.Name = (src.Name + " copy").slice(0, 64); }
        fill(base);
        $f("rtForm").on("submit", function (e) { e.preventDefault(); save(); });
        $f("rtForm").on("input change", "input, select, textarea", function () { syncEnabled(); schedulePreview(250); });
        $f("rtAddHdr").on("click", function () { $f("rtHdrs").append(headerRow()); schedulePreview(0); });
        $f("rtHdrs").on("click", ".rtHDel", function () { $(this).closest(".rtHdrRow").remove(); schedulePreview(0); });
        $f("rtHdrs").on("change", ".rtHRem", function () { $(this).closest(".rtHdrRow").find(".rtHVal").prop("disabled", this.checked); });
        $f("rtActs").html('<button type="button" class="ui basic button" id="rtBack"><i class="arrow left icon"></i> Back</button><button type="button" class="ui primary button" id="rtSave"><i class="save icon"></i> Save template</button>');
        $f("rtBack").on("click", function () { loadList(function () { $f("rtTitle").text("Rule templates"); showList(); }); });
        $f("rtSave").on("click", save);
        loadRuleChoices();
        schedulePreview(0);
        setTimeout(function () { $f("rtName").trigger("focus"); }, 100);
    }

    function loadRuleChoices() {
        var paint = function (rules) {
            var cur = $f("rtAgainst").val() || "";
            var h = '<option value="">A new rule with the default settings</option>';
            (rules || []).forEach(function (r) { h += '<option value="' + esc(r.RootOrMatchingDomain) + '">Rule: ' + esc(r.RootOrMatchingDomain) + '</option>'; });
            $f("rtAgainst").html(h).val(cur);
        };
        if (st.rules) { paint(st.rules); return; }
        $.get("/api/proxy/list?type=host", function (list) { if (list && list.forEach) { st.rules = list; paint(list); } });
    }

    /* ---------------------------------------------------------------- live preview + validation */
    function schedulePreview(ms) {
        clearTimeout(st.previewTimer);
        st.previewTimer = setTimeout(preview, ms === undefined ? 300 : ms);
    }

    function setError(msg) {
        st.error = msg || "";
        $f("rtSave").toggleClass("disabled", !!msg);
    }

    function preview() {
        var t = collect();
        var seq = ++st.previewSeq;
        var $p = $f("rtPreview");
        if (!$p.length) { return; }
        if (t.HSTSMaxAge === -1 || t.RateLimit === -1 || t.WebsocketTimeout === -1) {
            $p.html('<h4>What this template changes</h4><div class="rtErr"><i class="exclamation triangle icon"></i> Enter a number.</div>');
            setError("Enter a number.");
            return;
        }
        $.cjax({ url: "/api/proxy/templates/preview", method: "POST", data: { template: JSON.stringify(t), rule: $f("rtAgainst").val() || "" }, success: function (res) {
            if (seq !== st.previewSeq) { return; }
            var h = '<h4>What this template changes</h4>';
            if (res && res.error) {
                h += '<div class="rtErr"><i class="exclamation triangle icon"></i> ' + esc(res.error) + '</div>';
                setError(res.error);
            } else {
                setError("");
                var ch = (res && res.changes) || [];
                h += '<div class="rtHint">Compared with ' + esc(res && res.against || "") + '.</div>';
                if (!ch.length) {
                    h += '<div class="rtHint" style="margin-top:0.5em;">No change: every selected setting already has this value there.</div>';
                }
                ch.forEach(function (c) {
                    h += '<span class="rtChange"><b>' + esc(c.Field) + '</b><span class="rtOld">' + esc(c.Old) + '</span> &rarr; <span class="rtOk">' + esc(c.New) + '</span></span>';
                });
            }
            $p.html(h);
        }, error: function () { if (seq === st.previewSeq) { $p.html('<div class="rtErr">Preview request failed.</div>'); } } });
    }

    /* ---------------------------------------------------------------- save */
    function save() {
        var t = collect();
        if (st.error) { note(st.error, false); return; }
        var exists = st.list.some(function (x) { return x.Name.toLowerCase() === t.Name.toLowerCase() && x.Name !== st.original; });
        if (exists) { note("A template named \"" + t.Name + "\" already exists. Choose another name.", false); return; }
        var $b = $f("rtSave").addClass("loading disabled");
        $.cjax({ url: "/api/proxy/templates/save", method: "POST", data: { template: JSON.stringify(t) }, success: function (r) {
            $b.removeClass("loading disabled");
            if (r && r.error) { setError(r.error); $f("rtPreview").append('<div class="rtErr" style="margin-top:0.6em;"><i class="exclamation triangle icon"></i> ' + esc(r.error) + '</div>'); return; }
            var done = function () {
                note("Template saved", true);
                refreshPickers();
                loadList(function () { $f("rtTitle").text("Rule templates"); showList(); });
            };
            // renamed: remove the old entry after the new one is stored
            if (st.original && st.original !== t.Name) {
                $.cjax({ url: "/api/proxy/templates/delete", method: "POST", data: { name: st.original }, success: done, error: done });
            } else { done(); }
        }, error: function () { $b.removeClass("loading disabled"); note("Request failed", false); } });
    }

    /* ---------------------------------------------------------------- public */
    window.openRuleTemplateManager = function () {
        build();
        st.rules = null;
        $f("rtTitle").text("Rule templates");
        loadList(function () {
            showList();
            $m.modal("show");
        });
    };
})();
