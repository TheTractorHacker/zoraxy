/*
    apppresets.js

    App presets in the UI: the "Apply preset" dialog of the site editor and the helpers the New proxy
    rule dialog (newrule.js) uses to show what a preset sets. A preset is a built-in rule template with
    Category "app" (src/mod/dynamicproxy/ruletemplate_presets.json), so everything goes through the
    existing template APIs:

        GET  /api/proxy/templates/list
        POST /api/proxy/templates/preview   template (JSON), rule (optional)  -> {changes:[{Field,Old,New}], against}
        POST /api/proxy/bulk                action apply_template, template, rules   (applies)

    window.ZxPresets
        list(cb)                       cb(array of preset templates), cached for the page
        isPreset(tpl)
        preview(tpl, ruleName, cb)     cb(changes | null, error)
        renderChanges($box, changes)   safe DOM table (Setting / Now / After)
        openForRule(subd, {dirty})     the dialog in the site editor
*/
(function () {
    "use strict";
    if (window.ZxPresets) { return; }
    var $ = window.jQuery;

    function t(s) { return typeof window.t === "function" ? window.t(s) : s; }
    function tf(s) {
        var a = Array.prototype.slice.call(arguments, 1);
        return typeof window.tf === "function" ? window.tf.apply(window, [s].concat(a)) :
            s.replace(/\{(\d+)\}/g, function (m, n) { return a[+n] !== undefined ? a[+n] : m; });
    }

    var cache = null;

    function list(cb) {
        if (cache) { cb(cache); return; }
        $.get("/api/proxy/templates/list", function (all) {
            cache = (all || []).filter(function (x) { return x.Category === "app"; });
            cb(cache);
        }).fail(function () { cb([]); });
    }

    function isPreset(tpl) { return !!tpl && tpl.Category === "app"; }

    function preview(tpl, ruleName, cb) {
        var data = { template: JSON.stringify(tpl) };
        if (ruleName) { data.rule = ruleName; }
        $.cjax({
            url: "/api/proxy/templates/preview", method: "POST", data: data,
            success: function (r) {
                if (r && r.error) { cb(null, r.error); } else { cb((r && r.changes) || [], null); }
            },
            error: function () { cb(null, t("Request failed")); }
        });
    }

    // Appends to $box (the caller empties it): a table of what a preset changes, text only
    function renderChanges($box, changes) {
        if (!changes.length) {
            $box.append($("<p class=\"zx-help\">").text(t("This rule already has everything this preset sets. Nothing would change.")));
            return;
        }
        var $wrap = $("<div class=\"hrp-tablewrap\" tabindex=\"0\" role=\"region\">").attr("aria-label", t("What the preset changes"));
        var $tb = $("<table class=\"zx-table zx-table--compact\">");
        $tb.append($("<thead>").append($("<tr>")
            .append($("<th scope=\"col\">").text(t("Setting")))
            .append($("<th scope=\"col\">").text(t("Now")))
            .append($("<th scope=\"col\">").text(t("After")))));
        var $body = $("<tbody>");
        changes.forEach(function (c) {
            $body.append($("<tr>")
                .append($("<td>").attr("data-label", t("Setting")).text(c.Field))
                .append($("<td>").attr("data-label", t("Now")).append(c.Old === "" ? $("<i>").text(t("(not set)")) : $("<code>").text(c.Old)))
                .append($("<td>").attr("data-label", t("After")).append($("<code>").text(c.New))));
        });
        $wrap.append($tb.append($body));
        $box.append($wrap);
    }

    /* ------------------------------------------------------------------ dialog in the site editor */
    var $dlg = null, sel = null, seq = 0, ctx = null;

    function build() {
        if ($dlg) { return; }
        $dlg = $(
            "<div class=\"ui small modal\" id=\"hrpPresetModal\" role=\"dialog\" aria-modal=\"true\" aria-labelledby=\"hrpPresetTitle\">" +
            "<div class=\"content\">" +
            "<h3 id=\"hrpPresetTitle\" class=\"hrp-dlg-title\">Apply an app preset</h3>" +
            "<p class=\"zx-help\" id=\"hrpPresetFor\"></p>" +
            "<div class=\"zx-callout zx-callout--info\" role=\"note\"><span class=\"zx-callout__icon\"><i class=\"info circle icon\"></i></span>" +
            "<div class=\"zx-callout__body\">A preset is a starting point. It never changes the hostnames, destinations or login of the site and it never lowers protection that is already set. Review the changes below before you apply it.</div></div>" +
            "<div class=\"zxp-grid\" id=\"hrpPresetGrid\" role=\"radiogroup\" aria-label=\"App presets\"></div>" +
            "<div class=\"zxp-detail\" id=\"hrpPresetDetail\" aria-live=\"polite\"></div>" +
            "</div>" +
            "<div class=\"actions\">" +
            "<button type=\"button\" class=\"zx-btn zx-btn--secondary\" id=\"hrpPresetCancel\">Cancel</button> " +
            "<button type=\"button\" class=\"zx-btn zx-btn--primary\" id=\"hrpPresetApply\" disabled>Apply preset</button>" +
            "</div></div>").appendTo("body");
        $dlg.modal({ closable: true, autofocus: false, allowMultiple: false, onHidden: function () { seq++; } });
        $("#hrpPresetCancel").on("click", function () { $dlg.modal("hide"); });
        $("#hrpPresetApply").on("click", apply);
        $("#hrpPresetGrid").on("change", "input[name=hrpPreset]", function () { choose($(this).data("tpl")); });
    }

    function choose(tpl) {
        sel = tpl;
        var mine = ++seq, $d = $("#hrpPresetDetail").empty(), $apply = $("#hrpPresetApply").prop("disabled", true);
        if (!tpl) { return; }
        $d.append($("<p class=\"zx-help\">").text(t("Checking what would change...")));
        preview(tpl, ctx.host, function (changes, err) {
            if (mine !== seq) { return; }
            $d.empty();
            if (err) { $d.append($("<div class=\"zx-callout zx-callout--danger\" role=\"alert\">").text(err)); return; }
            $d.append($("<p class=\"zxp-note\">").text(tpl.Note || ""));
            if (tpl.RequiresAuth && ctx.authMethod === 0) {
                $d.append($("<div class=\"zx-callout zx-callout--warn\" role=\"note\">").text(t("This preset is meant for sites that ask for a login, and this site has no authentication provider yet. Set one in Security after applying.")));
            }
            renderChanges($d, changes);
            if (ctx.dirty) {
                $d.append($("<div class=\"zx-callout zx-callout--warn\" role=\"note\">").text(t("Save or discard your unsaved changes first, then apply the preset.")));
            } else {
                $apply.prop("disabled", !changes.length);
            }
        });
    }

    function apply() {
        if (!sel || !ctx) { return; }
        var $b = $("#hrpPresetApply").prop("disabled", true);
        ZxUI.setLoading($b, true);
        $.cjax({
            url: "/api/proxy/bulk", method: "POST",
            data: { rules: JSON.stringify([ctx.host]), action: "apply_template", params: "{}", dryrun: false, template: sel.Name },
            success: function (r) {
                ZxUI.setLoading($b, false);
                var res = r && r.results && r.results[0];
                if ((r && r.error) || !res || !res.OK) {
                    $("#hrpPresetDetail").prepend($("<div class=\"zx-callout zx-callout--danger\" role=\"alert\">").text((r && r.error) || (res && res.Error) || t("The preset could not be applied.")));
                    $b.prop("disabled", false);
                    return;
                }
                $dlg.modal("hide");
                ZxUI.toast(tf("Preset {0} applied to {1}", sel.Name, ctx.host), { type: "success" });
                if (typeof resyncProxyEditorConfig === "function") { resyncProxyEditorConfig(); }
                if (typeof listProxyEndpoints === "function") { listProxyEndpoints(); }
            },
            error: function () { ZxUI.setLoading($b, false); $b.prop("disabled", false); ZxUI.toast(t("Request failed"), { type: "error" }); }
        });
    }

    function openForRule(subd, opts) {
        if (!subd) { return; }
        build();
        ctx = { host: subd.RootOrMatchingDomain, authMethod: (subd.AuthenticationProvider || {}).AuthMethod || 0, dirty: !!(opts && opts.dirty) };
        sel = null;
        $("#hrpPresetFor").text(tf("For {0}", ctx.host));
        $("#hrpPresetDetail").empty();
        $("#hrpPresetApply").prop("disabled", true);
        var $g = $("#hrpPresetGrid").empty();
        list(function (presets) {
            if (!presets.length) {
                $g.append($("<div class=\"zx-empty\">").append($("<p class=\"zx-empty__title\">").text(t("No presets available"))));
                return;
            }
            presets.forEach(function (p, i) {
                var $l = $("<label class=\"zxp-card\">");
                var $in = $("<input type=\"radio\" name=\"hrpPreset\">").data("tpl", p).attr("id", "hrpPreset" + i);
                $l.append($in).append($("<b>").text(p.Name)).append($("<small>").text(p.Description || ""));
                $g.append($l);
            });
        });
        $dlg.modal("show");
        setTimeout(function () { $g.find("input").first().trigger("focus"); }, 350);
    }

    window.ZxPresets = { list: list, isPreset: isPreset, preview: preview, renderChanges: renderChanges, openForRule: openForRule,
        reset: function () { cache = null; } };
})();
