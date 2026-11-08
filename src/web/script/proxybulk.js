/*
    proxybulk.js

    Multi-select and bulk actions for the HTTP proxy rule table (components/httprp.html).
    The selection and the action bar live in script/proxytable.js, which calls ProxyBulk.run(action, ruleNames).
    This file holds the action dialogs (preview, confirm, result). All actions go through one call,
    /api/proxy/bulk, which answers with one result per rule.
*/
(function(){
    var modal, names = [];

    function esc(s){ return $("<div>").text(s).html(); }

    function ensureModal(){
        if (!modal || !document.body.contains(modal[0])) {
            $("#bulkModal").remove();
            modal = $('<div class="ui small modal" id="bulkModal"><div class="header"></div><div class="scrolling content"></div><div class="actions"></div></div>');
            $("body").append(modal);
        }
    }

    function openModal(title, bodyHtml, buttons){
        ensureModal();
        modal.find(".header").text(title);
        modal.find(".content").html(bodyHtml);
        var actions = modal.find(".actions").empty();
        buttons.forEach(function(b){
            actions.append($('<button class="ui button"></button>').addClass(b.cls || "").html(b.label).on("click", function(){ b.fn && b.fn(); }));
        });
        modal.modal({ closable: true }).modal("show");
    }
    function closeModal(){ modal.modal("hide"); }

    function showResults(results, dry){
        var ok = results.filter(function(r){ return r.OK; }).length;
        var html = '<div class="ui ' + (ok === results.length ? 'positive' : 'warning') + ' message">' + (dry ? 'Preview: ' : '') + ok + ' of ' + results.length + ' rule(s) ' + (dry ? 'would change' : 'updated') + '.</div>';
        html += '<table class="ui very compact table"><thead><tr><th>Rule</th><th>Result</th></tr></thead><tbody>';
        results.forEach(function(r){
            html += '<tr><td>' + esc(r.Rule) + '</td><td>';
            if (!r.OK) { html += '<span style="color:#c00;">' + esc(r.Error || "failed") + '</span>'; }
            else if (!r.Changes || !r.Changes.length) { html += '<i>no change</i>'; }
            else { html += r.Changes.map(function(c){ return esc(c.Field) + ': <code>' + esc(c.Old) + '</code> &rarr; <code>' + esc(c.New) + '</code>'; }).join("<br>"); }
            html += '</td></tr>';
        });
        html += '</tbody></table>';
        return html;
    }

    function call(action, params, extra, dry, done){
        var data = $.extend({ rules: JSON.stringify(names), action: action, params: JSON.stringify(params || {}), dryrun: !!dry }, extra || {});
        $.cjax({ url: "/api/proxy/bulk", method: "POST", data: data, success: function(resp){
            if (resp && resp.error) { msgbox(resp.error, false, 8000); return; }
            done(resp.results || []);
        }});
    }

    function execute(action, params, extra, title, preview){
        var applyIt = function(){
            call(action, params, extra, false, function(results){
                openModal(title + " - result", showResults(results, false), [{ label: "Close", cls: "primary", fn: closeModal }]);
                if (typeof listProxyEndpoints === "function") { listProxyEndpoints(); }
                if (typeof reloadUptimeList === "function") { try { reloadUptimeList(); } catch (e) {} }
            });
        };
        if (!preview) { applyIt(); return; }
        call(action, params, extra, true, function(results){
            openModal(title + " - preview", showResults(results, true), [
                { label: "Apply", cls: "primary", fn: applyIt },
                { label: "Cancel", fn: closeModal }
            ]);
        });
    }

    function run(act, selectedNames){
        names = selectedNames || [];
        var n = names.length;
        if (n === 0) { return; }
        if (act === "enable") { execute("enable", {}, null, "Enable " + n + " rule(s)", false); }
        else if (act === "disable") { execute("disable", {}, null, "Disable " + n + " rule(s)", false); }
        else if (act === "tags") {
            openModal("Tags for " + n + " rule(s)",
                '<div class="ui form"><div class="field"><label>Tags (comma separated)</label><input type="text" id="bulkTags"></div>' +
                '<div class="field"><div class="ui radio checkbox"><input type="radio" name="bulkTagMode" value="add_tags" checked><label>Add these tags</label></div></div>' +
                '<div class="field"><div class="ui radio checkbox"><input type="radio" name="bulkTagMode" value="remove_tags"><label>Remove these tags</label></div></div></div>',
                [{ label: "Apply", cls: "primary", fn: function(){
                    var tags = $("#bulkTags").val().split(",").map(function(t){ return t.trim(); }).filter(function(t){ return t; });
                    execute($("input[name=bulkTagMode]:checked").val(), { Tags: tags }, null, "Tags", false);
                } }, { label: "Cancel", fn: closeModal }]);
        }
        else if (act === "waf") {
            openModal("WAF for " + n + " rule(s)",
                '<div class="ui form"><div class="field"><label>Source</label><select id="bulkWafSrc"><option value="inherit">Global policy (inherit)</option><option value="off">Off</option><option value="detection_only">Detection only</option><option value="block">Block</option><option value="profile">Named profile</option></select></div>' +
                '<div class="field"><label>Profile name (for "Named profile")</label><input type="text" id="bulkWafProfile"></div></div>',
                [{ label: "Preview", cls: "primary", fn: function(){
                    execute("set_waf", { WAFSource: $("#bulkWafSrc").val(), WAFProfile: $("#bulkWafProfile").val().trim() }, null, "WAF", true);
                } }, { label: "Cancel", fn: closeModal }]);
        }
        else if (act === "rate") {
            openModal("Rate limit for " + n + " rule(s)",
                '<div class="ui form"><div class="field"><div class="ui checkbox"><input type="checkbox" id="bulkRateOn" checked><label>Enable rate limit</label></div></div>' +
                '<div class="two fields"><div class="field"><label>Requests per second</label><input type="number" id="bulkRate" value="100" min="1"></div>' +
                '<div class="field"><label>Burst (0 = same as rate)</label><input type="number" id="bulkBurst" value="0" min="0"></div></div></div>',
                [{ label: "Preview", cls: "primary", fn: function(){
                    execute("set_ratelimit", { RateLimitEnabled: $("#bulkRateOn").is(":checked"), RateLimit: parseInt($("#bulkRate").val(), 10) || 0, RateLimitBurst: parseInt($("#bulkBurst").val(), 10) || 0 }, null, "Rate limit", true);
                } }, { label: "Cancel", fn: closeModal }]);
        }
        else if (act === "auth") {
            openModal("Authentication for " + n + " rule(s)",
                '<div class="ui form"><div class="field"><label>Provider</label><select id="bulkAuth"><option value="oauth2">OAuth2 / OIDC (global provider)</option><option value="zorxauth">Zoraxy Auth (global provider)</option><option value="none">None (removes protection)</option></select></div>' +
                '<div class="field"><div class="ui checkbox"><input type="checkbox" id="bulkAuthConfirm"><label>I understand that choosing "None" makes these rules public</label></div></div>' +
                '<div class="ui basic message">Basic Auth and Forward Auth need per-rule credentials/URLs and cannot be set in bulk.</div></div>',
                [{ label: "Preview", cls: "primary", fn: function(){
                    execute("set_auth", { AuthMethod: $("#bulkAuth").val(), Confirm: $("#bulkAuthConfirm").is(":checked") }, null, "Authentication", true);
                } }, { label: "Cancel", fn: closeModal }]);
        }
        else if (act === "template") {
            $.get("/api/proxy/templates/list", function(list){
                var opts = (list || []).map(function(t){ return '<option value="' + esc(t.Name) + '">' + esc(t.Name) + (t.Builtin ? " (built in)" : "") + '</option>'; }).join("");
                var desc = {}; (list || []).forEach(function(t){ desc[t.Name] = t.Description || ""; });
                openModal("Apply template to " + n + " rule(s)",
                    '<div class="ui form"><div class="field"><label>Template</label><select id="bulkTpl">' + opts + '</select></div><p id="bulkTplDesc"></p></div>' +
                    '<p>A preview with the exact changes per rule is shown before anything is applied. Upstreams, domains and authentication are never touched.</p>',
                    [{ label: "Preview", cls: "primary", fn: function(){
                        execute("apply_template", {}, { template: $("#bulkTpl").val() }, "Template", true);
                    } }, { label: "Cancel", fn: closeModal }]);
                $("#bulkTpl").on("change", function(){ $("#bulkTplDesc").text(desc[$(this).val()] || ""); }).trigger("change");
            });
        }
        else if (act === "delete") {
            openModal("Delete " + n + " rule(s)?",
                '<div class="ui negative message">This permanently removes the following proxy rules:</div><div style="max-height:12em; overflow:auto;"><code>' + names.map(esc).join("<br>") + '</code></div>' +
                '<div class="ui form" style="margin-top:1em;"><div class="field"><label>Type DELETE to confirm</label><input type="text" id="bulkDelConfirm" autocomplete="off"></div></div>',
                [{ label: "Delete", cls: "red", fn: function(){
                    if ($("#bulkDelConfirm").val() !== "DELETE") { msgbox("Type DELETE to confirm", false); return; }
                    execute("delete", { Confirm: true }, null, "Delete", false);
                } }, { label: "Cancel", fn: closeModal }]);
        }
    }

    window.ProxyBulk = { run: run };
})();
