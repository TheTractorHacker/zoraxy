/*
    aiassist.js: shared helpers of the optional AI assistant (page: components/aiassist.html,
    "Explain this" blocks in waf.html and stats.html).

    Rules for this file:
      - model text is untrusted: it is always escaped; render() allows only **bold**, `code` and "- " lists
      - nothing is applied without the confirmation dialog, which shows exactly what will change, and
        every change goes through the EXISTING admin APIs (tuning apply, blacklist add)
      - nothing runs, polls or loads until the user clicks (the status call is the only request on mount)
*/
(function(){
    if (window.zrAI) return;
    var Z = window.zrAI = {};

    // translation helpers (i18n.js provides window.t / window.tf; plain English when it is not loaded)
    function t(s){ return typeof window.t === "function" ? window.t(s) : s; }
    function tf(s){
        var a = Array.prototype.slice.call(arguments, 1);
        if (typeof window.tf === "function") return window.tf.apply(null, [s].concat(a));
        return s.replace(/\{(\d+)\}/g, function(m, n){ return a[+n] !== undefined ? a[+n] : m; });
    }

    function esc(s){ return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\x22/g, "&quot;").replace(/\x27/g, "&#39;"); }
    Z.esc = esc;

    // tiny markdown subset on already escaped text
    Z.render = function(text){
        var lines = String(text == null ? "" : text).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f​-‏‪-‮⁦-⁩﻿]/g, "").split("\n");
        var out = "", inList = false;
        lines.forEach(function(l){
            var m = /^\s*[-*]\s+(.*)$/.exec(l);
            var e = esc(m ? m[1] : l).replace(/\*\*([^*\n]{1,200})\*\*/g, "<b>$1</b>").replace(/\x60([^\x60\n]{1,200})\x60/g, "<code>$1</code>");
            if (m) { if (!inList) { out += "<ul>"; inList = true; } out += "<li>" + e + "</li>"; }
            else { if (inList) { out += "</ul>"; inList = false; } if (e.trim() !== "") out += "<p>" + e + "</p>"; }
        });
        if (inList) out += "</ul>";
        return out;
    };

    function note(m, ok){ if (typeof msgbox === "function") msgbox(m, ok !== false, 5000); else console.log(m); }
    Z.note = note;

    function api(url, data, ok, bad){
        var opt = {url: url, method: data ? "POST" : "GET", data: data || undefined, dataType: "json",
            success: function(d){ if (d && d.error) { if (bad) bad(String(d.error)); } else if (ok) ok(d); },
            error: function(){ if (bad) bad(t("Request failed")); }};
        if ($.cjax) $.cjax(opt); else $.ajax(opt);
    }
    Z.api = api;

    // ---- modal (own markup, no dependency on the page it is opened from) ----
    var seq = 0;
    Z.modal = function(o){
        var id = "zrAIModal" + (++seq);
        var m = $('<div class="ui small modal" id="' + id + '"></div>');
        m.append($('<div class="header"></div>').text(o.title));
        var c = $('<div class="scrolling content"></div>');
        if (o.html) c.html(o.html); else c.append(o.node || $("<p>").text(o.text || ""));
        m.append(c);
        var a = $('<div class="actions"></div>');
        a.append($('<div class="ui cancel button"></div>').text(o.cancel || t("Cancel")));
        if (o.ok) a.append($('<div class="ui primary approve button"></div>').text(o.ok));
        m.append(a);
        $("body").append(m);
        m.modal({closable: true, autofocus: false, onApprove: function(){ if (o.onOk) o.onOk(); return true; },
            onHidden: function(){ m.remove(); }}).modal("show");
        return m;
    };

    // ---- preview before first use, then run ----
    // feature: explain | suggest | rule | audit ; params: form data of the feature
    Z.withPreview = function(feature, params, run, fail){
        var data = $.extend({feature: feature}, params || {});
        api("./api/ai/preview", data, function(pv){
            if (pv.acked) { run(); return; }
            var body = $("<div></div>");
            body.append($("<p></p>").text(tf("This is the exact text that will be sent to {0} (model {1}). Data policy: {2}. You see this once per feature; it is shown again if you change the provider or the data policy.", pv.host, pv.model, pv.data_policy)));
            body.append($("<h4></h4>").text(t("Instructions to the model")));
            body.append($('<pre class="zrAIPre"></pre>').text(pv.system));
            body.append($("<h4></h4>").text(t("Data")));
            body.append($('<pre class="zrAIPre"></pre>').text(pv.user));
            Z.modal({title: t("Preview of what will be sent"), node: body, ok: t("Send"), onOk: function(){
                api("./api/ai/preview/ack", {feature: feature}, run, function(e){ note(e, false); if (fail) fail(); });
            }});
        }, function(e){ note(e, false); if (fail) fail(); });
    };

    Z.preview = function(feature, params, target){
        api("./api/ai/preview", $.extend({feature: feature}, params || {}), function(pv){
            $(target).empty().append($('<div class="zrAIMuted"></div>').text(tf("To {0}, model {1}, about {2} input tokens at most. {3}.", pv.host, pv.model, pv.estimated_input_tokens, pv.data_policy)),
                $("<h4></h4>").text(t("Instructions to the model")), $('<pre class="zrAIPre"></pre>').text(pv.system),
                $("<h4></h4>").text(t("Data")), $('<pre class="zrAIPre"></pre>').text(pv.user)).show();
        }, function(e){ $(target).empty().append($('<div class="zrAIErr"></div>').text(e)).show(); });
    };

    // ---- what an action does, in words written by THIS code from the validated action fields ----
    // Never from model text: the model's own reason is shown separately and labelled as unverified.
    function summarize(a){
        if (a.type == "exclude_variable") return tf("Rule {0} will no longer inspect {1} (everything else stays inspected) on proxy rule {2}", a.rule_id, a.target, a.endpoint);
        if (a.type == "exclude_rule_for_path") return tf("Rule {0} will no longer inspect requests to exactly {1} on proxy rule {2}", a.rule_id, a.path, a.endpoint);
        if (a.type == "add_to_blocklist_proposal") return tf("Add {0} to the blocklist", a.ip);
        return t("No change");
    }
    Z.summarize = summarize;

    // ---- applying a suggested WAF action (always behind a confirmation) ----
    function applyAction(a, done){
        var onErr = function(e){ note(e, false); };
        var sum = summarize(a);
        if (a.type == "exclude_variable") {
            api("./api/waf/tuning/apply", {scope: "endpoint", rootname: a.endpoint, variable: a.variable,
                suggestion: JSON.stringify({kind: "variable", rule_ids: [String(a.rule_id)], target: a.target, path: "", exact: false, summary: sum})},
                function(){ note(t("Exclusion added")); if (done) done(); }, onErr);
        } else if (a.type == "exclude_rule_for_path") {
            api("./api/waf/tuning/apply", {scope: "endpoint", rootname: a.endpoint,
                suggestion: JSON.stringify({kind: "path-rule", rule_ids: [String(a.rule_id)], path: a.path, exact: true, summary: sum})},
                function(){ note(t("Exclusion added")); if (done) done(); }, onErr);
        } else if (a.type == "add_to_blocklist_proposal") {
            api("./api/blacklist/ip/add", {ip: a.ip, comment: "from an AI assistant suggestion"},
                function(){ note(tf("{0} added to the blocklist", a.ip)); if (done) done(); }, onErr);
        }
    }
    function label(type){
        if (type == "exclude_variable") return t("Exclude this variable");
        if (type == "exclude_rule_for_path") return t("Exclude this rule for this path");
        if (type == "add_to_blocklist_proposal") return t("Add to blocklist");
        return "";
    }
    Z.confirmAction = function(a){
        var body = $("<div></div>");
        body.append($("<p></p>").text(t("This changes the configuration of your proxy:")));
        body.append($("<div class='zrAIChange'></div>").text(summarize(a)));
        body.append($("<p class='zrAIMuted'></p>").text(t("The change is made by the same function as the manual buttons and can be removed on the same page. The AI only suggested it.")));
        Z.modal({title: label(a.type) || t("Apply"), node: body, ok: t("Apply change"), onOk: function(){ applyAction(a); }});
    };

    // ---- result of an explain call ----
    function showExplain(box, r){
        box.empty();
        var v;
        if (r.verdict == "likely_attack") v = ["red", t("Looks like an attack")];
        else if (r.verdict == "likely_false_positive") v = ["green", t("Looks like a false positive")];
        else v = ["grey", t("Unclear")];
        box.append($('<span class="ui tiny label ' + v[0] + '"></span>').text(v[1]));
        box.append($('<div class="zrAIText"></div>').html(Z.render(r.explanation)));
        var acts = (r.actions || []).filter(function(a){ return a.type != "no_action"; });
        acts.forEach(function(a){
            var row = $('<div class="zrAIAction"></div>');
            row.append($('<button type="button" class="ui mini basic button"></button>').text(label(a.type) || a.type).on("click", function(){ Z.confirmAction(a); }));
            row.append($('<span class="zrAISummary zrAIMuted"></span>').text(" " + summarize(a)));
            if (a.reason) {
                var why = $('<div class="zrAIWhy zrAIMuted"></div>');
                why.append($("<b></b>").text(t("Model explanation (not verified)") + ": "), document.createTextNode(String(a.reason)));
                row.append(why);
            }
            box.append(row);
        });
        (r.refused_actions || []).forEach(function(m){ box.append($('<div class="zrAIErr zrAIRefused"></div>').text(String(m))); });
        if (r.dropped_actions) box.append($('<div class="zrAIMuted"></div>').text(tf("{0} suggested action(s) did not fit this event and were discarded.", r.dropped_actions)));
        box.append($('<div class="zrAIMuted"></div>').text(t("AI generated. Check it before acting; nothing was changed.")));
    }

    // mount an "Explain this" block into a container. kind: waf | blocked, id: txid or seq
    Z.mount = function(container, kind, id){
        var c = $(container).empty();
        api("./api/ai/status", null, function(s){
            if (!s.enabled || !s.explain) return;
            var wrap = $('<div class="zrAIBlock"></div>');
            var btn = $('<button type="button" class="ui mini basic button"><i class="magic icon"></i> Explain this (AI)</button>');
            var out = $('<div class="zrAIResult" aria-live="polite"></div>');
            btn.on("click", function(){
                var p = {kind: kind, id: id};
                var fin = function(){ btn.removeClass("loading").prop("disabled", false); };
                Z.withPreview("explain", p, function(){
                    btn.addClass("loading").prop("disabled", true);
                    api("./api/ai/explain", p, function(r){ fin(); showExplain(out, r); }, function(e){ fin(); out.empty().append($('<div class="zrAIErr"></div>').text(e)); });
                });
            });
            wrap.append(btn, out);
            c.append(wrap);
        });
    };

    Z.showExplain = showExplain;

    // styles (one place, light and dark)
    if (!document.getElementById("zrAIStyle")) {
        var st = document.createElement("style");
        st.id = "zrAIStyle";
        st.textContent = ".zrAIBlock{margin:.8em 0;padding:.7em .9em;border:1px dashed rgba(128,128,128,.5);border-radius:6px}" +
            ".zrAIBlock .zrAIResult{margin-top:.6em}.zrAIText p{margin:.4em 0}.zrAIText ul{margin:.3em 0 .3em 1.2em}" +
            ".zrAIMuted{opacity:.7;font-size:.9em;margin:.3em 0}.zrAIErr{color:#c0392b;margin:.3em 0}body.darkTheme .zrAIErr{color:#ff8a80}" +
            ".zrAIAction{margin:.4em 0}.zrAIPre{white-space:pre-wrap;word-break:break-word;max-height:16em;overflow:auto;background:rgba(128,128,128,.14);padding:.6em .8em;border-radius:4px;font-size:.85em}" +
            ".zrAIChange{padding:.6em .8em;border-left:3px solid #f2711c;background:rgba(242,113,28,.1);margin:.6em 0;word-break:break-word}" +
            "body.darkTheme .ui.modal.zrAIDark{background:#1b1c1d;color:#ddd}";
        document.head.appendChild(st);
    }
})();
