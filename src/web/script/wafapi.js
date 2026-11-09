/*
    wafapi.js - API protection editor (limits, method / content type allow-list, OpenAPI spec).

    One widget, used by the WAF page (policy defaults and profiles) and by the proxy rule editor.
    Backend: /api/waf/api/get, /api/waf/api/set, /api/waf/api/spec (src/wafapi_openapi.go).

        var ctl = WafApi.mount($("#box"), {scope: "policy"|"profile"|"endpoint", name: "...", spec: true|false, readOnly: false});
        ctl.reload();            // fetch and fill
        ctl.value();             // current APIConfig or null
*/
(function(){
    if (window.WafApi) return;

    var CSS = '' +
        '.wfa .wfaTop { display:flex; flex-wrap:wrap; gap:.6em 1.5em; align-items:flex-end; margin-bottom:.8em; }' +
        '.wfa .wfaTop .field { margin:0 !important; min-width:12em; }' +
        '.wfa .wfaInfo { opacity:.8; font-size:.92em; flex:1 1 18em; }' +
        '.wfa .wfaSec { margin:1.1em 0 0; padding-top:.9em; border-top:1px solid rgba(128,128,128,.3); }' +
        '.wfa .wfaSec > h5 { margin:0 0 .5em; }' +
        '.wfa .wfaGroup { margin:.8em 0 .2em; font-weight:600; opacity:.85; }' +
        '.wfa .wfaGrid { display:grid; grid-template-columns:repeat(auto-fill,minmax(13em,1fr)); gap:.6em 1em; }' +
        '.wfa .wfaGrid .field { margin:0 !important; }' +
        '.wfa .wfaGrid label { font-size:.88em !important; }' +
        '.wfa .wfaGrid .wfaCheck { align-self:end; padding-bottom:.5em; }' +
        '.wfa .wfaMuted { opacity:.7; font-size:.9em; }' +
        '.wfa .wfaScroll { overflow-x:auto; }' +
        '.wfa table.wfaAllow { min-width:34em; }' +
        '.wfa table.wfaAllow input { width:100%; }' +
        '.wfa textarea.wfaSpec { font-family:monospace; font-size:.85em; white-space:pre; overflow:auto; }' +
        '.wfa .wfaResult { margin-top:.6em; padding:.5em .8em; border-radius:4px; border:1px solid rgba(128,128,128,.4); word-break:break-word; }' +
        '.wfa .wfaResult.ok { border-color:#21ba45; background:rgba(33,186,69,.1); }' +
        '.wfa .wfaResult.bad { border-color:#db2828; background:rgba(219,40,40,.1); }' +
        '.wfa .wfaBtns { margin-top:1em; display:flex; flex-wrap:wrap; gap:.5em; align-items:center; }' +
        'body.darkTheme .wfa input[type=file] { background:transparent; color:inherit; border:1px solid rgba(128,128,128,.4); border-radius:4px; padding:.3em; }' +
        'body.darkTheme .wfa .wfaResult.ok { background:rgba(33,186,69,.16); }' +
        'body.darkTheme .wfa .wfaResult.bad { background:rgba(219,40,40,.18); }';

    function esc(t){ return $("<div>").text(t == null ? "" : String(t)).html(); }
    function toast(m, ok){ if (typeof msgbox === "function") msgbox(m, ok !== false, ok === false ? 6000 : undefined); }

    // [key, label, hint]
    var GROUPS = [
        ["Request", [
            ["MaxBodyBytes", "Maximum body size (KiB)", "kib"], ["URLMaxLen", "URL length (bytes)"], ["HeaderMaxCount", "Header count"],
            ["HeaderMaxSize", "Size of one header (bytes)"], ["QueryMaxParams", "Query parameters"], ["QueryMaxParamLen", "Length of one parameter (bytes)"]]],
        ["JSON", [
            ["JSONMaxDepth", "Nesting depth"], ["JSONMaxKeys", "Keys per object"], ["JSONMaxArrayLen", "Array length"], ["JSONMaxStringLen", "String length (bytes)"],
            ["RejectDuplicateKeys", "Reject duplicate keys", "bool"], ["RejectInvalidUTF8", "Reject invalid UTF-8", "bool"]]],
        ["XML", [
            ["XMLMaxDepth", "Nesting depth"], ["XMLMaxElements", "Elements"], ["XMLMaxAttrs", "Attributes per element"],
            ["AllowDoctype", "Allow DOCTYPE (entities stay blocked)", "bool"]]],
        ["Forms and uploads", [
            ["FormMaxFields", "Form fields"], ["MultipartMaxParts", "Multipart parts"], ["MultipartMaxFiles", "Uploaded files"],
            ["AllowContentTypeMismatch", "Do not flag bodies that do not match their Content-Type", "bool"]]]
    ];

    function build(o){
        var h = '<div class="wfa"><div class="ui form">' +
            '<div class="wfaTop"><div class="field"><label>API protection</label><select class="ui dropdown wfaMode">' +
            (o.scope == "policy" ? '' : '<option value="">Inherit</option>') +
            '<option value="off">Off</option><option value="log">Log only</option><option value="block">Block</option></select></div>' +
            '<div class="wfaInfo"></div></div>' +
            '<div class="wfaBody">' +
            '<div class="wfaSec"><h5>Limits</h5>' +
            '<div class="ui checkbox"><input type="checkbox" class="wfaCustom"><label>Customise the limits <span class="wfaMuted">(unchecked: the inherited limits or the defaults shown below apply)</span></label></div>';
        GROUPS.forEach(function(g){
            h += '<div class="wfaGroup">' + g[0] + '</div><div class="wfaGrid">';
            g[1].forEach(function(f){
                if (f[2] == "bool") h += '<div class="field wfaCheck"><div class="ui checkbox"><input type="checkbox" class="wfaL" data-k="' + f[0] + '"><label>' + f[1] + '</label></div></div>';
                else h += '<div class="field"><label>' + f[1] + '</label><input type="number" class="wfaL wfaN" data-k="' + f[0] + '"' + (f[2] == "kib" ? ' data-kib="1"' : '') + ' min="-1"></div>';
            });
            h += '</div>';
        });
        h += '<div class="wfaMuted" style="margin-top:.6em">Empty = default, -1 = unlimited. A request that goes over a limit is logged or blocked (400, 413, 414 or 431) depending on the mode. Limits apply to bodies up to the maximum body size, which is also the most that is ever held in memory per request.</div></div>' +
            '<div class="wfaSec"><h5>Allowed methods and content types per path</h5>' +
            '<div class="wfaMuted" style="margin-bottom:.5em">A path prefix matches on path segments (<code>/api</code> matches <code>/api</code> and <code>/api/x</code>, not <code>/apix</code>; end it with <code>*</code> for a plain prefix). The longest matching prefix decides. Empty methods or content types = any. Content types are checked on requests that have a body; <code>type/*</code> works.</div>' +
            '<div class="wfaScroll"><table class="ui compact very basic small unstackable table wfaAllow"><thead><tr><th>Path prefix</th><th>Methods</th><th>Content types</th><th style="width:1%"></th></tr></thead><tbody class="wfaAllowBody"></tbody></table></div>' +
            '<button type="button" class="ui basic mini button wfaAddRule"><i class="plus icon"></i> Add path</button></div>';
        if (o.spec){
            h += '<div class="wfaSec"><h5>OpenAPI 3 validation <span class="wfaMuted">(optional)</span></h5>' +
                '<div class="wfaMuted" style="margin-bottom:.5em">Requests whose method and path are not in the spec, or whose query / path / header parameters or JSON body violate it, are logged or blocked. Paste a JSON or YAML document or load a file (up to <span class="wfaMaxSpec">2</span> MiB). Security schemes and response schemas are not evaluated; external <code>$ref</code>s are not followed.</div>' +
                '<div class="field"><textarea class="wfaSpec" rows="8" spellcheck="false" placeholder="openapi: 3.0.3&#10;info: {title: My API, version: &quot;1&quot;}&#10;paths: ..."></textarea></div>' +
                '<div class="wfaBtns"><input type="file" class="wfaFile" accept=".json,.yaml,.yml,application/json,text/yaml,text/plain" style="max-width:100%">' +
                '<button type="button" class="ui basic small button wfaCheckSpec"><i class="check icon"></i> Validate</button>' +
                '<button type="button" class="ui basic small button wfaClearSpec"><i class="trash alternate outline icon"></i> Remove spec</button></div>' +
                '<div class="wfaResult" style="display:none" role="status"></div>' +
                '<div class="wfaGrid" style="margin-top:.8em">' +
                '<div class="field wfaCheck"><div class="ui checkbox"><input type="checkbox" class="wfaOA" data-k="AllowUnknownPaths"><label>Allow paths that are not in the spec</label></div></div>' +
                '<div class="field wfaCheck"><div class="ui checkbox"><input type="checkbox" class="wfaOA" data-k="SkipBody"><label>Do not validate request bodies</label></div></div>' +
                '<div class="field wfaCheck"><div class="ui checkbox"><input type="checkbox" class="wfaOA" data-k="BlockUnknown"><label>Block when the spec cannot be used (otherwise fail open)</label></div></div></div></div>';
        }
        h += '</div>' +
            '<div class="wfaBtns"><button type="button" class="ui green button wfaSave"><i class="save icon"></i> Save API protection</button>' +
            '<span class="wfaMuted">Applies immediately, no restart.</span></div></div></div>';
        return h;
    }

    function mount(root, o){
        if (!document.getElementById("wfaStyle")){ $("head").append('<style id="wfaStyle">' + CSS + '</style>'); }
        root = $(root);
        root.html(build(o));
        var box = root.find(".wfa"), defaults = {}, lastSpec = null;

        function allowRow(r){
            r = r || {};
            return $('<tr><td><input type="text" class="wfaP" placeholder="/api" maxlength="512"></td><td><input type="text" class="wfaM" placeholder="GET, POST"></td>' +
                '<td><input type="text" class="wfaT" placeholder="application/json"></td><td><button type="button" class="ui mini basic icon button wfaDel" aria-label="Remove"><i class="times icon"></i></button></td></tr>')
                .find(".wfaP").val(r.Path || "").end().find(".wfaM").val((r.Methods || []).join(", ")).end().find(".wfaT").val((r.ContentTypes || []).join(", ")).end();
        }
        function list(s){ return s.split(/[\s,]+/).filter(function(x){ return x; }); }

        function syncCustom(){
            var on = box.find(".wfaCustom").prop("checked");
            box.find(".wfaL").prop("disabled", !on || !!o.readOnly);
            box.find(".wfaN").each(function(){
                var k = $(this).attr("data-k"), d = defaults[k];
                if (d != null) $(this).attr("placeholder", $(this).attr("data-kib") ? Math.round(d / 1024) : d);
            });
            if (!on){ box.find(".wfaN").val(""); box.find("input.wfaL:checkbox").prop("checked", false); }
        }
        function syncMode(){
            var m = box.find(".wfaMode").val();
            box.find(".wfaBody").css("opacity", m == "off" ? .55 : 1);
        }

        var ctl = {
            fill: function(view){
                view = view || {};
                var cfg = view.config || {}, lim = cfg.Limits;
                defaults = view.defaults || defaults;
                box.find(".wfaMode").val(cfg.Mode || (o.scope == "policy" ? "off" : ""));
                box.find(".wfaCustom").prop("checked", !!lim);
                box.find(".wfaN").each(function(){
                    var k = $(this).attr("data-k"), v = lim ? lim[k] : 0;
                    $(this).val(v ? ($(this).attr("data-kib") && v > 0 ? Math.round(v / 1024) : v) : "");
                });
                box.find("input.wfaL:checkbox").each(function(){ $(this).prop("checked", !!(lim && lim[$(this).attr("data-k")])); });
                var body = box.find(".wfaAllowBody").empty();
                (cfg.AllowList || []).forEach(function(r){ body.append(allowRow(r)); });
                if (view.max_spec_bytes) box.find(".wfaMaxSpec").text(Math.round(view.max_spec_bytes / 1048576));
                var oa = cfg.OpenAPI || {};
                box.find(".wfaSpec").val(oa.Spec || "");
                box.find(".wfaOA").each(function(){ $(this).prop("checked", !!oa[$(this).attr("data-k")]); });
                var res = box.find(".wfaResult").hide();
                if (view.spec) res.attr("class", "wfaResult ok").text(specText(view.spec)).show();
                else if (view.spec_error) res.attr("class", "wfaResult bad").text(view.spec_error).show();
                var info = "";
                if (o.scope == "endpoint" && view.effective){
                    info = "Effective for this rule: " + ({log: "log only", block: "block"}[view.effective.Mode] || view.effective.Mode) +
                        (view.effective.AllowList && view.effective.AllowList.length ? ", " + view.effective.AllowList.length + " allow-list path(s) in total" : "") + ".";
                } else if (o.scope == "endpoint"){
                    info = "Effective for this rule: off.";
                } else if (o.scope == "profile"){
                    info = "Applied on top of the policy defaults to every proxy rule that uses this profile.";
                } else {
                    info = "Default for every proxy rule that inherits the global policy (it must be enabled), and the base layer for profiles and rules.";
                }
                box.find(".wfaInfo").text(info);
                box.find("input,select,textarea,button.wfaAddRule,button.wfaSave").prop("disabled", !!o.readOnly);
                syncCustom(); syncMode();
            },
            reload: function(cb){
                var q = {scope: o.scope, name: o.name || ""};
                $.getJSON("/api/waf/api/get", q, function(v){
                    if (v && v.error != undefined){ toast(v.error, false); return; }
                    ctl.fill(v); if (cb) cb(v);
                });
            },
            setName: function(n){ o.name = n; },
            value: function(){
                var cfg = {Mode: box.find(".wfaMode").val() || ""};
                if (box.find(".wfaCustom").prop("checked")){
                    var l = {};
                    box.find(".wfaL").each(function(){
                        var k = $(this).attr("data-k");
                        if ($(this).is(":checkbox")){ if ($(this).prop("checked")) l[k] = true; return; }
                        var raw = $.trim($(this).val());
                        if (raw === "") return;
                        var n = parseInt(raw, 10);
                        if (isNaN(n)) return;
                        l[k] = $(this).attr("data-kib") && n > 0 ? n * 1024 : n;
                    });
                    cfg.Limits = l;
                }
                var allow = [];
                box.find(".wfaAllowBody tr").each(function(){
                    var p = $.trim($(this).find(".wfaP").val());
                    if (!p) return;
                    var r = {Path: p}, m = list($(this).find(".wfaM").val()).map(function(x){ return x.toUpperCase(); }), t = list($(this).find(".wfaT").val());
                    if (m.length) r.Methods = m;
                    if (t.length) r.ContentTypes = t;
                    allow.push(r);
                });
                if (allow.length) cfg.AllowList = allow;
                if (o.spec){
                    var spec = box.find(".wfaSpec").val();
                    if ($.trim(spec)){
                        var oa = {Spec: spec};
                        box.find(".wfaOA").each(function(){ if ($(this).prop("checked")) oa[$(this).attr("data-k")] = true; });
                        cfg.OpenAPI = oa;
                    }
                }
                if (!cfg.Mode && !cfg.Limits && !cfg.AllowList && !cfg.OpenAPI) return null;
                return cfg;
            },
            save: function(cb){
                var v = ctl.value();
                $.cjax({url: "/api/waf/api/set", method: "POST", data: {scope: o.scope, name: o.name || "", config: v ? JSON.stringify(v) : ""},
                    success: function(d){
                        if (d && d.error != undefined){ toast(d.error, false); if (cb) cb(false); return; }
                        toast("API protection saved and applied");
                        if (cb) cb(true);
                        if (o.onSaved) o.onSaved();
                    },
                    error: function(){ toast("Request failed", false); if (cb) cb(false); }});
            }
        };

        function specText(s){ return "Valid OpenAPI " + s.openapi + (s.title ? ": " + s.title : "") + (s.version ? " " + s.version : "") + ". " + s.paths + " path" + (s.paths == 1 ? "" : "s") + ", " + s.operations + " operation" + (s.operations == 1 ? "" : "s") + "."; }

        box.on("change", ".wfaCustom", syncCustom);
        box.on("change", ".wfaMode", syncMode);
        box.on("click", ".wfaAddRule", function(){ box.find(".wfaAllowBody").append(allowRow()); box.find(".wfaAllowBody tr:last .wfaP").focus(); });
        box.on("click", ".wfaDel", function(){ $(this).closest("tr").remove(); });
        box.on("click", ".wfaSave", function(){
            var b = $(this).addClass("loading");
            ctl.save(function(){ b.removeClass("loading"); ctl.reload(); });
            setTimeout(function(){ b.removeClass("loading"); }, 15000);
        });
        box.on("click", ".wfaClearSpec", function(){ box.find(".wfaSpec").val(""); box.find(".wfaResult").hide(); box.find(".wfaFile").val(""); });
        box.on("change", ".wfaFile", function(){
            var f = this.files && this.files[0];
            if (!f) return;
            if (f.size > 2 * 1048576){ toast("The file is larger than 2 MiB", false); this.value = ""; return; }
            var rd = new FileReader();
            rd.onload = function(){ box.find(".wfaSpec").val(String(rd.result)); box.find(".wfaCheckSpec").click(); };
            rd.readAsText(f);
        });
        box.on("click", ".wfaCheckSpec", function(){
            var spec = box.find(".wfaSpec").val(), res = box.find(".wfaResult");
            if (!$.trim(spec)){ res.attr("class", "wfaResult bad").text("Paste or load an OpenAPI document first.").show(); return; }
            var b = $(this).addClass("loading");
            $.cjax({url: "/api/waf/api/spec", method: "POST", data: {spec: spec},
                success: function(d){
                    b.removeClass("loading");
                    if (d && d.error != undefined) res.attr("class", "wfaResult bad").text(d.error).show();
                    else res.attr("class", "wfaResult ok").text(specText(d)).show();
                },
                error: function(){ b.removeClass("loading"); res.attr("class", "wfaResult bad").text("Request failed").show(); }});
        });
        syncCustom();
        return ctl;
    }

    window.WafApi = {mount: mount};
})();
