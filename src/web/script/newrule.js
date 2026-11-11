/*
    newrule.js

    The "New proxy rule" dialog: essentials first (domain, upstream with a live connection test, HTTPS
    auto-detection, template), everything else under "More options". Calls the same /api/proxy/add as the
    full form (components/rules.html, reachable as "Raw rule form"), so nothing changes on the server.

    openNewRuleDialog(opts)   opts.keep = true keeps template and options (used by "Add another")
                              opts.domain / opts.upstream pre-fill the fields

    Loaded by index.html, so any page can open it.
*/
(function () {
    "use strict";

    var $m = null;
    var st = { templates: null, testSeq: 0, tlsTouched: false, skipTouched: false, existing: {}, certs: null, certTimer: null, submitting: false, lastTest: null, testTimer: null };

    var CSS = [
        "#newRuleModal.ui.modal{ max-width:46em; }",
        "#newRuleModal .nrHead h2{ margin:0 0 0.15em; }",
        "#newRuleModal .nrHead p{ margin:0; opacity:0.7; }",
        "#newRuleModal .ui.form .field > label{ font-weight:700; }",
        "#newRuleModal .nrHint{ font-size:0.85em; opacity:0.7; margin-top:0.3em; display:block; }",
        "#newRuleModal .nrErr{ color:#db2828; font-size:0.88em; margin-top:0.3em; display:none; }",
        "#newRuleModal .field.error .nrErr{ display:block; }",
        "#newRuleModal .nrUpRow{ display:flex; gap:0.5em; }",
        "#newRuleModal .nrUpRow .ui.input{ flex:1; }",
        "#newRuleModal .nrTestRes{ font-size:0.9em; margin-top:0.45em; min-height:1.3em; }",
        "#newRuleModal .nrTestRes.ok{ color:#21ba45; }",
        "#newRuleModal .nrTestRes.warn{ color:#b58105; }",
        "#newRuleModal .nrTestRes.bad{ color:#db2828; }",
        "#newRuleModal #nrCert{ width:100%; box-sizing:border-box; max-width:100%; text-overflow:ellipsis; }",
        "#newRuleModal .nrCertHint > div{ margin-top:0.2em; }",
        "#newRuleModal .nrCertHint a{ color:#4b75ff; text-decoration:underline; }",
        "#newRuleModal .nrCertHint .warn{ color:#b58105; }",
        "#newRuleModal .nrCertHint .warn i.icon{ margin-right:0.25em; }",
        "#newRuleModal .nrTls{ display:flex; flex-wrap:wrap; gap:0.4em 1.4em; align-items:center; margin-top:0.6em; }",
        "#newRuleModal .nrAuto{ font-size:0.75em; padding:0.15em 0.55em; border-radius:2em; background:rgba(75,117,255,0.14); color:#4b75ff; margin-left:0.4em; }",
        "#newRuleModal .nrTplGrid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(13em,1fr)); gap:0.6em; }",
        "#newRuleModal .nrTpl{ border:1px solid var(--divider_color); border-radius:0.6em; padding:0.6em 0.8em; cursor:pointer; position:relative; display:block; }",
        "#newRuleModal .nrTpl:hover{ border-color:#4b75ff; }",
        "#newRuleModal .nrTpl input{ position:absolute; opacity:0; pointer-events:none; }",
        "#newRuleModal .nrTpl:has(input:checked){ border-color:#4b75ff; background:rgba(75,117,255,0.10); box-shadow:0 0 0 1px #4b75ff inset; }",
        "#newRuleModal .nrTpl:has(input:focus-visible){ outline:2px solid #4b75ff; outline-offset:2px; }",
        "#newRuleModal .nrTpl b{ display:block; }",
        "#newRuleModal .nrTpl small{ display:block; opacity:0.7; margin-top:0.15em; line-height:1.25; }",
        "#newRuleModal details.nrMore{ border:1px solid var(--divider_color); border-radius:0.6em; padding:0.5em 0.9em; margin-top:1em; }",
        "#newRuleModal details.nrMore > summary{ cursor:pointer; font-weight:700; padding:0.2em 0; }",
        "#newRuleModal details.nrMore[open] > summary{ margin-bottom:0.6em; }",
        "#newRuleModal details.nrMore input[type=text], #newRuleModal details.nrMore input[type=number], #newRuleModal details.nrMore select{ width:100%; box-sizing:border-box; max-width:100%; }",
        "#newRuleModal .nrGrid2 > *{ min-width:0; }",
        "#newRuleModal select, #newRuleModal #nrUtmUri{ background:var(--input_color); color:var(--text_color); border:1px solid rgba(127,127,127,0.4); border-radius:0.28em; padding:0.67em 1em; font:inherit; }",
        "#newRuleModal .ui.right.labeled.input{ display:flex; width:100%; }",
        "#newRuleModal .ui.right.labeled.input > input{ flex:1 1 0 !important; min-width:0; width:auto !important; }",
        "#newRuleModal #nrUtmUri::placeholder{ opacity:0.5; }",
        "#newRuleModal .nrGrid2 .ui.input{ max-width:100%; }",
        "#newRuleModal .nrGrid2{ display:grid; grid-template-columns:1fr 1fr; gap:0.2em 1.4em; }",
        "#newRuleModal .nrCheck{ margin:0.35em 0 !important; }",
        "#newRuleModal .nrFormErr{ display:none; margin-top:0.8em; }",
        "#newRuleModal .actions .nrAgain{ float:left; margin-top:0.55em; }",
        "#nrToast{ position:fixed; left:50%; bottom:1.5em; transform:translate(-50%,2em); opacity:0; pointer-events:none; z-index:2002; background:#27292d; color:#fcfcfc; border-radius:0.6em; padding:0.75em 1em; box-shadow:0 6px 20px rgba(0,0,0,0.3); display:flex; flex-wrap:wrap; gap:0.4em 1em; align-items:center; transition:opacity .2s, transform .2s; max-width:calc(100vw - 2em); }",
        "#nrToast span{ min-width:0; overflow-wrap:anywhere; }",
        "#nrToast.show{ opacity:1; transform:translate(-50%,0); pointer-events:auto; }",
        "#nrToast button{ border:0; background:transparent; color:#7aa2ff; font:inherit; font-weight:700; cursor:pointer; padding:0; }",
        "#nrToast button:hover{ text-decoration:underline; }",
        "@media (prefers-reduced-motion: reduce){ #nrToast{ transition:none; } }",
        "@media screen and (max-width:560px){ #newRuleModal .nrGrid2{ grid-template-columns:1fr; } #newRuleModal .nrUpRow{ flex-wrap:wrap; } }"
    ].join("\n");

    var HTML =
        '<div class="ui modal" id="newRuleModal" role="dialog" aria-labelledby="nrTitle">' +
        '<div class="content">' +
        '<div class="nrHead"><h2 id="nrTitle">New proxy rule</h2><p>Send a domain to a server on your network. Everything else can be changed later.</p></div>' +
        '<form class="ui form" id="nrForm" novalidate autocomplete="off" style="margin-top:1.1em;">' +
        '<div class="field" id="nrFDomain"><label for="nrDomain">Domain</label>' +
        '<input type="text" id="nrDomain" placeholder="app.example.com" autocapitalize="off" spellcheck="false">' +
        '<span class="nrHint">Use <code>*.example.com</code> for a wildcard. Separate extra hostnames (aliases) with commas.</span>' +
        '<div class="nrErr" id="nrDomainErr"></div></div>' +
        '<div class="field" id="nrFCert"><label for="nrCert">HTTPS certificate</label>' +
        '<select id="nrCert" aria-describedby="nrCertHint"><option value="">Automatic (match by hostname)</option></select>' +
        '<div class="nrHint nrCertHint" id="nrCertHint" role="status" aria-live="polite"></div></div>' +
        '<div class="field" id="nrFUp"><label for="nrUpstream">Upstream (where the app runs)</label>' +
        '<div class="nrUpRow"><div class="ui input"><input type="text" id="nrUpstream" placeholder="192.168.1.20:8080" autocapitalize="off" spellcheck="false"></div>' +
        '<button type="button" class="ui basic button" id="nrTest"><i class="plug icon"></i> Test connection</button></div>' +
        '<span class="nrHint">IP or hostname with a port. Pasting <code>https://host:8443</code> sets HTTPS for you. A Unix socket works as <code>unix:/run/app.sock</code>.</span>' +
        '<div class="nrErr" id="nrUpErr"></div>' +
        '<div class="nrTestRes" id="nrTestRes" role="status" aria-live="polite"></div>' +
        '<div class="nrTls" id="nrTls">' +
        '<div class="ui toggle checkbox" id="nrTlsBox"><input type="checkbox" id="nrTlsOn"><label for="nrTlsOn">Upstream uses HTTPS<span class="nrAuto" id="nrAuto" style="display:none;">detected</span></label></div>' +
        '<div class="ui checkbox" id="nrSkipBox" style="display:none;"><input type="checkbox" id="nrSkipVerify"><label for="nrSkipVerify">Ignore certificate errors (self-signed)</label></div>' +
        '</div></div>' +
        '<div class="field"><label>Template <a href="#" id="nrManageTpl" class="nrHint" style="float:right;font-weight:400;">Manage templates</a></label><div class="nrTplGrid" id="nrTplGrid" role="radiogroup" aria-label="Template"></div></div>' +
        '<details class="nrMore" id="nrPresetField" style="display:none;"><summary id="nrPresetLabel">Start from an app preset <span class="nrAuto" id="nrPresetPick" style="display:none;"></span></summary>' +
        '<span class="nrHint" style="margin:0 0 0.5em;">Ready-made settings for popular apps. Pick one to see exactly what it sets; you can review and change everything afterwards.</span>' +
        '<div class="nrTplGrid" id="nrPresetGrid" role="radiogroup" aria-labelledby="nrPresetLabel"></div>' +
        '<div class="zxp-detail" id="nrPresetDetail" aria-live="polite"></div></details>' +
        '<details class="nrMore" id="nrMore"><summary>More options</summary>' +
        '<div class="field"><label for="nrTags">Tags</label><input type="text" id="nrTags" placeholder="e.g. media, internal" list="nrTagList"><datalist id="nrTagList"></datalist></div>' +
        '<div class="field"><label for="nrAccess">Access rule</label><select id="nrAccess"><option value="default">Default (allow all)</option></select></div>' +
        '<div class="nrGrid2">' +
        '<div class="ui checkbox nrCheck"><input type="checkbox" id="nrRate"><label for="nrRate">Rate limit</label></div>' +
        '<div class="ui right labeled input"><input type="number" id="nrRateNum" value="100" min="1" max="100000" aria-label="Requests per second per IP" disabled><div class="ui basic label">req/s/IP</div></div>' +
        '<div class="ui checkbox nrCheck"><input type="checkbox" id="nrUtm" checked><label for="nrUtm">Uptime monitor</label></div>' +
        '<input type="text" id="nrUtmUri" placeholder="Health check path, e.g. /healthz" aria-label="Uptime monitor health check path">' +
        '<div class="ui checkbox nrCheck"><input type="checkbox" id="nrSticky"><label for="nrSticky">Sticky sessions</label></div>' +
        '<div class="ui checkbox nrCheck"><input type="checkbox" id="nrExploit"><label for="nrExploit">Block common exploits</label></div>' +
        '<div class="ui checkbox nrCheck"><input type="checkbox" id="nrPlain"><label for="nrPlain">Allow plain HTTP access</label></div>' +
        '<div class="ui checkbox nrCheck"><input type="checkbox" id="nrNoLog"><label for="nrNoLog">Disable request logging</label></div>' +
        '</div>' +
        '<span class="nrHint" style="margin-top:0.8em;">Need basic auth, custom headers or WebSocket tuning? <a href="#" id="nrAdvanced">Open the full form</a> or edit the rule after creating it.</span>' +
        '</details>' +
        '<div class="ui negative message nrFormErr" id="nrFormErr"></div>' +
        '</form></div>' +
        '<div class="actions">' +
        '<div class="ui checkbox nrAgain"><input type="checkbox" id="nrAgain"><label for="nrAgain">Add another afterwards</label></div>' +
        '<button type="button" class="ui basic button" id="nrCancel">Cancel</button>' +
        '<button type="submit" form="nrForm" class="ui primary button" id="nrCreate"><i class="plus icon"></i> Create rule</button>' +
        '</div></div>';

    function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]; }); }
    function $f(id) { return $("#" + id); }

    /* ---------------------------------------------------------------- build */
    function build() {
        if ($m) { return; }
        if (!document.getElementById("nrStyle")) { $("head").append('<style id="nrStyle">' + CSS + "</style>"); }
        $m = $(HTML).appendTo("body");
        $m.find(".ui.checkbox").checkbox();

        $f("nrForm").on("submit", function (e) { e.preventDefault(); submit(); });
        $f("nrCancel").on("click", function () { $m.modal("hide"); });
        $f("nrRate").on("change", function () { $f("nrRateNum").prop("disabled", !this.checked); });
        $f("nrUtm").on("change", function () { $f("nrUtmUri").prop("disabled", !this.checked); });

        $f("nrDomain").on("input", function () { validateDomain(false); scheduleCertPaint(); });
        $f("nrCert").on("change", paintCertHint);
        // an empty Domain is reported on Create, not on blur: the extra line moved the controls under a click in progress
        $f("nrDomain").on("blur", function () { cleanDomain(); validateDomain($f("nrDomain").val().trim() !== ""); });
        $f("nrUpstream").on("input", function () { validateUpstream(false); scheduleTest(900); });
        $f("nrUpstream").on("blur", function () { cleanUpstream(); validateUpstream(true); scheduleTest(0); });
        $f("nrUpstream").on("paste", function () { var el = this; setTimeout(function () { cleanUpstream(); validateUpstream(false); scheduleTest(200); }, 0); });
        $f("nrTest").on("click", function () { runTest(true); });
        $m.on("change", "input[name=nrTpl]", showPresetDetail);
        $f("nrPresetField").on("toggle", function () { $m.modal("refresh"); }); //re-centre when the preset section opens
        $f("nrTlsOn").on("change", function () { st.tlsTouched = true; $f("nrAuto").hide(); syncTlsUi(); });
        $f("nrSkipVerify").on("change", function () { st.skipTouched = true; });
        $f("nrAdvanced").on("click", function (e) { e.preventDefault(); openAdvanced(); });
        $f("nrManageTpl").on("click", function (e) {
            e.preventDefault();
            if (typeof openRuleTemplateManager !== "function") { return; }
            $m.modal("hide");
            setTimeout(openRuleTemplateManager, 400);
        });
        $m.on("keydown", function (e) {
            if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); submit(); }
        });
        $m.modal({ closable: true, autofocus: false, allowMultiple: false, onHidden: function () { clearTimeout(st.testTimer); st.testSeq++; } });
    }

    /* ---------------------------------------------------------------- data */
    function loadTemplates() {
        function paint(list) {
            var cur = $m.find("input[name=nrTpl]:checked").val() || "";
            var h = '<label class="nrTpl"><input type="radio" name="nrTpl" value=""' + (cur === "" ? " checked" : "") + '><b>Basic</b><small>Plain proxy with Zoraxy defaults.</small></label>';
            var ph = "";
            (list || []).forEach(function (t) {
                var one = '<label class="nrTpl"><input type="radio" name="nrTpl" value="' + esc(t.Name) + '"' + (cur === t.Name ? " checked" : "") + '><b>' + esc(t.Name) + '</b><small>' + esc(t.Description || "") + '</small></label>';
                if (t.Category === "app") { ph += one; } else { h += one; }
            });
            $f("nrTplGrid").html(h);
            $f("nrPresetGrid").html(ph);
            $f("nrPresetField").toggle(ph !== "");
            showPresetDetail();
        }
        if (st.templates) { paint(st.templates); return; }
        paint([]);
        $.get("/api/proxy/templates/list", function (list) { st.templates = list || []; paint(st.templates); });
    }
    // "what does this preset set": the same preview the template editor uses, for a new rule with the defaults
    function showPresetDetail() {
        var name = $m.find("input[name=nrTpl]:checked").val() || "";
        var tpl = (st.templates || []).filter(function (x) { return x.Name === name && x.Category === "app"; })[0];
        var $d = $f("nrPresetDetail").empty();
        $f("nrPresetPick").text(tpl ? tpl.Name : "").toggle(!!tpl);
        st.presetSeq = (st.presetSeq || 0) + 1;
        var mine = st.presetSeq;
        if (!tpl || !window.ZxPresets) { return; }
        $d.append($("<p class=\"nrHint\">").text("Checking what the preset sets..."));
        ZxPresets.preview(tpl, "", function (changes, err) {
            if (mine !== st.presetSeq) { return; }
            $d.empty();
            if (err) { $d.append($("<div class=\"ui negative message\">").text(err)); return; }
            $d.append($("<p class=\"zxp-note\">").text(tpl.Note || ""));
            if (tpl.RequiresAuth) { $d.append($("<p class=\"nrHint\">").text("This preset expects a login: choose an authentication provider in the site editor after creating the rule.")); }
            ZxPresets.renderChanges($d, changes);
        });
    }
    function loadExisting() {
        var fill = function (list) {
            st.existing = {};
            var tags = {};
            (list || []).forEach(function (r) {
                st.existing[r.RootOrMatchingDomain.toLowerCase()] = true;
                (r.MatchingDomainAlias || []).forEach(function (a) { st.existing[a.toLowerCase()] = true; });
                (r.Tags || []).forEach(function (t) { tags[t] = true; });
            });
            $f("nrTagList").html(Object.keys(tags).sort().map(function (t) { return '<option value="' + esc(t) + '">'; }).join(""));
        };
        $.get("/api/proxy/list?type=host", function (list) { if (list && !list.error) { fill(list); } });
    }
    function loadAccessRules() {
        $.get("/api/access/list", function (data) {
            if (!data || data.error || !data.forEach) { return; }
            var cur = $f("nrAccess").val();
            $f("nrAccess").html(data.map(function (a) { return '<option value="' + esc(a.ID) + '">' + esc(a.ID === "default" ? "Default (allow all)" : a.Name) + "</option>"; }).join("")).val(cur || "default");
        });
    }

    // The certificates Zoraxy has: the same list the TLS tab uses (/api/cert/list), with expiry, plus the names each covers
    function loadCerts() {
        var list = null, names = null, pending = 2;
        function done() {
            if (--pending) { return; }
            st.certs = null;
            if (list && list.forEach) {
                st.certs = list.map(function (c) {
                    return { name: c.Filename, expire: String(c.ExpireDate || "").slice(0, 10), days: c.RemainingDays, fallback: !!c.IsFallback, names: ((names || {})[c.Filename] || []).slice().sort() };
                });
            }
            paintCerts();
        }
        $.get("/api/cert/list?date=true", function (r) { if (r && r.forEach) { list = r; } }).always(done);
        $.get("/api/cert/listdomains?compact=true", function (r) { if (r && !r.error) { names = r; } }).always(done);
    }
    function ruleHosts() {
        return $f("nrDomain").val().split(",").map(function (x) { return x.trim().toLowerCase(); }).filter(function (x) { return x && HOST_RE.test(x); });
    }
    // does a certificate name list cover the host? A wildcard certificate covers one label; a wildcard rule host needs the identical name
    function nameCovers(certNames, host) {
        var set = {};
        (certNames || []).forEach(function (n) { set[String(n).replace(/^_\./, "*.").toLowerCase()] = true; });
        if (set[host]) { return true; }
        if (host.charAt(0) === "*") { return false; }
        var i = host.indexOf(".");
        return i > 0 && !!set["*" + host.slice(i)];
    }
    function certCovers(c, hosts) { return hosts.length > 0 && hosts.every(function (h) { return nameCovers(c.names, h); }); }
    function certById(name) { return (st.certs || []).filter(function (c) { return c.name === name; })[0]; }

    function certLabel(c, mark) {
        var bits = [c.name];
        if (c.fallback) { bits.push(t("default certificate")); }
        if (c.days < 0) { bits.push(t("expired")); } else if (c.expire) { bits.push(tf("expires {0}", c.expire)); }
        return (mark ? "\u2713 " : "") + bits[0] + (bits.length > 1 ? " (" + bits.slice(1).join(", ") + ")" : "");
    }
    function paintCerts() {
        var $s = $f("nrCert"), cur = $s.val() || "", hosts = ruleHosts(), certs = st.certs || [];
        certs = certs.slice().sort(function (a, b) { return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0); });
        var cover = certs.filter(function (c) { return certCovers(c, hosts); });
        var other = certs.filter(function (c) { return cover.indexOf(c) < 0; });
        function opt(c, mark) { return '<option value="' + esc(c.name) + '"' + (c.names.length ? ' title="' + esc(c.names.join(", ")) + '"' : "") + ">" + esc(certLabel(c, mark)) + "</option>"; }
        var h = '<option value="">' + esc(t("Automatic (match by hostname)")) + "</option>";
        if (cover.length && other.length) {
            h += '<optgroup label="' + esc(tf("Covers {0}", hosts.join(", "))) + '">' + cover.map(function (c) { return opt(c, true); }).join("") + "</optgroup>";
            h += '<optgroup label="' + esc(t("Other certificates")) + '">' + other.map(function (c) { return opt(c, false); }).join("") + "</optgroup>";
        } else {
            h += certs.map(function (c) { return opt(c, cover.indexOf(c) >= 0); }).join("");
        }
        // a choice the server refused stays selected (marked) so it is never dropped silently
        if (cur && !certById(cur) && st.refusedCert === cur) { h += '<option value="' + esc(cur) + '">' + esc(tf("{0} (not available)", cur)) + "</option>"; }
        $s.html(h);
        $s.val(certById(cur) || (cur && st.refusedCert === cur) ? cur : "");
        paintCertHint();
    }
    function scheduleCertPaint() {
        clearTimeout(st.certTimer);
        st.certTimer = setTimeout(function () { if (st.certs && st.certs.length) { paintCerts(); } }, 250);
    }
    function certLine(cls, icon, text) {
        var $d = $("<div>").addClass(cls || "");
        if (icon) { $d.append($("<i>").addClass(icon + " icon")); }
        return $d.append(document.createTextNode(text));
    }
    function shortList(a) { return a.length > 6 ? tf("{0} and {1} more", a.slice(0, 6).join(", "), a.length - 6) : a.join(", "); }
    function paintCertHint() {
        var $h = $f("nrCertHint").empty(), v = $f("nrCert").val() || "", c = certById(v), hosts = ruleHosts();
        if (!st.certs) { return; }
        if (!st.certs.length) {
            var $d = $("<div>").append(document.createTextNode(t("No certificates yet. Upload one, request one from an ACME provider or make a self-signed one on the Certificates page. Your entries here are kept.") + " "));
            $d.append($('<a href="#">').text(t("Open Certificates")).on("click", function (e) { e.preventDefault(); openCertsPage(); }));
            $h.append($d);
            return;
        }
        if (!c) { $h.append(certLine("", "", t("Zoraxy serves the certificate that matches the hostname."))); return; }
        $h.append(certLine("", "", tf("Certificate: {0}", c.name)));
        var shown = c.names.slice(0, 6).join(", ");
        if (c.names.length > 6) { shown = tf("{0} and {1} more", shown, c.names.length - 6); }
        $h.append(certLine("", "", c.names.length ? tf("Covers: {0}.", shown) : t("This certificate lists no names.")));
        var bad = hosts.filter(function (x) { return !nameCovers(c.names, x); });
        if (bad.length) { $h.append(certLine("warn", "exclamation triangle", tf("This certificate does not cover {0}. Visitors will see a certificate warning. You can still create the rule.", shortList(bad)))); }
        if (c.days < 0) { $h.append(certLine("warn", "exclamation triangle", t("This certificate has expired."))); }
        $h.append(certLine("", "", t("Zoraxy will serve it for every hostname of this rule and turn off automatic certificate matching (SNI) for this rule only.")));
    }
    function openCertsPage() {
        var d = $f("nrDomain").val(), u = $f("nrUpstream").val();
        $m.modal("hide");
        if (typeof openTabById === "function") { openTabById("cert"); }
        toast(t("Add a certificate, then come back to the new rule."), [{ label: t("Back to the new rule"), fn: function () { openNewRuleDialog({ keep: true, domain: d, upstream: u }); } }]);
    }

    /* ---------------------------------------------------------------- validation */
    var HOST_RE = /^(\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$/i;

    function cleanDomain() {
        var v = $f("nrDomain").val().trim().replace(/^[a-z]+:\/\//i, "").replace(/\/.*$/, "");
        v = v.split(",").map(function (x) { return x.trim(); }).filter(Boolean).join(", ");
        $f("nrDomain").val(v);
    }
    function validateDomain(final) {
        var v = $f("nrDomain").val().trim(), msg = "";
        if (v === "") { msg = final ? "Enter the domain this rule should answer for." : ""; }
        else {
            var parts = v.split(",").map(function (x) { return x.trim(); }).filter(Boolean);
            for (var i = 0; i < parts.length; i++) {
                if (!HOST_RE.test(parts[i])) { msg = "\"" + parts[i] + "\" is not a valid hostname."; break; }
                if (st.existing[parts[i].toLowerCase()]) { msg = parts[i] + " already has a proxy rule. Edit that rule instead."; break; }
            }
        }
        $f("nrFDomain").toggleClass("error", msg !== "");
        $f("nrDomainErr").text(msg);
        return msg === "" && v !== "";
    }

    function parseUpstream(v) {
        v = v.trim();
        if (/^unix:\/.+/i.test(v)) { return { ok: true, unix: true }; }
        var m = /^(https?:\/\/)?(\[[0-9a-f:.]+\]|[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?)(:(\d{1,5}))?(\/.*)?$/i.exec(v);
        if (!m) { return { ok: false, msg: "Enter an address like 192.168.1.20:8080 or my-app:3000." }; }
        if (m[5] && (+m[5] < 1 || +m[5] > 65535)) { return { ok: false, msg: "The port must be between 1 and 65535." }; }
        return { ok: true, scheme: m[1] ? m[1].replace("://", "").toLowerCase() : "", host: m[2], port: m[5] || "" };
    }
    function cleanUpstream() {
        var v = $f("nrUpstream").val().trim();
        var p = parseUpstream(v);
        if (p.ok && p.scheme) {
            $f("nrUpstream").val(v.replace(/^https?:\/\//i, ""));
            setTls(p.scheme === "https", false);
            st.tlsTouched = true;
        }
    }
    function validateUpstream(final) {
        var v = $f("nrUpstream").val().trim(), msg = "";
        if (v === "") { msg = final ? "Enter the address of the server to proxy to." : ""; }
        else {
            var p = parseUpstream(v);
            if (!p.ok) { msg = p.msg; }
        }
        $f("nrFUp").toggleClass("error", msg !== "");
        $f("nrUpErr").text(msg);
        var okNow = v !== "" && msg === "";
        if (okNow && !st.lastTest) {
            var p2 = parseUpstream(v);
            if (!p2.unix && !p2.port) { $f("nrTestRes").removeClass("ok warn bad").text("No port given: port " + (isTlsOn() ? "443" : "80") + " will be used."); }
        }
        return okNow;
    }

    /* ---------------------------------------------------------------- TLS + connection test */
    function isTlsOn() { return $f("nrTlsOn").is(":checked"); }
    function setTls(on, auto) {
        $f("nrTlsOn").prop("checked", on);
        $f("nrAuto").toggle(!!auto);
        syncTlsUi();
    }
    function syncTlsUi() {
        $f("nrSkipBox").toggle(isTlsOn());
        if (!isTlsOn()) { $f("nrSkipVerify").prop("checked", false); }
    }

    function scheduleTest(ms) {
        clearTimeout(st.testTimer);
        var v = $f("nrUpstream").val().trim();
        if (!v || !parseUpstream(v).ok) { return; }
        st.testTimer = setTimeout(function () { runTest(false); }, ms);
    }

    function runTest(explicit) {
        var v = $f("nrUpstream").val().trim();
        var p = parseUpstream(v);
        if (!v || !p.ok) { if (explicit) { validateUpstream(true); } return; }
        var seq = ++st.testSeq;
        var $r = $f("nrTestRes").removeClass("ok warn bad").html('<i class="notched circle loading icon"></i> Testing...');
        $f("nrTest").addClass("loading disabled");
        $.get("/api/proxy/testupstream", { url: v }, function (res) {
            if (seq !== st.testSeq) { return; }
            $f("nrTest").removeClass("loading disabled");
            st.lastTest = res;
            if (!res || res.error && res.ok === undefined) { $r.addClass("bad").text(res && res.error || "Test failed."); return; }
            if (!res.ok) { $r.addClass("bad").html('<i class="times circle icon"></i> ' + esc(res.error || "Not reachable")); return; }
            var https = res.protocol === "https";
            if (!st.tlsTouched) { setTls(https, true); }
            if (https && res.selfsign && !st.skipTouched) { $f("nrSkipVerify").prop("checked", true); }
            var bits = [];
            bits.push("Reachable over " + (https ? "HTTPS" : "HTTP"));
            if (res.status) { bits.push("answered " + res.status); }
            if (res.latencyMs) { bits.push(res.latencyMs + " ms"); }
            var txt = bits.join(", ");
            if (https && res.selfsign) { txt += ". The certificate is not trusted (self-signed?)"; }
            var cls = res.error ? "warn" : "ok";
            if (res.status >= 500) { cls = "warn"; }
            $r.addClass(cls).html('<i class="' + (cls === "ok" ? "check circle" : "exclamation triangle") + ' icon"></i> ' + esc(txt) + (res.error ? " (" + esc(res.error) + ")" : ""));
        }).fail(function () {
            if (seq !== st.testSeq) { return; }
            $f("nrTest").removeClass("loading disabled");
            $r.addClass("bad").text("The test could not be run.");
        });
    }

    /* ---------------------------------------------------------------- submit */
    function showFormError(msg) { $f("nrFormErr").text(msg).toggle(!!msg); }

    function submit() {
        if (st.submitting) { return; }
        showFormError("");
        cleanDomain(); cleanUpstream();
        var okD = validateDomain(true), okU = validateUpstream(true);
        if (!okD) { $f("nrDomain").focus(); return; }
        if (!okU) { $f("nrUpstream").focus(); return; }
        var rootname = $f("nrDomain").val().trim();
        var primary = rootname.split(",")[0].trim();
        var tls = isTlsOn();
        var payload = {
            type: "host", rootname: rootname, ep: $f("nrUpstream").val().trim(), tls: tls,
            tlsval: tls && $f("nrSkipVerify").is(":checked"),
            bpwsorg: true, bypassGlobalTLS: $f("nrPlain").is(":checked"), enableConnectSupport: false,
            bauth: false, cred: "[]", rate: $f("nrRate").is(":checked"), ratenum: $f("nrRateNum").val() || 100,
            access: $f("nrAccess").val() || "default", stickysess: $f("nrSticky").is(":checked"),
            tags: $f("nrTags").val().trim(), template: $m.find("input[name=nrTpl]:checked").val() || "",
            enableUtm: $f("nrUtm").is(":checked"), utmURI: $f("nrUtmUri").val().trim(),
            disableLog: $f("nrNoLog").is(":checked"), dStatisticCollection: $f("nrNoLog").is(":checked"),
            blockCommonExploits: $f("nrExploit").is(":checked"), blockAICrawlers: false, mitigationAction: 0,
            disableWebSocket: false, websocketTimeout: 0, enableTimeoutRefreshOnActivity: false
        };
        var cert = $f("nrCert").val() || "";
        if (cert) { payload.certificate = cert; } //absent = automatic, the request is exactly what it was before this field
        st.submitting = true;
        $f("nrCreate").addClass("loading disabled");
        $.cjax({
            url: "/api/proxy/add", method: "POST", data: payload,
            success: function (data) {
                st.submitting = false;
                $f("nrCreate").removeClass("loading disabled");
                if (data && data.error !== undefined) { showFormError(String(data.error)); if (cert) { st.refusedCert = cert; loadCerts(); } return; }
                created(primary, rootname, $f("nrAgain").is(":checked"), cert);
            },
            error: function () { st.submitting = false; $f("nrCreate").removeClass("loading disabled"); showFormError("The request failed. Check the connection and try again."); }
        });
    }

    function tlsListening() { try { return $("#tls").length ? $("#tls").checkbox("is checked") : false; } catch (e) { return false; } }

    function hasCertificateFor(host, names) {
        host = host.toLowerCase();
        var set = {};
        (names || []).forEach(function (n) { set[String(n).replace(/^_\./, "*.").toLowerCase()] = true; });
        if (set[host]) { return true; }
        var parts = host.split(".");
        for (var i = 1; i < parts.length - 1; i++) { if (set["*." + parts.slice(i).join(".")]) { return true; } }
        return false;
    }

    function created(primary, rootname, again, cert) {
        $m.modal("hide");
        if (typeof initQuickStartState === "function") { initQuickStartState(); }
        if (typeof reloadUptimeList === "function") { try { reloadUptimeList(); } catch (e) { } }
        // show the new rule, highlighted
        if (!$("#httprp").is(":visible") && typeof openTabById === "function") { openTabById("httprp"); }
        var done = typeof listProxyEndpoints === "function" ? listProxyEndpoints(true) : null;
        var hl = function () { if (window.ProxyTable) { window.ProxyTable.highlight(primary); } };
        if (done && done.then) { done.then(hl); } else { setTimeout(hl, 600); }

        var actions = [
            { label: "Open rule", fn: function () { if (window.ProxyTable) { window.ProxyTable.reload(true).then(function () { var r = window.httpProxyList.filter(function (x) { return x.RootOrMatchingDomain === primary; })[0]; if (r) { initHttpProxyRuleEditorModal(JSON.parse(JSON.stringify(r))); } }); } } },
            { label: "Add another", fn: function () { openNewRuleDialog({ keep: true }); } }
        ];
        var msg = cert ? tf("Created {0}, serving certificate {1}", primary, cert) : "Created " + primary;
        if (again) { setTimeout(function () { openNewRuleDialog({ keep: true }); }, 350); }
        // a certificate was chosen: do not offer to create another one for the host
        if (!cert && tlsListening() && primary.indexOf("*") < 0 && /[a-z]/i.test(primary) && primary.indexOf(".") > 0) {
            $.get("/api/cert/list", function (names) {
                if (!hasCertificateFor(primary, names)) {
                    actions.push({ label: "Create certificate for this host", fn: function () { requestCert(primary); } });
                }
                toast(msg, actions);
            }).fail(function () { toast(msg, actions); });
        } else {
            toast(msg, actions);
        }
    }

    function requestCert(host) {
        if (typeof obtainCertificate !== "function") { openTabById("cert"); return; }
        var ca = "";
        try { ca = ($("#defaultCA").dropdown("get value") || "").trim(); } catch (e) { }
        if (!ca) { ca = "Let's Encrypt"; }
        msgbox("Requesting certificate via " + ca + "...", true);
        obtainCertificate(host, false, ca, function () { if (typeof initManagedDomainCertificateList === "function") { initManagedDomainCertificateList(); } });
    }

    function toast(msg, actions) {
        var $t = $("#nrToast");
        if (!$t.length) { $t = $('<div id="nrToast" role="status" aria-live="polite"></div>').appendTo("body"); }
        clearTimeout($t.data("timer"));
        $t.empty().append($("<span></span>").text(msg));
        (actions || []).forEach(function (a) {
            $("<button type='button'></button>").text(a.label).on("click", function () { $t.removeClass("show"); a.fn(); }).appendTo($t);
        });
        $t.addClass("show").data("timer", setTimeout(function () { $t.removeClass("show"); }, 12000));
    }

    function openAdvanced() {
        var d = $f("nrDomain").val(), u = $f("nrUpstream").val(), tls = isTlsOn();
        $m.modal("hide");
        openTabById("rules");
        setTimeout(function () {
            $("#rootname").val(d); $("#proxyDomain").val(u);
            $("#reqTls").parent().checkbox(tls ? "set checked" : "set unchecked");
            if (tls && $f("nrSkipVerify").is(":checked")) { $("#skipTLSValidation").parent().checkbox("set checked"); }
        }, 250);
    }

    /* ---------------------------------------------------------------- public */
    // called by the template manager (script/ruletemplates.js) after a template was saved or deleted
    window.resetNewRuleTemplates = function () { st.templates = null; };

    window.openNewRuleDialog = function (opts) {
        opts = opts || {};
        build();
        // a dialog that is still fading in or out (e.g. "Add another" right after creating) cannot be reopened yet
        if (($m.modal("is animating") || ($m.hasClass("active") && !$m.hasClass("visible"))) && (opts._tries || 0) < 12) {
            opts._tries = (opts._tries || 0) + 1;
            setTimeout(function () { window.openNewRuleDialog(opts); }, 250);
            return;
        }
        if ($m.hasClass("active") && !$m.hasClass("visible")) { $m.removeClass("active hidden"); }
        var keep = !!opts.keep;
        if (!keep) {
            $f("nrForm")[0].reset();
            $m.find("input[name=nrTpl]").first().prop("checked", true);
            showPresetDetail();
            $("#nrPresetField").prop("open", false);
            $f("nrAccess").val("default");
            $f("nrAgain").prop("checked", false);
            $f("nrTags").val("");
            $("#nrMore").prop("open", false);
        }
        $f("nrDomain").val(opts.domain || "");
        $f("nrUpstream").val(opts.upstream || "");
        $("#nrFDomain, #nrFUp").removeClass("error");
        $f("nrTestRes").removeClass("ok warn bad").text("");
        $f("nrAuto").hide();
        showFormError("");
        st.tlsTouched = false; st.skipTouched = false; st.lastTest = null; st.refusedCert = null; st.testSeq++;
        $f("nrTlsOn").prop("checked", false); $f("nrSkipVerify").prop("checked", false);
        syncTlsUi();
        $f("nrRateNum").prop("disabled", !$f("nrRate").is(":checked"));
        $f("nrUtmUri").prop("disabled", !$f("nrUtm").is(":checked"));
        loadTemplates(); loadExisting(); loadAccessRules(); loadCerts();
        $m.find(".ui.checkbox").checkbox();
        $m.modal("show");
        setTimeout(function () { $f("nrDomain").trigger("focus"); }, 250);
    };
})();
