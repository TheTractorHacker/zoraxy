/*
    rulesbuilder.js: page logic of "Security rules" (components/ruleset.html): rule list, lists, import, request tester,
    shared helpers. The visual editor is script/rulesedit.js; data tables are rulesdata.js, the model rulesmodel.js.

    Rules for this file
      - every string that comes from the server or the user is inserted with textContent (h() does that), never innerHTML
      - nothing is saved without an explicit click; new rules are created log-only; switching to enforce asks first
      - API: /api/ruleset/* (src/rulesetapi.go). Toggles (enable / disable) apply at once and say so in a toast.
*/
(function () {
    "use strict";
    if (window.RB) { return; }
    function N_(s) { return s; }
    function t(s) { return typeof window.t === "function" ? window.t(s) : s; }
    function tf(s) {
        var a = Array.prototype.slice.call(arguments, 1);
        if (typeof window.tf === "function") { return window.tf.apply(null, [s].concat(a)); }
        return s.replace(/\{(\d+)\}/g, function (m, n) { return a[+n] !== undefined ? a[+n] : m; });
    }
    var D = window.RBData, M = window.RBModel;
    var RB = window.RB = { t: t, tf: tf, N_: N_ };
    var PAGE = 100;                       // rows rendered at once
    var AI_MARK = "[AI proposal] ";       // description prefix of rules created from an AI proposal (the engine has one action per rule, so no tag action)
    RB.AI_MARK = AI_MARK;
    var S = RB.S = { meta: null, site: "", rules: [], lists: [], q: "", shown: PAGE, ed: null, inited: false, busy: 0, loadSeq: 0 };

    // ------------------------------------------------------------------ DOM helper (text only, never innerHTML)
    function h(tag, props) {
        var e = document.createElement(tag);
        if (props) {
            Object.keys(props).forEach(function (k) {
                var v = props[k];
                if (v === null || v === undefined || v === false) { return; }
                if (k === "class") { e.className = v; }
                else if (k === "text") { e.textContent = v; }
                else if (k.indexOf("on") === 0 && typeof v === "function") { e.addEventListener(k.slice(2), v); }
                else if (k === "value" || k === "checked" || k === "disabled" || k === "hidden" || k === "selected" || k === "readOnly") { e[k] = v; }
                else { e.setAttribute(k, v === true ? "" : v); }
            });
        }
        for (var i = 2; i < arguments.length; i++) { add(e, arguments[i]); }
        return e;
    }
    function add(e, k) {
        if (k === null || k === undefined || k === false) { return; }
        if (Array.isArray(k)) { k.forEach(function (x) { add(e, x); }); }
        else if (k.nodeType) { e.appendChild(k); }
        else { e.appendChild(document.createTextNode(String(k))); }
    }
    RB.h = h;
    RB.clear = function (e) { while (e.firstChild) { e.removeChild(e.firstChild); } return e; };
    function ibtn(icon, label, fn, extra) {
        return h("button", { type: "button", class: "zx-btn zx-btn--ghost zx-btn--sm zx-btn--icon" + (extra ? " " + extra : ""), "aria-label": label, title: label, onclick: fn }, h("i", { class: icon + " icon", "aria-hidden": "true" }));
    }
    RB.ibtn = ibtn;
    function badge(text, cls, title) { return h("span", { class: "zx-badge" + (cls ? " zx-badge--" + cls : ""), title: title }, text); }
    RB.badge = badge;
    function $page() { return document.getElementById("rbPage"); }
    function q(sel) { return $page().querySelector(sel); }
    RB.q = q;
    RB.toast = function (m, o) { if (window.ZxUI) { ZxUI.toast(m, o); } else if (typeof msgbox === "function") { msgbox(m); } };
    function ago(ts) {
        if (!ts) { return t("never"); }
        var s = Math.max(0, Math.round(Date.now() / 1000 - ts));
        if (s < 60) { return t("just now"); }
        if (s < 3600) { return tf("{0} min ago", Math.round(s / 60)); }
        if (s < 86400) { return tf("{0} h ago", Math.round(s / 3600)); }
        return tf("{0} days ago", Math.round(s / 86400));
    }
    RB.ago = ago;

    // ------------------------------------------------------------------ API
    function call(method, url, body, retry) {
        return new Promise(function (resolve, reject) {
            var o = {
                url: url, method: method, dataType: "json", success: resolve,
                error: function (x) {
                    var d = x.responseJSON || {};
                    if (x.status === 429 && !retry) { setTimeout(function () { call(method, url, body, true).then(resolve, reject); }, 1100); return; }
                    reject({ error: d.error || tf("Request failed (HTTP {0})", x.status), detail: d.detail, status: x.status });
                }
            };
            if (method !== "GET") { o.contentType = "application/json"; o.data = JSON.stringify(body || {}); }
            ($.cjax || $.ajax)(o);
        });
    }
    RB.get = function (url) { return call("GET", url); };
    RB.post = function (url, body) { return call("POST", url, body); };
    RB.errText = function (e) { return (e && (e.error || e.message)) || t("Request failed"); };

    // ------------------------------------------------------------------ modal dialog (kit markup, focus trap like ZxUI.confirm)
    var dseq = 0;
    var FOCUSABLE = "a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex='-1'])";
    // o: {title, body: Node, confirmLabel, cancelLabel, danger, width, noCancel}; returns Promise<boolean>; o.onReady({ok, cancel, close})
    RB.dialog = function (o) {
        return new Promise(function (resolve) {
            var previous = document.activeElement, id = "rbdlg" + (++dseq), closed = false;
            var cancel = h("button", { type: "button", class: "zx-btn zx-btn--secondary" }, o.cancelLabel || t("Cancel"));
            var ok = h("button", { type: "button", class: "zx-btn " + (o.danger ? "zx-btn--danger" : "zx-btn--primary") }, o.confirmLabel || t("Confirm"));
            var dlg = h("div", { class: "zx-dialog" + (o.danger ? " zx-dialog--danger" : ""), role: o.danger ? "alertdialog" : "dialog", "aria-modal": "true", "aria-labelledby": id + "t", style: "width:min(" + (o.width || "44rem") + ",100%)" },
                h("h2", { class: "zx-dialog__title", id: id + "t" }, o.title), o.body,
                h("div", { class: "zx-dialog__foot" }, o.noCancel ? null : cancel, ok));
            var back = h("div", { class: "zx-dialog-backdrop" }, dlg);
            function close(r) {
                if (closed) { return; }
                closed = true;
                document.removeEventListener("keydown", onKey, true);
                if (back.parentNode) { back.parentNode.removeChild(back); }
                if (previous && previous.focus) { try { previous.focus(); } catch (e) { /* gone */ } }
                resolve(r);
            }
            function onKey(e) {
                if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(false); return; }
                if (e.key !== "Tab") { return; }
                var f = Array.prototype.filter.call(dlg.querySelectorAll(FOCUSABLE), function (n) { return n.offsetParent !== null; });
                if (!f.length) { return; }
                var first = f[0], last = f[f.length - 1];
                if (!dlg.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
                else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
                else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
            }
            cancel.addEventListener("click", function () { close(false); });
            ok.addEventListener("click", function () { if (!ok.disabled) { close(true); } });
            back.addEventListener("mousedown", function (e) { if (e.target === back) { close(false); } });
            document.addEventListener("keydown", onKey, true);
            document.body.appendChild(back);
            (o.danger ? cancel : ok).focus();
            if (o.onReady) { o.onReady({ ok: ok, cancel: cancel, close: close, dlg: dlg }); }
        });
    };

    // ------------------------------------------------------------------ labels
    RB.actionLabel = function (a) { return t((D.actions[a.type] || { label: a.type }).label); };
    RB.actionBadge = function (a) {
        var txt = RB.actionLabel(a), cls = "";
        if (a.type === "block") { txt = tf("Block {0}", a.status || 403); cls = "danger"; }
        else if (a.type === "redirect") { txt = tf("Redirect {0}", a.status || 302); cls = "warn"; }
        else if (a.type === "challenge") { cls = "warn"; }
        else if (a.type === "rate_limit") { txt = tf("Rate limit {0}/s", a.rate); cls = "warn"; }
        else if (a.type === "allow") { cls = "info"; }
        return badge(txt, cls);
    };
    RB.scopeLabel = function (site) {
        if (site === "") { return t("All sites (global rules)"); }
        if (S.meta && site === S.meta.default_site_key) { return t("Default site"); }
        return site;
    };
    RB.isAI = function (r) { return (r.description || "").indexOf(AI_MARK) === 0; };

    // ------------------------------------------------------------------ loading
    function loadMeta() {
        if (S.meta) { return Promise.resolve(S.meta); }
        return RB.get("./api/ruleset/meta").then(function (m) { S.meta = m; M.setMeta(m); return m; });
    }
    RB.loadMeta = loadMeta;
    RB.loadLists = function () { return RB.get("./api/ruleset/lists").then(function (l) { S.lists = l || []; return S.lists; }); };
    function loadRules(site) {
        var seq = ++S.loadSeq;
        return RB.get("./api/ruleset/rules?site=" + encodeURIComponent(site)).then(function (r) { if (seq === S.loadSeq) { S.rules = r || []; } return S.rules; });
    }
    RB.loadRules = loadRules;

    function fillScopeSelects() {
        var opts = [["", t("All sites (global rules)")], [S.meta.default_site_key, t("Default site")]];
        (S.meta.sites || []).forEach(function (s) { opts.push([s, s]); });
        ["#rbScope", "#rbTestSite"].forEach(function (sel) {
            var el = q(sel);
            if (!el) { return; }
            var cur = el.value;
            RB.clear(el);
            opts.forEach(function (o) { el.appendChild(h("option", { value: o[0], selected: o[0] === (sel === "#rbScope" ? S.site : cur) }, o[1])); });
        });
    }
    RB.scopeOptions = function () {
        var o = [["", t("All sites (global rules)")], [S.meta.default_site_key, t("Default site")]];
        (S.meta.sites || []).forEach(function (s) { o.push([s, s]); });
        return o;
    };

    // ------------------------------------------------------------------ rule list
    function spark(r) {
        var hrs = (r.stats && r.stats.hourly) || [], max = 1, total = 0;
        hrs.forEach(function (v) { max = Math.max(max, v); total += v; });
        var w = 4, gap = 1, hgt = 18, bars = [];
        hrs.forEach(function (v, i) {
            var bh = v ? Math.max(2, Math.round(v / max * hgt)) : 1;
            var rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
            rect.setAttribute("x", i * (w + gap)); rect.setAttribute("y", hgt - bh); rect.setAttribute("width", w); rect.setAttribute("height", bh);
            rect.setAttribute("fill", "currentColor"); rect.setAttribute("opacity", v ? "1" : "0.25");
            bars.push(rect);
        });
        var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("width", 24 * (w + gap)); svg.setAttribute("height", hgt); svg.setAttribute("role", "img"); svg.setAttribute("class", "rb-spark");
        svg.setAttribute("aria-label", total ? tf("{0} matches in the last 24 hours", total) : t("No matches in the last 24 hours"));
        bars.forEach(function (b) { svg.appendChild(b); });
        return svg;
    }

    function matchesFilter(r) {
        if (!S.q) { return true; }
        var needle = S.q.toLowerCase();
        return (r.name + " " + (r.description || "") + " " + (r.expression || "")).toLowerCase().indexOf(needle) >= 0;
    }

    function ruleRow(r, i, filtered) {
        var total = (r.stats.hits || 0) + (r.stats.dry_run || 0);
        var tr = h("tr", { "data-id": r.id, class: r.enabled ? "" : "rb-off" });
        var nameCell = h("td", { "data-label": t("Rule"), class: "rb-namecell" },
            h("div", { class: "rb-name" }, h("b", { text: r.name }), " ",
                RB.isAI(r) ? badge(t("AI proposal"), "info", t("Created from an AI suggestion after a human click")) : null,
                r.error ? badge(t("Cannot run"), "danger", r.error) : null,
                (r.warnings && r.warnings.length) ? badge(tf("{0} warning(s)", r.warnings.length), "warn", r.warnings.join("\n")) : null),
            h("div", { class: "rb-sum zx-muted", text: M.ruleSentence(r) }),
            r.error ? h("div", { class: "zx-error", text: r.error }) : null);
        var modeBtn = h("button", { type: "button", class: "zx-badge rb-modebtn zx-badge--" + (r.dry_run ? "info" : "ok"), "data-act": "mode",
            title: r.dry_run ? t("Log-only: matches are counted and recorded but nothing is done. Click to enforce.") : t("Enforcing: the action is performed. Click to switch to log-only."),
            "aria-label": (r.dry_run ? t("Log-only") : t("Enforcing")) + ": " + (r.dry_run ? t("switch to enforce") : t("switch to log-only")),
            onclick: function () { toggleMode(r); } }, r.dry_run ? t("Log-only") : t("Enforcing"));
        var sw = h("input", { type: "checkbox", class: "zx-switch", role: "switch", checked: r.enabled, "aria-label": tf("Enable rule {0}", r.name), "data-act": "enable",
            onchange: function () { setEnabled(r, sw); } });
        var nrows = S.rules.length, pos = S.rules.indexOf(r);
        tr.appendChild(h("td", { "data-label": "#", class: "zx-num rb-pos" }, String(pos + 1)));
        tr.appendChild(nameCell);
        tr.appendChild(h("td", { "data-label": t("Action") }, RB.actionBadge(r.action)));
        tr.appendChild(h("td", { "data-label": t("Mode") }, modeBtn));
        tr.appendChild(h("td", { "data-label": t("Matches"), class: "rb-hits" },
            h("div", {}, h("b", { class: "zx-num" }, String(total)), " ", h("span", { class: "zx-muted", text: r.stats.dry_run ? tf("({0} while log-only)", r.stats.dry_run) : "" })),
            h("div", { class: "rb-sparkbox" }, spark(r))));
        tr.appendChild(h("td", { "data-label": t("Last match") }, ago(r.stats.last_hit)));
        tr.appendChild(h("td", { "data-label": t("Enabled") }, sw));
        tr.appendChild(h("td", { class: "zx-actions" }, h("div", { class: "zx-row-actions" },
            (function () { var b = ibtn("arrow up", tf("Move {0} up", r.name), function () { move(r, -1); }); b.setAttribute("data-act", "up"); if (filtered || pos === 0) { b.disabled = true; } return b; })(),
            (function () { var b = ibtn("arrow down", tf("Move {0} down", r.name), function () { move(r, 1); }); b.setAttribute("data-act", "down"); if (filtered || pos === nrows - 1) { b.disabled = true; } return b; })(),
            (function () { var b = ibtn("edit outline", tf("Edit {0}", r.name), function () { RB.openEditor({ site: S.site, rule: r }); }); b.setAttribute("data-act", "edit"); return b; })(),
            (function () { var b = ibtn("copy outline", tf("Duplicate {0}", r.name), function () { duplicate(r); }); b.setAttribute("data-act", "dup"); return b; })(),
            (function () { var b = ibtn("trash alternate outline", tf("Delete {0}", r.name), function () { remove(r); }); b.setAttribute("data-act", "del"); return b; })())));
        return tr;
    }

    function renderRules(focus) {
        var box = RB.clear(q("#rbList"));
        var filtered = !!S.q;
        var rows = S.rules.filter(matchesFilter);
        q("#rbCount").textContent = S.rules.length ? (filtered ? tf("{0} of {1} rules", rows.length, S.rules.length) : tf("{0} rules", S.rules.length)) : "";
        q("#rbTemplatesCard").hidden = S.rules.length > 0 && !S.showTemplates;
        if (!S.rules.length) {
            box.appendChild(h("div", { class: "zx-empty" },
                h("div", { class: "zx-empty__icon", "aria-hidden": "true" }, h("i", { class: "shield alternate icon" })),
                h("h3", { class: "zx-empty__title" }, t("No rules in this scope yet")),
                h("p", { class: "zx-empty__text" }, t("A rule says WHEN a request looks a certain way, THEN do something. New rules start in log-only mode so you can watch what they would do before they act. Start from a template below or build one from scratch.")),
                h("button", { type: "button", class: "zx-btn zx-btn--primary", onclick: function () { RB.openEditor({ site: S.site }); } }, t("Create a rule"))));
            return;
        }
        if (!rows.length) {
            box.appendChild(h("div", { class: "zx-empty" }, h("h3", { class: "zx-empty__title" }, t("No rule matches this search")),
                h("button", { type: "button", class: "zx-btn zx-btn--secondary", onclick: function () { q("#rbSearch").value = ""; S.q = ""; renderRules(); } }, t("Clear the search"))));
            return;
        }
        var shown = rows.slice(0, S.shown);
        var tbody = h("tbody");
        shown.forEach(function (r, i) { tbody.appendChild(ruleRow(r, i, filtered)); });
        var tbl = h("table", { class: "zx-table zx-table--comfortable" },
            h("caption", { class: "zx-sr-only" }, t("Rules in evaluation order")),
            h("thead", {}, h("tr", {}, h("th", { scope: "col", class: "zx-num" }, "#"), h("th", { scope: "col" }, t("Rule")), h("th", { scope: "col" }, t("Action")), h("th", { scope: "col" }, t("Mode")),
                h("th", { scope: "col" }, t("Matches")), h("th", { scope: "col" }, t("Last match")), h("th", { scope: "col" }, t("Enabled")), h("th", { scope: "col", class: "zx-actions" }, t("Actions")))),
            tbody);
        box.appendChild(h("div", { class: "zx-table-wrap zx-table-wrap--tall", tabindex: "0", role: "region", "aria-label": t("Rules") }, tbl));
        if (rows.length > shown.length) {
            box.appendChild(h("p", { class: "rb-more" }, h("button", { type: "button", class: "zx-btn zx-btn--secondary",
                onclick: function () { S.shown += PAGE; renderRules(); } }, tf("Show {0} more ({1} left)", Math.min(PAGE, rows.length - shown.length), rows.length - shown.length))));
        }
        if (focus) {
            var el = box.querySelector('tr[data-id="' + focus.id + '"] [data-act="' + focus.act + '"]');
            if (el && el.disabled) { el = box.querySelector('tr[data-id="' + focus.id + '"] [data-act="' + (focus.act === "up" ? "down" : "up") + '"]'); }
            if (el && !el.disabled) { el.focus(); } else if ((el = box.querySelector('tr[data-id="' + focus.id + '"] [data-act]:not([disabled])'))) { el.focus(); }
        }
        updateOverview();
    }
    RB.renderRules = renderRules;

    function updateOverview() {
        var on = S.rules.filter(function (r) { return r.enabled; }).length, lo = S.rules.filter(function (r) { return r.enabled && r.dry_run; }).length;
        q("#rbOverview").textContent = S.rules.length ? tf("{0} active, {1} of them log-only. Rules run top to bottom; the first one that blocks, redirects or challenges ends the evaluation.", on, lo) : "";
    }

    function refresh(focus) {
        return Promise.all([loadMeta().then(fillScopeSelects), loadRules(S.site), RB.loadLists()]).then(function () {
            renderRules(focus);
            if (q("#rbListsBody")) { renderLists(); }
        }, function (e) {
            RB.clear(q("#rbList")).appendChild(h("div", { class: "zx-callout zx-callout--danger", role: "alert" }, h("div", { class: "zx-callout__body" }, RB.errText(e))));
        });
    }
    RB.refresh = refresh;

    // ------------------------------------------------------------------ list actions
    function setEnabled(r, sw) {
        var on = sw.checked;
        sw.disabled = true;
        RB.post("./api/ruleset/rule/" + (on ? "enable" : "disable"), { site: S.site, id: r.id }).then(function (ri) {
            Object.assign(r, ri);
            sw.disabled = false;
            RB.toast(on ? tf("Rule “{0}” enabled (applied immediately)", r.name) : tf("Rule “{0}” disabled (applied immediately)", r.name));
        }, function (e) { sw.checked = !on; sw.disabled = false; RB.toast(RB.errText(e), { type: "error" }); });
    }

    function move(r, dir) {
        var ids = S.rules.map(function (x) { return x.id; }), i = ids.indexOf(r.id), j = i + dir;
        if (i < 0 || j < 0 || j >= ids.length) { return; }
        ids.splice(i, 1); ids.splice(j, 0, r.id);
        RB.post("./api/ruleset/rule/reorder", { site: S.site, order: ids }).then(function (list) {
            S.rules = list || [];
            renderRules({ id: r.id, act: dir < 0 ? "up" : "down" });
            var s = q("#rbLive"); if (s) { s.textContent = tf("{0} moved to position {1} of {2}", r.name, j + 1, ids.length); }
        }, function (e) { RB.toast(RB.errText(e), { type: "error" }); });
    }

    function ruleInput(r, over) {
        var o = { name: r.name, description: r.description || "", enabled: r.enabled, dry_run: r.dry_run, tree: r.tree, action: r.action };
        return Object.assign(o, over || {});
    }

    function duplicate(r) {
        var name = (r.name + " " + t("(copy)")).slice(0, 80);
        var pos = S.rules.indexOf(r) + 1;
        RB.post("./api/ruleset/rule/create", { site: S.site, position: pos, rule: ruleInput(r, { name: name, dry_run: true, enabled: false }) }).then(function (ni) {
            RB.toast(tf("Copied as “{0}”: disabled and log-only until you review it", name));
            return loadRules(S.site).then(function () { renderRules({ id: ni.id, act: "edit" }); });
        }, function (e) { RB.toast(RB.errText(e), { type: "error" }); });
    }

    function remove(r) {
        ZxUI.confirm({ title: tf("Delete rule “{0}”?", r.name), message: t("The rule stops acting immediately. Its counters are lost. You can undo this right after."), danger: true, confirmLabel: t("Delete rule") }).then(function (ok) {
            if (!ok) { return; }
            var pos = S.rules.indexOf(r), snapshot = ruleInput(r), site = S.site;
            RB.post("./api/ruleset/rule/delete", { site: site, id: r.id }).then(function () {
                RB.toast(tf("Rule “{0}” deleted", r.name), { undo: function () {
                    RB.post("./api/ruleset/rule/create", { site: site, position: pos, rule: snapshot }).then(function () { if (S.site === site) { refresh(); } RB.toast(t("Rule restored")); },
                        function (e) { RB.toast(RB.errText(e), { type: "error" }); });
                } });
                return loadRules(S.site).then(function () { renderRules(); });
            }, function (e) { RB.toast(RB.errText(e), { type: "error" }); });
        });
    }

    // Switch a saved rule between log-only and enforce. Enforce asks first and shows the tester for a sample request.
    function toggleMode(r) {
        if (!r.dry_run) {
            RB.post("./api/ruleset/rule/dryrun", { site: S.site, id: r.id, dry_run: true }).then(function (ri) {
                Object.assign(r, ri); renderRules({ id: r.id, act: "mode" }); RB.toast(tf("Rule “{0}” is log-only now", r.name));
            }, function (e) { RB.toast(RB.errText(e), { type: "error" }); });
            return;
        }
        RB.confirmEnforce({ site: S.site, name: r.name, tree: r.tree, action: r.action, sentence: M.ruleSentence(r), issues: RB.lockoutClient(r.tree, r.action, S.site) }).then(function (ok) {
            if (!ok) { return; }
            RB.post("./api/ruleset/rule/dryrun", { site: S.site, id: r.id, dry_run: false }).then(function (ri) {
                Object.assign(r, ri); renderRules({ id: r.id, act: "mode" }); RB.toast(tf("Rule “{0}” is enforced now", r.name));
            }, function (e) { RB.toast(RB.errText(e), { type: "error" }); });
        });
    }

    // ------------------------------------------------------------------ request tester (also used inside the editor and the enforce dialog)
    function testBox(res, candidate) {
        var box = h("div", { class: "rb-testres" });
        if (res.error) { box.appendChild(h("div", { class: "zx-callout zx-callout--danger", role: "alert" }, h("div", { class: "zx-callout__body" }, res.error))); return box; }
        box.appendChild(h("div", { class: "zx-callout zx-callout--info", role: "note" }, h("span", { class: "zx-callout__icon", "aria-hidden": "true" }, h("i", { class: "info circle icon" })),
            h("div", { class: "zx-callout__body" }, t("Simulation only: nothing was performed, no counter changed and nothing was sent to any server."))));
        var draft = (res.rules || []).filter(function (x) { return x.scope === "draft"; })[0];
        if (draft) {
            box.appendChild(h("p", { class: "rb-verdict" }, draft.matched ? badge(t("This rule matches the request"), "warn") : badge(t("This rule does not match the request"), "ok")));
        } else {
            var dec = res.decision || "none";
            box.appendChild(h("p", { class: "rb-verdict" }, badge(dec === "none" ? t("No rule decides: the request passes") : tf("Decision: {0}", t(dec)), dec === "none" ? "ok" : (dec === "allow" ? "info" : "danger")), " ",
                h("span", { text: res.effect || "" })));
            if (res.decided_by) { box.appendChild(h("p", {}, tf("Decided by the rule “{0}” ({1}).", res.decided_by.name, res.decided_by.scope === "global" ? t("global") : t("site")))); }
        }
        var extra = h("ul", { class: "rb-extra" });
        (res.tags || []).forEach(function (x) { extra.appendChild(h("li", {}, tf("Tag added: {0}", x))); });
        (res.skips || []).forEach(function (x) { extra.appendChild(h("li", {}, tf("Skipped: {0}", x))); });
        (res.request_header_changes || []).forEach(function (x) { extra.appendChild(h("li", {}, tf("Request header: {0}", x))); });
        (res.response_header_changes || []).forEach(function (x) { extra.appendChild(h("li", {}, tf("Response header: {0}", x))); });
        if (extra.childNodes.length) { box.appendChild(extra); }
        (res.rules || []).forEach(function (r, i) {
            var head = h("div", { class: "rb-trhead" },
                h("span", { class: "zx-num" }, String(i + 1) + "."), " ", h("b", { text: r.name || t("(unnamed)") }), " ",
                r.scope && r.scope !== "draft" ? badge(r.scope === "global" ? t("global") : t("site")) : null, " ",
                r.dry_run ? badge(t("Log-only"), "info") : null, " ",
                r.evaluated ? badge(r.matched ? t("Matched") : t("Did not match"), r.matched ? "warn" : "") : badge(t("Not evaluated")), " ",
                r.action ? h("span", { class: "zx-muted", text: r.action }) : null);
            var det = h("details", { class: "rb-trace", open: (draft || r.matched) ? true : null }, h("summary", {}, head));
            if (r.note) { det.appendChild(h("p", { class: "zx-muted", text: r.note })); }
            if (r.trace && r.trace.length) {
                var ul = h("ul", { class: "rb-trlist" });
                r.trace.forEach(function (en) {
                    ul.appendChild(h("li", { style: "margin-left:" + (en.depth * 1.1) + "rem" },
                        h("span", { class: "zx-badge zx-badge--" + (en.result ? "ok" : "danger"), text: en.result ? t("true") : t("false") }), " ",
                        h("span", { class: "zx-mono", text: en.text }), en.actual !== undefined && en.actual !== "" ? h("span", { class: "zx-muted" }, " → ", h("span", { class: "zx-mono", text: en.actual })) : null));
                });
                det.appendChild(ul);
            }
            box.appendChild(det);
        });
        if (res.fields) {
            var tb = h("tbody");
            Object.keys(res.fields).sort().forEach(function (k) { tb.appendChild(h("tr", {}, h("th", { scope: "row", class: "zx-mono", text: k }), h("td", { class: "zx-mono", text: res.fields[k] }))); });
            box.appendChild(h("details", { class: "rb-fields" }, h("summary", {}, t("How Zoraxy read this request")), h("div", { class: "zx-table-wrap" }, h("table", { class: "zx-table zx-table--compact" }, tb))));
        }
        return box;
    }
    RB.testBox = testBox;

    // Build a tester form. opts: {site: fn, candidate: fn -> {tree}|{expression}|null, sample: {url, method, ip, country, headers}, onResult}
    RB.tester = function (opts) {
        var id = "rbt" + (++dseq), sm = opts.sample || {};
        var url = h("input", { class: "zx-input", id: id + "u", type: "text", value: sm.url || "https://example.com/", autocomplete: "off", spellcheck: "false", maxlength: "2000" });
        var method = h("select", { class: "zx-select", id: id + "m" }, ["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"].map(function (m) { return h("option", { value: m, selected: m === (sm.method || "GET") }, m); }));
        var ip = h("input", { class: "zx-input", id: id + "i", type: "text", value: sm.ip || "203.0.113.9", autocomplete: "off", spellcheck: "false", maxlength: "64" });
        var country = h("input", { class: "zx-input zx-input--short", id: id + "c", type: "text", value: sm.country || "", maxlength: "2", placeholder: "US", autocomplete: "off", spellcheck: "false" });
        var hdrs = h("textarea", { class: "zx-textarea", id: id + "h", rows: "3", spellcheck: "false", placeholder: "User-Agent: curl/8.0\nX-Api-Key: 123" }, sm.headers || "");
        var out = h("div", { "aria-live": "polite" });
        var run = h("button", { type: "button", class: "zx-btn zx-btn--secondary" }, t("Run the test"));
        function field(label, ctl, forId, help) { return h("div", { class: "zx-field" }, h("div", { class: "zx-field__label-row" }, h("label", { class: "zx-field__label", for: forId }, label)), h("div", { class: "zx-field__control" }, ctl), help ? h("p", { class: "zx-help" }, help) : null); }
        var form = h("div", { class: "rb-tform" },
            field(t("Address (URL)"), url, id + "u", t("A full address (https://host/path?x=1) or just a path; the host then comes from a Host header.")),
            h("div", { class: "rb-trow" }, field(t("Method"), method, id + "m"), field(t("Client IP address"), ip, id + "i"), field(t("Country (optional)"), country, id + "c", t("Two letters; empty = look up the address in the GeoIP database."))),
            field(t("Request headers (optional)"), hdrs, id + "h", t("One per line: Name: value")),
            h("div", { class: "zx-row" }, run));
        function parseHeaders() {
            var m = {};
            hdrs.value.split("\n").forEach(function (l) { var i = l.indexOf(":"); if (i > 0) { m[l.slice(0, i).trim()] = l.slice(i + 1).trim(); } });
            return m;
        }
        function doRun() {
            var cand = opts.candidate ? opts.candidate() : null;
            if (opts.candidate && !cand) { RB.clear(out).appendChild(h("div", { class: "zx-callout zx-callout--warn", role: "alert" }, h("div", { class: "zx-callout__body" }, t("Complete the conditions first (every condition needs a value)")))); return Promise.resolve(); }
            var body = { site: opts.site ? opts.site() : "", method: method.value, url: url.value.trim(), headers: parseHeaders(), client_ip: ip.value.trim(), country: country.value.trim().toUpperCase() };
            if (cand) { Object.assign(body, cand); }
            ZxUI.setLoading(run, true);
            return RB.post("./api/ruleset/test", body).then(function (res) {
                ZxUI.setLoading(run, false);
                RB.clear(out).appendChild(testBox(res, cand));
                if (opts.onResult) { opts.onResult(res); }
                return res;
            }, function (e) { ZxUI.setLoading(run, false); RB.clear(out).appendChild(h("div", { class: "zx-callout zx-callout--danger", role: "alert" }, h("div", { class: "zx-callout__body" }, RB.errText(e)))); });
        }
        run.addEventListener("click", doRun);
        var el = h("div", {}, form, out);
        return { el: el, run: doRun, setSample: function (s) { if (s.url) { url.value = s.url; } if (s.method) { method.value = s.method; } if (s.ip) { ip.value = s.ip; } }, inputs: { url: url, ip: ip } };
    };

    // ------------------------------------------------------------------ client-side lock-out heuristics (+ server probes through the tester)
    function walkConds(tree, fn) {
        (function walk(n, neg) {
            if (!n) { return; }
            if (n.type === "cond") { fn(n, neg); return; }
            (n.children || []).forEach(function (c) { walk(c, neg || n.type === "not"); });
        })(tree, false);
    }
    var BLOCKING = { block: 1, challenge: 1, redirect: 1, rate_limit: 1 };
    RB.blocking = function (a) { return !!(a && BLOCKING[a.type]); };
    RB.lockoutClient = function (tree, action, site) {
        var out = [];
        if (!RB.blocking(action) || !tree) { return out; }
        var host = (location.hostname || "").toLowerCase();
        if (host && (site === host || site === location.host)) { out.push(tf("This rule set belongs to {0}, the address you use for the admin interface.", host)); }
        var flat = 0, positive = 0;
        walkConds(tree, function (c, neg) {
            flat++;
            var vals = Array.isArray(c.value) ? c.value : [c.value];
            if (host && (c.field === "http.host" || c.field === "tls.sni") && vals.some(function (v) { return typeof v === "string" && v.toLowerCase().indexOf(host) >= 0; })) {
                out.push(tf("A condition names the admin address {0}.", host));
            }
            var v0 = vals[0];
            if (c.field === "http.path" && ((c.op === "starts_with" && v0 === "/") || (c.op === "matches" && (v0 === ".*" || v0 === "^" || v0 === "." || v0 === "^/")) || (c.op === "ne" && v0 === "") || (c.op === "contains" && v0 === "/"))) {
                out.push(t("This pattern matches every path, so it matches (nearly) every request."));
            }
            if (!neg && (c.op === "not_in" || c.op === "ne") && (c.field === "ip.country" || c.field === "ip.src")) { positive++; }
        });
        if (positive && flat === positive) { out.push(t("This blocks everybody who is NOT on the list. If your own address or country is not on it, you lock yourself out.")); }
        return out.filter(function (x, i) { return out.indexOf(x) === i; });
    };
    // three probes through the real tester: the admin address from a public client, an unrelated host, a private (LAN) client
    RB.lockoutProbe = function (cand, site) {
        var host = location.hostname || "localhost";
        function probe(url, ip) { return RB.post("./api/ruleset/test", Object.assign({ site: site, method: "GET", url: url, client_ip: ip }, cand)).then(function (r) { return !!(r && r.rules && r.rules[0] && r.rules[0].matched); }, function () { return false; }); }
        return Promise.all([probe("https://" + host + "/", "203.0.113.50"), probe("https://probe.invalid/", "198.51.100.23"), probe("https://" + host + "/", "192.168.1.10")]).then(function (r) {
            var out = [];
            if (r[0]) { out.push(tf("It matches a request to the admin address {0}. If you reach Zoraxy's admin interface through a proxy rule, enforcing it can lock you out.", host)); }
            if (r[1] && r[0]) { out.push(t("It matches an unrelated host too: this rule is very broad.")); }
            else if (r[1]) { out.push(t("It matches requests to an unrelated host: this rule is very broad.")); }
            if (r[2]) { out.push(t("It matches requests from private (LAN) addresses, which is how you may reach the admin interface.")); }
            return out;
        });
    };

    // Confirmation before a rule starts acting. o: {site, name, tree|expression, action, sentence, issues[]} -> Promise<boolean>
    RB.confirmEnforce = function (o) {
        var cand = o.expression ? { expression: o.expression } : { tree: o.tree };
        var sample = sampleFor(o.tree);
        var tester = RB.tester({ site: function () { return o.site; }, candidate: function () { return cand; }, sample: sample });
        var issues = h("div");
        function showIssues(list) {
            RB.clear(issues);
            if (list.length) {
                issues.appendChild(h("div", { class: "zx-callout zx-callout--warn", role: "alert" }, h("span", { class: "zx-callout__icon", "aria-hidden": "true" }, h("i", { class: "exclamation triangle icon" })),
                    h("div", { class: "zx-callout__body" }, h("span", { class: "zx-callout__title" }, t("This rule can lock you out")), h("ul", {}, list.map(function (x) { return h("li", { text: x }); })))));
            }
        }
        showIssues(o.issues || []);
        var body = h("div", { class: "rb-enforce" },
            h("p", {}, tf("“{0}” will start acting on real traffic.", o.name)),
            h("p", { class: "rb-sentence", text: o.sentence || "" }), issues,
            h("p", { class: "zx-muted" }, t("Try a sample request first. The test below only simulates; it does not change anything.")),
            tester.el);
        var p = RB.dialog({ title: t("Enforce this rule?"), body: body, confirmLabel: t("Enforce rule"), danger: true, width: "46rem", onReady: function () { tester.run(); } });
        if (RB.lockoutProbe && RB.blocking(o.action)) { RB.lockoutProbe(cand, o.site).then(function (more) { showIssues(((o.issues || []).concat(more)).filter(function (x, i, a) { return a.indexOf(x) === i; })); }); }
        return p;
    };
    // a plausible request for the tree: first path / host value found
    function sampleFor(tree) {
        var s = { url: "https://example.com/", method: "GET", ip: "203.0.113.9" }, host = "example.com", path = "/";
        walkConds(tree, function (c) {
            if (c.field === "http.host" && typeof c.value === "string" && c.value) { host = c.value; }
            if (c.field === "http.path" && typeof c.value === "string" && c.value.charAt(0) === "/" && c.op !== "ne") { path = c.value; }
            if (c.field === "http.method" && typeof c.value === "string") { s.method = c.value; }
        });
        s.url = "https://" + host + path;
        return s;
    }
    RB.sampleFor = sampleFor;

    // ------------------------------------------------------------------ templates
    function renderTemplates() {
        var box = RB.clear(q("#rbTemplates"));
        D.templates.forEach(function (tp) {
            box.appendChild(h("button", { type: "button", class: "rb-tpl", "data-tpl": tp.id, onclick: function () { RB.openEditor({ site: S.site, draft: JSON.parse(JSON.stringify(tp)), fromTemplate: true }); } },
                h("i", { class: tp.icon + " icon", "aria-hidden": "true" }), h("b", {}, t(tp.title)), h("span", { class: "zx-muted" }, t(tp.desc))));
        });
    }

    // ------------------------------------------------------------------ lists
    function typeLabel(x) { return x === "ip" ? t("IP addresses and networks") : x === "country" ? t("Countries") : t("Text values"); }
    function renderLists() {
        var body = RB.clear(q("#rbListsBody"));
        if (!S.lists.length) {
            body.appendChild(h("div", { class: "zx-empty" }, h("div", { class: "zx-empty__icon", "aria-hidden": "true" }, h("i", { class: "list icon" })),
                h("h3", { class: "zx-empty__title" }, t("No named lists yet")),
                h("p", { class: "zx-empty__text" }, t("A list is a reusable set of addresses, countries or words, for example your office networks. Rules refer to it by name, so you edit it in one place.")),
                h("button", { type: "button", class: "zx-btn zx-btn--primary", onclick: function () { listForm(null); } }, t("Create a list"))));
            return;
        }
        var tb = h("tbody");
        S.lists.forEach(function (l) {
            var used = l.used_by || [];
            var del = ibtn("trash alternate outline", tf("Delete list {0}", l.name), function () { deleteList(l); });
            if (used.length) { del.setAttribute("aria-disabled", "true"); del.title = tf("In use by {0} rule(s): remove it from the rules first", used.length); }
            tb.appendChild(h("tr", { "data-list": l.name },
                h("td", { "data-label": t("Name") }, h("b", { class: "zx-mono", text: "$" + l.name }), l.description ? h("div", { class: "zx-muted", text: l.description }) : null),
                h("td", { "data-label": t("Type") }, typeLabel(l.type)),
                h("td", { "data-label": t("Entries"), class: "zx-num" }, String((l.items || []).length)),
                h("td", { "data-label": t("Used by") }, used.length ? h("span", { title: used.join("\n") }, tf("{0} rule(s)", used.length)) : h("span", { class: "zx-muted" }, t("not used"))),
                h("td", { class: "zx-actions" }, h("div", { class: "zx-row-actions" }, ibtn("edit outline", tf("Edit list {0}", l.name), function () { listForm(l); }), del))));
        });
        body.appendChild(h("div", { class: "zx-table-wrap zx-table-wrap--tall", tabindex: "0", role: "region", "aria-label": t("Named lists") },
            h("table", { class: "zx-table zx-table--comfortable" }, h("thead", {}, h("tr", {}, h("th", { scope: "col" }, t("Name")), h("th", { scope: "col" }, t("Type")), h("th", { scope: "col", class: "zx-num" }, t("Entries")),
                h("th", { scope: "col" }, t("Used by")), h("th", { scope: "col", class: "zx-actions" }, t("Actions")))), tb)));
    }

    function deleteList(l) {
        if ((l.used_by || []).length) {
            RB.toast(tf("The list “{0}” is used by {1} and cannot be deleted. Remove it from those rules first.", l.name, l.used_by.join(", ")), { type: "error" });
            return;
        }
        ZxUI.confirm({ title: tf("Delete list “{0}”?", l.name), message: tf("It holds {0} entries. No rule uses it.", (l.items || []).length), danger: true, confirmLabel: t("Delete list") }).then(function (ok) {
            if (!ok) { return; }
            RB.post("./api/ruleset/list/delete", { name: l.name }).then(function () { RB.toast(tf("List “{0}” deleted", l.name)); return RB.loadLists().then(renderLists); },
                function (e) { RB.toast(RB.errText(e), { type: "error" }); });
        });
    }

    function listForm(l) {
        var box = RB.clear(q("#rbListForm")), lim = S.meta.limits;
        var isNew = !l, id = "rbl" + (++dseq);
        var name = h("input", { class: "zx-input", id: id + "n", type: "text", maxlength: "32", value: l ? l.name : "", readOnly: !isNew, autocomplete: "off", spellcheck: "false", "aria-describedby": id + "nh" });
        var type = h("select", { class: "zx-select", id: id + "t" }, ["ip", "country", "string"].map(function (x) { return h("option", { value: x, selected: l && l.type === x }, typeLabel(x)); }));
        var desc = h("input", { class: "zx-input", id: id + "d", type: "text", maxlength: "200", value: l ? (l.description || "") : "" });
        var items = h("textarea", { class: "zx-textarea rb-items", id: id + "i", rows: "8", spellcheck: "false", "aria-describedby": id + "ih" }, l ? (l.items || []).join("\n") : "");
        var count = h("span", {});
        var msg = h("div", { class: "zx-error", role: "alert" });
        function lines() { return items.value.split("\n").map(function (x) { return x.trim(); }).filter(Boolean); }
        function upd() {
            var n = lines().length;
            count.textContent = tf("{0} of {1} entries", n, lim.list_items);
            hint.textContent = type.value === "ip" ? t("One address or network per line, for example 203.0.113.7 or 198.51.100.0/24 (IPv4 and IPv6).") : type.value === "country" ? t("One two-letter country code per line, upper case, for example US.") : t("One exact value per line (case sensitive).");
        }
        var hint = h("span", { id: id + "ih" });
        var save = h("button", { type: "button", class: "zx-btn zx-btn--primary" }, isNew ? t("Create list") : t("Save list"));
        save.addEventListener("click", function () {
            msg.textContent = "";
            ZxUI.setLoading(save, true);
            RB.post("./api/ruleset/list/save", { name: name.value.trim(), type: type.value, description: desc.value.trim(), items: lines() }).then(function () {
                ZxUI.setLoading(save, false);
                RB.clear(box); RB.toast(tf("List “{0}” saved", name.value.trim()));
                return RB.loadLists().then(renderLists);
            }, function (e) { ZxUI.setLoading(save, false); msg.textContent = RB.errText(e) + (e.detail ? " (" + (e.detail.message || JSON.stringify(e.detail)) + ")" : ""); });
        });
        items.addEventListener("input", upd); type.addEventListener("change", upd); upd();
        function f(label, ctl, fid, help, hid) { return h("div", { class: "zx-field" }, h("div", { class: "zx-field__label-row" }, h("label", { class: "zx-field__label", for: fid }, label)), h("div", { class: "zx-field__control" }, ctl), help ? h("p", { class: "zx-help", id: hid }, help) : null); }
        box.appendChild(h("div", { class: "zx-card" }, h("div", { class: "zx-card__head" }, h("h3", { class: "zx-card__title" }, isNew ? t("New list") : tf("Edit list {0}", l.name))),
            h("div", { class: "zx-card__body zx-stack" },
                f(t("Name"), name, id + "n", tf("Lower case letters, digits and _, starting with a letter, up to 32 characters. Rules use it as ${0}.", "name"), id + "nh"),
                f(t("Type"), type, id + "t", t("A list in use cannot change its type.")),
                f(t("Description (optional)"), desc, id + "d"),
                h("div", { class: "zx-field" }, h("div", { class: "zx-field__label-row" }, h("label", { class: "zx-field__label", for: id + "i" }, t("Entries"))), h("div", { class: "zx-field__control" }, items),
                    h("p", { class: "zx-help" }, hint, " ", count, " ", tf("Limits: {0} entries per list (each up to 256 characters), {1} lists in total.", lim.list_items, lim.lists))),
                msg),
            h("div", { class: "zx-card__foot zx-row" }, save, h("button", { type: "button", class: "zx-btn zx-btn--ghost", onclick: function () { RB.clear(box); } }, t("Cancel")))));
        name.focus();
        box.scrollIntoView({ block: "nearest" });
    }

    // ------------------------------------------------------------------ import from the existing rules
    function renderImport(res) {
        var box = RB.clear(q("#rbImportBody"));
        box.appendChild(h("div", { class: "zx-callout zx-callout--info", role: "note" }, h("span", { class: "zx-callout__icon", "aria-hidden": "true" }, h("i", { class: "info circle icon" })), h("div", { class: "zx-callout__body", text: res.statement || "" })));
        var props = res.proposals || [];
        if (!props.length) { box.appendChild(h("div", { class: "zx-empty" }, h("h3", { class: "zx-empty__title" }, t("Nothing to import")), h("p", { class: "zx-empty__text" }, t("There are no path rules, header rules, bot rules or access list entries that can become rules.")))); }
        var list = h("div", { class: "rb-props" }), boxes = [];
        props.forEach(function (p, i) {
            var cb = h("input", { type: "checkbox", id: "rbp" + i, checked: p.valid, disabled: !p.valid, "aria-describedby": "rbpd" + i });
            boxes.push(cb);
            var tree = p.rule.tree, sentence = "";
            try { sentence = p.rule.expression ? p.rule.expression : M.sentence(M.fromTree(tree), p.rule.action); } catch (e) { sentence = ""; }
            list.appendChild(h("div", { class: "rb-prop" + (p.valid ? "" : " is-bad") },
                h("label", { class: "zx-check", for: "rbp" + i }, cb, h("b", { text: p.rule.name })), " ",
                badge(p.exact ? t("exact") : t("approximate"), p.exact ? "ok" : "warn"), " ", badge(RB.scopeLabel(p.site), ""), " ", RB.actionBadge(p.rule.action),
                h("div", { class: "zx-muted", id: "rbpd" + i }, tf("From {0}: {1}", p.source.replace(/_/g, " "), p.source_ref)),
                h("div", { class: "zx-mono rb-expr", text: p.rule.expression || sentence }),
                (p.notes || []).map(function (n) { return h("div", { class: "zx-help" }, n); }),
                (p.lists || []).length ? h("div", { class: "zx-help" }, tf("Also creates the list: {0}", p.lists.map(function (x) { return "$" + x.name; }).join(", "))) : null,
                !p.valid ? h("div", { class: "zx-error" }, tf("Cannot be imported: {0}", (p.problems || []).join("; "))) : null));
        });
        box.appendChild(list);
        if (props.length) {
            var msg = h("div", { "aria-live": "polite" });
            var go = h("button", { type: "button", class: "zx-btn zx-btn--primary" }, t("Create selected as log-only rules"));
            go.addEventListener("click", function () {
                var chosen = props.filter(function (p, i) { return boxes[i].checked && p.valid; });
                if (!chosen.length) { msg.textContent = t("Select at least one proposal."); return; }
                ZxUI.setLoading(go, true);
                var chain = Promise.resolve(), made = 0, failed = [];
                chosen.forEach(function (p) {
                    chain = chain.then(function () {
                        var lists = Promise.resolve();
                        (p.lists || []).forEach(function (l) { lists = lists.then(function () { return RB.post("./api/ruleset/list/save", l); }); });
                        return lists.then(function () {
                            var rule = Object.assign({}, p.rule, { dry_run: true });
                            return RB.post("./api/ruleset/rule/create", { site: p.site, rule: rule });
                        }).then(function () { made++; }, function (e) { failed.push(p.rule.name + ": " + RB.errText(e)); });
                    });
                });
                chain.then(function () {
                    ZxUI.setLoading(go, false);
                    msg.textContent = tf("{0} rule(s) created as log-only.", made) + (failed.length ? " " + tf("{0} failed: {1}", failed.length, failed.join(" | ")) : "");
                    RB.toast(tf("{0} rule(s) created as log-only", made));
                    refresh();
                });
            });
            box.appendChild(h("div", { class: "zx-row rb-importgo" }, go, msg));
        }
        var nc = res.not_converted || [];
        if (nc.length) {
            box.appendChild(h("h3", {}, t("What cannot be converted")));
            box.appendChild(h("ul", { class: "rb-nc" }, nc.map(function (x) { return h("li", {}, h("b", { text: x.source_ref }), " (", x.source.replace(/_/g, " "), "): ", x.reason); })));
        }
    }
    function runImport() {
        var b = q("#rbImportScan");
        ZxUI.setLoading(b, true);
        RB.get("./api/ruleset/migrate").then(function (res) { ZxUI.setLoading(b, false); renderImport(res); }, function (e) {
            ZxUI.setLoading(b, false);
            RB.clear(q("#rbImportBody")).appendChild(h("div", { class: "zx-callout zx-callout--danger", role: "alert" }, h("div", { class: "zx-callout__body" }, RB.errText(e))));
        });
    }

    // ------------------------------------------------------------------ public entry points
    window.RulesUI = {
        // open the page on a scope, filtered to a rule name (links from the blocked-request view)
        openFiltered: function (name, site) {
            if (typeof openTabById === "function") { openTabById("ruleset"); }
            init().then(function () {
                S.site = site || ""; q("#rbScope").value = S.site;
                S.q = name || ""; q("#rbSearch").value = S.q; S.shown = PAGE;
                return loadRules(S.site).then(function (rules) {
                    if (S.q && !rules.some(matchesFilter) && S.site !== "") { S.site = ""; q("#rbScope").value = ""; return loadRules("").then(function () {}); }
                }).then(function () { renderRules(); });
            });
        },
        // open the editor with a draft (AI proposals, templates): {site, name, description, expression|tree, action}
        openDraft: function (d) {
            if (typeof openTabById === "function") { openTabById("ruleset"); }
            init().then(function () { RB.openEditor({ site: d.site || "", draft: d, fromProposal: !!d.fromProposal }); });
        }
    };

    // ------------------------------------------------------------------ init
    var initP = null;
    // listeners are attached when the script loads (the markup is already there), so a click that arrives before the first
    // data load (command palette, deep link) still works; the handlers wait for init()
    function bind() {
        q("#rbScope").addEventListener("change", function () { S.site = this.value; S.shown = PAGE; refresh(); });
        q("#rbSearch").addEventListener("input", function () { S.q = this.value.trim(); S.shown = PAGE; if (S.inited) { renderRules(); } });
        q("#rbNew").addEventListener("click", function () { RB.openEditor({ site: S.site }); });
        q("#rbRefresh").addEventListener("click", function () { init().then(function () { refresh(); }); });
        q("#rbToggleTpl").addEventListener("click", function () { S.showTemplates = !S.showTemplates; q("#rbToggleTpl").setAttribute("aria-expanded", String(!!S.showTemplates)); init().then(function () { renderRules(); }); });
        q("#rbNewList").addEventListener("click", function () { init().then(function () { listForm(null); }); });
        q("#rbImportScan").addEventListener("click", runImport);
        var tt = RB.tester({ site: function () { return q("#rbTestSite").value; } });
        q("#rbTesterMount").appendChild(tt.el);
        ZxUI.tabs(q("#rbTabs"), { onChange: function (panel) { if (panel === "rbPanelLists" && S.inited) { renderLists(); } } });
    }
    function init() {
        if (initP) { return initP; }
        initP = loadMeta().then(function () {
            fillScopeSelects(); renderTemplates();
            S.inited = true;
            return refresh();
        });
        return initP;
    }
    RB.init = init;
    bind();
    if (typeof tabSwitchEventBind !== "undefined") { tabSwitchEventBind["ruleset"] = function () { if (S.ed) { return; } init().then(function () { if (initP && S.inited) { refresh(); } }); }; }
})();
