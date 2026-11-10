/*
    rulesedit.js: the visual rule editor of "Security rules" (WHEN conditions THEN action).

    Keyboard model (documented in docs/ux/rules-builder.md):
      - every control is a native button / select / input: Tab and Shift+Tab walk the page in reading order
      - a condition row is role=group "Condition N of M"; its buttons move it up / down inside its group, wrap it in a new
        group or remove it. Alt+ArrowUp / Alt+ArrowDown move the row from any text field of the row (not from a dropdown)
      - a group header has the same buttons; "Ungroup" dissolves a group into its parent
      - after any structural change the focus returns to the control that was used (or the new row's first field)
      - Ctrl/Cmd+S saves, Escape closes dialogs

    Saving is explicit (kit save bar). The bar tracks one hidden "state" field that holds the serialised rule, so any change
    made by the builder (typing, clicking, structural edits) counts as one unsaved change.
*/
(function () {
    "use strict";
    var RB = window.RB, h = RB.h, t = RB.t, tf = RB.tf, M = window.RBModel, D = window.RBData, S = RB.S;
    var ed = null, ui = null, bar = null, timer = null;

    function clone(x) { return JSON.parse(JSON.stringify(x)); }
    function id$(x) { return document.getElementById(x); }
    function rootEl() { return RB.q("#rbEditor"); }

    // ------------------------------------------------------------------ action model (strings while editing)
    function blankAction() { return { type: "block", status: "403", body: "", report_abuse: false, ttl: "30", skip: [], rate: "10", burst: "", rstatus: "", url: "", name: "", value: "", tag: "" }; }
    function loadAction(a) {
        var x = blankAction();
        x.status = ""; x.ttl = ""; x.rate = ""; x.burst = "";
        if (!a) { return x; }
        x.type = a.type || "block";
        if (a.type === "block") { x.status = a.status ? String(a.status) : ""; x.body = a.body || ""; x.report_abuse = !!a.report_abuse; }
        if (a.type === "redirect") { x.status = String(a.status || 302); x.url = a.url || ""; }
        if (a.type === "challenge") { x.ttl = a.ttl_minutes ? String(a.ttl_minutes) : ""; }
        if (a.type === "rate_limit") { x.rate = a.rate ? String(a.rate) : ""; x.burst = a.burst ? String(a.burst) : ""; x.rstatus = a.status ? String(a.status) : ""; }
        if (a.type === "skip") { x.skip = (a.skip || []).slice(); }
        if (/header$/.test(a.type)) { x.name = a.name || ""; x.value = a.value || ""; }
        if (a.type === "tag") { x.tag = a.tag || ""; }
        return x;
    }
    function num(s) { s = String(s).trim(); return /^-?\d+$/.test(s) ? parseInt(s, 10) : (s === "" ? undefined : NaN); }
    function buildAction() {
        var a = ed.a, o = { type: a.type };
        function put(k, v) { if (v !== undefined && !(typeof v === "number" && isNaN(v) && false)) { o[k] = v; } }
        switch (a.type) {
            case "block": put("status", num(a.status)); if (a.body) { o.body = a.body; } if (a.report_abuse) { o.report_abuse = true; } break;
            case "redirect": put("status", num(a.status)); o.url = a.url; break;
            case "challenge": put("ttl_minutes", num(a.ttl)); break;
            case "rate_limit": put("rate", num(a.rate)); put("burst", num(a.burst)); put("status", num(a.rstatus)); break;
            case "skip": o.skip = a.skip.slice(); break;
            case "set_request_header": case "set_response_header": o.name = a.name; o.value = a.value; break;
            case "remove_request_header": case "remove_response_header": o.name = a.name; break;
            case "tag": o.tag = a.tag; break;
        }
        return o;
    }

    // ------------------------------------------------------------------ serialisation (the save bar compares this string)
    function snapshot() {
        return { site: ed.site, name: ed.name, description: ed.description, enabled: ed.enabled, dry_run: ed.dry_run, tree: ed.adv ? null : M.toTree(ed.root), action: ed.a, adv: ed.adv, text: ed.adv ? ed.text : "" };
    }
    function touch() {
        if (!ed) { return; }
        ui.state.value = JSON.stringify(snapshot());
        if (bar) { bar.tracker.commit([]); }
        clearTimeout(timer);
        timer = setTimeout(function () { runCheck(); }, 450);
        ui.status.textContent = t("Checking…");
    }

    // ------------------------------------------------------------------ validation (server) and lock-out probes
    function candidate() {
        if (ed.adv) { return ed.check && ed.check.state === "ok" ? { expression: ed.text } : null; }
        if (M.incomplete(ed.root).length) { return null; }
        return { tree: M.toTree(ed.root) };
    }
    function runCheck() {
        clearTimeout(timer);
        var my = ++ed.seq, payload;
        ed.probeP = null;
        if (ed.adv) {
            if (!ed.text.trim()) { ed.check = { state: "empty" }; paint(); return Promise.resolve(ed.check); }
            payload = { expression: ed.text };
        } else {
            var inc = M.incomplete(ed.root);
            if (inc.length) { ed.check = { state: "incomplete", items: inc }; paint(); return Promise.resolve(ed.check); }
            payload = { tree: M.toTree(ed.root) };
        }
        payload.action = buildAction();
        return RB.post("./api/ruleset/validate", payload).then(function (res) {
            if (!ed || my !== ed.seq) { return ed && ed.check; }
            ed.check = { state: res.ok ? "ok" : "error", res: res };
            if (res.text) { ed.canon = res.text; }
            ed.lock = RB.lockoutClient(res.tree || (payload.tree), payload.action, ed.site);
            paint();
            if (res.ok && RB.blocking(payload.action)) {
                var cand = ed.adv ? { expression: ed.text } : { tree: payload.tree };
                ed.probeP = RB.lockoutProbe(cand, ed.site).then(function (more) {
                    if (!ed || my !== ed.seq) { return; }
                    ed.lock = ed.lock.concat(more).filter(function (x, i, a) { return a.indexOf(x) === i; });
                    paintLock();
                });
            }
            return ed.check;
        }, function (e) {
            if (!ed || my !== ed.seq) { return ed && ed.check; }
            ed.check = { state: "fail", error: RB.errText(e) };
            paint();
            return ed.check;
        });
    }

    // ------------------------------------------------------------------ painting of the check result
    function paintLock() {
        RB.clear(ui.lock);
        if (ed.lock && ed.lock.length) {
            ui.lock.appendChild(h("div", { class: "zx-callout zx-callout--warn", role: "note" }, h("span", { class: "zx-callout__icon", "aria-hidden": "true" }, h("i", { class: "exclamation triangle icon" })),
                h("div", { class: "zx-callout__body" }, h("span", { class: "zx-callout__title" }, t("This rule can lock you out")),
                    h("ul", {}, ed.lock.map(function (x) { return h("li", { text: x }); })),
                    h("span", {}, ed.dry_run ? t("It is log-only now, so nothing is blocked yet. You get this warning again, with a test, when you enforce it.") : t("It is set to enforce. Test it with your own address first.")))));
        }
    }
    function lineCol(text, pos) {
        var before = text.slice(0, pos), line = before.split("\n").length, col = pos - (before.lastIndexOf("\n") + 1) + 1;
        return { line: line, col: col };
    }
    function paint() {
        if (!ed || !ui) { return; }
        var c = ed.check || { state: "empty" }, res = c.res || {};
        // clear row errors
        Array.prototype.forEach.call(rootEl().querySelectorAll(".rb-rowerr"), function (e) { e.hidden = true; e.textContent = ""; });
        Array.prototype.forEach.call(rootEl().querySelectorAll("[aria-invalid]"), function (e) { e.removeAttribute("aria-invalid"); });
        RB.clear(ui.errBox); RB.clear(ui.warn); RB.clear(ui.errLine);
        ui.actionErr.hidden = true; ui.actionErr.textContent = "";
        var statusText = "";
        if (c.state === "ok") { statusText = t("Valid"); }
        else if (c.state === "incomplete") { statusText = tf("Incomplete: {0}", c.items[0].why); }
        else if (c.state === "empty") { statusText = t("Enter an expression"); }
        else if (c.state === "fail") { statusText = c.error; }
        else if (c.state === "error") { statusText = t("There are problems to fix"); }
        ui.status.textContent = statusText;
        ui.status.className = "rb-status " + (c.state === "ok" ? "is-ok" : (c.state === "error" || c.state === "fail" ? "is-bad" : ""));
        // incomplete rows
        if (c.state === "incomplete") {
            c.items.forEach(function (it) {
                var e = id$("rberr-" + it.node.id);
                if (e) { e.hidden = false; e.textContent = it.why; }
            });
        }
        (res.errors || []).forEach(function (er) {
            if (ed.adv) {
                var lc = lineCol(ed.text, er.pos || 0), line = ed.text.split("\n")[lc.line - 1] || "";
                ui.textArea.setAttribute("aria-invalid", "true");
                ui.errLine.appendChild(h("div", { class: "zx-error", role: "alert" }, tf("Line {0}, column {1}: {2}", lc.line, lc.col, er.message)));
                ui.errLine.appendChild(h("pre", { class: "rb-caret", "aria-hidden": "true" }, line + "\n" + new Array(lc.col).join(" ") + new Array(Math.max(1, Math.min((er.end || er.pos + 1) - er.pos, line.length - lc.col + 2))).join("^") + "^"));
            } else if (er.path !== undefined && er.path !== "") {
                var n = M.byPath(ed.root, er.path), e2 = id$("rberr-" + n.id);
                if (e2) { e2.hidden = false; e2.textContent = er.message; var ctl = e2.parentNode.querySelector("input, select, textarea"); if (ctl) { ctl.setAttribute("aria-invalid", "true"); } }
                else { ui.errBox.appendChild(h("div", { class: "zx-error", role: "alert" }, er.message)); }
            } else {
                ui.errBox.appendChild(h("div", { class: "zx-error", role: "alert" }, er.message));
            }
        });
        if (res.action_error) { ui.actionErr.hidden = false; ui.actionErr.textContent = res.action_error; }
        if (c.state === "error" && !(res.errors || []).length && !res.action_error) { ui.errBox.appendChild(h("div", { class: "zx-error", role: "alert" }, t("The server did not accept this rule."))); }
        if ((res.warnings || []).length) {
            ui.warn.appendChild(h("div", { class: "zx-callout zx-callout--warn", role: "note" }, h("span", { class: "zx-callout__icon", "aria-hidden": "true" }, h("i", { class: "exclamation triangle icon" })),
                h("div", { class: "zx-callout__body" }, h("span", { class: "zx-callout__title" }, t("Check this before saving")), h("ul", {}, res.warnings.map(function (w) { return h("li", { text: w }); })))));
        }
        // expression view and sentence
        var text = res.text || ed.canon || "";
        ui.exprView.textContent = c.state === "ok" || text ? text : "";
        ui.exprView.classList.toggle("is-stale", c.state !== "ok");
        if (ed.adv) {
            ui.sentence.textContent = c.state === "ok" && res.tree ? M.sentence(M.fromTree(res.tree), buildAction()) : t("Fix the expression to see the plain-English summary.");
        } else {
            ui.sentence.textContent = M.sentence(ed.root, buildAction());
        }
        ed.lock = c.state === "ok" ? (ed.lock || []) : [];
        paintLock();
    }

    // ------------------------------------------------------------------ small form helpers
    var fseq = 0;
    function fld(label, ctl, help, idTarget) {
        var fid = idTarget || ("rbf" + (++fseq));
        if (!idTarget && ctl.setAttribute) { ctl.id = fid; }
        return h("div", { class: "zx-field" }, h("div", { class: "zx-field__label-row" }, h("label", { class: "zx-field__label", for: fid }, label)), h("div", { class: "zx-field__control" }, ctl), help ? h("p", { class: "zx-help" }, help) : null);
    }
    function inp(value, onin, attrs) {
        var e = h("input", Object.assign({ class: "zx-input", type: "text", value: value, autocomplete: "off", spellcheck: "false" }, attrs || {}));
        e.addEventListener("input", function () { onin(e.value); touch(); });
        return e;
    }
    function sel(options, value, onch, attrs) {
        var e = h("select", Object.assign({ class: "zx-select" }, attrs || {}), options.map(function (o) { return h("option", { value: o[0], selected: String(o[0]) === String(value) }, o[1]); }));
        e.addEventListener("change", function () { onch(e.value); });
        return e;
    }
    function check(label, checked, onch, attrs) {
        var cb = h("input", Object.assign({ type: "checkbox", checked: !!checked }, attrs || {}));
        cb.addEventListener("change", function () { onch(cb.checked); });
        return h("label", { class: "zx-check" }, cb, h("span", {}, label));
    }

    // ------------------------------------------------------------------ conditions
    var countryDL = null;
    function ensureCountryDL() {
        if (countryDL && document.body.contains(countryDL)) { return; }
        countryDL = h("datalist", { id: "rbCountryDL" }, D.countries.map(function (c) { return h("option", { value: D.countryName(c) + " (" + c + ")" }); }));
        document.body.appendChild(countryDL);
    }
    function parseCountry(s) {
        s = String(s).trim();
        var m = /\(([A-Za-z]{2})\)\s*$/.exec(s), code = m ? m[1].toUpperCase() : (/^[A-Za-z]{2}$/.test(s) ? s.toUpperCase() : "");
        if (!code) { var low = s.toLowerCase(); D.countries.forEach(function (c) { if (D.countryName(c).toLowerCase() === low) { code = c; } }); }
        return D.countries.indexOf(code) >= 0 ? code : "";
    }
    function countryPicker(c) {
        ensureCountryDL();
        var chips = h("div", { class: "rb-chips" }), box = h("div", { class: "rb-picker" });
        var input = h("input", { class: "zx-input", type: "text", list: "rbCountryDL", placeholder: t("Type a country name or code, then Enter"), "aria-label": t("Add a country"), autocomplete: "off", spellcheck: "false" });
        function draw() {
            RB.clear(chips);
            c.items.forEach(function (code) {
                chips.appendChild(h("button", { type: "button", class: "rb-chip", "aria-label": tf("Remove {0}", D.countryName(code)), title: t("Remove"), onclick: function () {
                    c.items = c.items.filter(function (x) { return x !== code; }); draw(); touch(); input.focus();
                } }, D.countryName(code) + " (" + code + ")", " ", h("i", { class: "times icon", "aria-hidden": "true" })));
            });
            if (!c.items.length) { chips.appendChild(h("span", { class: "zx-muted" }, t("No country chosen yet"))); }
        }
        function addIt() {
            var code = parseCountry(input.value);
            if (!code) { if (input.value.trim()) { input.setAttribute("aria-invalid", "true"); } return; }
            input.removeAttribute("aria-invalid");
            if (c.items.indexOf(code) < 0) { c.items.push(code); }
            input.value = ""; draw(); touch();
        }
        input.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); addIt(); } });
        input.addEventListener("change", addIt);
        draw();
        box.appendChild(chips); box.appendChild(input);
        return box;
    }
    function compatLists(c) {
        var want = c.field === "ip.src" ? "ip" : (c.field === "ip.country" ? "country" : "string");
        return S.lists.filter(function (l) { return l.type === want; });
    }
    function listWidget(c) {
        var box = h("div", { class: "rb-listw" }), lists = compatLists(c), fd = D.fields[c.field] || {};
        if (c.useRef && !lists.some(function (l) { return l.name === c.ref; }) && c.ref) { lists = lists.concat([{ name: c.ref, items: [] }]); }
        if (lists.length) {
            box.appendChild(sel([["v", t("Values I enter")], ["l", t("A named list")]], c.useRef ? "l" : "v", function (v) {
                c.useRef = v === "l"; if (c.useRef && !c.ref && lists[0]) { c.ref = lists[0].name; }
                rerender("[data-nid=\"" + c.id + "\"] .rb-val select, [data-nid=\"" + c.id + "\"] .rb-val input"); touch();
            }, { "aria-label": t("Where the values come from"), class: "zx-select rb-lmode" }));
        }
        if (c.useRef) {
            box.appendChild(sel([["", t("Choose a list…")]].concat(lists.map(function (l) { return [l.name, "$" + l.name + " (" + tf("{0} entries", (l.items || []).length) + ")"]; })), c.ref, function (v) { c.ref = v; touch(); }, { "aria-label": t("Named list") }));
        } else if (c.field === "ip.country") {
            box.appendChild(countryPicker(c));
        } else if (fd.choices) {
            var grp = h("div", { class: "rb-checks", role: "group", "aria-label": t(fd.label) });
            fd.choices.forEach(function (ch) {
                grp.appendChild(check(ch, c.items.indexOf(ch) >= 0, function (on) {
                    c.items = c.items.filter(function (x) { return x !== ch; }); if (on) { c.items.push(ch); } touch();
                }));
            });
            box.appendChild(grp);
        } else {
            var ta = h("textarea", { class: "zx-textarea rb-lines", rows: "3", spellcheck: "false", "aria-label": t("One value per line"), placeholder: c.field === "ip.src" ? "203.0.113.0/24\n198.51.100.7" : t("One value per line") }, c.items.join("\n"));
            ta.addEventListener("input", function () { c.items = ta.value.split("\n").map(function (x) { return x.trim(); }).filter(Boolean); touch(); });
            box.appendChild(ta);
            box.appendChild(h("span", { class: "zx-help" }, tf("One value per line, at most {0}.", S.meta.limits.inline_list)));
        }
        return box;
    }
    var PLACE = { "http.path": "/admin", "http.raw_path": "/a%2fb", "http.host": "app.example.com", "http.query": "debug=1", "http.user_agent": "curl", "http.referer": "https://example.com/", "http.content_type": "application/json",
        "http.header": "value", "http.cookie": "value", "http.query_arg": "value", "ip.src": "203.0.113.7", "tls.sni": "app.example.com", "req.size": "1048576" };
    function valueWidget(c) {
        var kind = M.valueKind(c.field, c.op), fd = D.fields[c.field] || {}, w;
        if (kind === "none") { return h("span", { class: "zx-muted rb-noval" }, t("(no value needed)")); }
        if (kind === "bool") { return sel([["true", t("Yes")], ["false", t("No")]], c.value || "true", function (v) { c.value = v; touch(); }, { "aria-label": t("Value") }); }
        if (kind === "int") { return inp(c.value, function (v) { c.value = v; }, { type: "number", inputmode: "numeric", "aria-label": t("Value"), placeholder: "1048576" }); }
        if (kind === "list") { return listWidget(c); }
        if (kind === "string" && c.field === "ip.country") {
            return sel([["", t("Choose a country…")]].concat(D.countries.map(function (cc) { return [cc, D.countryName(cc) + " (" + cc + ")"]; })), c.value, function (v) { c.value = v; touch(); }, { "aria-label": t("Country") });
        }
        if (kind === "string" && fd.choices) {
            return sel([["", t("Choose…")]].concat(fd.choices.map(function (x) { return [x, x]; })), c.value, function (v) { c.value = v; touch(); }, { "aria-label": t("Value") });
        }
        w = inp(c.value, function (v) { c.value = v; }, { "aria-label": kind === "regex" ? t("Regular expression") : t("Value"), placeholder: kind === "regex" ? "^/api/v[0-9]+/" : (PLACE[c.field] || t("Value")), class: "zx-input" + (kind === "regex" ? " zx-mono" : ""), maxlength: "1000" });
        if (kind === "regex") { return h("div", { class: "rb-regex" }, w, h("span", { class: "zx-help" }, t("RE2 regular expression, not anchored: start with ^ to match from the beginning. Checked as you type."))); }
        return w;
    }

    // re-render the whole condition tree and put the focus back
    function rerender(focusSel) {
        renderConds();
        if (focusSel) { var el = rootEl().querySelector(focusSel); if (el) { el.focus(); } }
    }
    function parentOf(root, node) {
        var found = null;
        (function walk(g) { g.children.forEach(function (ch) { if (ch === node) { found = g; } if (ch.kind === "group") { walk(ch); } }); })(root);
        return found;
    }
    function moveNode(node, dir) {
        var p = parentOf(ed.root, node); if (!p) { return; }
        var i = p.children.indexOf(node), j = i + dir;
        if (j < 0 || j >= p.children.length) { return; }
        p.children.splice(i, 1); p.children.splice(j, 0, node);
        rerender("[data-nid=\"" + node.id + "\"] [data-act=\"" + (dir < 0 ? "up" : "down") + "\"]");
        ui.live.textContent = tf("Moved to position {0} of {1}", j + 1, p.children.length);
        touch();
    }
    function removeNode(node) {
        var p = parentOf(ed.root, node); if (!p) { return; }
        var i = p.children.indexOf(node); p.children.splice(i, 1);
        var next = p.children[Math.min(i, p.children.length - 1)];
        rerender(next ? "[data-nid=\"" + next.id + "\"] select, [data-nid=\"" + next.id + "\"] input, [data-nid=\"" + next.id + "\"] button" : "[data-nid=\"" + p.id + "\"] [data-act=\"addc\"]");
        ui.live.textContent = t("Removed");
        touch();
    }
    function wrapNode(node) {
        var p = parentOf(ed.root, node); if (!p) { return; }
        var g = M.newGroup("and", [node]), i = p.children.indexOf(node); p.children[i] = g;
        rerender("[data-nid=\"" + g.id + "\"] [data-act=\"addc\"]"); touch();
    }
    function ungroup(g) {
        var p = parentOf(ed.root, g); if (!p) { return; }
        var i = p.children.indexOf(g); [].splice.apply(p.children, [i, 1].concat(g.children));
        rerender("[data-nid=\"" + p.id + "\"] [data-act=\"addc\"]"); touch();
    }
    function depthOf(node) { var d = 0, p = parentOf(ed.root, node); while (p) { d++; p = parentOf(ed.root, p); } return d; }

    function ctlButtons(node, isRoot) {
        var p = parentOf(ed.root, node), i = p ? p.children.indexOf(node) : 0, n = p ? p.children.length : 1;
        var up = RB.ibtn("arrow up", t("Move up"), function () { moveNode(node, -1); }), dn = RB.ibtn("arrow down", t("Move down"), function () { moveNode(node, 1); });
        up.setAttribute("data-act", "up"); dn.setAttribute("data-act", "down");
        if (i === 0) { up.disabled = true; } if (i === n - 1) { dn.disabled = true; }
        var wrap = RB.ibtn("object group outline", t("Put this in its own group"), function () { wrapNode(node); }); wrap.setAttribute("data-act", "wrap");
        var rm = RB.ibtn("trash alternate outline", t("Remove"), function () { removeNode(node); }); rm.setAttribute("data-act", "rm");
        var list = [up, dn];
        if (node.kind === "cond") { list.push(wrap); } else { var un = RB.ibtn("object ungroup outline", t("Ungroup: move the conditions into the parent group"), function () { ungroup(node); }); un.setAttribute("data-act", "ungroup"); list.push(un); }
        list.push(rm);
        return h("div", { class: "zx-row-actions rb-ctl" }, list);
    }

    function fieldSelect(c) {
        var groups = [], seen = {};
        D.groups.forEach(function (g) {
            var opts = g.fields.filter(function (f) { return S.meta.fields.some(function (x) { return x.name === f; }); }).map(function (f) { seen[f] = 1; return h("option", { value: f, selected: f === c.field }, t(D.fields[f].label)); });
            if (opts.length) { groups.push(h("optgroup", { label: t(g.label) }, opts)); }
        });
        var other = S.meta.fields.filter(function (f) { return !seen[f.name]; }).map(function (f) { return h("option", { value: f.name, selected: f.name === c.field }, f.name); });
        if (other.length) { groups.push(h("optgroup", { label: t("Other") }, other)); }
        var s = h("select", { class: "zx-select rb-field", "aria-label": t("Field") }, groups);
        s.addEventListener("change", function () {
            var k0 = c.field; c.field = s.value;
            var f = M.newCond(c.field, S.meta);
            c.op = f.op; c.value = f.value; c.items = []; c.ref = ""; c.useRef = false; c.lower = false; if (!M.field(c.field).indexed) { c.key = ""; }
            rerender("[data-nid=\"" + c.id + "\"] .rb-field"); touch();
        });
        return s;
    }

    function condNode(c, parent) {
        var idx = parent.children.indexOf(c), fd = D.fields[c.field] || {}, f = M.field(c.field);
        var row = h("div", { class: "rb-row", role: "group", "aria-label": tf("Condition {0} of {1}", idx + 1, parent.children.length), "data-nid": c.id });
        var ops = M.opsFor(S.meta, c.field);
        var opSel = h("select", { class: "zx-select rb-op", "aria-label": t("Operator") }, ops.map(function (o) { return h("option", { value: o, selected: o === c.op }, t(D.ops[o].label)); }));
        opSel.addEventListener("change", function () {
            var k0 = M.valueKind(c.field, c.op); c.op = opSel.value; var k1 = M.valueKind(c.field, c.op);
            if (k0 !== k1) { c.value = (k1 === "bool") ? "true" : ""; c.items = []; c.ref = ""; c.useRef = false; }
            if (k1 === "regex" || k1 === "none") { c.lower = false; }
            if (k1 === "list" && k0 !== "list" && c.value) { c.items = [c.value]; c.value = ""; }
            rerender("[data-nid=\"" + c.id + "\"] .rb-op"); touch();
        });
        var notCb = check(t("NOT"), c.not, function (on) { c.not = on; touch(); }, { "aria-label": t("Negate this condition (NOT)"), title: t("Negate this condition (NOT)") });
        notCb.className = "zx-check rb-not";
        var top = h("div", { class: "rb-line" }, notCb, fieldSelect(c));
        if (f.indexed) {
            top.appendChild(inp(c.key, function (v) { c.key = v; }, { "aria-label": t(fd.keyLabel || "Name"), placeholder: fd.keyPlaceholder || "name", class: "zx-input rb-key", maxlength: "200" }));
        }
        top.appendChild(opSel);
        var val = h("div", { class: "rb-val" }, valueWidget(c));
        top.appendChild(val);
        var kind = M.valueKind(c.field, c.op);
        if (f.type === "string" && kind !== "none" && kind !== "regex" && c.field !== "ip.country") {
            top.appendChild(check(t("Ignore case"), c.lower, function (on) { c.lower = on; touch(); }, { title: t("Compare in lower case: the value is lower-cased too") }));
        }
        top.appendChild(ctlButtons(c));
        row.appendChild(top);
        row.appendChild(h("div", { class: "zx-error rb-rowerr", id: "rberr-" + c.id, hidden: true }));
        row.addEventListener("keydown", function (e) {
            if (e.altKey && (e.key === "ArrowUp" || e.key === "ArrowDown") && e.target.tagName !== "SELECT") { e.preventDefault(); moveNode(c, e.key === "ArrowUp" ? -1 : 1); }
        });
        return row;
    }

    function groupNode(g, parent) {
        var isRoot = !parent, depth = depthOf(g);
        var el = h("div", { class: "rb-group" + (isRoot ? " is-root" : ""), role: "group", "aria-label": isRoot ? t("Conditions") : t("Condition group"), "data-nid": g.id });
        var op = sel([["and", t("ALL of these are true (AND)")], ["or", t("ANY of these is true (OR)")]], g.op, function (v) { g.op = v; touch(); }, { "aria-label": t("How the conditions of this group combine"), class: "zx-select rb-gop" });
        var notCb = check(t("NOT"), g.not, function (on) { g.not = on; touch(); }, { "aria-label": t("Negate this whole group (NOT)"), title: t("Negate this whole group (NOT)") });
        notCb.className = "zx-check rb-not";
        var nodes = M.count(ed.root), lim = S.meta.limits;
        var addC = h("button", { type: "button", class: "zx-btn zx-btn--secondary zx-btn--sm", "data-act": "addc", disabled: nodes >= lim.nodes, onclick: function () {
            var c = M.newCond("http.path", S.meta); g.children.push(c); rerender("[data-nid=\"" + c.id + "\"] .rb-field"); touch();
        } }, h("i", { class: "plus icon", "aria-hidden": "true" }), t("Add condition"));
        var addG = h("button", { type: "button", class: "zx-btn zx-btn--secondary zx-btn--sm", "data-act": "addg", disabled: depth + 2 >= lim.depth || nodes >= lim.nodes - 1, onclick: function () {
            var c = M.newCond("http.path", S.meta), ng = M.newGroup("or", [c]); g.children.push(ng); rerender("[data-nid=\"" + c.id + "\"] .rb-field"); touch();
        } }, h("i", { class: "sitemap icon", "aria-hidden": "true" }), t("Add group"));
        var head = h("div", { class: "rb-ghead" }, op, notCb, h("span", { class: "zx-grow" }), addC, addG, isRoot ? null : ctlButtons(g, false));
        el.appendChild(head);
        var kids = h("div", { class: "rb-gkids" });
        g.children.forEach(function (ch) { kids.appendChild(ch.kind === "cond" ? condNode(ch, g) : groupNode(ch, g)); });
        if (!g.children.length) { kids.appendChild(h("p", { class: "zx-help" }, t("No conditions yet. Add one to say which requests this rule is about."))); }
        el.appendChild(kids);
        return el;
    }

    function renderConds() {
        var box = RB.clear(ui.condBox);
        if (ed.adv) {
            var ta = h("textarea", { class: "zx-textarea zx-mono rb-text", rows: "6", spellcheck: "false", "aria-label": t("Rule expression"), "aria-describedby": "rbTextHelp", maxlength: String(S.meta.limits.expression_bytes) }, ed.text);
            ta.addEventListener("input", function () { ed.text = ta.value; ed.check = { state: "empty" }; touch(); });
            ui.textArea = ta;
            box.appendChild(ta);
            box.appendChild(h("p", { class: "zx-help", id: "rbTextHelp" }, t("Example: http.path starts_with \"/admin\" and ip.country != \"US\". The text is checked as you type; switch back to the visual builder when it is valid.")));
            box.appendChild(ui.errLine);
        } else {
            box.appendChild(groupNode(ed.root, null));
        }
        ui.advSwitch.checked = ed.adv;
        if (ed.check) { paint(); }
    }

    // ------------------------------------------------------------------ action card
    function renderAction() {
        var a = ed.a, box = RB.clear(ui.actionBox), meta = (S.meta.actions || []).filter(function (x) { return x.type === a.type; })[0] || {};
        var groups = D.actionGroups.map(function (gl, gi) {
            return h("optgroup", { label: t(gl) }, Object.keys(D.actions).filter(function (k) { return D.actions[k].group === gi; }).map(function (k) { return h("option", { value: k, selected: k === a.type }, t(D.actions[k].label)); }));
        });
        var asel = h("select", { class: "zx-select", "aria-label": t("Action") }, groups);
        asel.addEventListener("change", function () {
            var keep = ed.a; ed.a = Object.assign(blankAction(), { type: asel.value });
            if (asel.value === "block") { ed.a.status = "403"; } if (asel.value === "redirect") { ed.a.status = "302"; } if (asel.value === "challenge") { ed.a.ttl = "30"; } if (asel.value === "rate_limit") { ed.a.rate = "10"; }
            renderAction(); touch();
            rootEl().querySelector(".rb-then select").focus();
        });
        box.appendChild(fld(t("Action"), asel, null));
        box.appendChild(h("p", { class: "zx-help" }, t((D.actions[a.type] || {}).help || "")));
        var p = h("div", { class: "rb-params zx-stack" });
        switch (a.type) {
            case "block":
                p.appendChild(fld(t("Status code"), inp(a.status, function (v) { a.status = v; }, { type: "number", inputmode: "numeric", min: "400", max: "599", class: "zx-input zx-input--short" }), t("400-599. 403 Forbidden shows the standard error page.")));
                p.appendChild(fld(t("Message (optional)"), (function () { var ta = h("textarea", { class: "zx-textarea", rows: "2", maxlength: "2000" }, a.body); ta.addEventListener("input", function () { a.body = ta.value; touch(); }); return ta; })(), t("Plain text shown instead of the standard page.")));
                p.appendChild(h("div", { class: "zx-toggle-row" }, check(t("Report to the automatic ban"), a.report_abuse, function (on) { a.report_abuse = on; touch(); }),
                    h("p", { class: "zx-help" }, t("When on, every block of this rule counts as a bad request towards the automatic ban of repeat offenders (Security Center, Auto-ban). Off by default: a block rule never bans anybody on its own. Log-only rules never report."))));
                break;
            case "redirect":
                p.appendChild(fld(t("Status code"), sel([[301, t("301 permanent")], [302, t("302 temporary")], [303, t("303 see other")], [307, t("307 temporary, keep method")], [308, t("308 permanent, keep method")]], a.status, function (v) { a.status = v; touch(); })));
                var urlI = inp(a.url, function (v) { a.url = v; }, { class: "zx-input zx-mono", placeholder: "https://example.com{uri}", maxlength: "2000" });
                p.appendChild(fld(t("Redirect to"), urlI, t("A full address (https://...) or a path starting with a single /.")));
                p.appendChild(h("div", { class: "zx-row" }, h("span", { class: "zx-muted" }, t("Insert:")), D.placeholders.map(function (ph) {
                    return h("button", { type: "button", class: "zx-btn zx-btn--ghost zx-btn--sm zx-mono", onclick: function () {
                        var s = urlI.selectionStart == null ? urlI.value.length : urlI.selectionStart; urlI.value = urlI.value.slice(0, s) + ph + urlI.value.slice(urlI.selectionEnd == null ? s : urlI.selectionEnd); a.url = urlI.value; urlI.focus(); touch();
                    } }, ph);
                })));
                break;
            case "challenge":
                p.appendChild(fld(t("Remember a solved challenge for (minutes)"), inp(a.ttl, function (v) { a.ttl = v; }, { type: "number", min: "1", max: "1440", class: "zx-input zx-input--short" }), t("1-1440. The CAPTCHA of the site is used. Without a CAPTCHA provider on the site, matching requests are blocked (fail closed).")));
                break;
            case "rate_limit":
                p.appendChild(fld(t("Requests per second, per client"), inp(a.rate, function (v) { a.rate = v; }, { type: "number", min: "1", class: "zx-input zx-input--short" })));
                p.appendChild(fld(t("Burst (optional)"), inp(a.burst, function (v) { a.burst = v; }, { type: "number", min: "1", class: "zx-input zx-input--short" }), t("How many requests may arrive at once. Empty = the same as the rate.")));
                p.appendChild(fld(t("Status when over the limit"), inp(a.rstatus, function (v) { a.rstatus = v; }, { type: "number", min: "400", max: "599", placeholder: "429", class: "zx-input zx-input--short" })));
                break;
            case "skip":
                p.appendChild(h("div", { class: "rb-checks", role: "group", "aria-label": t("Protections to skip") }, (S.meta.skip || Object.keys(D.skipLabels)).map(function (s) {
                    return check(t(D.skipLabels[s] || s), a.skip.indexOf(s) >= 0, function (on) { a.skip = a.skip.filter(function (x) { return x !== s; }); if (on) { a.skip.push(s); } touch(); });
                })));
                p.appendChild(h("div", { class: "zx-callout zx-callout--warn", role: "note" }, h("div", { class: "zx-callout__body" }, t("Skipping a protection removes it for every request this rule matches. Keep the conditions narrow."))));
                break;
            case "set_request_header": case "set_response_header":
                p.appendChild(fld(t("Header name"), inp(a.name, function (v) { a.name = v; }, { placeholder: "X-Content-Type-Options", maxlength: "100" })));
                p.appendChild(fld(t("Header value"), inp(a.value, function (v) { a.value = v; }, { placeholder: "nosniff", maxlength: "1000" })));
                break;
            case "remove_request_header": case "remove_response_header":
                p.appendChild(fld(t("Header name"), inp(a.name, function (v) { a.name = v; }, { placeholder: "Server", maxlength: "100" })));
                break;
            case "tag":
                p.appendChild(fld(t("Tag"), inp(a.tag, function (v) { a.tag = v; }, { placeholder: "suspicious", maxlength: "32" }), t("1-32 characters: a-z 0-9 _ . : -")));
                break;
            case "allow":
                p.appendChild(h("div", { class: "zx-callout zx-callout--info", role: "note" }, h("div", { class: "zx-callout__body" }, t("Later rules do not run for these requests. The WAF, rate limit, CAPTCHA and sign-in still apply; use “Skip protections” for those."))));
                break;
        }
        box.appendChild(p);
        box.appendChild(ui.actionErr);
    }

    // ------------------------------------------------------------------ editor skeleton
    function section(title, desc, body, cls) {
        return h("section", { class: "zx-card " + (cls || "") }, h("div", { class: "zx-card__head" }, h("h3", { class: "zx-card__title" }, title), desc ? h("p", { class: "zx-card__desc" }, desc) : null), h("div", { class: "zx-card__body zx-stack" }, body));
    }
    function build() {
        var root = RB.clear(rootEl());
        ui = {};
        ui.state = h("input", { type: "text", class: "zx-sr-only", tabindex: "-1", "aria-hidden": "true", "data-zx-label": t("Rule"), id: "rbState" });
        ui.stateBox = h("div", { id: "rbStateBox" }, ui.state);
        ui.sentence = h("div", { class: "rb-sentence", role: "status", "aria-live": "polite" });
        ui.status = h("span", { class: "rb-status", role: "status" });
        ui.live = h("div", { class: "zx-sr-only", role: "status", "aria-live": "polite" });
        ui.errBox = h("div"); ui.warn = h("div"); ui.lock = h("div"); ui.errLine = h("div");
        ui.actionErr = h("div", { class: "zx-error", role: "alert", hidden: true });
        ui.condBox = h("div", { class: "rb-conds" }); ui.actionBox = h("div", { class: "rb-then" });
        ui.advSwitch = h("input", { type: "checkbox", class: "zx-switch", role: "switch", id: "rbAdv", "aria-describedby": "rbAdvHelp" });
        ui.exprView = h("pre", { class: "rb-expr zx-mono", tabindex: "0", "aria-label": t("Rule expression (read only)") });

        var title = h("h2", { class: "zx-page-header__title", id: "rbEdTitle" }, ed.isNew ? t("New rule") : tf("Edit rule: {0}", ed.name));
        ui.title = title;
        var back = h("button", { type: "button", class: "zx-btn zx-btn--ghost", id: "rbBack", onclick: function () { closeEditor(false); } }, h("i", { class: "arrow left icon", "aria-hidden": "true" }), t("Back to rules"));
        root.appendChild(h("header", { class: "zx-page-header" }, h("div", { class: "zx-page-header__main" }, back, title,
            h("p", { class: "zx-page-header__sub" }, tf("Scope: {0}. Rules run top to bottom; this rule only acts when its conditions match.", RB.scopeLabel(ed.site))))));
        root.appendChild(ui.live);
        if (ed.isAI) {
            root.appendChild(h("div", { class: "zx-callout zx-callout--info", role: "note" }, h("span", { class: "zx-callout__icon", "aria-hidden": "true" }, h("i", { class: "lightbulb outline icon" })),
                h("div", { class: "zx-callout__body" }, t("This rule was proposed by the AI assistant. It is not trusted: read the conditions, test it, and only then enforce it."))));
        }
        // about
        var nameI = inp(ed.name, function (v) { ed.name = v; }, { maxlength: String(80), placeholder: t("For example: Block scanners on /admin"), "aria-required": "true" });
        var descI = inp(ed.description, function (v) { ed.description = v; }, { maxlength: "500", placeholder: t("Optional: why does this rule exist?") });
        ui.nameI = nameI;
        var scopeCtl = ed.isNew ? sel(RB.scopeOptions(), ed.site, function (v) { ed.site = v; touch(); }, { "aria-label": t("Scope") }) : null;
        root.appendChild(section(t("About this rule"), null, [fld(t("Name"), nameI), fld(t("Description"), descI), scopeCtl ? fld(t("Applies to"), scopeCtl, t("Global rules run first for every site, then the rules of the site.")) : null]));
        // summary
        root.appendChild(h("div", { class: "rb-sumcard" }, h("div", { class: "zx-muted rb-sumlabel" }, t("In plain English")), ui.sentence));
        // when
        var copy = h("button", { type: "button", class: "zx-btn zx-btn--secondary zx-btn--sm", onclick: function () {
            var txt = ui.exprView.textContent;
            if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(txt).then(function () { RB.toast(t("Copied")); }, function () { selectExpr(); }); } else { selectExpr(); }
        } }, h("i", { class: "copy outline icon", "aria-hidden": "true" }), t("Copy"));
        function selectExpr() { var r = document.createRange(); r.selectNodeContents(ui.exprView); var s = window.getSelection(); s.removeAllRanges(); s.addRange(r); RB.toast(t("Selected: press Ctrl+C to copy")); }
        var testBtn = h("button", { type: "button", class: "zx-btn zx-btn--secondary zx-btn--sm", id: "rbJumpTest", onclick: function () { ui.testCard.scrollIntoView({ block: "center" }); ui.tester.inputs.url.focus(); } }, h("i", { class: "flask icon", "aria-hidden": "true" }), t("Test this rule against…"));
        ui.advSwitch.addEventListener("change", function () { setAdvanced(ui.advSwitch.checked); });
        var advRow = h("div", { class: "zx-toggle-row" }, h("label", { class: "rb-swlabel", for: "rbAdv" }, ui.advSwitch, h("span", {}, t("Edit as text (advanced)"))),
            h("p", { class: "zx-help", id: "rbAdvHelp" }, t("Type the expression yourself. It is checked by the same parser as the visual builder; you can switch back when it is valid.")));
        root.appendChild(section(t("When"), t("Which requests does this rule apply to?"), [ui.condBox, ui.errBox, advRow,
            h("div", { class: "rb-exprbox" }, h("div", { class: "zx-row" }, h("b", {}, t("Expression")), h("span", { class: "zx-grow" }), ui.status, copy, testBtn), ui.exprView)], "rb-when"));
        // then
        root.appendChild(section(t("Then"), t("What happens to matching requests?"), ui.actionBox, "rb-then"));
        // mode
        var seg = h("div", { class: "zx-segmented", "aria-label": t("Mode") },
            h("button", { type: "button", class: "zx-segmented__item", "data-value": "log", "aria-checked": ed.dry_run ? "true" : "false" }, t("Log-only")),
            h("button", { type: "button", class: "zx-segmented__item", "data-value": "enforce", "aria-checked": ed.dry_run ? "false" : "true" }, t("Enforce")));
        var enabled = h("input", { type: "checkbox", class: "zx-switch", role: "switch", id: "rbEnabled", checked: ed.enabled });
        enabled.addEventListener("change", function () { ed.enabled = enabled.checked; touch(); });
        var modeHelp = h("p", { class: "zx-help", id: "rbModeHelp" });
        function modeText() { modeHelp.textContent = ed.dry_run ? t("Log-only: the rule is checked for every request and its matches are counted and listed, but nothing is blocked, redirected or changed. This is the safe way to find out what a rule would do.") : t("Enforce: matching requests are handled by the action above. You are asked to confirm, with a test, when you save."); }
        modeText();
        root.appendChild(section(t("Mode"), null, [seg, modeHelp, h("div", { class: "zx-toggle-row" }, h("label", { class: "rb-swlabel", for: "rbEnabled" }, enabled, h("span", {}, t("The rule is active (enabled)"))),
            h("p", { class: "zx-help" }, t("A disabled rule is kept but never evaluated.")))]));
        ZxUI.segmented(seg, { onChange: function (v) { var dry = v === "log"; if (dry !== ed.dry_run) { ed.dry_run = dry; modeText(); paintLock(); touch(); } } });
        root.appendChild(ui.warn); root.appendChild(ui.lock);
        // tester
        ui.tester = RB.tester({ site: function () { return ed.site; }, candidate: function () { if (ed.adv && !(ed.check && ed.check.state === "ok")) { return null; } return candidate(); }, sample: RB.sampleFor(ed.adv ? null : M.toTree(ed.root)) });
        ui.testCard = section(t("Test this rule"), t("Describe a request and see whether this rule would match it. Nothing is performed."), ui.tester.el, "rb-testcard");
        root.appendChild(ui.testCard);
        root.appendChild(ui.stateBox);
        root.addEventListener("keydown", function (e) { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") { e.preventDefault(); if (bar) { bar.save(); } } });
    }

    function setAdvanced(on) {
        if (on === ed.adv) { return; }
        if (on) {
            runCheck().then(function (c) {
                ed.text = (c && c.res && c.res.text) || ed.canon || "";
                ed.adv = true; ed.check = c && c.state === "ok" ? c : { state: "empty" };
                renderConds(); touch();
                if (ui.textArea) { ui.textArea.focus(); }
            });
        } else {
            runCheck().then(function (c) {
                if (!c || c.state !== "ok" || !c.res || !c.res.tree) { ui.advSwitch.checked = true; RB.toast(t("The text has problems. Fix them first, then switch back to the visual builder."), { type: "error" }); return; }
                ed.root = M.fromTree(c.res.tree); ed.adv = false; ed.text = "";
                renderConds(); touch();
                var f = rootEl().querySelector(".rb-field"); if (f) { f.focus(); }
            });
        }
    }

    // ------------------------------------------------------------------ open / close / save
    function start(o, parsed) {
        if (ed) { return; }
        var r = o.rule, d = o.draft || {}, act = r ? r.action : d.action;
        ed = { site: o.site || "", id: r ? r.id : null, isNew: !r, name: r ? r.name : (d.name || ""), description: r ? (r.description || "") : (d.description || ""),
            enabled: r ? r.enabled : true, dry_run: r ? r.dry_run : true, origDry: r ? r.dry_run : true, a: loadAction(act || { type: "block", status: 403 }),
            updated: r ? r.updated : null, probeP: null, adv: false, text: "", canon: r ? r.expression : (d.expression || ""), check: null, seq: 0, lock: [], isAI: String((r ? r.description : d.description) || "").indexOf(RB.AI_MARK) === 0 };
        if (r) { ed.root = M.fromTree(r.tree); }
        else if (d.tree) { ed.root = M.fromTree(d.tree); }
        else if (parsed && parsed.ok) { ed.root = M.fromTree(parsed.tree); }
        else if (d.expression) { ed.root = M.newGroup("and", []); ed.adv = true; ed.text = d.expression; }
        else { ed.root = M.newGroup("and", [M.newCond("http.path", S.meta)]); }
        RB.q("#rbMain").hidden = true;
        var rootNode = RB.q("#rbEditor"); rootNode.hidden = false;
        build(); renderConds(); renderAction();
        ui.advSwitch.checked = ed.adv;
        ed.origSig = ruleSig();
        ui.state.value = ed.isNew ? "" : JSON.stringify(snapshot());
        bar = ZxUI.saveBar({ form: ui.stateBox, mount: rootNode, id: "rules-editor", saveLabel: ed.isNew ? t("Create rule") : t("Save rule"), discardLabel: t("Discard changes"),
            successText: t("Saved"), onSave: save, onDiscard: function () {
                var again = ui.state.value === "" ? null : { site: ed.site, id: ed.id };
                closeEditor(true);
                if (again) { RB.refresh().then(function () { var r = S.rules.filter(function (x) { return x.id === again.id; })[0]; if (r && S.site === again.site) { RB.openEditor({ site: again.site, rule: r }); } }); }
            } });
        if (ed.isNew) { touch(); } else { runCheck(); }
        (ed.name ? rootNode.querySelector(".rb-field") : ui.nameI).focus();
        rootNode.scrollIntoView({ block: "start" });
        if (o.fromTemplate) { RB.toast(t("Template loaded in log-only mode. Fill in the empty values, then create the rule.")); }
    }

    RB.openEditor = function (o) {
        RB.init().then(RB.loadLists).then(function () {
            if (!o.rule && !o.draft && !o.fromTemplate) { return start(o); }
            var d = o.draft;
            if (d && d.expression && !d.tree) {
                return RB.post("./api/ruleset/validate", { expression: d.expression }).then(function (res) { start(o, res); }, function () { start(o, null); });
            }
            start(o);
        }).catch(function (e) { RB.toast(RB.errText(e), { type: "error" }); });
    };

    function closeEditor(force) {
        if (!ed) { return; }
        function done() {
            clearTimeout(timer);
            if (bar) { bar.destroy(); bar = null; }
            ed = null; ui = null;
            RB.clear(RB.q("#rbEditor")).hidden = true;
            RB.q("#rbMain").hidden = false;
            RB.refresh();
            var b = RB.q("#rbNew"); if (b) { b.focus(); }
        }
        if (!force && bar && bar.isDirty()) {
            ZxUI.confirm({ title: t("Discard your changes?"), message: t("The rule has changes that are not saved."), confirmLabel: t("Discard changes"), danger: true }).then(function (ok) { if (ok) { done(); } });
        } else { done(); }
    }

    // what the engine acts on: the condition and the action (not the name or the notes)
    function ruleSig() {
        try { return JSON.stringify({ c: ed.adv ? ed.text : M.toTree(ed.root), a: buildAction() }); } catch (e) { return ""; }
    }

    function save() {
        return runCheck().then(function (c) {
            // the real-tester probes run after the check: wait for them, so the warning below never depends on timing
            if (c && c.state === "ok" && ed.probeP) { return ed.probeP.then(function () { return c; }, function () { return c; }); }
            return c;
        }).then(function (c) {
            if (!c || c.state !== "ok") { return { error: t("The rule is not valid yet. Fix the marked problems and try again.") }; }
            if (!ed.name.trim()) { ui.nameI.focus(); return { error: t("Give the rule a name.") }; }
            var action = buildAction(), transition = !ed.dry_run && (ed.isNew || ed.origDry), issues = (ed.lock || []).slice();
            // an enforcing rule whose condition or action changed is confirmed too, whatever the lock-out checks found
            var changed = !ed.isNew && ruleSig() !== ed.origSig;
            var needConfirm = !ed.dry_run && (transition || issues.length > 0 || changed);
            var step = needConfirm ? RB.confirmEnforce({ site: ed.site, name: ed.name.trim(), tree: ed.adv ? (c.res && c.res.tree) : M.toTree(ed.root), expression: null, action: action, sentence: ui.sentence.textContent, issues: issues }) : Promise.resolve(true);
            return step.then(function (ok) {
                if (!ok) { return { error: t("Not saved: you did not confirm enforcing the rule.") }; }
                var rule = { name: ed.name.trim(), description: ed.description.trim(), enabled: ed.enabled, dry_run: ed.dry_run, action: action };
                if (ed.adv) { rule.expression = ed.text; } else { rule.tree = M.toTree(ed.root); }
                if (!ed.isNew && ed.updated) { rule.if_updated = ed.updated; }
                var req = ed.isNew ? RB.post("./api/ruleset/rule/create", { site: ed.site, rule: rule }) : RB.post("./api/ruleset/rule/update", { site: ed.site, id: ed.id, rule: rule });
                return req.then(function (ri) {
                    ed.id = ri.id; ed.isNew = false; ed.origDry = ri.dry_run; ed.name = ri.name; ed.updated = ri.updated; ed.origSig = ruleSig();
                    ui.title.textContent = tf("Edit rule: {0}", ri.name);
                    if (S.site === ed.site) { RB.loadRules(S.site); }
                    RB.toast(rule.dry_run ? tf("Rule “{0}” saved in log-only mode", ri.name) : tf("Rule “{0}” saved and enforcing", ri.name));
                    return true;
                }, function (e) {
                    if (e && e.status === 409) { return { error: t("This rule was changed in another session after you opened it. Nothing was saved. Copy what you need, discard your changes and open the rule again.") }; }
                    return { error: RB.errText(e) + (e.detail ? " (" + (e.detail.message || JSON.stringify(e.detail)) + ")" : "") };
                });
            });
        });
    }
})();
