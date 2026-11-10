/*
    ZxUI - small helper library of the admin UI component kit (window.ZxUI).

    Companion of ui/zxui.css.  Documentation and live examples: docs/ux/components.md, /ui/kit.html (-dev only).
    No dependencies except jQuery (already used everywhere in the admin UI).  Everything here is optional progressive
    enhancement: the markup/CSS of a component works without it unless noted.

      ZxUI.toast(message, {type, undo, undoLabel, action:{label,run}, duration})   notification, optional "Undo" and one more action
      ZxUI.confirm({title, message, confirmLabel, danger, typed})  -> Promise<boolean>
      ZxUI.dirty(form, opts)                                   dirty tracker (ignores programmatic changes)
      ZxUI.saveBar({form, onSave, onDiscard})                  sticky "unsaved changes" bar
      ZxUI.unsaved                                             registry of everything that holds unsaved work
      ZxUI.setLoading(button, on)                              button loading state
      ZxUI.skeleton(container, opts)                           loading placeholder, returns a function that removes it
      ZxUI.field(el).setError(text) / .clearError()            form row validation text
      ZxUI.tabs(el, opts), ZxUI.segmented(el, opts)            keyboard accessible tabs / segmented control
      ZxUI.esc(text)                                           HTML-escape (use for anything that came from a user or API)

    Strings: written as plain English, translated at runtime by script/i18n.js like the rest of the UI.
*/
(function () {
    "use strict";
    if (window.ZxUI) { return; }

    var ZxUI = window.ZxUI = { version: 1 };

    /* ------------------------------------------------------------------ helpers */
    var ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" };
    ZxUI.esc = function (s) {
        return String(s === undefined || s === null ? "" : s).replace(/[&<>"']/g, function (c) { return ESC[c]; });
    };
    function N_(s) { return s; } // marks a string for tools/i18n/extract.py; translation happens in tr()/trf() or in the DOM
    function tr(s) { return typeof window.t === "function" ? window.t(s) : s; }
    function trf(s) {
        var args = Array.prototype.slice.call(arguments, 1);
        return typeof window.tf === "function" ? window.tf.apply(window, [s].concat(args)) :
            s.replace(/\{(\d+)\}/g, function (m, n) { return args[+n] !== undefined ? args[+n] : m; });
    }
    function $el(x) { return window.jQuery ? window.jQuery(x).first() : null; }
    var uid = 0;
    function nextId(prefix) { uid++; return (prefix || "zx") + "-" + uid; }
    function raf(fn) { (window.requestAnimationFrame || window.setTimeout)(fn, 16); }

    /* ------------------------------------------------------------------ buttons */
    ZxUI.setLoading = function (btn, on) {
        var b = $el(btn);
        if (!b || !b.length) { return; }
        b.toggleClass("is-loading", !!on).attr("aria-busy", on ? "true" : null);
        if (b.is("button")) { b.prop("disabled", !!on); }
    };

    /* ------------------------------------------------------------------ toast */
    var toastBox = null;
    function ensureToastBox() {
        if (toastBox && toastBox.isConnected) { return toastBox; }
        toastBox = document.createElement("div");
        toastBox.className = "zx-toasts";
        toastBox.setAttribute("role", "region");
        toastBox.setAttribute("aria-label", "Notifications");
        toastBox.setAttribute("aria-live", "polite");
        document.body.appendChild(toastBox);
        return toastBox;
    }

    /*
        ZxUI.toast("Rule deleted", {type: "success", undo: function () { ... }})
        type: "info" (default) | "success" | "error" | "warn".  `undo` shows an Undo button that runs the function once.
        Returns {dismiss()}.  The message is inserted as text, never as HTML.
    */
    ZxUI.toast = function (message, opts) {
        opts = opts || {};
        var type = opts.type || "info";
        var box = ensureToastBox();
        var node = document.createElement("div");
        node.className = "zx-toast zx-toast--" + type;
        node.setAttribute("role", type === "error" ? "alert" : "status");
        var msg = document.createElement("span");
        msg.className = "zx-toast__msg";
        msg.textContent = String(message === undefined ? "" : message);
        node.appendChild(msg);
        var timer = null, done = false;
        function dismiss() {
            if (done) { return; }
            done = true;
            clearTimeout(timer);
            if (node.parentNode) { node.parentNode.removeChild(node); }
        }
        if (typeof opts.undo === "function") {
            var u = document.createElement("button");
            u.type = "button";
            u.className = "zx-btn zx-btn--ghost zx-btn--sm zx-toast__undo";
            u.innerHTML = "<span>Undo</span>";
            if (opts.undoLabel) { u.firstChild.textContent = opts.undoLabel; }
            u.addEventListener("click", function () {
                var fn = opts.undo;
                dismiss();
                try { fn(); } catch (e) { console.error("toast undo failed", e); }
            });
            node.appendChild(u);
        }
        if (opts.action && typeof opts.action.run === "function") {     // a second, non-destructive action, e.g. "View history"
            var a = document.createElement("button");
            a.type = "button";
            a.className = "zx-btn zx-btn--ghost zx-btn--sm zx-toast__undo";
            a.textContent = String(opts.action.label || "");
            a.addEventListener("click", function () {
                var fn = opts.action.run;
                dismiss();
                try { fn(); } catch (e) { console.error("toast action failed", e); }
            });
            node.appendChild(a);
        }
        var c = document.createElement("button");
        c.type = "button";
        c.className = "zx-btn zx-btn--ghost zx-btn--sm zx-btn--icon zx-toast__close";
        c.setAttribute("aria-label", "Dismiss");
        c.innerHTML = "<i class=\"times icon\" aria-hidden=\"true\"></i>";
        c.addEventListener("click", dismiss);
        node.appendChild(c);
        box.appendChild(node);
        while (box.children.length > 5) { box.removeChild(box.firstChild); }
        var duration = opts.duration !== undefined ? opts.duration : (opts.undo || opts.action ? 10000 : (type === "error" ? 8000 : 4000));
        function arm() { if (duration > 0) { clearTimeout(timer); timer = setTimeout(dismiss, duration); } }
        node.addEventListener("mouseenter", function () { clearTimeout(timer); });
        node.addEventListener("mouseleave", arm);
        node.addEventListener("focusin", function () { clearTimeout(timer); });
        node.addEventListener("focusout", arm);
        arm();
        return { dismiss: dismiss };
    };

    /* ------------------------------------------------------------------ confirm dialog */
    var FOCUSABLE = "a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";

    /*
        ZxUI.confirm({title, message, confirmLabel, cancelLabel, danger: true, typed: "example.com"}) -> Promise<boolean>
        danger: red confirm button and the focus starts on Cancel.
        typed: the confirm button stays disabled until the user typed exactly this text (use for irreversible actions).
    */
    ZxUI.confirm = function (o) {
        o = o || {};
        return new Promise(function (resolve) {
            var previous = document.activeElement;
            var id = nextId("zxdlg");
            var back = document.createElement("div");
            back.className = "zx-dialog-backdrop";
            var typedHtml = "";
            if (o.typed) {
                typedHtml = "<div class=\"zx-dialog__typed\"><label class=\"zx-field__label\" for=\"" + id + "-in\">" +
                    "<span>Type</span> <b class=\"zx-mono\" data-i18n-skip></b> <span>to confirm</span></label>" +
                    "<input id=\"" + id + "-in\" class=\"zx-input\" type=\"text\" autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\"></div>";
            }
            back.innerHTML =
                "<div class=\"zx-dialog" + (o.danger ? " zx-dialog--danger" : "") + "\" role=\"" + (o.danger ? "alertdialog" : "dialog") + "\" aria-modal=\"true\" aria-labelledby=\"" + id + "-t\" aria-describedby=\"" + id + "-d\">" +
                "<h2 class=\"zx-dialog__title\" id=\"" + id + "-t\"></h2><p class=\"zx-dialog__text\" id=\"" + id + "-d\"></p>" + typedHtml +
                "<div class=\"zx-dialog__foot\"><button type=\"button\" class=\"zx-btn zx-btn--secondary\" data-zx-cancel></button>" +
                "<button type=\"button\" class=\"zx-btn " + (o.danger ? "zx-btn--danger" : "zx-btn--primary") + "\" data-zx-ok></button></div></div>";
            var dlg = back.firstChild;
            back.querySelector("#" + id + "-t").textContent = o.title || tr(N_("Are you sure?"));
            back.querySelector("#" + id + "-d").textContent = o.message || "";
            var cancelBtn = back.querySelector("[data-zx-cancel]"), okBtn = back.querySelector("[data-zx-ok]");
            cancelBtn.textContent = o.cancelLabel || tr(N_("Cancel"));
            okBtn.textContent = o.confirmLabel || (o.danger ? tr(N_("Delete")) : tr(N_("Confirm")));
            var input = back.querySelector("input");
            if (input) {
                back.querySelector("b").textContent = o.typed;
                okBtn.disabled = true;
                input.addEventListener("input", function () { okBtn.disabled = input.value !== String(o.typed); });
            }
            var closed = false;
            function close(result) {
                if (closed) { return; }
                closed = true;
                document.removeEventListener("keydown", onKey, true);
                if (back.parentNode) { back.parentNode.removeChild(back); }
                if (previous && previous.focus) { try { previous.focus(); } catch (e) { /* element gone */ } }
                resolve(result);
            }
            function onKey(e) {
                if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(false); return; }
                if (e.key === "Enter" && input && e.target === input && !okBtn.disabled) { e.preventDefault(); close(true); return; }
                if (e.key !== "Tab") { return; }
                var f = Array.prototype.filter.call(dlg.querySelectorAll(FOCUSABLE), function (n) { return n.offsetParent !== null; });
                if (!f.length) { return; }
                var first = f[0], last = f[f.length - 1];
                if (!dlg.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
                else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
                else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
            }
            cancelBtn.addEventListener("click", function () { close(false); });
            okBtn.addEventListener("click", function () { if (!okBtn.disabled) { close(true); } });
            back.addEventListener("mousedown", function (e) { if (e.target === back) { close(false); } });
            document.addEventListener("keydown", onKey, true);
            document.body.appendChild(back);
            (input || (o.danger ? cancelBtn : okBtn)).focus();
        });
    };

    /* ------------------------------------------------------------------ unsaved-work registry */
    var guards = [];
    /*
        ZxUI.unsaved.register({id, isDirty: fn, owner: element (optional), discard: fn (optional)}) -> unregister()
        Everything that can hold unsaved work registers here (save bars do it automatically; the proxy rule editor
        guard of uxkit.js does too), so a single beforeunload prompt and the "leave this page?" prompt cover all of it.
    */
    ZxUI.unsaved = {
        register: function (g) {
            guards.push(g);
            return function () { var i = guards.indexOf(g); if (i >= 0) { guards.splice(i, 1); } };
        },
        list: function () { return guards.filter(function (g) { try { return g.isDirty(); } catch (e) { return false; } }); },
        any: function () { return ZxUI.unsaved.list().length > 0; }
    };
    ZxUI.hasUnsaved = function () { return ZxUI.unsaved.any(); };

    window.addEventListener("beforeunload", function (e) {
        if (ZxUI.unsaved.any()) { e.preventDefault(); e.returnValue = ""; }
    });

    // Leaving a page (menu, palette, openTabById) that has an unsaved save bar asks first.
    function installNavGuard() {
        var orig = window.openTabById;
        if (typeof orig !== "function" || orig.__zxGuard) { return; }
        var wrapped = function (tabID, obj) {
            var args = arguments, self = this;
            var open = $(".functiontab:visible").first();
            var blocking = open.length && open.attr("id") !== tabID ? ZxUI.unsaved.list().filter(function (g) {
                return g.owner && open[0].contains(g.owner);
            }) : [];
            if (!blocking.length) { return orig.apply(self, args); }
            ZxUI.confirm({
                title: N_("Leave without saving?"),
                message: trf(N_("This page has unsaved changes ({0}). They will be lost if you leave."), blocking.map(function (g) { return g.summary ? g.summary() : g.id; }).join(", ")),
                confirmLabel: N_("Discard changes and leave"), cancelLabel: N_("Stay on this page"), danger: true
            }).then(function (ok) {
                if (!ok) { return; }
                blocking.forEach(function (g) { if (g.discard) { g.discard(); } });
                orig.apply(self, args);
            });
        };
        wrapped.__zxGuard = true;
        window.openTabById = wrapped;
    }
    if (window.jQuery) { window.jQuery(function () { setTimeout(installNavGuard, 0); }); }

    /* ------------------------------------------------------------------ dirty tracker */
    var SKIP_TYPES = { button: 1, submit: 1, reset: 1, image: 1, file: 1, hidden: 0 };

    function labelOf(el) {
        var $e = window.jQuery(el);
        var l = $e.attr("data-zx-label");
        if (l) { return l; }
        var id = $e.attr("id");
        if (id) {
            var lab = document.querySelector("label[for='" + id.replace(/'/g, "\\'") + "']");
            if (lab) { l = lab.firstChild && lab.firstChild.nodeType === 3 ? lab.firstChild.nodeValue : lab.textContent; }
        }
        if (!l) { var wrap = $e.closest("label, .ui.checkbox, .ui.dropdown, .zx-field"); if (wrap.length) { l = wrap.find("label, .zx-field__label").first().clone().children().remove().end().text(); } }
        l = (l || $e.attr("aria-label") || $e.attr("placeholder") || $e.attr("name") || id || "").replace(/\s+/g, " ").trim();
        return l;
    }

    /*
        ZxUI.dirty(form, {ignore: ".selector", onChange: fn(tracker)}) -> tracker
        A control is dirty when its value differs from the baseline snapshot.  Only changes made by the user count:
        real (trusted) events, or untrusted events fired by page code within 600 ms of a pointer/keyboard action in the
        form (Fomantic dropdowns and checkboxes fire their change events from script).  Programmatic changes while a
        page loads its data never mark the form dirty; call tracker.reset() after loading to take the new baseline.
        tracker: isDirty(), changes() -> [{key,label,from,to}], reset(), commit(keys), restore(), pause(ms), destroy()
    */
    ZxUI.dirty = function (form, opts) {
        opts = opts || {};
        var $ = window.jQuery;
        var root = $(form)[0];
        if (!root) { throw new Error("ZxUI.dirty: form not found"); }
        var baseline = {}, current = {}, lastUser = 0, ignoreUntil = 0, listeners = [];

        function controls() {
            return $(root).find("input, select, textarea").filter(function () {
                var type = (this.type || "").toLowerCase();
                if (SKIP_TYPES[type]) { return false; }
                if ($(this).closest("[data-zx-ignore]").length) { return false; }
                if (opts.ignore && ($(this).is(opts.ignore) || $(this).closest(opts.ignore).length)) { return false; }
                return true;
            }).toArray();
        }
        function keyOf(el, idx) {
            if (el.name) { return el.name; }
            if (el.id) { return el.id; }
            var anc = $(el).closest("[id]");
            var sibs = anc.length ? anc.find("input, select, textarea").toArray() : [];
            return (anc.attr("id") || "ctl") + ":" + (sibs.indexOf(el) >= 0 ? sibs.indexOf(el) : idx);
        }
        function snapshot() {
            var out = {};
            controls().forEach(function (el, i) {
                var type = (el.type || "").toLowerCase();
                if (type === "radio") {
                    var k = el.name || keyOf(el, i);
                    if (!(k in out)) { out[k] = { v: "", label: labelOf(el), el: el }; }
                    if (el.checked) { out[k].v = el.value; }
                    return;
                }
                var key = keyOf(el, i);
                out[key] = { v: type === "checkbox" ? !!el.checked : el.value, label: labelOf(el), el: el };
            });
            return out;
        }
        function reset() { baseline = snapshot(); fire(); }
        function diff() {
            current = snapshot();
            var out = [];
            Object.keys(current).forEach(function (k) {
                if (!(k in baseline)) { return; }
                if (current[k].v !== baseline[k].v) { out.push({ key: k, label: current[k].label, from: baseline[k].v, to: current[k].v, el: current[k].el }); }
            });
            return out;
        }
        function fire() { listeners.forEach(function (fn) { try { fn(tracker); } catch (e) { console.error(e); } }); }
        function userAction() { lastUser = Date.now(); }
        function onEvent(e) {
            var now = Date.now();
            var trusted = e.isTrusted === true;
            if (!trusted && (now < ignoreUntil || now - lastUser > 600)) { return; }
            if ($(e.target).closest("[data-zx-ignore]").length) { return; }
            fire();
        }
        ["pointerdown", "keydown", "touchstart", "click"].forEach(function (n) { root.addEventListener(n, userAction, true); });
        root.addEventListener("input", onEvent, true);
        root.addEventListener("change", onEvent, true);

        var tracker = {
            root: root,
            isDirty: function () { return diff().length > 0; },
            changes: diff,
            reset: reset,
            // take the current value of these controls as saved (a save that only applied some of the fields)
            commit: function (keys) {
                var cur = snapshot();
                (keys || []).forEach(function (k) { if (cur[k]) { baseline[k] = cur[k]; } });
                fire();
            },
            pause: function (ms) { ignoreUntil = Date.now() + (ms === undefined ? 500 : ms); },
            restore: function () {
                tracker.pause(500);
                controls().forEach(function (el, i) {
                    var key = (el.type || "").toLowerCase() === "radio" ? (el.name || keyOf(el, i)) : keyOf(el, i);
                    if (!(key in baseline)) { return; }
                    var v = baseline[key].v, type = (el.type || "").toLowerCase();
                    if (type === "checkbox") {
                        el.checked = !!v;
                        $(el).closest(".ui.checkbox").toggleClass("checked", !!v);
                    } else if (type === "radio") {
                        el.checked = (el.value === v);
                    } else {
                        el.value = v;
                        var dd = $(el).closest(".ui.dropdown");
                        if (dd.length && dd.dropdown) { try { dd.dropdown("set selected", v); } catch (e) { /* not a Fomantic dropdown */ } }
                    }
                    el.dispatchEvent(new Event("input", { bubbles: true }));
                    el.dispatchEvent(new Event("change", { bubbles: true }));
                });
                fire();
            },
            onChange: function (fn) { listeners.push(fn); },
            destroy: function () {
                ["pointerdown", "keydown", "touchstart", "click"].forEach(function (n) { root.removeEventListener(n, userAction, true); });
                root.removeEventListener("input", onEvent, true);
                root.removeEventListener("change", onEvent, true);
                listeners = [];
            }
        };
        if (typeof opts.onChange === "function") { listeners.push(opts.onChange); }
        baseline = snapshot();
        return tracker;
    };

    /* ------------------------------------------------------------------ save bar */
    var barCount = 0;
    function updateBodyFlag() { document.body.classList.toggle("zx-has-savebar", barCount > 0); }

    /*
        ZxUI.saveBar({
            form:      element / selector / jQuery   the container whose inputs are tracked
            onSave:    function (ctx) -> Promise | jqXHR | value   ctx = {changes, tracker, bar}
                       Failure = rejected promise, a thrown error, a result of `false`, or a result object with `.error`.
            onDiscard: optional function, runs after the fields were put back to the saved values
            mount:     optional element; the bar is appended here (default: the page container of the form, so it
                       sticks to the bottom of the viewport while the page is scrolled)
            ignore:    optional selector of controls that are not part of the form state
            saveLabel / discardLabel / successText / historyObject (substring of the History "Object" filter, e.g. "WAF")
        })
        -> bar: {reset(), isDirty(), save(), discard(), tracker, destroy()}
        Call bar.reset() after the page loaded its values from the API, and after changing values from code.
    */
    ZxUI.saveBar = function (o) {
        var $ = window.jQuery;
        o = o || {};
        var tracker = ZxUI.dirty(o.form, { ignore: o.ignore });
        var formEl = tracker.root;
        var mount = o.mount ? $(o.mount)[0] : ($(formEl).closest(".functiontab")[0] || formEl.parentNode);
        var slot = document.createElement("div");
        slot.className = "zx-savebar-slot";
        slot.innerHTML =
            "<div class=\"zx-savebar\" role=\"region\" aria-label=\"Unsaved changes\" hidden>" +
            "<div class=\"zx-savebar__msg\" role=\"status\" aria-live=\"polite\"><span class=\"zx-savebar__count\"></span><span class=\"zx-savebar__what\"></span></div>" +
            "<div class=\"zx-savebar__actions\">" +
            "<button type=\"button\" class=\"zx-btn zx-btn--ghost\" data-zx-discard></button>" +
            "<button type=\"button\" class=\"zx-btn zx-btn--primary\" data-zx-save></button></div></div>";
        mount.appendChild(slot);
        var barEl = slot.firstChild;
        var countEl = barEl.querySelector(".zx-savebar__count"), whatEl = barEl.querySelector(".zx-savebar__what");
        var saveBtn = barEl.querySelector("[data-zx-save]"), discardBtn = barEl.querySelector("[data-zx-discard]");
        saveBtn.textContent = o.saveLabel || tr(N_("Save changes"));
        discardBtn.textContent = o.discardLabel || tr(N_("Discard"));
        var state = "idle", hideTimer = null, shown = false;

        function summary() {
            var ch = tracker.changes();
            return ch.map(function (c) { return c.label; }).filter(Boolean).slice(0, 3).join(", ");
        }
        function render() {
            var ch = tracker.changes();
            var n = ch.length;
            clearTimeout(hideTimer);
            barEl.classList.toggle("is-saving", state === "saving");
            barEl.classList.toggle("is-error", state === "error");
            barEl.classList.toggle("is-success", state === "success");
            saveBtn.disabled = discardBtn.disabled = (state === "saving");
            ZxUI.setLoading(saveBtn, state === "saving");
            saveBtn.disabled = state === "saving";
            var visible = n > 0 || state === "success" || state === "error" || state === "saving";
            if (state === "success") {
                countEl.textContent = o.successText || tr(N_("Saved"));
                whatEl.textContent = "";
                saveBtn.hidden = discardBtn.hidden = true;
                hideTimer = setTimeout(function () { state = "idle"; render(); }, 2200);
            } else {
                saveBtn.hidden = discardBtn.hidden = false;
                if (state === "error") { /* keep the message set by fail() */ }
                else {
                    countEl.textContent = n === 1 ? trf(N_("{0} unsaved change"), n) : trf(N_("{0} unsaved changes"), n);
                    var names = ch.map(function (c) { return c.label; }).filter(Boolean);
                    whatEl.textContent = names.length ? names.slice(0, 4).join(", ") + (names.length > 4 ? trf(N_(" and {0} more"), names.length - 4) : "") : "";
                }
            }
            if (visible !== shown) {
                shown = visible;
                barEl.hidden = !visible;
                barCount += visible ? 1 : -1;
                updateBodyFlag();
            }
        }
        function fail(err) {
            var text = err && (err.error || err.message || err.statusText) || (typeof err === "string" ? err : "");
            state = "error";
            render();
            countEl.textContent = tr(N_("Not saved"));
            whatEl.textContent = text ? String(text) : tr(N_("The server did not accept the changes. Nothing was lost; try again."));
        }
        function save() {
            if (state === "saving" || !tracker.isDirty()) { return Promise.resolve(false); }
            var ctx = { changes: tracker.changes(), tracker: tracker, bar: api };
            state = "saving";
            render();
            var r;
            try { r = typeof o.onSave === "function" ? o.onSave(ctx) : undefined; }
            catch (e) { fail(e); return Promise.resolve(false); }
            return Promise.resolve(r).then(function (v) {
                if (v === false || (v && typeof v === "object" && v.error !== undefined && v.error !== null && v.error !== false)) { fail(v === false ? "" : v); return false; }
                tracker.pause(700);
                tracker.reset();
                state = "success";
                render();
                if (window.ZxHistory && window.ZxHistory.savedToast) { window.ZxHistory.savedToast(o.successText || tr(N_("Saved")), o.historyObject); }
                return true;
            }, function (e) { fail(e); return false; });
        }
        function discard() {
            if (state === "saving") { return; }
            state = "idle";
            tracker.restore();
            if (typeof o.onDiscard === "function") { try { o.onDiscard(); } catch (e) { console.error(e); } }
            render();
        }
        saveBtn.addEventListener("click", save);
        discardBtn.addEventListener("click", discard);
        tracker.onChange(function () { if (state === "error" || state === "success") { state = "idle"; } render(); });
        // Ctrl/Cmd+S saves while the focus is inside the form
        function onKey(e) {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s" && tracker.isDirty()) { e.preventDefault(); save(); }
        }
        formEl.addEventListener("keydown", onKey);
        var unregister = ZxUI.unsaved.register({
            id: o.id || formEl.id || "form", owner: formEl,
            isDirty: function () { return tracker.isDirty(); }, discard: discard, summary: summary
        });
        var api = {
            tracker: tracker, el: barEl,
            isDirty: function () { return tracker.isDirty(); },
            reset: function () { state = "idle"; tracker.reset(); render(); },
            save: save, discard: discard,
            destroy: function () {
                unregister(); tracker.destroy(); formEl.removeEventListener("keydown", onKey);
                if (shown) { barCount--; updateBodyFlag(); }
                if (slot.parentNode) { slot.parentNode.removeChild(slot); }
            }
        };
        render();
        return api;
    };

    /* ------------------------------------------------------------------ form row helpers */
    ZxUI.field = function (el) {
        var $ = window.jQuery;
        var row = $(el).closest(".zx-field");
        var err = row.find(".zx-error").first();
        return {
            setError: function (text) {
                if (!err.length) {
                    err = $("<p class=\"zx-error\"></p>").attr("id", nextId("zxerr")).appendTo(row);
                }
                err.text(text);
                row.addClass("is-invalid");
                row.find("input, select, textarea").first().attr({ "aria-invalid": "true", "aria-describedby": err.attr("id") });
            },
            clearError: function () {
                row.removeClass("is-invalid");
                row.find("input, select, textarea").first().removeAttr("aria-invalid aria-describedby");
            }
        };
    };

    /* "what is this?" popovers: <button class="zx-whatis" aria-controls="id" aria-expanded="false"> + <div class="zx-popover" id="id" hidden> */
    function closePopovers(except, returnFocus) {
        document.querySelectorAll(".zx-whatis[aria-expanded='true']").forEach(function (b) {
            if (b === except) { return; }
            b.setAttribute("aria-expanded", "false");
            var p = document.getElementById(b.getAttribute("aria-controls"));
            if (p) { p.hidden = true; }
            if (returnFocus) { b.focus(); }
        });
    }
    document.addEventListener("click", function (e) {
        var btn = e.target.closest && e.target.closest(".zx-whatis");
        if (!btn) { if (!(e.target.closest && e.target.closest(".zx-popover"))) { closePopovers(); } return; }
        var p = document.getElementById(btn.getAttribute("aria-controls"));
        if (!p) { return; }
        var open = btn.getAttribute("aria-expanded") === "true";
        closePopovers(btn);
        btn.setAttribute("aria-expanded", open ? "false" : "true");
        p.hidden = open;
        if (!open) {
            var row = p.parentNode;
            if (row && getComputedStyle(row).position === "static") { row.style.position = "relative"; }
            p.style.top = (btn.offsetTop + btn.offsetHeight + 6) + "px";
            p.style.left = "0px";
        }
    });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") { closePopovers(null, true); } });

    /* ------------------------------------------------------------------ tabs / segmented */
    function rovingKeys(items, e, activate) {
        var i = items.indexOf(document.activeElement);
        if (i < 0) { return; }
        var n = items.length, next = i;
        if (e.key === "ArrowRight" || e.key === "ArrowDown") { next = (i + 1) % n; }
        else if (e.key === "ArrowLeft" || e.key === "ArrowUp") { next = (i - 1 + n) % n; }
        else if (e.key === "Home") { next = 0; }
        else if (e.key === "End") { next = n - 1; }
        else { return; }
        e.preventDefault();
        items[next].focus();
        activate(items[next]);
    }

    /*
        ZxUI.tabs(listEl, {onChange(name, tab)}):  <div class="zx-tabs" role="tablist"> <button class="zx-tab" role="tab" data-zx-panel="panelId">..
        Tabs show/hide the elements named by data-zx-panel.  Left/Right/Home/End move between tabs.
    */
    ZxUI.tabs = function (list, o) {
        o = o || {};
        var listEl = window.jQuery(list)[0];
        listEl.setAttribute("role", "tablist");
        var tabs = Array.prototype.slice.call(listEl.querySelectorAll("[role=tab], .zx-tab"));
        function select(tab, focus) {
            tabs.forEach(function (t) {
                var on = t === tab;
                t.setAttribute("aria-selected", on ? "true" : "false");
                t.tabIndex = on ? 0 : -1;
                var p = document.getElementById(t.getAttribute("data-zx-panel") || "");
                if (p) { p.hidden = !on; p.setAttribute("role", "tabpanel"); }
            });
            if (focus) { tab.focus(); }
            if (o.onChange) { o.onChange(tab.getAttribute("data-zx-panel"), tab); }
        }
        tabs.forEach(function (t) {
            t.setAttribute("role", "tab");
            t.addEventListener("click", function () { select(t); });
        });
        listEl.addEventListener("keydown", function (e) { rovingKeys(tabs, e, function (t) { select(t); }); });
        select(tabs.filter(function (t) { return t.getAttribute("aria-selected") === "true"; })[0] || tabs[0]);
        return { select: function (i) { select(tabs[i], true); } };
    };

    /* ZxUI.segmented(el, {onChange(value, item)}): <div class="zx-segmented" role="radiogroup"> <button class="zx-segmented__item" data-value=".."> */
    ZxUI.segmented = function (el, o) {
        o = o || {};
        var box = window.jQuery(el)[0];
        box.setAttribute("role", "radiogroup");
        var items = Array.prototype.slice.call(box.querySelectorAll(".zx-segmented__item"));
        function select(it) {
            items.forEach(function (x) { var on = x === it; x.setAttribute("aria-checked", on ? "true" : "false"); x.tabIndex = on ? 0 : -1; });
            if (o.onChange) { o.onChange(it.getAttribute("data-value"), it); }
        }
        items.forEach(function (it) { it.setAttribute("role", "radio"); it.addEventListener("click", function () { select(it); }); });
        box.addEventListener("keydown", function (e) { rovingKeys(items, e, select); });
        var start = items.filter(function (x) { return x.getAttribute("aria-checked") === "true"; })[0] || items[0];
        items.forEach(function (x) { x.setAttribute("aria-checked", x === start ? "true" : "false"); x.tabIndex = x === start ? 0 : -1; });
        return { value: function () { var c = items.filter(function (x) { return x.getAttribute("aria-checked") === "true"; })[0]; return c && c.getAttribute("data-value"); } };
    };

    /* ------------------------------------------------------------------ skeleton */
    /* ZxUI.skeleton(container, {lines: 3, title: true, block: false}) -> remove(); marks the container aria-busy meanwhile */
    ZxUI.skeleton = function (container, o) {
        o = o || {};
        var c = window.jQuery(container)[0];
        var wrap = document.createElement("div");
        wrap.className = "zx-skeleton-group";
        wrap.setAttribute("aria-hidden", "true");
        var html = o.title ? "<span class=\"zx-skeleton zx-skeleton--title\"></span>" : "";
        for (var i = 0; i < (o.lines === undefined ? 3 : o.lines); i++) { html += "<span class=\"zx-skeleton zx-skeleton--text\"></span>"; }
        if (o.block) { html += "<span class=\"zx-skeleton zx-skeleton--block\"></span>"; }
        wrap.innerHTML = html;
        c.setAttribute("aria-busy", "true");
        c.appendChild(wrap);
        return function remove() { c.removeAttribute("aria-busy"); if (wrap.parentNode) { wrap.parentNode.removeChild(wrap); } };
    };
})();
