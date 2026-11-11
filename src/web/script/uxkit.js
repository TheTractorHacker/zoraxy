/*
    Zoraxy admin UI - UX kit

    Small, self-contained progressive enhancements for the management UI.
    Loaded at the end of index.html. Everything here is optional: if this file
    fails, the UI still works.

      1. Menu filter box (focus with "/")
      2. Non-blocking toast instead of blocking alert()
      3. Keyboard / screen reader accessibility (aria-labels, focusable menu groups)
      4. Unsaved-changes warning for the HTTP proxy rule editor
      5. Rate limited toast on failed API requests
*/
(function () {
    "use strict";

    function storeGet(key) {
        try { return localStorage.getItem(key); } catch (e) { return null; }
    }
    function storeSet(key, val) {
        try { localStorage.setItem(key, val); } catch (e) { /* storage blocked */ }
    }

    /* ---------------------------------------------------------------
       1. Menu filter
    --------------------------------------------------------------- */
    function initMenuFilter() {
        var $menu = $("#mainmenu");
        if ($menu.length === 0 || $("#navFilterInput").length > 0) { return; }
        var $box = $(
            '<div class="navFilter" role="search">' +
            '<div class="ui small fluid icon input">' +
            '<input id="navFilterInput" type="search" autocomplete="off" spellcheck="false" ' +
            'placeholder="Filter menu  ( / )" aria-label="Filter menu items">' +
            '<i class="search icon"></i></div>' +
            '<div id="navFilterEmpty" class="navFilterEmpty" style="display:none;">No matching menu item</div>' +
            '</div>');
        $menu.prepend($box);

        var $input = $("#navFilterInput");

        function apply() {
            var q = $.trim($input.val()).toLowerCase();
            $menu.toggleClass("navFiltering", q !== "");
            var shown = 0;
            $menu.find("a.item").each(function () {
                var $a = $(this);
                var hay = ($a.text() + " " + ($a.attr("tag") || "") + " " + ($a.attr("title") || "")).toLowerCase();
                var hit = q === "" || hay.indexOf(q) > -1;
                $a.toggleClass("navHidden", !hit);
                if (hit && q !== "") { shown++; }
            });
            $menu.find(".menugroup-container").each(function () {
                var any = $(this).find("a.item:not(.navHidden)").length > 0;
                $(this).toggleClass("navHidden", !any);
            });
            $("#navFilterEmpty").toggle(q !== "" && shown === 0);
        }

        $input.on("input search", apply);
        $input.on("keydown", function (e) {
            if (e.key === "Escape") {
                $input.val("");
                apply();
                $input.blur();
            } else if (e.key === "Enter") {
                var $first = $menu.find("a.item:not(.navHidden):visible").filter(function () {
                    return $(this).closest(".navHidden").length === 0 && $(this).attr("tag");
                }).first();
                if ($first.length) { $first.trigger("click"); $input.val(""); apply(); $input.blur(); }
            }
        });

        // "/" focuses the filter (unless typing somewhere)
        $(document).on("keydown", function (e) {
            if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) { return; }
            var t = e.target;
            var tag = (t && t.tagName || "").toLowerCase();
            if (tag === "input" || tag === "textarea" || tag === "select" || (t && t.isContentEditable)) { return; }
            e.preventDefault();
            if (window.innerWidth < 750 && !$(".toolbar").is(":visible")) {
                $(".toolbar").fadeIn("fast");
            }
            $input.trigger("focus").select();
        });
    }

    /* ---------------------------------------------------------------
       2. Toast instead of alert()
    --------------------------------------------------------------- */
    function toast(message, ok) {
        message = String(message === undefined ? "" : message);
        if (typeof window.msgbox === "function") {
            window.msgbox(message, ok === true, ok === true ? 3000 : 6000);
            return true;
        }
        if (window.parent && window.parent !== window && typeof window.parent.msgbox === "function") {
            window.parent.msgbox(message, ok === true, ok === true ? 3000 : 6000);
            return true;
        }
        return false;
    }

    var nativeAlert = window.alert;
    function softAlert(message) {
        if (!toast(message, false)) { nativeAlert.call(window, message); }
    }
    window.alert = softAlert;

    // Snippets are loaded in same-origin iframes: give them the same non-blocking alert
    function patchFrame(frame) {
        try {
            if (frame.contentWindow && frame.contentWindow.location.origin === window.location.origin) {
                frame.contentWindow.alert = softAlert;
            }
        } catch (e) { /* cross origin, ignore */ }
    }
    document.addEventListener("load", function (e) {
        if (e.target && e.target.tagName === "IFRAME") { patchFrame(e.target); }
    }, true);

    function initToastRegion() {
        $("#messageBox").attr({ role: "status", "aria-live": "polite" });
    }

    /* ---------------------------------------------------------------
       3. Accessibility
    --------------------------------------------------------------- */
    var ICON_LABELS = {
        "trash": "Delete", "times": "Close", "close": "Close", "edit": "Edit", "pencil": "Edit",
        "sign-out": "Log out", "sign out": "Log out", "content": "Toggle menu", "bars": "Toggle menu",
        "sun": "Switch theme", "moon": "Switch theme", "plus": "Add", "save": "Save",
        "copy": "Copy", "download": "Download", "upload": "Upload", "refresh": "Refresh",
        "redo": "Refresh", "sync": "Refresh", "search": "Search", "question": "Help",
        "cog": "Settings", "setting": "Settings", "eye": "Show", "pin": "Pin", "filter": "Filter",
        "check": "Confirm", "info": "Information", "play": "Start", "stop": "Stop", "external": "Open"
    };

    function iconLabel($el) {
        var cls = ($el.find("i").first().attr("class") || "").toLowerCase();
        var found = "";
        $.each(ICON_LABELS, function (key, label) {
            if (!found && new RegExp("(^|\\s)" + key.replace(" ", "\\s") + "(\\s|$)").test(cls)) { found = label; }
        });
        return found;
    }

    function labelIconButtons(root) {
        $(root).find("button, a.button, a.icon").addBack("button, a.button, a.icon").each(function () {
            var $b = $(this);
            if ($b.attr("aria-label") || $b.attr("aria-labelledby")) { return; }
            if ($.trim($b.text()) !== "") { return; }
            if ($b.find("i").length === 0) { return; }
            var label = $b.attr("title") || iconLabel($b);
            if (label) { $b.attr("aria-label", label); }
        });
    }

    function makeMenuAccessible(root) {
        $(root).find(".menugroup-header, .recent-section-header").each(function () {
            var $h = $(this);
            if ($h.attr("role")) { return; }
            var gid = ($h.find(".menugroup-chevron").attr("id") || "").replace("chevron-", "");
            $h.attr({ role: "button", tabindex: "0" });
            if (gid) { $h.attr("aria-controls", "group-" + gid); }
        });
        $(root).find(".menugroup-header, .recent-section-header").each(function () {
            var gid = ($(this).find(".menugroup-chevron").attr("id") || "").replace("chevron-", "");
            if (gid) { $(this).attr("aria-expanded", $("#group-" + gid).is(":hidden") ? "false" : "true"); }
        });
        $(root).find("a.item[tag]").each(function () {
            if (!this.hasAttribute("tabindex")) { $(this).attr({ tabindex: "0", role: "link" }); }
        });
    }

    function initKeyboardMenu() {
        $(document).on("keydown", "#mainmenu a.item, #mainmenu .menugroup-header, #mainmenu .recent-section-header, #mainmenu .recent-item", function (e) {
            if (e.key === "Enter" || e.key === " ") {
                if ($(e.target).is("input")) { return; }
                e.preventDefault();
                this.click();
            }
        });
        // keep aria-expanded in sync after a group was toggled
        $(document).on("click", "#mainmenu .menugroup-header, #mainmenu .recent-section-header", function () {
            var $h = $(this);
            setTimeout(function () { makeMenuAccessible($h.parent()); }, 260);
        });
    }

    // Only the nodes that were added since the last run are scanned (scanning document.body on every
    // DOM change cost several ms per run on pages that update text every second). Mutations that only
    // touch text / chart readouts add no element with a button, so they are ignored cheaply.
    var a11yTimer = null;
    var a11yPending = [];
    var a11yMenuDirty = false;

    function onA11yMutations(records) {
        for (var i = 0; i < records.length; i++) {
            var added = records[i].addedNodes;
            for (var j = 0; j < added.length; j++) {
                var n = added[j];
                if (n.nodeType !== 1) { continue; }
                if (a11yPending.length < 200) { a11yPending.push(n); }
                else { a11yPending = [document.body]; }
                if (!a11yMenuDirty && (n.id === "mainmenu" || (records[i].target && records[i].target.closest && records[i].target.closest("#mainmenu")))) { a11yMenuDirty = true; }
            }
        }
        if (a11yPending.length === 0 || a11yTimer) { return; }
        a11yTimer = setTimeout(function () {
            a11yTimer = null;
            var nodes = a11yPending; a11yPending = [];
            var menu = a11yMenuDirty; a11yMenuDirty = false;
            for (var k = 0; k < nodes.length; k++) {
                if (nodes[k].isConnected) { labelIconButtons(nodes[k]); }
            }
            if (menu) { makeMenuAccessible($("#mainmenu")); }
        }, 250);
    }

    function initA11y() {
        labelIconButtons(document.body);
        makeMenuAccessible($("#mainmenu"));
        initKeyboardMenu();
        if (window.MutationObserver) {
            new MutationObserver(onA11yMutations).observe(document.body, { childList: true, subtree: true });
        }
    }

    /* ---------------------------------------------------------------
       4. Unsaved changes warning for the proxy rule editor
    --------------------------------------------------------------- */
    var editorDirty = false;
    var editorGuardPass = false;

    window.resetEditorDirty = function () { editorDirty = false; if (window.HrpEditor && window.HrpEditor.bar) { window.HrpEditor.bar.reset(); } };
    // The site editor (script/siteeditor.js) tracks its own fields with a Save bar. Edits to those fields are the bar's
    // business; this flag only keeps covering the sub forms that save themselves ([data-hrp-selfsave]) and the old behaviour
    // when the editor script is not there.
    function barDirty() { return !!(window.HrpEditor && window.HrpEditor.bar && window.HrpEditor.bar.isDirty()); }
    function guardDirty() { return editorDirty || barDirty(); }

    function initEditorGuard() {
        // any user edit inside the editor marks it dirty
        $(document).on("input change", "#httprpEditModal input, #httprpEditModal textarea, #httprpEditModal select", function (e) {
            if (e.originalEvent === undefined || e.originalEvent.isTrusted === false) { return; } //programmatic change while populating
            if ($(this).closest(".ui.dropdown, .search").length && e.type === "input") { /* typing in a dropdown search */ return; }
            if (window.HrpEditor && window.HrpEditor.bar && !$(this).closest("[data-hrp-selfsave]").length) { return; } //tracked by the Save bar
            editorDirty = true;
        });
        // a successful save through the API clears the flag
        $(document).ajaxSuccess(function (ev, xhr, settings) {
            if (!editorDirty || !settings || (settings.type || settings.method || "GET").toUpperCase() === "GET") { return; }
            var u = String(settings.url || "");
            if (u.indexOf("/api/proxy/") !== 0 && u.indexOf("/api/waf/") !== 0) { return; }
            var data = xhr && xhr.responseJSON;
            if (data && data.error !== undefined) { return; }
            editorDirty = false;
        });
        // intercept the ways of closing the editor (capture phase, runs before inline handlers)
        document.addEventListener("click", function (e) {
            if (!guardDirty() || editorGuardPass) { return; }
            var closer = $(e.target).closest("#httprpEditDarkenLayer, .httpProxyEditClosePC, .httpProxyEditCloseMobile");
            if (closer.length === 0) { return; }
            e.stopImmediatePropagation();
            e.preventDefault();
            $("#confirmBox").show();
            window.confirmBox("You have changes in this editor that may not be saved. Close anyway?", function (choice) {
                if (choice === true) {
                    editorDirty = false;
                    editorGuardPass = true;
                    if (barDirty()) { window.HrpEditor.bar.reset(); } //closing discards: the next open starts clean
                    closer[0].click();
                    editorGuardPass = false;
                }
            }, 10);
        }, true);
        // opening the editor again starts clean
        $(document).on("click", "#httpProxyList .editBtn, #httpProxyList [onclick*='editEndpoint']", function () {
            editorDirty = false;
        });
        // let the component kit (script/zxui.js) know about this guard: one registry of everything holding unsaved work
        if (window.ZxUI && ZxUI.unsaved) {
            ZxUI.unsaved.register({ id: "proxy-editor-selfsave", isDirty: function () { return editorDirty && $("#httprpEditModalWrapper").is(":visible"); } });
        }
        window.addEventListener("beforeunload", function (e) {
            if (guardDirty() && $("#httprpEditModalWrapper").is(":visible")) {
                e.preventDefault();
                e.returnValue = "";
            }
        });
    }

    /* ---------------------------------------------------------------
       5. Failed API requests -> toast (rate limited)
    --------------------------------------------------------------- */
    var lastAjaxToast = 0;

    /* A request answered with 401, or redirected to the login page (what the server does when the session cookie is gone or
       expired), means the session ended. Show ONE banner with a sign-in link instead of a stream of failed requests. */
    var sessionEnded = false;
    function endedSession(xhr, settings) {
        if (!xhr) { return false; }
        var url = String((settings && settings.url) || "").split("?")[0];
        if (/\/api\/auth\/(login|logout|checkLogin|authEnabled|register)$/.test(url)) { return false; }
        if (xhr.status === 401) { return true; }
        var ru = String(xhr.responseURL || "");
        return /\/login\.html(\?|#|$)/.test(ru) && !/\/login\.html(\?|#|$)/.test(url);
    }
    function showSessionExpired() {
        if (sessionEnded) { return; }
        sessionEnded = true;
        var bar = document.createElement("div");
        bar.className = "zx-session-banner";
        bar.setAttribute("role", "alert");
        var msg = document.createElement("span");
        msg.className = "zx-session-banner__msg";
        msg.textContent = (typeof window.t === "function" ? window.t("Your session expired.") : "Your session expired.");
        var link = document.createElement("a");
        link.href = "/login.html";
        link.className = "zx-btn zx-btn--primary zx-session-banner__link";
        link.textContent = (typeof window.t === "function" ? window.t("Sign in again") : "Sign in again");
        bar.appendChild(msg);
        bar.appendChild(link);
        document.body.appendChild(bar);
        document.body.classList.add("zx-session-ended");
    }
    window.zxSessionExpired = showSessionExpired;
    function initSessionExpiry() {
        //ajaxComplete runs for every finished request (also a redirect to the login page that came back as 200)
        $(document).ajaxComplete(function (ev, xhr, settings) {
            if (endedSession(xhr, settings)) { showSessionExpired(); }
        });
    }

    function initAjaxErrorToast() {
        initSessionExpiry();
        $(document).ajaxError(function (ev, xhr, settings) {
            if (sessionEnded && (endedSession(xhr, settings) || (xhr && xhr.status === 401))) { return; } //already explained by the banner
            if (!xhr || xhr.statusText === "abort" || xhr.status === 0 && xhr.readyState === 0) { return; }
            //The server explains itself in {"error": "..."} (also with HTTP 4xx): show that text, not a bare status code
            var reason = "";
            try {
                var body = xhr.responseJSON || JSON.parse(xhr.responseText);
                if (body && typeof body.error === "string") { reason = body.error; }
            } catch (e) { /* not JSON */ }
            if (reason) { toast(reason, false); return; }
            var now = Date.now();
            if (now - lastAjaxToast < 10000) { return; }
            lastAjaxToast = now;
            var url = String((settings && settings.url) || "").split("?")[0];
            var what = xhr.status ? ("HTTP " + xhr.status) : "network error";
            toast("Request failed (" + what + "): " + url, false);
        });
    }

    /* ---------------------------------------------------------------
       6. Scroll cue for tab bars that scroll sideways on narrow screens: a fade at the cut-off edge
          (classes zx-scroll-start / zx-scroll-end, styled in main.css) so hidden tabs can be discovered
    --------------------------------------------------------------- */
    function updateScrollCue(el) {
        var max = el.scrollWidth - el.clientWidth;
        el.classList.toggle("zx-scroll-end", max > 2 && el.scrollLeft < max - 2);
        el.classList.toggle("zx-scroll-start", max > 2 && el.scrollLeft > 2);
    }
    function initScrollCue() {
        var SEL = ".ui.tabular.menu, .zx-tabs";
        var timer = null;
        function scan() { document.querySelectorAll(SEL).forEach(updateScrollCue); }
        function later() { clearTimeout(timer); timer = setTimeout(scan, 120); }
        document.addEventListener("scroll", function (e) {
            if (e.target && e.target.matches && e.target.matches(SEL)) { updateScrollCue(e.target); }
        }, true);
        window.addEventListener("resize", later);
        new MutationObserver(later).observe(document.body, { childList: true, subtree: true });
        scan();
    }

    $(function () {
        try {
            initScrollCue();
            initMenuFilter();
            initToastRegion();
            initA11y();
            initEditorGuard();
            initAjaxErrorToast();
        } catch (e) {
            console.error("uxkit init failed", e);
        }
    });
})();
