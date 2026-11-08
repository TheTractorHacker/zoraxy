/*
    Zoraxy admin UI - performance kit

    Every page (components/*.html) is loaded into the document at start up and keeps its own
    setInterval polling alive, whether or not the page is on screen. With ~30 pages this meant
    a few dozen timers redrawing hidden DOM, re-parsing JSON and recalculating styles all day.

    This file (loaded right after jQuery, before any component) makes interval timers
    visibility aware without touching every component:

      * an interval registered while a page component is being loaded belongs to that page;
        its callback only runs while that page is the active tab (otherwise the tick is skipped);
      * no interval callback runs while the browser tab is hidden;
      * when a page becomes active again (or the browser tab becomes visible) the callbacks that
        missed ticks run once, staggered, so the data is fresh without a burst of work.

    Timers created later (inside ajax callbacks, event handlers) are not attributed to a page and
    only honour the "browser tab hidden" rule. Opt out for a timer that must always run by calling
    window.setIntervalAlways(fn, ms).
*/
(function () {
    "use strict";
    if (window.__perfkit) { return; }
    window.__perfkit = true;

    var nativeSet = window.setInterval.bind(window);
    var nativeClear = window.clearInterval.bind(window);
    var records = {};          // timer id -> {fn, tab, missed}
    var loadingTab = null;     // page component whose HTML (and scripts) is being inserted right now
    var activeTab = (window.location.hash || "#status").replace(/^#/, "");
    if (activeTab.charAt(0) === "{") { activeTab = "pluginContextWindow"; }

    window.setInterval = function (fn, ms) {
        if (typeof fn !== "function") { return nativeSet.apply(window, arguments); }
        var extra = Array.prototype.slice.call(arguments, 2);
        var rec = { fn: fn, extra: extra, tab: loadingTab, missed: false };
        var id = nativeSet(function () {
            if (document.hidden || (rec.tab && rec.tab !== activeTab)) {
                rec.missed = true;
                return;
            }
            rec.missed = false;
            return fn.apply(window, extra);
        }, ms);
        records[id] = rec;
        return id;
    };
    window.setIntervalAlways = nativeSet;
    window.clearInterval = function (id) {
        delete records[id];
        nativeClear(id);
    };

    // tag intervals created while jQuery inserts a page component (.load() -> .html())
    if (window.jQuery) {
        var origHtml = jQuery.fn.html;
        jQuery.fn.html = function (value) {
            if (value !== undefined && this.length === 1 && this[0].classList && this[0].classList.contains("functiontab")) {
                var prev = loadingTab;
                loadingTab = this[0].id;
                try { return origHtml.apply(this, arguments); } finally { loadingTab = prev; }
            }
            return origHtml.apply(this, arguments);
        };
    }

    function catchUp(tab) {
        var delay = 0;
        Object.keys(records).forEach(function (id) {
            var r = records[id];
            if (!r.missed || (r.tab && r.tab !== tab)) { return; }
            r.missed = false;
            delay += 40; // spread the refreshes out, never one long task
            setTimeout(function () {
                if (records[id] && !document.hidden) { try { r.fn.apply(window, r.extra); } catch (e) { console.error(e); } }
            }, delay);
        });
    }

    document.addEventListener("visibilitychange", function () {
        if (!document.hidden) { catchUp(activeTab); }
    });

    window.perfkitSetActiveTab = function (tab) {
        if (tab === activeTab) { return; }
        activeTab = tab;
        catchUp(tab);
    };

    // follow the tab switches of index.html
    jQuery(function () {
        var orig = window.openTabById;
        if (typeof orig !== "function") { return; }
        window.openTabById = function (tabID) {
            window.perfkitSetActiveTab(tabID);
            return orig.apply(this, arguments);
        };
    });
})();
