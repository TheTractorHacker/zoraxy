/*
    Zoraxy admin UI - small delegated page helpers (consistency pass)

    [data-zx-history="Object"]   a History shortcut button: opens System > History filtered to that object (read only).
    [data-nav-open="tag"]        handled by nav.js (links of the Related boxes).
    [data-zx-toggle="id"]        collapsible card: the button toggles the element with that id (aria-expanded kept in step).
*/
(function () {
    "use strict";
    document.addEventListener("click", function (e) {
        var h = e.target.closest && e.target.closest("[data-zx-history]");
        if (h) {
            e.preventDefault();
            if (window.ZxHistory) { window.ZxHistory.view(h.getAttribute("data-zx-history")); }
            return;
        }
        var t = e.target.closest && e.target.closest("[data-zx-toggle]");
        if (t) {
            var box = document.getElementById(t.getAttribute("data-zx-toggle"));
            if (!box) { return; }
            var open = t.getAttribute("aria-expanded") !== "true";
            t.setAttribute("aria-expanded", open ? "true" : "false");
            box.hidden = !open;
        }
    });
})();
