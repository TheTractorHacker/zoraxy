/*
    Zoraxy admin UI - change history helper (window.ZxHistory)

    Thin wrapper around /api/history/* for any page or script. It has no UI of
    its own; the History page (components/history.html) is the UI.

      ZxHistory.list({page, pageSize, object, actor, from, to})  -> Promise<{items,total,...}>
      ZxHistory.get(id)                                          -> Promise<{version, previous}>
      ZxHistory.diff(from, to)                                   -> Promise<{files:[...]}>  (secrets masked)
      ZxHistory.restore({id, scope, dryrun, confirm})            -> Promise<result>
      ZxHistory.settings(values?)                                -> Promise<settings>
      ZxHistory.snapshot(note)                                   -> Promise<{version, created}>
      ZxHistory.undoLast()                                       -> Promise<{latest, target, scope}>
          Opens the History page with the restore preview of the state before the most recent
          change (nothing is changed until the admin confirms there). The "Undo" action of a
          save toast calls this.
*/
(function () {
    "use strict";

    function csrf() {
        var m = document.getElementsByTagName("meta")["zoraxy.csrf.Token"];
        return m ? m.getAttribute("content") : "";
    }

    function qs(params) {
        var out = [];
        Object.keys(params || {}).forEach(function (k) {
            var v = params[k];
            if (v !== undefined && v !== null && v !== "") { out.push(encodeURIComponent(k) + "=" + encodeURIComponent(v)); }
        });
        return out.length ? "?" + out.join("&") : "";
    }

    function call(method, path, params) {
        var opt = { method: method, credentials: "same-origin", headers: {} };
        var url = "./api/history/" + path;
        if (method === "GET") {
            url += qs(params);
        } else {
            opt.headers["X-CSRF-Token"] = csrf();
            opt.headers["Content-Type"] = "application/x-www-form-urlencoded";
            opt.body = qs(params).slice(1);
        }
        return fetch(url, opt).then(function (r) {
            return r.json().catch(function () { return {}; }).then(function (j) {
                if (!r.ok || (j && j.error && !j.version && !j.items)) {
                    var e = new Error((j && j.error) || ("request failed (" + r.status + ")"));
                    e.status = r.status;
                    e.body = j;
                    throw e;
                }
                return j;
            });
        });
    }

    function areaOf(changes) {
        var areas = {};
        (changes || []).forEach(function (c) { areas[c.area || ""] = true; });
        var keys = Object.keys(areas);
        return keys.length === 1 && keys[0] !== "" ? keys[0] : "all";
    }

    var ZxHistory = {
        list: function (p) { return call("GET", "list", p); },
        get: function (id) { return call("GET", "get", { id: id }); },
        diff: function (from, to) { return call("GET", "diff", { from: from, to: to }); },
        restore: function (o) {
            return call("POST", "restore", { id: o.id, scope: o.scope || "all", dryrun: o.dryrun ? "true" : "", confirm: o.confirm || "" });
        },
        settings: function (v) { return v ? call("POST", "settings", v) : call("GET", "settings"); },
        snapshot: function (note) { return call("POST", "snapshot", { note: note || "" }); },
        // Opens System > History with the Object filter set (a substring of the changed object, e.g. "example.com" or "WAF").
        // Read-only: it never restores anything.
        view: function (object) {
            if (typeof window.openTabById === "function") { window.openTabById("history"); }
            var tries = 0;
            (function apply() {
                var input = document.getElementById("hxFilterObject"), btn = document.getElementById("hxFilterBtn");
                if (input && btn && window.ZxHistoryUI) {
                    input.value = object || "";
                    btn.click();
                } else if (tries++ < 60) {
                    setTimeout(apply, 100);
                }
            })();
        },
        // The kit toast shown after a successful configuration save: message plus a "View history" action.
        savedToast: function (message, object) {
            if (!window.ZxUI || !window.ZxUI.toast) { return null; }
            var label = typeof window.t === "function" ? window.t("View history") : "View history";
            return window.ZxUI.toast(message || "Saved", { type: "success", action: { label: label, run: function () { ZxHistory.view(object); } } });
        },
        undoLast: function () {
            return call("GET", "list", { pageSize: 2 }).then(function (res) {
                var items = res.items || [];
                if (items.length < 2) { throw new Error("There is no earlier version to go back to."); }
                var latest = items[0], target = items[1];
                var scope = areaOf(latest.changes);
                var tab = document.querySelector('#mainmenu [tag="history"], .menugroup-items [tag="history"]');
                if (tab) { tab.click(); }
                var tries = 0;
                (function open() {
                    if (window.ZxHistoryUI && window.ZxHistoryUI.openRestore) {
                        window.ZxHistoryUI.openRestore(target.id, scope);
                    } else if (tries++ < 60) {
                        setTimeout(open, 100);
                    }
                })();
                return { latest: latest.id, target: target.id, scope: scope };
            });
        }
    };
    window.ZxHistory = ZxHistory;
})();
