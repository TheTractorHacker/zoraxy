/*
    proxytable.js

    The HTTP proxy rule list (components/httprp.html): one component for listing, filtering, sorting,
    selecting (checkboxes, shift-click ranges, select all) and acting on rules.

    - Renders from a model (state.list) with one innerHTML write per page, event delegation on the table body,
      and pagination (page size 25/50/100) so that hundreds of rules never mean hundreds of DOM rows.
    - Bulk actions are handled by script/proxybulk.js (ProxyBulk.run), which calls /api/proxy/bulk.
    - Single enable / disable is the status pill in each row (one click, with an undo toast).
    - No API changes: /api/proxy/list, /api/proxy/toggle, /api/proxy/del, /api/utm/list, /api/access/list.

    Globals kept for the rest of the UI (snippets call them through parent.*): listProxyEndpoints,
    renderTagsPreview, updateAccessRuleNameUnderHost, updateAliasListForEndpoint, editEndpoint, deleteEndpoint,
    filterProxyList. ProxyTable.highlight(name) scrolls to a rule and flashes its row (used after creating one).
*/
(function () {
    "use strict";

    var PAGE_SIZES = [25, 50, 100];
    var state = {
        list: [],            // rules as returned by /api/proxy/list
        healthRaw: {},       // rule -> upstream -> latest uptime monitor result
        waf: null,           // global WAF policy (Enabled, DefaultMode), decides what "follows the global policy" means
        access: {},          // access rule id -> access rule
        sel: {},             // rule -> true
        q: "",
        status: "all",       // all | enabled | disabled | errors | noauth
        tags: [],            // selected tag filters (a rule must have all of them)
        sort: { key: "host", dir: 1 },
        page: 1,
        pageSize: 50,
        view: [],            // filtered + sorted rules
        lastClicked: null,   // rule name, anchor for shift-click range selection
        flash: "",           // rule whose row is flashing (survives the re-renders caused by late health / access data)
        loaded: false
    };

    try {
        var saved = JSON.parse(localStorage.getItem("httprp_table") || "{}");
        if (saved.sort && saved.sort.key) { state.sort = saved.sort; }
        if (PAGE_SIZES.indexOf(saved.pageSize) > -1) { state.pageSize = saved.pageSize; }
    } catch (e) { /* storage may be blocked */ }
    function persist() {
        try { localStorage.setItem("httprp_table", JSON.stringify({ sort: state.sort, pageSize: state.pageSize })); } catch (e) { }
    }

    function esc(s) {
        return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c];
        });
    }
    function $page() { return $("#httprpPage"); }
    function byName(name) {
        for (var i = 0; i < state.list.length; i++) { if (state.list[i].RootOrMatchingDomain === name) { return state.list[i]; } }
        return null;
    }
    function selNames() { return Object.keys(state.sel); }

    /* ------------------------------------------------------------------ derived values */
    function authLabel(r) {
        var m = r.AuthenticationProvider ? r.AuthenticationProvider.AuthMethod : 0;
        return { 1: "Basic Auth", 2: "Forward Auth", 3: "OAuth2", 4: "Zoraxy Auth" }[m] || "";
    }

    // "on" enabled and fine, "err" enabled but cannot serve, "off" disabled
    function ruleState(r) {
        if (r.Disabled) { return "off"; }
        if (!r.ActiveOrigins || r.ActiveOrigins.length === 0) { return "err"; }
        if (healthOf(r) === "down") { return "err"; }
        return "on";
    }
    function stateText(r) {
        if (r.Disabled) { return "Disabled"; }
        if (!r.ActiveOrigins || r.ActiveOrigins.length === 0) { return "Enabled, but no active upstream"; }
        var h = healthOf(r);
        if (h === "down") { return "Enabled, upstream offline (uptime monitor)"; }
        if (h === "up") { return "Enabled, upstream online"; }
        return "Enabled";
    }

    function prepare(r) {
        var ups = (r.ActiveOrigins || []).map(function (o) { return o.OriginIpOrDomain; });
        r._up = ups.join(" ").toLowerCase();
        r._hay = [r.RootOrMatchingDomain, (r.MatchingDomainAlias || []).join(" "), r._up, (r.Tags || []).join(" "), authLabel(r)].join(" ").toLowerCase();
        r._tags = (r.Tags || []).map(function (t) { return t.toLowerCase(); });
    }

    function applyFilter() {
        var q = state.q.trim().toLowerCase();
        var terms = q ? q.split(/\s+/) : [];
        var wantTags = state.tags.map(function (t) { return t.toLowerCase(); });
        var out = state.list.filter(function (r) {
            for (var i = 0; i < terms.length; i++) { if (r._hay.indexOf(terms[i]) < 0) { return false; } }
            for (var j = 0; j < wantTags.length; j++) { if (r._tags.indexOf(wantTags[j]) < 0) { return false; } }
            switch (state.status) {
                case "enabled": return !r.Disabled;
                case "disabled": return !!r.Disabled;
                case "errors": return ruleState(r) === "err";
                case "noauth": return !(r.AuthenticationProvider && r.AuthenticationProvider.AuthMethod);
            }
            return true;
        });
        var k = state.sort.key, d = state.sort.dir;
        var rank = { err: 0, on: 1, off: 2 };
        out.sort(function (a, b) {
            var x, y;
            if (k === "upstream") { x = a._up; y = b._up; }
            else if (k === "status") { x = rank[ruleState(a)]; y = rank[ruleState(b)]; }
            else if (k === "tags") { x = (a.Tags || []).length ? a._tags.slice().sort()[0] : "￿"; y = (b.Tags || []).length ? b._tags.slice().sort()[0] : "￿"; }
            else { x = a.RootOrMatchingDomain.toLowerCase(); y = b.RootOrMatchingDomain.toLowerCase(); }
            if (x < y) { return -d; }
            if (x > y) { return d; }
            return a.RootOrMatchingDomain < b.RootOrMatchingDomain ? -1 : 1;
        });
        state.view = out;
        var pages = Math.max(1, Math.ceil(out.length / state.pageSize));
        if (state.page > pages) { state.page = pages; }
    }

    /* ------------------------------------------------------------------ rendering */
    function tlsGlobalOn() {
        try { return $("#tls").length ? $("#tls").checkbox("is checked") : false; } catch (e) { return false; }
    }
    function hostLink(r, host) {
        var proto = tlsGlobalOn() ? "https://" : "http://";
        var port = (typeof currentListeningPort !== "undefined") ? currentListeningPort : "";
        port = (port === "" || port == 80 || port == 443) ? "" : ":" + port;
        return proto + host.replace(/^\*\./, "") + port;
    }

    function rowHtml(r) {
        var name = r.RootOrMatchingDomain, e = esc(name);
        var st = ruleState(r);
        var tlsOn = tlsGlobalOn();
        var lock = !tlsOn ? '<i class="yellow lock open icon" title="Plain text (HTTPS is off)"></i>'
            : (r.BypassGlobalTLS ? '<i class="grey lock icon" title="HTTPS bypass: plain HTTP allowed for this host"></i>'
                : '<i class="green lock icon" title="Served over HTTPS"></i>');

        // sub line
        var sub = [];
        if (r.MatchingDomainAlias && r.MatchingDomainAlias.length) {
            sub.push('<span class="ptAlias" title="Alias hostnames">Alias: ' + r.MatchingDomainAlias.map(function (a) {
                return '<a href="' + esc(hostLink(r, a)) + '" target="_blank" rel="noopener">' + esc(a) + '</a>';
            }).join(", ") + '</span>');
        }
        if (r.ListeningPorts && r.ListeningPorts.length) { sub.push('<span title="Alternative listening ports"><i class="plug icon"></i>' + r.ListeningPorts.map(esc).join(", ") + '</span>'); }
        var vd = r.VirtualDirectories || [];
        if (vd.length) {
            sub.push('<a href="#" class="ptVdir" data-ep="' + e + '" title="' + esc(vd.map(function (v) { return v.MatchingPath + " > " + v.Domain; }).join("\n")) + '"><i class="folder outline icon"></i>' + vd.length + ' virtual dir' + (vd.length > 1 ? "s" : "") + '</a>');
        }
        var aid = r.AccessFilterUUID || "default";
        if (aid !== "default") {
            var ar = state.access[aid];
            sub.push('<span class="ptAccess" title="Access rule">' + (ar ? '<i class="filter icon"></i>' + esc(ar.Name) : '<span class="ptBad"><i class="exclamation triangle icon"></i>Access rule missing</span>') + '</span>');
        }

        // upstreams
        var ups = r.ActiveOrigins || [], upHtml;
        if (!ups.length) {
            upHtml = '<span class="ptBad"><i class="exclamation triangle icon"></i> No active upstream</span>';
        } else {
            upHtml = ups.slice(0, 2).map(function (u) {
                var lk = u.RequireTLS ? (u.SkipCertValidations ? '<i class="yellow lock icon" title="TLS without certificate verification"></i>' : '<i class="green lock icon" title="TLS to upstream"></i>') : "";
                var addr = u.OriginIpOrDomain;
                if (/^unix:/i.test(addr)) { return '<span class="ptUp">' + esc(addr) + '</span>'; }
                return '<a class="ptUp" href="' + esc((u.RequireTLS ? "https://" : "http://") + addr) + '" target="_blank" rel="noopener">' + esc(addr) + '</a> ' + lk;
            }).join("<br>");
            if (ups.length > 2) {
                upHtml += '<br><a href="#" class="ptMoreUp ptMuted" data-ep="' + e + '" title="' + esc(ups.slice(2).map(function (u) { return u.OriginIpOrDomain; }).join("\n")) + '">+' + (ups.length - 2) + ' more</a>';
            }
        }

        // protection badges
        var b = [], al = authLabel(r);
        if (al) { b.push('<span class="ptBadge auth" title="' + al + '"><i class="key icon"></i>' + al.replace(" Auth", "") + '</span>'); }
        var ws = r.WAFSource || (r.WAF ? "custom" : "");
        if (ws && ws !== "inherit" && ws !== "off") {
            b.push('<span class="ptBadge waf" title="Web application firewall: ' + esc(ws) + (r.WAFProfile ? " (" + esc(r.WAFProfile) + ")" : "") + '"><i class="shield alternate icon"></i>WAF' + (ws === "detection_only" ? " detect" : "") + '</span>');
        }
        if (r.RequireCaptcha) { b.push('<span class="ptBadge" title="CAPTCHA challenge"><i class="puzzle piece icon"></i>CAPTCHA</span>'); }
        if (r.RequireRateLimit) { b.push(r.RateUnit === "minute" ? '<span class="ptBadge" title="Rate limit ' + esc(r.RateLimit) + ' requests per minute per IP"><i class="tachometer alternate icon"></i>' + esc(r.RateLimit) + '/min</span>' : '<span class="ptBadge" title="Rate limit ' + esc(r.RateLimit) + ' requests per second per IP"><i class="tachometer alternate icon"></i>' + esc(r.RateLimit) + '/s</span>'); }
        if (r.BlockCommonExploits) { b.push('<span class="ptBadge" title="Blocks common exploit payloads"><i class="bug icon"></i>Exploits</span>'); }
        if (r.BlockAICrawlers) { b.push('<span class="ptBadge" title="Blocks AI crawlers and bots"><i class="user secret icon"></i>Bots</span>'); }
        if ((!ws || ws === "inherit") && state.waf && state.waf.Enabled) {
            var gm = state.waf.DefaultMode === "block" ? "blocking" : "detection only";
            b.push('<span class="ptBadge waf" title="Follows the global WAF policy (currently ' + gm + ')"><i class="shield alternate icon"></i>WAF (global)</span>');
        }
        if (!b.length) { b.push('<span class="ptMuted">None</span>'); }

        var tags = (r.Tags || []).map(function (t) {
            return '<a href="#" class="ptTag" data-tag="' + esc(t) + '" style="background-color:' + getTagColorByName(t) + ';color:' + getTagTextColor(t) + '">' + esc(t) + '</a>';
        }).join("");

        var on = !r.Disabled;
        return '<tr class="subdEntry ptRow ' + (r.Disabled ? "isOff " : "") + (state.sel[name] ? "isSel " : "") + (state.flash === name ? "ptFlash" : "") + '" eptuuid="' + e + '" data-ep="' + e + '">' +
            '<td class="ptSel"><input type="checkbox" class="bulkSel" data-ep="' + e + '" aria-label="Select ' + e + '"' + (state.sel[name] ? " checked" : "") + '></td>' +
            '<td class="ptName"><span class="ptDot ' + st + '" title="' + esc(stateText(r)) + '"></span><div class="ptNameBody">' +
            '<a class="ptHost" href="' + esc(hostLink(r, name)) + '" target="_blank" rel="noopener">' + e + '</a> ' + lock +
            (sub.length ? '<div class="ptSub">' + sub.join('<span class="ptSep"></span>') + '</div>' : '') + '</div></td>' +
            '<td class="ptUps">' + upHtml + '</td>' +
            '<td class="ptProt">' + b.join("") + '</td>' +
            '<td class="ptTagsCell">' + tags + '</td>' +
            '<td class="ptStatusCell"><button type="button" class="ptPill ' + (on ? "on" : "off") + (st === "err" ? " err" : "") + '" data-act="toggle" role="switch" aria-checked="' + on + '" title="' + esc(stateText(r)) + ". Click to " + (on ? "disable" : "enable") + '">' +
            '<span class="ptPillDot"></span>' + (on ? (st === "err" ? "Enabled, upstream down" : "Enabled") : "Disabled") + '</button></td>' +
            '<td class="ptAct"><button type="button" class="ui mini basic blue button editBtn" data-act="edit" title="Edit proxy rule"><i class="edit icon"></i> Edit</button>' +
            '<button type="button" class="ui mini basic icon button ptDel" data-act="delete" title="Remove proxy rule" aria-label="Remove ' + e + '"><i class="red trash icon"></i></button></td>' +
            '</tr>';
    }

    function renderRows() {
        var start = (state.page - 1) * state.pageSize;
        var rows = state.view.slice(start, start + state.pageSize);
        var $body = $("#httpProxyList");
        var cols = 7;
        if (!state.list.length) {
            $body.html('<tr class="ptEmptyRow"><td colspan="' + cols + '"><div class="ptEmpty"><i class="sitemap icon"></i><h3>No proxy rules yet</h3>' +
                '<p>A proxy rule sends requests for a domain to a server on your network.</p>' +
                '<button type="button" class="ui primary button" onclick="openNewRuleDialog()"><i class="plus icon"></i> Create your first proxy rule</button></div></td></tr>');
        } else if (!rows.length) {
            $body.html('<tr class="ptEmptyRow"><td colspan="' + cols + '"><div class="ptEmpty"><i class="search icon"></i><h3>No rule matches</h3><p>Nothing fits the current search and filters.</p>' +
                '<button type="button" class="ui basic button" data-act="clearfilters">Clear filters</button></div></td></tr>');
        } else {
            var html = "";
            for (var i = 0; i < rows.length; i++) { html += rowHtml(rows[i]); }
            $body.html(html);
        }
    }

    function renderHeader() {
        $("#httpProxyTable thead th[data-sort]").each(function () {
            var k = $(this).attr("data-sort"), active = state.sort.key === k;
            $(this).attr("aria-sort", active ? (state.sort.dir > 0 ? "ascending" : "descending") : "none")
                .toggleClass("sorted", active).find(".ptArrow").text(active ? (state.sort.dir > 0 ? "▲" : "▼") : "");
        });
    }

    function renderTools() {
        var counts = { all: state.list.length, enabled: 0, disabled: 0, errors: 0, noauth: 0 };
        state.list.forEach(function (r) {
            if (r.Disabled) { counts.disabled++; } else { counts.enabled++; }
            if (ruleState(r) === "err") { counts.errors++; }
            if (!(r.AuthenticationProvider && r.AuthenticationProvider.AuthMethod)) { counts.noauth++; }
        });
        $("#ptSeg button").each(function () {
            var f = $(this).attr("data-f");
            $(this).toggleClass("active", state.status === f).attr("aria-pressed", state.status === f)
                .find(".n").text(counts[f]);
        });
        $("#ptSeg button[data-f=errors]").toggleClass("hasErr", counts.errors > 0);

        // tag chips: most used first, the rest in a dropdown
        var tc = {};
        state.list.forEach(function (r) { (r.Tags || []).forEach(function (t) { tc[t] = (tc[t] || 0) + 1; }); });
        var tags = Object.keys(tc).sort(function (a, b) { return tc[b] - tc[a] || a.localeCompare(b); });
        state.tags = state.tags.filter(function (t) { return tc[t]; });
        var shown = tags.slice(0, 8), rest = tags.slice(8);
        state.tags.forEach(function (t) { if (shown.indexOf(t) < 0) { shown.push(t); rest = rest.filter(function (x) { return x !== t; }); } });
        var html = shown.map(function (t) {
            var on = state.tags.indexOf(t) > -1;
            return '<button type="button" class="ptChip' + (on ? " on" : "") + '" data-tag="' + esc(t) + '" aria-pressed="' + on + '"><span class="ptChipDot" style="background:' + getTagColorByName(t) + '"></span>' + esc(t) + ' <span class="n">' + tc[t] + '</span></button>';
        }).join("");
        if (rest.length) {
            html += '<select id="ptMoreTags" class="ptMoreTags" aria-label="More tags"><option value="">+' + rest.length + ' more tags</option>' +
                rest.map(function (t) { return '<option value="' + esc(t) + '">' + esc(t) + ' (' + tc[t] + ')</option>'; }).join("") + '</select>';
        }
        $("#ptTagChips").html(html).toggle(tags.length > 0);
        $("#ptClear").toggle(!!(state.q || state.tags.length || state.status !== "all"));
    }

    function renderPager() {
        var total = state.view.length, pages = Math.max(1, Math.ceil(total / state.pageSize));
        var from = total ? (state.page - 1) * state.pageSize + 1 : 0, to = Math.min(total, state.page * state.pageSize);
        var filtered = total !== state.list.length;
        $("#ptCount").text(total ? ("Showing " + from + "-" + to + " of " + total + " rule" + (total === 1 ? "" : "s") + (filtered ? " (" + state.list.length + " in total)" : "")) : "");
        $("#ptPager").toggle(total > 0 && (pages > 1 || total > PAGE_SIZES[0]));
        $("#ptPrev").prop("disabled", state.page <= 1);
        $("#ptNext").prop("disabled", state.page >= pages);
        $("#ptPageNo").text("Page " + state.page + " / " + pages);
        $("#ptPageSize").val(state.pageSize);
    }

    function renderBulk() {
        var names = selNames(), n = names.length;
        $("#bulkBar").prop("hidden", n === 0);
        $("#bulkBar .bulkCount").text(n + " selected");
        // header checkbox reflects the rows on this page
        var start = (state.page - 1) * state.pageSize, pageRows = state.view.slice(start, start + state.pageSize);
        var onPage = pageRows.filter(function (r) { return state.sel[r.RootOrMatchingDomain]; }).length;
        var h = document.getElementById("bulkSelectAll");
        if (h) { h.checked = pageRows.length > 0 && onPage === pageRows.length; h.indeterminate = onPage > 0 && onPage < pageRows.length; }
        // offer to extend the selection to every match when the filter spans more than this page
        var matching = state.view.length, allSel = state.view.filter(function (r) { return state.sel[r.RootOrMatchingDomain]; }).length;
        var offer = pageRows.length > 0 && onPage === pageRows.length && matching > pageRows.length && allSel < matching;
        $("#bulkSelectMatching").toggle(offer).find("a").text("Select all " + matching + " matching rules");
        $("#bulkBar .bulkAllSel").toggle(allSel === matching && matching > pageRows.length && n > 0);
    }

    function render() {
        applyFilter();
        renderTools();
        renderHeader();
        renderRows();
        renderPager();
        renderBulk();
    }

    /* ------------------------------------------------------------------ data */
    function loadHealth() {
        $.get("/api/utm/list", function (data) {
            var h = {};
            if (data && typeof data === "object" && !data.error) {
                Object.keys(data).forEach(function (id) {
                    // newest result per probed URL; stale URLs of upstreams that were since changed are ignored below
                    var last = {};
                    (data[id] || []).forEach(function (rec) {
                        var u = String(rec.URL || "").replace(/^[a-z]+:\/\//i, "").replace(/\/$/, "");
                        if (!last[u] || rec.Timestamp >= last[u].Timestamp) { last[u] = rec; }
                    });
                    h[id] = last;
                });
            }
            state.healthRaw = h;
            if (state.loaded) { render(); }
        });
    }
    // "up" / "down" for a rule from the uptime monitor results of its current active upstreams, "" when unknown
    function healthOf(r) {
        var recs = state.healthRaw && state.healthRaw[r.RootOrMatchingDomain];
        if (!recs) { return ""; }
        var seen = 0, up = 0;
        (r.ActiveOrigins || []).forEach(function (o) {
            // the probed URL carries the health-check path (host:port/healthz), and results recorded before the
            // path was changed stay in the log under the old URL: take the newest result of any URL of this upstream
            var origin = String(o.OriginIpOrDomain).replace(/\/$/, ""), rec = null;
            Object.keys(recs).forEach(function (u) {
                if (u !== origin && u.indexOf(origin + "/") !== 0) { return; }
                if (!rec || recs[u].Timestamp >= rec.Timestamp) { rec = recs[u]; }
            });
            if (rec) { seen++; if (rec.Online) { up++; } }
        });
        return seen === 0 ? "" : (up > 0 ? "up" : "down");
    }
    function loadWaf() {
        $.getJSON("/api/waf/policy", function (p) {
            if (p && !p.error) { state.waf = p; if (state.loaded) { render(); } }
        });
    }
    function loadAccess() {
        $.get("/api/access/list", function (data) {
            if (data && !data.error && data.forEach) {
                var m = {};
                data.forEach(function (a) { m[a.ID] = a; });
                state.access = m;
                if (state.loaded) { render(); }
            }
        });
    }

    function reload(preserveFilters) {
        if (preserveFilters === false) { state.tags = []; state.status = "all"; state.q = ""; $("#searchInput").val(""); }
        return $.get("/api/proxy/list?type=host", function (data) {
            if (data && data.error !== undefined) {
                $("#httpProxyList").html('<tr><td colspan="7"><div class="ptEmpty"><i class="red remove icon"></i><h3>Could not load the proxy rules</h3><p>' + esc(data.error) + '</p></div></td></tr>');
                return;
            }
            state.list = data || [];
            state.list.forEach(prepare);
            window.httpProxyList = state.list;
            Object.keys(state.sel).forEach(function (k) { if (!byName(k)) { delete state.sel[k]; } });
            state.loaded = true;
            render();
            loadHealth();
            loadAccess(); loadWaf();
        });
    }

    /* ------------------------------------------------------------------ actions */
    function toast(msg, actionLabel, fn) {
        var $t = $("#ptToast");
        if (!$t.length) {
            $t = $('<div id="ptToast" role="status" aria-live="polite"><span class="ptToastMsg"></span><button type="button" class="ptToastAct"></button></div>').appendTo("body");
        }
        clearTimeout($t.data("timer"));
        $t.find(".ptToastMsg").text(msg);
        var $b = $t.find(".ptToastAct").off("click").toggle(!!actionLabel).text(actionLabel || "");
        if (fn) { $b.on("click", function () { $t.removeClass("show"); fn(); }); }
        $t.addClass("show").data("timer", setTimeout(function () { $t.removeClass("show"); }, 7000));
    }

    function setEnabled(name, enable, undoable) {
        var r = byName(name);
        if (!r) { return; }
        var was = !r.Disabled;
        r.Disabled = !enable;
        render();
        $.cjax({
            url: "/api/proxy/toggle", data: { ep: name, enable: enable },
            success: function (data) {
                if (data && data.error !== undefined) {
                    r.Disabled = !was; render(); msgbox(data.error, false);
                    return;
                }
                if (typeof reloadUptimeList === "function") { try { reloadUptimeList(); } catch (e) { } }
                if (undoable) { toast(name + (enable ? " enabled" : " disabled"), "Undo", function () { setEnabled(name, was, false); }); }
                else { toast(name + (enable ? " enabled" : " disabled")); }
            },
            error: function () { r.Disabled = !was; render(); }
        });
    }

    function openEditor(name) {
        var r = byName(name);
        if (!r) { return; }
        var copy = JSON.parse(JSON.stringify(r));
        Object.keys(copy).forEach(function (k) { if (k.charAt(0) === "_") { delete copy[k]; } });
        initHttpProxyRuleEditorModal(copy);
    }

    function deleteRule(name) {
        window.confirmBox("Remove the proxy rule for " + name + "?", function (choice) {
            if (choice !== true) { return; }
            $.cjax({
                url: "/api/proxy/del", method: "POST", data: { ep: name },
                success: function (data) {
                    if (data && data.error !== undefined) { msgbox(data.error, false); return; }
                    delete state.sel[name];
                    reload();
                    msgbox("Proxy rule deleted", true);
                    if (typeof reloadUptimeList === "function") { try { reloadUptimeList(); } catch (e) { } }
                }
            });
        });
    }

    function setSelected(name, on) { if (on) { state.sel[name] = true; } else { delete state.sel[name]; } }

    function toggleRange(name, on) {
        // shift-click: every rule between the previous click and this one, in the order shown
        var a = state.view.findIndex(function (r) { return r.RootOrMatchingDomain === state.lastClicked; });
        var b = state.view.findIndex(function (r) { return r.RootOrMatchingDomain === name; });
        if (a < 0 || b < 0) { setSelected(name, on); return; }
        var lo = Math.min(a, b), hi = Math.max(a, b);
        for (var i = lo; i <= hi; i++) { setSelected(state.view[i].RootOrMatchingDomain, on); }
    }

    function syncChecks() {
        $("#httpProxyList tr.ptRow").each(function () {
            var name = $(this).attr("data-ep"), on = !!state.sel[name];
            $(this).toggleClass("isSel", on).find(".bulkSel").prop("checked", on);
        });
        renderBulk();
    }

    function clearSelection() { state.sel = {}; state.lastClicked = null; syncChecks(); }

    function highlight(name) {
        var r = byName(name);
        if (!r) { return; }
        // make sure the row is not hidden by a filter, then find its page
        if (state.view.indexOf(r) < 0) { state.q = ""; state.tags = []; state.status = "all"; $("#searchInput").val(""); applyFilter(); }
        var idx = state.view.indexOf(r);
        if (idx < 0) { return; }
        state.page = Math.floor(idx / state.pageSize) + 1;
        render();
        state.flash = name;
        render();
        var row = $("#httpProxyList tr.ptRow").filter(function () { return $(this).attr("data-ep") === name; });
        if (row.length) { row[0].scrollIntoView({ block: "center", behavior: "smooth" }); }
        clearTimeout(highlight.t);
        highlight.t = setTimeout(function () { state.flash = ""; $("#httpProxyList tr.ptFlash").removeClass("ptFlash"); }, 3500);
    }

    /* ------------------------------------------------------------------ events */
    function bind() {
        var $body = $("#httpProxyList");

        $body.on("click", ".bulkSel", function (ev) {
            var name = $(this).attr("data-ep"), on = this.checked;
            if (ev.shiftKey && state.lastClicked) { toggleRange(name, on); } else { setSelected(name, on); }
            state.lastClicked = name;
            syncChecks();
        });
        $body.on("click", "[data-act]", function (ev) {
            var act = $(this).attr("data-act"), name = $(this).closest("tr").attr("data-ep");
            if (act === "clearfilters") { clearFilters(); return; }
            if (act === "toggle") { var r = byName(name); if (r) { setEnabled(name, !!r.Disabled, true); } }
            else if (act === "edit") { openEditor(name); }
            else if (act === "delete") { deleteRule(name); }
        });
        $body.on("click", ".ptTag, .ptChip", function (ev) { ev.preventDefault(); toggleTag($(this).attr("data-tag")); });
        $body.on("click", ".ptVdir", function (ev) { ev.preventDefault(); quickEditVdir($(this).attr("data-ep")); });
        $body.on("click", ".ptMoreUp", function (ev) { ev.preventDefault(); openEditor($(this).attr("data-ep")); });

        $page().on("click", "#ptTagChips .ptChip", function () { toggleTag($(this).attr("data-tag")); });
        $page().on("change", "#ptMoreTags", function () { if (this.value) { toggleTag(this.value); } });
        $page().on("click", "#ptSeg button", function () { state.status = $(this).attr("data-f"); state.page = 1; render(); });
        $page().on("click", "#ptClear", clearFilters);
        $page().on("click", "#httpProxyTable thead th[data-sort]", function () {
            var k = $(this).attr("data-sort");
            if (state.sort.key === k) { state.sort.dir = -state.sort.dir; } else { state.sort = { key: k, dir: 1 }; }
            persist(); render();
        });
        $page().on("keydown", "#httpProxyTable thead th[data-sort]", function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); $(this).click(); } });
        $page().on("input search", "#searchInput", function () {
            state.q = this.value; state.page = 1;
            clearTimeout(bind.t); bind.t = setTimeout(render, 120);
        });
        $page().on("keydown", "#searchInput", function (ev) { if (ev.key === "Escape" && this.value) { this.value = ""; state.q = ""; render(); ev.stopPropagation(); } });
        $page().on("click", "#ptPrev", function () { state.page--; render(); window.scrollTo(0, 0); });
        $page().on("click", "#ptNext", function () { state.page++; render(); window.scrollTo(0, 0); });
        $page().on("change", "#ptPageSize", function () { state.pageSize = parseInt(this.value, 10) || 50; state.page = 1; persist(); render(); });
        $page().on("click", "#ptRefresh", function () { reload(); });

        $page().on("change", "#bulkSelectAll", function () {
            var on = this.checked, start = (state.page - 1) * state.pageSize;
            state.view.slice(start, start + state.pageSize).forEach(function (r) { setSelected(r.RootOrMatchingDomain, on); });
            syncChecks();
        });
        $page().on("click", "#bulkSelectMatching a", function (ev) {
            ev.preventDefault();
            state.view.forEach(function (r) { state.sel[r.RootOrMatchingDomain] = true; });
            syncChecks();
        });
        $page().on("click", "#bulkBar button", function () {
            var act = $(this).attr("data-act");
            if (act === "clear") { clearSelection(); return; }
            if (window.ProxyBulk) { window.ProxyBulk.run(act, selNames()); }
        });

        // Esc clears the selection (unless a dialog or the search box wants the key)
        $(document).on("keydown.ptSel", function (ev) {
            if (ev.key !== "Escape" || !selNames().length) { return; }
            if (!$("#httprp").is(":visible")) { return; }
            if ($(".ui.modal.visible, .ui.modal.active").length || $("#httprpEditModalWrapper").is(":visible") || $("#newRuleModal.active").length) { return; }
            var t = ev.target;
            if (t && /^(input|textarea|select)$/i.test(t.tagName) && t.type !== "checkbox") { return; }
            clearSelection();
        });
        // "n" opens the new rule dialog when nothing else wants the key
        $(document).on("keydown.ptNew", function (ev) {
            if (ev.key !== "n" || ev.ctrlKey || ev.metaKey || ev.altKey || !$("#httprp").is(":visible")) { return; }
            var t = ev.target;
            if (t && (/^(input|textarea|select)$/i.test(t.tagName) || t.isContentEditable)) { return; }
            if ($(".ui.modal.visible, .ui.modal.active").length || $("#httprpEditModalWrapper").is(":visible")) { return; }
            ev.preventDefault();
            if (typeof openNewRuleDialog === "function") { openNewRuleDialog(); }
        });
    }

    function toggleTag(t) {
        var i = state.tags.indexOf(t);
        if (i > -1) { state.tags.splice(i, 1); } else { state.tags.push(t); }
        state.page = 1; render();
    }
    function clearFilters() {
        state.q = ""; state.tags = []; state.status = "all"; state.page = 1;
        $("#searchInput").val(""); render();
    }

    /* ------------------------------------------------------------------ compatibility API (called by snippets) */
    window.listProxyEndpoints = function (preserveFilters) { return reload(preserveFilters !== false ? true : false); };
    window.filterProxyList = function () { state.q = $("#searchInput").val() || ""; state.page = 1; render(); };
    window.editEndpoint = function (hex) { openEditor(hex.hexDecode()); };
    window.deleteEndpoint = function (hex) { deleteRule(decodeURIComponent(hex).hexDecode()); };
    window.renderTagsPreview = function (endpoint, tags) {
        var r = byName(endpoint);
        if (r) { r.Tags = tags || []; prepare(r); render(); }
    };
    window.updateAccessRuleNameUnderHost = function (epuuid, newruleUID) {
        var r = byName(epuuid);
        if (r) { r.AccessFilterUUID = newruleUID; }
        loadAccess(); loadWaf(); render();
    };
    window.updateAliasListForEndpoint = function (endpointName, aliases) {
        var r = byName(endpointName);
        if (r) { r.MatchingDomainAlias = aliases || []; prepare(r); render(); }
    };
    window.ProxyTable = { reload: reload, highlight: highlight, clearSelection: clearSelection, selected: selNames, state: state };

    $(function () {
        if (!document.getElementById("httpProxyList")) { return; }
        bind();
    });
})();
