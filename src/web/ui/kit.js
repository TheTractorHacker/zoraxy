/* Living documentation of the component kit: renders every example in a light and a dark pane, with copyable markup. */
(function () {
    "use strict";
    var $ = window.jQuery;
    var main = document.getElementById("kitSections");
    var toc = document.getElementById("kitToc");

    document.getElementById("kitTheme").addEventListener("click", function () {
        window.setDarkTheme(!document.body.classList.contains("darkTheme"));
    });

    /* ------------------------------------------------------------- tokens */
    var COLOR_TOKENS = [
        ["Surfaces", ["--zx-bg", "--zx-surface", "--zx-surface-2", "--zx-surface-3"]],
        ["Lines", ["--zx-border", "--zx-border-strong"]],
        ["Text", ["--zx-text", "--zx-text-muted", "--zx-text-faint", "--zx-link"]],
        ["Primary", ["--zx-primary", "--zx-primary-hover", "--zx-on-primary", "--zx-primary-soft", "--zx-primary-soft-text"]],
        ["OK", ["--zx-ok-solid", "--zx-ok-bg", "--zx-ok-text", "--zx-ok-line"]],
        ["Warning", ["--zx-warn-solid", "--zx-warn-bg", "--zx-warn-text", "--zx-warn-line"]],
        ["Danger", ["--zx-danger-solid", "--zx-danger-bg", "--zx-danger-text", "--zx-danger-line"]],
        ["Info", ["--zx-info-solid", "--zx-info-bg", "--zx-info-text", "--zx-info-line"]],
        ["Neutral", ["--zx-neutral-bg", "--zx-neutral-text", "--zx-neutral-line"]]
    ];
    // [foreground token, background token, minimum ratio, what]
    var CONTRAST = [
        ["--zx-text", "--zx-surface", 4.5, "Body text on a card"],
        ["--zx-text", "--zx-bg", 4.5, "Body text on the page"],
        ["--zx-text-muted", "--zx-surface", 4.5, "Help text on a card"],
        ["--zx-text-muted", "--zx-surface-2", 4.5, "Muted text on a sunken area"],
        ["--zx-text-faint", "--zx-surface", 4.5, "Placeholders"],
        ["--zx-link", "--zx-surface", 4.5, "Links"],
        ["--zx-on-primary", "--zx-primary", 4.5, "Primary button label"],
        ["--zx-primary-soft-text", "--zx-primary-soft", 4.5, "Selected tab / row"],
        ["--zx-on-solid", "--zx-danger-solid", 4.5, "Danger button label"],
        ["--zx-ok-text", "--zx-ok-bg", 4.5, "OK badge / callout"],
        ["--zx-warn-text", "--zx-warn-bg", 4.5, "Warning badge / callout"],
        ["--zx-danger-text", "--zx-danger-bg", 4.5, "Danger badge / callout"],
        ["--zx-info-text", "--zx-info-bg", 4.5, "Info badge / callout"],
        ["--zx-neutral-text", "--zx-neutral-bg", 4.5, "Neutral badge"],
        ["--zx-danger-text", "--zx-surface", 4.5, "Error text under a field"],
        ["--zx-border-strong", "--zx-surface", 3, "Control borders (non-text)"],
        ["--zx-focus", "--zx-surface", 3, "Focus ring (non-text)"]
    ];

    function probe(scheme) {
        var d = document.createElement("div");
        d.className = "zx-scheme-" + scheme;
        d.style.display = "none";
        document.body.appendChild(d);
        var cs = getComputedStyle(d);
        var get = function (n) { return cs.getPropertyValue(n).trim(); };
        return { get: get, done: function () { d.remove(); } };
    }
    function rgb(c) {
        var cv = document.createElement("canvas"); cv.width = cv.height = 1;
        var x = cv.getContext("2d"); x.fillStyle = "#000"; x.fillStyle = c; x.fillRect(0, 0, 1, 1);
        var p = x.getImageData(0, 0, 1, 1).data; return [p[0], p[1], p[2]];
    }
    function lum(c) {
        var v = rgb(c).map(function (n) { n /= 255; return n <= 0.03928 ? n / 12.92 : Math.pow((n + 0.055) / 1.055, 2.4); });
        return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2];
    }
    function ratio(a, b) { var l1 = lum(a), l2 = lum(b); return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05); }

    function tokensSection() {
        var L = probe("light"), D = probe("dark");
        var html = "<h2 id=\"tokens\">Design tokens</h2><p class=\"kit-desc\">All colours come from <code>--zx-*</code> custom properties. Light values live on <code>:root</code>, dark values on <code>body.darkTheme</code> (the class the theme toggle sets). Use the token, never the hex value. Legacy variables (<code>--theme_bg</code>, <code>--text_color</code>, ...) still work.</p>";
        html += "<div class=\"kit-tblwrap\"><table class=\"kit-tbl\"><thead><tr><th>Token</th><th>Light</th><th>Dark</th></tr></thead><tbody>";
        COLOR_TOKENS.forEach(function (g) {
            html += "<tr><th colspan=\"3\">" + g[0] + "</th></tr>";
            g[1].forEach(function (t) {
                html += "<tr><td><code>" + t + "</code></td><td><span class=\"kit-sw\" style=\"background:" + L.get(t) + "\"></span> <code>" + L.get(t) + "</code></td><td><span class=\"kit-sw\" style=\"background:" + D.get(t) + "\"></span> <code>" + D.get(t) + "</code></td></tr>";
            });
        });
        html += "</tbody></table></div>";
        html += "<h3 style=\"margin-top:24px\">Contrast (WCAG 2.1)</h3><p class=\"kit-desc\">Text pairs need 4.5:1, borders of controls and the focus ring 3:1. Computed live from the tokens above.</p>";
        html += "<div class=\"kit-tblwrap\"><table class=\"kit-tbl\"><thead><tr><th>Pair</th><th>Used for</th><th>Light</th><th>Dark</th></tr></thead><tbody>";
        CONTRAST.forEach(function (c) {
            var cells = [L, D].map(function (S) {
                var r = ratio(S.get(c[0]), S.get(c[1]));
                return "<td class=\"" + (r >= c[2] ? "kit-pass" : "kit-fail") + "\">" + r.toFixed(2) + ":1 " + (r >= c[2] ? "pass" : "FAIL (min " + c[2] + ")") + "</td>";
            }).join("");
            html += "<tr><td><code>" + c[0] + "</code> on <code>" + c[1] + "</code></td><td>" + c[3] + "</td>" + cells + "</tr>";
        });
        html += "</tbody></table></div>";
        html += "<h3 style=\"margin-top:24px\">Spacing, radius, type, shadow</h3><div class=\"kit-tblwrap\"><table class=\"kit-tbl\"><tbody>";
        [["--zx-space-1", "4px"], ["--zx-space-2", "8px"], ["--zx-space-3", "12px"], ["--zx-space-4", "16px"], ["--zx-space-5", "24px"], ["--zx-space-6", "32px"], ["--zx-space-7", "48px"]].forEach(function (s) {
            html += "<tr><td><code>" + s[0] + "</code></td><td>" + s[1] + "</td><td><span class=\"kit-spacing\" style=\"width:var(" + s[0] + ")\"></span></td></tr>";
        });
        [["--zx-radius-sm", "4px"], ["--zx-radius-md", "8px"], ["--zx-radius-lg", "12px"], ["--zx-radius-pill", "999px"]].forEach(function (s) {
            html += "<tr><td><code>" + s[0] + "</code></td><td>" + s[1] + "</td><td><span class=\"kit-sw\" style=\"width:60px;height:28px;border-radius:var(" + s[0] + ")\"></span></td></tr>";
        });
        [["--zx-fs-xs", "12px"], ["--zx-fs-sm", "13px"], ["--zx-fs-md", "14px body"], ["--zx-fs-lg", "16px"], ["--zx-fs-xl", "20px"], ["--zx-fs-2xl", "26px"]].forEach(function (s) {
            html += "<tr><td><code>" + s[0] + "</code></td><td>" + s[1] + "</td><td style=\"font-size:var(" + s[0] + ")\">The quick brown fox</td></tr>";
        });
        [["--zx-shadow-1", "cards"], ["--zx-shadow-2", "popovers, toasts"], ["--zx-shadow-3", "dialogs, save bar"]].forEach(function (s) {
            html += "<tr><td><code>" + s[0] + "</code></td><td>" + s[1] + "</td><td><span class=\"kit-sw\" style=\"width:60px;height:28px;background:var(--zx-surface);box-shadow:var(" + s[0] + ")\"></span></td></tr>";
        });
        html += "<tr><td><code>--zx-focus-ring</code></td><td>focus indicator (two-tone)</td><td><button class=\"zx-btn zx-btn--secondary\" style=\"box-shadow:var(--zx-focus-ring)\">Focused</button></td></tr>";
        html += "</tbody></table></div>";
        L.done(); D.done();
        return html;
    }

    /* ------------------------------------------------------------- examples */
    var EX = [];
    function ex(id, title, desc, markup, demo) { EX.push({ id: id, title: title, desc: desc, markup: markup.replace(/^\n/, ""), demo: demo }); }

    ex("page-header", "Page header", "Title, subtitle, breadcrumbs (filled automatically from the menu definition when the element carries data-zx-crumbs) and primary actions. Use one per page; the page title is the only h2.",
`<header class="zx-page-header">
  <div class="zx-page-header__main">
    <div class="zx-page-header__crumbs" data-zx-crumbs></div>
    <h2 class="zx-page-header__title">HTTP Proxy</h2>
    <p class="zx-page-header__sub">Hosts Zoraxy forwards to an upstream.</p>
  </div>
  <div class="zx-page-header__actions">
    <button type="button" class="zx-btn zx-btn--secondary">Import</button>
    <button type="button" class="zx-btn zx-btn--primary"><i class="plus icon"></i> New proxy rule</button>
  </div>
</header>`, function (pane) {
        // the demo has no menu: show what the crumbs look like
        $(pane).find("[data-zx-crumbs]").addClass("zx-crumbs").html("<ol><li><span class=\"zx-crumb\">Sites</span></li><li><span class=\"zx-crumb\" aria-current=\"page\">HTTP Proxy</span></li></ol>");
    });

    ex("card", "Section card", "Groups related fields. Title and description answer 'what is this section for'. Footer holds section-level actions. Variants: .zx-card--flat, .zx-card--danger.",
`<section class="zx-card" aria-labelledby="c1">
  <div class="zx-card__head"><h3 class="zx-card__title" id="c1">Timeouts</h3><span class="zx-badge zx-badge--ok zx-badge--dot">Active</span></div>
  <p class="zx-card__desc">In seconds, 0 disables a timeout.</p>
  <div class="zx-card__body">Card content goes here.</div>
  <div class="zx-card__foot"><button type="button" class="zx-btn zx-btn--secondary zx-btn--sm">Reset to defaults</button></div>
</section>
<section class="zx-card zx-card--danger" aria-labelledby="c2">
  <div class="zx-card__head"><h3 class="zx-card__title" id="c2">Danger zone</h3></div>
  <div class="zx-card__body">Deleting a rule cannot be undone.</div>
</section>`);

    ex("form-row", "Form row", "Label, control, help text, error text and an optional 'what is this?' popover. The label is always a real &lt;label for&gt;. Errors: ZxUI.field(el).setError('text') sets aria-invalid and links the message.",
`<div class="zx-field">
  <div class="zx-field__label-row">
    <label class="zx-field__label" for="f-port">Listening port</label>
    <button type="button" class="zx-whatis" aria-expanded="false" aria-controls="f-port-what" aria-label="What is this?">?</button>
  </div>
  <div class="zx-popover" id="f-port-what" role="note" hidden>The TCP port Zoraxy accepts visitors on. HTTPS normally uses 443.</div>
  <div class="zx-field__control"><input class="zx-input zx-input--short" id="f-port" value="443" inputmode="numeric"></div>
  <p class="zx-help">1 to 65535.</p>
  <p class="zx-error" id="f-port-err">Enter a port between 1 and 65535.</p>
</div>
<div class="zx-field is-invalid">
  <div class="zx-field__label-row"><label class="zx-field__label" for="f-host">Host name</label></div>
  <div class="zx-field__control"><input class="zx-input" id="f-host" value="not a host" aria-invalid="true" aria-describedby="f-host-err"></div>
  <p class="zx-error" id="f-host-err">This is not a valid host name.</p>
</div>`, function (pane) {
    });

    ex("toggle-row", "Toggle row", "A switch with a title and a plain-language description; the whole row is the click target. Use for settings that are on or off. Say in the description what happens when it is on.",
`<div>
  <label class="zx-toggle-row"><span class="zx-toggle-row__text"><span class="zx-toggle-row__title">HTTP/3 (QUIC)</span><span class="zx-toggle-row__desc">Serve HTTP/3 over UDP on the same port.</span></span><input type="checkbox" class="zx-switch" role="switch" checked></label>
  <label class="zx-toggle-row"><span class="zx-toggle-row__text"><span class="zx-toggle-row__title">PROXY protocol</span><span class="zx-toggle-row__desc">Accept PROXY protocol v1/v2 headers on the TLS listener.</span></span><input type="checkbox" class="zx-switch" role="switch"></label>
</div>`);

    ex("buttons", "Buttons", "Primary: the one main action of a view. Secondary: other actions. Danger: destructive and irreversible. Ghost: low emphasis, toolbars. Icon: needs aria-label. Loading: ZxUI.setLoading(btn, true).",
`<div class="zx-row">
  <button type="button" class="zx-btn zx-btn--primary">Primary</button>
  <button type="button" class="zx-btn zx-btn--secondary">Secondary</button>
  <button type="button" class="zx-btn zx-btn--danger">Delete</button>
  <button type="button" class="zx-btn zx-btn--danger-outline">Remove</button>
  <button type="button" class="zx-btn zx-btn--ghost">Ghost</button>
  <button type="button" class="zx-btn zx-btn--secondary zx-btn--icon" aria-label="Refresh"><i class="sync icon"></i></button>
  <button type="button" class="zx-btn zx-btn--primary" disabled>Disabled</button>
  <button type="button" class="zx-btn zx-btn--primary is-loading" aria-busy="true">Saving</button>
  <button type="button" class="zx-btn zx-btn--secondary zx-btn--sm">Small</button>
</div>`);

    ex("badges", "Badge / status pill", "State is never shown by colour alone: always include text (and optionally the dot or an icon).",
`<div class="zx-row">
  <span class="zx-badge zx-badge--ok zx-badge--dot">Healthy</span>
  <span class="zx-badge zx-badge--warn zx-badge--dot">Expires in 6 days</span>
  <span class="zx-badge zx-badge--danger zx-badge--dot">Down</span>
  <span class="zx-badge zx-badge--info">Detection only</span>
  <span class="zx-badge">Disabled</span>
  <span class="zx-badge zx-badge--ok"><i class="check icon"></i> Protected</span>
</div>`);

    ex("callout", "Callout", "Info: explains. Warning: something needs attention but nothing is broken. Danger: something is broken or risky. Success: confirms. role='note' for static text; use role='alert' only for messages that appear after an action.",
`<div class="zx-callout zx-callout--info" role="note"><span class="zx-callout__icon" aria-hidden="true"><i class="info circle icon"></i></span><div class="zx-callout__body"><span class="zx-callout__title">Detection only</span>Matching requests are logged, not blocked.</div></div>
<div class="zx-callout zx-callout--warn" role="note"><span class="zx-callout__icon" aria-hidden="true"><i class="exclamation triangle icon"></i></span><div class="zx-callout__body"><span class="zx-callout__title">Port 80 is in use</span>Another service answers on port 80.</div></div>
<div class="zx-callout zx-callout--danger" role="alert"><span class="zx-callout__icon" aria-hidden="true"><i class="times circle icon"></i></span><div class="zx-callout__body"><span class="zx-callout__title">Certificate expired</span>Visitors see a browser warning for example.com.</div></div>
<div class="zx-callout zx-callout--success" role="status"><span class="zx-callout__icon" aria-hidden="true"><i class="check circle icon"></i></span><div class="zx-callout__body"><span class="zx-callout__title">Saved</span>The listener restarted without errors.</div></div>`);

    ex("empty", "Empty state", "Every empty list says what it is for and offers the next action.",
`<div class="zx-empty">
  <div class="zx-empty__icon" aria-hidden="true"><i class="sitemap icon"></i></div>
  <h3 class="zx-empty__title">No proxy rules yet</h3>
  <p class="zx-empty__text">A proxy rule sends traffic for a host name to an upstream server.</p>
  <button type="button" class="zx-btn zx-btn--primary"><i class="plus icon"></i> New proxy rule</button>
</div>`);

    ex("table", "Data table", "Sticky header inside a scrolling region (give the wrapper a label and tabindex=0 so it scrolls with the keyboard), density modifiers .zx-table--compact / --comfortable, row actions, numbers right aligned. Below 480px every row becomes a card using the data-label of each cell.",
`<div class="zx-table-wrap" style="--zx-table-max: 14rem" tabindex="0" role="region" aria-label="Proxy rules">
  <table class="zx-table zx-table--compact">
    <thead><tr><th scope="col">Host</th><th scope="col">Upstream</th><th scope="col">Status</th><th scope="col" class="zx-num">Requests</th><th scope="col" class="zx-actions"><span class="zx-sr-only">Actions</span></th></tr></thead>
    <tbody>
      <tr><td data-label="Host">app.example.com</td><td data-label="Upstream">127.0.0.1:8080</td><td data-label="Status"><span class="zx-badge zx-badge--ok zx-badge--dot">Healthy</span></td><td data-label="Requests" class="zx-num">12,408</td><td class="zx-actions"><span class="zx-row-actions"><button type="button" class="zx-btn zx-btn--ghost zx-btn--icon zx-btn--sm" aria-label="Edit app.example.com"><i class="pencil icon"></i></button><button type="button" class="zx-btn zx-btn--ghost zx-btn--icon zx-btn--sm" aria-label="Delete app.example.com"><i class="trash icon"></i></button></span></td></tr>
      <tr class="is-selected"><td data-label="Host">git.example.com</td><td data-label="Upstream">10.0.0.5:3000</td><td data-label="Status"><span class="zx-badge zx-badge--warn zx-badge--dot">Slow</span></td><td data-label="Requests" class="zx-num">932</td><td class="zx-actions"><span class="zx-row-actions"><button type="button" class="zx-btn zx-btn--ghost zx-btn--icon zx-btn--sm" aria-label="Edit git.example.com"><i class="pencil icon"></i></button></span></td></tr>
      <tr><td data-label="Host">old.example.com</td><td data-label="Upstream">10.0.0.9:80</td><td data-label="Status"><span class="zx-badge">Disabled</span></td><td data-label="Requests" class="zx-num">0</td><td class="zx-actions"></td></tr>
      <tr><td data-label="Host">wiki.example.com</td><td data-label="Upstream">10.0.0.7:8081</td><td data-label="Status"><span class="zx-badge zx-badge--danger zx-badge--dot">Down</span></td><td data-label="Requests" class="zx-num">57</td><td class="zx-actions"></td></tr>
    </tbody>
  </table>
</div>`);

    ex("tabs", "Tabs and segmented control", "Tabs switch panels of one page (ZxUI.tabs: arrow keys, Home/End, aria-selected). A segmented control chooses one of a few values (ZxUI.segmented, role=radiogroup).",
`<div class="zx-tabs" id="demo-tabs">
  <button type="button" class="zx-tab" aria-selected="true" data-zx-panel="demo-p1">Overview</button>
  <button type="button" class="zx-tab" data-zx-panel="demo-p2">Events</button>
  <button type="button" class="zx-tab" data-zx-panel="demo-p3">Policy</button>
</div>
<div id="demo-p1" class="zx-tabpanel">Overview panel</div>
<div id="demo-p2" class="zx-tabpanel" hidden>Events panel</div>
<div id="demo-p3" class="zx-tabpanel" hidden>Policy panel</div>
<div class="zx-segmented" id="demo-seg" aria-label="Mode" style="margin-top:12px">
  <button type="button" class="zx-segmented__item" data-value="off">Off</button>
  <button type="button" class="zx-segmented__item" data-value="detect" aria-checked="true">Detect</button>
  <button type="button" class="zx-segmented__item" data-value="block">Block</button>
</div>`, function (pane) {
        ZxUI.tabs($(pane).find(".zx-tabs")[0]);
        ZxUI.segmented($(pane).find(".zx-segmented")[0]);
    });

    ex("stat", "Stat tile", "A single number with a label and a hint. Tone modifiers .zx-stat--ok / --warn / --danger colour only the value text.",
`<div class="zx-grid">
  <div class="zx-stat"><span class="zx-stat__label">Requests today</span><span class="zx-stat__value">24,310</span><span class="zx-stat__hint">+12% vs yesterday</span></div>
  <div class="zx-stat zx-stat--warn"><span class="zx-stat__label">Certificates expiring</span><span class="zx-stat__value">2</span><span class="zx-stat__hint">within 14 days</span></div>
  <div class="zx-stat zx-stat--danger"><span class="zx-stat__label">Blocked</span><span class="zx-stat__value">318</span><span class="zx-stat__hint">last 24 hours</span></div>
</div>`);

    ex("savebar", "Save bar", "One Save for a form. Appears when the form is dirty (counts and names what changed), Save is disabled while saving, shows success or the error. Programmatic changes never make the form dirty. Ctrl/Cmd+S saves. Registers with ZxUI.unsaved so leaving the page asks first. Try changing a field below.",
`<form id="demo-form" onsubmit="return false">
  <div class="zx-field"><div class="zx-field__label-row"><label class="zx-field__label" for="sb-name">Display name</label></div><input class="zx-input" id="sb-name" value="Edge proxy"></div>
  <div class="zx-field"><div class="zx-field__label-row"><label class="zx-field__label" for="sb-port">Port</label></div><input class="zx-input zx-input--short" id="sb-port" value="443"></div>
  <label class="zx-toggle-row"><span class="zx-toggle-row__text"><span class="zx-toggle-row__title">Redirect HTTP to HTTPS</span></span><input type="checkbox" class="zx-switch" id="sb-redir" role="switch"></label>
</form>
<script>
var bar = ZxUI.saveBar({
  form: '#demo-form',
  onSave: function (ctx) {
    // return a promise (or a jqXHR from $.cjax). A rejection or {error: "..."} shows the failure.
    return new Promise(function (ok, fail) { setTimeout(function () { ctx.changes.some(function (c) { return c.to === '0'; }) ? fail('Port 0 is not allowed') : ok(); }, 700); });
  }
});
// after loading values from the API:  bar.reset();
</script>`, function (pane) {
        var s = pane.dataset.scheme;
        var form = $(pane).find("form")[0];
        ZxUI.saveBar({
            form: form, mount: pane, id: "kit-" + s,
            onSave: function (ctx) {
                return new Promise(function (ok, fail) {
                    setTimeout(function () {
                        var bad = ctx.changes.some(function (c) { return c.to === "0"; });
                        bad ? fail("Port 0 is not allowed") : ok();
                    }, 700);
                });
            }
        });
        $(pane).append("<p class=\"zx-help\">Demo: saving takes 0.7 s; set the port to 0 to see a failure.</p>");
    });

    ex("toast", "Toast", "Non-blocking notification. Messages are inserted as text. Pass undo to offer a one-click undo (wired by the caller). errors use role=alert and stay longer.",
`<div class="zx-row">
  <button type="button" class="zx-btn zx-btn--secondary" id="t-ok">Success toast</button>
  <button type="button" class="zx-btn zx-btn--secondary" id="t-err">Error toast</button>
  <button type="button" class="zx-btn zx-btn--secondary" id="t-undo">Toast with Undo</button>
</div>
<script>
ZxUI.toast('Rule saved', {type: 'success'});
ZxUI.toast('Rule deleted', {type: 'info', undo: function () { /* restore it */ }});
ZxUI.toast('Could not save: port in use', {type: 'error'});
</script>`, function (pane) {
        $(pane).find("[id^=t-ok]").on("click", function () { ZxUI.toast("Rule saved", { type: "success" }); });
        $(pane).find("[id^=t-err]").on("click", function () { ZxUI.toast("Could not save: port 443 is in use", { type: "error" }); });
        $(pane).find("[id^=t-undo]").on("click", function () { ZxUI.toast("Rule deleted", { undo: function () { ZxUI.toast("Rule restored", { type: "success" }); } }); });
    });

    ex("confirm", "Confirm dialog", "ZxUI.confirm returns a promise. Danger variant puts the focus on Cancel. The typed variant keeps the confirm button disabled until the exact text is typed: use it for irreversible actions on one named object.",
`<div class="zx-row">
  <button type="button" class="zx-btn zx-btn--secondary" id="c-plain">Confirm</button>
  <button type="button" class="zx-btn zx-btn--danger-outline" id="c-danger">Danger confirm</button>
  <button type="button" class="zx-btn zx-btn--danger-outline" id="c-typed">Typed confirmation</button>
</div>
<script>
ZxUI.confirm({title: 'Delete rule?', message: 'app.example.com stops working.', danger: true, confirmLabel: 'Delete rule', typed: 'app.example.com'})
  .then(function (ok) { if (ok) { /* delete */ } });
</script>`, function (pane) {
        $(pane).find("[id^=c-plain]").on("click", function () { ZxUI.confirm({ title: "Apply changes?", message: "The proxy restarts for about a second.", confirmLabel: "Apply" }).then(function (ok) { ZxUI.toast(ok ? "Confirmed" : "Cancelled"); }); });
        $(pane).find("[id^=c-danger]").on("click", function () { ZxUI.confirm({ title: "Remove all blocked IPs?", message: "Every temporary ban is lifted.", danger: true, confirmLabel: "Remove all" }).then(function (ok) { ZxUI.toast(ok ? "Removed" : "Cancelled"); }); });
        $(pane).find("[id^=c-typed]").on("click", function () { ZxUI.confirm({ title: "Delete rule?", message: "app.example.com stops working. This cannot be undone.", danger: true, confirmLabel: "Delete rule", typed: "app.example.com" }).then(function (ok) { ZxUI.toast(ok ? "Deleted (demo)" : "Cancelled"); }); });
    });

    ex("skeleton", "Skeleton / loading", "Use while a section loads, instead of a spinner on an empty page. ZxUI.skeleton(container, {lines, title, block}) returns a function that removes it. The group is aria-hidden and the container gets aria-busy.",
`<div class="zx-card" style="margin:0"><div class="zx-card__body" id="sk-box">
  <span class="zx-skeleton zx-skeleton--title"></span>
  <span class="zx-skeleton zx-skeleton--text"></span>
  <span class="zx-skeleton zx-skeleton--text"></span>
  <span class="zx-skeleton zx-skeleton--text"></span>
</div></div>`);

    /* ------------------------------------------------------------- render */
    function esc(s) { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
    function copy(text, btn) {
        var done = function () { var o = btn.textContent; btn.textContent = "Copied"; setTimeout(function () { btn.textContent = o; }, 1500); };
        if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text).then(done, done); return; }
        var ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select();
        try { document.execCommand("copy"); } catch (e) { /* ignore */ } ta.remove(); done();
    }

    var out = tokensSection();
    var tocHtml = "<a href=\"#intro\">Overview</a><a href=\"#tokens\">Design tokens</a>";
    EX.forEach(function (e) {
        tocHtml += "<a href=\"#ex-" + e.id + "\">" + e.title + "</a>";
        out += "<h2 id=\"ex-" + e.id + "\">" + e.title + "</h2><p class=\"kit-desc\">" + e.desc + "</p>" +
            "<div class=\"kit-pair\" data-ex=\"" + e.id + "\"><div class=\"kit-pane zx-scheme-light\" data-scheme=\"light\"><span class=\"kit-label\">Light</span><div class=\"kit-demo\"></div></div>" +
            "<div class=\"kit-pane zx-scheme-dark\" data-scheme=\"dark\"><span class=\"kit-label\">Dark</span><div class=\"kit-demo\"></div></div></div>" +
            "<details class=\"kit-code\"><summary>Markup <button type=\"button\" class=\"zx-btn zx-btn--secondary zx-btn--sm kit-copy\" data-copy=\"" + e.id + "\">Copy</button></summary><pre><code>" + esc(e.markup) + "</code></pre></details>";
    });
    main.innerHTML = out;
    toc.innerHTML = tocHtml;

    // every pane gets its own ids so the page has no duplicates
    function uniquify(root, suffix) {
        $(root).find("[id]").each(function () { this.id = this.id + "-" + suffix; });
        ["for", "aria-controls", "aria-describedby", "aria-labelledby", "data-zx-panel"].forEach(function (a) {
            $(root).find("[" + a + "]").each(function () {
                this.setAttribute(a, this.getAttribute(a).split(" ").map(function (v) { return v + "-" + suffix; }).join(" "));
            });
        });
    }
    EX.forEach(function (e) {
        // the <script> part of an example is shown in the markup only
        var previewMarkup = e.markup.replace(/<script>[\s\S]*?<\/script>/g, "");
        $(main).find("[data-ex='" + e.id + "'] .kit-pane").each(function () {
            var demo = this.querySelector(".kit-demo");
            demo.dataset.scheme = this.getAttribute("data-scheme");
            $(demo).html(previewMarkup);
            uniquify(demo, demo.dataset.scheme);
            if (e.demo) { e.demo(demo, this); }
        });
    });

    $(main).on("click", "[data-copy]", function (ev) {
        ev.preventDefault();
        var id = this.getAttribute("data-copy");
        var e = EX.filter(function (x) { return x.id === id; })[0];
        copy(e.markup, this);
    });
    // popovers in the panes work through the global handler of zxui.js

    var sk = document.getElementById("sk-box");
    if (sk) { /* the static skeleton markup is the example */ }
    window.__kitReady = true;
})();
