# Admin UI component kit and navigation

Phase 0 (component kit) and Phase 1 (navigation) of the redesign in [audit-2026-11.md](audit-2026-11.md).
The kit is plain CSS plus one small helper (`ZxUI`) on top of jQuery and Fomantic UI (decision D1: no framework, no build step).

| Part | File |
|---|---|
| Tokens and component CSS | `src/web/ui/zxui.css` |
| Helper library `window.ZxUI` (toast, confirm, save bar, dirty tracker, tabs, ...) | `src/web/script/zxui.js` |
| Menu definition (`NAV`), breadcrumbs, `window.ZxNav` | `src/web/script/nav.js` |
| Command palette `window.ZxPalette` (settings index, actions) | `src/web/script/palette.js` |
| Menu, breadcrumb and palette CSS | `src/web/ui/nav.css` |
| Living documentation: every component in light and dark with copyable markup | `src/web/ui/kit.html` (+ `kit.js`) |

**Living page.** Start Zoraxy with `-dev` and open `/ui/kit.html` (System > UI kit in the menu). Without `-dev` the page is not served (404) and the menu entry is hidden. The page also shows the live contrast ratios of the tokens.

**Used by:** the proxy rule editor ([site-editor.md](site-editor.md): five sections, Easy / Advanced, one Save bar, app presets).

Everything is namespaced `zx-` and additive: it never styles a bare element or a Fomantic `.ui` class, and the legacy CSS variables of `darktheme.css` (`--theme_bg`, `--text_color`, ...) keep working. Pages migrate one at a time.

## 1. Design tokens

Defined in `zxui.css`; light on `:root`, dark on `body.darkTheme` (the class the theme toggle sets). `.zx-scheme-light` / `.zx-scheme-dark` force a scheme for a subtree (the kit page uses them to show both side by side). Always use the token, never a hex value.

| Group | Tokens |
|---|---|
| Surfaces | `--zx-bg` (page), `--zx-surface` (cards, inputs), `--zx-surface-2` (sunken, table head, hover), `--zx-surface-3` (pressed, tracks), `--zx-overlay` |
| Lines | `--zx-border` (decorative), `--zx-border-strong` (control borders, 3:1) |
| Text | `--zx-text`, `--zx-text-muted`, `--zx-text-faint` (placeholders only, never below 12px), `--zx-link` |
| Primary | `--zx-primary`, `--zx-primary-hover`, `--zx-on-primary`, `--zx-primary-soft`, `--zx-primary-soft-text` |
| Semantic | `--zx-{ok,warn,danger,info}-{solid,bg,text,line}`; `--zx-neutral-{bg,text,line}`; `--zx-on-solid` |
| Focus | `--zx-focus`, `--zx-focus-ring` (two-tone box-shadow) |
| Shadow | `--zx-shadow-1` cards, `-2` popovers and toasts, `-3` dialogs and the save bar |
| Radius | `--zx-radius-sm` 4, `-md` 8, `-lg` 12, `-pill` |
| Spacing | `--zx-space-1..7` = 4, 8, 12, 16, 24, 32, 48 px |
| Type | `--zx-fs-xs..2xl` = 12, 13, 14 (body), 16, 20, 26 px; `--zx-font-mono` |
| Sizes | `--zx-control-h` 36px, `--zx-touch` 44px |

`*-solid` is a filled background (button, switch) with `--zx-on-solid` text; `*-bg` is a tinted area with `*-text` on it; `*-line` its border.

## 2. Components

Markup of every component is on the kit page (copy button). Summary and the rules that are not visible in the markup:

| Component | Class / API | Notes |
|---|---|---|
| Page header | `.zx-page-header` (`__main`, `__crumbs`, `__title`, `__sub`, `__actions`) | One per page, the only `h2`. An element with `data-zx-crumbs` gets the breadcrumbs from the menu definition |
| Section card | `.zx-card` (`__head`, `__title`, `__desc`, `__body`, `__foot`), `--flat`, `--danger` | Group by purpose, title says what the section is for |
| Form row | `.zx-field` (`__label-row`, `__label`, `__control`), `.zx-help`, `.zx-error`, `.zx-whatis` + `.zx-popover` | Real `<label for>`. Errors: `ZxUI.field(el).setError(text)` (sets `aria-invalid`, `aria-describedby`) |
| Toggle row | `.zx-toggle-row` + `input.zx-switch[role=switch]` | Description says what happens when it is on |
| Buttons | `.zx-btn` + `--primary --secondary --danger --danger-outline --ghost --icon --sm --block`, `.is-loading` | `ZxUI.setLoading(btn, true)`. Icon buttons need `aria-label`. One primary per view |
| Badge | `.zx-badge` + `--ok --warn --danger --info`, `--dot` | Text always present, colour is never the only signal |
| Callout | `.zx-callout` + `--info --warn --danger --success` | `role="note"`; `role="alert"` only for messages that appear after an action |
| Empty state | `.zx-empty` (`__icon`, `__title`, `__text`) | Always offers the next action |
| Data table | `.zx-table-wrap > table.zx-table`, `--compact --comfortable`, `.zx-num`, `.zx-actions`, `.zx-row-actions` | Sticky header; give the wrapper `tabindex="0" role="region" aria-label`; `data-label` on every `td` for the 480px card layout |
| Tabs | `.zx-tabs > .zx-tab[data-zx-panel]`, `ZxUI.tabs(el, {onChange})` | Arrow keys, Home/End, roving tabindex |
| Segmented control | `.zx-segmented > .zx-segmented__item[data-value]`, `ZxUI.segmented(el, {onChange})` | `role=radiogroup` |
| Stat tile | `.zx-stat` (`__label`, `__value`, `__hint`), `--ok --warn --danger` | |
| Save bar | `ZxUI.saveBar({form, onSave, onDiscard, mount, ignore, saveLabel, discardLabel, successText})` | See 2.1 |
| Toast | `ZxUI.toast(message, {type, undo, undoLabel, duration})` | See 2.2 |
| Confirm | `ZxUI.confirm({title, message, confirmLabel, cancelLabel, danger, typed})` -> `Promise<boolean>` | See 2.3 |
| Skeleton | `.zx-skeleton` (`--text --title --block --circle`), `ZxUI.skeleton(container, {lines, title, block})` | Returns a function that removes it; sets `aria-busy` |
| Breadcrumbs | `.zx-crumbs` | Filled by `nav.js` |

### 2.1 Save bar and dirty tracker

```js
var bar = ZxUI.saveBar({
    form: "#myForm",                       // container whose inputs are tracked
    ignore: ".ui.checkbox",                // optional: controls that save themselves
    onSave: function (ctx) {               // ctx.changes = [{key, label, from, to}]
        return $.cjax({url: "/api/...", method: "POST", data: {...}});   // a promise / jqXHR
    }
});
// after the page filled its fields from the API: bar.reset();   (re-baseline)
// partial saves:  ctx.tracker.commit(["fieldId"]);
```

* The bar (sticky at the bottom of the page) appears when a tracked control differs from its baseline and shows how many changes and which fields. Changing a value back hides it.
* Save is disabled while saving; success shows "Saved" briefly; failure keeps the bar, shows the reason and leaves the form dirty. Failure = rejected promise, thrown error, `false`, or a result object with `error` (Zoraxy APIs answer `{error: "..."}` with HTTP 200). `$.cjax` returns the jqXHR for this.
* Discard puts the fields back to the baseline. Ctrl/Cmd+S in the form saves.
* **Programmatic changes never make the form dirty**: only trusted (real) events count, plus untrusted events fired by page code within 600 ms of a pointer or keyboard action in the form (Fomantic dropdowns and checkboxes fire their change events from script). Code that fills the form must call `bar.reset()` (or `ctx.tracker.commit`) afterwards.
* Control keys: `name`, else `id`, else the id of the nearest ancestor with an id plus an index. Labels: `data-zx-label`, `label[for]`, wrapping label, `aria-label`, placeholder. Put `data-zx-ignore` on controls that are not form state.
* Integration with the unsaved-changes guard: every bar registers in `ZxUI.unsaved` (the proxy rule editor guard of `uxkit.js` too). While a bar is dirty, `beforeunload` asks, and opening another page (menu, palette, `openTabById`) shows "Leave without saving?" and discards on confirm.

Rule (decision D2): security and certificate pages use explicit Save; instant save is for toggles that are inherently live, and must say so (toast). New pages should not mix both in one card.

### 2.2 Toast with Undo

`ZxUI.toast("Rule deleted", {undo: function () { /* restore */ }})`. The caller wires the undo (the change-history work will provide real undo); the toast only offers the button (10 s) and runs the function once. Errors use `role="alert"` and stay 8 s; the message is inserted as text.

### 2.3 Confirm

```js
ZxUI.confirm({title: "Delete rule?", message: "app.example.com stops working.", danger: true,
              confirmLabel: "Delete rule", typed: "app.example.com"}).then(function (ok) { ... });
```
Danger puts the initial focus on Cancel. `typed` keeps the confirm button disabled until that exact text is typed; use it for irreversible actions on one named object. Escape cancels, Tab is trapped, focus returns to the opener.

### 2.4 Drawer

`ZxUI.drawer({title, label, onClose, returnFocus})` returns `{el, body, foot, setTitle, close, isOpen}`. A modal panel from the right edge, a bottom sheet at 600px and narrower (max 88% of the height, safe-area aware). Esc, the close button and a click on the dimmed area close it; Tab is trapped; focus returns to `returnFocus` (default: the element that was focused). One drawer at a time. Layer `--zx-z-drawer` (1100), below dialogs, toasts (an Undo toast stays visible above it) and the palette. Fill `body` and `foot` yourself; `foot` hides while empty. First user: "Why was this blocked?" on Statistics > Blocked (docs/ux/why-blocked.md).

## 3. Navigation

### 3.1 Menu definition

The menu is the `NAV` array at the top of `src/web/script/nav.js`, rendered into `#navTree` of `index.html`. Breadcrumbs and the command palette read the same array.

**Adding a page to the menu = one line**, in the `items` of the group it belongs to:

```js
{tag: "mypage", label: N_("My page"), icon: "star", kw: "words people may type"},
```
plus the page container in `index.html`: `<div id="mypage" class="functiontab" target="mypage.html"></div>` and the component `components/mypage.html`. Fields: `tag` (container id and URL hash, never rename an existing one), `label` (wrapped in `N_()` so `tools/i18n/extract.py` finds it; translated by the DOM translator), `icon` (Fomantic icon name), `kw` (extra palette search words), optional `id`, `hidden`, `dev` (only with `-dev`), `href` (opens a link in a new tab instead of a page). A group has `id` (suffix of `#group-ID`, key of the saved open/closed state), `label`, `icon`, `items`, optional `home` (tag the group breadcrumb links to, e.g. a future "Security overview").

Groups (8): **Overview** (Status, Quick Start), **Sites** (HTTP Proxy, Default Site, Redirection, Path routes, Stream Proxy, Static Web Server, Raw rule form), **Security** (Security Center, WAF, Access Rules, SSO / OAuth2, CAPTCHA), **Certificates** (TLS / SSL, ACME), **Traffic** (Statistics, Visitors, Uptime Monitor), **Network** (Listeners, Trusted Proxies, Tunnels, Encrypted Client Hello, Network Interfaces, Network Tools), **Fleet & HA** (Fleet, Cluster / HA), **System** (Update, API Tokens, Plugin Manager, App Store, Utilities, Settings, UI kit in `-dev`).

Compatibility: all `tag` ids, `#hash` deep links and `openTabById()` calls are unchanged; only the placement changed. Renamed labels (D4): Ingress -> Listeners, Virtual Directories -> Path routes, Advanced Rule Form -> Raw rule form (labels only, ids and API paths untouched). Saved menu state (`localStorage.zoraxy_menu_groups`) is migrated to version 3. Groups start collapsed except Overview on a first visit; opening a page expands its group and no longer collapses the others.

Behaviour: groups are `role=button` headers with `aria-expanded`/`aria-controls`; Up/Down/Home/End move through the menu, Left/Right collapse/expand a group (Left on an item jumps to its header), Enter/Space activate; the active page has `aria-current="page"`. On phones the menu is the existing slide-in panel behind the hamburger button, rows are 44px high.

### 3.2 Breadcrumbs

"Group > Page", shown above the page content of every page, from `NAV` (`ZxNav.crumbsFor(tag)`). A page that renders its own header puts `data-zx-crumbs` in `.zx-page-header__crumbs` and the strip above the page hides.

### 3.3 Command palette

Ctrl+K / Cmd+K, or the Search button in the header (the `/` menu filter still works). Searches pages (labels and `kw` synonyms: "firewall" finds WAF, "ssl" finds Certificates, "ban" finds Access Rules and Auto-ban), proxy hosts (`GET /api/proxy/list`, cached, refreshed every time the palette opens), a static index of settings (`SETTINGS` in `palette.js`, page + CSS anchor; the page opens, the tab or accordion is opened, the field scrolls into view and flashes) and actions (`ACTIONS`: New proxy rule, Enable WAF (opens the WAF page, changes nothing by itself), Check for updates, Toggle dark mode, Change language, Set up auto-ban). Fuzzy, grouped, keyboard only (type, Up/Down, Enter, Esc), recent items kept in `localStorage`. Nothing leaves the browser; every inserted string is set with `textContent` (host and rule names are user data).

To add a setting: one line in `SETTINGS`, `{label: N_("..."), page: "tag", pre: "selector to click first (tab/accordion)", at: "#anchor", kw: "synonyms"}`. `tools/ui-smoke/smoke.py` checks that every entry resolves.

### 3.4 Top bar

`<div class="menubar zx-topbar">` in `index.html`, logic in `script/topbar.js` (`window.ZxTopbar`), styles in `ui/topbar.css`. Left to right: logo (links to Status), **status pills**, then the controls: **Search** (Ctrl+K, primary-coloured border so it stays the most prominent), **Theme**, **Language**, **Account** (only with authentication), and on phones **More** and the hamburger of the page menu. Every control is a `.zx-topbtn`: 36px high (40px at 748px and below), 8px radius, `--zx-border-strong` border, `--zx-focus` 2px focus ring. Colours only from `--zx-*` tokens; the bar is `--zx-surface` in both themes.

* **Theme menu**: Light / Dark / System (the button shows the current mode as icon + word). System = no stored choice, the OS preference decides and follows changes. Light and Dark store `localStorage.theme` as before, `toggleTheme()` (palette action "Toggle dark mode") still works and `darktheme.js` fires `zoraxy:theme` so the button follows.
* **Language menu**: globe + current code (`EN`, `DE`, `ZH-CN` ...), all languages of `i18n.languages` by their native names, the current one checked. Scrolls inside the menu when the list is long. The native `select.i18n-picker` stays on the Settings page.
* **Account menu** (hidden when `GET /api/auth/authEnabled` is false): user name and role (`/api/auth/username`, `/api/auth/role`), Change password (opens Utilities), Log out.
* **Status pills** (one light poll, `ZxTopbar.refresh()` forces it): health ("Online", or a danger "Proxy stopped"; the tooltip names the listening port), "N sites down" (Uptime Monitor, only when something is down), "N certificates expiring" (Certificates, only within the 30 day warning window of the Status page, danger at 7 days or less), "Update vX" (Update page), "N blocked today - See why" (opens Statistics > Blocked). Each pill is a real `<a href="#page">` with a tooltip and `aria-label`; when no data can be read one neutral "Status unavailable" pill is shown (never a spinner).
  * Data reused, nothing new on the server: `GET /api/stats/glance` (blocked today, upstreams down, certificates; what the Status tiles use) and `GET /api/proxy/status` (Running, port; what the Status banner uses), both every 45 s, only while the tab is visible (plus one refresh when it becomes visible after 30 s or more).
  * **The update badge makes no request of its own.** Zoraxy never contacts GitHub by itself (the Update page says "Not checked yet"), so the badge shows the result of the last check made on the Update page in this browser (`ZxTopbar.setUpdate(result)`, `localStorage.zoraxy.topbar.update`, kept 14 days, dropped when the running version changes).
* **Widths**: above 1180px full text; 749-1180px pills shrink to icon + number, Search to an icon, theme / language / account to icon (the full text stays in `aria-label` and tooltip); 748px and below: pills, theme, language and account fold into one **More** menu (a dot marks it when something needs attention) next to Search and the hamburger. Pills that do not fit are clipped in priority order (health first, blocked counter last), never wrapped over the content.
* **Keyboard**: Tab order is logo, pills, Search, Theme, Language, Account (phone: Search, More, hamburger). Enter / Space / ArrowDown open a menu with focus on the current choice; Up/Down/Home/End move; Enter chooses and returns focus to the button; Esc closes and returns focus; Tab and an outside click close. Menus are `role=menu` with `menuitemradio` (`aria-checked`) / `menuitem`; buttons carry `aria-haspopup="menu"` and `aria-expanded`.
* Adding a pill = one entry in `pills()` of `topbar.js` (state `ok|warn|danger|info|neutral`, icon, `tag` of an existing page). Do not add a pill that has no page to open.

## 4. Do and don't

* Do build new pages from the kit classes and tokens; do not add page-local colours, shadows or radii.
* Do use one save model per page (section 2.1). Do not put an "Apply" button next to each field.
* Do write labels and help in plain language; explain jargon once with the "what is this?" popover.
* Do give every empty list an empty state with the next action.
* Do not convey state by colour alone; do not use `--zx-text-faint` for anything but placeholders.
* Do not change a default behaviour as a side effect of a UI change (D3).
* Do not use `innerHTML` with user data; use `ZxUI.esc()` or `textContent`.
* Do not rename `tag` ids, group ids or API paths when relabelling (D4).

## 5. Accessibility rules (checked in review)

* **Keyboard.** Everything reachable and operable with the keyboard; order follows reading order; no keyboard traps except modal dialogs (confirm, palette), which trap Tab, close on Escape and return focus to the opener.
* **Focus.** A visible focus indicator on every interactive element (`--zx-focus-ring`, 3:1 against its surroundings); never `outline: none` without a replacement.
* **Names and roles.** Controls have a name (`<label for>`, text, or `aria-label` for icon buttons); toggles `role=switch`; tabs `role=tab` with `aria-selected`; disclosure headers `aria-expanded`; status changes announce through `role=status` / `aria-live=polite`, errors `role=alert`; invalid fields `aria-invalid` + `aria-describedby`.
* **Contrast.** Text at least 4.5:1 and non-text UI (control borders, focus ring) at least 3:1 in both schemes; the kit page computes the ratios of the tokens live and marks failures.
* **Touch.** At 748px and below, or on coarse pointers, controls are at least 44px (36px for small buttons in dense tables).
* **Motion.** Animations respect `prefers-reduced-motion`; forced-colors mode keeps borders and focus.
* **Responsive.** Test at 390px: no horizontal page scroll; tables collapse to cards below 480px.
* **Language.** Visible English text must be extractable (`python3 tools/i18n/extract.py`); use `N_("...")` for strings that are only in JavaScript data.

## 6. What was verified, and what was not

Verified by the browser smoke test (`tools/ui-smoke`): the top bar (`--topnav-only` via `topnav_run.sh`: sizes, overflow, collisions, contrast, pills, menus, keyboard, phone More menu, Log out), palette (Ctrl+K, page/host/setting, Enter), breadcrumbs, every legacy `tag`, every palette settings anchor, kit page load, save bar on Listeners and Settings, screenshots in light, dark and 390px. **Not verified:** real screen readers (NVDA, VoiceOver, TalkBack), real touch devices, Safari/Firefox rendering (Chromium only), forced-colors mode.

## 7. Page patterns of the consistency pass

Added in `src/web/ui/zxpages.css` and `src/web/script/zxpage.js` (loaded by `index.html`). Same rules as the kit: tokens only, namespaced `zx-`.

| Pattern | Markup | Used by |
|---|---|---|
| Page header with breadcrumbs, one-line plain-language subtitle and a History shortcut | `.zx-page-header` with `data-zx-crumbs` and `<button class="zx-btn zx-btn--secondary" data-zx-history="Object">` | Certificates, ACME, Access Rules, Trusted Proxies, SSO, CAPTCHA, Security Center, Path routes (WAF has its own hero with the same crumbs and button) |
| Related box | `<aside class="zx-related"><span class="zx-related__title">Related</span><ul><li><a data-nav-open="tag">Page</a> <span>why</span></li></ul></aside>` | the same pages; `data-nav-open` is handled by `nav.js` so the link uses `openTabById` and the unsaved-changes guard |
| Sibling page tabs | `.zx-pagetabs > a[data-nav-open]` with `aria-current="page"` | Certificates and ACME Client: two pages (and two menu entries) that look like tabs of one |
| Stat row | `.zx-statrow > .zx-stat` | Certificates |
| Collapsible card | `button.zx-collapse__toggle[data-zx-toggle=id][aria-expanded]` + `div#id[hidden]` | "Add a certificate" |
| Item list in a callout or card | `.zx-itemlist` | Expiring soon, Hosts without a certificate |
| Checklist | `.zx-steps` | Get started on Status |
| Help popover | `.zx-whatis` + `.zx-popover` (section 2) | SNI, fallback certificate, trusted proxy gating, paranoia level, anomaly score |

### 7.1 History hook

`ZxUI.toast(msg, {action: {label, run}})` shows one extra, non-destructive action. `ZxHistory.savedToast(msg, object)` is the standard success toast with a **View history** action; `ZxHistory.view(object)` opens System > History with the Object filter set (it never restores: every restore restarts Zoraxy, so a toast must not trigger one). `ZxUI.saveBar({historyObject: "Auto-ban"})` shows that toast after every successful save. The object is a substring of the history entry label ("Certificate", "ACME", "WAF", "Access rule", "Auto-ban", "Virtual directory", ...).

### 7.2 Save model decision (D2 applied)

Converted to the kit save bar (an explicit form with one Save): Listeners and Settings (earlier), **Security Center > Auto-ban**.
Deliberately left, because a save bar would change behaviour:

* Access Rules, WAF mode cards, ACME auto-renew switch, Trusted Proxies list: live switches and per-row add / remove actions. They keep instant save with the toast.
* Trusted Proxies "Edit as text": already a modal edit mode with its own Save and Cancel.
* CAPTCHA: has its own dirty tracker, a scope switch with a discard prompt and per-rule Save; rebuilding that on the kit tracker is a separate change.
* WAF profiles / exclusions, SSO providers, ACME CA settings: several independent Save buttons for independent objects.
* Bot rules, Header rules, Basic auth (Security Center): edited as lists with their own add / remove actions.

### 7.3 Escaping

Anything that came from the configuration (host names, aliases, upstreams, tags, rule names, redirect addresses, user names) is escaped with `ZxUI.esc()` (components) or the local `zxEsc()` (snippets run in their own iframe). Values that a button needs are carried in `data-*` attributes and read with `this.dataset`, never put inside `onclick="f('${value}')"`. `tools/ui-smoke` adds a rule with the host name `"><img src=x onerror=...>` and fails if it becomes markup on any listing page.
