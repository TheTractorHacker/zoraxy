# Site editor: classic tabs or five sections, Easy / Advanced, one Save, app presets

Phase 4 of the redesign in [audit-2026-11.md](audit-2026-11.md) (section 4). The proxy rule editor (the dialog opened from the
HTTP Proxy table) used to have 11 tabs organised by technology. It now has **five sections organised by task**, an
**Easy / Advanced switch**, **one save model** and **app presets**. No control was removed and no API call or validation changed.

| Part | File |
|---|---|
| Markup (sections, cards, every control) | `src/web/components/httprp.html` |
| Editor logic: modes, sections, Save bar, Protection, focus | `src/web/script/siteeditor.js` (`window.HrpEditor`) |
| Layout and preset styles | `src/web/ui/siteeditor.css` |
| Preset dialog and preview helpers | `src/web/script/apppresets.js` (`window.ZxPresets`) |
| New proxy rule dialog ("Start from an app preset") | `src/web/script/newrule.js` |
| Preset data (Go side) | `src/mod/dynamicproxy/ruletemplate_presets.json`, `ruletemplate_presets.go`, tests `ruletemplate_presets_test.go` |
| Old control inventory + the test | `tools/ui-smoke/siteeditor_inventory.json`, `siteeditor_inventory.py`, scenario `site_editor_ui` in `smoke.py` |

## 0. Layouts: Tabs (classic) and Sections

The editor has two layouts over **the same cards and the same controls** (no control is in the DOM twice). A **Layout switch**
(`#hrpLayout`, kit segmented control, "Tabs (classic)" / "Sections") sits at the top of the dialog and is remembered per browser in
`localStorage` key `zoraxy_site_editor_layout` (read and written in try / catch; any other value means Tabs). **The default is
Tabs (classic) for everyone**; the Easy / Advanced key (`zoraxy_site_editor_mode`) is a separate preference and is never touched by
the layout.

* **Tabs (classic)**: the 11 tabs of the editor before the redesign, in the old order with the old labels and icons: Host
  (`downstream`), Destinations (`upstream`), Virtual Directory (`vdirs`), WebSocket (`websocket`), Alias (`alias`), TLS / SSL
  (`ssl`), Headers (`headers`), Access Rules (`accessrule`), Security (`security`), WAF (`waf`), Tags (`tags`). Each tab shows
  the cards that hold the controls it had (git history: the commit before "Site editor redesign: five sections", and
  `siteeditor_inventory.json`, which records the old tab of every control). Everything is visible: Easy / Advanced does not apply
  (the switch is hidden, the dialog behaves as Advanced, the note about advanced settings is not shown). The only card that was
  not in the old editor is **Protection** (the one-select protection summary that mirrors the WAF source), shown at the top of the
  WAF tab.
* **Sections**: the five sections and the Easy / Advanced switch described below.

How it works (one code path): every card carries `data-hrp-tab` (its old tab) and `data-hrp-ord` (its position inside that tab, set
as the CSS `order` by `siteeditor.js`). The five `.hrp-sec` wrappers stay in the DOM; in Tabs they are `display: contents`, and a card
is shown when its `data-hrp-tab` is the open tab (class `is-tab`). `renderNav()` builds the buttons of `#hrpNav` for the current
layout (`TABS` or `SECTION_NAV`), both with class `hrpedit_menu_item` and the attribute `cfgpage`; the click and keyboard handlers
are the same. The Save bar, the dirty tracking, the focus trap, presets and every sub editor are shared and do not know the layout.
To add a card: put it in a section, give it `data-hrp-tab` and `data-hrp-ord`; `src/siteeditor_tabs_test.go` fails when a card has
no tab or the tab disagrees with the inventory.

Accessibility: Tabs is a `tablist` of 11 `tab` buttons with `aria-selected`, roving tabindex and Arrow / Home / End keys (wrapping);
the one `tabpanel` is `#hrpSections` (`aria-labelledby` the selected tab, the tab's `aria-controls` points at it) and the section
wrappers get `role=presentation`. In Sections each section is its own `tabpanel`, as before. At 390px the strip scrolls sideways
(`overflow-x: auto`) and shows the scroll cue (`.zx-scroll-end` / `.zx-scroll-start` from `main.css`, set by `uxkit.js` for `#hrpNav`).

Deep links in both layouts: `HrpEditor.show(name)` accepts the old tab names (`downstream`, `upstream`, `vdirs`, `websocket`,
`alias`, `ssl`, `headers`, `accessrule`, `security`, `waf`, `tags`) and the section names. In Tabs a section name opens the tab with
its first card (general: Host, routing: Virtual Directory, security: Security, tls: TLS / SSL, advanced: Host); in Sections an old tab
name opens the section that holds it. Switching the layout keeps the place (the WAF tab opens the Security section and back).
`HrpEditor.layout()` / `HrpEditor.setLayout()` read and set the layout.

## 1. Sections and where the old tabs went

| Section | Cards (`data-hrp-card`) |
|---|---|
| **General** | `host` (hostname, rename), `upstream` (destinations), `lb` (sticky sessions), `health` (uptime monitor, health-check URI), `alias`, `tags` |
| **Routing** | `websocket`, `wsopts`, `vdirs` (path routes), `headers` (header rewrite rules), `pathrules` (path rules, error pages, responses, CORS), `ports` (extra listening ports) |
| **Security** | `protection` (Easy only), `accesseasy` (Easy only), `accessrule`, `auth`, `ratelimit`, `captcha`, `exploits`, `waf`, `wafresp`, `wafapi`, `wafevents` |
| **TLS** | `certeasy` (Easy only), `certs` (certificate per hostname, SNI, legacy matching, auto HTTPS, get certificate), `plainhttp`, `clientcerts` |
| **Advanced** | `compat` (chunked encoding, HTTP/1.1, client IP headers), `forwarding` (CONNECT, protocol upgrade), `uptimeopts` (healthy status codes), `logging`, `scripts` (Lua, Sablier) |

Mapping table, old tab to new place (every selector of the old editor is in `tools/ui-smoke/siteeditor_inventory.json` with its
section and card; 126 controls):

| Old tab | Controls | New section | Card |
|---|---|---|---|
| Host | hostname, rename, save / cancel | General | `host` |
| Host | Allow plain HTTP access (`BypassGlobalTLS`) | TLS | `plainhttp` |
| Host | HTTP CONNECT, protocol upgrade forwarding | Advanced | `forwarding` |
| Host | Disable request logging, disable statistic collection | Advanced | `logging` |
| Host | Alternative listening ports | Routing | `ports` |
| Destinations | upstream list, Edit Upstreams | General | `upstream` |
| Destinations | Monitor uptime, health-check URI | General | `health` |
| Destinations | Status codes that count as up | Advanced | `uptimeopts` |
| Destinations | Sticky session | General | `lb` |
| Destinations | Chunked encoding, Force HTTP/1.1, Sanitise client IP headers | Advanced | `compat` |
| Virtual Directory | list, Edit Virtual Directories | Routing | `vdirs` |
| WebSocket | Enable WebSocket | Routing | `websocket` |
| WebSocket | Connection timeout, refresh on activity | Routing | `wsopts` |
| Alias | alias editor (embedded) | General | `alias` |
| TLS / SSL | certificate per hostname, SNI, legacy matching, auto HTTPS, Get Certificate, Self-signed | TLS | `certs` |
| Headers | header editor (embedded) | Routing | `headers` |
| Access Rules | access rule picker (embedded) | Security | `accessrule` |
| Security | authentication provider, OAuth2 fields, credential / exception buttons | Security | `auth` |
| Security | Path Rules, Error Pages / Static Responses / CORS / Bandwidth | Routing | `pathrules` |
| Security | Client Certificates, Peers and Secondary TLS | TLS | `clientcerts` |
| Security | Lua Script, Sablier | Advanced | `scripts` |
| Security | Block common exploits, AI crawlers, mitigation action | Security | `exploits` |
| Security | Rate limit, burst | Security | `ratelimit` |
| Security | CAPTCHA and its page customisation | Security | `captcha` |
| WAF | source, profile, challenge band, variable exclusions, custom settings | Security | `waf` |
| WAF | response protection | Security | `wafresp` |
| WAF | API protection | Security | `wafapi` |
| WAF | recent events | Security | `wafevents` |
| Tags | tag editor (embedded) | General | `tags` |
| side menu | the 11 tab buttons | the five section buttons (`.hrpedit_menu_item[cfgpage=general|routing|security|tls|advanced]`) | |

Compatibility: the class `hrpedit_menu_item` and the attribute `cfgpage` stay on the section buttons, with the new values.
`HrpEditor.show("waf")` (and `downstream`, `upstream`, `ssl`, ...) still opens the right section: old tab names map to the
section that holds their controls. Cards keep the old name in their `rpcfg` attribute. `saveProxyInlineEdit(uuid)`,
`closeHttpRuleEditor()`, `resyncProxyEditorConfig()` and `resetEditorDirty()` exist and work as before.

**The test.** (Sections layout.) `site_editor_ui` loads `siteeditor_inventory.json` (generated from the old markup by
`siteeditor_inventory.py`), checks that every selector matches exactly one element of the new editor, that it sits in the
recorded section, and that its card is shown when the section is open in Advanced mode. The three retired "Apply" buttons
of the WAF block (`.wafSourceSaveBtn`, `.wafChallengeSaveBtn`, `.wafSaveBtn`) are kept in the DOM, hidden
(`data-hrp-retired`), because the Save bar calls the same code; they are the only controls not required to be visible.

## 2. Easy and Advanced

The switch is at the top of the dialog (`#hrpMode`, a kit segmented control) and is remembered per browser
(`localStorage` key `zoraxy_site_editor_mode`; default Easy).

* **Easy** shows one column with the cards that carry `data-easy`: hostname, destinations, WebSocket on/off, **Protection**,
  **Access rule** (a plain picker), **HTTPS certificate** (status), and a "Show advanced settings" link. The section navigation is hidden.
* **Protection** is one select: Off / Detect only / Block (plus "Follow the global policy"), with a one-line explanation. It is
  the WAF source of the rule and uses the existing API (`POST /api/waf/endpoint/set`). It mirrors the source select of the WAF
  card; a rule that uses a profile or a custom setup shows that value ("change it in Advanced") instead of hiding it.
* **Advanced** shows one section at a time with the vertical navigation (`role=tablist`, arrow keys, Home / End).
* **Never hide a non-default setting.** Cards have `data-hrp-nd="key"`; `nonDefaults(rule)` in `siteeditor.js` lists the keys
  whose setting is not at its default (aliases, tags, sticky sessions, health-check changes, WebSocket timing, path routes,
  headers, extra ports, path rules / ops, authentication, rate limit, CAPTCHA, exploit blocking, WAF profile / custom /
  exclusions / response / API, TLS options, plain HTTP, client certificates, compatibility flags, CONNECT / upgrade, healthy
  status codes, logging switches, scripts). In Easy mode those cards are shown too and a note, **"This rule has advanced
  settings"**, lists them with an "Open in Advanced" button each.

To add a setting: put its markup in a card, give the card `data-hrp-nd` and add one line to `nonDefaults`.

## 3. Save model (decision D2)

One model for the whole editor: **explicit Save**.

* Every setting that used to save on change is now collected by one kit save bar (`ZxUI.saveBar`, sticky at the bottom of the
  dialog): "N unsaved changes" with the names of the fields, **Save changes** and **Discard**. Ctrl/Cmd+S saves.
* Save runs the same calls as before, in this order, only for the groups that changed: `POST /api/proxy/edit`
  (`saveProxyInlineEdit`, the whole form), `POST /api/proxy/setTlsConfig` (`saveTlsConfigs`), `POST /api/cert/setPreferredCertificate`
  (one per changed hostname), `POST /api/waf/endpoint/set` (source, profile, challenge band) or `POST /api/waf/set` (custom WAF),
  `POST /api/access/attach` (access rule of Easy mode). Validation messages are unchanged; a failure keeps the bar and the edits.
* **Inherently live** switches keep instant save, with a toast ("Saved. This switch takes effect at once."): the two logging
  switches. They are in their own card, marked `data-hrp-live`, and only save at once when nothing else is pending (otherwise
  they are collected like any field).
* **Sub editors that are their own page** keep their own saving and say so in the card text: alias, tags, header rules and the
  access rule cards (embedded pages, picking an access rule saves at once), the side editors opened by buttons (upstreams, path
  rules, error pages, credentials, ...), hostname rename, the listening port list (add / remove), **response protection** and
  **API protection** (their own Save buttons). Their inputs carry `data-zx-ignore` / `data-hrp-selfsave`.
* **Guard.** Closing (Close, backdrop, Escape) with unsaved edits asks first (`uxkit.js initEditorGuard`, now also asking the
  save bar). Only real user edits count (trusted events; Fomantic dropdown events fired within 600 ms of a pointer or key press);
  the form is re-baselined after it is populated and after late loaded lists (profiles, providers, certificates, access rules),
  so opening an editor never gives a false prompt. When the form is refilled while it holds edits (a side editor was closed)
  the edits are re-applied, not lost.
* Opening another page, or leaving the browser tab, with unsaved edits goes through the same `ZxUI.unsaved` registry as every save bar.

### A bug found on the way (also on `dev`)

`<select class="ui dropdown">` is turned into a `<div class="ui dropdown">` by Fomantic, and `.val()` on that div is a plain
property: the WAF source, profile, mode and paranoia selects of the old editor sent the stale value when saved
(choosing Block and pressing "Apply source" sent `source=inherit`). The editor now reads and writes them through
`hrpSel` (`siteeditor.js`), which works on both forms.

## 4. App presets

A preset is a **built-in rule template** (`Category: "app"`) in `ruletemplate_presets.json`; the template engine
(`ApplyRuleTemplate`), the `/api/proxy/templates/*` APIs, the bulk "apply template" action and the template editor are
unchanged and work on them. A preset may only set what the engine supports: WebSocket, headers, rate limit, WAF source,
uptime path, tags, exploit blocking, HSTS, request id header. Each has a plain-language note that starts with
"A starting point, review it".

| Preset | What it sets |
|---|---|
| WordPress | WAF detection only, uptime monitor `/`, `nosniff`, tags |
| Nextcloud | WebSocket on, WAF detection only, uptime `/status.php`, `nosniff` |
| Home Assistant | WebSocket on, WAF detection only, uptime `/` |
| Jellyfin | WebSocket on, uptime `/health`; no WAF or rate limit (streaming) |
| Plex | WebSocket on, uptime `/identity`; no WAF or rate limit (streaming) |
| Grafana | WebSocket on (Live), WAF detection only, uptime `/api/health`, `nosniff` |
| Vaultwarden | WebSocket on (notifications), WAF detection only, uptime `/alive`, `nosniff` |
| Gitea or GitLab | WebSocket on, WAF detection only, uptime `/`, `nosniff` |
| Portainer | WebSocket on (console), WAF detection only, uptime `/api/system/status`, `nosniff` |
| JSON API | rate limit 100 / burst 200, request id header, WAF detection only, WebSocket off |
| Static website | hardening headers, exploit blocking, rate limit 50 / burst 100, WebSocket off |
| Strict admin panel | rate limit 10 / burst 20, WAF **block**, exploit blocking, hardening headers |
| Public website, Login page, Admin dashboard, Odoo ERP, REST API per key, Webhook receiver, File upload, WebSocket app limits, Monitoring-friendly | per-minute limits, path limits, keying and WebSocket caps from the rate limit guidance table; see [rate-limits.md](rate-limits.md) |

What the presets deliberately do **not** do:

* They never touch upstreams, domains, authentication or the access rule (engine rule). The admin preset therefore does not
  turn on authentication; it is flagged `RequiresAuth`, so the dialogs warn when the rule has no provider.
* **No WAF exclusions.** The engine has no exclusion field, and no exclusion is claimed for any app: presets use detection
  only, so false positives are logged and the WAF tuning assistant proposes exclusions from real traffic.
* **No `X-Forwarded-Proto` header**: Zoraxy already sets it. No per-app body-size or WebDAV setting: Zoraxy imposes no body limit.
* Notes about the app's own configuration (trusted proxies, root URL, ...) are text only.
* **`NoDowngrade`** (set on every preset): the WAF source is only raised (off < inherit < detection only < block; a profile or a
  custom WAF is never replaced), a rate limit is only applied when the rule has none or a looser one, exploit blocking is never
  turned off, HSTS is never lowered, a header the operator already set keeps its value, an existing uptime path is kept.
  Applying a preset twice changes nothing.

UI: the **New proxy rule** dialog has a collapsed "Start from an app preset" section under the template grid (same radio
group, so the existing submit is unchanged; it starts closed so the dialog keeps its size, and the dialog content scrolls when
it is taller than the window) and shows the preview of the selected preset for a new rule. In the editor, **Apply preset**
opens a dialog with the same presets and a diff preview for *this* rule (`POST /api/proxy/templates/preview` with the rule
name: Setting / Now / After, text only); **Apply** calls the bulk `apply_template` action. It is blocked while the editor has
unsaved edits (they would be overwritten). Presets are read only in the template manager; clone one to change it.

## 5. Accessibility, XSS, i18n

* The dialog is `role=dialog aria-modal`, named by its title. Focus moves to the title when it opens, Tab stays inside (also
  after an embedded editor), Escape closes (side editor first, and not while a dropdown or another dialog is open), focus returns
  to the element that opened it. The section navigation is a `tablist` with `aria-selected`, `aria-controls`, roving tabindex.
* Host names, aliases, upstream addresses, paths, ports, certificate names and tags are user data: the editor renders them with
  `textContent` / `hrpEsc`, and the embedded alias, tag and access-rule pages were changed from string templates to DOM calls.
* Every new visible string is extractable (`python3 tools/i18n/extract.py --check`).

## 6. Verified, and not

Tabs layout (`tools/ui-smoke/smoke.py --editor-tabs-only`, `editortabs_smoke.py`, also part of the full run; Go: `src/siteeditor_tabs_test.go`):
the default with no stored choice, the 11 labels and names in order, every inventory control exactly once and visible on its old tab
(and each tab showing exactly its cards, in the old order), no Easy / Advanced switch and its stored preference untouched, tablist /
tabpanel aria and arrow / Home / End keys, the Tab trap, legacy deep links in both directions, the layout switch and its memory
(and a broken stored value falling back to Tabs), one Save bar over edits on two tabs, the preset dialog with its diff, a hostile
host name, no overflow, the scroll cue at 390px, and screenshots in light, dark and 390px. `smoke.py` stores the Sections layout
for every other scenario (an init script) so they keep testing the sections; the Tabs scenario opts out of that.

Verified by the browser smoke (`tools/ui-smoke/smoke.py --site-editor-only`, also part of the full run): the inventory, legacy
tab names, aria and keyboard, focus in and out, Tab trap, Easy / Advanced and its memory, the non-default note and forced
cards, the save bar (collect, no early save, count, refuse to close, discard, save, live switch, TLS options, no false prompt),
Protection through the WAF source API, preset preview / apply / idempotence / no-downgrade, the New rule dialog, a hostile host
name and tag, and screenshots in light, dark and 390px.

Not verified: real screen readers, real touch devices, Firefox / Safari, the old Save-on-change behaviour of the embedded
sub editors under every combination, custom-WAF saving with invalid SecLang through the bar (the validation is the server's and
is shown in the bar), and presets against the real apps (the settings come from each app's documentation, not from running it).
