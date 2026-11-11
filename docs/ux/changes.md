# User-visible changes of the UX redesign

Newest first within each area. Each item names the page and what a user notices; design background is in [audit-2026-11.md](audit-2026-11.md), the components in [components.md](components.md).

## Admin sign-in session
* **Security Center > Admin accounts > Sign-in session** (new card): how long an admin stays signed in. Two number fields (minutes without "Remember me", days with it, ranges 5 to 43200 minutes and 1 to 365 days, with the current value in words), a checkbox **Keep me signed in while I am active** (sliding expiry) and a Save bar. The defaults are exactly the old fixed values (60 minutes, 7 days, sliding off), so nothing changes until an admin saves. A new value applies to the next sign-in without a restart; accounts that are already signed in keep the expiry they got (the card says so).
* Why this place: the setting is about admin accounts, the Admin accounts tab already holds sign-in related things (accounts, roles, audit log) and is admin-only; System settings is about the interface and visitor pages. Not added to the Security overview checks (no clear "good" value to score).
* Sliding expiry re-issues the cookie at most every 5 minutes (a quarter of the lifetime for short lifetimes), and only for page loads and changes, not for the background GET calls an open page makes, so an idle tab does not keep the session alive and the idle logout still works. The lifetime is also enforced on the server (not only by the cookie), and the cookie library's own 30 day limit is raised so a long "Remember me" is honoured.
* **Session expired**: when the session ends while a page is open (a 401, or the redirect to the login page that the server answers with), the admin UI shows one banner "Your session expired. Sign in again" with a link, instead of a stream of "Request failed" toasts and a login form injected into a panel.

## Navigation and search
* New menu: Overview, Sites, Security, Certificates, Traffic, Network, Fleet & HA, System (was six groups of about 30 pages). All old `#tag` links and saved menu state still work.
* Breadcrumbs on every page, a command palette (Ctrl+K) that finds pages, proxy hosts, settings and actions, and a menu filter (`/`).

## Look and feel
* One component kit (buttons, toggles, cards, tables, empty states, callouts, toasts, confirm dialog, help popovers) in light and dark, 390px mobile, keyboard and screen-reader rules. Living page under `-dev`: `/ui/kit.html`.
* One save model: forms use a **Save bar** with an unsaved-changes count, Discard and a leave guard (Listeners, Settings, Auto-ban); live toggles save at once with a toast.

## Security
* **Security Overview**: a 0-100 score with the evidence behind every check and one-click, previewable, reversible fixes.
* Every security page has a short subtitle, a **Related** box linking the pages that deal with the same concept (Access Rules, Auto-ban, Trusted Proxies, WAF, SSO, CAPTCHA, Security Overview) and a **History** shortcut. Jargon (trusted proxy gating, paranoia level, anomaly score, SNI) has a "what is this?" popover.
* Rules and presets: the rules engine page and app presets are described in their own sections of DEVELOPMENT.md.

## Certificates
* The Certificates page leads with stat tiles, an **Expiring soon** callout, **Hosts without a certificate** and the certificate list sorted by expiry with status chips; upload / paste / ACME request live in a collapsible **Add a certificate** card. ACME Client is reachable as a tab of the page.

## Overview
* Status gets a **Get started** checklist (first proxy rule, certificate, WAF, backup, notifications); the security score tile stays. Quick Start remains (tour code unchanged) and links to it.

## History and undo
* **System > History**: every configuration change creates a version; diff viewer, scoped restore with a dry-run preview. After a save, the toast offers **View history**, which opens History filtered to the changed object. Restores are never started from a toast.

## AI assistant
* Optional (off by default, own key or local model). Explain an event, turn plain English into a rule, and a configuration **audit** that reads the posture results (read only, never applies a fix); the audit appears when the assistant is enabled.

## Terminology
* Ingress is **Listeners**, Virtual Directories are **Path routes**, Advanced Rule Form is **Raw rule form** (see [terminology.md](terminology.md)).

## Fixes found on the way
* Host names, aliases, upstreams, tags, rule names and similar values from the configuration were inserted into pages without escaping on several pages (HTTP Proxy rule editor and lists, Path routes, Uptime Monitor, Redirection, Access Rules, Stream Proxy, Trusted Proxies, Wake on LAN, Plugins, upstream / alias / tag / access-rule editors, ...). They are escaped now.
* Status: the Upstream health card no longer makes the page scroll sideways on a phone when a host name is very long.
* Certificates, ACME, Statistics, Visitors, Uptime Monitor (audit follow-up, scenario `tools/ui-smoke/certs_traffic_smoke.py`): an upload reports the result of both files (and refuses non-PEM input in the browser and on the server) and cannot be double-submitted; every side drawer has a Close button and closes with Escape; the same toast message is shown once; `SendErrorResponse` JSON-escapes its message (a quoted value in an error no longer shows as "Request failed (HTTP 200)"); chart colours follow the light / dark switch; Escape closes the date picker; settings that are out of range are refused with a reason instead of silently clamped.
