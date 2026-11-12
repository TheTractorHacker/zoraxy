# User-visible changes of the UX redesign

Newest first within each area. Each item names the page and what a user notices; design background is in [audit-2026-11.md](audit-2026-11.md), the components in [components.md](components.md).

## Database card and offline compaction
* **System > Settings > Database** (new card, admin only, read only): file size on disk, data inside, free space inside, table count, and a table list sorted by size (key count, stored size with a bar, one line on what each known table holds; the first 8 rows, "Show all N tables" for the rest). A large file (200 MB or more) gets a callout saying a Bolt file never shrinks by itself and that offline compaction is available; the "Compact the database file (offline)" help (opened automatically for a large file, otherwise collapsed) shows the exact commands with the real database path: stop the service, `./zoraxy -compact-db -dbpath <path>`, start the service. Nothing is deleted automatically.
* Why this page: Settings is the System page for the instance itself and already a stack of cards; System > Updater and History are about versions and configuration changes, and the card is a one-off look rather than a workflow. Viewers get a 403 from `GET /api/system/dbusage`, and the card hides itself for them. The endpoint reads in one read transaction and stops after 5 seconds ("counting stopped", sizes with a plus sign); it is not part of the `/api/v1` token API.
* `-compact-db` and the growth table of every sys.db table (what grows without a limit, existing caps, recommendations) are in [../db-growth.md](../db-growth.md). Finding: only the `stats` table grows with time and traffic (one record per day, never deleted, per-day caps only).
* **A second Zoraxy on the same database** no longer hangs silently. Opening BoltDB waits 10 seconds for the lock, then the process exits with status 1 and a message naming the file and the commands `sudo lsof <path>` and `ps -eo pid,etimes,args | grep [z]oraxy` (to the log and to stderr). LevelDB, which fails at once on a lock, gives the same message. Normal start-up is unchanged.

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
* **Central CAPTCHA provider**: the CAPTCHA page has a "Central provider" section (provider, site key, secret key, session length and provider options, saved with the Save bar, with a list of the sites that use it). In a proxy rule's CAPTCHA settings, "Provider settings" offers "Use central provider" or "Custom for this site"; with the central one the rule's key fields are hidden and a one-line summary links to the central page. Off by default: nothing changes until a central provider is saved and a site opts in. Paths, exceptions and page look stay per site. If a site uses the central provider while none is saved, it blocks the requests that need a CAPTCHA (it never lets them through). The secret is never shown again; leave the field empty to keep it.
* Rules and presets: the rules engine page and app presets are described in their own sections of DEVELOPMENT.md.

## Certificates
* **New proxy rule > HTTPS certificate** (new field under Domain, no need to open More options): pick which stored certificate the rule serves. Default **Automatic (match by hostname)**: nothing changes and the request is exactly what it was. The list is the same one the TLS tab uses, each entry with its expiry; once a hostname is typed the certificates that cover all of its names (exact or wildcard) are listed first and marked, and choosing one that does not cover a name shows a warning but does not block the rule. The hint under the field lists the names the chosen certificate covers. With no certificates the field says so and links to the Certificates page (the form keeps what was typed). API: `POST /api/proxy/add` (and `POST /api/v1/proxy-rules`) accept `certificate`; an unknown name is refused and nothing is created. The rule and the choice are saved together; the success toast names the certificate and does not offer "Create certificate for this host".
* **Why the choice also turns SNI matching off for that rule**: the server only looks at a rule's preferred certificate when SNI matching is off for that rule (the TLS tab greys the dropdowns out while "Enable SNI" is on). So choosing a certificate in the form stores it for the host and every alias and sets "Enable SNI" off on that rule only; the form says so. Other rules and the default are untouched. A wildcard rule key (`*.example.com`) is now honoured for the names it matches, so a chosen certificate also works for wildcard rules. With SNI matching on and several certificates covering a name, the automatic pick is whichever matches first and is not defined; choosing one removes that ambiguity.
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
