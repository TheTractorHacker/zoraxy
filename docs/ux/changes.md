# User-visible changes of the UX redesign

Newest first within each area. Each item names the page and what a user notices; design background is in [audit-2026-11.md](audit-2026-11.md), the components in [components.md](components.md).

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
* Host names, aliases, upstreams, tags, rule names and similar values from the configuration were inserted into pages without escaping on several pages (Path routes, Uptime Monitor, Redirection, Access Rules, Stream Proxy, Trusted Proxies, Wake on LAN, Plugins, upstream / alias / tag / access-rule editors, ...). They are escaped now.
* Status: the Upstream health card no longer makes the page scroll sideways on a phone when a host name is very long.
