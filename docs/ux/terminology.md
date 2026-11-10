# Terminology (decision D4)

Labels only. Ids, URLs (`#tag`), API paths, config keys and file names never change.

| Old label | New label | Where it applies | Unchanged |
|---|---|---|---|
| Ingress | **Listeners** | menu, breadcrumbs, palette, page title, tours, docs | tag `globalsettings`, `/api/proxy/...` and `/api/*` paths, CSS ids |
| Virtual Directories / Virtual Directory | **Path routes** / **Path route** | menu, page, SSO page text, palette | tag `vdir`, `/api/proxy/vdir/*`, the "Virtual directory" wording of History entries (backend label) |
| Advanced Rule Form | **Raw rule form** | menu, page title, Quick Start text | tag `rules` |

Plain-language subtitles (the line under each page title): Listeners "Where Zoraxy accepts visitors", Path routes "Send part of a site to a different place", Certificates "The certificates Zoraxy serves over HTTPS, when each one expires and which of your sites have none", ACME Client "Let Zoraxy request and renew free certificates", Access Rules "Choose who may reach your sites", Trusted Proxies "Which proxies in front of Zoraxy it may believe about the visitor's real address", SSO / OAuth2 "Put a login in front of your sites", CAPTCHA "Make visitors prove they are human", Security Center "Ban abusive clients automatically, block bots, ...".

Search words keep the old names (`kw` in `nav.js`: "ingress", "virtual directory", "advanced rule form"), so the palette still finds the page when someone types the old name.

Not renamed on purpose: the plugin API terms "static / dynamic capture ingress" (a different concept), and the proxy rule editor (`httprp.html`: tab "Virtual Directory", "Edit Virtual Directories"), which another change redesigns; rename it there.

Locales: `tools/i18n/extract.py` regenerates `en.json`; stale keys were pruned from every locale (translations of strings that only changed case were kept); zh-CN has the new labels.
