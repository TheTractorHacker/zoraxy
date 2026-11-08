# Fork roadmap

Goal: turn Zoraxy into an advanced, production-grade reverse proxy while keeping it easy to run.
Every item ships with tests, keeps existing configs working (migrations where needed), and stays AGPL-3.0.
Borrowed code must come from AGPL-compatible projects (MIT/BSD/Apache-2.0/GPL-3.0) with attribution.

Status: ✅ done · 🔧 in progress · 📋 planned

## 0. Fixes already shipped
- ✅ gRPC bidirectional streams (NetBird Signal) deadlocked behind the #1204 body peek
  (`fix/grpc-bidi-stream-deadlock`, release `v3.3.5-rc5-grpcfix.1`).

## 1. Bugs and security (first)
- 📋 **CAPTCHA keeps re-challenging.** Sessions are in-memory (lost on every restart, not shared between
  nodes) and the duration field is raw seconds with no server-side minimum, so "30" means 30 seconds.
  Fix: HMAC-signed stateless session cookie (host-bound, survives restarts, works across HA nodes),
  duration input with minutes/hours/days units, server-side minimum, clear display of the effective value.
- 📋 Non-TLS path (`handleNonTLSRequest`: port-80 bypass and secondary ports) skips redirects, exploit
  detection and plugins. Share one pre-proxy chain between both paths.
- 📋 A GeoIP lookup error makes `IsBlacklisted` return false before the IP blacklist is checked.
- 📋 Admin and ZorxAuth passwords are unsalted SHA-512. Move to argon2id/bcrypt with transparent re-hash on login.
- 📋 Rate-limit counter is shared across all endpoints (keyed by IP only, reset every second).
  Per-endpoint buckets, token bucket with burst, optional per-path limits.
- 📋 Exploit regexes are recompiled on every request; TLS key pairs are read from disk on every handshake.
  Precompile and cache (with reload on cert change).
- ✅ `ExploitRequestResponseTypeCaptcha` returns "handled" without writing a response. Now shows the endpoint's CAPTCHA challenge (or the blocked page).
- 📋 Triage the open upstream issues mirrored here: reproduce each bug with a test, fix or close with evidence.

## 2. Admin panel
- 📋 **HTTPS for the admin UI.** Auto-generated self-signed certificate (ECDSA P-256, ~10-year validity,
  SANs for hostname, localhost and local IPs) stored under `conf/webui/`, or a user-supplied cert, or any
  cert managed by Zoraxy/ACME. Plain-HTTP requests on the same port get redirected to HTTPS. Secure cookies
  and HSTS when enabled. Plugins keep a loopback channel so nothing breaks.
- ✅ Bulk IP blocklist / whitelist import (paste, TXT/CSV upload, https URL with SSRF protection, dry run report,
  scheduled refresh of URL sources that only replaces the entries it added; upstream #512 / #661).
- 📋 Admin login hardening: rate limiting / lockout on login, optional TOTP for the admin account.

## 3. Bot protection and CAPTCHA pages
- ✅ Customisable challenge pages (fork issue #77): per-endpoint title, message, logo, colours and full custom HTML template,
  edited and previewed from the UI (the `<webroot>/templates/` override already exists; this adds UI and
  per-endpoint selection).
- ✅ Separate pages for "challenge", "verification failed" and "blocked".
- ✅ Turnstile options: widget mode (managed/non-interactive/invisible), appearance, action/cData binding,
  hostname check of the siteverify response.

## 4. Authentication
- 🔧 **Authentik** (#78): forward auth through the proxy outpost (single application and domain level) and OIDC via the
  OAuth2/OpenID provider, with UI presets and `docs/authentik.md`.
  - ✅ Forward auth: outpost callback path proxied on the protected host, sign-in redirect with a server built `rd`,
    Host preservation, `X-authentik-*` wildcard copy and spoofed header stripping, bounded timeouts, fail closed.
  - ✅ OIDC: discovery by issuer, PKCE S256, state (browser bound) + nonce, ID token validation with cached JWKS,
    refresh, RP-initiated logout, group allow-list, claim to header mapping, discovery test button.
  - 📋 Verified only against fake outpost/OIDC servers so far; run the checklist in `docs/authentik.md` against a real Authentik.
- ✅ Per-endpoint exception rules (path prefix / exact / regex, IP / CIDR) for Forward Auth and OAuth2/OIDC, trusted-proxy aware and
  traversal safe (upstream #652).
- 🔧 Generic OIDC hardening: ✅ discovery, PKCE, token refresh, logout. 📋 group-based policies per route (the
  allow-list is currently global to the OAuth2 provider); 📋 stateless/shared sessions (see HA).

## 5. Load balancing (beyond weighted random)
- ✅ Algorithms (#79): round robin, smooth weighted round robin, least connections, least response time, IP hash,
  consistent hash on header or cookie (ring with virtual nodes), power of two choices. Hash on path: 📋.
- ✅ **Active health checks** (#80): HTTP or TCP, path, method, interval, timeout, expected status range, body match,
  rise/fall thresholds, per endpoint with optional per-upstream override (API only, no UI yet).
- ✅ Passive health checks (#80): eject after N consecutive failures, cooldown, slow-start on recovery.
- ✅ Retries on another upstream for idempotent requests, per-upstream max in-flight, draining (#80).
- Inspiration: HAProxy, Envoy, Traefik, Caddy (Apache-2.0), nginx.

## 6. High availability
- ✅ Shared session state (#81): optional cluster secret (`-cluster_secret` / `conf/cluster.json`) keys the CAPTCHA and
  sticky-session cookies with HKDF so any node accepts them; unset = unchanged. 📋 ZorxAuth (SSO portal) sessions are
  still per node (database backed random IDs).
- ✅ Cluster config sync (#81): primary exposes a signed, encrypted, versioned snapshot; followers poll, apply atomically
  with backup, rollback and a boot guard; primary wins (follower edits refused). Cluster / HA page with node list.
  📋 Database-stored settings (inbound port, SSO provider config, ZorxAuth users) are not synced yet.
- ✅ Certificate sync with a single ACME issuer (#81): optional, primary only (followers get renewal switched off).
- ✅ Virtual IP failover guide (keepalived/VRRP, HAProxy/nginx) and `GET /.zoraxy/health` (+ `-health_port`) (#81).
- ✅ **Central management (Fleet)**: hub role with one time join tokens and per node keys (revoke, rotate), pinned https join,
  pluggable config scopes (proxy rules with tag filter, redirects, access + trusted proxies, path rules, stream proxy, ACME,
  certificates) with node-local objects kept and hub-wins conflicts reported, groups and per node variables, versioned config with
  diff, immediate / manual / canary rollout with automatic halt and rollback, Fleet dashboard (status, drift, bounded telemetry,
  aggregates), audit log. No remote command execution. See DEVELOPMENT.md "Central management (Fleet)".
  📋 Central WAF scope (register a `cluster.Scope` once `feat/central-waf` is merged); 📋 settings stored in the database (inbound
  port, SSO provider config, ZorxAuth users) are not part of any scope yet; 📋 hub high availability (one hub, cold standby by copying
  `conf/.cluster`); 📋 mTLS / Ed25519 signed bundles instead of HMAC.

## 7. WAF
- ✅ Request inspection layer after access rules (`Server.go`, marker `WAF-HOOK`) built on **Coraza** with the
  embedded **OWASP Core Rule Set** v4: per-endpoint mode (off / detection only / block), paranoia level 1-4,
  anomaly threshold, rule and path-scoped exclusions, validated custom SecLang rules, body limit with
  replay, gRPC and WebSocket passthrough, JSON audit log + in-memory events + counters, WAF tab with recent
  events and one-click exclusions (`feat/waf-coraza`).
- ✅ WAF runs in the shared pre-proxy chain, so the non-TLS path is covered.
- ✅ **Central WAF** (`feat/central-waf`): global policy, inherit/off/detection/block/profile/custom per rule, built-in and custom profiles,
  global exclusions and trusted path / IP bypass, Security > WAF page (policy, profiles, exclusions, events across all rules, rules reference,
  coverage), cluster replication, metrics. See DEVELOPMENT.md.
- 📋 Central WAF follow-ups: per-profile CRS application exclusion packs (the embedded CRS has no REQUEST-903 files), time-boxed exclusions, event export.
- 📋 Response inspection (CRS RESPONSE-* rules), per-path paranoia level, CRS version update flow, WAF metrics.
- 📋 Replace the regex exploit detector with WAF rules, or keep it as a lightweight mode.

## 8. Plugins / add-ons
- 📋 Pre-auth hook stage (so plugins can act as WAF/bot filters), request/response modification
  middleware (add headers and continue), body access for dynamic capture, sniff timeouts, global plugins
  that do not need endpoint tags.

## 9. Observability
- ✅ Prometheus metrics (`-metrics`, `-metrics_port`, `/api/metrics`, see DEVELOPMENT.md) incl. per-upstream health/in-flight/EWMA, WAF, CAPTCHA, rate limit and certificate expiry.
- 📋 Structured JSON access logs.
- 📋 Prometheus metrics endpoint, structured JSON access logs, per-upstream latency/error stats.

## 10. Triage batch 2 (fixed in `fix/triage-bugs-2`)
- ✅ Per-upstream connection reuse switch (#1343), ACME issuance serialised (#1117), proxy rule edit is a true partial update (#1109),
  precompiled IP blacklist index (#986), opt-in client IP header sanitising (#1359), map typed ACME DNS credentials incl. selfhost.de
  and Hurricane Electric (#1067, #410), per-upstream h2c (#1029).
- 🔧 GeoIP (#1334): Malaysian IPv6 prefixes are pinned by an overrides table. 📋 Switch to a maintained dataset (licence decision) and
  regenerate `geoipv4.csv` / `geoipv6.csv`; `tools` updater still downloads the deprecated npm package.
- 📋 Whitelist lookup still scans linearly (same index idea as the blacklist). 📋 h2c: apply the response-header timeout.

## 11. Networking (`feat/networking-1`)
- ✅ Per-rule client certificate authentication (mTLS): request / require / require_and_verify, CA bundle, allow and block lists, identity headers (upstream #442). 📋 CRL / OCSP revocation.
- ✅ Upstream mTLS (client certificate from the certificate store) and PROXY protocol v1/v2 towards HTTP upstreams. 📋 WebSocket/CONNECT paths, per-visitor address behind a CDN, stream proxy.
- ✅ TLS on secondary listening ports (upstream #1042).
- ✅ Path scoped allow / deny / require-auth / rate-limit rules with normalised matching and CIDR/country scopes (upstream #238, #726).
- ✅ "Direct TCP peer must be in this CIDR set" per rule (upstream #761).
- ✅ Opt-in rate limited logging of default site requests (upstream #578).
- ✅ Run plugins as an unprivileged OS user, `-plugin_user` / `-plugin_group` (upstream #760). 📋 Per-plugin user, automatic ownership fix.
- ✅ Network diagnostics: DNS lookup, TLS certificate inspector, HTTP request tester with metadata address guard.

## 11. Certificates and ACME batch (`feat/certs-acme-2`)
- ✅ ACME key type selection (#1123), staging CA + saved custom CA profiles with EAB (#408, #1267), reusable DNS credential profiles
  with a default profile (#1332, #380), CSR generation + pairing (#433), certificates from a watched directory (#798), certificate
  event webhooks and an opt-in command hook (#496/#899 certificate part), `-offline` mode (#782), richer certificate list with
  renew-now log.
- 📋 Notification sources beyond certificates (uptime, WAF) can reuse `mod/notify`; per-event retry persistence (undelivered webhooks are
  dropped after the retry window); webhook delivery log in the UI; DNS profile selection inside the proxy rule dialog itself
  (`httprp.html` is owned by the networking work); ARI (renewal information) support when lego exposes it; Encrypted Client Hello (#1319) is out of scope.

## 12. Statistics, logs and notifications (`feat/stats-logs-notify`)
- ✅ Per-site statistics with a site filter, comparison table and sparklines (#349, #764); status code and top path tables.
- ✅ Statistics filters: exclude own IP/CIDR (one-click "add my IP"), exclude blocked requests, URL query strip/mask/full for "top requested paths" (#352, #1344, #1354).
- ✅ Stream proxies in the Status network diagram (#1186); at-a-glance overview (requests/min, error rate, blocked, upstream health, certificate expiry, alerts).
- ✅ Per-site log files with size/age/count retention, gzip, text or JSON lines (#596); access log search with filters, live tail, CSV/JSON export (#1243).
- ✅ Notification centre: Discord, Slack, Telegram, ntfy, Gotify, Pushover, SMTP channels, subscriptions, quiet hours, dedupe, rate limit, digest, retry/backoff,
  delivery log, webhook JSON templates; events for uptime (flap suppressed), WAF spikes, fleet nodes, admin logins, updates (#1046, #899).
- ✅ Dynamic capture sniff payload carries the matched rule (#1351).
- 📋 Persist the delivery log and undelivered messages across restarts; per-site statistics for the status-code/country dimension of the global map; notification
  events for auto-ban and certificate renewal are emitted by their own modules through `notify.Emit` (see DEVELOPMENT.md).
## Security and access (feat/security-access-2)

Done (all opt-in): built-in auto-ban + remote ban API, multiple admin accounts with viewer role and audit log, challenge countries,
drop-on-block, access rule sort / duplicate, bot rules, header rules, shared basic auth lists + path scoped basic auth, auth audit and
auto-tagging, OAuth2 / OIDC claim and e-mail allow-lists, Altcha CAPTCHA.

Open: multiple OIDC / OAuth2 providers selectable per proxy rule (needs one `OAuth2Router` per provider and per-provider callback paths),
FriendlyCaptcha, counting SSO redirect failures in the auto-ban, per-user admin API tokens, fine grained roles beyond admin / viewer.
## 12. Proxy behaviour and ops (`feat/proxy-ops-2`)
- ✅ Global / per-rule error pages with html/template, Retry-After, request id (upstream #313); streaming, gRPC and WebSocket responses are never replaced.
- ✅ Static responses served without the upstream, public or behind auth (upstream #431).
- ✅ Unix domain socket upstreams `unix:/path.sock` (upstream #663). 📋 WebSocket and the passive uptime monitor over a socket.
- ✅ Load balancing by client CIDR / country with fallback (upstream #677).
- ✅ Proxy handled CORS with preflight (upstream #680).
- ✅ Opt-in backtracking regex engine for redirect rules, hard match timeout (upstream #689).
- ✅ `{{host}}` `{{client_ip}}` `{{request_id}}` `{{rule_name}}` `{{external_ip}}` in headers, redirects, static responses; rule templates; bulk edit (upstream #370 #826 #877 #924).
- ✅ API tokens + `/api/v1` + OpenAPI (upstream #382 #714 #996), response bandwidth limit (upstream #1208), plain HTTP listener address (#909), IP calculators (#504), opt-in split-horizon DNS responder (#769).
- 📋 UI editor for custom rule templates (API exists), bandwidth limit for WebSocket traffic.

### Closure verification follow-ups (fix/closure-bugs)

* Optional: "Reset all ACME state" button (upstream #1193 c), literal `CF-IPCountry` support gated on trusted peers (#831), smoother nav chevron + divider under default site (#1201, belongs to the nav rework).
* Open for reporter evidence: Infomaniak punycode zone (#458), Authelia v3.2.3 redirect (#698), VoidAuth (#958), oauth2-proxy behind Cloudflare Tunnel (#1032), Uptime Kuma chain (#403), Let's Encrypt 400 (#537). See `docs/triage/closure-bugs.md`.
## Support closure (`docs/support-closure`)
- ✅ 14 task guides under `docs/guides/` answering the mirrored support questions; fixes: virtual directory longest match and WebSocket base path,
  blank DNS credential fields, logged upstream failure reasons, error page host variable, pprof endpoints, access rule help text.
- 📋 Forward-auth subrequest should send the Trusted Proxy resolved client IP to Authelia/Authentik. 📋 Real-instance runs of the Authentik, Keycloak,
  Google and Pocket ID guides. 📋 Per-route group policies (see section 4). 📋 Publish a container image from the fork (needs Docker Hub credentials).
## 13. Auth and CAPTCHA remaining items (`feat/auth-captcha-remaining`)
- ✅ Multiple OIDC / OAuth2 providers, selectable per proxy rule (fork #172 / #223, upstream #884 / #1162): provider registry, per-provider
  callback path and cookie, provider manager on the SSO page, per-rule provider and extra allow-lists. The legacy single configuration
  is migrated to the provider `default`.
- ✅ OIDC sessions persisted encrypted at rest (fork #212), shared across HA nodes through a short lived portable ticket when a cluster secret is set.
- ✅ Friendly Captcha v2 provider (fork #228 / upstream #1198), incl. the EU endpoint.
- ✅ CAPTCHA path exceptions in exact and regex mode with canonical-path-only matching (fork #222 / upstream #1161).
- ✅ Role claim shapes (Keycloak realm / client roles, Entra roles and groups, Authentik groups, Google hd) tested and documented (fork #172).
- 📋 Per path (not per rule) provider selection; a rule-level override that widens (instead of narrowing) the provider's allow-lists; real-IdP verification of Entra, Google and GitHub presets.
## UI performance, Status page, Visitors (`feat/ui-perf-status-visitors`)
- ✅ Idle admin UI CPU cut (endless accordion re-init loop, background polling of hidden pages, MutationObserver scans, canvas traffic map); `tools/ui-perf`.
- ✅ Status page: KPI cards with skeletons, traffic over time chart, upstream / certificate / alert lists, latest visitors, traffic map hide / pause.
- ✅ Visitors list (per IP, recent visits, Cloudflare aware, retention, export, purge, per IP delete, optional new-country notification).
- 📋 Visitors: city level GeoIP, per-host retention, hourly history chart on the Status page, virtualised rows for very large pages.
## Proxy UX (`feat/ui-proxy-ux`)
- ✅ HTTP proxy list rebuilt: status pill with undo, search, status and tag filters, sorting, pagination, shift-click multi-select with a sticky bulk bar.
- ✅ Navigation regrouped into Proxy / Security / Certificates / Observability / Tools / System; saved menu state migrated.
- ✅ "New proxy rule" dialog with live upstream test and HTTPS auto-detection; the full form stays as Advanced Rule Form.
- ✅ Quick Start hides once an instance is set up or dismissed (stored server side), "Show Quick Start again" in Ingress.
- 📋 Per-rule request count / sparkline in the list (needs a cheap per-host aggregate), editing custom rule templates in the UI, a "create certificate" action that handles wildcard domains through DNS challenge from the dialog.
## 13. Platform features (`feat/platform-features`)
- ✅ **Encrypted Client Hello** (fork #235 / upstream #1319): server side ECH with HPKE key generation, rotation (newest key advertised, older keys decrypt-only for a retain
  window), PEM import / export, per-handshake hot reload through `GetEncryptedClientHelloKeys` (kept by the per-SNI mTLS clones, also on HTTP/3), ECHConfigList + HTTPS record
  example, DNS HTTPS record check. 📋 Automatic DNS publishing through a provider API; 📋 per-rule hostname selection; 📋 verification against real browsers.
- ✅ **Lua scripts** (fork #88 / upstream #367): sandboxed per-rule script handler / hook (gopher-lua, step-budgeted patterns, time / heap / size limits, KV, JSON, crypto helpers),
  admin test run. 📋 Script versions and diff, a shared library of snippets, per-script metrics.
- ✅ **Sablier** (fork #120 / upstream #564): native dynamic / blocking strategies per rule, ready cache, fail open / closed, SSRF-safe URL. 📋 Verified only against a fake Sablier.
- ✅ **zrok** (fork #63 / upstream #136): supervised zrok CLI behind `-allow_external_tools` (shares, reserved names on 1.x, private access, backoff, redacted logs).
  📋 Verified only against a fake zrok binary; 📋 zrok agent mode and a Windows path.
