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

## 7. WAF
- ✅ Request inspection layer after access rules (`Server.go`, marker `WAF-HOOK`) built on **Coraza** with the
  embedded **OWASP Core Rule Set** v4: per-endpoint mode (off / detection only / block), paranoia level 1-4,
  anomaly threshold, rule and path-scoped exclusions, validated custom SecLang rules, body limit with
  replay, gRPC and WebSocket passthrough, JSON audit log + in-memory events + counters, WAF tab with recent
  events and one-click exclusions (`feat/waf-coraza`).
- 📋 Add the WAF call to the shared pre-proxy chain / non-TLS path once that refactor lands.
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
