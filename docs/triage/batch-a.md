# Triage batch A: upstream issues #22 to #764

Branch `triage/batch-a`, based on fork `dev`. 77 open upstream issues. Issue text is treated as untrusted data.

## Counts

* feature-request: 42
* support-question: 19
* already-fixed: 5
* needs-hardware-or-env: 3
* fixed-by-you: 3
* duplicate: 3
* cannot-reproduce: 2

Verdict meanings: `already-fixed` needs file/test evidence; `fixed-by-you` has a commit on this branch with a test (JS-only fix #611 has none, noted); `real-bug-open` none were confirmed that were too large to fix (see notes); unverified UI behaviour is stated explicitly.

## Table

| # | Title | Verdict | Summary |
|---|---|---|---|
| 22 | Fail2ban features | feature-request | Fail2ban-style brute-force protection. |
| 33 | Include forward authentication support | already-fixed | Forward authentication (Authelia/Authentik/Keycloak style) in the UI. |
| 89 | Multi account accès webmin page | feature-request | Multiple admin accounts for the management UI. |
| 136 | Zrok support (similar to ZeroTier, FOSS) | feature-request | Built-in Zrok support (like ZeroTier). |
| 166 | Can you add Chinese Simplified Chinese? | feature-request | Simplified Chinese UI. |
| 183 | Cluster capability? | feature-request | Cluster / HA capability. |
| 236 | Multilanguage support | feature-request | Multi-language UI. |
| 238 | block / restict access to a sub path/location | feature-request | Restrict access to a sub path (e.g. /admin LAN only). |
| 281 | Regional Challenge Page | feature-request | Challenge (CAPTCHA) instead of block for selected countries. |
| 313 | global 'error_page' for HTTP status codes | feature-request | Global error pages for upstream status codes (proxy_intercept_errors). |
| 314 | Using with odoo > problem with the websocket | support-question | Odoo websocket (/websocket on port 8072) fails behind a virtual directory. |
| 331 | Json: cannot unmarshal string into Go struct field Config.MaxRetries of type int | already-fixed | Route 53 DNS challenge: 'cannot unmarshal string into Config.MaxRetries of type int'. |
| 349 | Filter Statistics per Site | feature-request | Filter statistics per site. |
| 352 | Exclude Own IP or make filter by gui | feature-request | Exclude own IP from statistics. |
| 366 | Source IP Changed when using tcp stream to mail, have to use a header like x forwarded for? | support-question | Source IP lost when forwarding SMTP via TCP stream proxy. |
| 367 | Lua scripts | feature-request | Serve Lua scripts instead of a backend. |
| 370 | Variables and Aliasing | feature-request | Variables/aliases (e.g. {{external_ip}}) in rules. |
| 379 | Ability to Disable Weak Ciphers in ACME Registration Menu | already-fixed | Disable weak (CBC-SHA1/3DES) ciphers. |
| 380 | Ability to opt into DNS Challenge Automatically for Certificate Registration when making a New Proxy Rule | feature-request | Pre-select DNS challenge when creating a proxy rule. |
| 382 | RESTful API to list or create proxy records | feature-request | REST API to list/create proxy records. |
| 386 | Not possible to create an SSL certificate | support-question | ACME HTTP-01 gets 404 (Docker, DDNS domain). |
| 403 | Uptime Kuma weird behavior with Zoraxy | needs-hardware-or-env | Uptime Kuma intermittently reports ECONNREFUSED / 'unable to verify the first certificate'. |
| 408 | Staging ACME Provider | feature-request | Staging ACME provider. |
| 410 | Add DNS Challenege Provider he.net | feature-request | Hurricane Electric (he.net) DNS provider. |
| 417 | How to create additional locations for a domain | support-question | How to proxy only /api, /local, /media of a host (nginx location regex). |
| 418 | URL rewrite for static files | support-question | Static files 404 when an app is mounted under a virtual directory /app/. |
| 431 | Robots.txt file option or crawler discouragment or static file responses in virtual directories | feature-request | robots.txt / static response per host or vdir. |
| 433 | SSL Certificate CSR request | feature-request | Generate CSR in the UI. |
| 442 | Mtls | feature-request | Mutual TLS (client certificate auth). |
| 446 | Domoticz not working properly | support-question | Domoticz/OctoPrint resources return 404 behind Zoraxy. |
| 458 | Problem with punycode domains | needs-hardware-or-env | Punycode (IDN) domain fails with Infomaniak DNS challenge ('domain not found eu'). |
| 459 | Expire At is not recognized | fixed-by-you | Certificate shows 'Unknown' expiry when the PEM starts with a PUBLIC KEY block. |
| 461 | Expose Monitoring Data for Prometheus | feature-request | Prometheus metrics endpoint. |
| 490 | ACME module not compatible with "Allow plain HTTP access" option | already-fixed | ACME fails (403) once any proxy rule has 'Allow plain HTTP access'. |
| 494 | How to Update Zoraxy instance | support-question | How to update a bare-metal Zoraxy. |
| 496 | certs renew-hooks | feature-request | Hooks after certificate renewal. |
| 501 | Change username | feature-request | Change the admin username. |
| 504 | IPv6 Calulator | feature-request | IPv6 calculator in the toolbox. |
| 512 | Import of multiple IPs into IP Blacklist / Access Control | feature-request | Bulk import IPs/CIDRs into the blacklist. |
| 513 | Force certificate requests and replies over IPv4. Letsencrypt errors. Dual stack IPv6. | support-question | Let's Encrypt validates over IPv6 (AAAA) and hits a different server. |
| 514 | Send client IP to proxy host | support-question | Backend sees Zoraxy's IP instead of the client IP. |
| 518 | Allow email send without authentication to port 25 | cannot-reproduce | Allow SMTP without authentication. |
| 537 | Error 400 during renew Let's encrypt certificates | cannot-reproduce | LE renewal error 400 'Error getting validation data'. |
| 543 | Proxy Host not resolving without invalid cert warning via HTTPS despite valid SSL Cert | support-question | Certificate warning for a proxied Synology on macvlan. |
| 561 | Zoraxy Docker, Statistics of actual day is lost when reboot | already-fixed | Today's statistics lost on container restart. |
| 564 | Add Sablier compatibility | feature-request | Sablier (scale-to-zero) compatibility. |
| 578 | Entry for 404 Error in Log. | feature-request | Log requests answered by the default-site 404. |
| 590 | Show the correct public IP | support-question | Backend shows Zoraxy IP not public IP. |
| 596 | Separate Logs Per Site | feature-request | Separate log files per site. |
| 611 | Filename cannot be empty for certs containing multiple domains | fixed-by-you | 'Filename cannot be empty for certs containing multiple domains' when obtaining a cert for a host with aliases. |
| 612 | ACL Not Working | support-question | Access rule blocks WireGuard clients (sees VPN server IP). |
| 615 | Bot Blocking Capabilities | feature-request | Bot blocking (user-agent rules, known bad bot lists). |
| 621 | Basic Authentication für die "Virtual Directory"-Einstellungen | feature-request | Basic auth only for a virtual directory (/admin). |
| 622 | CleanSlate deployment errors with ZORAXY and websocket connections | support-question | Websocket 'bad handshake' to graphql backend. |
| 648 | Crowdsec needs live logs? | support-question | CrowdSec needs live logs. |
| 652 | Bypass Authentik/Authelia | feature-request | Bypass forward-auth for server-to-server calls. |
| 655 | Odd errors appearing in the container logs. Possibly a leak being triggered from external source? | fixed-by-you | ACME relay logs 'connection refused' and answers 200 to scanner probes of /.well-known/acme-challenge/. |
| 660 | Metrics exposed in Prometheus format | duplicate | Prometheus metrics. |
| 661 | Import blocklist of IP addresses | duplicate | Import IP blocklist (TXT). |
| 663 | Proxy to unix socket file | feature-request | Proxy to unix socket. |
| 665 | Default Website certificate error | support-question | Certificate error when hitting the default site by IP. |
| 676 | Automatically pass through the real IP instead of the cloudflare IP's | support-question | Pass the real client IP instead of Cloudflare's. |
| 677 | Load balance based on IP/Region/CIDR/IP Range | feature-request | Load balance by client IP/region/CIDR. |
| 680 | CORS Error with Immich | feature-request | Answer CORS preflight (OPTIONS) in the proxy. |
| 681 | Can not add a DNS Challenge | support-question | How to configure PowerDNS provider (udmedia.de). |
| 689 | Adding Regexp2 | feature-request | Lookahead/lookbehind regex in redirect rules. |
| 698 | Forward Auth Redirection error in v3.2.3 | needs-hardware-or-env | Authentik forward auth gives redirect errors / 400. |
| 714 | Simple API for Managing Proxy Rules & Access Control | duplicate | Simple API for proxy rules and ACLs. |
| 726 | limit request based on uri path | feature-request | Rate limit by URI path. |
| 741 | enable CodeQL Scanning (part of GitHub advanced security) | feature-request | CodeQL scanning. |
| 749 | Cannot get Authelia & Zoraxys to work | support-question | Authelia unreachable via domain (404). |
| 750 | Certificate on a Local only proxy | support-question | Certificate for a LAN-only host. |
| 754 | [tracker] Plugin System Improvements | feature-request | Tracker: plugin system improvements. |
| 760 | run plugins as unpriviledged user | feature-request | Run plugins as an unprivileged user. |
| 761 | Access control by Cloudflare IPs | feature-request | Only accept connections from Cloudflare IPs. |
| 762 | Duplicate & Sort Access Control Rules | feature-request | Sort and duplicate access rules. |
| 764 | Statistics and logging for each proxy | feature-request | Per-proxy statistics and logs view. |

## Details

### #22 Fail2ban features
* Verdict: **feature-request**
* Evidence / analysis: No fail2ban integration in dev. Closest pieces: per-endpoint rate limit (ratelimit.go), WAF (Coraza/CRS), access blacklist; logs are plain text under the log folder so external fail2ban/CrowdSec can read them (see #578, #648). Roadmap sections 1 (admin login lockout) and 9 (structured JSON access logs) are the right vehicles. Value M, effort M (login lockout S, auto-ban from 401/403 counts M).

### #33 Include forward authentication support
* Verdict: **already-fixed**; proposed close
* Evidence / analysis: AuthMethodForward in src/mod/dynamicproxy/authProviders.go (handleForwardAuth), generic forward auth module src/mod/auth/sso/forward, Authentik presets + OIDC in the fork (mod/auth/sso/forward/authentik_test.go, docs/authentik.md; ROADMAP section 4). Not verified against a real Authentik (fork issue #213).
* Proposed reply: Forward auth is available in the HTTP proxy rule editor (Authentication provider -> Forward Auth), including Authentik presets and OIDC on this fork (see `docs/authentik.md`). Closing; open specific bugs separately.

### #89 Multi account accès webmin page
* Verdict: **feature-request**
* Evidence / analysis: Admin auth is a single user (src/mod/auth). ZorxAuth (site SSO) has multiple users but that is for proxied sites, not the admin panel. Effort L (user model, roles, audit); maintainers' stance upstream was 'put an auth gateway in front'. With OIDC support now in the fork, an SSO-protected admin panel is the more realistic route. Value M, effort L.

### #136 Zrok support (similar to ZeroTier, FOSS)
* Verdict: **feature-request**
* Evidence / analysis: Not present. Zrok can be run as a sidecar/plugin that exposes a local port. Better suited to the plugin system than core. Value low, effort M.

### #166 Can you add Chinese Simplified Chinese?
* Verdict: **feature-request**
* Evidence / analysis: No i18n framework in the admin UI (strings hard-coded in src/web/*.html). Tied to #236. Value M, effort L (extract strings, translation files, language switch).

### #183 Cluster capability?
* Verdict: **feature-request**
* Evidence / analysis: Maps to ROADMAP section 6 (config sync, stateless sessions, certificate sync, keepalived guide). Already partly done in the fork: stateless CAPTCHA sessions. Cluster work is in flight elsewhere, so not touched. Interim answer from upstream thread: run two nodes with the same config and keepalived/VRRP.

### #236 Multilanguage support
* Verdict: **feature-request**
* Evidence / analysis: Same as #166: no i18n layer. Value M, effort L.

### #238 block / restict access to a sub path/location
* Verdict: **feature-request**
* Evidence / analysis: Access rules attach to a whole host endpoint (runEndpointChain in src/mod/dynamicproxy/Server.go), not to a vdir/path. Basic auth has path/CIDR exception rules but no path-scoped allow list. Related fork roadmap item: per-path rate limits (section 1) and WAF path-scoped rules (WAF custom SecLang can already deny a path from non-LAN IPs: SecRule REQUEST_URI "@beginsWith /admin" chained with REMOTE_ADDR !@ipMatch ...). Value H, effort M.

### #281 Regional Challenge Page
* Verdict: **feature-request**
* Evidence / analysis: GeoIP block/allow exists; the fork has per-endpoint CAPTCHA with customisable pages (roadmap section 3, fork #77) but no 'challenge when country is X' action. Reasonable small addition: add a country list to the CAPTCHA trigger. Value M, effort M.

### #313 global 'error_page' for HTTP status codes
* Verdict: **feature-request**
* Evidence / analysis: Only the default-site 404 template (<webroot>/templates/notfound.html) and the host error page are customisable; upstream error status codes are passed through. Value M, effort M.

### #314 Using with odoo > problem with the websocket
* Verdict: **support-question**
* Evidence / analysis: Virtual directories strip the matching prefix before forwarding (rewriteURL in src/mod/dynamicproxy/proxyRequestHandler.go), so a vdir '/websocket' -> http://odoochat:8072 reaches Odoo as '/' not '/websocket' (nginx's proxy_pass without URI keeps the path). Unverified here (no Odoo). Suggested reply below.
* Proposed reply: Zoraxy strips the vdir prefix, unlike `proxy_pass http://odoochat;`. Try giving the virtual directory `/websocket` the target `odoochat-host:8072/websocket` (include the path in the target) so the prefix is re-added upstream. Also make sure the proxied host keeps the original Host header and that Odoo has `proxy_mode = True`. If that still fails please post the websocket request/response headers.

### #331 Json: cannot unmarshal string into Go struct field Config.MaxRetries of type int
* Verdict: **already-fixed** (fork commit `583fb4d`); proposed close
* Evidence / analysis: UI builds int fields from number inputs (class typeint in src/web/snippet/acme.html readDnsCredentials, parseInt) so the payload carries a JSON number. Test mod/acme/acme_dns_int_test.go (commit 583fb4d) shows numeric MaxRetries accepted and a string value still produces the quoted error, i.e. only a payload from an old UI/stale saved credentials can trigger it. Residual: credentials saved by an old UI keep the string; re-save them.
* Proposed reply: Fixed: the ACME UI now sends integer provider fields (e.g. `MaxRetries`) as JSON numbers; covered by `TestRoute53IntCredentialFieldsAccepted`. If you saved Route 53 credentials with an old version, re-enter and save them once.

### #349 Filter Statistics per Site
* Verdict: **feature-request**
* Evidence / analysis: Statistics are global (src/mod/statistic, analytic loader). The data model keeps per-host maps so a host filter is feasible. Overlaps #764 and #596. Value M, effort M.

### #352 Exclude Own IP or make filter by gui
* Verdict: **feature-request**
* Evidence / analysis: No ignore list in statistic.RecordRequest. Value M, effort S (ignore CIDR list option in the collector).

### #366 Source IP Changed when using tcp stream to mail, have to use a header like x forwarded for?
* Verdict: **support-question**
* Evidence / analysis: Stream proxy supports PROXY protocol v1/v2 (ProxyProtocolV1/V2 in src/mod/streamproxy/streamproxy.go), which is exactly the answer for mail. Backend (Proxmox Mail Gateway/Postfix postscreen) must be configured to accept it.
* Proposed reply: Enable **PROXY protocol** (v1 or v2) on the TCP proxy rule and configure the receiving MTA to expect it (Postfix: `postscreen_upstream_proxy_protocol = haproxy`). A plain TCP stream always shows Zoraxy's own IP as source, headers like X-Forwarded-For do not exist for SMTP.

### #367 Lua scripts
* Verdict: **feature-request**
* Evidence / analysis: Out of scope for core; plugin territory (fork roadmap section 8). Value low, effort L.

### #370 Variables and Aliasing
* Verdict: **feature-request**
* Evidence / analysis: Not present. Low value; the same need is met by trusted-proxy lists and access rules. Effort M.

### #379 Ability to Disable Weak Ciphers in ACME Registration Menu
* Verdict: **already-fixed**; proposed close
* Evidence / analysis: TLS cipher profile setting (Global settings -> TLS cipher profile; src/mod/dynamicproxy/tlscipherprofile.go, tests tlscipherprofile_test.go): 'intermediate' removes CBC-SHA1 suites, 'modern' is TLS 1.3 only. 3DES is already disabled in Go.
* Proposed reply: Available now: System Settings -> TLS cipher profile (`intermediate` = Mozilla intermediate AEAD-only TLS 1.2 suites, `modern` = TLS 1.3 only). Closing.

### #380 Ability to opt into DNS Challenge Automatically for Certificate Registration when making a New Proxy Rule
* Verdict: **feature-request**
* Evidence / analysis: UI-only convenience: new-rule flow calls obtainCertificate(..., dns=false) in web/components/rules.html. Value L-M, effort S.

### #382 RESTful API to list or create proxy records
* Verdict: **feature-request**
* Evidence / analysis: Internal /api/* endpoints exist but are cookie+CSRF authenticated for the UI; plugins have API keys (ROADMAP section 8). A documented token-based API would be new. Related fork roadmap: Swagger docs (fork #197 mirrors upstream). Value H, effort M.

### #386 Not possible to create an SSL certificate
* Verdict: **support-question**
* Evidence / analysis: A 404 for /.well-known/acme-challenge/<token> means the request did not reach Zoraxy's ACME relay (another service on port 80, router forwarding port 80 elsewhere) or Zoraxy was not listening on 80. dev fixes one real cause (c0d317e: host with a proxy rule + plain-HTTP listener returned 400 for challenges). Cannot verify reporter's network.
* Proposed reply: A 404 from Let's Encrypt means the challenge request was answered by something other than Zoraxy. Check that external port 80 is forwarded to the Zoraxy container's port 80 (and that 'Enable HTTP server on port 80' is on), and that no other service (NAS web server, router UI) answers on 80. Test with `curl -v http://yourdomain/.well-known/acme-challenge/test` from outside; it should return 400/404 from Zoraxy, not a foreign page. If the domain also has an AAAA record make sure IPv6 reaches Zoraxy as well.

### #403 Uptime Kuma weird behavior with Zoraxy
* Verdict: **needs-hardware-or-env**
* Evidence / analysis: 'unable to verify the first certificate' is the classic missing-intermediate-chain symptom: the served PEM must contain leaf + chain (Zoraxy serves the uploaded file as is). ECONNREFUSED comes from upstream/Docker networking. Not reproducible without the reporter's environment.

### #408 Staging ACME Provider
* Verdict: **feature-request**
* Evidence / analysis: A global flag -acmetestmode switches every CA to its staging URL (src/def.go, src/mod/acme/ca.json 'Test' map), but there is no per-request toggle in the UI. Value M, effort S.

### #410 Add DNS Challenege Provider he.net
* Verdict: **feature-request**
* Evidence / analysis: lego v5.5.2 ships dns/hurricane but it is absent from src/mod/acme/acmedns/providers.json and acmedns.go; its Config uses Credentials map[string]string (domain -> 'user:token'), which the generated key/value form cannot express. Needs a map-type field in the form and the code generator. Value L-M, effort M.

### #417 How to create additional locations for a domain
* Verdict: **support-question**
* Evidence / analysis: Virtual directories are prefix based, one per path. Default behaviour is that the host's own target handles everything else, so the 'other directories stop working' point suggests the proxy rule root target is missing/wrong rather than a Zoraxy limitation.
* Proposed reply: Set the host rule's target to Home Assistant (`homeassistant:8123`); that already serves `/lovelace`, `/api`, `/local`, `/media` and everything else. Virtual directories are only needed to send a *path* to a *different* upstream. Create the three vdirs only if they must go elsewhere, one per prefix (no regex alternation).

### #418 URL rewrite for static files
* Verdict: **support-question**
* Evidence / analysis: Vdir strips the prefix (rewriteURL) but the app emits absolute links (/css/...). Zoraxy does not rewrite response bodies; the app must be configured with a base URL/path or be given its own sub-domain.
* Proposed reply: Zoraxy forwards `/app/x` to the container as `/x` and does not rewrite HTML. If the app emits root-relative URLs (`/css/style.css`) the browser requests them without `/app`. Either set the app's base-URL/path option, or use a dedicated sub-domain (`app.example.com`) instead of a virtual directory.

### #431 Robots.txt file option or crawler discouragment or static file responses in virtual directories
* Verdict: **feature-request**
* Evidence / analysis: No static-response endpoint; closest is default-site templates. Could be a 'static response' vdir type or a WAF/response rule. Value M, effort S-M.

### #433 SSL Certificate CSR request
* Verdict: **feature-request**
* Evidence / analysis: Not present (tlscert generates self-signed certs only). Value low, effort S-M (crypto/x509.CreateCertificateRequest).

### #442 Mtls
* Verdict: **feature-request**
* Evidence / analysis: Not implemented for proxy endpoints (tls.Config ClientAuth not set; only appears in cert generation). Needs per-host CA upload + tls.Config GetConfigForClient. Highly requested upstream. Value H, effort M-L.

### #446 Domoticz not working properly
* Verdict: **support-question**
* Evidence / analysis: Same pattern as #418: sub-path (vdir) mounting with root-relative asset URLs. Reporter said no special rules, so more info (rule screenshot) needed.
* Proposed reply: Please post the HTTP proxy rule and virtual directory configuration. If these apps are mounted under a path (e.g. `/domoticz`) the vdir prefix is stripped and absolute asset links break; serve them on their own sub-domain, or set the app's base path.

### #458 Problem with punycode domains
* Verdict: **needs-hardware-or-env**
* Evidence / analysis: Error comes from lego's Infomaniak provider zone lookup for the xn-- name (Infomaniak API appears to expect the Unicode form or the registered zone). Needs an Infomaniak account to reproduce; the fix might be passing the Unicode name to that provider only.

### #459 Expire At is not recognized
* Verdict: **fixed-by-you** (fork commit `a00613f`); proposed close
* Evidence / analysis: Real bug: handler.go only decoded the FIRST PEM block, so any bundle where block 1 is not a CERTIFICATE (public key first, key first, ...) lost expiry/domain. Added firstCertificate() in src/mod/tlscert/helper.go (skips non-certificate blocks) used by the 3 listing sites; test mod/tlscert/firstcert_test.go (failed to build before, passes now).
* Proposed reply: Fixed on the fork (a00613f): the certificate list now scans all PEM blocks and uses the first CERTIFICATE one, so bundles that start with a PUBLIC KEY block show the right expiry date and domain. Test: `TestFirstCertificateSkipsLeadingNonCertBlocks`.

### #461 Expose Monitoring Data for Prometheus
* Verdict: **feature-request**
* Evidence / analysis: Not present; ROADMAP section 9 (planned). Value H, effort M. #660 asks for the same.

### #490 ACME module not compatible with "Allow plain HTTP access" option
* Verdict: **already-fixed** (fork commit `c0d317e`); proposed close
* Evidence / analysis: Root cause was the non-TLS path (port 80 bypass) skipping the special routing rules, so challenges were proxied to the backend (403). Fixed in dev by d3add94 (shared pre-proxy chain; handleNonTLSRequest calls handleSpecialAndRedirect); test TestNonTLS_SpecialRoutingRuleApplies. Additionally c0d317e fixes the sibling case from the same thread (host has a rule, no plain-HTTP bypass, 'force HTTPS redirect' off -> port 80 returned 400 for challenges): handlePort80Request now answers ACME rules first; test TestPort80ServesACMEChallengeForExistingProxyRule fails without the change.
* Proposed reply: Fixed on the fork: plain-HTTP endpoints now go through the same special routing (ACME) as HTTPS ones (d3add94, test `TestNonTLS_SpecialRoutingRuleApplies`), and the port-80 listener answers ACME HTTP-01 challenges for any host with a proxy rule (c0d317e, test `TestPort80ServesACMEChallengeForExistingProxyRule`).

### #494 How to Update Zoraxy instance
* Verdict: **support-question**
* Evidence / analysis: The fork has an in-app updater (System -> Update, DEVELOPMENT.md 'Updating / releasing'); for the source install: git pull, rebuild in src/ (go build), restart; the reporter built in the right place so 'no newer version' simply means their checkout was already current.
* Proposed reply: On this fork use **System -> Update** (checks signed GitHub releases, one click install with rollback). For a source checkout: back up `conf/` and `sys.db`, `git pull`, `cd src && go build`, restart the service. Docker: pull the new image.

### #496 certs renew-hooks
* Verdict: **feature-request**
* Evidence / analysis: Not present (renewal in src/mod/acme/autorenew.go). Value M, effort S (run configured command/webhook after a successful renew).

### #501 Change username
* Verdict: **feature-request**
* Evidence / analysis: Username is fixed at first-run setup; only the password can be changed (src/mod/auth). Value L, effort S (add field + migration of the stored hash key). Workaround: edit the database.

### #504 IPv6 Calulator
* Verdict: **feature-request**
* Evidence / analysis: Only IPv4 calculator exists (web/components/utils.html). Pure front-end task. Value low, effort S.

### #512 Import of multiple IPs into IP Blacklist / Access Control
* Verdict: **feature-request**
* Evidence / analysis: Trusted-proxy list has a CSV bulk import (handleBulkUpdateTrustedProxies in accesslist.go) but the blacklist/whitelist editors do not. Same ask as #661, fork issue #211. Value H, effort S.

### #513 Force certificate requests and replies over IPv4. Letsencrypt errors. Dual stack IPv6.
* Verdict: **support-question**
* Evidence / analysis: LE prefers IPv6 when an AAAA record exists; Zoraxy does not control which family LE uses and cannot force the challenge client to IPv4. The 403 shows the AAAA address answering.
* Proposed reply: Let's Encrypt chooses the address family itself: if the name has an AAAA record, validation goes to that IPv6 address (here a backend server, hence 403). Either remove the AAAA record for names Zoraxy must obtain certs for, forward IPv6 port 80/443 to Zoraxy too, or use the DNS challenge, which does not depend on reachability.

### #514 Send client IP to proxy host
* Verdict: **support-question**
* Evidence / analysis: Zoraxy sets X-Forwarded-For and X-Real-Ip on proxied requests; backends must be told to trust the proxy (Authelia: trusted proxies / X-Forwarded-For). If Zoraxy itself sits behind another hop, add that hop to Trusted proxies.
* Proposed reply: Zoraxy already sends `X-Forwarded-For` / `X-Real-Ip`. The backend (Authelia here) must be configured to trust Zoraxy's address (`server.endpoints.authz.*.implementation: ForwardAuth` + trusted proxy list) and read the client IP from those headers. The TCP source address is always Zoraxy's in an HTTP reverse proxy.

### #518 Allow email send without authentication to port 25
* Verdict: **cannot-reproduce**
* Evidence / analysis: email.go SendEmail already skips auth when the password is empty (smtp.SendMail with nil auth), and in dev nothing calls NewEmailSender (no 'forgot password' UI wired). Nothing to change/verify here.
* Proposed reply: In the current code the mail sender sends without AUTH when no password is set, but the reset-by-email flow is not wired into the UI on this fork. Please re-open as a feature request if you still need it.

### #537 Error 400 during renew Let's encrypt certificates
* Verdict: **cannot-reproduce**
* Evidence / analysis: LE reports it could not fetch the challenge from the host, i.e. reachability/DNS (CNAME to DDNS, IPv6, port 80 forwarding). One genuine Zoraxy cause is fixed by c0d317e (port 80 answered 400 for hosts with a proxy rule and no redirect) but the thread has no evidence this is the reporter's case.
* Proposed reply: That error is raised by Let's Encrypt, not Zoraxy: it could not fetch `http://<host>/.well-known/acme-challenge/...`. Check port 80 forwarding, the CNAME/DDNS target and any AAAA record. Recent fork builds also fix the port-80 listener rejecting challenges for hosts with a proxy rule when 'force HTTPS redirect' is off (c0d317e); please retest.

### #543 Proxy Host not resolving without invalid cert warning via HTTPS despite valid SSL Cert
* Verdict: **support-question**
* Evidence / analysis: Client-side name resolution/hairpin (macvlan shim, Pi-hole); if the browser reaches Zoraxy through a name/IP not covered by the certificate it gets the fallback cert. Not a Zoraxy defect.
* Proposed reply: A browser warning with a valid cert means the request is being served with the fallback (self-signed) certificate, i.e. the hostname used did not match a proxy rule/cert (or SNI is missing because the client uses the IP). Verify that the local DNS record resolves the same name used in the proxy rule and open the exact hostname; `openssl s_client -connect ip:443 -servername host` shows which cert is served.

### #561 Zoraxy Docker, Statistics of actual day is lost when reboot
* Verdict: **already-fixed** (fork commit `1368039`); proposed close
* Evidence / analysis: NewStatisticCollector reloads today's summary from the database (src/mod/statistic/statistic.go), autosave every 10 min (STATISTIC_AUTO_SAVE_INTERVAL) and ShutdownSeq saves on SIGTERM/SIGINT (src/main.go). New test mod/statistic/restart_test.go: TestTodayStatsSurviveRestart passes (commit 1368039). Requires sys.db to be on a persistent volume.
* Proposed reply: Today's totals are reloaded at startup, saved every 10 minutes and on SIGTERM; regression test `TestTodayStatsSurviveRestart`. Make sure `sys.db` lives on the mounted volume (`/opt/zoraxy/config`).

### #564 Add Sablier compatibility
* Verdict: **feature-request**
* Evidence / analysis: Plugin territory (upstream thread says a plugin is planned). Needs pre-request hook that waits for a container; ROADMAP section 8 hooks would enable it. Value L-M, effort M.

### #578 Entry for 404 Error in Log.
* Verdict: **feature-request**
* Evidence / analysis: Deliberate: Server.go (default-site branch) says 'Do not log default site requests to avoid flooding the logs', and serve404PageWithTemplate does not log. Making it optional is small. Value M, effort S (setting 'log unmatched-host requests').

### #590 Show the correct public IP
* Verdict: **support-question**
* Evidence / analysis: Same as #514/#676: HTTP reverse proxy sets forwarding headers; the backend must read them.
* Proposed reply: Zoraxy sends `X-Forwarded-For`/`X-Real-Ip`. Configure the backend service to trust the proxy and use those headers. If another firewall/NAT sits in front and masquerades the source, Zoraxy sees that device's IP: fix at the firewall (disable source NAT / use PROXY protocol).

### #596 Separate Logs Per Site
* Verdict: **feature-request**
* Evidence / analysis: Single log stream (src/mod/info/logger, rotation by month). Could add per-endpoint log file option. Overlaps #764 and ROADMAP section 9. Value M, effort M.

### #611 Filename cannot be empty for certs containing multiple domains
* Verdict: **fixed-by-you** (fork commit `67036ea`); proposed close
* Evidence / analysis: Real bug in web/components/cert.html obtainCertificate(): filename was hard-coded to '' so any comma-separated domain list (alias) always took the error branch. Now the file is named after the first domain. JS-only change: no automated test possible in this repo, logic checked by reading; UI not click-tested.
* Proposed reply: Fixed on the fork (67036ea): requesting a certificate for a host with aliases now names the file after the primary domain instead of failing. Not click-tested in a browser; please confirm.

### #612 ACL Not Working
* Verdict: **support-question**
* Evidence / analysis: The client's source is whatever address reaches Zoraxy; WireGuard server masquerading (SNAT) hides the client. Trusted proxies only helps with HTTP headers.
* Proposed reply: If the WireGuard server NATs (masquerades) client traffic, Zoraxy only ever sees the VPN server's IP. Disable masquerade for the LAN-bound traffic (route the VPN subnet instead of NAT-ing it) and then allow the VPN subnet in the access rule.

### #615 Bot Blocking Capabilities
* Verdict: **feature-request**
* Evidence / analysis: No UA rule UI. The fork WAF (Coraza + CRS, ROADMAP section 7) already includes scanner/bot detection rules and accepts custom SecLang (e.g. block a User-Agent) so a lot is possible via WAF; a UI list and a bundled bad-bot list would be new. Value M, effort M.

### #621 Basic Authentication für die "Virtual Directory"-Einstellungen
* Verdict: **feature-request**
* Evidence / analysis: Basic auth is per host endpoint with exception paths (BasicAuthExceptionRules) but cannot be scoped to include only a path. Value M, effort M (per-vdir auth).

### #622 CleanSlate deployment errors with ZORAXY and websocket connections
* Verdict: **support-question**
* Evidence / analysis: Backend rejected the upgrade; upstream thread suggests config issue. Zoraxy forwards Upgrade headers and rewrites Origin for vdirs (proxyRequestHandler.go vdirRequest). A usual cause: vdir prefix stripping (/graphql -> /) or Origin/Host check on the backend. Cannot verify.
* Proposed reply: 'bad handshake' = the backend answered the websocket Upgrade with something other than 101. Check the backend log for the response code. Likely causes: the vdir prefix is stripped so the path differs from what the app expects (include the path in the vdir target), or the app validates Origin/Host. Try 'Skip WebSocket Origin Check' on the rule.

### #648 Crowdsec needs live logs?
* Verdict: **support-question**
* Evidence / analysis: HTTP access lines are written live to <logfolder>/zr_YYYY-M.log (src/mod/info/logger/logger.go); CrowdSec can tail that file with a custom acquisition + parser.
* Proposed reply: Zoraxy writes request lines continuously to `log/zr_<year>-<month>.log` (one file per month; older months stay in the folder). Point a CrowdSec `file` acquisition at `log/zr_*.log`; a community parser/bouncer plugin exists (see the plugin list).

### #652 Bypass Authentik/Authelia
* Verdict: **feature-request**
* Evidence / analysis: Real gap: Basic auth and ZorxAuth have exception rules (authProviders.go) but handleForwardAuth/OAuth2 have none. Add IP/CIDR and path exception rules to all providers. Value H, effort S-M.

### #655 Odd errors appearing in the container logs. Possibly a leak being triggered from external source?
* Verdict: **fixed-by-you** (fork commit `45a5c89`)
* Evidence / analysis: Real (minor) bugs: the relay (src/acme.go) printed Printf errors and wrote an empty 200 when no issuance was running and never passed through the internal listener's status. Extracted serveACMEChallenge: 404 when the internal listener is down, status passthrough, token regex rejects names like my1.php with 400 (that part was already fixed). Test src/acme_challenge_test.go. NOT fixed: the ACME routing rule has UseSystemAccessControl=false so blacklisted IPs can still reach it (harmless while the listener is closed).
* Proposed reply: Partly fixed on the fork (45a5c89): the challenge relay now answers 404 quietly when no certificate request is running and passes the real status through. The 'errors' were scanner probes of the well-known path, not a leak. Leaving open: ACME path ignores the IP blacklist.

### #660 Metrics exposed in Prometheus format
* Verdict: **duplicate**; proposed close
* Evidence / analysis: Duplicate of #461.
* Proposed reply: Duplicate of #461 (Prometheus metrics endpoint, ROADMAP section 9).

### #661 Import blocklist of IP addresses
* Verdict: **duplicate**; proposed close
* Evidence / analysis: Duplicate of #512 (bulk import of IPs/CIDRs into blacklist).
* Proposed reply: Duplicate of #512 / fork #211 (bulk import for the blacklist).

### #663 Proxy to unix socket file
* Verdict: **feature-request**
* Evidence / analysis: Not present; dpcore transport could dial unix:// targets (DialContext). Upstream says plugin/non-Windows. Value M, effort M.

### #665 Default Website certificate error
* Verdict: **support-question**
* Evidence / analysis: Answered in thread: the default site over HTTPS needs a fallback certificate that matches; IP access always warns because a cert cannot match an unknown host.
* Proposed reply: That is expected: for requests by IP or unknown host Zoraxy serves the *fallback certificate* (self-signed unless you set one under TLS/SSL -> Set as fallback). A browser can only avoid the warning if the name used is covered by that certificate; a redirect is performed after the TLS handshake.

### #676 Automatically pass through the real IP instead of the cloudflare IP's
* Verdict: **support-question**
* Evidence / analysis: Zoraxy passes X-Real-Ip/X-Forwarded-For; with Cloudflare, add Cloudflare ranges to Trusted proxies (web/components/trustedproxy.html, access/trustedProxy tests) so the CF-Connecting-IP value is used for access control and forwarded.
* Proposed reply: Add the Cloudflare IP ranges under the **Trusted Proxy** page so Zoraxy takes the client IP from `CF-Connecting-IP`/`X-Forwarded-For`, then configure Home Assistant (`http: use_x_forwarded_for: true`, `trusted_proxies: <zoraxy ip>`).

### #677 Load balance based on IP/Region/CIDR/IP Range
* Verdict: **feature-request**
* Evidence / analysis: Fork LB has IP hash and consistent hash (ROADMAP section 5, #79) but no GeoIP/CIDR routing. Value M, effort M (a 'geo' selection rule in loadbalance).

### #680 CORS Error with Immich
* Verdict: **feature-request**
* Evidence / analysis: Custom headers exist, but no way to answer OPTIONS at the proxy without hitting the upstream. A 'CORS' option per endpoint would cover it. Value M, effort S-M.

### #681 Can not add a DNS Challenge
* Verdict: **support-question**
* Evidence / analysis: Provider 'pdns' exists in providers.json: needs API key + Host URL; optional fields may be left empty.
* Proposed reply: Choose provider `pdns`. Fill **APIKey** and **Host** (your PowerDNS API base URL, e.g. `https://ns.example.org`) and leave the optional fields at their defaults; **ServerName** is usually `localhost`.

### #689 Adding Regexp2
* Verdict: **feature-request**
* Evidence / analysis: Redirect rules use Go RE2 (error 'invalid or unsupported Perl syntax: (?!'). regexp2 (MIT) could be used, with ReDoS/timeouts considered. Value L-M, effort S-M.

### #698 Forward Auth Redirection error in v3.2.3
* Verdict: **needs-hardware-or-env**
* Evidence / analysis: Upstream feature has been reworked in the fork: Authentik forward auth uses the outpost callback path, server-built rd, Host preservation and X-authentik-* handling (ROADMAP 4, docs/authentik.md, src/mod/auth/sso/forward tests with fake outposts). Needs a real Authentik instance to confirm (fork issue #213).

### #714 Simple API for Managing Proxy Rules & Access Control
* Verdict: **duplicate**; proposed close
* Evidence / analysis: Duplicate of #382 (REST API to manage proxy records).
* Proposed reply: Duplicate of #382 (token-based management API).

### #726 limit request based on uri path
* Verdict: **feature-request**
* Evidence / analysis: Fork has per-endpoint token-bucket rate limiting (ratelimit.go); optional per-path limits are listed in ROADMAP section 1. A bounded per-(endpoint,path-prefix) bucket map answers the maintainer's memory concern. Value M, effort M.

### #741 enable CodeQL Scanning (part of GitHub advanced security)
* Verdict: **feature-request**
* Evidence / analysis: .github/workflows/ci.yaml runs go vet and go test only. Adding a codeql.yml workflow is a standalone 20-line addition; left untouched to avoid CI changes in a triage PR. Value L-M, effort S.

### #749 Cannot get Authelia & Zoraxys to work
* Verdict: **support-question**
* Evidence / analysis: 404 from Zoraxy means no matching proxy rule/host or default site; verify the rule hostname and the upstream scheme/port.
* Proposed reply: A 404 page from Zoraxy means no proxy rule matched the requested hostname (or the rule is disabled). Check that the rule's *Matching Domain* is exactly `auth.mydomain.net`, that DNS points the name at Zoraxy, and that the target is `http://<container-ip>:9091`. Compare with the access log line for the request.

### #750 Certificate on a Local only proxy
* Verdict: **support-question**
* Evidence / analysis: Use the DNS challenge (does not need inbound access) or exempt the ACME path from the access rule; the ACME routing rule is evaluated before host access rules.
* Proposed reply: Use the **DNS challenge** for that name (no inbound connection to the host required). The HTTP challenge path `/.well-known/acme-challenge/` is handled before the host's access rules, so it works with a LAN-only rule as long as port 80 is reachable by Let's Encrypt.

### #754 [tracker] Plugin System Improvements
* Verdict: **feature-request**
* Evidence / analysis: Tracker for plugin API-key auth etc. Plugin package is being reworked elsewhere (ROADMAP section 8), nothing to verify here.

### #760 run plugins as unpriviledged user
* Verdict: **feature-request**
* Evidence / analysis: Plugins are started by the plugin manager as Zoraxy's user. Setting SysProcAttr.Credential on Linux is small, but the plugins package is being edited elsewhere, so not touched. Value H (security), effort S.

### #761 Access control by Cloudflare IPs
* Verdict: **feature-request**
* Evidence / analysis: Access rules evaluate the (possibly forwarded) client IP; there is no 'direct peer must be in set' rule. Needs an option to match on RemoteAddr after trusted-proxy handling. Value M, effort S-M.

### #762 Duplicate & Sort Access Control Rules
* Verdict: **feature-request**
* Evidence / analysis: UI list is unsorted (web/components/access.html) and there is no clone. Value L, effort S.

### #764 Statistics and logging for each proxy
* Verdict: **feature-request**
* Evidence / analysis: See #349/#596; also realtime per-host view. ROADMAP section 9 (per-upstream stats). Value M-H, effort M-L.
