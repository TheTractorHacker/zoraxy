# Triage of upstream issues #766-#1359 (batch B)

Branch `triage/batch-b` on top of fork `dev`. 77 open upstream issues (tobychui/zoraxy), each read with its comments.
Issue text is treated as untrusted data. Where a verdict says *unverified* only the code was read; nothing was run against the real third-party service.

## Verdict counts

- feature-request: 33
- already-fixed: 15
- support-question: 12
- cannot-reproduce: 6
- real-bug-open: 4
- fixed-by-you: 3
- duplicate: 2
- needs-hardware-or-env: 2

## Summary table

| # | Title | Verdict | Summary |
|---|-------|---------|---------|
| 766 | [HELP] / [BUG] dns-01 challenge via pdns | already-fixed | PowerDNS (pdns) DNS-01 failed with 'cannot unmarshal string into ... Config.Host of type url.URL'. |
| 769 | [ENHANCEMENTS] Internal DNS provider | feature-request | Internal DNS resolver on port 53 that answers with the proxy's IP for every hosted domain. |
| 770 | [HELP] High CPU usage when high traffic load | support-question | High CPU under a synthetic wrk load (1024 connections, 100 threads). |
| 775 | [HELP] Use of groups with Keycloak | support-question | How to restrict an app to a Keycloak group. |
| 782 | [ENHANCEMENTS] Option to disable internet dependent features for airgapped deployments | feature-request | -offline option to skip GeoIP update and public-IP lookups in air-gapped installs. |
| 793 | [HELP] [forward-auth] Authelia Zoraxy Forward-Auth - configuration issue | support-question | Authelia forward-auth shows the site without a login. |
| 798 | [ENHANCEMENTS] Support use of certs on mapped volume | feature-request | Use certificates dropped into a mapped volume (certbot fullchain/privkey). |
| 816 | [BUG] Memory overflow with false forward-auth redirect (Authelia) | cannot-reproduce | Zoraxy memory grows without bound after a wrongly configured Authelia forward-auth URL. |
| 826 | [ENHANCEMENTS] Header template(s) | feature-request | Header templates applied to new proxy rules. |
| 831 | [ENHANCEMENTS] Support CF_IPCountry for geolocating | already-fixed | Geo access rules behind Cloudflare see Cloudflare's IP; asked for CF-IPCountry support. |
| 877 | [ENHANCEMENTS] Templates for Proxy hosts / virtual directories | feature-request | Defaults/templates for new proxy hosts and virtual directories (HSTS, uptime monitor, headers). |
| 884 | [ENHANCEMENTS] OAuth 2.0 - Only with specific role(s) | feature-request | Allow OAuth2 login only for users with specific role claim values; later: several IdPs, selectable per host. |
| 890 | Virtual Directory resolving to base IP | cannot-reproduce | Virtual directories answer 404/307 from the base proxy when accessed over plain HTTP. |
| 895 | [HELP] Forward Auth with Authentik | support-question | How to configure Authentik forward auth. |
| 896 | [ENHANCEMENTS] Disable load balance and do not pause upstream for 60s when only 1 upstream is configured | already-fixed | Single upstream gets paused for 60 s by the uptime monitor -> 521 during container restarts. |
| 898 | [ENHANCEMENTS] API or plugin to control blacklist remotely | feature-request | API/plugin to ban and unban IPs remotely (fail2ban). |
| 899 | [ENHANCEMENTS] send Webhook | feature-request | Webhooks on certificate renew / events. |
| 908 | [ENHANCEMENTS] Close connection to black listed ip | feature-request | Close the TCP connection instead of the 403 page for blacklisted IPs. |
| 909 | [ENHANCEMENTS] Allow Custom Ports When Running Zoraxy in Host Networking Mode | feature-request | Configurable plain-HTTP (port 80) listener for host-network Docker on Synology. |
| 917 | [BUG] Json: cannot unmarshal string into Go struct field Config.Host of type url.URL. | duplicate | Same pdns 'cannot unmarshal string into Config.Host of type url.URL' error as #766. |
| 922 | [BUG] ACME Tool not working for DNS challenge with INWX | already-fixed | INWX DNS challenge: '[id] expected type int, got unconvertible type string'. |
| 924 | [ENHANCEMENTS] Bulk Edit HTTP Proxy | feature-request | Bulk edit of HTTP proxy rules, bigger edit button. |
| 934 | [HELP] Zoraxy behind Haproxy, Receive Proxy Protocol | already-fixed | Receive PROXY protocol (HAProxy send-proxy-v2) on the TLS listener. |
| 950 | [BUG] Speedtest through proxy - Upload is not realistic | cannot-reproduce | OpenSpeedTest through Zoraxy reports 25+ Gbit/s upload on a 10 GbE network. |
| 954 | [HELP] UI Crash "Cannot read properties of null (reading 'map')" when using "Pick from Docker Containers" | already-fixed | Pick from Docker Containers crashes with 'Cannot read properties of null (reading map)'. |
| 958 | [HELP] Forward auth with VoidAuth | needs-hardware-or-env | Forward auth with VoidAuth ends in a redirect loop. |
| 959 | [HELP] Are there any guides to get Google OAuth2 configured? | support-question | How to configure Google as OAuth2/OIDC provider. |
| 969 | [ENHANCEMENTS] mark rc* as early access | already-fixed | Mark rc releases as GitHub pre-releases. |
| 971 | [BUG] Uptime monitor fails with self-signed certificate | cannot-reproduce | Uptime monitor fails against an IPMI with self-signed certificate despite 'Skip Verification'. |
| 974 | [ENHANCEMENTS] Support secure-websocket for HTTP Upstream connections | cannot-reproduce | Secure WebSocket (wss) towards HTTP upstreams. |
| 986 | [ENHANCEMENTS] [Perf] Use a Trie for IP lookups instead of a hashmap | feature-request | Use a trie instead of a linear scan for IP blacklist lookups. |
| 993 | [ENHANCEMENTS] Mobile reCAPTCHA | support-question | reCAPTCHA breaks iOS/Android apps that use the proxied API. |
| 996 | [ENHANCEMENTS] Swagger Documentation | feature-request | OpenAPI/Swagger documentation of the admin API. |
| 1006 | [ENHANCEMENTS] Allow Basic Auth Credential list, so it can be reused. | feature-request | Reusable list of Basic Auth credentials. |
| 1012 | Headscale with reverse proxy Zoraxy not working because allegedly WebSockets are not passing through | already-fixed | Headscale (TS2021 Upgrade) does not work through Zoraxy: 'No Upgrade header in TS2021 request'. |
| 1029 | [HELP] NetBird setup | feature-request | NetBird behind Zoraxy (needs h2c / gRPC to plain-HTTP upstream). |
| 1032 | [HELP] Authentication Issues with oauth2-proxy Behind Zoraxy and Cloudflare Tunnel | needs-hardware-or-env | oauth2-proxy via forward auth behind Cloudflare Tunnel loops/fails. |
| 1042 | [ENHANCEMENTS] Secondary Listening Ports | feature-request | Secondary listening ports have no TLS. |
| 1046 | [ENHANCEMENTS] add notifications ( i.e. shoutrrr ) to uptime monitor | feature-request | Notifications (shoutrrr) from the uptime monitor. |
| 1067 | [ACME] selfhostde RID mapping input field missing | real-bug-open | selfhost.de DNS challenge: 'missing record mapping' - no UI field for the RID mapping. |
| 1070 | [ENHANCEMENTS] Multi-Node sync / cluster mode for anycast deployments | feature-request | Multi-node sync / cluster mode. |
| 1073 | [ENHANCEMENTS] Support for Passkey (WebAuthn) in Zoraxy Auth | already-fixed | Passkey (WebAuthn) support in Zoraxy Auth. |
| 1075 | [ENHANCEMENTS] Make access control available to Stream Proxy as well? | already-fixed | Access control for the stream proxy. |
| 1087 | [BUG] 3.3.2 Denies access | support-question | 3.3.2 returns 403 for Cloudflare users with a country whitelist; downgrade fixes it. |
| 1095 | [HELP] Custom Error 521 template , how to set ? | support-question | Custom 521 error page. |
| 1100 | [ENHANCEMENTS] - Import a list of Blacklist IP | support-question | Import a list of IPs into the blacklist. |
| 1102 | [HELP] Transmission web UI returns 521 when proxied | support-question | Transmission web UI gives 521 behind Zoraxy. |
| 1107 | [BUG] The "Require Rate Limit" is not a setting per HTTP Proxy | already-fixed | 'Require Rate Limit' value is shared between proxy rules in the UI. |
| 1109 | [ENHANCEMENTS]  Auto-tagging based on Authentication Provider + audit/enforcement | feature-request | Auto-tag proxy rules with their auth provider and audit/enforce. |
| 1117 | [BUG] Cannot generate certificate from ZeroSSL. listen tcp :56563: bind: address already in use | real-bug-open | ACME HTTP challenge: 'listen tcp :56563: bind: address already in use'; renew spinner never ends. |
| 1118 | [HELP] Using X-Auth-User header variable with Pocket ID and Navidrome | support-question | Pass the OIDC user name to Navidrome via X-Auth-User (Pocket ID). |
| 1119 | [ENHANCEMENTS] Certificate watch folder - or another automatic existing certificate import feature. | duplicate | Certificate watch folder / automatic import of existing certificates. |
| 1123 | [ENHANCEMENTS] Allow user to select ACME certificate key type (RSA/ECDSA) instead of hardcoded RSA2048 | feature-request | Choose ACME key type (RSA2048/3072/4096, EC256/384). |
| 1156 | [ACME] DNS Challenge with plesk.com -> baseURL not working | fixed-by-you | Plesk DNS challenge always fails with 'plesk: missing server base URL'. |
| 1161 | [ENHANCEMENTS] Path‑Level reCAPTCHA Exemptions | feature-request | Path-level CAPTCHA exemptions. |
| 1162 | [ENHANCEMENTS] Path‑Level OAuth2 Exemptions | feature-request | Path-level OAuth2 exemptions (and per-route provider, email allow-list). |
| 1165 | [ENHANCEMENTS] Bypass Zoraxy Auth for internal requests (e. g. from LAN subnet)? | already-fixed | Bypass Zoraxy Auth for LAN subnets. |
| 1174 | Looking for a new Docker maintainer | support-question | Maintainer announcement: looking for a Docker maintainer. |
| 1186 | [ENHANCEMENTS] Show Stream Proxy rules in the Status page network diagram | feature-request | Show stream proxy rules in the Status page network diagram. |
| 1193 | [ENHANCEMENTS] [ACME] Stale DNS credentials/metadata after cert delete + no UI to rotate credentials of existing cert | fixed-by-you | Cert deletion leaves <name>.json and acme DB keys; no UI to rotate DNS credentials. |
| 1198 | [ENHANCEMENTS] More Captcha providers - Altcha & FriendlyCaptcha | feature-request | More CAPTCHA providers (Altcha, FriendlyCaptcha). |
| 1201 | [ENHANCEMENTS] Dropdown & Sidebar tweaks | cannot-reproduce | UI dropdown/sidebar glitches in 3.3.3. |
| 1207 | [BUG] UDP stream proxy never releases per-client sockets/goroutines (Timeout ignored) → socket/goroutine leak and eventual forwarding stall | already-fixed | UDP stream proxy never releases per-client sockets/goroutines. |
| 1208 | [ENHANCEMENTS] add limit_rate for http proxy | feature-request | limit_rate (bandwidth limit) for HTTP proxies. |
| 1243 | [ENHANCEMENTS] Logging Feature Enhance | feature-request | Access-log viewer with filtering in the admin UI. |
| 1267 | [ENHANCEMENTS] Add support for multiple ACME certificate authorities and per-certificate CA assignments | feature-request | Multiple ACME CAs/profiles with per-certificate assignment. |
| 1297 | [ENHANCEMENTS] WAF plugin support / Coraza integration | already-fixed | WAF / Coraza integration. |
| 1319 | [ENHANCEMENTS] Native Support for Encrypted Client Hello (ECH) | feature-request | Encrypted Client Hello (ECH). |
| 1332 | [ENHANCEMENTS] Allow reuse of DNS challange credentials across proxies | feature-request | Reuse DNS-challenge credentials across certificates. |
| 1334 | [BUG] IPv6 GeoIP maps Malaysian ISPs to AU; hardcoded geo-whois-asn-country source is deprecated upstream | real-bug-open | IPv6 GeoIP maps Malaysian prefixes to AU; update source deprecated. |
| 1342 | [ACME] BypassGlobalTLS ("Allow plain HTTP access") hosts never see the HTTP-01 challenge handler | already-fixed | Hosts with 'Allow plain HTTP access' never reach the ACME HTTP-01 handler. |
| 1343 | [ENHANCEMENTS] Per-route option to disable upstream keep-alive (and note on what "Force HTTP/1.1" actually does) | real-bug-open | Reused keep-alive connections to upstreams that close after each response cause 502/521; ForceHTTP11 only helps by accident. |
| 1344 | [ENHANCEMENTS] Add a toggle to exclude blocked IPs from traffic statistics | feature-request | Toggle to exclude blocked requests from statistics. |
| 1351 | [ENHANCEMENTS] Tell plugins which proxy rule matched in dynamic capture sniff | feature-request | Tell plugins which proxy rule matched in the dynamic capture sniff payload. |
| 1354 | Feature Request: Display Full URLs in Top Requested Paths | feature-request | Show full URLs (host + query) in 'Top Requested Paths'. |
| 1356 | [ENHANCEMENTS] Header-based access rules: drop requests missing required headers/values | feature-request | Header-based access rules (require header X-Origin-Auth, drop otherwise). |
| 1359 | [BUG] Upstream X-Forwarded-For / X-Real-IP can be spoofed by clients: trusted proxy list not applied to headers sent to backends | fixed-by-you | Clients can spoof X-Forwarded-For/X-Real-IP/CF-Connecting-IP forwarded to upstreams. |

## Details

### #766 [HELP] / [BUG] dns-01 challenge via pdns

- **Verdict:** already-fixed (fork commit a6653f5)
- **Summary:** PowerDNS (pdns) DNS-01 failed with 'cannot unmarshal string into ... Config.Host of type url.URL'.
- **Evidence:** mod/acme/acme_dns.go GetDnsChallengeProviderByName lifts every *url.URL field out of the credentials JSON, parses it and passes it to the provider (commits aec1cf7, 1da73e1). Regression test TestDNSProviderPowerDNSHostURL (a6653f5) passes on dev. Provider construction only; a real PowerDNS server was not available.
- **Proposed:** close

### #769 [ENHANCEMENTS] Internal DNS provider

- **Verdict:** feature-request
- **Summary:** Internal DNS resolver on port 53 that answers with the proxy's IP for every hosted domain.
- **Evidence:** No such feature in dev. Not on the fork roadmap.
- **Notes:** Value low-medium (homelab convenience, split-horizon DNS), effort L (DNS server, lifecycle, security exposure of port 53). Better as a plugin (roadmap section 8) or documented with Pi-hole/CoreDNS wildcard records.

### #770 [HELP] High CPU usage when high traffic load

- **Verdict:** support-question
- **Summary:** High CPU under a synthetic wrk load (1024 connections, 100 threads).
- **Evidence:** Not a defect report: no profile or comparison was supplied. CPU scales with TLS termination, access-rule/GeoIP checks and request logging per request.
- **Notes:** Draft reply: 1024 connections x 100 threads on a TLS listener will saturate all cores on any Go proxy. To find a hotspot, compare (a) an endpoint with logging and statistics disabled, (b) with GeoIP/country rules removed, (c) `-fastgeoip=true` (default, trades RAM for CPU), (d) HTTP vs HTTPS. A `net/http/pprof` flag would help users profile; suggest adding one (S).

### #775 [HELP] Use of groups with Keycloak

- **Verdict:** support-question
- **Summary:** How to restrict an app to a Keycloak group.
- **Evidence:** dev has OIDC SSO with a group allow-list: mod/auth/sso/oauth2/claims.go (groups claim, default 'groups') and the 'Groups claim' / 'Allowed groups' fields in web/components/sso.html.
- **Notes:** Draft reply: in Keycloak add a 'Group Membership' mapper to the client so the token carries a `groups` claim, then in Zoraxy SSO/OAuth2 set the issuer (discovery URL), client id/secret, Groups claim = `groups` and Allowed groups = the group name(s). Oauth2-proxy is no longer needed. Caveat: the allow-list is global to the OAuth2 provider, not per proxy rule (roadmap section 4, per-route group policies).

### #782 [ENHANCEMENTS] Option to disable internet dependent features for airgapped deployments

- **Verdict:** feature-request
- **Summary:** -offline option to skip GeoIP update and public-IP lookups in air-gapped installs.
- **Evidence:** Public IP lookup: mod/access/loopback.go UpdatePublicIP uses http.Client{} with no timeout against checkip.amazonaws.com. GeoIP auto-update is already optional (mod/geodb/updater.go SetGeoDBAutoUpdate).
- **Notes:** Effort S: add `-offline` flag that skips the public-IP updater and geodb auto-update, plus a 10 s timeout on the public-IP client (the missing timeout is the real cause of slow start-up when the network is black-holed).

### #793 [HELP] [forward-auth] Authelia Zoraxy Forward-Auth - configuration issue

- **Verdict:** support-question
- **Summary:** Authelia forward-auth shows the site without a login.
- **Evidence:** Reporter solved it in the thread: the forward-auth address must be an internal URI that is not proxied by Zoraxy itself (maintainer of Authelia confirmed). dev's forward auth has an X-Original-* switch and fails closed (TestForwardAuthFailsClosedWhenAuthServerDown).
- **Notes:** No code change needed. Could be added to docs: use `http://authelia:9091/api/authz/forward-auth` (container name), not the public auth URL.

### #798 [ENHANCEMENTS] Support use of certs on mapped volume

- **Verdict:** feature-request
- **Summary:** Use certificates dropped into a mapped volume (certbot fullchain/privkey).
- **Evidence:** No folder watcher in dev. Certs are loaded from conf/certs (mod/tlscert).
- **Notes:** Effort S-M: watch/scan a configurable folder for `<name>.pem`+`.key` pairs (or certbot `live/<domain>/fullchain.pem`+`privkey.pem`) and import. Same ask as #1119. Related: fork HA/cert sync (#81).

### #816 [BUG] Memory overflow with false forward-auth redirect (Authelia)

- **Verdict:** cannot-reproduce
- **Summary:** Zoraxy memory grows without bound after a wrongly configured Authelia forward-auth URL.
- **Evidence:** dev's forward-auth client (mod/auth/sso/forward/forward.go) has a 15 s overall timeout, never follows redirects (ErrUseLastResponse), and caps the copied auth response with io.LimitReader (MaxAuthResponseBody). A dead or non-HTTP auth server fails closed with a 500 (TestForwardAuthFailsClosedWhenAuthServerDown). A second reporter sees the same growth without any auth, which points at statistics/uptime rather than forward auth: dev has the statistics soft cap (-stats_max_entries, mod/statistic/bounded.go) and the uptime-monitor connection leak fix (#1241).
- **Notes:** Not reproduced (no heap profile available). Suggest the reporters re-test on dev and, if it persists, capture `pprof heap`. A pprof flag would make this diagnosable (S).

### #826 [ENHANCEMENTS] Header template(s)

- **Verdict:** feature-request
- **Summary:** Header templates applied to new proxy rules.
- **Evidence:** No default/template headers in dev.
- **Notes:** Effort M: a global 'default headers' preset (security headers, HSTS) applied when creating a rule. Same family as #877. Value medium-high (security headers).

### #831 [ENHANCEMENTS] Support CF_IPCountry for geolocating

- **Verdict:** already-fixed
- **Summary:** Geo access rules behind Cloudflare see Cloudflare's IP; asked for CF-IPCountry support.
- **Evidence:** The reporter later found that Cloudflare forwards the real IP. dev has the trusted proxy list (mod/access/trustedProxy.go, default Cloudflare ranges in default_trusted_proxies.csv) so X-Real-IP/CF-Connecting-IP of trusted peers is used for access rules, GeoIP, logs and statistics (tests in mod/dynamicproxy/captcha_gating_test.go, ratelimit_test.go). Using CF-IPCountry itself is not implemented and not needed once the real IP is trusted.
- **Notes:** Note: enabling it is per access rule ('trust proxy headers' toggle). See #1087 for the migration surprise.

### #877 [ENHANCEMENTS] Templates for Proxy hosts / virtual directories

- **Verdict:** feature-request
- **Summary:** Defaults/templates for new proxy hosts and virtual directories (HSTS, uptime monitor, headers).
- **Evidence:** No template mechanism in dev.
- **Notes:** Effort M. Merge with #826 into one 'proxy rule defaults/templates' feature.

### #884 [ENHANCEMENTS] OAuth 2.0 - Only with specific role(s)

- **Verdict:** feature-request
- **Summary:** Allow OAuth2 login only for users with specific role claim values; later: several IdPs, selectable per host.
- **Evidence:** Global part exists: group/role allow-list with a configurable claim name (oauth2GroupsClaim, oauth2AllowedGroups; claims.go). Multiple OAuth2 profiles / per-host selection are not implemented (ROADMAP section 4: group policies per route).
- **Notes:** Effort M-L. Reply: set the claim name to `role` in the OAuth2 settings.

### #890 Virtual Directory resolving to base IP

- **Verdict:** cannot-reproduce (fork commit 537f83d)
- **Summary:** Virtual directories answer 404/307 from the base proxy when accessed over plain HTTP.
- **Evidence:** TestNonTLS_VirtualDirectoryIsProxied (537f83d) proves that vdirs are routed and the missing-trailing-slash redirect works on the plain-HTTP path (handleNonTLSRequest). Vdir matching is case-sensitive (strings.HasPrefix in endpoints.go GetVirtualDirectoryHandlerFromRequestURI): the report mixes `/Server1/` and `/server1`.
- **Notes:** Likely reporter-side: lowercase vs configured case, or the hostname not matching the rule (admin UI on `/` answered with 307 /login.html). Ask for rule screenshot with 'Allow plain HTTP access' and exact URL; consider case-insensitive vdir matching (S, behaviour change).

### #895 [HELP] Forward Auth with Authentik

- **Verdict:** support-question
- **Summary:** How to configure Authentik forward auth.
- **Evidence:** dev has an Authentik preset (forward auth through the proxy outpost, X-authentik-* headers, `/outpost.goauthentik.io` callback proxying) with tests against a fake outpost (mod/auth/sso/forward/authentik_test.go) and docs/authentik.md.
- **Notes:** Draft reply: use the Authentik preset in SSO > Forward Auth, set the outpost URL (e.g. `http://authentik:9000`), enable 'Preserve Host' and the callback proxy. Real Authentik verification is still open (fork issue #213), so mark as unverified.

### #896 [ENHANCEMENTS] Disable load balance and do not pause upstream for 60s when only 1 upstream is configured

- **Verdict:** already-fixed (fork commit a6653f5)
- **Summary:** Single upstream gets paused for 60 s by the uptime monitor -> 521 during container restarts.
- **Evidence:** mod/dynamicproxy/loadbalance/onlineStatus.go FilterOfflineOrigins never filters out the only upstream, plus per-rule DisableAutoFallback (db407d4). Test TestFilterOfflineOriginsKeepsOnlyUpstream (a6653f5).
- **Proposed:** close

### #898 [ENHANCEMENTS] API or plugin to control blacklist remotely

- **Verdict:** feature-request
- **Summary:** API/plugin to ban and unban IPs remotely (fail2ban).
- **Evidence:** Blacklist endpoints exist (/api/blacklist/ip/add and /api/blacklist/list among others, api.go) and are reachable from plugins through the plugin API-key mechanism (plugin_api.go).
- **Notes:** What is missing is a static API token for external tools such as fail2ban. Effort S-M. Roadmap section 8/9 (plugin and API work); note the in-flight plugin package rewrite.

### #899 [ENHANCEMENTS] send Webhook

- **Verdict:** feature-request
- **Summary:** Webhooks on certificate renew / events.
- **Evidence:** An internal event system exists (mod/eventsystem) used by plugins, but there is no webhook sender.
- **Notes:** Effort M: webhook subscriber plugin or built-in sink for cert renew/obtain, blacklist and uptime events. Same family as #1046. Roadmap section 8.

### #908 [ENHANCEMENTS] Close connection to black listed ip

- **Verdict:** feature-request
- **Summary:** Close the TCP connection instead of the 403 page for blacklisted IPs.
- **Evidence:** Closing is feasible: the exploit 'Drop Connection' action and DefaultSite_NoResponse already use http.Hijacker and conn.Close() (dynamicproxy.go). accessRequestBlocked (mod/dynamicproxy/access.go) always writes a 403 page.
- **Notes:** Effort S: access rule option 'drop connection on blacklist'. The maintainer's remark that this is impossible at the application layer is not accurate. Value medium.

### #909 [ENHANCEMENTS] Allow Custom Ports When Running Zoraxy in Host Networking Mode

- **Verdict:** feature-request
- **Summary:** Configurable plain-HTTP (port 80) listener for host-network Docker on Synology.
- **Evidence:** Port 80 is hardcoded in mod/dynamicproxy/dynamicproxy.go (httpServer Addr ':80', condition Option.Port != 80). Only -default_inbound_port exists in def.go. Secondary listening ports exist but are HTTP only.
- **Notes:** Effort S: add `-default_http_port` flag / setting. Value medium (NAS users).

### #917 [BUG] Json: cannot unmarshal string into Go struct field Config.Host of type url.URL.

- **Verdict:** duplicate (fork commit a6653f5)
- **Summary:** Same pdns 'cannot unmarshal string into Config.Host of type url.URL' error as #766.
- **Evidence:** Duplicate of #766; fixed on dev by the *url.URL handling in mod/acme/acme_dns.go (test a6653f5).
- **Proposed:** close

### #922 [BUG] ACME Tool not working for DNS challenge with INWX

- **Verdict:** already-fixed
- **Summary:** INWX DNS challenge: '[id] expected type int, got unconvertible type string'.
- **Evidence:** Caused by an INWX API change; fixed in lego v4.29.0 ('inwx: fix API breaking changes with record IDs', CHANGELOG.md of lego). dev builds against lego v5.5.2 (go.mod) which contains it. Not verified against the live INWX API.

### #924 [ENHANCEMENTS] Bulk Edit HTTP Proxy

- **Verdict:** feature-request
- **Summary:** Bulk edit of HTTP proxy rules, bigger edit button.
- **Evidence:** No bulk edit in dev.
- **Notes:** Effort M-L. Value medium for many-rule users; could build on tags (select tag -> apply setting). Related to proxy-rule templates (#877).

### #934 [HELP] Zoraxy behind Haproxy, Receive Proxy Protocol

- **Verdict:** already-fixed
- **Summary:** Receive PROXY protocol (HAProxy send-proxy-v2) on the TLS listener.
- **Evidence:** dev has a PROXY protocol v1/v2 toggle on the TLS listener (Option.UseProxyProtocol, HandleProxyProtocolChange in reverseproxy.go, 'PROXY Protocol' switch in web/components/globalsettings.html). It is mutually exclusive with HTTP/3 and is still marked experimental upstream (reported to break Nextcloud). No automated test; not exercised against a real HAProxy.
- **Notes:** Port-80 listener does not accept PROXY protocol (TLS listener only).

### #950 [BUG] Speedtest through proxy - Upload is not realistic

- **Verdict:** cannot-reproduce
- **Summary:** OpenSpeedTest through Zoraxy reports 25+ Gbit/s upload on a 10 GbE network.
- **Evidence:** Zoraxy streams request bodies through httputil-style copying and cannot exceed the link; the dashboard graph reads kernel NIC counters (hence the Docker/loopback double counting). The browser's upload progress measures bytes handed to the socket, which a buffering intermediary inflates. Not reproducible without the reporter's network.
- **Notes:** Suggest iperf3 or curl --upload-file as ground truth and testing with `-disablehttp2` / `-h2_conn_buffer`.

### #954 [HELP] UI Crash "Cannot read properties of null (reading 'map')" when using "Pick from Docker Containers"

- **Verdict:** already-fixed
- **Summary:** Pick from Docker Containers crashes with 'Cannot read properties of null (reading map)'.
- **Evidence:** web/snippet/dockerContainersList.html normalises container.Ports (Array.isArray ? Ports : []) since 9a01fe8 ('fix: normalize null container ports'). UI code, verified by reading only (no browser run).

### #958 [HELP] Forward auth with VoidAuth

- **Verdict:** needs-hardware-or-env
- **Summary:** Forward auth with VoidAuth ends in a redirect loop.
- **Evidence:** Requires a running VoidAuth. Generic forward-auth settings in dev (preserve host, X-Original headers, cookie/header allow-lists) cover the common causes; an auth cookie whose domain does not cover the app host causes exactly this loop.
- **Notes:** Need: VoidAuth proxyauth config, its cookie domain, and Zoraxy forward-auth options used.

### #959 [HELP] Are there any guides to get Google OAuth2 configured?

- **Verdict:** support-question
- **Summary:** How to configure Google as OAuth2/OIDC provider.
- **Evidence:** dev supports OIDC discovery by issuer (mod/auth/sso/oauth2/oidc.go) with PKCE and a discovery test button.
- **Notes:** Draft reply: Issuer/Auth URL `https://accounts.google.com`, client id/secret from the Google Cloud console, and register the redirect URI that the Zoraxy SSO page shows with Google; scopes `openid email profile`. Selecting OAuth2 must be done per rule under Security > Authentication Provider.

### #969 [ENHANCEMENTS] mark rc* as early access

- **Verdict:** already-fixed
- **Summary:** Mark rc releases as GitHub pre-releases.
- **Evidence:** Fork process: DEVELOPMENT.md 'Cutting a release' says to tick pre-release for the beta channel and the in-app updater's beta channel only offers pre-releases (mod/updater). Upstream's release practice is outside the fork.

### #971 [BUG] Uptime monitor fails with self-signed certificate

- **Verdict:** cannot-reproduce (fork commit 70c7d3e)
- **Summary:** Uptime monitor fails against an IPMI with self-signed certificate despite 'Skip Verification'.
- **Evidence:** TestGetWebsiteStatusSelfSignedCertificate (70c7d3e): with skip-verification the monitor reports 200 against a self-signed TLS server. 'tls: handshake failure' in the report is a TLS version/cipher mismatch with the old IPMI firmware, not certificate verification. The 'https://host:80' log line comes from the monitor's http<->https fallback retry.
- **Notes:** Needs the IPMI's TLS versions/ciphers. The 521 through the proxy has the same cause (Go cannot handshake).

### #974 [ENHANCEMENTS] Support secure-websocket for HTTP Upstream connections

- **Verdict:** cannot-reproduce
- **Summary:** Secure WebSocket (wss) towards HTTP upstreams.
- **Evidence:** The request is not well defined: wss implies TLS to the upstream, which is the 'Require TLS' upstream option; plain-HTTP upstreams use ws. Upgrade/WebSocket handling is covered by dpcore tests.
- **Notes:** Ask the reporter for the failing request (Beszel/Bezsel hub) and logs; the usual cause of 400 is the WebSocket origin check ('Skip WebSocket Origin Check').

### #986 [ENHANCEMENTS] [Perf] Use a Trie for IP lookups instead of a hashmap

- **Verdict:** feature-request
- **Summary:** Use a trie instead of a linear scan for IP blacklist lookups.
- **Evidence:** Confirmed: mod/access/blacklist.go IsIPBlacklisted does a map lookup then loops over every entry calling MatchIpWildcard and MatchIpCIDR per request (O(n), CIDR parsed each time).
- **Notes:** Effort M: pre-parse CIDRs into a prefix trie/`netip.Prefix` set with an RWMutex. Value high once large imported blocklists are used (#1100). Would interact with the fork's GeoIP/blacklist work, so not done here.

### #993 [ENHANCEMENTS] Mobile reCAPTCHA

- **Verdict:** support-question
- **Summary:** reCAPTCHA breaks iOS/Android apps that use the proxied API.
- **Evidence:** Mobile apps cannot solve a browser challenge. dev has CAPTCHA exception rules by path prefix and CIDR (mod/dynamicproxy/captcha/captcha.go ExceptionRule), but they are only editable in the config JSON.
- **Notes:** Draft reply: exclude the app's API paths (or the app's source IPs) with a CAPTCHA exception rule. A UI for these rules is tracked with #1161.

### #996 [ENHANCEMENTS] Swagger Documentation

- **Verdict:** feature-request
- **Summary:** OpenAPI/Swagger documentation of the admin API.
- **Evidence:** No OpenAPI spec in dev.
- **Notes:** Effort M (spec for ~150 handlers; could be generated from api.go route table). Value medium, helps plugin/automation authors.

### #1006 [ENHANCEMENTS] Allow Basic Auth Credential list, so it can be reused.

- **Verdict:** feature-request
- **Summary:** Reusable list of Basic Auth credentials.
- **Evidence:** Credentials are stored per proxy rule (AuthenticationProvider.BasicAuthCredentials).
- **Notes:** Effort M: named credential groups referenced from rules. Maintainer acknowledged it.

### #1012 Headscale with reverse proxy Zoraxy not working because allegedly WebSockets are not passing through

- **Verdict:** already-fixed
- **Summary:** Headscale (TS2021 Upgrade) does not work through Zoraxy: 'No Upgrade header in TS2021 request'.
- **Evidence:** dev forwards generic HTTP Upgrade requests when the per-rule option 'Enable Upgrade Forwarding' (EnableUpgradeForwarding) is on: dpcore AllowUpgrade, tests TestUpgradeTunnelsBidirectionally, TestUpgradeIsBlockedByDefault etc. (commit 6a74358) all pass. Not exercised against a real Headscale/Tailscale client.
- **Notes:** Reporters must enable 'Enable Upgrade Forwarding' on the rule. Marked unverified with a real client, so not proposed for closing.

### #1029 [HELP] NetBird setup

- **Verdict:** feature-request
- **Summary:** NetBird behind Zoraxy (needs h2c / gRPC to plain-HTTP upstream).
- **Evidence:** Zoraxy has an h2c round tripper (mod/dynamicproxy/modh2c) with a test, but it is not wired into the proxy (no `h2c://` upstream handling). The fork's gRPC bidi-stream fix (v3.3.5-rc5-grpcfix.1) fixed the body peek deadlock but does not add h2c.
- **Notes:** Effort M: upstream option 'HTTP/2 cleartext (h2c)' selecting modh2c in dpcore. Value high (NetBird, Headscale-gRPC, any gRPC backend). Needs a NetBird setup to verify end to end.

### #1032 [HELP] Authentication Issues with oauth2-proxy Behind Zoraxy and Cloudflare Tunnel

- **Verdict:** needs-hardware-or-env
- **Summary:** oauth2-proxy via forward auth behind Cloudflare Tunnel loops/fails.
- **Evidence:** Needs the full cloudflared + oauth2-proxy + Entra ID setup. Most likely causes: cookie domain/path (`cookie_path=/oauth2` and `samesite=none`), the auth URL pointing at the public hostname instead of an internal one (see #793), or Host/X-Forwarded-* rewriting by the tunnel.
- **Notes:** Ask for forward-auth address, header lists and a HAR of the redirect chain.

### #1042 [ENHANCEMENTS] Secondary Listening Ports

- **Verdict:** feature-request
- **Summary:** Secondary listening ports have no TLS.
- **Evidence:** startSecondaryListeners (dynamicproxy.go) starts plain http.Servers via handleNonTLSRequest; no TLS config. The UI text suggests otherwise.
- **Notes:** Effort M: serve TLS on secondary ports using the same certificate manager (tlsConfig of the primary server). Value medium-high (exposing selected hosts on a different port). Also fix the misleading UI description in the meantime.

### #1046 [ENHANCEMENTS] add notifications ( i.e. shoutrrr ) to uptime monitor

- **Verdict:** feature-request
- **Summary:** Notifications (shoutrrr) from the uptime monitor.
- **Evidence:** No notification sender in dev.
- **Notes:** Effort M: reuse the event system (#899): notification sink + uptime up/down events. Roadmap section 9 (observability).

### #1067 [ACME] selfhostde RID mapping input field missing

- **Verdict:** real-bug-open
- **Summary:** selfhost.de DNS challenge: 'missing record mapping' - no UI field for the RID mapping.
- **Evidence:** Confirmed from code: lego selfhostde.Config.RecordsMapping is map[string]*Seq and is listed under HiddenFields in mod/acme/acmedns/providers.json, so the UI cannot supply it and the provider always fails.
- **Notes:** Root cause: unsupported field type in the generated provider config. Fix: expose a 'RecordsMapping' text field in the format `domain:id1:id2,...` and parse it in acme_dns.go like the Plesk special case. Size S-M (the field type needs a custom parser plus UI text field).

### #1070 [ENHANCEMENTS] Multi-Node sync / cluster mode for anycast deployments

- **Verdict:** feature-request
- **Summary:** Multi-node sync / cluster mode.
- **Evidence:** Not implemented; ROADMAP section 6 (High availability) and fork issue #81.
- **Notes:** Effort L; in flight by another agent (cluster code).

### #1073 [ENHANCEMENTS] Support for Passkey (WebAuthn) in Zoraxy Auth

- **Verdict:** already-fixed
- **Summary:** Passkey (WebAuthn) support in Zoraxy Auth.
- **Evidence:** dev has ZorxAuth passkeys (mod/auth/sso/zorxauth/passkey.go: register begin/complete, list, remove, auth begin/complete, go-webauthn) and TOTP 2FA (typedef.go TOTPSecret, Enable2FA). No automated tests; not exercised with a real authenticator.

### #1075 [ENHANCEMENTS] Make access control available to Stream Proxy as well?

- **Verdict:** already-fixed
- **Summary:** Access control for the stream proxy.
- **Evidence:** dev has per-stream-rule access rules: ProxyRelayInstance.AccessRuleUUID, getEffectiveAccessRule and AllowIpAccess checks for TCP and UDP (mod/streamproxy/streamproxy.go, udpprox.go; commit e41031a 'add stream proxy access rules'). The new UDP test TestUDPIdleSessionsAreReleased exercises the same relay.

### #1087 [BUG] 3.3.2 Denies access

- **Verdict:** support-question
- **Summary:** 3.3.2 returns 403 for Cloudflare users with a country whitelist; downgrade fixes it.
- **Evidence:** By design since the trusted-proxy change: AccessRule.GetClientIP (mod/access/trustedProxy.go) only honours X-Real-IP/CF-Connecting-IP/X-Forwarded-For when the rule has 'trust proxy headers' enabled and the TCP peer is in the trusted list. With it off the peer address (Cloudflare edge, cloudflared on loopback) is what the whitelist sees, so a country whitelist rejects it. Reporter's IPv6 resolves to DE; the 100.67.x address resolves to the CarrierNAT zone (geodb test).
- **Notes:** Draft reply: enable 'Trust proxy headers' in the access rule and make sure the peer (Cloudflare ranges are preloaded; for cloudflared add 127.0.0.1 / its docker subnet) is in the trusted proxy list; also whitelist CarrierNAT if IPv4 CGNAT clients matter. The same applies to the tunnel certificate errors in the uptime monitor log of the second reporter: that needs 'Skip verification' on that upstream. Consider a migration note in the release notes.

### #1095 [HELP] Custom Error 521 template , how to set ?

- **Verdict:** support-question
- **Summary:** Custom 521 error page.
- **Evidence:** Supported: serveProxyRequestError (mod/dynamicproxy/proxyRequestHandler.go) loads `<webroot>/templates/rperror.html` for 521 (also `hosterror.html` for 404 host-not-found and `forbidden.html`).
- **Notes:** Draft reply: put the page at `www/templates/rperror.html` (webroot is the `-webroot` flag, default ./www; in Docker the mapped www folder). The maintainer's statement that there is no 521 template is outdated.

### #1100 [ENHANCEMENTS] - Import a list of Blacklist IP

- **Verdict:** support-question
- **Summary:** Import a list of IPs into the blacklist.
- **Evidence:** A community plugin exists (zoraxy-blocklist-import-plugin, linked in the thread). Core has no bulk import.
- **Notes:** Draft reply: use the plugin. A native 'import from file/URL' in core would also need the blacklist lookup rewrite (#986). Fork issue #113 tracks bulk import.

### #1102 [HELP] Transmission web UI returns 521 when proxied

- **Verdict:** support-question
- **Summary:** Transmission web UI gives 521 behind Zoraxy.
- **Evidence:** 521 means Zoraxy could not connect to the upstream. Transmission also validates the Host header (rpc-host-whitelist) and redirects /transmission/web, but those produce 4xx, not 521.
- **Notes:** Draft reply: check the upstream is `10.10.100.223:9091` (or a hostname resolvable from the Zoraxy host - `transmission.internal` must resolve on the proxy host), test `curl` from the proxy host, and look at the proxy log line (`[router:host-http]`) and the 'upstream' column.

### #1107 [BUG] The "Require Rate Limit" is not a setting per HTTP Proxy

- **Verdict:** already-fixed
- **Summary:** 'Require Rate Limit' value is shared between proxy rules in the UI.
- **Evidence:** UI bug in the shared editor; fixed in dc05233 (web/components/httprp.html loads the saved value with .val() per proxy). Verified by reading the code only (no browser run). The backend stores the value per rule.

### #1109 [ENHANCEMENTS]  Auto-tagging based on Authentication Provider + audit/enforcement

- **Verdict:** feature-request (fork commit 4eac194)
- **Summary:** Auto-tag proxy rules with their auth provider and audit/enforce.
- **Evidence:** Not implemented. Separately, a likely cause of the reporter's 'AuthMethod silently became None' was found: ReverseProxyHandleEditEndpoint defaulted a missing `authprovider` form value to "0" (None), so any stale cached UI/API client/plugin posting an edit without it removed the authentication. Fixed in 4eac194 (a missing parameter now keeps the current method). This is a hypothesis for the report; other fields in that handler (rate limit, captcha, exploit blocking) still reset to off when absent.
- **Notes:** Follow-up (S-M): make the edit handler a true partial update for all security fields, or require a schema/version parameter. Auto-tagging itself: effort S, value low-medium.

### #1117 [BUG] Cannot generate certificate from ZeroSSL. listen tcp :56563: bind: address already in use

- **Verdict:** real-bug-open
- **Summary:** ACME HTTP challenge: 'listen tcp :56563: bind: address already in use'; renew spinner never ends.
- **Evidence:** Not reproduced. Code reading: the HTTP-01 provider listens on a random port >= 30000 chosen once at start-up (acme.go getRandomPort + IsPortInUse) and ObtainCert has no mutex (no mutex in mod/acme/acme.go, mod/acme/autorenew.go or the main package acme.go). Concurrent obtain/renew requests (auto-renew + manual click, several SAN names) use the same port and collide; a port in the ephemeral range can also be taken later by an outbound socket.
- **Notes:** Suggested fix (S): serialise ObtainCert/renew with a mutex, and re-check/pick a free port immediately before SetHTTP01Provider; surface the error in the UI instead of an endless spinner. Reporters in ZeroSSL-restricted countries also hit CA-side restrictions.

### #1118 [HELP] Using X-Auth-User header variable with Pocket ID and Navidrome

- **Verdict:** support-question
- **Summary:** Pass the OIDC user name to Navidrome via X-Auth-User (Pocket ID).
- **Evidence:** dev maps claims to upstream headers: 'Header=claim' pairs (OAuth2HeaderMappings, mod/auth/sso/oauth2/claims.go ParseHeaderMappings; field in web/components/sso.html). Custom headers in the proxy rule are static strings, which is why `${username}` is passed literally.
- **Notes:** Draft reply: in SSO/OAuth2 settings set header mappings to `X-Auth-User=preferred_username` (or `sub`/`email`) and remove the static X-Auth-User header from the rule.

### #1119 [ENHANCEMENTS] Certificate watch folder - or another automatic existing certificate import feature.

- **Verdict:** duplicate
- **Summary:** Certificate watch folder / automatic import of existing certificates.
- **Evidence:** Same request as #798 (import certs placed in a folder, e.g. from certbot).
- **Proposed:** close

### #1123 [ENHANCEMENTS] Allow user to select ACME certificate key type (RSA/ECDSA) instead of hardcoded RSA2048

- **Verdict:** feature-request
- **Summary:** Choose ACME key type (RSA2048/3072/4096, EC256/384).
- **Evidence:** Hardcoded: mod/acme/acme.go line ~361 KeyType: certcrypto.RSA2048.
- **Notes:** Effort S-M: add `keyType` to the obtain request, persist in <name>.json (CertificateInfoJSON) so renewals keep it, dropdown in the ACME tool. Default stays RSA2048. zen8841 was asked to take it.

### #1156 [ACME] DNS Challenge with plesk.com -> baseURL not working

- **Verdict:** fixed-by-you (fork commit 3dca06d)
- **Summary:** Plesk DNS challenge always fails with 'plesk: missing server base URL'.
- **Evidence:** Root cause: lego's plesk.Config.baseURL is an unexported field, so the JSON-based provider factory dropped the UI value. Fixed in 3dca06d (mod/acme/acme_dns_plesk.go sets the field with reflect/unsafe, special-cased in acme_dns.go); test TestDNSProviderPleskBaseURL failed before (error 'missing server base URL') and passes now.
- **Notes:** Verified with provider construction only; no live Plesk server. Other lego providers with unexported config fields would need the same treatment (none found in the provider list besides Plesk).
- **Proposed:** close

### #1161 [ENHANCEMENTS] Path‑Level reCAPTCHA Exemptions

- **Verdict:** feature-request
- **Summary:** Path-level CAPTCHA exemptions.
- **Evidence:** Backend exists: captcha.ExceptionRule (path prefix or CIDR) evaluated in the CAPTCHA gating (tests in mod/dynamicproxy/captcha/captcha_exception_test.go and captcha_gating_test.go). But buildCaptchaConfigFromRequest (reverseproxy.go) never reads exception rules from the request and there is no UI, so they are config-file only and are dropped when the rule is edited (fork issue #200).
- **Notes:** Effort S-M: UI + API fields for ExceptionRules and keep them on edit. Crawler exemption (Googlebot, second reporter) needs UA + reverse-DNS verification and is a separate feature.

### #1162 [ENHANCEMENTS] Path‑Level OAuth2 Exemptions

- **Verdict:** feature-request
- **Summary:** Path-level OAuth2 exemptions (and per-route provider, email allow-list).
- **Evidence:** No ignored-paths option for OAuth2 in dev; forward auth has 'Ignored Paths' (mod/auth/sso/forward/ignoredpaths.go) and ZorxAuth/Basic have exception rules. OAuth2 allow-list by group exists globally.
- **Notes:** Effort M: reuse the forward-auth ignored-path matcher for OAuth2. Value high (manifest.json, webhooks, API paths). Roadmap section 4.

### #1165 [ENHANCEMENTS] Bypass Zoraxy Auth for internal requests (e. g. from LAN subnet)?

- **Verdict:** already-fixed
- **Summary:** Bypass Zoraxy Auth for LAN subnets.
- **Evidence:** ZorxAuth exception rules support path prefix/regex and IP/CIDR (dynamicproxy.ZorxAuthExceptionRule, zorxAuthExceptionMatched in mod/dynamicproxy/authProviders.go, 'ZorxAuth Exceptions' editor in the proxy rule UI). Not covered by a ZorxAuth-specific unit test; the identical Basic Auth CIDR matcher is (TestBasicAuthExceptionMatchedCIDR).

### #1174 Looking for a new Docker maintainer

- **Verdict:** support-question
- **Summary:** Maintainer announcement: looking for a Docker maintainer.
- **Evidence:** Not a bug or feature; project governance.
- **Notes:** Nothing to do for the fork (the fork does not maintain the Docker image).

### #1186 [ENHANCEMENTS] Show Stream Proxy rules in the Status page network diagram

- **Verdict:** feature-request
- **Summary:** Show stream proxy rules in the Status page network diagram.
- **Evidence:** Not implemented.
- **Notes:** Effort S-M (UI only). Value low-medium.

### #1193 [ENHANCEMENTS] [ACME] Stale DNS credentials/metadata after cert delete + no UI to rotate credentials of existing cert

- **Verdict:** fixed-by-you (fork commit d66b8e5)
- **Summary:** Cert deletion leaves <name>.json and acme DB keys; no UI to rotate DNS credentials.
- **Evidence:** Part (a) fixed in d66b8e5: tlscert.Manager.RemoveCert now also deletes <name>.json and calls OnCertRemoved, which start.go wires to delete the acme/<name>_dns_provider|_dns_credentials|_dns_servers keys; test TestRemoveCertDeletesAcmeMetadata. Parts (b) credential editor and (c) reset-all remain open.
- **Notes:** Remaining (b): expose HandleSetDNS as an 'edit DNS credentials' action (M). Related #1332. Stale state previously also forced ObtainCert to use the old challenge type via certInfo.UseDNS.

### #1198 [ENHANCEMENTS] More Captcha providers - Altcha & FriendlyCaptcha

- **Verdict:** feature-request
- **Summary:** More CAPTCHA providers (Altcha, FriendlyCaptcha).
- **Evidence:** Providers are Cloudflare Turnstile and Google reCAPTCHA only (captcha.Provider).
- **Notes:** Effort M: Altcha is self-hosted proof-of-work (no third party, fits air-gapped installs). Roadmap section 3. Value medium-high for privacy-minded users.

### #1201 [ENHANCEMENTS] Dropdown & Sidebar tweaks

- **Verdict:** cannot-reproduce
- **Summary:** UI dropdown/sidebar glitches in 3.3.3.
- **Evidence:** Reporter confirmed it was a stale 3.3.2 browser cache; only cosmetic wishes (chevron animation, divider) remain.
- **Notes:** Nothing to fix.

### #1207 [BUG] UDP stream proxy never releases per-client sockets/goroutines (Timeout ignored) → socket/goroutine leak and eventual forwarding stall

- **Verdict:** already-fixed (fork commit a6653f5)
- **Summary:** UDP stream proxy never releases per-client sockets/goroutines.
- **Evidence:** mod/streamproxy/udpprox.go (2b8ee8a) adds an idle timeout (rule Timeout, default 60 s), removes sessions with CompareAndDelete and stops on read errors. New test TestUDPIdleSessionsAreReleased (a6653f5) passes on dev and fails on the pre-fix file (20 sessions never released).
- **Proposed:** close

### #1208 [ENHANCEMENTS] add limit_rate for http proxy

- **Verdict:** feature-request
- **Summary:** limit_rate (bandwidth limit) for HTTP proxies.
- **Evidence:** Not implemented; the rate limiter is requests per second only.
- **Notes:** Effort M: wrap the response writer with a token-bucket throttle per request or per IP. Value medium (Nextcloud downloads).

### #1243 [ENHANCEMENTS] Logging Feature Enhance

- **Verdict:** feature-request
- **Summary:** Access-log viewer with filtering in the admin UI.
- **Evidence:** Not implemented; a contributor announced a plan in the thread (per-site monthly logs, backend filter API).
- **Notes:** Effort M-L. Roadmap section 9 (structured logging) overlaps.

### #1267 [ENHANCEMENTS] Add support for multiple ACME certificate authorities and per-certificate CA assignments

- **Verdict:** feature-request
- **Summary:** Multiple ACME CAs/profiles with per-certificate assignment.
- **Evidence:** Single global CA today. The 'skipTLS key case mismatch' mentioned in the thread does not exist on dev: UI and handler both use `skipTLS` (acme.go).
- **Notes:** Effort L (account/EAB separation, migration). Value medium (internal step-ca + public CA).

### #1297 [ENHANCEMENTS] WAF plugin support / Coraza integration

- **Verdict:** already-fixed
- **Summary:** WAF / Coraza integration.
- **Evidence:** The fork added a core WAF (Coraza + OWASP CRS v4) per endpoint: mod/dynamicproxy/waf, WAF-HOOK in Server.go, tests waf_integration_test.go and TestNonTLS_WAFBlocksAttackAndPassesCleanRequest. The request for a plugin inspection hook is tracked separately (fork issue #83, ROADMAP section 8).

### #1319 [ENHANCEMENTS] Native Support for Encrypted Client Hello (ECH)

- **Verdict:** feature-request
- **Summary:** Encrypted Client Hello (ECH).
- **Evidence:** Not implemented; go.mod is Go 1.26 which has server-side ECH in crypto/tls.
- **Notes:** Effort L (key management, rotation, DNS publication guidance, tests). Value low-medium. Needs security review.

### #1332 [ENHANCEMENTS] Allow reuse of DNS challange credentials across proxies

- **Verdict:** feature-request
- **Summary:** Reuse DNS-challenge credentials across certificates.
- **Evidence:** Credentials are stored per certificate name (acme/<name>_dns_*).
- **Notes:** Effort M: named credential sets. Related to the open part of #1193. zen8841 planned a provider-settings store.

### #1334 [BUG] IPv6 GeoIP maps Malaysian ISPs to AU; hardcoded geo-whois-asn-country source is deprecated upstream

- **Verdict:** real-bug-open
- **Summary:** IPv6 GeoIP maps Malaysian prefixes to AU; update source deprecated.
- **Evidence:** Reproduced: embedded mod/geodb/geoipv6.csv contains a single row `2001:cf1::,2001:d27:ffff:...,AU` spanning other countries; lookups of 2001:d08::1, 2001:f40::1, 2001:e68::1 all return AU on dev. The updater (mod/geodb/updater.go) downloads the same deprecated npm dataset `@ip-location-db/geo-whois-asn-country`.
- **Notes:** Root cause: bad data + deprecated source. Fix (M): switch the source and embedded CSVs to a maintained dataset with an acceptable licence (the thread proposes sapics user-country, PDDL), regenerate geoipv4/geoipv6.csv, add the three prefixes as test cases in geodb_test.go. Cannot be done offline here.

### #1342 [ACME] BypassGlobalTLS ("Allow plain HTTP access") hosts never see the HTTP-01 challenge handler

- **Verdict:** already-fixed
- **Summary:** Hosts with 'Allow plain HTTP access' never reach the ACME HTTP-01 handler.
- **Evidence:** The port-80 bypass path now shares the pre-proxy chain: handleNonTLSRequest calls handleSpecialAndRedirect first (mod/dynamicproxy/dynamicproxy.go, Server.go), which runs routing rules such as acme-autorenew (#84 refactor d3add94). Test TestNonTLS_SpecialRoutingRuleApplies passes; the pre-d3add94 handleNonTLSRequest had no such call.
- **Proposed:** close

### #1343 [ENHANCEMENTS] Per-route option to disable upstream keep-alive (and note on what "Force HTTP/1.1" actually does)

- **Verdict:** real-bug-open
- **Summary:** Reused keep-alive connections to upstreams that close after each response cause 502/521; ForceHTTP11 only helps by accident.
- **Evidence:** Confirmed by code: dpcore.ProxyHTTP clones the transport per request when ForceHTTP11 (trc = tr.Clone(), dpcore.go ~418), giving an empty idle pool; the base transport keeps connections (DisableKeepAlives:false). There is no per-upstream keep-alive option, and MaxConn only sets MaxIdleConns*.
- **Notes:** Suggested fix (S): per-upstream `DisableKeepAlive` option (transport DisableKeepAlives:true on that upstream's transport), plus relabel/document ForceHTTP11 and MaxConn. Cloning the transport per request also leaves idle connections to age out (resource cost). Maintainer plans an experimental option in 3.3.6-rc1.

### #1344 [ENHANCEMENTS] Add a toggle to exclude blocked IPs from traffic statistics

- **Verdict:** feature-request
- **Summary:** Toggle to exclude blocked requests from statistics.
- **Evidence:** Blocked requests are recorded through logRequest with succ=false (proxyRequestHandler.go); no toggle.
- **Notes:** Effort S: global/endpoint setting that skips RecordRequest for forward types blacklist/whitelist/captcha/waf. Value medium.

### #1351 [ENHANCEMENTS] Tell plugins which proxy rule matched in dynamic capture sniff

- **Verdict:** feature-request
- **Summary:** Tell plugins which proxy rule matched in the dynamic capture sniff payload.
- **Evidence:** HandleRoute already receives sep.Tags; DynamicSniffForwardRequest has no rule fields.
- **Notes:** Effort S, additive JSON fields (matched_rule, tags). Roadmap section 8 / fork #83. Touches the plugins package that is being rewritten, so not done here.

### #1354 Feature Request: Display Full URLs in Top Requested Paths

- **Verdict:** feature-request
- **Summary:** Show full URLs (host + query) in 'Top Requested Paths'.
- **Evidence:** Statistics store host+escaped path without query by design (logRequest: RequestURL = r.Host + EscapedPath()).
- **Notes:** Effort S-M and privacy sensitive (query strings carry tokens); needs an opt-in plus masking as the reporter suggests.

### #1356 [ENHANCEMENTS] Header-based access rules: drop requests missing required headers/values

- **Verdict:** feature-request (fork commit 889873a)
- **Summary:** Header-based access rules (require header X-Origin-Auth, drop otherwise).
- **Evidence:** Already expressible with the per-endpoint WAF custom SecLang rules: TestWAFCustomRuleRequiresHeader (889873a) rejects requests without/with a wrong header and passes the right one. Missing relative to the request: silently dropping the connection, stripping the header before forwarding, UI for simple header conditions.
- **Notes:** Draft workaround: `SecRule &REQUEST_HEADERS:X-Origin-Auth "@eq 0" "id:100001,phase:1,deny,status:403"` and `SecRule REQUEST_HEADERS:X-Origin-Auth "!@streq <token>" "id:100002,phase:1,deny,status:403"`. Maintainer suggested a plugin (fork #83).

### #1359 [BUG] Upstream X-Forwarded-For / X-Real-IP can be spoofed by clients: trusted proxy list not applied to headers sent to backends

- **Verdict:** fixed-by-you (fork commit aa42d1d)
- **Summary:** Clients can spoof X-Forwarded-For/X-Real-IP/CF-Connecting-IP forwarded to upstreams.
- **Evidence:** Fixed in aa42d1d for access rules with 'trust proxy headers' enabled: StripUntrustedClientIPHeaders (mod/access/trustedProxy.go), called from handleAccessRouting (mod/dynamicproxy/access.go), removes X-Forwarded-For, X-Real-Ip, Forwarded, CF-Connecting-IP, Fastly-Client-IP, True-Client-IP, X-Client-IP from requests whose TCP peer is not in the trusted list, so dpcore rebuilds them from the real peer. Test TestUntrustedClientIPHeadersAreStripped fails without the call and passes with it; rules that never enabled the option behave exactly as before.
- **Notes:** Residual gap (open): with the option OFF (the default) Zoraxy still forwards client-supplied headers unchanged to preserve existing setups behind CDNs. Possible follow-up (S-M): make the option on by default for new installs or add a separate 'sanitise client IP headers' switch; also decide leftmost vs rightmost X-Forwarded-For when the peer is trusted.
