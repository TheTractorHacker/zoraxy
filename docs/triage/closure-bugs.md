# Closure bugs: verification of fork issues for upstream reports already believed fixed

Branch `fix/closure-bugs`. Every entry has a test or a documented audit; commits are on the branch (see `git log`).

Verdict counts: cannot-verify: 2, fixed-now: 7, not-a-bug: 5, verified-fixed: 16

| fork | upstream | verdict | close | commit | evidence |
|---|---|---|---|---|---|
| #28 | #33 | verified-fixed | yes | - | mod/auth/sso/forward tests (TestForwardOAuth2ProxySemantics, TestForwardAutheliaRedirectPassthrough, TestForwardVoidAuthCookieAndRedirect, authentik_test.go), mod/dynamicproxy TestForwardAuthExceptionsEndToEnd |
| #71 | #331 | verified-fixed | yes | - | mod/acme/acme_dns_int_test.go (numeric MaxRetries accepted, string value still gives the quoted error) |
| #170 | #831 | verified-fixed | yes | - | mod/access/trustedProxy_test.go, mod/dynamicproxy/clientip_headers_test.go, captcha_gating_test.go, ratelimit_test.go (CF-Connecting-IP of trusted peers drives access rules, rate limit and logs) |
| #182 | #922 | verified-fixed | yes | - | mod/acme TestDNSProviderINWX; lego v5.5.2 inwx provider uses string record IDs (goinwx v0.12.0) |
| #186 | #934 | verified-fixed | yes | 1825867 | mod/dynamicproxy TestProxyProtocolListenerExposesRealClientAddress (v1 and v2 headers) |
| #188 | #954 | fixed-now | yes | 0495438 | tools/ui-smoke/regress.py scenario docker-picker-null (fails before the fix with exactly 'Cannot read properties of null (reading map)') |
| #191 | #969 | fixed-now | yes | dadde4e | mod/updater TestMarkEarlyAccess; tools/ui-smoke/regress.py scenario updater-early-access |
| #199 | #1012 | verified-fixed | yes | - | mod/dynamicproxy/dpcore TestUpgradeTunnelsBidirectionally, TestUpgradeIsBlockedByDefault; dynamicproxy TestWebSocketUpstreamMatrix |
| #207 | #1073 | verified-fixed | yes | 6946cf3 | mod/auth/sso/zorxauth TestPasskeyAuthBeginBindsRelyingPartyToHost; passkey.go register/list/remove/auth endpoints |
| #208 | #1075 | verified-fixed | yes | 6dde353 | mod/streamproxy TestStreamProxyAppliesAccessRule, TestRejectedClientDoesNotStallAcceptLoop |
| #215 | #1107 | verified-fixed | yes | bcfc5aa | mod/dynamicproxy TestHandleRateLimit_IsPerProxyRule; UI scenario not needed (editor loads the saved value per rule since dc05233) |
| #224 | #1165 | verified-fixed | yes | 6dde353 | mod/dynamicproxy TestZorxAuthExceptionByCIDR |
| #234 | #1297 | verified-fixed | yes | - | mod/dynamicproxy waf_integration_test.go, TestNonTLS_WAFBlocksAttackAndPassesCleanRequest |
| #124 | #611 | verified-fixed | yes | 0495438 | tools/ui-smoke/regress.py scenario cert-multi-domain |
| #132 | #655 | verified-fixed | yes | - | src/acme_challenge_test.go |
| #221 | #1156 | verified-fixed | yes | - | mod/acme TestDNSProviderPleskBaseURL (failed before the fix) |
| #227 | #1193 | verified-fixed | yes | 887ce40 | mod/tlscert TestRemoveCertDeletesAcmeMetadata; mod/acme TestDNSProfileCredentialRotation |
| #116 | #518 | verified-fixed | yes | 6a181e8 | mod/email TestSendEmailWithoutAuthentication, TestSendEmailUsernameOnlyDoesNotAuth |
| #117 | #537 | not-a-bug | no | f06676f | mod/acme TestExplainACMEError; mod/dynamicproxy TestPort80AnswersACMEChallengeBeforeRedirectOrRejection |
| #163 | #816 | not-a-bug | yes | 1646041 | mod/auth/sso/forward TestForwardAuthAlwaysRedirectDoesNotLeak (7300+ requests in 20 s, goroutines 3 -> 3, heap flat); TestForwardAuthFailsClosedWhenAuthServerDown |
| #173 | #890 | not-a-bug | yes | - | mod/dynamicproxy TestNonTLS_VirtualDirectoryIsProxied (plain HTTP vdir with a different default upstream) |
| #187 | #950 | not-a-bug | yes | 3db74d4 | mod/dynamicproxy TestUploadIsStreamedThroughProxy (plain and WAF), TestUploadBackpressureReachesClient |
| #192 | #971 | fixed-now | yes | 0d86cee | mod/uptime TestGetWebsiteStatusSelfSignedCertificate, TestGetWebsiteStatusLegacyCipherUpstreamWithSkipVerify (failed before); dpcore uses the same TLS config |
| #194 | #974 | fixed-now | yes | 7391fa6 | mod/websocketproxy TestSkipTLSValidationDoesNotPoisonDefaultDialer (failed before); mod/dynamicproxy TestWebSocketUpstreamMatrix |
| #229 | #1201 | not-a-bug | yes | - | Reporter confirmed it was a stale 3.3.2 browser cache. |
| #95 | #403 | cannot-verify | no | dd1aa21 | mod/tlscert TestServedCertificateIncludesChain; mod/dynamicproxy TestMonitorStyleProbes (HEAD, keep-alive, unknown host) |
| #104 | #458 | fixed-now | no | 5dcee97 | mod/utils TestNormalizeHostname; mod/dynamicproxy TestProxyRuleMatchesUnicodeAndPunycodeHost; mod/tlscert TestGetCertificateByHostnameIDN |
| #143 | #698 | fixed-now | no | 1646041 | mod/auth/sso/forward TestForwardBehindTLSTerminatingTunnel, TestForwardAutheliaRedirectPassthrough |
| #189 | #958 | cannot-verify | no | 1646041 | mod/auth/sso/forward TestForwardVoidAuthCookieAndRedirect |
| #202 | #1032 | fixed-now | no | 1646041 | mod/auth/sso/forward TestForwardOAuth2ProxySemantics, TestForwardBehindTLSTerminatingTunnel |

## Real bugs found and fixed here

* WebSocket skip-verify mutated the shared `websocket.DefaultDialer`, switching off certificate verification for all WebSocket upstreams (upstream #974).
* Forward auth ignored a TLS-terminating trusted proxy: wrong scheme/client IP sent to the auth server (upstream #698, #1032).
* Unicode/punycode host names never matched between rules, SNI/certificates and ACME (upstream #458).
* Docker container picker crashed on rules without upstreams / empty Docker list (upstream #954).
* Skip-verify upstreams with legacy TLS/RSA-only ciphers (IPMI) failed in the proxy and uptime monitor (upstream #971).
* Added: early-access label for rc releases (#969), Let's Encrypt error hints (#537).

## Per issue notes

### fork #28 / upstream #33 (verified-fixed, close=true)

Forward authentication is implemented (per-rule `Forward` auth method plus the global forward-auth settings). Verified against fake oauth2-proxy, Authelia, VoidAuth and Authentik servers; see `mod/auth/sso/forward/compat_test.go`. Closing as completed.

### fork #71 / upstream #331 (verified-fixed, close=true)

The UI now sends integer credential fields as JSON numbers and the backend accepts them (`acme_dns_int_test.go`). The error can only come from credentials saved by a very old UI; re-save the DNS credentials once. Closing; reopen with the provider name if it still happens.

### fork #170 / upstream #831 (verified-fixed, close=true)

Behind Cloudflare, Zoraxy uses the real client address from `CF-Connecting-IP` / `X-Real-IP` when the connecting peer is in the Trusted Proxy list (Cloudflare ranges are the default), and country rules are evaluated on that address with the GeoIP database. A spoofed header from any other peer is ignored (tests listed in the evidence), which is the property the issue asked for. Reading `CF-IPCountry` directly is intentionally not done (it would let any client bypass country rules). Closing as completed.

Notes: If a human wants the literal CF-IPCountry header support it is a new feature with a trusted-peer gate; not needed for the reported use case.

### fork #182 / upstream #922 (verified-fixed, close=true)

The 'expected type int, got unconvertible type string' error came from INWX changing record IDs to strings; the lego/goinwx versions in this build use string IDs and the provider builds from the UI credentials (`TestDNSProviderINWX`). Not run against the live INWX API. Closing; please reopen with the log if the live API still fails.

Notes: Not exercised against the live INWX API.

### fork #186 / upstream #934 (verified-fixed, close=true)

Receiving the PROXY protocol (HAProxy `send-proxy` / `send-proxy-v2`) is available as the 'PROXY Protocol' option in global settings; the test feeds v1 and v2 headers and checks the handler sees the real client address. Note: it applies to the TLS listener only and is mutually exclusive with HTTP/3. Closing as completed.

### fork #188 / upstream #954 (fixed-now, close=true)

Reproduced in a headless browser: the picker still crashed with that error when a proxy rule had no upstreams (`ActiveOrigins: null`) or Docker returned no containers. The earlier fix only covered `Ports`. Fixed in `snippet/dockerContainersList.html` and covered by `tools/ui-smoke/regress.sh`. Closing as completed.

### fork #191 / upstream #969 (fixed-now, close=true)

The in-app updater now flags release candidates (`-rcN` tags) and GitHub pre-releases as 'early access / pre-release'. Channel selection still follows the GitHub pre-release flag. Marking the GitHub release itself as pre-release is part of the release procedure in DEVELOPMENT.md. Closing as completed.

Notes: Deliberately informational: making rc tags invisible on the stable channel would hide the fork's own rc-tagged releases.

### fork #199 / upstream #1012 (verified-fixed, close=true)

Generic HTTP Upgrade forwarding (Tailscale/Headscale TS2021 'controlupgrade') is supported per rule via 'Enable Upgrade Forwarding'; WebSocket upgrades work for ws and wss upstreams (tests listed). Turn that option on for the Headscale rule. Not run against a real Headscale. Closing as completed.

Notes: Needs the option enabled on the rule; not tested with a real tailscale client.

### fork #207 / upstream #1073 (verified-fixed, close=true)

ZorxAuth supports passkeys (register, list, remove, discoverable login) and TOTP. The login ceremony begin step is covered by a test (relying party bound to the browser-facing host, also behind a proxy). Signature verification with a physical authenticator was not exercised. Closing as completed.

Notes: No hardware authenticator test; the WebAuthn verification is delegated to go-webauthn.

### fork #208 / upstream #1075 (verified-fixed, close=true)

Stream proxy instances take an access rule (blacklist/whitelist, country, CIDR); a client outside the rule is refused for TCP and UDP. `TestStreamProxyAppliesAccessRule` proves it with a real relay. Closing as completed.

### fork #215 / upstream #1107 (verified-fixed, close=true)

Rate limiting is stored and enforced per HTTP proxy rule (separate counters per rule, `TestHandleRateLimit_IsPerProxyRule`), and the editor shows each rule's own value. Closing as completed.

### fork #224 / upstream #1165 (verified-fixed, close=true)

ZorxAuth exception rules accept IP/CIDR entries (e.g. `192.168.0.0/16`, IPv6 CIDR). A public client spoofing LAN addresses in X-Forwarded-For / X-Real-IP is still challenged unless the rule has 'trust proxy headers' on. Test: `TestZorxAuthExceptionByCIDR`. Closing as completed.

### fork #234 / upstream #1297 (verified-fixed, close=true)

A built-in WAF (Coraza + OWASP CRS) is available per proxy rule and covered by integration tests on both the TLS and the port-80 path. A plugin-level inspection hook is tracked separately (fork roadmap section 8). Closing as completed.

### fork #124 / upstream #611 (verified-fixed, close=true)

Requesting a certificate for a comma separated domain list now names the file after the first domain instead of failing with 'Filename cannot be empty'. Verified in a headless browser (the request carries `filename=<first domain>` and all domains). Closing as completed.

### fork #132 / upstream #655 (verified-fixed, close=true)

The ACME challenge relay no longer prints errors / returns an empty 200 when no issuance is running (404, status passthrough, token validation; `acme_challenge_test.go`). The odd log lines were scanners hitting `/.well-known/acme-challenge/`. Closing as completed.

### fork #221 / upstream #1156 (verified-fixed, close=true)

The Plesk `baseURL` field is now passed to the provider (it lives in an unexported lego field); `TestDNSProviderPleskBaseURL` failed before and passes now. Not verified against a live Plesk server. Closing as completed.

Notes: Provider construction only.

### fork #227 / upstream #1193 (verified-fixed, close=true)

(a) Deleting a certificate now also removes its `.json` metadata and the stored `acme/<name>_dns_*` keys. (b) DNS credentials are rotated by editing the saved DNS credential profile (ACME settings): secrets are masked, only changed fields are replaced, and certificates reference the profile so the next renewal uses the new token (`TestDNSProfileCredentialRotation`). (c) The optional global 'reset all ACME state' button was not implemented. Closing as completed for (a) and (b).

Notes: (c) bonus not implemented.

### fork #116 / upstream #518 (verified-fixed, close=true)

Email notifications go through the SMTP channel in Notification settings. When the password is left empty, Zoraxy sends without AUTH (checked against a fake port-25 relay that advertises no AUTH, `mod/email/email_test.go`). Closing as completed.

### fork #117 / upstream #537 (not-a-bug, close=false)

Let's Encrypt's 'Error getting validation data' means the CA could not fetch the HTTP-01 token from your server. Zoraxy answers `/.well-known/acme-challenge/` on port 80 before any redirect or host rule (tested), so the usual causes are outside Zoraxy: the domain's public DNS (CNAME to a DDNS name, A/AAAA/IPv6), port 80 not forwarded from the internet, or another service answering on port 80. Zoraxy now appends exactly this checklist to such errors. Leaving this open for the reporter to confirm with a current build; please post the new error text.

Notes: Needs the reporter's DNS/port-forwarding facts; v3.1.7 is far behind current code.

### fork #163 / upstream #816 (not-a-bug, close=true)

Tried again with a fake Authelia that always answers 302/401 with a 256 KiB body, 16 parallel clients, goroutine and heap sampling: no growth (goroutines 3 -> 3, heap ~600 KiB flat). The auth client never follows redirects, caps copied bodies and has a 15 s timeout. Set `ZORAXY_LEAK_SECONDS=300` to soak longer. Closing as not reproducible; if it still happens please attach `/api/info/pprof` heap output from the growing process (a second reporter saw growth without any forward auth, so it is probably elsewhere).

Notes: Tested the forward-auth module and request path; not the full process under real traffic.

### fork #173 / upstream #890 (not-a-bug, close=true)

Virtual directories are routed on both HTTPS and plain HTTP (when 'Allow plain HTTP access' is set), including the trailing-slash redirect; a rule with a different default upstream does not hijack them (test). Vdir paths are case sensitive (`/Server1/` is not `/server1`) and the hostname must match the rule exactly; the 307 to `/login.html` in the report is the admin UI on `/`, i.e. the request did not match the rule's vdir. Closing as not reproducible; reopen with the vdir log lines (`router:vdir-http`).

### fork #187 / upstream #950 (not-a-bug, close=true)

Measured: a 96 MiB upload through the proxy runs at the same speed as direct (test, with and without the WAF), the body is streamed (no buffering, back-pressure reaches the client). The implausible 25 Gbit/s figure is a browser-side number: the speed-test page measures bytes handed to the local socket, and the dashboard graph counts NIC counters (loopback/Docker count traffic twice). Use iperf3 or `curl --upload-file` as ground truth. Closing as not reproducible.

### fork #192 / upstream #971 (fixed-now, close=true)

A self-signed upstream with 'Skip Verification' was already accepted. The reported 'remote error: tls: handshake failure' is what IPMI/BMC firmware (RSA key exchange only / old TLS) produces against Go's strict defaults. With 'Skip Verification' on, the proxy and the uptime monitor now also offer legacy TLS versions and RSA cipher suites. The test fails before and passes after. Closing as completed; reopen if your IPMI still fails.

Notes: Reporter's actual device not available; reproduced with a server limited to TLS_RSA_WITH_AES_128_CBC_SHA.

### fork #194 / upstream #974 (fixed-now, close=true)

Matrix tested: ws to an HTTP upstream, wss to a self-signed HTTPS upstream with Skip Verification, strict verification, and a TLS upstream configured as plain HTTP. The scheme towards the upstream follows the upstream's 'Require TLS' option. While doing this I found a real bug: enabling 'Skip Verification' on one WebSocket upstream disabled certificate verification for every other WebSocket upstream in the process (shared dialer mutated). Fixed with a test. Closing as completed.

### fork #229 / upstream #1201 (not-a-bug, close=true)

The breakage was a cached 3.3.2 UI. Remaining wishes (smoother chevron rotation, a divider under the default-site entry) are cosmetic and tracked with the navigation rework. Closing.

Notes: Remaining: chevron animation + divider below the default site tab; the nav is being restructured on feat/ui-proxy-ux, so left alone here.

### fork #95 / upstream #403 (cannot-verify, close=false)

Checked everything a monitor touches that does not need your setup: the served certificate includes the intermediate chain from the PEM file, HEAD is proxied like GET, keep-alive probes work and an unknown host gets a proper HTTP status. 'unable to verify the first certificate' is the classic sign of an uploaded certificate without its intermediate (use the full chain PEM); ECONNREFUSED comes from the upstream address/Docker network. Leaving open: please post `openssl s_client -connect host:443 -servername host -showcerts` output and the monitor's URL/type.

Notes: Needs the reporter's cert chain output and Uptime Kuma monitor config.

### fork #104 / upstream #458 (fixed-now, close=false)

Internationalised domain names are now normalised to punycode everywhere a name is compared or sent: proxy rule and alias matching (Unicode and `xn--` spellings are the same rule), certificate selection by SNI, and the identifiers sent to the CA and the DNS-01 challenge. This removes the Unicode/punycode mismatches in Zoraxy itself. Whether Infomaniak's API additionally wants the Unicode zone name could not be tested without an account, so please re-test on the next build and post the exact error if it persists.

Notes: Infomaniak DNS provider behaviour with xn-- zones unverified; needs an Infomaniak account or the full error with the zone name.

### fork #143 / upstream #698 (fixed-now, close=false)

Found and fixed one cause of redirect errors: the auth subrequest always reported `X-Forwarded-Proto: http` and the TCP peer as client when Zoraxy sat behind a TLS terminating proxy/tunnel, so the auth server built http:// redirect URLs. Now the scheme and client IP are taken from the peer's headers when the peer is in the Trusted Proxy list (and only then). Authelia-style 302 redirects are passed through unchanged (test). Leaving open until confirmed on a real Authelia v3.2.3 setup: post the forward-auth settings, the Authelia access-control rule and the redirect URL seen in the browser.

Notes: Not run against a real Authelia.

### fork #189 / upstream #958 (cannot-verify, close=false)

A fake VoidAuth (302 + Location to its login, session cookie, Remote-* headers) works with Zoraxy's forward auth: the browser cookie reaches the auth server, Set-Cookie can be relayed, the redirect is passed through and not followed. An endless redirect loop usually means the session cookie's domain does not cover the app host (use the parent domain). Leaving open: need the VoidAuth proxy-auth settings and the cookie domain.

Notes: Not run against real VoidAuth.

### fork #202 / upstream #1032 (fixed-now, close=false)

oauth2-proxy `/oauth2/auth` semantics (202 allow, 401 deny, X-Auth-Request-* copied, spoofed headers dropped) are tested. Behind a Cloudflare Tunnel, Zoraxy used to tell oauth2-proxy that the request was plain http from the tunnel's address, which produces http:// redirect_uri values and a login loop; it now forwards the tunnel's `X-Forwarded-Proto` and `CF-Connecting-IP` when the tunnel is a trusted proxy (add the cloudflared source IP to Trusted Proxies). Leaving open until verified with Entra ID: need forward-auth settings, oauth2-proxy `cookie_domains`/`redirect_url`, and the redirect chain.

Notes: Not verified against oauth2-proxy + Entra ID.
