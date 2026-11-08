# Development notes (fork)

This file collects fork-specific developer documentation. Zoraxy is licensed under
the AGPL-3.0 (see `LICENSE`); all source headers and notices stay intact.

## Updating / releasing

The admin panel has an **Update** page (System menu, "Others" group, `src/web/components/updater.html`,
backend in `src/mod/updater`). It updates the running binary from signed GitHub releases of
`TheTractorHacker/zoraxy` (override with the `-update_repo owner/name` flag) and can run the
config/database migrations on demand.

Properties worth knowing:

* **No network traffic on its own.** Releases are only queried when an admin opens the Update page or
  presses *Check for updates*. There is **no automatic update**. (A future "auto update" setting, if it is ever
  added, must default to off; it does not exist today.)
* **Channels:** `stable` (default; non-prerelease GitHub releases) and `beta` (also includes pre-releases).
* **Forward only.** A release is offered only if it sorts strictly after the running build.
  Tags look like `v<upstream>[-rc<N>][-<topic>].<build>`, e.g. `v3.3.5-rc5-grpcfix.1`. Because the topic is free
  text, ordering is: upstream `major.minor.patch`, then the GitHub *published-at* time, then the trailing build
  number. The running build's identity is recorded in `conf/updater/installed.json` when the updater installs a
  binary (trusted only while the SHA-256 of the running executable still matches); a binary that was not installed
  by the updater is treated as `SYSTEM_VERSION` with an unknown date, i.e. any dated release of the same or a
  newer upstream version is offered. **Make sure each new release has a later published-at time than the previous
  one.** Rolling back to the saved previous binary is a separate, explicit action.
* Not available in Docker (`-docker` flag or `/.dockerenv`): the buttons are disabled with the reason shown.
  Releases are Linux-only.

### Release assets

Attach exactly these files to a GitHub release (all produced by `tools/build_release.sh`):

| file | content |
| --- | --- |
| `zoraxy_linux_amd64`, `zoraxy_linux_arm64`, `zoraxy_linux_arm` (GOARM=6), `zoraxy_linux_386`, `zoraxy_linux_riscv64`, `zoraxy_linux_mipsle` | static binaries, `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"` |
| `SHA256SUMS` | `sha256sum` format list of the binaries, preceded by the signed header line `# zoraxy-release tag=<tag> build=<n> upstream=<ver>` (ignored by `sha256sum -c`) |
| `SHA256SUMS.sig` | raw 64-byte ed25519 signature over the exact bytes of `SHA256SUMS` |

The updater verifies, in this order: the signature of `SHA256SUMS` with the public key embedded in the binary
(`src/mod/updater/release_pubkey.pem`), then the SHA-256 of the downloaded binary against the signed
`SHA256SUMS`. Anything else is rejected and the running binary is never touched. The binary must also run
`-version` successfully and report the release's upstream version before it is installed.

**Anti-replay (downgrade protection).** The signed header binds the release tag and a monotonically increasing
build number. The updater refuses a `SHA256SUMS` whose header is missing, whose `tag` differs from the GitHub
release it fetched, or whose `build` is not greater than the build recorded in `conf/updater/installed.json` for the
running binary (unknown/unrecorded installs count as build 0). Releases signed before this scheme (no header) can
no longer be installed by the in-app updater. Always pass the exact GitHub tag to the release script and keep the
build number increasing: `tools/build_release.sh -t v3.3.6-topic.1 [-b N]` (default build = current unix time).

### Signing key

* The release **private key lives outside the repository**, by convention at
  `~/.zoraxy-release-key/private.pem` (PKCS#8 PEM, ed25519, mode 0600, directory 0700) on the release machine.
  It is never committed, copied into the repo, logged or passed on a command line other than by *path*.
* Only the **public key** (`src/mod/updater/release_pubkey.pem`, SPKI PEM) is in the repo and embedded in the
  binary with `go:embed`.
* **Back up the private key.** If it is lost, no installed instance can be updated in-app any more (they only trust
  this key) and the only way forward is manual installation of a build with a new public key. Keep at least two
  offline copies (e.g. an encrypted USB stick and a password manager attachment / printed paper copy in a safe),
  never in a cloud drive or in plain email. To check that a backup copy is the right key, run
  `tools/build_release.sh -k <backup-copy> -o /tmp/keycheck`: it signs and then verifies with the committed public
  key, and aborts on a mismatch.
* If the key is ever suspected compromised: generate a new pair, ship a manually installed build with the new
  public key, and revoke by deleting the releases signed with the old key.

### Cutting a release

```bash
# 1. make sure the working tree is at the commit you want to release and tests pass
(cd src && go vet ./... && go test ./...)

# 2. cross-compile (Linux amd64, arm64, arm v6, 386, riscv64, mipsle), sign, and self-verify
tools/build_release.sh -t <tag>               # key: $ZORAXY_RELEASE_KEY or ~/.zoraxy-release-key/private.pem
tools/build_release.sh -t <tag> -k /path/to/private.pem -o /tmp/zoraxy-dist   # explicit key / output dir

# 3. create a GitHub release (tag like v3.3.5-rc5-grpcfix.1, tick "pre-release" for the beta channel)
#    and attach every file in dist/:  gh release create <tag> dist/* --title ... --notes ...
```

`tools/build_release.sh` injects nothing into the binaries beyond `-s -w`, signs with
`tools/sign_release.go`, then verifies its own output with the committed public key (set
`ZORAXY_RELEASE_PUB` only for experiments with throwaway keys). The signing tool can be tested with
throwaway keys: `cd tools && go test sign_release.go sign_release_test.go`; the updater package additionally
tests that its verifier accepts the tool's output (`go test ./mod/updater`).

### What happens during an update

1. Preflight: binary directory and `conf/` writable, running binary path, restart method, free disk space.
2. Optional (default on) backup: `conf/`, `sys.db` and `sys.uuid` are zipped to `<conf>/../backups/zoraxy-pre-update-<ts>.zip`
   (last 10 kept). If the backup fails the update is aborted. The database is copied while Zoraxy is running, so for
   a guaranteed consistent copy of an embedded database stop Zoraxy and copy `sys.db` yourself.
3. Download `SHA256SUMS`, `SHA256SUMS.sig`, then the binary into a temp file next to the executable; verify; `chmod +x`;
   smoke test with `<new> -version`.
4. The old binary is kept as `zoraxy.prev` (older ones as `.prev.1`, `.prev.2`; last 3 are kept) and the new binary is
   atomically renamed over the old one.
5. A *pending update* marker (`conf/updater/pending.json`) is written and an out-of-process rollback watchdog is started.
6. **Restart:** Zoraxy runs its normal shutdown sequence and re-executes the new binary *in place* with `execve` (same PID,
   same arguments and environment). Because the PID does not change this works under systemd regardless of the unit's
   `Restart=` setting. If `execve` fails the process exits with status 75 so that a supervisor with
   `Restart=on-failure` or `always` starts the new binary. For reliable failure handling prefer `Restart=always`
   in the unit.
7. **Health + rollback:** once the admin HTTP listener is bound and the proxy router is initialised, the new process deletes the
   marker ("healthy"). If that does not happen within 90 s, or the new binary has been started more than 3 times without
   becoming healthy (crash loop), `zoraxy.prev` is restored and started. Two independent mechanisms do this: an
   in-process guard (armed at the very start of `main`, also covers crash loops via the start counter in the marker) and
   the watchdog child (the old binary run as `-updater_watchdog <marker>`; it can recover a process that hangs or dies
   before the guard runs). Under systemd the watchdog child lives in the unit's cgroup, so it survives the in-place
   exec but is killed if the unit is stopped/restarted by systemd; the in-process guard and crash-loop counter then
   still protect the next start. If the watchdog has to kill a hung process under systemd, the unit needs
   `Restart=always` to come back up.
8. State files live in `conf/updater/`: `settings.json` (channel, backup-first), `installed.json`, `pending.json`,
   `history.json` (update history), `audit.log` (one line per action).

**Update Database** runs the existing migrations (`update.RunConfigUpdate`, unchanged) after an optional backup and reports
the version file transition and which files under `conf/` were added/modified/removed. It operates on `./conf` (like the
startup migration does), so it is disabled when a different `-conf` path is used.

The API (`/api/updater/*`, admin-auth, mutations are POST + CSRF, one running operation at a time) is
documented in `src/mod/updater/api.go`.

### Tests

```bash
cd src
go vet ./...
go test ./...
go test -race ./mod/updater      # updater: signatures, ordering, preflight, backup, state machine, API, fake GitHub
```


## Admin panel HTTPS (`-webui_tls`)

The management web UI is plain HTTP by default (`-webui_tls=off`, unchanged behaviour).

| Value    | Behaviour |
|----------|-----------|
| `off`    | Plain HTTP (default). |
| `auto`   | HTTPS using a self-signed ECDSA P-256 certificate (10 years) generated into `<conf>/webui/webui.crt` + `webui.key` (key mode 0600). Reused on later starts; regenerated automatically when it has less than 30 days left or no longer covers this machine's hostname / interface IPs. If you place your own `webui.crt` + `webui.key` there (no `.autogenerated` marker file), they are used and never overwritten. |
| `custom` | Require your own `webui.crt` + `webui.key` in `<conf>/webui/`; fail to start if missing. |

Details:

- HTTPS is served on the same `-port`. Plain HTTP requests to that port get a `308` redirect to `https://`.
- Plugins keep using plain HTTP: when TLS is on, Zoraxy opens an extra loopback-only (`127.0.0.1`, random port) HTTP listener and passes that port as `ZoraxyPort` to plugins. That listener serves **only** `/plugin/` (everything else is 404), so the admin UI/API is never reachable over plain HTTP.
- Session and CSRF cookies get the `Secure` flag when TLS is on.
- `-webui_hsts` additionally sends `Strict-Transport-Security` (off by default; avoid with self-signed certificates).
- The HTTPS URL and certificate SHA-256 fingerprint are printed at startup; compare it with what your browser shows when trusting the certificate.

Example: `./zoraxy -port=:8000 -webui_tls=auto`

Implementation: `src/mod/webuitls`.

## Load balancing and health checks

All of it lives in `src/mod/dynamicproxy/loadbalance` and is driven by one optional per-endpoint object,
`ProxyEndpoint.LoadBalanceConfig` (`nil` in every config written before this feature = weighted random, no
checks, no retries, exactly the old behaviour).

- **Selection** (`originPicker.go`, `algorithms.go`, `hashring.go`): `SelectUpstream` filters candidates
  (uptime monitor, draining, `MaxInFlight`, active/passive health; if health would remove everything the
  endpoint fails open) and then applies the algorithm. Sticky sessions are checked first. Weight 0 is fallback only
  for every algorithm. Hash algorithms use a consistent ring with virtual nodes.
- **Per upstream state** (`state.go`): in-flight counter, EWMA of time to first byte, passive ejection with
  cooldown and slow start, active rise/fall state. Memory only, never serialized. All time dependent code takes a
  `now` value so tests use a fake clock (`RouteManager.Now`).
- **Active checks** (`healthcheck.go`): one goroutine per checked upstream, grouped per endpoint and owned by the
  `RouteManager`. The router syncs them in `lbglue.go` (start with the router, stop on `StopProxyService`, follow
  endpoint updates and removal). New code that stores or removes an endpoint must go through `UpdateToRuntime` /
  `Remove` so the goroutines follow.
- **Retries** (`retry.go`): `ServeWithRetry` wraps the client `ResponseWriter` in a gate so a failed attempt can be
  discarded while nothing was sent. Request bodies are only replayed if empty or fully buffered up front (known
  length, under `MaxBodyKB`); non-idempotent methods retry only when listed in `ExtraMethods`.
- **Config fields** (all optional): `LoadBalanceConfig{Algorithm, HashKey, ActiveHealthCheck, PassiveHealthCheck,
  Retry, SlowStartSeconds}` on the endpoint; `MaxInFlight`, `Draining`, `HealthCheck` on each `Upstream`.
- **API**: `/api/proxy/upstream/lb/get|set`, `/setDraining`, `/setMaxInFlight`; `/list` also returns live `States`.
- Algorithms and checks are clean-room implementations of publicly documented designs (nginx smooth WRR, HAProxy
  leastconn, power of two choices, ketama ring); no third-party code was copied.
- Tests: `go test -race ./mod/dynamicproxy/...` (distribution, ring stability, state machines with a fake clock,
  goroutine leak check, retry rules, old-config compatibility).

## Web Application Firewall (WAF)

Package `src/mod/dynamicproxy/waf` embeds [Coraza](https://github.com/corazawaf/coraza) (Apache-2.0, pure Go, no CGO)
with the OWASP Core Rule Set v4 via `github.com/corazawaf/coraza-coreruleset/v4` (CRS is compiled into the
binary, about +5 MB). Licences: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

**Config** is `ProxyEndpoint.WAF` (`*waf.Config`, omitted/`null` = off, so old configs are unchanged):

| Field | Default | Meaning |
|---|---|---|
| `Mode` | `off` | `off`, `detection_only` (log, never block), `block` |
| `ParanoiaLevel` | 1 | CRS paranoia level 1-4 (blocking and detection) |
| `InboundThreshold` | 5 | CRS inbound anomaly score needed to block (5 = one CRITICAL rule) |
| `MaxBodyBytes` | 131072 | Request bodies up to this size are buffered, inspected and replayed |
| `ExcludedRuleIDs` | none | Rule IDs or ranges (`942100`, `949000-949999`) disabled for the endpoint |
| `PathExclusions` | none | `{Path, Exact, RuleIDs}`: rules disabled for matching request paths (prefix unless `Exact`) |
| `CustomRules` | empty | Extra SecLang, appended after the CRS. Use IDs above 1000000 |

**Request path.** `ProxyHandler.ServeHTTP` calls `Router.wafInspect(w, r, sep)` (`waf_inspect.go`) right after
`handleAccessRouting`; it is a single nil check when the endpoint has no WAF. The call sites are marked
`WAF-HOOK` in `Server.go` (one for host endpoints, one for the default-site root endpoint). The call lives in
the shared pre-proxy chain (`runEndpointChain`), so the TLS and non-TLS (`handleNonTLSRequest`) paths both run it.

**Behaviour.**
- Compiled instances are cached by the hash of the normalised config, so endpoints with identical settings share
  one compiled CRS (memory). Compilation happens in `PrepareProxyRoute`; an invalid config or custom rule makes
  it return an error, which rejects the save (the running config is untouched). Coraza never gets to panic the
  proxy: compile panics are recovered and `Inspect` fails open on an internal panic.
- Only the `REQUEST-*` CRS files are loaded. Response inspection is not implemented (always off).
- Rules are loaded from the embedded read-only CRS filesystem only. Custom rules cannot `Include`, use `*FromFile`
  operators or change engine / audit / body directives (checked on save).
- Request bodies: up to `MaxBodyBytes` are read, inspected and replayed byte for byte. Larger bodies (known
  `Content-Length` or discovered while reading) are passed through uninspected; at most `MaxBodyBytes+1` bytes are
  ever buffered, the rest streams. `application/grpc*` requests and any request with an `Upgrade` header
  (WebSocket) are not inspected at all, so `dpcore` streaming and its gRPC handling are untouched.
- CRS defaults were widened for a reverse proxy: methods PUT/PATCH/DELETE and common API/upload content types
  are allowed (rules 911100 / 920420 would otherwise reject normal REST traffic).
- Go's regexp engine is linear time, so CRS regexes cannot cause catastrophic backtracking; body size, argument
  count (1000) and JSON depth (64) are bounded by directives.
- Blocked requests get the normal 403 page (`<webroot>/templates/forbidden.html` override supported) with the
  transaction ID appended and an `X-Request-Id` header. No rule data goes to the client.

**Audit.** Every request that triggers a rule produces one JSON line (`waf.Event`) in
`<log folder>/zr-waf_<year>-<month>.log` (same `logger.Logger`, so the log rotation settings apply; `-enablelog`
must be on), an entry in the in-memory ring buffer (1000 events) and increments the per-rule and per-endpoint
counters. `action` is `blocked` or `detected`; `would_block` says the anomaly threshold was reached.

**API** (admin auth, `src/wafapi.go`): `POST /api/waf/set` (`rootname`, `config` JSON), `POST /api/waf/validate`,
`GET /api/waf/events?limit=&endpoint=`, `GET /api/waf/stats`, `POST /api/waf/exclude` (`rootname`, `ruleid`,
`path` empty = whole endpoint). UI: the **WAF** tab of the endpoint editor (`src/web/components/httprp.html`).

**Tuning.** Start with `detection_only`, browse the events in the WAF tab, use *exclude for this path* for false
positives, then switch to `block`. Typical offenders are rich-text editors and admin consoles (941xxx XSS, 942xxx
SQLi on free text fields), JSON APIs with odd content types (920420) and WebDAV-style methods (911100).

**Benchmarks** (`go test ./mod/dynamicproxy -run xxx -bench 'Proxy(GET|POSTJSON|Attack)_WAF' -benchmem`) drive a request
through `ProxyHandler.ServeHTTP` to a local upstream. See the PR description for numbers.

### Central WAF (policy, profiles, inheritance)

The WAF is managed centrally from **Security > WAF** (`src/web/components/waf.html`); per proxy rule settings
still exist but are now one of several *sources*. Code: `waf/central.go` (State, Resolve, bypass), `waf/profiles.go`
(built-ins), `waf/rulesref.go` (CRS rule reference), `dynamicproxy/waf_inspect.go` (apply / coverage / hook),
`src/wafcentral.go` (persistence + mutations), `src/wafcentralapi.go` + `src/wafapi.go` (HTTP APIs).

**Storage.** `<conf>/waf_central.json` = `{Policy, Profiles}` (user profiles only). It is a file, not a sysdb table,
so it is part of the conf backup zip and, because `waf_central.json` is in the cluster snapshot allow-list
(`mod/cluster/snapshot.go`, validated in `validateClusterPayload`), it replicates to followers. A missing file means
policy off, no custom profiles (the pre-upgrade behaviour). Endpoint fields (`ProxyEndpoint`, all `omitempty`):
`WAFSource`, `WAFProfile`, `WAFExtra`; the existing `WAF` field is the *custom* config.

**Policy** (`waf.Policy`): `Enabled` (master switch for inheriting rules, default off), `DefaultMode`
(`off|detection_only|block`), `ParanoiaLevel`, `InboundThreshold`, `MaxBodyBytes`, `AllowEndpointOverride`,
`ExcludedRuleIDs`, `PathExclusions`, `CustomRules` (global SecLang), `TrustedPaths` (`{Host, Path, Exact}`) and
`AllowedIPs` (IP/CIDR) which skip the WAF.

**Sources** (`ProxyEndpoint.WAFSource`): empty means `custom` if `WAF` is set (every pre-existing config, behaves
exactly as before) else `inherit`; `inherit` (policy `DefaultMode` if `Enabled`, else off), `off`, `detection_only`,
`block` (fixed mode, policy tuning), `profile` (`WAFProfile`), `custom` (own full config, standalone).

**Merge** (`State.Resolve`): global values, then profile (mode, non-zero paranoia / threshold), then `WAFExtra`
(paranoia / threshold only if `AllowEndpointOverride`, otherwise ignored with a warning and rejected on save).
Exclusions are additive and de-duplicated; custom rules are concatenated global, profile, endpoint, so later ones run
after earlier ones. A profile that disappeared (e.g. synced config) degrades to the global default with a warning in
the coverage table instead of failing to load. `custom` endpoints do not use global exclusions or rules.

**Bypass** (`State.BypassReason`): allowed IP, `/.well-known/acme-challenge/<token>` (GET/HEAD, built in), trusted
paths. Applies to every non-custom effective WAF, and to `custom` endpoints only while the policy is enabled (so an
upgrade changes nothing). Path matching fails closed: only paths that are already canonical qualify (no `//`, `/./`,
`..`, `%`, backslash, control characters, encoded `/` or `.` in the raw path); case sensitive. Anything ambiguous is
simply inspected.

**Applying changes.** `Router.ApplyWAFState(state)` compiles the policy, every user profile and every endpoint's
resolved config first (bad SecLang rejects the whole change and nothing moves), then swaps the state and the per
endpoint `wafRuntime` atomically (`atomic.Pointer`), so there is no restart and no half applied request. Compiled
instances are shared through the config-hash cache (now 48 entries), so unchanged effective configs reuse their
instance. Endpoints prepared concurrently are re-synced after the swap. `wafCentralMu` serialises every read-modify-write
of policy, profiles and endpoint WAF settings.

**APIs** (admin auth + CSRF): `GET/POST /api/waf/policy`, `GET /api/waf/profiles`, `POST /api/waf/profile/{save,clone,delete}`
(built-ins are read-only, deleting a profile in use is refused), `GET /api/waf/coverage`, `POST /api/waf/endpoint/set`
(`rootname` or `/` for the default site, `source`, `profile`, `extra`), `GET /api/waf/events?limit&endpoint&rule&action&ip&since`,
`GET /api/waf/summary?hours` (top rules / IPs / endpoints), `GET /api/waf/stats` (now with `per_hour`, 7 days max),
`GET /api/waf/rules`, `POST /api/waf/exclude` (`ruleid`, `scope=global|endpoint|path`, `rootname`, `path`, `exact`; without
`scope` the old rootname/path semantics apply; the exclusion lands in `WAFExtra` or, for custom rules, in `WAF`).
`POST /api/waf/set` still exists and means *custom*. Metrics: `zoraxy_waf_policy_enabled`, `zoraxy_waf_endpoints{mode}`
(three label values) next to the existing event counters.

**Built-in profiles:** `WordPress`, `API-only`, `Strict`, `Learning` (detection only, PL2). Clone them to edit.

**Tests:** `waf/central_test.go`, `dynamicproxy/waf_central_test.go` (inheritance matrix through `ProxyHandler.ServeHTTP`
and the non-TLS path, bypass tricks, profile propagation, concurrency), `src/wafcentral_test.go` (APIs, persistence, cluster).

## Customising CAPTCHA pages

Each proxy endpoint with "Require CAPTCHA Challenge" enabled can restyle its bot-check pages from the endpoint editor
(Security tab, **Customise page**). Everything is optional: with nothing set the pages look and read exactly as before,
and configs saved by older versions load unchanged. Implementation: `src/mod/dynamicproxy/captcha`
(`branding.go`, `pages.go`, `verify.go`, templates `page_base.html`, `challenge.html`, `failed.html`, `blocked.html`).

### Pages

| Page | When | Status |
|------|------|--------|
| challenge | visitor has no valid CAPTCHA session | 403 (unchanged) |
| verification failed | the verify endpoint rejects a token and the client asked for HTML (no-script flow). Shows a retry button. The built-in script shows the failure inline with a retry button instead of looping. | 401 |
| blocked | the exploit / crawler detector's action is "CAPTCHA challenge" but the endpoint has no CAPTCHA configured | 403 |

The exploit / crawler action **CAPTCHA challenge** now works: a flagged request gets the endpoint's challenge; a
visitor who already holds a valid CAPTCHA session is let through; an endpoint without CAPTCHA falls back to the blocked page.
The verify path (`/.zoraxy/captcha/verify`) is always reachable for a challenged client.

### Config fields (`CaptchaConfig`, all optional)

| Field | Default | Meaning |
|-------|---------|---------|
| `Branding.Title` / `Heading` / `Message` / `Notice` | `Just a moment...` / host name / `Verify you are human by completing the action below.` / `{domain} needs to review the security of your connection before proceeding.` | page texts; `{domain}` is replaced with the requested host |
| `Branding.VerifyingText` `SuccessText` `FailedText` `ErrorText` `RetryText` | stock wording, `Try again` | status strings |
| `Branding.BlockedTitle` `BlockedHeading` `BlockedMessage` | `Access blocked` ... | blocked page |
| `Branding.LogoURL` | none | `https://` URL or `data:image/(png\|jpeg\|gif\|webp);base64,...`, max 256 KiB decoded, content sniffed, SVG refused |
| `Branding.AccentColor` / `BackgroundColor` | `#2c7cb0` / theme | hex colours only |
| `Branding.Theme` | `auto` | `auto` (browser), `light`, `dark` |
| `Branding.HideFooter` | `false` | hide "Performance & security by Zoraxy" |
| `Branding.CustomTemplate` | none | full custom challenge page, max 64 KiB, see below |
| `Turnstile.Mode` | `managed` | `managed`, `non-interactive`, `invisible`. Must match the widget type of the site key (it is chosen in the Cloudflare dashboard); the page uses it to decide whether to show a spinner. |
| `Turnstile.Appearance` | `always` | `always`, `execute`, `interaction-only` |
| `Turnstile.Theme` / `Size` | `auto` / `normal` | widget theme `auto\|light\|dark`, size `normal\|flexible\|compact` |
| `Turnstile.Action` / `CData` | none | bound to the token; when set, siteverify must return the same value or the token is rejected |
| `RecaptchaInvisible` | `false` | reCAPTCHA v2 invisible badge (needs an invisible-type key) |
| `RecaptchaAction` | `access` | reCAPTCHA v3 action name, checked in siteverify |
| `VerifyHostname` | `false` | reject tokens whose siteverify `hostname` differs from the requested host |

All of these are validated when the endpoint is saved (clear error in the UI) and validated again when rendering, so a
hand-edited config cannot inject markup. Text is escaped by `html/template`; a `<script>` in the title is shown as text.

Turnstile widgets use explicit rendering with `refresh-expired=auto`, expiry/timeout callbacks and an error counter, so an
expired token is refreshed instead of leaving a dead page; after three widget errors a retry button appears.

### Content-Security-Policy and nonces

Every challenge/failed/blocked response carries a CSP with a fresh per-response nonce, `Cache-Control: no-store`,
`X-Frame-Options: DENY` and `frame-ancestors 'none'`:

- Turnstile: `script-src 'nonce-..' https://challenges.cloudflare.com`, `frame-src` and `connect-src` for the same host, `style-src 'nonce-..'`.
- reCAPTCHA: `script-src 'nonce-..' https://www.google.com https://www.gstatic.com`, `frame-src https://www.google.com https://recaptcha.google.com`, and `style-src 'unsafe-inline'` because the reCAPTCHA widget injects inline styles that cannot carry a nonce.
- everything else `default-src 'none'`; `connect-src 'self'` for the verify call; images from `data:` and `https:` (logo).

Inline `<script>` and `<style>` in a custom template **must** carry `nonce="{{.Nonce}}"`, otherwise the browser blocks them.
Legacy overrides in `<webroot>/templates/captcha_cloudflare.html`, `captcha_recaptcha_v2.html`, `captcha_recaptcha_v3.html`
(still honoured, lower priority than a per-endpoint custom template) predate nonces and get `'unsafe-inline'`.

### Custom template reference

A custom template is a Go `html/template`. It is parsed and rendered once per provider with sample data when saved; a
template that does not parse, references an unknown field/function/template, or fails to execute is rejected with the error
text. If a stored template ever fails at request time the stock page is served instead of an error.

Variables (`{{.Name}}`):

| Variable | Value |
|----------|-------|
| `Domain`, `SiteKey`, `VerifyPath` | host being protected, public site key, `/.zoraxy/captcha/verify` |
| `Nonce` | CSP nonce for inline script/style |
| `Provider` | `turnstile`, `recaptcha_v2`, `recaptcha_v3` |
| `Page` | `challenge` |
| `Preview` | true in the admin preview |
| `Title`, `Heading`, `Message`, `Notice` | resolved texts (defaults applied, `{domain}` expanded) |
| `Strings.Verifying` `.Success` `.Failed` `.Error` `.Retry` | status strings |
| `LogoURL` | validated logo or empty |
| `Accent`, `Background`, `Theme` | `#rrggbb`, empty = default, `auto\|light\|dark` |
| `ShowFooter`, `ShowLoader` | booleans |
| `Client` | the JSON blob the runtime script reads (provider, key, verify path, texts, Turnstile options) |

Named templates you can include: `zx_css` (the built-in stylesheet, uses the accent/theme/background), `zx_head`,
`zx_widget` (widget container, spinner, `#status`, retry button), `zx_footer`, and `zx_runtime` (the script that loads the
provider, submits the token to `VerifyPath`, handles expiry/retry and reloads on success). The shortest working page:

```html
<!DOCTYPE html>
<html><head><title>{{.Title}}</title></head>
<body><h1>{{.Heading}}</h1>{{template "zx_widget" .}}{{template "zx_runtime" .}}</body></html>
```

If you write your own script instead of `zx_runtime`, POST the token as form field `cf-turnstile-response` (Turnstile) or
`g-recaptcha-response` (reCAPTCHA) to `VerifyPath` with header `Accept: application/json`; the answer is `{"success":true}`
(and a session cookie) or `{"success":false,"error":..}` with status 401.

Examples: `example/captcha-templates/` (minimal card, split screen, fully hand written). The editor's
"Insert starter template" button inserts the minimal card.

### Preview

The **Preview** buttons in the editor POST the current, unsaved form to `POST /api/proxy/captcha/preview` (admin auth +
CSRF like every other admin API) and show the answer in a modal iframe. Challenge, verification failed and blocked pages
can each be previewed. The server renders with the providers' public test site key (Turnstile `1x00000000000000000000AA`,
reCAPTCHA v2 `6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI`), calls no external service, verifies nothing and never echoes the real
keys. Only the visitor's browser loads the provider script. reCAPTCHA v3 has no public test key, so its preview is simulated.

### Tests

```bash
cd src
go test ./mod/dynamicproxy/captcha/ .        # rendering, escaping, CSP/nonce, template validation, siteverify, preview
go test -race ./mod/dynamicproxy/...
```

Siteverify URLs are variables (`captcha.TurnstileVerifyURL`, `captcha.RecaptchaVerifyURL`) so tests point them at an `httptest` server.

## Authentik / OIDC SSO

Step-by-step setup (forward auth and OIDC) is in [docs/authentik.md](docs/authentik.md). Code: forward auth in
`src/mod/auth/sso/forward` (`outpost.go` for the Authentik outpost proxy), OIDC in `src/mod/auth/sso/oauth2`
(`oidc.go` discovery/JWKS/ID token, `session.go`, `claims.go`). Tests use fake outpost / OIDC servers
(`authentik_test.go`, `fakeidp_test.go`, `oidc_test.go`); run them with
`go test -race ./mod/auth/...`.

## High availability

Everything lives in `src/mod/cluster` plus glue in `src/cluster.go`. All of it is inert by default: with no cluster
secret and role `standalone` nothing is exposed, no files are created and every key is derived exactly as before.

### What a cluster shares

| Thing | Shared across nodes? | How |
|---|---|---|
| CAPTCHA session cookie | yes | signing key derived from the cluster secret (HKDF, purpose `captcha-session`) |
| Load balancer sticky cookie | yes | cookie store key derived from the cluster secret (purpose `lb-sticky-session`) |
| Proxy rules, redirects, access rules, stream proxies, path rules, trusted proxies, ACME settings | primary to followers | signed + encrypted snapshot, pull model |
| Certificates (`conf/certs`) | only if "sync certificates" is on | same snapshot |
| Admin CSRF key, admin login session, admin account, `sys.uuid`, admin HTTPS cert, updater state, logs | never | node local |
| ZorxAuth (SSO portal) sessions | no | stored per node in the database (random IDs, not a signed cookie). Put the SSO portal behind sticky routing, or users sign in again after a failover. OAuth2/OIDC cookies hold the provider token and work on every node |

Without a cluster secret the key input stays the node UUID (`cluster.KeyMaterial` returns it unchanged), so a
standalone node is byte-identical to before. Existing sessions are invalidated once when a secret is first set.

### Setting it up

1. Generate a secret on one node (Cluster / HA page, or `zoraxy -cluster_gen_secret`) and give the same value to every
   node (page, `-cluster_secret`, or `conf/cluster.json`). Restart every node once so session keys switch.
2. Pick the primary: role **Primary**. On each other node: role **Follower**, primary admin URL
   (`https://primary:8000`), and optionally the primary's admin certificate SHA-256 fingerprint (pinning, for the
   self-signed `-webui_tls=auto` certificate; the fingerprint is printed in the primary's startup log).
3. Edit configuration on the primary only. Followers pull every 60 s (+0..20% jitter, configurable 10 to 3600 s).
   "Sync now" on the follower page triggers it immediately.

`conf/cluster.json` (mode 0600, node local, never synced):
`{"role":"standalone|primary|follower","secret":"...","primaryUrl":"","primaryFingerprint":"","syncIntervalSeconds":60,"syncCerts":false,"healthDisabled":false,"healthAllow":[]}`

Flags: `-cluster_secret`, `-cluster_gen_secret`, `-cluster_allow_local_edits`, `-health_port`.

### Health endpoint

`GET /.zoraxy/health` on the proxy listeners (HTTP, HTTPS, HTTP/3, secondary ports), answered before host routing,
so any `Host` header works. Only that exact path is intercepted (`/.zoraxy/captcha/verify` and ACME paths are
untouched). Returns `200 {"status":"ok","version","uptimeSeconds","proxyRunning":true,"activeEndpoints":N}` or `503`
with `proxyRunning:false` when the router is stopped. No secrets. Optional allow-list of IPs/CIDRs on the Cluster page
(matched against the TCP peer, never `X-Forwarded-For`; default allow all). `-health_port=:8081` serves the same path
on a separate tiny listener, reachable even when the proxy is stopped (then it answers 503).

### Config sync design

- **Transport.** `GET /api/cluster/snapshot?have=<version>` and `POST /api/cluster/heartbeat` on the admin port,
  mounted outside the admin session and CSRF layers. They answer `404` unless the node role is `primary`.
  Authentication is a bearer token `zxc1:<unix>:<node>:<nonce>:<hmac>` where the HMAC (key derived from the secret) covers
  method, path, timestamp, node id and a random nonce: bound to one request, valid for +-60 s, single use (replay
  cache), compared in constant time. 30 requests/minute per client IP, valid or not.
- **Snapshot.** JSON envelope `{version, createdAt, node, nonce, data, sig}`; `data` is AES-256-GCM(gzip(payload)) and
  `sig` is HMAC-SHA256 over the header and ciphertext (separate HKDF keys). The files are an allow-list:
  `conf/proxy/*.config`, `redirect`, `access`, `streamproxy`, `rules`, `trusted_proxies.json`, `acme_conf.json` and
  optionally `certs`. Anything else (`sys.uuid`, admin accounts, `conf/webui`, updater state, `cluster.json`, logs,
  database) cannot be included. Followers re-validate every path.
- **Versioning.** The version only moves when the content hash changes: `max(previous+1, now in ms)`, persisted in
  `conf/.cluster/primary.json`. Followers refuse a lower version than the one applied ("Force sync" overrides, for a
  rebuilt primary).
- **Apply.** The follower verifies, validates (JSON plus the real schemas: `validateClusterPayload`), stages into
  `conf/.cluster/staging-*`, swaps each root with renames keeping the old one in `conf/.cluster/backup-*` (last 3 kept),
  then restarts itself (`syscall.Exec`, same binary and arguments) because Zoraxy has no in-place reload of every
  module. It only restarts when content actually changed. A failed apply or reload is rolled back. If the restarted
  process dies before it has been up for 20 s and is started again (systemd / container restart policy), the boot guard
  restores the backup and remembers the snapshot as rejected until the primary changes it. Run followers under a
  supervisor.
- **Conflict policy: primary wins.** On a follower, writes to synced objects through the admin API are refused with 403
  unless `-cluster_allow_local_edits` (then they are overwritten by the next primary change). Node local settings
  (listen port, TLS toggles, timeouts, start/stop) stay editable.
- **Not synced (known gaps).** Settings stored in the database (inbound port, TLS mode, SSO provider settings,
  ZorxAuth users, redirect regex/case flags, geo-IP, plugins), the Docker/uptime/statistics state and static web server
  content. Set those on every node or use `/api/conf/export` with the database option.
- **Security.** The cluster secret is as sensitive as the admin password: whoever holds it can read the whole synced
  configuration (including captcha keys, basic-auth hashes and, with cert sync, private keys) and can forge visitor
  sessions. Prefer HTTPS for the admin port (`-webui_tls`) and pin the fingerprint, even though the snapshot is already
  encrypted and signed. Keep node clocks within a few seconds (NTP): the token window is 60 s.

### ACME in a cluster

Two safe approaches:
1. **Single issuer.** Make the primary the only node that runs ACME, turn on "sync certificates". Followers receive the
   certificates (renewals included) and their copy of `acme_conf.json` has automatic renewal switched off, so only the
   primary talks to the CA. HTTP-01 works if the CA can reach the primary; otherwise use DNS-01 on the primary.
2. **DNS-01 on every node.** No certificate sync; each node obtains its own certificate with a DNS challenge, so it does
   not matter which node the VIP points at. Mind the CA rate limits (N nodes means N certificates per name).

HTTP-01 on a VIP-fronted pair only works on the node that currently owns the VIP, which is why 1 or 2 is needed.

### Active/passive with keepalived (VRRP)

Two nodes, `192.0.2.11` (node-a) and `192.0.2.12` (node-b), VIP `192.0.2.10`, interface `eth0`.

```
# /etc/keepalived/keepalived.conf on node-a (node-b: state BACKUP, priority 100, swap unicast addresses)
global_defs {
    enable_script_security
    script_user keepalived_script
}

vrrp_script chk_zoraxy {
    script "/usr/bin/curl -fsS --max-time 2 http://127.0.0.1/.zoraxy/health -H 'Host: health.local' -o /dev/null"
    interval 2
    timeout 3
    fall 2
    rise 2
}

vrrp_instance VI_ZORAXY {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 150
    advert_int 1
    unicast_src_ip 192.0.2.11
    unicast_peer {
        192.0.2.12
    }
    authentication {
        auth_type PASS
        auth_pass change-me-8ch
    }
    virtual_ipaddress {
        192.0.2.10/24
    }
    track_script {
        chk_zoraxy
    }
}
```

Use `https://127.0.0.1/.zoraxy/health` with `-k` if the node only listens with TLS (the health path answers before
certificate/host selection; with `-k` the default certificate is fine). If port 80 is disabled use `-health_port`.
Zoraxy listens on all addresses, so it needs no special binding for the VIP. Create the `keepalived_script` user
(`useradd -r -s /sbin/nologin keepalived_script`) or drop the `script_user` lines.

With a shared cluster secret a visitor's CAPTCHA session and sticky cookie survive the failover. Without config sync
the standby must hold an identical configuration (sync, or keep it by hand).

### Active/active behind nginx or HAProxy

```
# HAProxy
frontend fe_https
    bind :443
    mode tcp
    default_backend be_zoraxy
backend be_zoraxy
    mode tcp
    balance roundrobin
    option httpchk GET /.zoraxy/health
    http-check expect status 200
    server zx1 192.0.2.11:443 check port 443 check-ssl verify none inter 2s fall 2 rise 2 send-proxy-v2
    server zx2 192.0.2.12:443 check port 443 check-ssl verify none inter 2s fall 2 rise 2 send-proxy-v2
```

```
# nginx (stream module, TCP pass-through; TLS terminates on the Zoraxy nodes)
stream {
    upstream zoraxy { server 192.0.2.11:443 max_fails=2 fail_timeout=5s; server 192.0.2.12:443 max_fails=2 fail_timeout=5s; }
    server { listen 443; proxy_pass zoraxy; proxy_protocol on; }
}
```

`send-proxy-v2` / `proxy_protocol on` need Zoraxy's "PROXY protocol" setting enabled so the real client IP survives; drop
both if you do not need it. Active health checks in nginx open source are passive only (`max_fails`); use HAProxy or
nginx Plus for `/.zoraxy/health` probing. Because CAPTCHA and sticky cookies are keyed from the cluster secret, any node
accepts them, so no stickiness is required at this layer.

### Failover test checklist

1. `curl -i http://<node>/.zoraxy/health` returns 200 on both nodes and the JSON has `proxyRunning:true`.
2. Same cluster secret fingerprint on both Cluster pages; both show no pending restart.
3. Change a proxy rule on the primary; within one interval the follower shows the new snapshot version, restarts
   once, and the primary's node list shows it as current.
4. Solve a CAPTCHA (or get a sticky cookie) through node A, then send the same cookie to node B directly: accepted
   without a new challenge.
5. Stop Zoraxy on the VIP owner (`systemctl stop zoraxy`): the VIP moves within `fall * interval` seconds and traffic
   resumes; `curl` the VIP in a loop to measure the gap.
6. Start it again: the VIP returns only if the node has higher priority (use `nopreempt` to avoid flapping).
7. Break the follower's network to the primary: sync status shows an error, the follower keeps serving its last
   applied configuration.
8. Stop the proxy service from the UI on the VIP owner: health returns 503 and keepalived fails over.
9. Edit a synced object on the follower: refused with 403 (primary wins).
10. Wrong secret on a follower: sync error "primary rejected the request", no files changed.

## Plugin request / response hooks (filter API)

Plugins can act as middleware / WAF style filters. User-facing documentation is in
`docs/plugins/docs/2. Architecture/7. Request and Response Hooks.md`; this section is the developer map.

- **SDK / wire format**: `src/mod/plugins/zoraxy_plugin/hooks.go` (`HookSettings`, `FilterRequest`, `FilterVerdict`, helpers,
  `HookAPIVersion`). The SDK is copied into every example by `example/plugins/build_all.sh`; run it and commit the copies.
  A new example directory needs an empty `mod/` directory created first, otherwise `cp -r` creates `mod` as the SDK itself.
- **Runtime**: `src/mod/plugins/hooks_pipeline.go` (stage execution, concurrency, merge, body preview, response writer wrapper),
  `hooks_validate.go` (verdict sanitising, manifest sanitising), `hooks_runtime.go` (HTTP client, circuit breaker, admin settings,
  invoke token), `traffic_router.go` (`HandleStage`, legacy capture).
- **Integration**: `src/mod/dynamicproxy/plugin_hooks.go` is the only glue. `runEndpointChain` calls
  `routePluginStage(pre_auth)` right after the access check, `routePlugin` (post_auth) is unchanged in position, and
  `pluginWrapResponse` wraps the `ResponseWriter` before the chain in `ServeHTTP` and `handleNonTLSRequest`.
- **Admin state** (global attach, fail-closed consent) lives in the `plugin_hooks` database table, API `POST /api/plugins/hooks/set`
  on the admin router only (never register it on the plugin REST router). fail_closed needs manifest AND consent.
- **Tests**: `go test -race ./mod/plugins/... ./mod/dynamicproxy/...`. `mod/plugins/hooks_test.go` uses `httptest` servers as fake
  plugin processes; `mod/dynamicproxy/plugin_hooks_test.go` drives `ProxyHandler.ServeHTTP` end to end.

## Prometheus metrics

Package `src/mod/metrics` (hand-rolled text exposition 0.0.4, no new dependency); glue in `src/metrics.go`;
request hooks in `src/mod/dynamicproxy/metrics_hook.go`.

* **Off by default.** `-metrics` records metrics and serves them on the admin API `GET /api/metrics` (admin auth, same as every
  `/api/*` route). `-metrics_port :9090` (implies `-metrics`) additionally serves `GET /metrics` on a separate listener; protect it
  with a bearer token: `-metrics_token`, env `ZORAXY_METRICS_TOKEN` or `{"token":"..."}` in `<conf>/metrics.json` (the flag is visible
  in the process list, prefer env/file). A non-loopback listener without a token logs a warning. Disabled = one nil check + atomic load
  per request; `/api/metrics` answers 503.
* **Hooks** (all behind `Option.Metrics.Enabled()`): `ProxyHandler.ServeHTTP` and `handleNonTLSRequest` wrap the response writer
  (Flusher, Hijacker and `Unwrap` are preserved) for status/bytes/duration/in-flight; `handleRateLimit`, `handleAccessRouting` and the
  CAPTCHA gating count events. Upstream state, WAF counters, certificate expiry, cluster role and build info are pulled at scrape time.
* **Cardinality:** `endpoint` is the configured rule name (`_default` for the default site), capped at 512 distinct values
  (overflow folds into `__other__`), event vectors capped at 1024 series, WAF rules limited to the top 200. Paths, hosts from headers
  and client IPs are never labels.
* **Series:** `zoraxy_http_requests_total{endpoint,status_class,method}`, `zoraxy_http_request_duration_seconds` (histogram),
  `zoraxy_http_requests_in_flight`, `zoraxy_http_request_bytes_total`, `zoraxy_http_response_bytes_total`,
  `zoraxy_upstream_{up,in_flight,ewma_seconds,ejections_total}{endpoint,upstream}`, `zoraxy_waf_{events_total,rule_hits_total,blocked_total}`,
  `zoraxy_captcha_{challenges,verified,failed}_total`, `zoraxy_ratelimit_rejected_total`, `zoraxy_access_blocked_total`,
  `zoraxy_tls_certificate_expiry_days{certificate,cn}`, `zoraxy_build_info`, `zoraxy_uptime_seconds`, `zoraxy_cluster_role`,
  `zoraxy_cluster_snapshot_version`.
* **Tests:** `go test -race ./mod/metrics ./mod/dynamicproxy -run Metrics`.

## Bulk IP blocklist import

Package `src/mod/access/blocklistimport` (parser, fetcher, source manager + scheduler), additive helpers in
`src/mod/access/bulk.go` (`BulkEditIPList`: one copy, one swap, one config write instead of one per entry), admin API in
`src/blocklistimport.go`, UI in `src/web/components/access.html` ("Bulk import" accordion on the IP blacklist and whitelist tabs).

* **Formats:** one entry per line, IPv4 / IPv6 / CIDR. `#` or `;` at line start = comment; text after the address (whitespace, `,`, `;`,
  `#` separated) is the comment, so the first column of a CSV works. Entries are canonicalised (`10.1.2.3/8` -> `10.0.0.0/8`, `/32` ->
  host, IPv4-mapped IPv6 -> IPv4). `/0`, `0.0.0.0`, `::`, scope ids and wildcards are rejected (use CIDR). Duplicates (inside the input
  and against the list) and invalid lines are reported with line numbers; counts are exact, the lists are capped at 500 each.
  Limits: 1M entries, 4 KiB per line, 32 MiB per upload/download. Comments are stripped of markup (parts of the UI render them raw).
* **Dry run:** `POST /api/access/import/preview` returns the same report as `/apply` without changing anything.
* **URL sources:** https only, no credentials in the URL, no proxy. Every connection (also each redirect hop, max 3, https only) is
  resolved by our own dialer which refuses the target if ANY answer is non-public (loopback, RFC1918, link-local incl. 169.254.169.254,
  CGNAT, ULA, multicast, NAT64/6to4, IPv4-mapped...) and then dials the validated IP directly (no DNS rebinding window). 30 s total
  timeout, 32 MiB cap, comments in remote files are ignored.
* **Scheduled refresh:** sources live in `<conf>/blocklist_sources.json` (id, rule, list, url, interval 15 min - 7 days, state). Entries a
  source adds carry the comment prefix `[src:<id>] `; a refresh removes only entries carrying exactly that prefix and no longer in the
  download, adds new ones, and leaves everything else (manual entries, other sources, entries that were added manually first) alone.
  A download with zero valid entries never wipes a source (`ErrWouldEmpty`); errors keep the old entries and are shown in the UI.
  Caveat: the tag is a comment convention, an admin typing `[src:<id>]` by hand could make an entry refreshable.
* **Performance:** 200k entries parse and import in about a second (3 s under -race) (test: `TestLargeImport200k`). Request-time matching is the job of the
  `mod/access` lookup (`IsIPBlacklisted`); the admin UI renders at most 1000 rows of a list (rest still enforced).
* **Tests:** `go test -race ./mod/access/... ` (SSRF tests use an httptest TLS server plus a stub resolver / dialer).

## Forward Auth / OAuth2 exception rules

Per proxy rule, `AuthenticationProvider.ExternalAuthExceptionRules []*AuthExceptionRule` (type in `mod/dynamicproxy/typedef.go`, matching and
validation in `mod/dynamicproxy/authexceptions.go`, API in `src/authexceptions.go`, UI `web/snippet/ssoExceptionEditor.html` opened from the
"Forward Auth / OAuth2 Exceptions" button of the proxy rule editor). One list serves both providers; ZorxAuth and Basic Auth keep their own
rule lists and matchers (unchanged). `handleAuthProviderRouting` consults the list before calling the provider.

* Rule = path (`prefix` on segment boundaries, `exact`, or `regex` that must match the whole normalised path; optional ignore-case) or an
  IP / CIDR. Any matching rule skips the SSO check. `/` as prefix and `/0` CIDRs are refused.
* **Client IP** is `Router.GetClientIPForEndpoint` (trusted-proxy aware). Unlike the older Basic/ZorxAuth rules there is no per-rule
  "trust proxy headers" flag: headers are only honoured when the access rule has `TrustProxyHeadersOnly` and the peer is in the trusted
  proxy list. (Existing Basic/ZorxAuth rules with `UseTrustedProxy=true` still read the raw headers, see the warning in their UI.)
* **Fail-closed paths:** a path rule only applies to a request target that is already canonical. Dot segments, `//`, anything that decodes
  into them (`%2e%2e`, `%2f`), `;` path parameters (`/public/..;/admin`), `\`, control characters and a `%` left after one decoding round
  (double encoding) never match, the normal SSO check runs instead.
* Requests that skip SSO get the provider's identity headers scrubbed (`ScrubIdentityHeaders` on the forward auth and OAuth2 routers:
  configured response headers, `X-authentik-*` in Authentik mode, mapped OAuth2 claim headers).
* Tests: `go test -race ./mod/dynamicproxy -run 'AuthException|CanonicalException|ForwardAuthException|OAuth2Exceptions'`.
## Triage fixes, batch 2 (upstream #1343 #1117 #1109 #986 #1359 #1067 #410 #1334 #1029)

Developer map and operator notes for the fixes in `fix/triage-bugs-2`.

- **Proxy rule edit is a partial update (#1109)**: `ReverseProxyHandleEditEndpoint` (`src/reverseproxy.go`) loads the current rule first and
  every field uses `postBoolOr(r, key, current)` / `formHas(r, key)`: absent parameter = keep the current value, present = change it
  (an empty `utmURI` / `tags` clears the field). WAF and load-balance config are not part of this form and are never touched. When you add
  a form field, add a row to `editCases` in `src/reverseproxy_edit_test.go`.
- **Disable connection reuse per upstream (#1343)**: `Upstream.DisableKeepAlive` sets `DisableKeepAlives` on that upstream's transport
  (`dpcore.DpcoreOptions.DisableKeepAlive`), so there is no per-request transport clone. API: `nokeepalive=true` on `/api/proxy/upstream/add`,
  or the field in the `payload` of `/api/proxy/upstream/update`. "Force HTTP/1.1" only disables HTTP/2 and does not stop connection reuse.
- **ACME issuance is serialised (#1117)**: `ACMEHandler.ObtainCert` holds a mutex for the whole issuance (manual request, auto renew and
  SAN names queue up) and re-checks the HTTP-01 port right before use, picking a new free one if it was taken since start-up.
- **IP blacklist index (#986)**: `src/mod/access/blacklist_index.go` compiles `BlackListIP` once (exact map, IPv4 wildcard trie, CIDR prefix
  maps per prefix length) and is rebuilt when the map pointer or its size changes (Add/Remove swap the map). 100k entries: about 53 ms
  per lookup before, 2.3 us after (`go test ./mod/access -bench Blacklist`). `blacklist_index_test.go` keeps the old linear scan as a
  reference and compares both on random data. The whitelist still scans linearly.
- **Sanitise client IP headers (#1359)**: opt-in, default off, per proxy rule (`sanitiseClientIP` on `/api/proxy/edit`) and global
  (`/api/proxy/sanitiseClientIP`, stored in `settings/sanitiseClientIP`). Peers that are not in the Trusted Proxy list lose
  `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `CF-Connecting-IP`, `True-Client-IP`, `Fastly-Client-IP`, `X-Client-IP`; the proxy then
  builds `X-Forwarded-For` / `X-Real-IP` from the real peer. Behind a CDN, list the CDN ranges as trusted proxies first or leave the switch off.
- **Map typed DNS credentials (#1067, #410)**: provider fields of type `map[string]string` / `map[string]*Seq` are shown as text areas in the
  ACME form. `src/mod/acme/acme_dns_maps.go` decodes `name:value` lists (comma or new line separated) or a JSON object. `selfhostde`
  (`RecordsMapping`, `domain:id[:id]`) has its own constructor because lego's `Seq` has no exported fields. `hurricane`, `dnshomede` and
  `myaddr` (all `Credentials`) are enabled. `providers.json` / `acmedns.go` were edited by hand to match what `tools/update_acmedns.sh`
  produces after the `extract.go` change; regenerate when lego is bumped.
- **GeoIP overrides (#1334)**: `src/mod/geodb/overrides.go` pins verified ranges on top of the CSV (embedded or downloaded). The proper fix
  (switch to a maintained dataset with an acceptable licence and regenerate the CSVs) needs network access and a licence decision and is
  still open. Refresh procedure: replace the CSVs (see `mod/geodb/README.txt`), then drop overrides the new data already gets right.
- **h2c upstreams (#1029)**: `Upstream.H2C` (API `h2c=true` on upstream add / `H2C` in the update payload, ignored when "Require TLS" is
  set) makes dpcore use an `http2.Transport` with plain TCP dials (`dpcore/h2c.go`). Streaming bodies and trailers work (gRPC); `Upgrade`
  and CONNECT requests fall back to HTTP/1.1. The old `modh2c` round tripper is not used: it builds a transport per request and cancels the
  context when `RoundTrip` returns, which breaks streaming. The gRPC body-peek block in `dpcore.go` is unchanged. Limits: the upstream
  "response timeout" is not applied to h2c upstreams, and "Force HTTP/1.1" on the rule is ignored for them.

## Bug sweep 1 (path handling, backups, stream proxy)

Report: `docs/triage/sweep-1.md|json`. Developer notes for the fixes on `fix/bug-sweep-1`.

- **`-conf` is honoured by ACME and ZorxAuth**: `acme.ACMEHandler.CertStorePath` (set from `CONF_CERT_STORE` in `src/acme.go`, default `./conf/certs`)
  is the only place certificates, keys and `<name>.json` are read or written. `zorxauth.DefaultConfigFolder` (set in `start.go`) replaces the old
  hard-coded `./conf/sso/zorxauth`; saved options that still carry the legacy value follow it. Still hard-coded: `mod/update` migrations (`./conf`)
  and a few `./tmp` paths (tlscert localhost cert, cert download zip, gotty).
- **Config backup** (`src/confbackup.go`): zip entries are always `conf/<relative path>` and `sys.db`, whatever `-conf` / `-dbpath` are. Restore validates
  every entry first (`zipRestoreTarget`, rejects anything outside `conf/`, `..`, absolute names), only then renames the live folder to `<conf>.old_<ts>`
  and extracts into `-conf` (`sys.db` into `-dbpath`). Archives made by older builds with the default `-conf` still restore.
- **Edit handlers are partial updates**: stream proxy edit keeps TCP/UDP/logging/PROXY protocol when the parameter is absent; redirect add/edit
  returns on a missing destination; vdir edit keeps `Disabled`.
- **Stream proxy**: `connCopy` always releases its wait group and closes both sockets on error; PROXY headers pick TCPv4/TCPv6 (UDPv4/UDPv6) from the
  addresses; rejected clients are closed after 300 ms in a goroutine so the accept loop never sleeps.

## Central management (Fleet)

Fleet turns one Zoraxy into a management hub for several others. It extends `src/mod/cluster` (files `fleet_*.go`, page
`web/components/fleet.html`, glue `src/fleet.go`); the legacy shared-secret primary/follower mode above is unchanged, still works with
its `conf/cluster.json` and flags, and is labelled "Legacy shared-secret mode" on the Cluster / HA page. A node uses one mode:
`standalone`, legacy `primary`/`follower`, or Fleet `hub`/`node`. Everything is inert until the hub role is enabled.

**What the hub can do, and what it cannot.** The hub publishes immutable, versioned configuration and can ask a node to "sync now".
A node pulls a bundle, validates it, applies it atomically (stage, backup, rename, local rollback, boot guard) and reports. There
is **no remote command execution** of any kind: no shell, no plugin install, no update trigger, no file path chosen by the hub. A
bundle can only contain files of the allow-listed roots (`proxy`, `redirect`, `access`, `rules`, `streamproxy`, `trusted_proxies.json`,
`acme_conf.json`, optionally `certs`) and items of registered scopes. Admin accounts, `sys.uuid`, `conf/webui` (admin TLS keys), updater
state, `cluster.json`, node keys and logs are never exported or accepted.

### Data model and files

| File (in `conf/.cluster/`, all 0600) | Side | Content |
|---|---|---|
| `fleet-hub.json` | hub | hub id, settings, nodes (with node keys), groups (scopes, variables, stable version, latest rollout), join token hashes, version index |
| `fleet-hub.key` | hub | random 32 byte key; seals stored versions (AES-256-GCM + HMAC, the snapshot format) |
| `fleet/versions/<n>.zcs` | hub | immutable sealed config versions; secrets inside are encrypted at rest |
| `fleet-audit.jsonl` | hub | audit log (who, when, what; never keys, tokens or variable values) |
| `fleet-node.json` | node | hub id and this node's key. Never logged, never synced |
| `follower.json` | node | applied version/hash, managed keys per scope, conflicts (shared with the legacy follower state) |

`conf/cluster.json` only gains the roles `hub` and `node` (for a node `primaryUrl` / `primaryFingerprint` hold the hub URL and pin).

### Enrollment and per node credentials

1. Hub: Fleet, "Join nodes", create a token: single use, 1 minute to 24 h, optional node name and group preselected. Token format
   `zj1.<id>.<secret>`; only a SHA-256 of the secret is stored; compared in constant time; unknown id, wrong secret, used, revoked and
   expired all answer the same 401. `POST /api/fleet/join` is rate limited to 10 per minute per client IP and audited.
2. Node: Fleet, enter the hub admin URL and token. For https the node first connects and shows the hub certificate's SHA-256
   fingerprint; the admin compares it with the one on the hub's "Join nodes" tab (`-webui_tls` certs) and confirms; the pin is stored and
   used for every later request (`newPinnedClient`). A self-signed hub certificate without a pin, and a plain `http` URL without an
   explicit confirmation, are refused.
3. The hub answers with a random 32 byte node key (hex). From then on every request carries the existing HMAC bearer token
   (`zxc1:ts:node:nonce:mac`, bound to method and path, +-60 s, single use) computed with that node's own key. The config bundle is
   sealed with the node key too, so a bundle for node A cannot be read or forged with node B's key.
4. Revoke: `nodeRevoke` marks the node revoked; its tokens stop working on the next request (all failures look the same). Rotation:
   `nodeRotate` stages a new key which is delivered inside the next sealed bundle; when the node authenticates with the new key the
   hub drops the old one. A leaked old key stays valid only until the node's next sync. Re-enrol a revoked node with a new token.
5. Leave (node): role back to standalone, key deleted, managed files stay as ordinary local config.

### Scopes (`Scope` registry, `fleet_scope.go`)

```go
type Scope interface {
    Name() string; Label() string
    Export(env *ScopeEnv, sel Selection) ([]FileEntry, error)   // hub: items of this scope
    Validate(items []FileEntry) error                           // hub at publish AND node before applying
    Apply(env *ScopeEnv, items []FileEntry, prevManaged []string) (*ScopePlan, error) // node: final files + Commit/Undo hooks
    OwnsPath(p string) bool
}
cluster.RegisterScope(s) // replaces by name
```

Built in (file based): `proxy` (merge mode, tag filter), `redirect`, `access` (access rules + trusted proxies), `pathrules`,
`streamproxy`, `acme`, `certs` (off by default, hub setting "capture certificates"). The scope list is chosen per group and can be
overridden per node. **No scope selected means nothing is managed** (a fresh group changes nothing).

- Whole-root scopes mirror the hub (local additions in that root are removed).
- `proxy` merges: hub rules are installed, rules the hub published before and no longer publishes are removed, **node local rules
  are never touched**. A local rule with the same file key as a hub rule is replaced (hub wins) and reported as a conflict (node UI,
  heartbeat, hub drawer). Optionally only rules carrying given tags (case insensitive `Tags` of the rule) are managed.
- A scope that is switched off stops being managed; its files stay as local config.
- Non file scopes (the Central WAF policy and profiles in the settings DB): implement `Scope`, exchange items with paths prefixed
  `"<scope>:"` (such items travel in `FleetMeta.Extra`), persist in `ScopePlan.Commit` (runs after the files are installed, before the
  reload) and revert in `ScopePlan.Undo` when the reload fails. `TestPluggableScope` shows the shape with a fake `waf` scope. After
  `feat/central-waf` merges, add a `wafScope` in `src/` and `cluster.RegisterScope(...)` from an `init()`; nothing else changes.
- The node UI shows a "Managed by hub" banner; `GuardLocalEdits` answers 403 to writes against managed scopes' APIs and against managed
  proxy rules (matched on the `ep`, `rootname`, `domain` form field), local rules stay editable. This is a UX guard; the authority is the
  apply step (hub wins on the next sync).

### Variables

Managed JSON files may contain `{{node.NAME}}`. Names `[a-z][a-z0-9_]{0,31}`; values are limited to `A-Za-z0-9 . _ : / @ + - [ ]` (max
253), so a value cannot close a JSON string, add keys or inject braces. Built in: `{{node.id}}`, `{{node.name}}`, `{{node.group}}`
(sanitised). Order: group variables, overridden by node variables. A malformed `{{node.` placeholder fails the capture; the publish
preflight dry-runs every node (all placeholders defined, result is valid JSON and still passes scope validation) and refuses the whole
publish otherwise; the node re-validates and refuses a bundle with a bad value or missing variable (nothing is applied). Certificates
are never templated. The hub itself should not proxy templated rules (it would read the raw placeholder).

### Versions, rollout, rollback

"Publish" captures the hub's current files into a new version (identical captures are not duplicated), keeps the newest N (default 10;
versions a group still uses are never pruned), then starts a rollout for a group:

- **immediate**: the group's stable version becomes the new one.
- **manual**: nothing changes until "Approve".
- **canary**: one node (chosen or the first online) is pointed at the new version, the rest stay on the stable one. The hub watches the
  canary's heartbeats. It must report the new bundle hash applied and `health: ok` (router running, from the same logic as
  `/.zoraxy/health`) for "healthy for N s" (heartbeats late by more than 90 s restart the period). It then promotes, or with "hold
  for approval" waits for you. Failure halts the rollout and points the canary back at the stable version: reported apply error for
  that bundle, unhealthy longer than the grace period (30 s default), did not apply within the timeout (300 s default), offline
  more than 5 min after applying, or the canary was revoked/removed. The first ever publish to a group has no earlier version to go
  back to (the reason says so; node-local rollback still protects a failed apply).
- Rollback is "publish an older version" (Groups tab: roll back to the version before, Versions tab: any kept version) with the same
  strategies. The diff view lists added/removed/changed objects per scope with contents of small non-certificate files.

Nodes apply with the legacy follower machinery (`finishApply`): stage, backup, rename, reload (Zoraxy restarts itself), pending marker
and boot guard that restores the backup when the new files stop the node from starting; a failed reload or scope `Commit` rolls back
immediately. `Tick` is driven by a 5 s timer and by every heartbeat; the state machine is a pure function of heartbeats and an
injectable clock (`TestCanary*`).

### Dashboard, telemetry, audit

Nodes send a heartbeat every 20 s (hub configurable) with bounded numbers only: uptime, health, active rule count, soonest certificate
expiry, strictest WAF mode, cumulative request / 5xx / WAF event counters, applied version and hash, last apply result, whether managed
files were edited locally (drift), conflicts. The hub derives per minute rates (a counter reset is handled) and aggregates totals,
error rate, WAF events and drifting nodes from those; nothing per request is shipped. Status: online (heartbeat < 90 s, healthy, last
apply ok), degraded (90 s to 5 min, unhealthy, or last apply failed), offline (> 5 min), never-seen, revoked. Drift = applied bundle hash
differs from the node's desired hash, or managed files changed on the node. The audit log (Fleet, Audit log) records token creation,
joins (also denied ones, with the source IP), revocations, rotations, scope/variable changes (variable names only), captures, rollouts,
halts, promotions, approvals, settings.

### Threat model

| Threat | Mitigation |
|---|---|
| Stolen node key | affects that node only (per node keys); revoke/rotate; bundles for other nodes are sealed with other keys |
| Stolen join token | single use, <= 24 h, hash at rest, revocable, rate limited, audited; a used token is useless |
| Network attacker | https + pinned fingerprint confirmed at join; bundles are encrypted and signed anyway; tokens bound to method/path/time/node, single use, +-60 s; plain http is refused unless explicitly accepted (still no secret config in clear) |
| Replay | per-hub verifier remembers token MACs for the window; stale timestamps rejected |
| Brute force | constant time compares, uniform 401, per IP rate limits (join 10/min, sync 240/min) |
| Hostile or compromised hub | cannot execute code; can only change the scopes it manages on that node (still powerful: a proxy rule can point traffic anywhere, treat the hub as the most sensitive host, like the admin password). Node validates paths (allow-list roots), JSON, scope schemas, variable charset |
| Secret exposure | captcha keys, basic auth hashes, certificate keys live inside sealed versions; hub key file 0600; node key file 0600; nothing secret is logged or audited |
| Injection through variables | strict charset, JSON re-validation, preflight dry run on the hub, re-check on the node |
| Admin API abuse | `/api/fleet/hub/*` is behind the admin session and CSRF like every admin API; the unauthenticated endpoints answer 404 unless the role is hub |

Residual risks: the hub holds every node key and all published secrets (protect it like the admin account, restrict its admin port with
the firewall); a node trusts its hub completely for the managed scopes; clocks must be within 60 s (NTP); heartbeat telemetry is
self-reported by the node.

### Setup walkthrough (hub VM + N proxy VMs, systemd)

1. Same Zoraxy build on all VMs, each with its own `conf` / `sys.db` (no copying `conf` between VMs: `sys.uuid` is the node id).
2. NTP on every VM (`timedatectl status` shows "System clock synchronized: yes"); skew over 60 s breaks authentication.
3. Firewall: nodes need outbound TCP to the hub admin port (default 8000); the hub's admin port must accept the nodes' addresses only.
   Nodes need no inbound port for Fleet (they poll). Start the hub with `-webui_tls auto` (self-signed) or provide a CA certificate.
4. Hub: Fleet, "Enable hub role". Create a group (e.g. `edge-eu`) with its managed scopes (start with `proxy`), optional tags and
   variables. Build the proxy rules on the hub like on any Zoraxy.
5. Join nodes: hub, Join nodes, create a token (name and group preselected). Node: Fleet, hub URL `https://<hub>:8000`, token, "Check
   hub certificate", compare the fingerprint with the hub tab, Join. The node appears on the hub within a heartbeat.
6. Per node variables (drawer), then Groups and rollout, Publish: try canary with the group's smallest node first.
7. systemd: nothing special; `Restart=always` is what lets the boot guard roll a bad bundle back. Apply restarts the process (about 3 s).

### Manual verification checklist (hub + 2 throwaway VMs)

- [ ] Enable hub; create group; token with preselected name; join node A over https with the fingerprint confirmed; wrong fingerprint is refused.
- [ ] The same token a second time, an expired token and a revoked token are all refused.
- [ ] Join node B. Both appear online with version, uptime, health, rule count, WAF mode; req/min moves under load.
- [ ] Publish `proxy` immediately: both nodes get the hub's rules after a restart; a node-local rule created beforehand is still there and editable; hub rules show the banner and cannot be edited on the node (403).
- [ ] Create a local rule with a hub rule's name before publishing: it is replaced and listed as a conflict.
- [ ] Add `{{node.upstream_ip}}` to a hub rule: publish is refused until each node has a value; then each node gets its own upstream. A value containing a quote is rejected.
- [ ] Canary: publish a change; only A changes; after the healthy period B follows. Publish a rule with an invalid upstream on a throwaway node and watch the canary halt and return to the stable version.
- [ ] Break A's health (stop its router): canary halts, group stays on the stable version.
- [ ] Roll back from the Versions tab; diff shows the change.
- [ ] Edit a managed file on node A by hand: drift icon on the hub.
- [ ] Rotate A's key: A keeps syncing; the old key no longer authenticates. Revoke B: B's next sync fails immediately and the hub shows it revoked.
- [ ] Audit log lists every action above with who and when.
- [ ] Legacy: another pair in primary/follower mode keeps working and says "Legacy shared-secret mode".
## Networking features (feat/networking-1)

All of these are opt-in; a rule without the new fields behaves exactly as before. Logic lives in new files of `src/mod/dynamicproxy`, the shared
`runEndpointChain` (Server.go) only gained two hook lines. Order in the chain: **allowed peer set -> access rule -> client certificate -> path rules ->
plugin pre_auth -> WAF -> exploit detection -> rate limit -> CAPTCHA -> auth -> plugin routing**. Config for all per-rule features is stored in the
rule's `.config` file (`ClientCert`, `PathRules`, `AllowedPeerCIDRs`, `SecondaryPortsTLS`, omitted when empty) and edited through
`src/networkingapi.go` (`/api/proxy/networking/*`) with the side panels `web/snippet/networkingEditor.html` and `pathRulesEditor.html`
(buttons in the rule editor, `httprp.html`, "Networking"). `PrepareProxyRoute` compiles the options; a config that does not compile (hand edited file)
makes the rule answer **503 to every request** (fail closed) instead of dropping the protection.

* **Client certificates / mTLS (upstream #442)** `clientcert.go`. Modes: `request` (optional; if a CA bundle is set a presented certificate must verify),
  `require` (certificate required, chain NOT verified; refused unless an allow list pins it), `require_and_verify` (CA bundle, `ExtKeyUsageClientAuth`).
  The listener config has `GetConfigForClient` that picks the policy by SNI, so only the hosts that need a certificate prompt for one. The handshake is not the
  security boundary: SNI and `Host` are independent, so the chain re-verifies against the CA pool of the rule selected by `Host` (a client that completed TLS for an
  open host cannot reach an mTLS host; plain HTTP requests to a required rule get 403). Allow/block list entries: `cn:`, `san:`, `serial:<hex>`, SHA-256 fingerprint
  or a bare CN/SAN; block list = manual revocation. **Revocation (CRL/OCSP) is not supported.** Upstream sees `X-Client-Cert-Subject/-Fingerprint/-Serial/-Verified`
  (the four names are always deleted from the incoming request first; `DisableIdentityHeaders` turns the headers off). Per-handshake config clones do not share
  session ticket keys, so TLS session resumption never carries a client certificate decision to another handshake. Tests: `clientcert_test.go` (real in-process TLS
  handshakes: valid, expired, wrong CA, intermediate chain, blocked serial, SNI/Host mismatch, allow list, header spoofing).
* **Upstream mTLS + PROXY protocol (per upstream)** `Upstream.ClientCertName` = a pair `name.pem`/`name.key` in the certificate store, loaded on every handshake
  (`loadbalance.UpstreamClientCertLoader`, set by `initUpstreamClientCertLoader`); only for `RequireTLS` upstreams; also used by the active health probe.
  `Upstream.ProxyProtocol` 1/2 (`dpcore/proxyproto.go`): header on every upstream connection announcing `r.RemoteAddr` (the TCP peer as Zoraxy sees it; behind a CDN
  that is the CDN). Because the header belongs to a connection, those upstreams get **no connection reuse, no h2/h2c, no environment proxy**; health probes send a LOCAL/UNKNOWN
  header. Not applied to WebSocket upgrades and CONNECT (they use their own dialers), nor to the TCP/UDP stream proxy. Edit in the upstream panel
  (`/api/proxy/upstream/update` payload fields, `proxyproto` / `clientcert` on `/add`).
* **TLS on secondary ports (upstream #1042)** `secondarytls.go`, `SecondaryPortsTLS` on the rule. A listener address is shared; it is TLS if any rule listing it asks for TLS
  (warning logged for mixed use). `UpdateSecondaryListeners` restarts a listener whose mode changed. Same certificate store/SNI, min TLS version and cipher profile as the main
  listener, plus the mTLS policy. Test: `secondarytls_test.go` (real handshake, switch off/on).
* **Path rules (upstream #238, #726)** `pathrules.go`. Ordered, first match decides: `allow` (only stops path-rule evaluation), `deny` 403, `rate_limit` (token bucket per rule+client, 429),
  `require_auth` (forces the rule's auth provider even if a Basic/ZorxAuth/Forward/OAuth2 exception would skip it via the `pathForcesAuth` request context flag; 403 if the rule has no
  provider). Restrictive actions match if **any** reading of the path matches (single/multiple decoding up to 4 rounds, `//`, dot segments, `;params`, `\`, NUL); `allow` only matches a target
  that is already canonical. Scope: CIDRs/countries, optionally inverted. Methods are the real HTTP method (override headers are ignored). Case sensitive unless the rule says otherwise
  (tick it for case-insensitive upstreams). Tests: `pathrules_test.go` (bypass table).
* **Allowed direct peers (upstream #761)** `peerset.go`, `AllowedPeerCIDRs`: only `r.RemoteAddr` is looked at, never forwarded headers; first check of the chain; works on TLS, port 80 and
  secondary ports. With the PROXY-protocol listener option the peer is the announced address. Tests: `peerset_test.go`.
* **Default site logging (upstream #578)** `defaultsitelog.go`: switch `settings/logDefaultSite` (`/api/proxy/defaultsite/logging`, checkbox on the Default Site page), default off. Logs the 404 page
  and unknown host on secondary ports; global token bucket (20 burst, 5/s) plus a "N request(s) not logged" summary line. Proxied/static default site requests keep following the default
  site rule's own logging setting.
* **Plugins as unprivileged user (upstream #760)** flags `-plugin_user`, `-plugin_group` (`mod/plugins/runas_unix.go`): setuid/setgid via `SysProcAttr.Credential`, supplementary groups dropped,
  `HOME/USER/LOGNAME` set. Requires root, otherwise `StartPlugin` returns a clear error (no silent fallback). Refuses uid/gid 0. Files are NOT chowned: the binary and the plugin folder must be
  accessible to the user (checked first; the error names the `chown -R` to run). Ignored with a log line on Windows. Unit tests simulate root with a seam; nothing here was run as real root.
* **Network diagnostics** `mod/netutils/diagnostics.go`: `/api/tools/dns`, `/api/tools/tlsinspect`, `/api/tools/httptest` ("Diagnostics" tab of Network Tools). Admin only; connections to metadata /
  link-local addresses are refused by default at dial time (so rebinding and redirects are covered), `allowmetadata=true` overrides per call. HTTP tester follows redirects manually (max 10), GET/HEAD/OPTIONS only.
## Admin UI: UX overhaul and smoke test

### What changed (`feat/ui-ux-overhaul`)

* **Nav scrolling fix.** `.toolbar` (left menu) is a sticky column limited to the viewport
  (`100vh` / `100dvh`), with its own `overflow-y: auto` and `overscroll-behavior: contain`, so the mouse wheel over the
  menu scrolls the menu, not the page (it used to be as tall as the whole page and therefore never scrolled itself).
  The mobile drawer got the same treatment.
* `src/web/script/uxkit.js` (new, loaded at the end of `index.html`, optional enhancements):
  menu filter box (press `/` to focus, `Esc` clears, `Enter` opens the first match); `alert()` is replaced by the
  non-blocking toast (`msgbox`) in the main window and in snippet iframes; aria-labels for icon-only buttons and
  keyboard operation of the menu groups; rate limited toast when an API request fails; unsaved-changes confirmation when
  closing the HTTP proxy rule editor after editing a field (cleared by any successful `/api/proxy/*` write; it is per
  editor, not per section).
* Theme: with no stored choice the UI follows the OS dark/light preference; the toggle still persists the choice.
* Responsive: no horizontal page overflow on phones, tabular menus scroll sideways, wide tables scroll inside their box.
* Fixed bugs found by the smoke test: `/api/proxy/status` failed to marshal (func fields in `tlscert.Manager`,
  `access.Controller`, `loadbalance.RouteManager`, `dynamicproxy.RouterOption` now tagged `json:"-"`) which broke the
  Status/Ingress pages; null `Tags`/`MatchingDomainAlias`/certificate lists crashing the HTTP proxy page; a 404 script in the
  certificate page.
* Collapsible nav groups with remembered state already existed (`zoraxy_menu_groups` in localStorage).

### UI smoke test (`tools/ui-smoke/`)

`smoke.py` drives headless Chromium (Playwright) against a running admin UI. It opens every menu page in light and dark
theme and fails on JavaScript errors, `console.error`, failed or 4xx/5xx requests, empty/missing page containers and
horizontal overflow; it takes a screenshot per page; it checks the nav wheel-scroll behaviour on a short desktop viewport
and on a 390px phone viewport; it tests the menu filter, icon-button labels and the editor unsaved-changes guard (it creates
and deletes a rule `smoke-test.invalid`, so run it only against a throw-away instance).

```bash
# one-time setup (any directory outside the repo)
python3 -m venv venv && ./venv/bin/pip install playwright && ./venv/bin/playwright install chromium
# (if chromium misses system libraries and you have no root: apt-get download the missing -dev-less
#  libs, dpkg -x them into a scratch dir and export LD_LIBRARY_PATH; a fonts.conf via FONTCONFIG_FILE and one
#  TTF font are needed too)

# builds this checkout, starts a throw-away instance (-noauth, temp conf/db, port 18765) and runs the test
PY=./venv/bin/python tools/ui-smoke/run.sh --out ~/ui-smoke-shots
# or against an instance you started yourself (use -noauth -dev with scratch -conf/-dbpath):
./venv/bin/python tools/ui-smoke/smoke.py --url http://127.0.0.1:8000 --out ~/ui-smoke-shots
```

Exit status is non-zero on any failure; `--allow REGEX` tolerates a known message (e.g. offline-only failures).

## Certificates and ACME (feat/certs-acme-2)

Everything below is opt-in; with no new flag and no saved profile Zoraxy behaves as before (RSA2048, Let's Encrypt,
per certificate DNS credentials).

### ACME options
* **Key type** (`RSA2048|RSA3072|RSA4096|EC256|EC384`): per request (`keyType`), default preference
  (`/api/acme/keytype`, table `acmepref` key `keytype`). Order: request, key type stored in `<cert>.json`, preference, RSA2048.
* **Staging CA**: built in as `Let's Encrypt (Staging)` (`mod/acme/ca.json`). **Saved CA profiles** (`/api/acme/profiles/ca`,
  stored in `acmepref/ca_profiles`): custom directory URL, optional EAB key id + HMAC, skip-TLS, default ACME `profile`.
  ACME accounts are already stored per directory URL + email, so several CAs live side by side.
* **Per certificate metadata** (`conf/certs/<name>.json`) additionally records `key_type`, `acme_profile`, `ca_profile_id`,
  `dns_profile_id`, `managed_by`, `source`, `issued_at`. Renewal reuses all of them. Old files without these fields still work.
* **ACME profile selection** is passed through to lego (`ObtainRequest.Profile`); CAs that do not offer profiles ignore an empty value.
* **DNS credential profiles** (`/api/acme/profiles/dns`, `acmepref/dns_profiles`): named provider + credentials. Secrets are
  stored in the system database exactly like the per certificate DNS credentials, are masked (`********`) in every API response
  and a masked value sent back keeps the stored secret. A *default* profile is pre-selected in the request dialog and is used
  when a certificate has no credentials of its own (this covers the proxy rule creation flow, #380).
* The EAB HMAC key is no longer written to the log.
* **Renew now** (`POST /api/acme/renewCert cert=<name>`) renews one certificate with its stored settings and returns the
  operation log (`{ok, log[], error}`); lines mentioning hmac/password/secret/token are withheld.
* Unattended renewal skips certificates whose `managed_by` is `mapdir`, `csr` or `upload`.

### CSR flow (`/api/cert/csr`)
`op=generate` creates key + CSR (subject, SANs incl. wildcard/IP, key type). The key is written 0600 to
`conf/certs/pending-csr/<id>.key` (a sub folder, never loaded as a certificate). `op=complete` takes the issued PEM (leaf first),
checks it matches the key, is not expired and covers the requested names (override with `force`), refuses to replace an existing
certificate unless `overwrite`, then installs `<name>.pem/.key/.json` (`managed_by: csr`) and deletes the pending key.

### Certificates from a directory (`-certs_dir`, `-certs_dir_interval`)
Polling (mtime+size, then SHA-256) every N seconds, no extra dependency. Layouts: `fullchain.pem`+`privkey.pem` (also in
`live/<name>/`, symlinks followed), `<name>.crt|.pem`+`<name>.key`, `tls.crt`+`tls.key`, one pair per sub folder. Key/certificate
mismatch and expired certificates are rejected, an existing certificate not imported from the directory is never overwritten,
source files are only read, and when a source disappears the imported copy stays. Imports are `managed_by: mapdir` (badge
"Folder (external)") and are never renewed by ACME. Status: `/api/cert/mapdir`.

### Event hooks (`mod/notify`, `/api/notify/hooks`, `conf/notify.json` mode 0600)
Events: `certificate.issued`, `certificate.renewal_failed`, `certificate.expiring` (checked every 6 h, once per day per
certificate, window `expiryWarnDays`, default 14). Sources call `notifyManager.Emit(notify.Event{...})`; destinations implement
`notify.Sink`. A later notifications batch (uptime, WAF) only needs new event names and `Emit` calls. The plugin
`eventsystem` package was not reused because its event type is plugin-API specific.
* **Webhooks**: https only, JSON body (`event, time, source, subject, domains, expiry, days_left, ca, error`), headers
  `X-Zoraxy-Event`, `X-Zoraxy-Timestamp` and, with a secret, `X-Zoraxy-Signature: sha256=hex(HMAC(secret, timestamp + "." + body))`.
  10 s request timeout, 4 attempts with 1 s, 4 s, 16 s backoff for network errors / 429 / 5xx (other 4xx are final), redirects are not followed,
  environment proxies are ignored. **SSRF guard**: the dialer refuses loopback, RFC1918/ULA, link-local (incl. 169.254.169.254), CGNAT,
  multicast and unspecified addresses *after DNS resolution*, so rebinding and internal hostnames are caught. The admin toggle
  "allow private targets" lifts the guard (and then permits `http://`). Webhooks are not sent in offline mode.
* **Command hook**: only available when Zoraxy is started with `-allow_hook_commands`; without it the config cannot be saved and nothing
  ever runs. **This lets an administrator execute programs as the Zoraxy user.** The program must be an absolute path, is started
  without a shell (arguments are literal), with a minimal environment (`PATH` plus `ZORAXY_EVENT, ZORAXY_SOURCE, ZORAXY_SUBJECT,
  ZORAXY_DOMAINS, ZORAXY_CA, ZORAXY_ERROR, ZORAXY_TIME, ZORAXY_EXPIRY, ZORAXY_DAYS_LEFT, ZORAXY_EVENT_JSON`; the parent environment is
  not inherited), 30 s default timeout (max 10 min) and the first 4 KB of output are logged.

### Offline mode (`-offline`)
`mod/offline` is a process wide switch. When on, these refuse with `ErrOffline` before opening a socket: GeoIP database download
(manual, weekly scheduler, `-update_geoip`), public IP lookup (access controller start-up and ticker, HTTPS wizard), update check
and download, plugin store sync and plugin downloads, scheduled and start-up certificate renewal, webhooks.
**Not affected**: proxying, upstream health checks and uptime monitors, mDNS, and certificates an administrator explicitly requests
(obtain / renew now, which need to reach the CA and DNS provider). Features that call out by configuration (SSO/OIDC providers, CAPTCHA
verification, cluster follower) are not blocked; they cannot work without network anyway. Tests (`mod/offline`, `mod/plugins`,
`mod/updater`, `mod/acme`) install a counting failing dialer (`offlinetest.Install`) and assert zero dials in offline mode and
at least one dial in the online control run.

### Certificate list
`/api/cert/list?date=true` adds `Issuer, KeyType, ManagedBy, CAProfileID, DNSProfileID, Renewable, Source`; `/api/cert/usage` maps
certificate store names to the proxy rule hostnames that resolve to them. The list shows a green/orange/red days badge
(over 30 / 30 to 8 / 7 or less), managed-by label, used-by and a renew button with log output.

### Manual verification needing real accounts
Staging issuance (`Let's Encrypt (Staging)`), EAB with ZeroSSL, a real DNS provider profile, ACME `profile` support, and webhook delivery to a
real HTTPS receiver cannot be covered by unit tests (no CA is contacted in tests).

## Statistics, logs and notifications (feat/stats-logs-notify)

### Per-site statistics (`mod/statistic/site.go`)
Every proxy rule gets a compact `SiteSummary` next to the global daily summary, **keyed by the configured rule
(`RootOrMatchingDomain`), never by the raw Host header**. Bounds: at most 128 sites per day (further ones fold into `_other`), every
per-site map is soft-capped at `-stats_max_entries / 8` (min 100; 1000 when the flag is 0). Per site: totals, errors, blocked, 24 hourly counters
(sparkline), status codes, countries, client IPs, referers, user agents, top URLs, methods. Persisted inside the existing daily record
(`Sites`, additive JSON; old records load unchanged). API: `/api/analytic/load`, `/api/analytic/loadRange` accept `&site=<rule>` and answer in
the usual shape; `/api/analytic/sites?start=&end=` returns the comparison table. Global `StatusCodes` and `BlockedRequest` were added the same way.

### Statistics filters
`/api/stats/settings` (GET/POST JSON `{ExcludeNetworks, ExcludeBlocked, QueryMode}`) and `/api/stats/excludeMyIP`. Persisted in the `statsettings`
table. Defaults record everything and strip the query string (the old behaviour). `QueryMode` `mask` keeps parameter names and replaces values with `*`;
`full` records the whole query (can contain secrets, off by default). Blocked = access list, rate limit, WAF, CAPTCHA, exploit detection, path rules,
plugin, peer and client-certificate denials (`statistic.IsBlockedForwardType`).

### Per-site log files (`mod/info/logger/sitelog.go`)
Off by default. `conf/sitelog.json` (`/api/log/sites/config`): default mode `off|also|only`, per-rule override, `text|json` lines, rotate at size,
keep N rotated files, delete older than N days, gzip. Files: `<log>/sites/<safe name>/<safe name>.log`; `SafeSiteName` maps any rule key to one safe path
component (lower case `[a-z0-9._-]`, hash suffix when anything changed, so no traversal or collisions). Rules with "disable logging" never write.

### Access log search (`mod/info/logviewer/search.go`, page `snippet/logsearch.html`)
`/api/log/search`, `/api/log/searchExport?format=csv|json`, `/api/log/sources`. Files are discovered by walking the log folder only (no user supplied paths).
Plain files are read backwards in 64 KB chunks (newest first, stops early), gzip files are streamed. Bounds: 256 MB / 10 s per search by default (caps 2 GB / 60 s),
64 KB per line, RE2 regex of at most 200 characters, 1000 rows per page, 100000 rows per export. A search that hits a bound reports `truncated` with the reason.
CSV cells that start with `= + - @` are prefixed with `'`.

### Notification centre (`mod/notify`, page `snippet/notifications.html`)
Extends the certificate hooks (`notify.json`, mode 0600). Channels are `Sink`s of the same dispatcher and reuse the webhook SSRF guard (connect-time address
check, no redirects, no environment proxy). A channel reaches private/loopback/link-local targets or plain http **only** with its own "allow private" toggle; SMTP
hosts are resolved and checked before connecting (a rebinding race remains possible, hence use the toggle only for trusted LAN hosts). Secrets are masked in
every response, a posted mask keeps the stored value, and secrets are scrubbed from error text, the delivery log and the system log.
Rules (channels only; webhooks/command hook are unchanged): quiet hours (critical can bypass), digest, dedupe window, per-channel hourly rate limit, retry with
backoff (1s, 4s, 16s), in-memory delivery log (`/api/notify/deliveries`). Webhooks gained an optional JSON `template` (Go text/template with a `json` helper,
validated on save).

Event schema (see `mod/notify/events_ext.go`); other modules only call `notify.Emit(notify.Event{...})`, which is a no-op until the centre is started:

| event | severity | Subject | Extra |
|---|---|---|---|
| `uptime.down` / `uptime.up` | critical / info | target name | url, status_code, failures, downtime |
| `certificate.issued` / `renewal_failed` / `expiring` | info / critical / warning | store name | (Event fields) |
| `waf.spike` | warning | rule | blocks, window_seconds |
| `security.autoban` | warning | banned address | reason, duration, rule |
| `cluster.node_offline` / `node_online` | critical / info | node name | node_id, last_seen |
| `admin.login_failed` / `login_new_ip` | warning | user name | ip |
| `updater.available` | info | release tag | current, channel, url |

Flap suppression: `uptime.down` after N consecutive failed checks (default 3), `uptime.up` after M good ones (default 2). WAF spike: default 100 blocks in 60 s
per rule, cooldown 15 min. `updater.available` is only emitted when an administrator runs a check (the updater never polls by itself). Auto-ban and
renewal sources live on other branches and call `notify.Emit` (types `notify.EventAutoBan`, `notify.EventCertRenewFailed`).

### Plugin sniff payload
`DynamicSniffForwardRequest.rule = {name, uuid, tags}` (additive, omitted by older Zoraxy). Rules have no stored UUID, so `uuid` is a stable 16 hex digit hash of the rule key.

## Security and access features (feat/security-access-2)

Everything here is opt-in; with nothing configured the request chain and every config file behave as before. UI: the new
**Security Center** page (Security group; `web/components/security.html` + one partial per tab in `web/components/security/`) and an
**Options** tab on the Access Control page (`web/components/access_options.html`).

Where the features sit in the request chain (`runEndpointChain`, Server.go): abuse ban lookup (before everything, in `ServeHTTP` /
`handleNonTLSRequest`) -> allowed peers -> access rule (blacklist / whitelist / `DropOnBlock` / challenge countries) -> client cert ->
path rules -> **header rules** -> **bot rules** -> plugin pre_auth -> WAF -> exploit detection -> rate limit -> CAPTCHA -> auth
(basic with scope + credential lists / SSO) -> plugins.

| Feature | Code | Config / storage | Upstream |
| --- | --- | --- | --- |
| Auto-ban ("fail2ban") | `mod/abuse`, `mod/dynamicproxy/abuse_hook.go`, `abusewire.go` | `<conf>/abuse/config.json`, `bans.json` | #22 #898 |
| Admin accounts, roles, audit | `mod/auth/users.go`, `router.go` | `auth` table: `role/<u>`, `disabled/<u>`, `sessver/<u>`; `<conf>/auth_audit.log` | #89 #501 |
| Challenge countries, drop on block, sort / duplicate rules | `mod/access/ruleextra.go`, `mod/dynamicproxy/country_challenge.go`, `accessextra.go` | access rule JSON (`SortOrder`, `DropOnBlock`, `ChallengeCountryCode`, all omitted when unset) | #281 #908 #762 |
| Bot rules | `mod/botrules`, `bot_hook.go`, `securityapi.go` | `<conf>/botrules.json`; per rule `BotPolicy` | #615 |
| Header rules | `mod/dynamicproxy/headerrules.go` | per rule `HeaderRules` | #1356 |
| Basic auth lists and scope | `mod/dynamicproxy/basicauth_ext.go`, `securityapi_basic.go` | `<conf>/basicauth_lists.json` (0600); `BasicAuthListNames`, `BasicAuthScopePrefixes` | #621 #1006 |
| Auth audit | `mod/dynamicproxy/authaudit.go`, `authauditapi.go` | tags `auth:<provider>`; setting `authAuditRequireAll` | #1109 |
| OAuth2 / OIDC claim, e-mail allow-lists | `mod/auth/sso/oauth2/access.go` | db keys `oauth2AllowedClaims`, `oauth2AllowedEmails`, `oauth2AllowedEmailDomains` | #884 #1162 |
| Altcha CAPTCHA | `mod/dynamicproxy/captcha/altcha.go` | `CaptchaConfig.Provider = 2` | #1198 |

### Auto-ban

* Detectors (`mod/abuse.Kind`): 401, 403, 404, 429 / rate limit, WAF block, exploit block, bot block, CAPTCHA failure, admin login failure.
  Each has `Threshold` events within `WindowSec`. Status based detectors observe the final response status through a
  response-writer wrapper (Hijack / Flush / Unwrap preserved, so websockets and streaming keep working); explicit events (WAF, exploit,
  captcha, bot) are noted through the request context (`abuseNoteKind`) and win over the derived status.
* The client IP is always `GetClientIPForEndpoint` (trusted proxy aware): a spoofed `X-Forwarded-For` from an untrusted peer can neither
  ban a victim nor evade a ban. IPv4-mapped IPv6 is unmapped, IPv6 is tracked per `/64` (`IPv6Prefix`, 32..128).
* Never banned: loopback, private, link-local, multicast, unspecified, the allow-list, trusted proxies and the server's public IP
  (`Protect` callback), unless `BanPrivate` is set explicitly. Manual and remote bans obey the same rule.
* Ban duration `BanSeconds`, escalated by `EscalationFactor` per repeat offence inside `OffenderMemory`, capped by `MaxBanSeconds`.
  Memory is bounded (`MaxTracked` counters, `MaxBans` bans, expired entries swept every minute, state flushed every 5 s and on shutdown).
* `DropConnection` closes banned connections without a response (see below). `PerEndpoint` keeps counters and bans per proxy rule.
* Remote API for external tools (#898), outside CSRF and session: `POST /api/abuse/remote/ban|unban`, `GET|POST /api/abuse/remote/list`
  with `Authorization: Bearer <token>`. The token is generated in the UI (shown once, only its SHA-256 is stored, compared in constant
  time); no token = the API answers 401. Admin APIs: `/api/abuse/{list,config,setConfig,ban,unban,token}`.
* Metrics: bans and rejections use the existing `zoraxy_access_blocked_total{reason="auto-ban"|"auto-ban-created"}` counter.
* Not covered: SSO / ZorxAuth failures that answer with a redirect (302) are not counted; basic auth failures (401) are.

### Dropping connections (`dropConnection`)

HTTP/1.x: `Hijack()` + close (RST via `SetLinger(0)`). HTTP/2 cannot hijack, so the handler panics with `http.ErrAbortHandler`, which
net/http turns into RST_STREAM without logging a stack trace. Used by auto-ban `DropConnection`, access rule `DropOnBlock`, header rule
action `drop` and bot action `drop`. All default to off.

### Admin accounts

* `role/<user>` missing = admin, `sessver/<user>` missing = 0: an upgrade changes nothing for the existing account and keeps its sessions.
  The role is always read from the database (30 s cache, invalidated on every write), never from the cookie.
* Viewer = read only. `auth.RouterDef` refuses every method except GET / HEAD / OPTIONS for viewers (`viewerReadOnlyPOST` is the explicit,
  currently empty, allow-list) and also GET on `/api/conf/export`, `/api/info/pprof`, `/api/users/`, `/api/abuse/config`, `/web.ssh/`,
  `/plugin.ui/`. Mutations in this code base read their parameters with `PostPara` (form body), so a GET cannot mutate.
  `adminroles_test.go` enumerates every registered managed route and checks viewer POST / PUT / DELETE is refused: a new route is covered
  automatically, but remember to register it through the managed router.
* The last enabled admin cannot be deleted, disabled or demoted; admins cannot delete / disable themselves. Password change, disable,
  rename and delete bump the session generation (all sessions end; on a self password change the current session is re-issued).
  New passwords need 8+ characters (the original admin keeps whatever it has). `-reset_ac` drops the whole `auth` table as before.
* Audit log: JSON lines in `<conf>/auth_audit.log` (rotated at 2 MiB), last 200 entries in the UI. Logins, failed logins, account changes,
  password changes. Passwords are never logged.

### Header rules, bot rules

* Header rules: `equals` compares SHA-256 digests with `subtle.ConstantTimeCompare` over all alternatives (no early exit), `regex` is RE2
  with full match, values are capped (4 KiB, 8 values). Optional path scope uses the path-rule matcher (encoded dots / slashes, `;params`...).
  Values are never logged and are masked in `/api/proxy/list|detail` and `/api/headerrules/get` (`MaskHeaderRuleSecrets`; an empty value in the
  save API keeps the stored secret). Invalid stored rules answer 503 instead of opening the endpoint.
* Bot rules: categories (`ai_crawler` is built from `exploits.AIBotPatterns()`, not a copy), custom substring / regex rules (first match
  wins, regex max 200 chars, RE2), good bots verified by forward-confirmed reverse DNS (cached, at most 16 lookups in flight, otherwise "not
  verified"), actions block / challenge / log / drop. All `User-Agent` header values are judged. The user agent is truncated to 512 bytes.
  A User-Agent is spoofable: this stops lazy bots, not determined clients.

### Challenge countries

An access rule can list countries that get the endpoint CAPTCHA instead of a block (needs `CaptchaConfig` on the proxy rule; `RequireCaptcha`
itself is not needed). Without a configured CAPTCHA the visitors are blocked (fail closed); the Options tab warns about proxy rules lacking
one. Blacklist entries always win. A GeoIP lookup failure does not challenge anybody (same fail-open-for-country-only policy as the blacklist).

### Basic auth lists and scope

Lists live in a 0600 file with argon2id hashes; an endpoint accepts its own users OR any assigned list (unknown list names grant nothing,
list users are verified with the same throttling / verification cache). `BasicAuthScopePrefixes` restricts basic auth to path prefixes:
scope is matched liberally (any plausible reading of the path), a broken scope answers 503, and a client supplied `X-Remote-User` is removed
outside the scope. Without a scope the whole host is protected as before.

### Auth audit

`/api/authaudit/get` lists each proxy rule's provider and weakening factors (exception rules, basic scope, exceptions trusting forwarded
headers, basic auth without users). `autotag` replaces `auth:*` tags (other tags are kept). The "require auth on all rules" lint is report only.

### OAuth2 / OIDC and Altcha

* Claim rules `claim=v1,v2; claim2=v3` (all rules AND, values OR, exact match, nested claim paths), e-mail and e-mail domain allow-lists
  (exact domain; `email_verified: false` is refused), AND-combined with the group list; a broken rule set denies. **Multiple providers per proxy
  rule are not implemented**: `OAuth2Router` still holds a single configuration (sessions, JWKS cache and callback path are per router), so
  that needs a router-per-provider refactor. The legacy single provider is untouched.
* Altcha: `GET /.zoraxy/captcha/altcha` issues an HMAC signed SHA-256 challenge (secret = `SecretKey`, `SiteKey` unused, work factor
  `AltchaMaxNumber` clamped to 1k..2M); the page solves it with WebCrypto (needs HTTPS or localhost) and POSTs the widget compatible payload as
  field `altcha`. The server checks signature, hash, expiry (5 min) and single use (bounded replay cache). FriendlyCaptcha is not implemented.

### Tests

```bash
cd src
go vet ./...
go test -timeout 500s ./...
go test -race ./mod/abuse ./mod/botrules ./mod/access ./mod/auth/... ./mod/dynamicproxy/...
```
UI: `tools/ui-smoke/smoke.py` now also opens every Security Center tab and the Access rule Options tab.
## REST API and API tokens

A stable, token authenticated subset of the management API lives under `/api/v1/` (code: `src/apiv1.go`,
`src/mod/apitoken/`, spec `src/web/openapi.yaml`, docs page `/api/v1/docs`, UI `src/web/components/apitokens.html`
under Others > API Tokens).

- Tokens: `zrx_` + 256 bit random value, shown once at creation, stored only as SHA-256 hash (table `apitokens` in the
  system database), compared in constant time. Scope `read` (GET/HEAD only) or `readwrite`; optional expiry and IP/CIDR
  allow-list; revocable; last-used timestamp. Sent as `Authorization: Bearer <token>`.
- `/api/v1/` is mounted on the entry mux in `main.go` (`mountAPIv1`), outside the cookie + CSRF stack, so no CSRF token is
  needed for it. Bearer tokens are accepted ONLY there; every other route keeps cookie auth + CSRF unchanged. Token
  management (`/api/apitoken/list|create|revoke|delete`) is registered on the normal admin router (cookie + CSRF).
- Routes are thin wrappers: JSON body keys map 1:1 to the form parameters of the existing handlers, which are run through the
  cluster edit guard using their legacy `/api/...` path. A route must be added to both `v1Routes` and `openapi.yaml`
  (`TestAPIv1OpenAPIMatchesRoutes` enforces this). Never add token management or secret-returning routes to v1.
- The client IP is the TCP peer address (forwarding headers are ignored); behind a reverse proxy, allow-list the proxy.
- Token auth is rate limited (token bucket per token and per IP; 10 failed auths/minute per IP block that IP with 429) and
  every use is audit logged (token name, method, route, IP, status; never the token or hash).
## Proxy ops 2: plain HTTP listener address, network calculators, DNS responder

**Plain HTTP listener address (upstream #909).** `RouterOption.HttpListenAddr` (default empty = `:80`, behaviour unchanged) sets where the optional plain-HTTP listener binds (`src/mod/dynamicproxy/httplistenaddr.go`). DB key `settings/httpListenAddr`. API `GET/POST /api/proxy/httpListenAddr` (`addr=host:port`, empty resets). Validation refuses a bad host/port, the management UI port (`-port`) and the HTTPS proxy port. A change restarts the proxy service. The existing "Enable HTTP server on port 80" toggle and the redirect toggle apply to whatever address is configured. UI: `components/globalsettings.html`.

**Network calculators (upstream #504).** `src/mod/netcalc`: IPv4/CIDR and IPv6 calculators and range-to-CIDR, all constant-time big-integer arithmetic (a `::/0` query is free). `GET /api/tools/netcalc?q=...` (admin auth). UI: `components/netcalc.html` in the Network Tools "Calculators" tab.

**DNS responder (upstream #769, opt-in).** `src/mod/dnsresponder`: UDP+TCP authoritative responder for proxy rule hostnames and aliases (wildcards by glob), built on `github.com/miekg/dns`. Off by default; must be bound to a specific IP (wildcard bind needs `allowAllInterfaces`); default port 5353; non-hosted names get REFUSED; optional forwarding only when `forwardEnabled` and the client is inside `allowedCidrs` (a `/0` is refused); ANY/AXFR refused; per-client token bucket (queries over the limit are dropped), UDP size cap, TCP timeouts and connection cap. Config in DB key `settings/dnsResponder`, API `GET/POST /api/tools/dnsresponder` (`config=<JSON>`), glue in `src/dnsresponder_glue.go`, UI `components/dnsresponder.html` ("DNS Responder" tab of Network Tools). It is a split-horizon helper, not a general DNS server; do not expose it to the internet.

## Proxy behaviour and ops (`feat/proxy-ops-2`)

All of it is opt-in; configs written by older versions load unchanged (`ProxyEndpoint.Ops` is omitted when unset).

**Per rule `Ops`** (`mod/dynamicproxy/ops_config.go`, `ops_handlers.go`, `ops_bandwidth.go`; API `opsapi.go`; UI `snippet/opsEditor.html`)

- `opsBegin` (called next to the plugin response wrapper on the TLS and non-TLS paths) attaches `{{request_id}}` /
  `{{rule_name}}` / `{{client_ip}}` to the request context and wraps the `ResponseWriter` (`opsWriter`; Flush/Hijack/Unwrap kept).
- **Error pages:** the status codes (400-599) chosen by the admin are replaced by an `html/template` page (`Status, StatusText,
  RequestID, Host, Path, RuleName`; validated and test-rendered on save, max 64 KiB, HTML escaped). Interception happens in
  `WriteHeader`; the original body is discarded, nothing is buffered. It only becomes active once the request is being proxied
  (`armOps`), so auth challenges, CAPTCHA pages and access-list blocks are never replaced. Never replaced: `text/event-stream`,
  `application/grpc` (request or response), `Grpc-Status`, `Trailer`, any request with `Upgrade` (WebSocket), CONNECT. Zoraxy's own
  errors (521 unreachable, 404 DNS failure, 503 busy) are replaced too when listed. Rule mode: `inherit` (global default,
  `/api/proxy/ops/globalerrors`, stored in `settings/globalErrorPages`), `off`, `on`.
- **Static responses:** exact or segment-prefix path, methods (default GET+HEAD), status, content type, body, `Location`, extra headers.
  `Public` ones are answered right after the access list (before client cert, path rules, WAF, rate limit, auth); the others after auth.
- **CORS:** exact / `https://*.example.com` / `regex:` (RE2) / `*` origins. Preflights (OPTIONS + Origin + Access-Control-Request-Method)
  are answered by the proxy after the access-list check and before authentication; a non matching origin, method or header gets 403.
  Normal responses get ACAO/ACAC/ACEH and `Vary: Origin`; CORS headers set by the upstream are replaced. `*` with credentials is
  refused at save time and again at runtime.
- **Bandwidth:** token buckets per response and optionally shared per client IP, paced writes of at most 16 KiB with a flush after
  each chunk; clock and sleep are injectable (tests use a fake clock). WebSocket traffic is not limited.
- **Variables** (`rewrite/templatevars.go`): `{{host}} {{client_ip}} {{request_id}} {{rule_name}} {{external_ip}}` in custom header values,
  redirect targets and static responses. Substituted values lose control characters and are capped at 256 characters; header names are
  never expanded. `{{external_ip}}` is the access controller's public IP and is empty when `SkipPublicIPCheck` / offline.
  Variables are deliberately not expanded in upstream addresses (SSRF).

**Unix socket upstreams** (`loadbalance/unix.go`): origin `unix:/abs/clean/path.sock`; absolute, no `.`/`..`/`//`, no control characters,
at most 104 bytes, no TLS/PROXY protocol/H2C. dpcore dials the socket; active health checks (HTTP and TCP mode) use it too.
Not supported: WebSocket upgrades (502) and the passive uptime monitor (skipped).

**Client attribute load balancing** (`loadbalance/clientrules.go`): `Config.ClientRules` is an ordered list of `{Name, CIDRs, Countries,
Upstreams, Fallback any|deny}`. The first match restricts the candidates (after the health/draining filters) to the group and the
configured algorithm runs inside it; a sticky session pointing outside the group is ignored. The country comes from
`Option.GeodbStore` and is resolved lazily.

**Advanced regex** (`redirection/advanced.go`): `RuleTable.AdvancedRegex` (`/api/redirect/advancedregex`, default off) matches redirect
patterns with `github.com/dlclark/regexp2` (MIT) under a 50 ms match timeout, 500 character patterns and 4096 character inputs; a timeout
counts as "no match".

**Templates and bulk edit** (`ruletemplate.go`, `bulk.go`, API `bulkapi.go`): built in templates "Secure web app", "API backend",
"WebSocket app", "Static site" plus custom ones in the `ruletemplates` DB table. `POST /api/proxy/add` accepts `template`. A template
only sets what it lists (tags are added, headers merged) and never touches upstreams, domains or authentication.
`POST /api/proxy/bulk {rules, action, params, dryrun}`: enable, disable, add_tags, remove_tags, set_waf, set_ratelimit, set_auth
(`none` needs `Confirm`; otherwise only oauth2/zorxauth), apply_template, delete (needs `Confirm`). An invalid request changes nothing;
otherwise each rule is applied independently on a copy and reported (partial updates). UI: `script/proxybulk.js`.

Tests: `go test -race ./mod/dynamicproxy/...` (ops_test.go through `ProxyHandler.ServeHTTP`, bulk_test.go, unix_upstream_test.go,
loadbalance/clientrules_test.go, redirection/advanced_test.go).

## UI audit bot, CAPTCHA page, WAF page (feat/ui-audit-captcha-waf)

### UI audit bot (`tools/ui-audit/`)
`audit.py` is a Playwright bot that opens every nav page and every sub tab (Security Center, WAF, Access, SSO, Network tools,
Utilities ...) in light and dark theme at a desktop (1366 px) and a phone (390 px) width and reports, per page / tab / selector:
`icon` (an `<i class="... icon">` whose `::before` draws nothing, i.e. the icon name does not exist in the bundled Semantic UI 2.4.2
icon font), `empty-label` (button / link / field without text, aria-label or title), `overflow`, `clipped` text, `small-target`
(< 24x24 px), `contrast` (WCAG ratio < 4.5:1, 3:1 for large text, sampled), `table-header`, `img-alt`, `console` and `request`
(failed / HTTP >= 400). It also saves a full-page screenshot of each state. `seed.py` fills a throw-away instance with a dozen proxy
rules, CAPTCHA settings, a WAF policy and WAF events produced by attack-looking requests, so pages are judged with data.

```bash
# throw-away instance (never your real one): own conf, db, admin port and proxy port
./zoraxy -noauth -dev -port :28783 -default_inbound_port 28443 -conf ./conf -dbpath ./sys.db &
PY=./venv/bin/python           # a python with playwright + chromium, see "UI smoke test"
$PY tools/ui-audit/seed.py --url http://127.0.0.1:28783 --proxy-port 28443
$PY tools/ui-audit/audit.py --url http://127.0.0.1:28783 --out ~/audit-out    # audit-report.md / .json + shots/
```
Options: `--pages a,b` (nav tags), `--themes`, `--viewports`, `--no-shots`, `--allow REGEX`, `--report-only`. Exit status 1 when a
finding of severity major or worse exists. Icons: only names that exist in `script/semantic/semantic.css` render (for example
`robot` and `palette` do not, `bug`, `crosshairs`, `paint brush` do).

### CAPTCHA / Bot check page (`components/captcha.html`)
Top level page (Security group). Overview of every proxy rule (CAPTCHA on/off, provider, session, branding customised) with a
Customise / Set up action; a full page editor per rule (provider and keys, session duration in minutes / hours / days, path prefixes,
exceptions via `snippet/captchaExceptionEditor.html`, texts, logo upload, colours, theme, footer, Turnstile and reCAPTCHA options,
custom template with variable reference and starter template) with live Challenge / Failed / Blocked previews (debounced form POST
into an iframe, desktop / phone width) and a test key helper. The endpoint editor has a "Customise bot-check page" button
(`captchaPageOpen(ep)`). Saving a rule posts the CAPTCHA fields to the existing partial update `POST /api/proxy/edit`.

**Global default branding**: `GET/POST /api/proxy/captcha/default` (`captcha_default_api.go`, stored in `settings/captchaDefaultBranding`,
loaded at start). `captcha.MergeBranding` fills every field a rule leaves empty from the default (field by field, `HideFooter` is OR-ed;
provider, keys and Turnstile options are never inherited); the merge happens in `renderPage` for live pages, and for previews when the
form posts `applyDefault=true`. Not replicated by cluster sync (node local setting).

### WAF page (`components/waf.html`)
Tabs: Overview (mode selector cards, tiles, events per hour, needs-attention list, top rules / IPs), Events (filters, group by rule /
IP / URL / proxy rule, severity badges, rule descriptions from the CRS reference, detail drawer with the matched variable / value
(control characters stripped, length capped), exclude globally / per rule / per path, allow IP, copy request; 100 rows at a time; "Live"
polling pauses while the tab or the browser tab is hidden), Coverage (rules with no WAF highlighted, filter chips, bulk apply through
`/api/proxy/bulk` `set_waf`), Policy, Profiles (presets Log only / Standard / Strict / Paranoid fill the form), Exclusions (structured
list with search, add and remove), Rules reference. First run state offers "Enable in detection-only mode for all rules". Policy changes
re-read the stored policy before writing so a stale tab cannot overwrite them. No new server endpoints.
## Closure verification notes (branch fix/closure-bugs)

* `docs/triage/closure-bugs.md|json` list, per fork issue, the test or audit that backs the verdict and the reply text to post.
* Targeted UI regression scenarios (mocked API, headless Chromium): `PY=$HOME/ui-test-tools/py.sh tools/ui-smoke/regress.sh` (default port 28784). Scenarios: Docker picker with null lists (#954), multi-domain certificate request (#611), updater early-access label (#969).
* Forward auth behind a TLS-terminating tunnel (Cloudflare Tunnel): add the tunnel source address to Trusted Proxies; the auth subrequest then carries the tunnel's `X-Forwarded-Proto` and `CF-Connecting-IP` (`forward.AuthRouterOptions.IsTrustedProxy`).
* Host names are compared in punycode (`utils.NormalizeHostname`): use it for any new place that compares or stores a domain.
* Upstreams with "Skip Verification" use `utils.InsecureUpstreamTLSConfig` (legacy TLS versions and RSA suites allowed) for IPMI-class devices.
* Soak the forward-auth module for leaks: `ZORAXY_LEAK_SECONDS=300 go test ./mod/auth/sso/forward -run Leak -v`.

## Support closure batch (`docs/support-closure`)

Answers for the mirrored support-question issues live in `docs/guides/` (index below) and `docs/triage/closure-support.{md,json}`.
Behaviour changes that came out of them:

* **Virtual directories:** the longest matching `MatchingPath` wins (`GetVirtualDirectoryHandlerFromRequestURI`), creation order no longer matters.
  A WebSocket upgrade through a virtual directory now honours a base path in the target (`host:8072/websocket`), like plain HTTP does
  (`vdirWebsocketPath`); an empty remainder maps to the base path without a trailing slash.
* **DNS challenge credentials:** empty string fields sent by the UI are dropped before the provider config is decoded, so provider defaults
  (PowerDNS `ServerName=localhost`) apply.
* **Upstream failures:** the reason behind a 521/404 (dial refused, TLS handshake, DNS) is logged as `[proxy] Upstream X failed for request to Y`,
  at most once per upstream+reason per 30 s (`upstream_error_log.go`).
* **Error pages:** `{{.Host}}` / `{{.Path}}` are captured when the writer is wrapped (the proxy rewrites `r.Host` / `r.URL` later).
* **pprof:** `/api/info/pprof/` serves profile, heap, goroutine, ... (admin only, viewer role refused by the prefix rule). Use
  `go tool pprof` with the session cookie.
* **Access UI help text** explains which address access rules check, CGNAT (`100.64.0.0/10`) and the exact LAN list; the list is pinned by
  `TestIsPrivateIPRangeMatchesDocumentedList`, keep the text in `web/components/access.html` in sync.
* Known limitation documented in `docs/guides/authelia.md`: the forward-auth subrequest's `X-Forwarded-For` is the TCP peer, not resolved
  through the Trusted Proxy list (`mod/auth/sso/forward/util.go`).

Guides: `websockets-odoo-cleanslate-domoticz`, `url-rewrite-and-locations`, `real-client-ip-cloudflare`, `ssl-troubleshooting`, `authelia`,
`authentik`, `keycloak-groups`, `google-oauth2`, `pocket-id-navidrome`, `performance-tuning`, `updating`, `crowdsec`, `error-pages-and-521`,
`captcha-and-mobile-apps`.
## OAuth2 provider registry, persisted sessions, Friendly Captcha, CAPTCHA path modes (`feat/auth-captcha-remaining`)

This section supersedes the statements above that OIDC sessions are in memory only and that "OAuth2/OIDC cookies hold the provider token".

**Providers** (`src/mod/auth/sso/oauth2/providers.go`). Named providers live in DB table `oauth2_providers` (key = id, JSON record, the
client secret is stored like it always was and is never returned by the API). Id: `^[a-z0-9][a-z0-9_-]{0,31}$`, at most 32 providers.
`default` is the legacy single configuration: on the first start the old `oauth2` table keys are copied into the record `default`
(marker `oauth2/providersMigrated`), later starts read only the registry. Edits of `default` are mirrored back to the legacy keys so a
downgrade keeps working. Rules without a provider id use `default`; a rule that names a missing provider fails closed (HTTP 500).
- API (admin): `GET/POST/DELETE /api/sso/OAuth2/providers` (`id`, `name`, `preset` + the `oauth2*` fields of the legacy API; a blank or masked secret on
  update keeps the stored one; DELETE is refused while a rule uses it); `GET/POST /api/sso/OAuth2/discovery` accepts `id`; `/api/sso/OAuth2` keeps
  operating on `default`.
- Rule: `AuthenticationProvider.OAuth2ProviderID` and the optional `OAuth2AllowedGroups|Claims|Emails|EmailDomains` (all `omitempty`, so old rule files
  load unchanged). Rule lists are AND-combined with the provider's (they can only narrow). `/api/proxy/edit` accepts `oauth2provider`, `oauth2groups`,
  `oauth2claims`, `oauth2emails`, `oauth2emaildomains` (only the ones sent change).
- Isolation: callback `/internal/oauth2` and logout `/internal/oauth2/logout` for `default`, `/internal/oauth2/p/<id>` and `/p/<id>/logout` for the others
  (register that redirect URI at the IdP). Session cookie `z-session` (default) / `z-session-<id>`; the pending-login state, the session record and the
  cookie are bound to host and provider, a state or cookie of one provider is refused by another. Editing or deleting a provider ends its sessions only.
  Path exceptions (`ExternalAuthExceptionRules`) are evaluated before any provider code, so they work with every provider. Identity headers mapped by
  any provider are scrubbed from client requests.
- Claims: `claimValue` resolves nested paths with the longest-key-wins rule (`resource_access.my.app.roles`); arrays, scalars and booleans are matched exactly.

**Sessions at rest** (`persist.go`). Table `oauth2_sessions`: `{exp, p, blob}`, blob = AES-256-GCM(nonce|JSON) with AAD `session|<id>`, key = HKDF of the
same secret as the cookie signing key (node UUID, or `cluster.KeyMaterial(..., "oauth2-session")` when a cluster secret is set). Max 5000 records
(earliest expiry dropped), expired/tampered records removed on read and by a 10 minute janitor. Not persisted when no stable key exists. Logout deletes the record.
HA: the database is node local, so with a cluster secret the login also sets a sealed `z-ticket[-id]` cookie (claims only, no tokens, at most 30 minutes, AAD = session id). A node
without the record rebuilds a non refreshable session from it; afterwards the browser re-authenticates (usually silently). A ticket cannot be revoked on other nodes before it expires.

**Friendly Captcha** (`captcha/friendly.go`). Provider `3`. Site key = sitekey, secret key = API key (`X-API-Key`), field `frc-captcha-response`, siteverify
`POST https://global.frcapi.com/api/v2/captcha/siteverify` (EU: `https://eu.frcapi.com/...`, config `FriendlyEndpoint` `global|eu`, also sets `data-api-endpoint` of the widget), JSON
`{response, sitekey}`; any non-200 fails closed. With `VerifyHostname` the challenge origin must be the requested host. Widget SDK pinned to `@friendlycaptcha/sdk@1.1.3` from jsDelivr; CSP adds the SDK path, `*.frcapi.com`,
`worker-src blob:` and `'wasm-unsafe-eval'` for this provider only (the Altcha page no longer receives Google hosts either). Tests point the verify URLs at httptest servers.

**CAPTCHA path exceptions** (`captcha/exceptions.go`). `ExceptionRule.MatchMode` `""|prefix|exact|regex` and `CaseInsensitive` (both `omitempty`). exact/regex match the whole path and only
canonical request targets (`pathmatch.CanonicalPath`, shared with the SSO exceptions); the legacy prefix mode is unchanged. API `/api/proxy/captcha/exceptions/add|delete` takes `mode`, `nocase`.

**Route fix.** The Forward Auth / OAuth2 exception API was registered on the same URLs as the basic auth exception API (`/api/proxy/auth/exceptions/*`), so the
router dropped it (duplicate endpoint warning) and the SSO exception editor talked to the basic auth handler ("Invalid matching prefix given"). It now lives at
`/api/proxy/auth/sso/exceptions/list|add|delete` (found by the UI smoke test).
## UI performance, Status page and Visitors (feat/ui-perf-status-visitors)

### UI performance probe (`tools/ui-perf/perf.py`)
Starts (or attaches to) a throw-away `-noauth -dev` instance, seeds 30 proxy rules and ~600 proxied requests (behind a "trusted CDN",
with `CF-Connecting-IP` / `X-Forwarded-For`), then measures every menu page with CDP: main-thread CPU % over an idle window
(`ThreadTime`, immune to a loaded machine), long tasks, layout / style recalcs per second, timers per second, rAF callbacks,
network requests per 10 s, JS heap growth, DOM nodes, click-to-second-paint latency of typical interactions and the frame rate while
dragging the traffic map. `--profile N --only PAGE` prints a CPU profile, `--prep JS` runs JavaScript first (to test a suspect).
```bash
PY=$HOME/ui-test-tools/py.sh
$PY tools/ui-perf/perf.py --spawn ./zoraxy --web src/web --port 28781 --json perf.json
$PY tools/ui-perf/perf.py --url http://127.0.0.1:28781 --no-seed --only status --profile 10
```
Findings and fixes: `rules.html` re-initialised its accordion every 300 ms forever (`$._data` got a jQuery object, so the check never
passed), which kept mutating the DOM and re-triggered the `uxkit.js` MutationObserver (full `document.body` scan each time);
all ~30 page components polled in the background while hidden (`script/perfkit.js` now skips interval ticks of pages that are not
the active tab or when the browser tab is hidden); the traffic map repainted a big SVG every frame with CSS `stroke-dashoffset`
animation and SVG drop-shadow filters (the dashes are now drawn on a canvas at 8 fps, paused while hidden / off screen / user paused /
idle for 45 s, the grid is a viewport sized background). `uxkit.js` scans only the added nodes.

### Visitors (`src/mod/visitors`, `src/visitorsapi.go`, `components/visitors.html`)
* One aggregate per client IP (first / last seen, hits, blocked hits, country, top 16 hosts, top 12 paths, last UA / path / status,
  `via` = direct | cloudflare | proxy and the header the address came from, 30 daily counters) plus a ring buffer of the last N visits.
* Hot path: `Tracker.Record` is a settings check, the exclusion checks and a non-blocking channel send (queue 8192, drops are counted).
  A single writer goroutine owns the map. `go test -bench . ./mod/visitors` compares it with a global mutex map.
* Attribution uses `GetClientIPForEndpoint`; `visitors.Attribute` only labels a hit "cloudflare" / "proxy" when the resolved client differs from
  the TCP peer, so a forged `CF-Connecting-IP` from an untrusted peer is ignored and the hit is recorded as direct under the peer address.
* Honours the statistics exclusion list and "exclude blocked", and the per rule "disable statistics collection".
* Persistence: `conf/visitors.json.gz` (atomic replace) every 5 min when dirty and on shutdown. Settings in sysdb table `visitors`:
  `Enabled` (default on), `MaxIPs` 20000, `MaxAgeDays` 90, `MaxVisits` 5000, `KeepQuery` off, `NotifyNewCountry` off (event `visitor.new_country`).
* API: `GET /api/visitors/{summary,list,recent,detail,export,settings}`, `POST /api/visitors/{settings,delete,purge}`. CSV export neutralises formula injection.
* Country only (the embedded GeoIP database has no city data; no network lookups).
## Proxy UX: navigation, rule list, new rule dialog, Quick Start (`feat/ui-proxy-ux`)

**Navigation map** (`index.html`, one commented block). Groups (`id="group-ID"`): `proxy`, `security`, `certs`, `observe`, `tools`,
`system`; Quick Start and Status stay above them. To add a page append one line to the right group:
`<a class="item" tag="TABID" tab_group="GROUPID"><i class="simplistic ICON icon"></i> Label</a>` (and a `<div id="TABID" class="functiontab"
target="x.html">`). Tab ids and `tab_group` attributes drive `openTabById`, the Recent list, group auto-expand and the UI smoke test, so
never rename them. Every item needs an icon that exists in Semantic UI 2.4.2 (the smoke test checks the computed `::before`). Collapse
state is `localStorage.zoraxy_menu_groups` (`{groupId: expanded, _v: 2}`); state saved under the version 1 ids (`reverseproxy`, `services`,
`others`) is migrated by `getMenuGroupStates()`.
Old to new: Reverse Proxy (HTTP Proxy, Virtual Directory, Create Proxy Rule, Stream Proxy) and the top level Default Site and Ingress became
**Proxy** (HTTP Proxy, Default Site, Redirection, Virtual Directories, Stream Proxy, Ingress, Advanced Rule Form); Access & Connections
(Redirection, Access Control, Trusted Proxy) and Security (TLS, ACME, SSO, WAF, Security Center) became **Security** (Security Center, WAF,
Access Rules, Trusted Proxies, SSO / OAuth2) and **Certificates** (TLS / SSL Certificates, ACME Client); Others / Statistical Analysis and
Services / Uptime Monitor became **Observability** (Statistics, Uptime Monitor; Visitors goes here); Services, Networking and Utilities
became **Tools** (Static Web Server, Network Tools, Network Interfaces, Utilities); Cluster, Fleet, API Tokens, Update became **System**.

**HTTP proxy list** (`components/httprp.html` markup, `script/proxytable.js`, `script/proxybulk.js`). The table renders from a model
(`ProxyTable.state.list`, also exposed as `httpProxyList`) with one `innerHTML` write per page (25/50/100 rows) and event delegation, so
hundreds of rules never mean hundreds of DOM rows. Row = status dot, host (+ alias, listening ports, virtual directories, access rule),
upstreams, protection badges (auth, WAF, CAPTCHA, rate limit, exploit/bot blocking), tags, a status pill that enables / disables with one
click and an undo toast, Edit and remove. Health (red dot, "Errors" filter) comes from `/api/utm/list` matched against the rule's current
upstreams. Filters: search (host, alias, upstream, tag, auth), All / Enabled / Disabled / Errors / No auth, tag chips (all selected tags
must match). Sort: host, upstream, tags, status (saved in `localStorage.httprp_table`). Selection: checkboxes, shift-click range in the order
shown, select all on the page (then "select all N matching"), Esc clears, a sticky bar shows only while rules are selected. The bar calls
`ProxyBulk.run(action, names)` which uses `/api/proxy/bulk` with the existing preview / confirm dialogs. `n` opens the new rule dialog.
Snippets still call `parent.renderTagsPreview / updateAliasListForEndpoint / updateAccessRuleNameUnderHost`, which are kept.

**New proxy rule dialog** (`script/newrule.js`, loaded by `index.html`, `openNewRuleDialog({keep, domain, upstream})`): domain with
validation and duplicate check, upstream with live validation and `GET /api/proxy/testupstream?url=host[:port][/path]` (read only: TCP dial,
TLS probe, certificate verification, one GET; unix sockets are only dialled) which also sets the HTTPS toggle and "ignore certificate
errors" unless the user touched them, template picker (`/api/proxy/templates/list`), "More options" (tags, access rule, rate limit, uptime
monitor, sticky sessions, exploit blocking, plain HTTP, logging). It posts the same `/api/proxy/add` as `components/rules.html`, which stays
as "Advanced Rule Form" (the dialog's "Open the full form" copies domain and upstream over). After creating it opens HTTP Proxy, flashes the
new row and offers Open rule / Add another / Create certificate for this host (when HTTPS is on and no certificate covers the host).

**Quick Start** (`quickstartapi.go`): `GET /api/quickstart` returns `{dismissed, configured, show, rules, proxyRunning}`; `POST` with
`dismissed=true|false` stores the flag in the `settings` table (key `quickstartDismissed`). The instance counts as set up when at least one
HTTP proxy rule exists and the proxy listener runs; `show = !dismissed && !configured`. The menu item is hidden and the default landing page
is Status when `show` is false; a fresh install lands on Quick Start. "Show Quick Start again" is in Ingress (`.quickStartShowAgain`).

Tests: `go test -run 'QuickStart|Upstream' .`; the UI smoke test seeds 36 rules and covers nav structure/icons/collapse/state migration,
Quick Start dismissal, search, status and tag filters, sorting, shift-click range, bulk preview, Esc, status pill + undo, pagination, the
phone layout and the whole new rule dialog (validation, connection test, Enter to submit, highlight, quick actions).
## Platform features (`feat/platform-features`)

Four opt-in features, all off by default: Encrypted Client Hello, Lua script handlers, Sablier (scale-to-zero) integration
and zrok tunnels. Each keeps its logic in its own package; the shared files only got small hooks.

### Encrypted Client Hello (fork #235 / upstream #1319)

Code: `src/mod/ech` (keys, config serialisation, DNS check), `src/echapi.go` (APIs), `src/mod/dynamicproxy/ech_glue.go`
(router wiring), `src/web/components/ech.html` (page: Networking > Encrypted Client Hello).

- Server side ECH uses `tls.Config.GetEncryptedClientHelloKeys`, which crypto/tls calls per handshake, so enabling, rotating and
  retiring keys never needs a listener restart. The callback is installed on the HTTPS listener config *before* the per-SNI
  `GetConfigForClient` clones (client certificate / mTLS), and `tls.Config.Clone` copies it; ECH is decrypted before
  `GetConfigForClient` runs, so mTLS and certificate selection see the inner SNI (test: `TestEchKeysSurviveClientCertClones`,
  `TestHandshakeHidesInnerSNI` with and without the clone). The secondary TLS listeners get the same callback.
- Keys: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM + ChaCha20-Poly1305, random config id, configurable public name and
  `maximum_name_length` (default 64). Stored in `conf/ech/ech.json` (dir 0700, file 0600; the private keys are never returned
  by any API except the admin-only PEM export, which viewers cannot call). `conf/` backups contain them like TLS private keys.
  Cluster/Fleet snapshots do not carry ECH keys: configure each node (or copy the PEM) on purpose.
- Rotation: the newest `active` key is the only one advertised in the `ECHConfigList` and the only one sent as retry config;
  older keys become `retired` (decrypt-only) and are purged after the retain window (default 7 days, keep it above the DNS TTL).
  Optional automatic rotation every N hours (checked every 10 minutes).
- Rejections: a client with the wrong/unknown key is answered with the outer certificate for the public name plus the retry
  configs (`tls.ECHRejectionError.RetryConfigList` on the client); with ECH disabled the server ignores the extension.
  The public name needs a certificate Zoraxy can serve (an existing wildcard works); the page warns when none matches.
- DNS: the page shows the base64 list, a copy-ready `HTTPS 1 . alpn=... ech=...` record and a lookup helper
  (`/api/ech/dnscheck`, HTTPS RR through miekg/dns against the system or a given resolver IP) that compares the published `ech=`
  with the active list. Automatic publishing through a DNS provider is *not* implemented (needs a record API beyond lego's
  ACME challenge providers).
- HTTP/3: the QUIC listener clones the same config; with the pinned quic-go and Go version ECH is accepted over QUIC
  (`TestQUICECHSupport` fails if that stops being true, then revisit this paragraph).
- Observability: the page shows counts of TLS requests that arrived through ECH vs. not; `r.TLS.ECHAccepted` is available to code.
- Not validated here: real browsers (Firefox/Chrome) against a public DNS record; the Go client in the tests is the interop peer.

### Lua script handlers (fork #88 / upstream #367)

Code: `src/mod/luascript` (sandbox, helper libraries, pattern matcher), `src/mod/dynamicproxy/script_handler.go` (per-rule `Script`
config, request handling, admin test run), `src/scriptapi.go`, `src/web/snippet/scriptEditor.html` (button "Lua Script" in the
endpoint editor). Off unless a rule has `Script.Enabled`.

Modes: `handler` (the script produces the response, no upstream is contacted) and `hook` (runs before the upstream, may answer through
`respond()` / `redirect()` / a changed `response` table or let the request continue after `request_header_set/del`). It runs in the shared
endpoint chain after authentication and static responses, before plugin routing and the upstream. `PathPrefix` limits it to a subtree.

API available to scripts: `request.*` (method, path, query, args, headers (lower case), host, client_ip, rule, request_id, scheme, body in
handler mode, 64 KiB max), `response.status/headers/body`, `respond`, `redirect`, `request_header_set/del`, `log`, `json`, `base64`, `hex`,
`url`, `crypto.sha256/hmac_sha256/equals`, `time.now/format`, `kv.get/set/incr/delete` (in memory, per rule, 1000 keys / 1 MiB, optional TTL,
survives edits of the script, cleared on restart).

**Security review (this is admin-authored code execution in the proxy process).** Threat model: a rule editor (admin) can already run the
proxy as any upstream they like, but the script must not become a shell, a file reader, a port scanner or an availability weapon.

| Risk | Control | Test |
|---|---|---|
| Files, processes, network, env | Only `base`, `table`, `string`, `math` are opened. `os`, `io`, `package`, `debug`, `coroutine`, `require`, `module`, `dofile`, `loadfile`, `load`, `loadstring`, `getfenv`, `setfenv`, `collectgarbage`, `print`, `newproxy` are nil. No Go function that touches the OS is exposed. Precompiled chunks are refused. | `TestNoDangerousGlobals`, `TestEscapeAttempts` (os.execute, io.open, io.popen, require, load/loadstring, dofile, debug, package.loaded, getfenv, string.dump, metatable tricks) |
| Infinite loops | Context deadline (default 100 ms, max 2 s) checked by the VM on every instruction (this is the instruction limit: it is time based, gopher-lua has no instruction counter). Client disconnect also cancels. A run that ignores the deadline for 750 ms more is abandoned, counted, and scripts are refused if more than 16 such runs exist (should stay 0). | `TestInfiniteLoopTimesOut` (while, tail call, pcall loop, table fill, sort comparator, gsub loop), `TestCancelledParent` |
| Deep recursion / stack abuse | Call stack 120 frames, Lua registry capped at 40960 slots: recursion and `unpack` of huge ranges fail with a stack overflow error. | `TestDeepRecursion` |
| Memory bombs | `string.rep` / `string.format` capped at 1 MiB / width 99; `gsub` result 1 MiB; JSON in/out 256 KiB; kv 1 MiB; response body cap (default 256 KiB, max 1 MiB); source 64 KiB. Everything else (concat doubling, table growth) is stopped by the **live heap watchdog**: sampled every 2 ms, cancels the run when the process live heap grew more than 64 MiB since the run started. The sample is process wide, so a heavily loaded proxy can occasionally make an innocent run fail with "memory ceiling" (500); a single concat step can overshoot the ceiling by about 2x before the next sample. | `TestMemoryBombs` |
| Pattern DoS (`a*a*a*b`) | gopher-lua's matcher is replaced by a step budgeted port of the Lua 5.1 matcher (400k steps, recursion 200, subject 256 KiB, pattern 256 bytes): `string.find/match/gmatch/gsub`. | `TestPatternCatastrophe`, `TestPatterns` |
| Cross-request leaks | A fresh Lua state per run (no shared globals), a per-script semaphore (default 4 parallel runs, max 32; extra requests wait for the remaining time budget, then 503). Panics are recovered. | `TestConcurrentRunsAreIsolated`, `TestConcurrencyPoolBusy` |
| Header / response injection | Header names and values validated (no CR/LF/NUL), hop-by-hop and `Content-Length` refused, status 200-599, redirect 3xx only. | `TestResponseValidation`, `TestRespondStopsAndRedirect` |
| Information disclosure | Failures answer `500 - Script error (request id ...)`; details (line number, message) go to the log only. The source is only served by `/api/proxy/script/get`, which viewer accounts cannot call. | `TestScriptErrorsAreOpaque` |

Residual risk: a native Go function that ignores the context could in theory hold a request goroutine (every exposed native is bounded as
above). The heap watchdog is a ceiling, not an accountant. Treat script editing like shell access to the proxy host's CPU and memory,
not like a safe multi-tenant sandbox: do not give untrusted users the admin role.

### Sablier compatibility (fork #120 / upstream #564)

Code: `src/mod/sablier` (config validation, HTTP client, gate with ready cache), `src/mod/dynamicproxy/sablier_gate.go` (request stage),
`src/sablierapi.go`, `src/web/snippet/sablierEditor.html` (button "Sablier (scale to zero)" in the endpoint editor). Off unless a rule has
`Sablier.Enabled`. No plugin is needed: this is Sablier's reverse proxy plugin contract implemented natively.

- Per rule: Sablier URL, strategy `dynamic` (`/api/strategies/dynamic`, waiting page, `display_name`, `theme`, `refresh_frequency`,
  `show_details`) or `blocking` (`/api/strategies/blocking`, `timeout`), `session_duration`, `names` (repeated parameter) or `group`.
- `X-Sablier-Session-Status: ready` -> the request is proxied. Any other value -> Sablier's body, status and Content-Type are served with
  `Cache-Control: no-store`. A response without that header (wrong URL, an auth portal in between, a 500) is an *error*, not a waiting page.
- Position in the chain: after authentication and the Lua stage, right before plugin routing / the upstream. A Lua *handler* replaces the upstream, so
  it never wakes the workload; public static responses and `/.zoraxy/health` are answered earlier; `BypassPaths` skips the gate per prefix.
- Cache: a `ready` answer is trusted for 3 s (0-60 s configurable, -1 = ask every time); "not ready" is never cached; concurrent callers share one call
  to Sablier (no thundering herd) and the shared call has its own deadline (5 s, blocking: timeout + 5 s) so one impatient client cannot cancel it.
- Fail mode: Sablier unreachable / erroring -> `503` + `Retry-After` (fail closed, default) or proxy anyway (`FailOpen`).
- WebSocket upgrades and clients that do not accept HTML (JSON APIs) get a plain `503` + `Retry-After` instead of the HTML waiting page; the
  request has still woken the workload. A ready workload passes upgrades through.
- SSRF: the URL must be http(s) without credentials/query; link-local (169.254.0.0/16 incl. 169.254.169.254, fe80::/10), `0.0.0.0/8`, multicast
  and the Alibaba / Oracle / AWS-IPv6 metadata addresses are refused at validation *and* at dial time (after DNS resolution), redirects are not
  followed, no environment proxy is used. Loopback and private addresses are allowed (Sablier normally runs next to the proxy). `AllowMetadataAddress` opts out.
- Not validated: against a real Sablier server and real Docker / Swarm / Kubernetes providers. The fake Sablier in the tests follows the documented API
  (`X-Sablier-Session-Status`, `/api/strategies/{dynamic,blocking}`), so compare the "Check connection" button's URL with your Sablier version's docs.
