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
- Plugins keep using plain HTTP: when TLS is on, Zoraxy opens an extra loopback-only (`127.0.0.1`, random port) HTTP listener and passes that port as `ZoraxyPort` to plugins.
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
`WAF-HOOK` in `Server.go` (one for host endpoints, one for the default-site root endpoint). The non-TLS path
(`handleNonTLSRequest`) does not have the call yet: add it to the shared pre-proxy chain when that lands.

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
