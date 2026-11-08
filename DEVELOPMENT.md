# Developing this Zoraxy fork

This repository is **TheTractorHacker/zoraxy**, a fork of [tobychui/zoraxy](https://github.com/tobychui/zoraxy).
Zoraxy is © tobychui and contributors and licensed under the **GNU AGPL v3** (see [LICENSE](LICENSE)).
This fork stays under AGPL-3.0. Planned work is in [ROADMAP.md](ROADMAP.md).

## License obligations (read before shipping anything)

- Keep `LICENSE`, the header in `src/main.go`, and every bundled sub-license:
  `src/mod/dynamicproxy/dpcore/LICENSE`, `src/mod/reverseproxy/LICENSE`,
  `src/mod/websocketproxy/LICENSE.md`, `src/mod/forwardproxy/cproxy/LICENSE.md`,
  `src/mod/sshprox/gotty/LICENSE`. GeoIP data is CC0 (`src/mod/geodb/README.txt`).
- **AGPL §13:** if you run a modified build where other people can reach it over a network,
  you must offer them the corresponding source. Publishing each release's tag on this public
  repository satisfies this; the release notes link the source.
- Code taken from other projects must have an AGPL-3.0-compatible license (MIT, BSD,
  Apache-2.0, GPL-3.0, LGPL-3.0, MPL-2.0). Keep its copyright notice and license file next to it
  and mention it in the commit message. Ideas and designs from any project are fine to reuse.

## Repository layout

| Path | What it is |
|---|---|
| `src/` | Go module `imuslab.com/zoraxy` (everything outside `mod/` is `package main`) |
| `src/web/` | Admin UI: plain HTML + jQuery + Semantic UI, embedded with `go:embed`, no build step |
| `src/mod/` | Feature packages (proxy core, TLS, ACME, auth, access control, plugins, ...) |
| `example/plugins/` | Example plugins and the plugin SDK copy script (`build_all.sh`) |
| `docker/` | Dockerfile, entrypoint, compose files |
| `docs/` | Plugin documentation site generator |
| `.github/upstream-sync/` | **Fork only:** issue mirror script and local code-sync script |
| `.github/workflows/fork-*.yml` | **Fork only:** upstream issue and code sync workflows |

## Build, run, test

Requirements: Go (version in `src/go.mod`, currently 1.26.x; newer works). No CGO, no Node.

```bash
cd src
go build -o zoraxy .          # build for this machine
./zoraxy -port=:8000           # admin UI on :8000; proxy listens on :443/:80 by default
./zoraxy -dev                  # serve web/ from disk for live UI editing + verbose logs
go test ./...                  # all tests (what CI runs)
./run_tests.sh                 # same, with a readable report (PKGS=..., VERBOSE=1)
go vet ./... && staticcheck ./...
make binary                    # cross-compile every platform into src/dist/
```

Runtime data is created in the working directory: `sys.db` (BoltDB key-value store),
`conf/` (proxy, cert, access and redirect configs as JSON), `log/`, `tmp/`, `www/`, `plugins/`, `sys.uuid`.
Use a scratch directory for development so you never touch a production `conf/`.

Release builds use upstream's flags: `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"` (`GOARM=6` for arm),
asset names `zoraxy_<os>_<arch>`, tags named `v<upstream-version>-<fix>.<n>` so they never collide with upstream tags.

## Architecture

### Startup (`src/main.go`, `src/start.go`, `src/def.go`)
`main()` parses flags (all defined in `src/def.go`), runs config migrations (`mod/update`), then
`startupSequence()` builds the global singletons in a fixed order (logger → database → auth → TLS manager →
redirects → GeoIP → load balancer → access control → SSO routers → stats → web server → ACME → plugins).
API handlers are registered in `src/api.go` through `auth.NewManagedHTTPRouter`, which wraps each handler in
the admin auth check; the CSRF middleware (gorilla/csrf) wraps the whole admin mux. `ReverseProxyInit()`
(`src/reverseproxy.go`) creates the proxy router, loads `conf/proxy/*.config` and starts the listeners.
The admin UI is then served with plain `http.ListenAndServe(-port)`. Plugins talk to Zoraxy on that same port
under `/plugin/` with per-plugin API keys.

### Request flow (`src/mod/dynamicproxy/Server.go`)
For each request on the TLS/main listener, `ProxyHandler.ServeHTTP` runs, in order:
special routing rules (ACME http-01) → redirect rules → host match (`proxyRequestHandler.go`, exact then
wildcard/alias) → **access rules** (IP/country black/whitelist) → **WAF** (`waf/`) → exploit detector → rate limit →
**CAPTCHA** (`captcha/`) → **auth provider** (basic, forward auth, OAuth2, ZorxAuth) → **plugins** →
virtual directory or host proxying. `hostRequest` picks an upstream (`loadbalance/`), applies header rules
(`rewrite/`, `permissionpolicy/`) and proxies through `dpcore` (the reverse proxy engine, `dpcore/dpcore.go`).
Unmatched hosts fall through to the default site (`handleRootRouting`).

Known gap: `handleNonTLSRequest` (port 80 bypass and per-endpoint secondary ports) skips redirects, exploit
detection and plugins. Fixing that means pulling the pre-proxy chain into one shared function.

### Subsystems
| Area | Where | Notes |
|---|---|---|
| Proxy core | `mod/dynamicproxy`, `dpcore/` | Endpoint config type `ProxyEndpoint` in `typedef.go`; saved by `src/config.go` |
| Load balancing | `mod/dynamicproxy/loadbalance` | Weighted random + optional sticky cookie; offline filtering from `mod/uptime` (5 min). No round robin / least-conn / active checks yet |
| TLS | `mod/tlscert` | SNI lookup over `conf/certs/*.pem/.key`; fallback cert; per-host behaviour. Loads key pairs from disk per handshake |
| ACME | `mod/acme` | lego v5, HTTP-01 (special route) and DNS-01 providers, auto-renew (`conf/acme_conf.json`) |
| Admin auth | `mod/auth` | Single admin, gorilla cookie sessions, CSRF, plugin API keys |
| Per-route auth | `mod/auth/sso/{forward,oauth2,zorxauth}` | Forward auth (Authelia/Authentik style), OAuth2, built-in ZorxAuth SSO with TOTP and passkeys |
| Access control | `mod/access`, `mod/geodb` | IP/CIDR/country lists in `conf/access/*.json`, trusted proxies for client-IP headers |
| WAF | `mod/dynamicproxy/waf` | Coraza + OWASP CRS, per endpoint, off by default. See [Web Application Firewall](#web-application-firewall-waf) |
| Bot defence | `dynamicproxy/exploits`, `dynamicproxy/captcha` | Regex exploit + AI-bot UA blocker; Turnstile / reCAPTCHA with in-memory sessions; templates overridable in `<webroot>/templates/` |
| Streams | `mod/streamproxy` | TCP/UDP forwarding |
| Storage | `mod/database` | BoltDB by default (`-db`), LevelDB optional, file DB on mipsle/riscv64 |
| Plugins | `mod/plugins` | Separate processes launched with `-configure`; static path capture or dynamic "sniff" capture on tagged endpoints; UI proxied at `/plugin.ui/<id>/`; events via `mod/eventsystem` |

### Plugins in one paragraph
A plugin is a folder in `./plugins` containing an executable of the same name. Zoraxy runs it with
`-introspect` to read its manifest (`src/mod/plugins/zoraxy_plugin/zoraxy_plugin.go`), then starts it with
`-configure=<json>` on a random localhost port. Requests on endpoints whose tags match a plugin group are
offered to the plugin by path prefix (static) or by a per-request JSON "sniff" call (dynamic). Plugins run
after access/CAPTCHA/auth and can only take over a whole request, not modify it and pass it on.
See `example/plugins/` and `docs/plugins/`.

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

## Tests

`go test ./...` covers most `mod/` packages (proxy core incl. gRPC streaming, captcha gating, rate limit,
auth providers, access rules, load balance, ACME DNS, databases, stream proxy, uptime). Not covered:
the API handlers in `src/*.go`, end-to-end `ServeHTTP`, non-TLS handling, exploit detection, TLS manager,
admin auth, OAuth2, migrations, the web UI. A few tests need network (they skip or fetch from GitHub).
**Every bug fix in this fork should come with a test that fails without the fix.**

## Working on the fork

### Remotes and branches
```bash
git remote -v
# origin    https://github.com/TheTractorHacker/zoraxy.git
# upstream  https://github.com/tobychui/zoraxy.git (push URL set to DISABLED)
```
- `main` = upstream `main` + fork tooling (`DEVELOPMENT.md`, `ROADMAP.md`, `.github/upstream-sync`, `fork-*` workflows).
- Feature and fix branches: `fix/<topic>`, `feat/<topic>`, opened as PRs into `main`.
- Never force-push shared branches. Keep upstream-originated code changes small and isolated so upstream
  merges stay easy, and consider offering generic fixes upstream.

### Pulling upstream code
Run **Actions → "Fork: upstream code sync"** (manual). It pushes `upstream-sync/<sha>` pointing at the upstream
commit, test-merges it into `main`, runs build/vet/test and opens a PR with results or the list of conflicts.
It never merges, force-pushes or deploys. If upstream changed workflow files, GitHub blocks the push from the
built-in token: run `.github/upstream-sync/code_sync.sh` locally instead (needs `gh` with `workflow` scope).
The weekly schedule is commented out in the workflow until you enable it.

### Mirrored upstream issues
Upstream issues are mirrored into this repo's Issues with the `upstream` label by
`.github/upstream-sync/issue_sync.py`. Each mirrored issue has a managed block between
`<!-- upstream-sync:begin/end -->` markers plus a hidden meta line; **write your own notes below the block or in
comments** and the sync will never touch them. If you edit inside the block, the sync reports a conflict and
leaves it alone. Closing or relabelling a mirrored issue on the fork is respected: upstream state changes are only
applied when the fork still has the value the sync last wrote. Original authors are credited as links and
@mentions are neutralised so nobody upstream gets pinged; links go through `redirect.github.com` so no
back-references appear on upstream issues.

```bash
python3 .github/upstream-sync/issue_sync.py import --target TheTractorHacker/zoraxy --dry-run   # preview
python3 .github/upstream-sync/issue_sync.py import --target TheTractorHacker/zoraxy --yes       # resume/complete
python3 .github/upstream-sync/issue_sync.py sync   --target TheTractorHacker/zoraxy             # incremental
```
In Actions: **"Fork: upstream issue sync"** (manual, defaults to dry run; scheduled run commented out).

### Releasing a build
1. Merge the change into `main` (or release from a fix branch for a hotfix).
2. Tag `v<upstream-version>-<topic>.<n>` and push the tag.
3. Build the Linux targets with the release flags above, write `SHA256SUMS`, and create the GitHub release
   with the binaries. State what changed and link the source tag (AGPL).
4. Deploy by hand: stop the service, back up the old binary, install, start, test. Nothing deploys automatically.

Upstream's `docker.yml` pushes images on every release and defaults to upstream's Docker Hub account. Keep it
disabled on this fork, or set `DOCKER_ACCOUNT` and your own secrets first.
