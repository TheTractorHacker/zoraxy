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
wildcard/alias) → **access rules** (IP/country black/whitelist) → exploit detector → rate limit →
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
| Load balancing | `mod/dynamicproxy/loadbalance` | Selection algorithms, active/passive health checks, retries, per-upstream limits and draining. See [Load balancing](#load-balancing-and-health-checks) |
| TLS | `mod/tlscert` | SNI lookup over `conf/certs/*.pem/.key`; fallback cert; per-host behaviour. Loads key pairs from disk per handshake |
| ACME | `mod/acme` | lego v5, HTTP-01 (special route) and DNS-01 providers, auto-renew (`conf/acme_conf.json`) |
| Admin auth | `mod/auth` | Single admin, gorilla cookie sessions, CSRF, plugin API keys |
| Per-route auth | `mod/auth/sso/{forward,oauth2,zorxauth}` | Forward auth (Authelia/Authentik style), OAuth2, built-in ZorxAuth SSO with TOTP and passkeys |
| Access control | `mod/access`, `mod/geodb` | IP/CIDR/country lists in `conf/access/*.json`, trusted proxies for client-IP headers |
| Bot defence | `dynamicproxy/exploits`, `dynamicproxy/captcha` | Regex exploit + AI-bot UA blocker; Turnstile / reCAPTCHA with in-memory sessions; templates overridable in `<webroot>/templates/` |
| Streams | `mod/streamproxy` | TCP/UDP forwarding |
| Storage | `mod/database` | BoltDB by default (`-db`), LevelDB optional, file DB on mipsle/riscv64 |
| Plugins | `mod/plugins` | Separate processes launched with `-configure`; static path capture or dynamic "sniff" capture on tagged endpoints; UI proxied at `/plugin.ui/<id>/`; events via `mod/eventsystem` |

### Load balancing and health checks

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

### Plugins in one paragraph
A plugin is a folder in `./plugins` containing an executable of the same name. Zoraxy runs it with
`-introspect` to read its manifest (`src/mod/plugins/zoraxy_plugin/zoraxy_plugin.go`), then starts it with
`-configure=<json>` on a random localhost port. Requests on endpoints whose tags match a plugin group are
offered to the plugin by path prefix (static) or by a per-request JSON "sniff" call (dynamic). Plugins run
after access/CAPTCHA/auth and can only take over a whole request, not modify it and pass it on.
See `example/plugins/` and `docs/plugins/`.

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
