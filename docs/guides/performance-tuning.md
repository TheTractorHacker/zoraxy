# High CPU under load: measure first, then tune

Answers upstream #770 (`wrk -c1024 -t100` pushes all cores to 80%). A Go reverse proxy that terminates TLS
legitimately uses every core when 1024 clients hammer it, so "80% CPU" alone is not a bug. What matters is
**requests per second per core** and **where the time goes**.

## 1. Find where the CPU goes (new in this fork)

The Go profiler is now reachable below `/api/info/pprof/` (before, only an index page existed and every link on it
returned 404). It needs the same admin login as the rest of the management API and is refused for *viewer* accounts.

```bash
# 30 second CPU profile while the load test runs (copy your session cookie from the browser, or use a lab instance started with -noauth)
curl -s -b 'session-cookie-name=VALUE' -o cpu.pprof 'http://127.0.0.1:8000/api/info/pprof/profile?seconds=30'
go tool pprof -top -cum -nodecount=40 ./zoraxy cpu.pprof      # text summary
go tool pprof -http=:8080 ./zoraxy cpu.pprof                    # flame graph in the browser
# memory / goroutines
curl -s -b '...' -o heap.pprof 'http://127.0.0.1:8000/api/info/pprof/heap'
curl -s -b '...' 'http://127.0.0.1:8000/api/info/pprof/goroutine?debug=1' | head
```

(`profile`, `heap`, `goroutine`, `allocs`, `block`, `mutex`, `threadcreate`, `trace`, `cmdline`, `symbol`.) Read
the biggest `cum` lines that belong to `imuslab.com/zoraxy/...`; everything under `crypto/tls` is handshake/encryption cost, under
`net/http` + `syscall` is plain I/O. Attach the profile when you report a performance problem.

Reproduction note: a quick run on a 4 core VM (64 keep-alive TLS connections, trivial backend, no features enabled) gave about
1,300 requests/second with no Zoraxy specific hotspot in the profile (time in syscalls, dialing the backend and GC).
That is not a benchmark, it only shows the endpoint works and how to look.

## 2. Usual causes, cheapest fix first

| Cause | What to do |
|---|---|
| New TLS connection per request (`wrk` without keep-alive, clients that reconnect) | each handshake is real CPU. Test with keep-alive; prefer an ECDSA certificate (Certificates > ACME *key type*, upstream #1123) over RSA 4096; leave "Minimum TLS version"/cipher profile on the defaults |
| Upstream that closes the connection after every response | Zoraxy then dials per request. Fix the upstream (enable keep-alive); the rule's upstream option **Disable connection reuse** must stay *off* |
| Per-request work you do not need | per rule: **Disable Statistic Collection** and **Disable Requests Logging** (HTTP Proxy > edit rule); turn off per-site log files (per-site log files are off by default); lower detail in the CAPTCHA/WAF only where needed |
| WAF / exploit blocking / bot rules inspect every request | each costs CPU in proportion to request count. The WAF skips bodies above its size limit and gRPC/WebSocket. Enable it on the rules that face the internet, use *Trusted paths* for health checks and static assets |
| GeoIP lookups (country rules) | keep the default `-fastgeoip=true` (precomputed, more RAM, much less CPU). Only turn it off on very small devices |
| Statistics maps growing | `-stats_max_entries` (default 20000 per dimension, 0 = unbounded) caps memory/CPU of the statistics collector |
| HTTP/2 | for many parallel streams adjust `-h2_max_concurrent_streams`, `-h2_conn_buffer`, `-h2_stream_buffer`; `-disablehttp2` serves HTTP/1.1 only (usually not faster) |
| Container CPU limits | Go 1.25+ sets `GOMAXPROCS` from the container's CPU limit automatically; override with the `GOMAXPROCS` environment variable (e.g. `GOMAXPROCS=2`) to leave cores to other services, or raise the limit |
| Memory pressure / GC | set `GOMEMLIMIT` (e.g. `GOMEMLIMIT=1GiB`) so the garbage collector works before the OOM killer does |
| Timeouts | `-readheadertimeout`, `-writetimeout`, `-idletimeout` bound slow clients; very short idle timeouts increase handshakes |

## 3. A fair load test

* Use keep-alive and a realistic number of connections (`wrk -t4 -c256 -d30s https://host/`), run it **from another
  machine**; the generator itself needs about as much CPU as the proxy.
* Compare three targets: the backend directly, a rule with all optional features off, your real rule. The difference
  between the first two is the proxy's floor, between the last two the cost of your features.
* Watch `zoraxy_*` Prometheus metrics (`-metrics`) for in-flight requests and upstream latency during the test.
