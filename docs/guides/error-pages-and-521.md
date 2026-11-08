# Error pages and "521 Web server is down"

Answers upstream #1095 (custom 521 page) and #1102 (Transmission web UI returns 521). Verified on a throw-away instance.

## What 521 means in Zoraxy

Zoraxy sends **521** when it could not talk to the upstream at all (connection refused, timeout, TLS handshake
failure, endpoint disabled); **404 "host error"** when the upstream name does not resolve; **503** when every
upstream is at its concurrency limit. If the upstream itself answers with an error (500, 502...) that status is
passed through.

### Finding out why (new in this fork)

The Logs page only shows `521`. Since this version the **reason is written to the system log** (once per upstream and
reason every 30 seconds so a dead upstream cannot flood it), for example:

```
[proxy] [system:error] Upstream 127.0.0.1:19999 failed for request to down.test: dial tcp 127.0.0.1:19999: connect: connection refused
[proxy] [system:error] Upstream 127.0.0.1:19001 failed for request to tlsrp.test: net/http: TLS handshake timeout
[proxy] [system:error] Upstream no-such-host.invalid:9091 failed for request to nxd.test: dial tcp: lookup no-such-host.invalid on 127.0.0.53:53: no such host
```

Most common causes (#1102 is one of the first two):

| Log says | Fix |
|---|---|
| `TLS handshake timeout`, `first record does not look like a TLS handshake` | the rule has **Require TLS** ticked but the upstream speaks plain HTTP (Transmission on :9091 does). Untick it, or use `http://` |
| `connection refused` / `no route to host` / `i/o timeout` | wrong IP or port, the service listens only on 127.0.0.1 of another machine, a firewall between *Zoraxy's* address and the upstream (test with `curl -v http://upstream:9091/` **from the Zoraxy host**, not from your PC) |
| `lookup name ...: no such host` (gives 404, not 521) | the DNS name works on your PC but not on the Zoraxy host/container; use the IP or fix its resolver |
| `x509: certificate signed by unknown authority` / `doesn't contain any IP SANs` | upstream TLS with a self-signed or IP-only certificate: tick **Skip Verification** for that upstream |

Transmission also has an RPC host whitelist: if requests reach it but are refused you see 4xx from Transmission, not 521.
Its redirects to `/transmission/web/` are followed by the browser and are not a cause of 521.

## Custom error pages

Two mechanisms, use whichever fits:

1. **Per rule or global, by status code (recommended, new)**: Ingress settings > *Default error pages* (all rules set
   to "use the global default") or HTTP Proxy > rule > *Error Pages, Static Responses, CORS & Bandwidth* >
   Error pages. Pick the status codes (`521, 502, 503, 504`...), paste an HTML template with `{{.Status}}`
   `{{.StatusText}}` `{{.RequestID}}` `{{.Host}}` `{{.Path}}` `{{.RuleName}}` (escaped; 64 KiB max), *Preview*, save.
   This also replaces upstream error responses, but never event streams, gRPC or WebSocket upgrades. Verified:
   template `<h1>{{.Status}} for {{.Host}}</h1>` served for a 521 shows the requested host (a bug where the host was
   empty for Zoraxy generated errors is fixed in this version).
2. **Template files** (apply to *Zoraxy generated* errors only, all rules): put files in the `templates` folder under the
   web root (`-webroot`, default `./www`, so `./www/templates/`):
   * `rperror.html` -> 521 (upstream unreachable) *(a file called `521.html` is not read)*
   * `hosterror.html` -> 404 DNS / unknown upstream host
   * `forbidden.html` -> 403 of the header rules, bot rules and peer (networking) checks

   The file is read on every request, no restart. *Verified* with `rperror.html`. The built-in page is the fallback if the file is missing.
