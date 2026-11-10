# Rate limits: units, keys, path limits, monitoring, WebSockets and presets

What rate limiting is for, and what it is not:

* **Rate limiting protects availability.** It keeps one client from flooding a site or hammering an endpoint.
* **It is not account protection.** A per-IP limit does not stop an attacker who uses many addresses, and it does not lock an
  account. Login pages still need lockout, multi-factor sign-in and a password policy *in the application*. Admin interfaces are
  better behind a VPN or an IP restriction (access rule) than behind a rate limit.
* **The numbers are starting points.** They come from a general guidance table, not from your traffic. Watch the 429 count in the
  statistics (and the `zoraxy_ratelimit_rejected_total` metric) and adjust.
* **Everything here is off until you turn it on.** No default changed; a configuration saved by an older build loads and behaves exactly as before.

## Guidance table and what we build for it

| Service | Starting point | Recommendation | Where it is in Zoraxy |
|---|---|---|---|
| Public website | 120 req/min per IP | Enable | preset **Public website**: site limit 120 per minute |
| Login page | 5 to 10 attempts/min per IP | Strict, plus account protection in the app | preset **Login page**: path limits 5 per minute (burst 5) on `/login`, `/signin`, `/wp-login.php`, `/auth` |
| Admin dashboard | 60 req/min per IP | Prefer VPN or IP restriction | preset **Admin dashboard**: 60 per minute; flagged "needs a login" |
| Odoo ERP | 300 req/min per IP | Allow bursts, tune by endpoint | preset **Odoo ERP**: 300 per minute, burst 600, `/web/login` 10 per minute (burst 5), WebSocket cap |
| REST API | 120 req/min per client | Prefer API-key limits | preset **REST API per key**: 120 per minute keyed by the `Authorization` header |
| Webhook receiver | 120 req/min per source | Authenticate, allow bursts | preset **Webhook receiver**: 120 per minute, burst 240 |
| File upload | 10 to 20 req/min per user | Separate from general limits | preset **File upload**: path limits 15 per minute (burst 5), POST/PUT, on `/upload`, `/uploads`, `/api/upload` |
| WebSocket app | connection limits | Avoid normal HTTP throttling | preset **WebSocket app limits**: 20 connections per IP, handshakes not counted |
| Monitoring endpoints | depends on polling | Exempt trusted monitoring | preset **Monitoring-friendly**: 300 per minute, plus the **trusted monitoring** exemption |

"Per user" and "per client" are approximated: Zoraxy sees addresses and request headers, not accounts. Count per `Authorization`
header (or another header) when clients carry an API key or token.

## 1. Units

`RateLimit` stays "a number of requests". The new `RateUnit` says what it is per: empty (every older config) = **per second**,
`"minute"` = **per minute**. The number is stored exactly as typed; nothing is converted or rounded. The token bucket is unchanged:
it refills `RateLimit / 60` tokens per second for a per-minute limit and holds at most `burst` tokens; a burst of 0 means "as many as
the number" (120 per minute allows 120 at once and then 2 per second; 5 per minute allows 5, then one every 12 seconds).

* UI: the Rate limit card of the site editor has "The limit is a number of requests per: second / minute".
* API: `POST /api/proxy/edit` takes `rateunit` (`second` or `minute`) next to `rate`, `ratenum`, `rateburst`; `POST /api/proxy/add` too.
  **A client that sends `ratenum` without `rateunit` means per second** (it predates units), so an old script can never have its number read as per minute.
  Without both, the stored unit stays. The bulk action `set_ratelimit` takes `RateUnit` and also defaults to per second.
* A per-minute 429 carries `Retry-After` (seconds until one token is back); per-second limits answer as before.
* A build older than this one reads a per-minute limit as per second (looser). Rolling back after using minutes is not supported.

## 2. Path limits

Per-site path limits already exist as the `rate_limit` action of **Path rules** (`ProxyEndpoint.PathRules`, one list per site, matched
on a normalised path, optional method and scope). That is the least invasive place, so this feature extends it instead of adding a
second list or touching the rules engine (`mod/ruleset`), whose `rate_limit` action stays per second and is not affected by the
options below:

* `PathRule.RateUnit` (`""`/`minute`), `PathRule.KeyBy` / `KeyHeader`: the same unit and keying as the site limit.
* The path rule editor shows the unit; the **Rate limit** card of the site editor has an editor for exactly these rules (add, remove).
* Rules run in order and the **first match decides**. Rate-limit rules therefore end the evaluation of the later rules for that
  path. Limits added by a preset or by the new editor are appended at the **end**, so they can never shadow a deny rule you already have.

## 3. Keying

`KeyBy` is `""`/`ip` (default, per client address), `authorization` (the `Authorization` header) or `header` plus `KeyHeader`.

* The value is hashed (SHA-256) in memory only. It is never logged, never stored, never in a metric label; the log shows only the numbers and "keyed by authorization".
* **Safe fallback:** a request without the header (or with one over 8 KB) is counted per IP.
* **Guard:** clients can invent keys, so a keyed limit also enforces a per-IP guard of 10 times the limit and burst; rotating keys
  cannot give unlimited throughput. Honest limit: a client who shares one address with many legitimate keys can reach 10 times a single key's budget.
* Keys that are not authenticated by the application are only a bookkeeping convenience; the application must verify them.

## 4. Trusted monitoring exemption

`RateOptions.ExemptCIDRs` (addresses or CIDRs) and an optional `ExemptHeader` + secret `ExemptHeaderValue` (at least 8 characters,
compared in constant time). A matching request skips the site limit **and** the path limits of the rule and is not counted. The
address is the trusted client address: a forwarded header from a peer that is not a trusted proxy does not exempt anyone. The
secret is stored in the rule's configuration like other secrets, shown only to administrators; treat it as a password and use HTTPS.
It does not exempt from the WAF, access rules, authentication or the rules engine.

## 5. WebSockets (how it works)

A WebSocket starts as an ordinary HTTP `GET` with `Upgrade: websocket` (the handshake), runs through the same chain as every request,
and then the connection is taken over; the messages inside it are not HTTP requests and **were never counted**. So today
**each handshake counts as one request** against the site limit and against matching path limits, and nothing limited how many
connections one client could hold open. Both are now explicit and opt-in (`RateOptions`):

* `WSMaxConnsPerIP` (0 = no cap): maximum concurrent WebSocket connections per client address and rule; further handshakes get 429 (`Retry-After: 5`). Counted until the connection ends (virtual directory routes too).
* `WSExempt`: handshakes are not counted against the request limit or the path limits. It can only be switched on together with a connection cap, so exempt handshakes are never unlimited. Not applied when the rule blocks WebSockets.
* Trusted monitoring addresses are never capped.

## 6. Presets

The nine presets are ordinary app presets (`ruletemplate_presets.json`, `NoDowngrade`), shown in "Apply preset" with a before and
after comparison and in the New proxy rule dialog. Templates gained optional fields: `RateUnit`, `RateKeyBy`/`RateKeyHeader`,
`PathRateLimits`, `WSMaxConnsPerIP`, `WSExemptFromRateLimit`. With `NoDowngrade`:

* the site limit is only applied when there is none or a looser one, compared in requests per second (60 per minute equals 1 per second);
* a key is only set together with the limit it belongs to, and never over a key you chose;
* a WebSocket cap only gets lower; exemptions are never touched;
* a path limit for a path that already has a limit keeps the stricter one (and its scope); new ones go to the end of the list;
* applying a preset twice changes nothing.

The notes of the presets say what the table recommends ("prefer VPN or IP restriction", "authenticate webhooks", "account-level
protection is needed in the app"). The preset **Monitoring-friendly** cannot know your monitoring system: add its addresses under the
trusted monitoring exemption.

## 7. Security overview

A new informational check, **Login and admin paths have a rate limit** (category Abuse), lists proxy rules that have no rate limit
that could cover login or admin paths (neither a site limit nor a path limit on a path that looks like `login`, `admin`, `auth`, ...).
It is a heuristic by path name, has no fix and **never changes the score** (status `info`, like "not applicable" it is left out of
the calculation). Nothing is applied automatically.

## 8. Verified, and not

Verified: Go unit tests for the limiter math (per minute, burst, refill cap, equivalence with per second), unit conversion and
storage, keying (hashing, fallback, key rotation guard), exemption (CIDR, header, spoofed forwarded address), WebSocket accounting
(handshake counted by default, exempt, connection cap, release), path limits, templates and presets (no downgrade, idempotence,
ordering, no mutation of a live rule), old configs, bulk, the posture check; the browser smoke `ratelimit_smoke.py`
(`--ratelimit-only`) for the editor in light, dark and at 390 px and a real per-minute limit against a throw-away upstream.

Not verified: behaviour behind a real CDN, long-running real WebSocket clients holding connections, per-minute limits under heavy
concurrent load, the presets against the real applications (the numbers come from the guidance table), screen readers.
