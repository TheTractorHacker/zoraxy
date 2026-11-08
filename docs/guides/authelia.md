# Authelia with Zoraxy (forward auth)

Answers upstream #749 (404 on the Authelia login page), #793 (forward-auth configuration) and the Authelia part of
#514. The Zoraxy side is read from the code (`mod/auth/sso/forward`, `web/components/sso.html`); I did **not** run a
real Authelia, so the Authelia-side settings come from Authelia's documentation and from the maintainers'
comments in the upstream issues. For Authentik see [../authentik.md](../authentik.md).

## Step 1: make `auth.example.com` reachable through Zoraxy (#749)

A plain proxy rule, **no authentication on it**:

* Rule: `auth.example.com` -> `http://authelia:9091` (container name / LAN address and port of Authelia, plain HTTP).
* A **"404 page not found"** answer in the browser means no rule matched the host name (typo, rule disabled, DNS
  pointing at another server, or you used the container IP in the address bar). It is not an Authelia error.
  Check the Zoraxy log line and the *Matching Domain* of the rule; open `https://auth.example.com/api/health`
  (Authelia answers `{"status":"OK"}`).
* Authelia's own `server.endpoints.authz.forward-auth.implementation: ForwardAuth` (default) is the right one.
* Authelia must trust the proxy for client IPs (see below).

## Step 2: Zoraxy forward auth settings (#793)

SSO > **Forward Auth**. Type the base URL in *Authorization server base URL* and press the **Authelia** preset, which fills
(from `sso.html`):

| Field | Value |
|---|---|
| Address | `<base>/api/authz/forward-auth` |
| Response Headers | `Remote-User,Remote-Groups,Remote-Name,Remote-Email` |
| Use X-Original-* Headers | off |
| Send the protected host as Host header | off (leave off for Authelia) |
| Outpost URL / When not signed in | empty (Authentik only) |

Then **Apply Change**.

**The one setting that goes wrong (reported by the Authelia maintainer in #793):** the *Address* must be the
address Zoraxy uses to reach Authelia **directly** (`http://authelia:9091/api/authz/forward-auth` or
`http://192.168.1.20:9091/api/authz/forward-auth`), *not* `https://auth.example.com/...`. If the subrequest goes
back through Zoraxy, the `X-Forwarded-*` headers are rewritten by the proxy hop and Authelia sees the wrong
target URL. Use `http://` when Authelia listens on plain HTTP (an `https://` address to a plain HTTP port gives
an error, reported in #793/#895). Do not add `X-Original-URL` custom headers by hand; the defaults are enough
(confirmed in #793).

Zoraxy sends the subrequest with the client's cookies and the original request in `X-Forwarded-Method`, `-Proto`,
`-Host`, `-Uri` and `-For`, computed by Zoraxy (client supplied values of these are dropped). A `2xx` answer lets
the request through and copies the listed *Response Headers* to the backend; a `401/302` is returned to the
browser; anything else or a timeout denies the request (fail closed).

## Step 3: protect a host

HTTP Proxy > edit the rule > **Authentication Provider: Forward Auth**. Test with a private window: you should be
redirected to the Authelia portal and back. If you get the protected page without a login, the provider is still
*None* on that rule (a symptom reported in #793).

Authelia side (from Authelia's documentation, adapt to your version):

```yaml
access_control:
  default_policy: deny
  rules:
    - domain: test1.example.com
      policy: one_factor
session:
  cookies:
    - domain: example.com
      authelia_url: https://auth.example.com
      default_redirection_url: https://www.example.com
```

The session cookie domain must be a parent of both `auth.example.com` and the protected host.

## Client IPs and the Authelia "ip" rules (#514)

Authelia (regulation, `ip`-based access rules, logs) sees whatever Zoraxy puts into the subrequest's
`X-Forwarded-For`. **Limitation (read from the code, `mod/auth/sso/forward/util.go`): that is the TCP peer
address that connected to Zoraxy, it is not resolved through the Trusted Proxy list.** Directly exposed Zoraxy:
that is the visitor, which is what you want. Zoraxy behind Cloudflare, a tunnel or another proxy: Authelia sees that
proxy's address, so Authelia IP rules cannot distinguish visitors in that setup. Use Authelia policies that do not
depend on the address, or put the IP based restrictions into a Zoraxy access rule (which does honour the
Trusted Proxy list, see [real-client-ip-cloudflare.md](real-client-ip-cloudflare.md)).

## Exceptions

Per rule, **Forward Auth / OAuth2 Exceptions** (HTTP Proxy list > the rule) lets path prefixes, exact paths, regexes
and IP/CIDRs bypass the login (health checks, API paths). Matching is normalised so `/..` tricks do not bypass.
