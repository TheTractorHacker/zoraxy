# Authentik with Zoraxy

Zoraxy can protect a host with [Authentik](https://goauthentik.io) in two ways. Pick one per deployment (the
Forward Auth and OAuth 2.0 settings are global, the choice of provider is per proxy rule, see
*HTTP Proxy > Edit rule > Authentication*).

| | Forward auth (proxy outpost) | OIDC (OAuth2/OpenID provider) |
|---|---|---|
| Authentik objects | Proxy Provider + Outpost | OAuth2/OpenID Provider |
| Who authenticates the request | Authentik outpost, asked by Zoraxy on every request | Zoraxy, after a one-time login |
| Group based access | Authentik policy bindings on the application | Authentik policy bindings **and** Zoraxy "Allowed groups" |
| Identity to the backend | `X-authentik-*` headers | headers you map from claims (e.g. `X-Auth-User`) |
| Extra load on Authentik | one subrequest per request | none after login (token refresh every access token lifetime) |

> Everything below was developed and tested against fake Authentik outpost / OIDC servers (see the test files in
> `src/mod/auth/sso/`). Follow the verification checklist at the end against your real instance.

---

## A. Forward auth (proxy outpost)

### A1. Authentik side, single application mode

1. **Applications > Providers > Create > Proxy Provider**
   * Name: `app-proxy`
   * Authorization flow: *default-provider-authorization-implicit-consent* (or explicit if you want a consent page)
   * Mode: **Forward auth (single application)**
   * External host: `https://app.example.com` (exactly the URL users type, scheme included, no trailing slash)
2. **Applications > Applications > Create**, name/slug as you like, Provider: `app-proxy`. Add policy/group
   bindings here to control who may use the app.
3. **Applications > Outposts**: edit **authentik Embedded Outpost** (or your own proxy outpost) and move the
   application to *Selected Applications*.

### A2. Authentik side, domain level mode

Use this when one login should cover many hosts under one parent domain.

1. Proxy Provider, Mode: **Forward auth (domain level)**
   * Authentication URL: `https://auth.example.com` (the Authentik URL users reach)
   * Cookie domain: `example.com`
2. Application + Outpost as in A1. One provider/application covers every host under `*.example.com`.

### A3. Zoraxy side

1. **SSO > Forward Auth**.
2. Enter the **outpost base URL** in *Authorization server base URL*:
   * embedded outpost: your Authentik URL, e.g. `https://auth.example.com`
   * standalone outpost: e.g. `http://outpost:9000` (HTTPS is port 9443)
3. Click **Authentik: single application** or **Authentik: domain level**. The preset fills:

   | Field | Value |
   |---|---|
   | Address | `<base>/outpost.goauthentik.io/auth/nginx` |
   | Use X-Original-* Headers | on (sends `X-Original-URL`; the `X-Forwarded-*` headers are sent too) |
   | Send protected host as Host header | on |
   | Outpost URL | `<base>` |
   | When not signed in | single: redirect to `/outpost.goauthentik.io/start` on the protected host; domain: redirect to `<base>/outpost.goauthentik.io/start` |
   | Response Headers | `X-authentik-username, X-authentik-groups, X-authentik-entitlements, X-authentik-email, X-authentik-name, X-authentik-uid, X-authentik-jwt, X-authentik-meta-jwks, X-authentik-meta-outpost, X-authentik-meta-provider, X-authentik-meta-app, X-authentik-meta-version, X-authentik-meta-*` |
   | Response Client Headers | `Set-Cookie` |

   For the Traefik/Caddy/Envoy flavours change the address suffix to `/auth/traefik`, `/auth/caddy` or `/auth/envoy` and
   untick *Use X-Original-\* Headers* (those flavours read `X-Forwarded-Host/Proto/Uri`).
4. **Apply Change**.
5. On each host to protect: *HTTP Proxy > edit the rule > Authentication > Forward Auth*.

### What Zoraxy does

* `GET <Address>` as a subrequest with the client's cookies/headers, `X-Original-URL` and `X-Forwarded-Host/Proto/Uri/Method/For`
  computed by Zoraxy (client supplied copies of these headers are dropped), and `Host` set to the protected host.
* `2xx`: the listed *Response Headers* replace any client supplied value (a trailing `*` is a prefix match, e.g.
  `X-authentik-meta-*`), *Response Client Headers* (`Set-Cookie`) go back to the browser, the request continues.
* `401` and a browser navigation: redirect (302) to `/outpost.goauthentik.io/start?rd=<original URL>`. `rd` is built
  only from the request Zoraxy itself received, so it cannot be steered to another site. Non-browser callers get 401.
* `3xx` from the outpost is passed through.
* Anything else, or an error/timeout (15 s) talking to the outpost: the request is **denied** (fail closed).
* `/outpost.goauthentik.io/...` on the protected host is reverse proxied to the Outpost URL **without**
  authentication (callback, `start`, `sign_out`, static assets), `Host`, `X-Forwarded-*` and `X-Original-URL`
  set so the outpost recognises the application. This is what makes the session cookie land on the application's own
  domain. The old *Ignored Paths* + Virtual Directory workaround is no longer needed.
* When an Outpost URL is configured, every inbound `X-authentik-*` request header is removed before anything else.

Sign out: link users to `https://app.example.com/outpost.goauthentik.io/sign_out`.

---

## B. OIDC (OAuth2/OpenID provider)

### B1. Authentik side

1. **Applications > Providers > Create > OAuth2/OpenID Provider**
   * Name: `app-oidc`
   * Authorization flow: *default-provider-authorization-implicit-consent*
   * Client type: **Confidential**
   * Redirect URIs/Origins: add **`https://app.example.com/internal/oauth2`** with matching mode *Strict*
     (one entry per protected host, or one *Regex* entry such as `https://.*\.example\.com/internal/oauth2`)
   * Signing Key: select a certificate (e.g. *authentik Self-signed Certificate*). Without a signing key Authentik
     signs ID tokens with HS256 using the client secret; Zoraxy accepts that only because discovery advertises it, but
     RS256/ES256 is strongly preferred.
   * Advanced protocol settings > Scopes: keep `openid`, `profile`, `email`; **add `offline_access`** (needed for refresh
     tokens). The `profile` scope delivers `preferred_username`, `name` and `groups`.
   * Subject mode / Include claims in id_token: defaults are fine (include claims on).
   * Access token validity (default 5 minutes) is also how often Zoraxy refreshes; Refresh token validity default 30 days.
   * Copy **Client ID** and **Client Secret**.
2. **Applications > Applications > Create** with Provider `app-oidc`. Copy the **slug**.
   The issuer is `https://auth.example.com/application/o/<slug>/` (trailing slash included).
3. (Optional) Logout: add `https://app.example.com/` under *Post logout redirect URIs* if your Authentik version has the field.

### B2. Zoraxy side

1. **SSO > OAuth 2.0**.
2. Enter the issuer URL in the preset box and click **Authentik (OIDC)**. It fills Issuer, Scopes
   `openid profile email offline_access`, Code Challenge Method **PKCE (S256)**, Groups claim `groups` and header
   mappings `X-Auth-User=preferred_username,X-Auth-Email=email,X-Auth-Name=name,X-Auth-Groups=groups`.
3. Paste Client ID/Secret. Optionally fill **Allowed groups** (comma separated Authentik group names; a user needs at
   least one). Press **Test discovery**: Zoraxy fetches the discovery document server side and shows issuer, endpoints,
   PKCE S256 support, ID token algorithms and whether the JWKS is reachable and contains keys.
4. **Apply Change**, then select *OAuth2* as the authentication provider on the proxy rule.

### What Zoraxy does

* Discovery from `<issuer>/.well-known/openid-configuration`; the reported issuer must equal the configured one;
  an `https` issuer must not point to `http` endpoints. Metadata is cached (default 60 s, stale copy reused if Authentik is briefly down).
* Authorization code flow with PKCE **S256**, random single-use `state` (10 min), `nonce`. `state` is bound to the browser by a
  signed, HttpOnly cookie, so a callback with someone else's `state`/`code` is rejected (login CSRF), and to the host.
* The return location is stored server side and reduced to a same-site relative path (`//host`, `\`, `scheme:` and control
  characters collapse to `/`). The old behaviour of putting the URL into `state` is gone.
* ID token: signature against the JWKS (cached 1 h, re-fetched on an unknown `kid`, at most every 10 s), `iss`, `aud`
  (+`azp` when several), `exp` (required), `iat`/`nbf` with 60 s skew, `nonce`. Accepted algorithms RS/PS/ES/EdDSA; HS* only if
  the provider advertises it (verified with the client secret); `none` never.
* `userinfo` is merged for missing claims (`sub` must match). Groups claim default `groups`, dotted paths allowed.
* Session: an opaque random id in an HttpOnly, `SameSite=Lax` cookie (`Secure` on HTTPS) signed with a key derived from the
  node UUID; tokens never reach the browser. Sessions are in memory (a restart sends users through login again; they are
  not shared between Zoraxy nodes).
* Refresh: when the access token is within 60 s of expiry the refresh token is used; claims/groups are re-evaluated, a
  user removed from the allowed group is locked out at the next refresh. Refresh failure restarts login.
* Logout: `https://app.example.com/internal/oauth2/logout` destroys the session and redirects to the provider's
  `end_session_endpoint` (with `id_token_hint`, `client_id`, and the configured post logout URL if any). No redirect
  target is ever taken from the request.
* Upstream headers: the mapped headers are removed from the incoming request and set from verified claims. Host,
  Authorization, Cookie, `X-Forwarded-*` etc. cannot be mapped.
* Denied by group: HTTP 403 page with a sign-out link, no session created.

Existing configurations keep working: the same settings keys are used, `PKCE`/`PKCE_S256`/none behave as before, a bare
discovery URL or manually entered endpoints (plain OAuth 2.0 without `openid`, identity from the userinfo endpoint) still
work. Differences: empty scopes now default to `openid profile email` instead of every scope the provider lists; the
login cookie is the new `z-session`, so users sign in once more after the upgrade; an OIDC login requires a valid ID token.

---

## Verification checklist against a real Authentik

Forward auth:
1. `curl -i https://app.example.com/` returns `401` (non-browser), a browser lands on the Authentik login and comes back to the
   original URL (including query string).
2. After login your backend sees `X-authentik-username` etc. Send a request with a forged `X-authentik-username: root` and
   confirm the backend still sees the real one (or none when logged out).
3. `https://app.example.com/outpost.goauthentik.io/ping` returns `204` without logging in (proxied to the outpost).
4. `.../outpost.goauthentik.io/sign_out` logs out.
5. Stop the outpost: requests must return 5xx/401, never reach the backend.

OIDC:
1. *Test discovery* is green (issuer, S256, JWKS keys).
2. Login works, the backend sees the mapped headers; a user outside *Allowed groups* gets 403.
3. Remove the user from the group in Authentik, wait one access token lifetime: access is revoked.
4. Disable the user in Authentik: refresh fails and login is required.
5. `/internal/oauth2/logout` ends the Authentik session too.
6. Open `https://app.example.com//evil.example/` and log in: you must land on `/`, not on evil.example.

## Troubleshooting

* *redirect_uri mismatch*: the Authentik redirect URI must be exactly `https://<host>/internal/oauth2` (scheme as seen by
  the browser). If another TLS terminator sits in front of Zoraxy the scheme Zoraxy sees may be `http`.
* Forward auth loop: the outpost does not know the application by Host. Check *Send protected host as Host header* and the
  provider's *External host*.
* Cookie not set / endless login in forward auth: `Set-Cookie` must be in *Response Client Headers* and `/outpost.goauthentik.io/`
  must be reachable on the host (set the Outpost URL).
* `groups` missing: ensure the `profile` scope mapping is attached to the provider, then use *Allowed groups* only after a login shows
  the claim (map `X-Auth-Groups=groups` and look at the backend).
