# Sign in with Google (OIDC)

Answers upstream #959. Zoraxy side: verified with the project's fake OIDC provider (discovery, PKCE S256, e-mail and
claim allow-lists). **Not tested against the real Google endpoints.**

## Google side

1. https://console.cloud.google.com > APIs & Services > **OAuth consent screen**: configure (External or Internal for
   Workspace). Add your users as test users while it is in "Testing".
2. **Credentials > Create credentials > OAuth client ID**, type **Web application**.
   * Authorized redirect URIs: `https://app.example.com/internal/oauth2` for every protected host (exact match, `https`,
     a real domain name; Google rejects bare IPs and `.local` names).
3. Copy the **Client ID** and **Client secret**.

## Zoraxy side

SSO > **OAuth 2.0**:

| Field | Value |
|---|---|
| Issuer URL (OIDC) | `https://accounts.google.com` |
| Client ID / Secret | from Google |
| Code challenge method | PKCE (S256) (Google supports it) |
| Scopes | `openid profile email` |
| Upstream header mappings | `X-Auth-Email=email,X-Auth-Name=name` (optional) |

Leave Authorization / Token / User Info URL empty: they come from
`https://accounts.google.com/.well-known/openid-configuration`. Press **Test discovery** (shows issuer, S256 support, JWKS
keys), **Apply Change**, then on the proxy rule choose *Authentication Provider: OAuth2*.

Why the upstream report "selecting OAuth2 behaves like None" does not apply here: in this fork a rule set to OAuth2
fails closed (HTTP 500 "OAuth2 is not configured") while Client ID or issuer are missing, it never falls back to
*None*. (Issuer value from #959: use the bare `https://accounts.google.com`, not a `/o/oauth2/v2/auth` URL.)

## Who may sign in

Google has no groups. Without a restriction **every Google account** that can authenticate gets in. Restrict it:

* *Allowed e-mail addresses*: `alice@gmail.com,bob@example.com`
* *Allowed e-mail domains*: `example.com` (exact domain, subdomains are not included). The e-mail must not be reported
  as unverified.
* Google Workspace only: *Allowed claim values* `hd=example.com` (the hosted-domain claim). Prefer the e-mail
  domain rule for consumer accounts.

If a list is set and the token has no `email`, access is denied.

## Troubleshooting

* `redirect_uri_mismatch`: the URI in Google must be exactly `https://<host>/internal/oauth2` as the browser sees it
  (if a TLS terminator sits in front of Zoraxy, Zoraxy may see `http`).
* `Error 400: invalid_request / access blocked`: the consent screen is incomplete or the user is not a test user.
* Logout: `https://app.example.com/internal/oauth2/logout` ends the Zoraxy session (Google has no end-session
  endpoint, so you stay signed in at Google).
* Sessions live in memory: a Zoraxy restart sends users through the (usually silent) sign-in again.
