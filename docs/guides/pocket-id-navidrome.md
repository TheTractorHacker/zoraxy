# Pocket ID + Navidrome: passing the user name in a header

Answers upstream #1118. The OIDC claim -> header mapping is covered by Zoraxy's tests with a fake provider
(`TestFullLoginPKCES256AndSessionCookieFlags`, `TestScrubIdentityHeaders`); **Pocket ID and Navidrome themselves were not run**.

## The mistake in the report

Header variables like `$username`, `{username}`, `${username}` in the rule's *Custom Headers* are not OIDC claims:
those fields only know request/connection values (`{{client_ip}}`, `{{host}}`, `$remote_ip`, ...). A literal text is
sent as is, which is why Navidrome created users called `$username` and `username`. The user name from the identity
provider is delivered by the OAuth2 settings instead:

1. **Remove** the custom header `X-Auth-User` from the Navidrome rule (a static value would also be wrong for everybody).
2. SSO > OAuth 2.0 > **Upstream header mappings**:

   ```
   X-Auth-User=preferred_username
   ```

   (comma separated `Header=claim` pairs; add `X-Auth-Email=email,X-Auth-Name=name` if you want them). Zoraxy first
   **deletes** these headers from the incoming request (clients cannot forge them) and then sets them from the
   verified ID token / userinfo claims.
3. Scopes `openid profile email` (the `preferred_username` claim comes with `profile`; Pocket ID calls it the
   "username"). Issuer URL `https://pocket.example.com` (Pocket ID's OIDC discovery lives at
   `/.well-known/openid-configuration`), PKCE (S256), Client ID/Secret from Pocket ID with callback URL
   `https://music.example.com/internal/oauth2`.
4. Press **Test discovery**, **Apply Change**, and set the rule to *Authentication Provider: OAuth2*.

## Navidrome

Environment (names for Navidrome 0.55 and newer; older versions call them `ND_REVERSEPROXYUSERHEADER` and
`ND_REVERSEPROXYWHITELIST`):

```
ND_EXTAUTH_USERHEADER=X-Auth-User
ND_EXTAUTH_TRUSTEDSOURCES=172.18.0.0/16      # the address Zoraxy connects from, NOT 0.0.0.0/0
```

`0.0.0.0/0` makes Navidrome trust the header from anybody who can reach its port, so any LAN host could log in as
any user by sending `X-Auth-User`. Use the Zoraxy address / Docker network. Check the header arrives: temporarily point the rule
at a header-echo container such as `traefik/whoami`.

## Subsonic and mobile clients

Navidrome's apps (`/rest/*`) cannot do an interactive OIDC login. Keep OAuth2 for the web UI and add a
**Forward Auth / OAuth2 exception** (HTTP Proxy > the rule > *Forward Auth / OAuth2 Exceptions*) for the path prefix `/rest/`
(and `/share/` if you use shares); those clients then authenticate with their Navidrome password/token. Do not
exempt it if you expose Navidrome to the internet without understanding that Navidrome's own credentials are then the only barrier.
