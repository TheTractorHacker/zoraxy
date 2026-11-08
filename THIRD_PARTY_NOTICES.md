# Third-party notices

Zoraxy is licensed under AGPL-3.0. Dependencies added or newly used directly by the fork are listed below.
Each project keeps its own licence; the full texts are available in the Go module cache and in the upstream repositories.

## Authentik / OIDC support

- **github.com/go-jose/go-jose/v4** - Apache-2.0. JWT/JWS parsing and signature verification of OIDC ID tokens
  (`src/mod/auth/sso/oauth2`). Already a transitive dependency; now a direct one.
- **golang.org/x/oauth2** - BSD-3-Clause. OAuth 2.0 authorization code flow, PKCE helpers and token refresh.
- **github.com/jellydator/ttlcache/v3** - MIT. Expiring in-memory session and login-state stores.
