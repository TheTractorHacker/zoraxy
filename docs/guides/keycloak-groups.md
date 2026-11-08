# Keycloak and groups (OIDC)

Answers upstream #775 ("how do I restrict an app to a Keycloak group, like oauth2-proxy `--allowed-group`").
Zoraxy side: verified with the project's fake OIDC provider tests (`mod/auth/sso/oauth2/*_test.go`:
group allow-list, nested claim paths, header mapping). **Not tested against a real Keycloak**; the Keycloak
screens below follow Keycloak's documentation and may differ slightly between versions.

## Keycloak

1. Realm > **Clients > Create client**: type *OpenID Connect*, *Client authentication* **on** (confidential),
   *Standard flow* on.
   * Valid redirect URIs: `https://app.example.com/internal/oauth2` (one per protected host, or a pattern such as
     `https://*.example.com/internal/oauth2`)
   * Valid post logout redirect URIs (optional): `https://app.example.com/`
2. Client > **Credentials**: copy the client secret.
3. Put the group names into the token. Client > **Client scopes** > `<client>-dedicated` > **Add mapper > By
   configuration > Group Membership**:
   * Name `groups`, Token Claim Name **`groups`**
   * **Full group path: OFF** (then values are `admins`; with it ON they are `/admins`, `/parent/child`)
   * Add to ID token **ON**, Add to userinfo **ON**, Add to access token as you like
4. Put users into groups (Groups menu), or assign realm roles if you prefer roles (below).

## Zoraxy

SSO > **OAuth 2.0** (global settings; the provider is then chosen per proxy rule as *Authentication Provider: OAuth2*):

| Field | Value |
|---|---|
| Issuer URL (OIDC) | `https://keycloak.example.com/realms/<realm>` (older Keycloak: `https://keycloak.example.com/auth/realms/<realm>`) |
| Client ID / Secret | from Keycloak |
| Code challenge method | PKCE (S256) |
| Scopes | `openid profile email` |
| Groups claim | `groups` |
| Allowed groups | `admins` (comma separated; a user needs at least one; with *Full group path* ON write `/admins`) |
| Upstream header mappings | `X-Auth-User=preferred_username,X-Auth-Email=email,X-Auth-Groups=groups` (optional) |

Press **Test discovery**: it shows the issuer, endpoints, S256 support and whether the JWKS is reachable. Then
**Apply Change** and select *OAuth2* on the rule. Users outside the group get a 403 page and no session; if the token carries no
group claim at all the user is denied as well. Group membership is re-evaluated at every token refresh.

### Roles instead of groups

Keycloak puts realm roles into `realm_access.roles`. Zoraxy supports dotted claim paths:
*Allowed claim values* `realm_access.roles=app-admin,app-user` (any of the values; several rules separated by `;`
must all match). Keycloak only adds that claim to the **access** token by default; add a *User Realm Role* mapper to the client
with Token Claim Name `realm_access.roles`, *Add to ID token* **on** (and userinfo), otherwise Zoraxy does not see it.
Not verified against a real Keycloak.

## Limitation: one group list for all hosts

*Allowed groups* belong to the single OAuth2 provider configuration, so every host that uses *OAuth2* shares the
same allow-list. Per-route group policies are on the roadmap (ROADMAP.md, section 4, "group-based policies per route").
Until then, for different groups per application use one of:

* **oauth2-proxy as Forward Auth** (one instance per group set, `--allowed-group`), Zoraxy Forward Auth address
  `http://oauth2-proxy:4180/oauth2/auth` and Response Headers `X-Auth-Request-User,X-Auth-Request-Email`. This is the
  structure of the guide you linked; it works with Zoraxy's generic Forward Auth, but I did not test it here. Only
  one Forward Auth server can be configured in Zoraxy at a time, so the multi-instance variant needs separate
  Zoraxy nodes or a front proxy; treat it as a workaround, not a recommendation.
* Keycloak itself: the *Authorization* policy of a client, or separate Keycloak clients/realms per audience, with
  a second Zoraxy node, are heavier alternatives.
* Zoraxy's own access rules (IP/country) combined with a single group for "may sign in at all".
