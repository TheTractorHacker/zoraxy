# Authentik forward auth: quick path and the 404 checklist

Answers upstream #895 ("Forward Auth with Authentik", 404 pages from the outpost). The full guide, covering forward auth
and OIDC, Authentik-side settings and a verification checklist, is **[../authentik.md](../authentik.md)**. It was developed
against fake outpost / OIDC servers (tests in `src/mod/auth/sso/forward` and `.../oauth2`), not yet against a real Authentik, so
please run its checklist and report differences.

## Short version

1. Authentik: Proxy Provider, mode *Forward auth (single application)*, **External host** = `https://app.example.com`
   (exactly what users type); create the Application; add the Application to an Outpost (the embedded one is fine).
2. Zoraxy: SSO > Forward Auth > *Authorization server base URL* = the outpost URL (`https://auth.example.com`, or
   `http://10.0.0.6:9000` for the container), press **Authentik: single application**, **Apply Change**. The preset sets
   address `<base>/outpost.goauthentik.io/auth/nginx`, *Use X-Original-\* Headers* **on**, *Send the protected host as Host header*
   **on**, *Outpost URL* = the base URL, redirect mode and the `X-authentik-*` response headers.
3. Rule to protect: Authentication Provider **Forward Auth**.

## Authentik answers 404 (reported by several users in #895)

The outpost picks the application from the **Host** of the request it receives. A 404 means it did not find an application for that
host. Check, in this order:

* *Send the protected host as the Host header of the auth subrequest* is **on** (the preset does this). With it off the outpost
  sees its own address and answers 404.
* The provider's **External host** equals the protected URL (scheme, host, no trailing slash) and the application is assigned
  to the outpost you point at.
* Address scheme matches the listener: `http://ip:9000/...` for the plain port, `https://...:9443` or the public URL for TLS.
  `https://` to the plain port fails (several reports).
* Domain-level mode: the cookie domain is the parent domain of both Authentik and the apps, the preset *Authentik: domain level* uses
  the outpost start URL for redirects.
* The **Outpost URL** field is set (it makes Zoraxy proxy `/outpost.goauthentik.io/` on the protected host without authentication
  so the session cookie lands on the app's own domain). The older "Ignored Paths + virtual directory" workaround is no longer needed.
* Which endpoint flavour: `/auth/nginx` needs *Use X-Original-\** on, `/auth/traefik`, `/auth/caddy`, `/auth/envoy` read the
  `X-Forwarded-*` headers (untick it).
* Test from the Zoraxy host: `curl -i -H 'Host: app.example.com' -H 'X-Original-URL: https://app.example.com/' http://outpost:9000/outpost.goauthentik.io/auth/nginx`
  should be a `401`/`302`, not a `404`.

"Rules switched back to *None* after a restart" (one report in #895): not reproduced here; if you see it, include the Zoraxy version and
whether the instance is read-only or part of a cluster (`conf/` synced from a primary overwrites local edits).
