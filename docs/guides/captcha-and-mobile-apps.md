# CAPTCHA, phones and native apps

Answers upstream #993 ("mobile reCAPTCHA": the immich / audiobookshelf iOS apps cannot log in behind a CAPTCHA rule).

## Two separate things

**1. Challenge pages on a phone.** The challenge / "verification failed" / "blocked" pages are responsive
(`<meta viewport>`, fluid container). Checked with headless Chromium in a mobile context at 360x640 and 320x568 for the
Turnstile, reCAPTCHA and Altcha variants of all three pages with a 304 px widget: no horizontal scrolling at either size
(the widget ends at 332 px of 360 px, 312 px of 320 px). Mobile *browsers* therefore work with every provider.

**2. Native apps cannot solve a CAPTCHA.** A CAPTCHA is an interactive web page. An app that calls an API
(`/api/...`, `/rest/...`, a WebDAV or sync endpoint) gets the challenge HTML (an HTTP 200 page, see
`captcha/pages.go`) instead of JSON and fails with a parse or login error. There is no "mobile reCAPTCHA" flow for
proxies: the Google / Cloudflare mobile SDKs verify a *client-side app*, not a request passing through a reverse proxy,
and no part of the app would know to send the result. So the fix is not to challenge the app's traffic.

## What to do

HTTP Proxy > edit the rule > CAPTCHA, then one or both of:

* **Protected Path Prefixes (optional)**: if set, only these path prefixes are challenged (for example `/login`,
  `/auth`). Everything else, including the API the apps use, is not.
* **CAPTCHA Exceptions** button (same section): requests matching any rule skip the challenge. *Path prefix*
  (`/api`, `/rest`, `/hooks`) or *IP / CIDR* (your VPN / home network). IP rules use the client address resolved with the
  rule's trusted proxy policy ([real-client-ip-cloudflare.md](real-client-ip-cloudflare.md)).

Example for immich or audiobookshelf: add a *Path prefix* exception `/api` (and whatever other paths the app uses, watch the
Logs page while the app connects). The web UI keeps its CAPTCHA, the apps use their own login/tokens. Keep rate limiting
and auto-ban (Security Center) on, they compensate for the missing CAPTCHA on that path.

Notes: exceptions are managed in their own dialog and survive normal rule edits; a CAPTCHA session cookie is
host-bound and does not help apps that do not keep cookies.
