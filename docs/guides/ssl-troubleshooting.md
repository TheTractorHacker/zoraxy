# Certificates: creating, DNS challenge, LAN-only hosts, warnings, default site, IPv4/IPv6

Answers upstream #386, #513, #543, #665, #681 and #750. Checks marked *verified* were done on a throw-away instance.

## 1. "Cannot create a certificate" with the HTTP challenge (#386)

The HTTP-01 challenge makes the CA fetch `http://<your name>/.well-known/acme-challenge/<token>` on **port 80**
from the internet. Error `403 :: unauthorized ... Invalid response from http://name/.well-known/...: 404` means
*something answered with 404* instead of Zoraxy's challenge responder.

Checklist:

1. **Port 80 must reach Zoraxy.** Docker: `-p 80:80`. Router: forward external 80 (and 443) to the Zoraxy host.
   ISP/CGNAT or a second router in front (double NAT) breaks this; use the DNS challenge (section 2).
2. **The name must point at your public address** (`dig +short A name`, and `AAAA`, see section 5).
3. Zoraxy opens the port 80 listener temporarily for an HTTP-01 request even when "Enable HTTP server on port 80" is off.
   If another program already uses port 80, Zoraxy cannot; Ingress settings shows "Port 80 is occupied".
4. **Ask the port yourself** from outside your network (phone on mobile data):
   `curl -i http://name/.well-known/acme-challenge/test`.
   *Verified:* when Zoraxy answers, the body is `No ACME challenge in progress` (HTTP 404, outside an issuance).
   Any other 404 page (nginx, router UI, another container) is the thing that is stealing port 80.
5. A rule with an **access rule / whitelist** does not block the challenge: the `/.well-known/acme-challenge/` path is
   answered before access rules (`UseSystemAccessControl: false`), but your firewall/CDN still can.
6. Redirect/"always HTTPS" features of a CDN in front (Cloudflare orange cloud) can interfere with HTTP-01; the DNS
   challenge avoids this.
7. Run one issuance at a time (requests are serialised since #1117) and look at the log
   (`log/`, or Logs page) for the CA's message. Use the **staging CA** option to test without rate limits.

## 2. DNS challenge (no inbound ports, wildcards, LAN-only names) (#681, #665, #750)

Certificates > Request a new certificate > challenge type **DNS**, choose your DNS provider (214 providers from
lego are built in), fill the credential fields, optionally *save as a DNS profile* to reuse it.

* Fill what the provider needs: for PowerDNS (`pdns`, e.g. udmedia.de) the required fields are **APIKey** and **Host**
  (the API base URL, `https://ns.example.org:8081`). **ServerName** is `localhost` (default), **APIVersion** is
  detected automatically, the rest stay empty.
  *Fixed in this fork:* blank fields used to be sent as empty strings and overwrote those defaults (the PowerDNS API
  was called as `/servers//zones`); empty fields are now ignored so the provider defaults apply
  (test `TestDNSProviderEmptyFieldsKeepProviderDefaults`).
* Other examples: `ovh` = `APIEndpoint` (e.g. `ovh-eu`), `ApplicationKey`, `ApplicationSecret`, `ConsumerKey`;
  `cloudflare` = `AuthToken` (an API token with `Zone:DNS:Edit`, `Zone:Zone:Read`); `duckdns`/`desec` = `Token`.
* A wildcard needs the DNS challenge: enter both `example.com` and `*.example.com`. (Wildcard certificates do not
  cover `example.com` itself or `a.b.example.com`.)
* If a provider needs a propagation wait longer than the default (2 minutes) raise **PropagationTimeout**.
* DDNS names (`*.duckdns.org`, `*.ddns.net`) cannot be wildcards for your sub-names unless the DDNS service offers a
  TXT API; the `duckdns` provider (Token only) is the one to use for `yourname.duckdns.org` and `*.yourname.duckdns.org` (not tested here).

## 3. A host that is only reachable on the LAN needs a certificate (#750)

The CA never has to reach your server with the DNS challenge, so this works for an internal name such as
`vault.home.example.com` whose A record points at a private address (or has no public record at all):

1. Obtain `*.home.example.com` (or the single name) with the **DNS challenge**.
2. Create the proxy rule for the name; restrict it to your LAN with an **Access Rule** whitelist for
   `192.168.0.0/16` etc. (see [real-client-ip-cloudflare.md](real-client-ip-cloudflare.md) if you sit behind a proxy)
   or with the rule's *Networking* option "TCP peer must be in this CIDR set".
3. Public DNS can hold the private A record, or use the optional split-horizon DNS responder / your own DNS
   (Pi-hole etc.) so the name only exists inside.

HTTP-01 for such a name fails by design (the CA cannot reach a private address). Running your own CA is only
needed if you do not own a public domain.

## 4. "Invalid certificate" warnings (#543, #665)

Work out which of these three it is:

| What the browser shows | Cause | Fix |
|---|---|---|
| Certificate issued by *Zoraxy Self-host* (the built-in self-signed one) | Zoraxy found no certificate for the name the browser sent (SNI), or the browser sent no name (you typed an IP) | issue/upload a certificate that contains that name; Certificates page shows "Domain" (SAN) per file |
| A real CA certificate, but for a different name | wrong certificate selected, or a wildcard that does not cover the name | wildcard `*.a.example.com` does not match `a.example.com` or `x.y.a.example.com`; request the needed names |
| Zoraxy cert is fine but the **upstream** HTTPS is broken | you ticked "Require TLS" and the upstream has a self-signed cert; you get a 502/521, not a browser warning | tick *Skip Verification* for that upstream (or install its CA) |

How Zoraxy picks the certificate for a TLS connection (code: `mod/tlscert/tlscert.go`): a per-host preferred
certificate (if "disable SNI" is set), a file named exactly `<hostname>.pem/.key`, otherwise the **first stored certificate whose
names match** (wildcards work), otherwise the **fallback certificate**, otherwise the built-in self-signed one.
Test any name from a shell, with the same SNI the browser uses:

```
openssl s_client -connect zoraxy-host:443 -servername dsm.example.com </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName
```

*Verified:* without `-servername` and for an unknown name the answer is the built-in `Zoraxy Self-host` certificate.

For #543 specifically (macvlan Docker, DSM on `:5001`, DuckDNS wildcard): the proxied name matched, so check with
the command above that the answer for `dsm.<name>.duckdns.org` is the wildcard and not `Zoraxy Self-host`, and that
the browser really uses that name (not the IP of the NAS) and a DNS record pointing to Zoraxy's macvlan address.
I could not reproduce the setup, so this is a diagnosis recipe, not a confirmed cause.

### Default site / unknown names / opening the IP (#665)

Requests for an unknown name or the bare IP get the **fallback certificate** (Certificates > the house icon "Set as
Default / Fallback Certificate") or, without one, the self-signed one. A browser can only skip the warning if the
name typed in the address bar is inside that certificate. So:

* "Redirect unknown hosts" (Default site) works silently over **HTTP** (port 80 listener on) because no certificate
  is involved; over HTTPS the TLS handshake happens first, so the certificate warning comes before the redirect.
* Typing the IP over HTTPS can never be warning-free with a normal CA certificate (a certificate for a host name does not
  cover an IP address). Use the name, or accept the warning for the catch-all.
* Wildcard `*.example.com` as the fallback certificate makes **any** `something.example.com` without its own rule
  show the default-site redirect instead of a warning.

## 5. Force the ACME validation over IPv4? (#513)

Not possible from Zoraxy, so there is no such setting: the *CA* does the validation from its own servers and
picks the address itself; Let's Encrypt looks up `A` and `AAAA` for the name and prefers the `AAAA` (IPv6) one when it
exists. Zoraxy's own outbound connection to the CA does not influence this. If your `AAAA` points at a different
machine (a backend with its own IPv6), the challenge lands there (403/404). Choose one:

1. Remove the `AAAA` record for that name (or point it at Zoraxy and forward IPv6 80/443 to Zoraxy).
2. Use the **DNS challenge** (section 2): validation is a TXT lookup, address family irrelevant.
3. Make the backend answer `/.well-known/acme-challenge/` by forwarding to Zoraxy's port 80.
