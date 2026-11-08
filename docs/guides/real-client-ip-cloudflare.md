# Real client IP: Cloudflare, tunnels, VPNs, TCP streams, access rules

Answers upstream #590, #514, #676, #612, #366 and #1087. The behaviour below was checked with a throw-away
instance (a fake backend printing the headers it receives) unless marked otherwise.

## Two different questions

1. **What does my upstream application see?** (logs, fail2ban, "too many logins", Home Assistant, Authelia ...)
2. **Which address does Zoraxy itself use** for access rules (whitelist / blacklist / country), auto-ban, rate limit,
   CAPTCHA exceptions, statistics?

Zoraxy can only know the address of the machine that opened the TCP connection (the *peer*). A visitor's real address is
learned from headers (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`...) **and a header is only believable if
the peer that sent it is a proxy you trust.** If a router does NAT in front of Zoraxy (port forward with masquerade, a WireGuard
server without routing, Docker userland proxy, a Proxmox LXC behind NAT) the peer is that device and the real
address is gone before Zoraxy sees it. Fix that at the network layer (disable masquerade / route the subnet /
use host networking), no proxy setting can recover it.

## 1. What the upstream receives

For every proxied HTTP request Zoraxy sends (verified):

| Header | Value |
|---|---|
| `X-Forwarded-For` | the incoming `X-Forwarded-For` (if any) followed by `, <peer address>` |
| `X-Real-Ip` | kept if the client/CDN sent one, else `CF-Connecting-IP`, else `Fastly-Client-IP`, else the first entry of `X-Forwarded-For` |
| `X-Forwarded-Proto` | `http` or `https` |
| `X-Forwarded-Host` | the host the visitor asked for |

Consequences:

* A typical app (Home Assistant, Nextcloud, Authelia, Gitea...) must be told **which proxy addresses to trust** and
  then reads the client from `X-Forwarded-For`/`X-Real-IP`. Without that setting it reports the proxy's address
  (this is the "I see Zoraxy's IP" and "Cloudflare IPs" complaint, #514, #590, #676). Add the address Zoraxy connects
  *from* (its LAN address or the Docker network gateway), not the visitor's.
* Apps that insist on the *last* entry of `X-Forwarded-For` (some old software) get Zoraxy's peer; point them at
  `X-Real-Ip` instead, or send a dedicated header from the rule's *Custom Headers*:
  `X-Client-IP: {{client_ip}}` (see below). `$remote_ip` is the peer address without port, `$remote_addr` includes the port.
* Anything in `X-Forwarded-For` before Zoraxy's entry was supplied by the client or an earlier proxy. If Zoraxy is
  the first proxy, enable **Sanitise client IP headers** (Ingress settings, or per rule) so spoofed values are
  dropped from peers that are not in the trusted proxy list. It is off by default.
* WebSocket upgrades get `X-Forwarded-For` and `X-Forwarded-Proto` but not `X-Real-Ip` unless the client sent one;
  turn on **Enable WebSocket Custom Header** if your custom headers must reach WebSockets.

## 2. Which address Zoraxy uses itself

Each access rule has **Enable Trusted Proxy Gating** (Access Rules > the rule editor; default rule = "default").

* **Off (default):** the peer address is used. Behind Cloudflare that is a Cloudflare edge address, behind a
  Cloudflare Tunnel (`cloudflared`) it is the tunnel's address (127.0.0.1 or a Docker address), behind WireGuard or
  Tailscale it is the VPN gateway or a `100.64.0.0/10` address.
* **On:** if the peer is on the **Trusted Proxy** page (left menu) the visitor address is taken from
  `X-Real-IP`, then `CF-Connecting-IP`, `Fastly-Client-IP`, `X-Forwarded-For`. If the peer is not listed the peer
  address is used and the headers are ignored (spoof proof).

Verified with a peer of 127.0.0.1 sending `CF-Connecting-IP: 203.0.113.5`:

| Gating | peer in Trusted Proxy | `{{client_ip}}` seen by upstream |
|---|---|---|
| off | - | `127.0.0.1` |
| on | yes | `203.0.113.5` |

### Cloudflare, step by step

1. **Trusted Proxy** page: the list is pre-filled with Cloudflare's published IPv4/IPv6 ranges (use *Reset to Default*
   to restore it; compare with https://www.cloudflare.com/ips/ from time to time, Cloudflare changes them rarely).
2. If you use a **Cloudflare Tunnel**, `cloudflared` is the peer, not a Cloudflare range. Add its address
   (`127.0.0.1`, or the Docker network subnet) to the Trusted Proxy list.
3. Access Rules > rule editor > enable **Trusted Proxy Gating**.
4. In the application, trust Zoraxy's address as shown in section 1.
5. Check: access rules and auto-ban use the visitor address, and a forged `CF-Connecting-IP` sent
   directly to your origin (not through Cloudflare) is ignored by Zoraxy's own decisions.

### WireGuard / VPN clients (#612)

If the VPN server NATs (masquerades) client traffic, Zoraxy sees the VPN server's address for every client.
Either route instead of masquerade for traffic to Zoraxy and whitelist the VPN subnet, or whitelist the VPN
server's address (all VPN users then share it).

### "3.3.2 denies access" with a country whitelist (#1087)

Symptoms: 403 for users coming through Cloudflare, a Cloudflare Tunnel or Tailscale after upgrading; fixed by
enabling *Trusted Proxy Gating*. Reason: the whitelist checks the **peer** address (see above). That address is a
reserved or unrelated one and
* **has no country**: reserved ranges (private 10/8, 172.16/12, 192.168/16, CGNAT `100.64.0.0/10` shown as zone
  "CarrierNAT", loopback, link-local...) can never match a country entry;
* "Enable LAN and Loopback" covers 127/8, ::1, 10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7, fe80::/10 but
  **not** `100.64.0.0/10` (pinned by the unit test `TestIsPrivateIPRangeMatchesDocumentedList`).

Fix, in order of preference: turn on Trusted Proxy Gating and list your proxy; or add the peer's CIDR to the
*IP whitelist*. The access page now says this next to the whitelist and the gating toggle.

## 3. TCP/UDP stream proxies (#366: SMTP, SSH...)

A stream proxy opens a new TCP connection to the target, so the target sees Zoraxy's address and no HTTP header
can exist. Use the **PROXY protocol**: Stream Proxy > edit > *Proxy Protocol* v1 or v2 (UDP: v2 only).
*Verified:* with v1 selected the target receives `PROXY TCP4 <client> <local> <sport> <dport>\r\n` as the first
bytes of the connection. The receiving service must be configured to **require/accept** it, otherwise it sees garbage
and drops the connection:

* Postfix: `postscreen_upstream_proxy_protocol = haproxy` (when using postscreen) and/or
  `smtpd_upstream_proxy_protocol = haproxy` in `main.cf`. Postfix only accepts the header from the port it is set for,
  so use a separate listening port for proxied traffic. Not tested here, and I do not know how Proxmox Mail Gateway
  exposes this setting.
* Services without PROXY support (OpenSSH): put `haproxy` or `go-mmproxy` on the target host to strip the header
  and re-present the original address (reported working in upstream #366 by a user).
* Alternative without the protocol: make Zoraxy's host a router for that traffic (no NAT, target's default route
  via Zoraxy). That is network design, not a Zoraxy option.

For HTTP upstreams that speak PROXY protocol (rare) there is a per-upstream *PROXY protocol* switch in the upstream
settings. Zoraxy can also *accept* PROXY protocol from a load balancer in front of it (Ingress settings > PROXY
Protocol; mutually exclusive with HTTP/3).

## Header variables for custom headers

`{{client_ip}}` = the address Zoraxy resolved with the rule's trusted-proxy policy (what access rules use),
`$remote_ip` = the TCP peer, `$remote_addr` = peer with port, `{{host}}`, `{{request_id}}`. The old nginx names
`$remote_addr`/`$host` etc. are replaced as plain text, there is no `$proxy_add_x_forwarded_for`.
