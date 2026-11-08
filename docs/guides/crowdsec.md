# CrowdSec with Zoraxy

Answers upstream #648 ("does CrowdSec need live logs?"). Log format and the ban API were checked on a throw-away
instance; the CrowdSec configuration itself was **not** run (no CrowdSec here), treat the YAML as a starting point.

## Reading the logs (detection)

* Zoraxy appends every proxied request to `log/zr_<YYYY>-<MM>.log` as it happens (one file per month, older months
  stay in the folder). That *is* the live log: point CrowdSec at it with a glob so it follows the monthly rotation:

  ```yaml
  # /etc/crowdsec/acquis.d/zoraxy.yaml
  filenames:
    - /opt/zoraxy/log/zr_*.log
  labels:
    type: zoraxy
  ```
  (In Docker mount the log folder read-only into the CrowdSec container.)
* Line format (verified on 19,000 lines; all matched the pattern below):

  ```
  [2026-11-08 19:28:10.569106] [router:host-http] [origin:odoo.test:18443] [client: 203.0.113.5] [useragent: curl/8.18.0] GET /foo 404
  ```
  `client` is the visitor address resolved with the rule's trusted proxy policy (see
  [real-client-ip-cloudflare.md](real-client-ip-cloudflare.md)); behind Cloudflare enable *Trusted Proxy Gating* or
  CrowdSec will see Cloudflare addresses. A Grok/regex parser for it:

  ```
  ^\[(?P<ts>[^\]]+)\] \[router:(?P<router>[^\]]+)\] \[origin:(?P<host>[^\]]*)\] \[client: (?P<ip>[^\]]+)\] \[useragent: (?P<ua>[^\]]*)\] (?P<method>[A-Z]+) (?P<uri>\S+) (?P<status>\d{3})$
  ```
  A community collection for Zoraxy was proposed to the CrowdSec hub (see upstream discussion #338); check the hub
  before writing your own.
* Alternative: per-site log files in **JSON lines** (`time, class, site, origin, upstream, client, useragent, method,
  uri, status`), configured in the logging settings; easier to parse with CrowdSec's JSON helpers (not tested here).
  They default to *off*.

## Enforcing decisions (remediation)

CrowdSec's Nginx/Traefik bouncers do not apply. Two options:

1. **Firewall bouncer** (`crowdsec-firewall-bouncer`, iptables/nftables): blocks the IP before Zoraxy sees it. Works
   when Zoraxy sees real client addresses (no NAT in front); easiest and cheapest.
2. **Zoraxy remote ban API** (Security Center > Auto-ban): generate a token in the UI, switch *Auto-ban* on, then a
   custom bouncer or script can push bans:

   ```bash
   curl -X POST -H "Authorization: Bearer $TOKEN" -d ip=203.0.113.9 -d seconds=3600 -d reason=crowdsec \
        http://zoraxy:8000/api/abuse/remote/ban
   curl -X POST -H "Authorization: Bearer $TOKEN" -d ip=203.0.113.9 http://zoraxy:8000/api/abuse/remote/unban
   curl -H "Authorization: Bearer $TOKEN" http://zoraxy:8000/api/abuse/remote/list
   ```
   *Verified:* ban and list return the ban record. Bans are only enforced while Auto-ban is enabled (the list shows
   `"Active": false` otherwise), loopback/private/trusted-proxy addresses are never banned, and the API listens on the
   management port, so keep that port off the internet. Wiring this to `crowdsec-custom-bouncer` is not tested.

Zoraxy's own auto-ban (401/403/404/429, WAF, bots, CAPTCHA failures) covers much of what CrowdSec scenarios
detect for HTTP and may be enough on its own.
