# Virtual directories, locations and path rewriting

Answers upstream #417 (extra "locations" for a domain, Home Assistant), #418 (static files 404 under a sub path)
and part of #446. Verified with a throw-away instance and a fake backend that logs the request line it gets.

## There are no nginx `location` blocks

Zoraxy routes in two steps:

1. **Host**: the `Host` header selects a proxy rule (`ha.example.com`). Wildcards (`*.example.com`) and aliases work.
2. **Path (optional)**: *virtual directories* on that rule send a path prefix to a **different** upstream.

If every path of a site goes to the same upstream you need **no** virtual directory. The nginx block

```
location ~ ^/(api|local|media)/ { proxy_pass http://homeassistant:8123; }
```

only makes sense when the server also has other locations. For Home Assistant create one rule
`home.example.com` -> `homeassistant:8123` (it serves `/api`, `/local`, `/media` and the UI itself). Home
Assistant must trust the proxy, otherwise it answers 400: in `configuration.yaml`

```yaml
http:
  use_x_forwarded_for: true
  trusted_proxies:
    - 192.168.1.10   # the address Zoraxy connects from
```

Regular expressions in paths are not supported by virtual directories. Redirect rules (HTTP Proxy > Redirection
Rules) do support regex, and path rules (allow/deny/auth/rate-limit per path) match on normalised path prefixes; they never send a path to another upstream.

## Matching and ordering

* A virtual directory matches when the request path **starts with** its matching path (`/api` also matches
  `/apiary`; end the path with `/` if you want a directory boundary).
* **The longest matching path wins** (this fork; upstream used the first one in the list, so a `/` entry
  shadowed everything added after it and the only way to reorder was edit+save). Order of creation no longer
  matters. *Verified by unit test* `TestVirtualDirectoryLongestPrefixWins`.
* A request for `/dir` without trailing slash is redirected to `/dir/` when the directory is defined as `/dir/`.

## The prefix is removed, and the target can carry a base path

Request `/web-check/style.css` through a virtual directory `/web-check` -> `192.168.0.11:5555`:

| target | upstream receives |
|---|---|
| `192.168.0.11:5555` | `/style.css` |
| `192.168.0.11:5555/web-check` | `/web-check/style.css` |

(`/web-check` alone with the second target is sent as `/web-check/`.) *Verified.*

## #418: apps that emit root-relative URLs

Zoraxy does **not** rewrite HTML/JS/CSS bodies. If the app writes `<link href="/css/style.css">`, the browser asks
`https://mydomain.com/css/style.css`, which is not under `/app/` and therefore not routed to the container (404).
Options, best first:

1. Give the app its own host name (`app.mydomain.com` -> `192.168.0.11:5555`). No path problems at all.
2. Configure the app for a base path (most apps have `BASE_URL`, `--base-path`, `url_base`, `ROOT_PATH`...) **and**
   put that path in the target: virtual directory `/app/` -> `192.168.0.11:5555/app`.
3. Otherwise the app cannot live under a sub path behind any reverse proxy that does not rewrite bodies.

Redirects (`Location: /login`) from the upstream are rewritten to stay under the virtual directory when the
virtual directory prefix is known (see `PathPrefix` handling in `dpcore`); content is not.

## WebSockets through a virtual directory

See [websockets-odoo-cleanslate-domoticz.md](websockets-odoo-cleanslate-domoticz.md): the base path in the target
is honoured for WebSocket upgrades too.
