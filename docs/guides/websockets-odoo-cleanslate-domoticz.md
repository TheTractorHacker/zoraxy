# WebSockets, Odoo, CleanSlate (Hasura), Domoticz

Answers upstream issues #314 (Odoo), #622 (CleanSlate) and #446 (Domoticz). Everything marked *verified* was
reproduced with a throw-away Zoraxy instance and a fake backend that logs the request line it receives.

## How Zoraxy handles WebSockets

* There is nothing to switch on. A request with `Upgrade: websocket` is detected automatically on a proxy rule
  and on a virtual directory. (The rule option **Enable WebSocket** (Advanced) can be unticked to turn it off.)
* On a normal rule the path and query are forwarded unchanged: `wss://app.example.com/graphql` reaches
  `ws://upstream/graphql`.
* Zoraxy sends `X-Forwarded-For`/`X-Forwarded-Proto` and keeps `Origin`, `Cookie`, `Sec-WebSocket-Protocol` and the
  original `Host`. Custom headers are only copied to the upstream when the rule option
  **Enable WebSocket Custom Header** (in the rule's *Custom Headers* editor) is on.
* "websocket: bad handshake" in the Zoraxy log means *the upstream answered the upgrade with something other than
  `101`*. Look at the upstream's own log for the reason. The two most common reasons are a wrong path (below) and an
  upstream that checks `Origin`/`Host`.

## Virtual directories strip their prefix (and used to lose the path for WebSockets)

A virtual directory (`/websocket` -> `host:8072`) removes its matching prefix before forwarding, like nginx
`location /websocket/ { proxy_pass http://host:8072/; }`. If the upstream needs the path, **put the path in the
target**:

| Virtual directory path | Target | Request | Upstream receives |
|---|---|---|---|
| `/websocket` | `10.0.0.5:8072` | `/websocket` | `/` |
| `/websocket` | `10.0.0.5:8072/websocket` | `/websocket` | `/websocket` |
| `/websocket` | `10.0.0.5:8072/websocket` | `/websocket/x?y=1` | `/websocket/x?y=1` |

*Verified.* Before the fix in this fork the WebSocket upgrade through a virtual directory ignored the base path in
the target and always arrived as `/`; that is exactly what broke Odoo (`/websocket` on port 8072) and CleanSlate
(Hasura answers `only '/v1/graphql', '/v1alpha1/graphql' and '/v1beta1/relay' are supported on websockets`,
`"path":"$"`, i.e. it received `/`). Plain HTTP requests already behaved like the table.

## Odoo

Odoo 16 and older used `/longpolling` on port 8072, Odoo 17+ uses `/websocket` on the gevent port 8072 when
`workers` is greater than 0. With `workers = 0` (single process) everything including WebSockets is served on 8069 and you need
**no** virtual directory at all.

With workers:

1. Proxy rule `odoo.example.com` -> `10.0.0.5:8069`. Leave *Enable WebSocket* ticked.
2. Virtual directory on that rule: path `/websocket`, target `10.0.0.5:8072/websocket`
   (Odoo 16: path `/longpolling`, target `10.0.0.5:8072/longpolling`).
3. In `odoo.conf` set `proxy_mode = True` so Odoo trusts `X-Forwarded-*`.

Docker note: if Odoo runs in a container, publish both ports (for example `13000:8069`, `14000:8072`) and use
those host ports in the target. Do not use the same virtual directory for the upstream's HTTP and WebSocket
traffic with different ports; the longest matching directory wins (see
[url-rewrite-and-locations.md](url-rewrite-and-locations.md)).

Not tested against a real Odoo, only against a fake backend.

## CleanSlate / Hasura GraphQL

CleanSlate proxies `/v1/graphql` to a Hasura container. Create a virtual directory with the **full path**:

* path `/v1/graphql`, target `graphql-server:8080/v1/graphql`

(or give the whole host to a proxy rule if the frontend and GraphQL share a hostname and only that path goes
elsewhere.) The Hasura log lines `not-found ... path "$"` mean the upstream received `/`, fix as above.
Not tested against real Hasura.

## Domoticz (#446)

Reported symptom: the UI loads but images/JS/CSS show 404 in the browser console while the same URLs open fine
when clicked. We could not reproduce this and found no Zoraxy-side cause; the proxy forwards those requests
unchanged. Things to try, in this order:

1. Check *what* answers: the access log (Logs page) shows the status Zoraxy returned, the upstream's own log
   shows what it saw. If both say 200 the 404 is browser side (cache, a service worker, mixed content).
2. Domoticz's built-in web server is old and drops idle keep-alive connections. In the rule's upstream settings
   turn on **Disable connection reuse (keep-alive)**, and try **Force HTTP/1.1** in the rule's advanced options.
3. Make sure the target is plain `http://host:8080` (untick *Proxy target requires TLS*) unless you enabled
   HTTPS in Domoticz.
4. If it happens only when mounted on a sub path (`/domoticz`), see
   [url-rewrite-and-locations.md](url-rewrite-and-locations.md): the app must be configured for that base path.

Status: not reproduced, so these are suggestions, not a confirmed fix.
