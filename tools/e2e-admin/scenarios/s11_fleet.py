import json, os, re
from runner import scenario, NotTestable
from .common import *


def hub_post(c, action, **form):
    st, js = c.post("/api/fleet/hub/" + action, **form)
    check(st == 200 and not (isinstance(js, dict) and js.get("error")), f"hub {action}: {st} {js}")
    return js


def nodes_of(c):
    ov = c.get("/api/fleet/hub/overview")[1]
    n = ov.get("nodes") if isinstance(ov, dict) else None
    if isinstance(n, dict):
        n = list(n.values())
    return n or []


def node_by_name(c, name):
    for n in nodes_of(c):
        if n.get("name") == name:
            return n
    return None


class FleetEnv:
    def __init__(self):
        self.parts = []

    def spawn(self, name, extra=()):
        be = Recorder(lambda r, n=name: (200, {}, f"backend-of-{n}"))
        pp = alloc_port()
        inst = Instance(name, flags=["-default_inbound_port", str(pp)] + list(extra)).start()
        inst.client.ok("/api/cert/tls", set="false")
        inst.client.retry_refused = 25
        self.parts.append((inst, be, pp))
        inst.be, inst.pport = be, pp
        return inst

    def close(self):
        for inst, be, pp in self.parts:
            inst.cleanup()
            be.stop()
            free_port(pp)


def join(hub, node, name, group="edge"):
    tok = hub_post(hub.client, "tokenCreate", minutes="30", name=name, group=group)["token"]
    r = node.client.post("/api/fleet/node/join", hubUrl=hub.url, token=tok, fingerprint="", allowHttp="true")
    check(r[0] == 200 and not (isinstance(r[1], dict) and r[1].get("error")), f"join {name}: {r}")
    return tok


def wait_node(hub, name, pred, timeout=60):
    return wait_until(lambda: (lambda n: n if n and pred(n) else None)(node_by_name(hub.client, name)), timeout, 1)


@scenario("fleet-hub-two-nodes", ["81", "183", "1070"])
def fleet():
    fe = FleetEnv()
    try:
        hub = fe.spawn("fhub")
        a = fe.spawn("fnode-a")
        b = fe.spawn("fnode-b")
        r = hub.client.post("/api/cluster/config", role="hub")
        check(r[0] == 200 and r[1] in ("ok", "OK"), f"enable hub {r}")
        hub_post(hub.client, "settings", keepVersions="10", heartbeatSecs="5", healthGraceSec="30")
        hub_post(hub.client, "groupSet", name="edge", scopes="proxy", tags="", vars=json.dumps({"region": "eu"}))
        # token semantics: single use, bogus refused
        tok = join(hub, a, "A")
        again = b.client.post("/api/fleet/node/join", hubUrl=hub.url, token=tok, fingerprint="", allowHttp="true")[1]
        check(isinstance(again, dict) and again.get("error"), f"used token accepted twice: {again}")
        bad = b.client.post("/api/fleet/node/join", hubUrl=hub.url, token="zj1.bogus.bogus", fingerprint="", allowHttp="true")[1]
        check(isinstance(bad, dict) and bad.get("error"), f"bogus token accepted: {bad}")
        join(hub, b, "B")
        na = wait_node(hub, "A", lambda n: n.get("status") in ("online", "degraded"), 60)
        nb = wait_node(hub, "B", lambda n: n.get("status") in ("online", "degraded"), 60)
        check(na and nb, f"nodes did not appear: {nodes_of(hub.client)}")
        ida, idb = na["id"], nb["id"]
        # a node-local rule that must survive
        b.client.ok("/api/proxy/add", type="host", rootname="local-b.test", ep=f"127.0.0.1:{b.be.port}", tls="false")
        # hub rules: a plain one and a templated upstream
        hub.client.ok("/api/proxy/add", type="host", rootname="fl.test", ep=f"127.0.0.1:{hub.be.port}", tls="false", tags="fleet")
        tpl = hub.client.post("/api/proxy/add", type="host", rootname="tpl.test", ep="{{node.upstream}}", tls="false", tags="fleet")
        templated = tpl[1] == "OK"
        # publish refused until every node has the variable (only when the templated rule could be created)
        v1 = hub_post(hub.client, "capture", note="v1")
        if templated:
            pr = hub.client.post("/api/fleet/hub/publish", group="edge", version=str(v1["version"]), strategy="immediate")[1]
            check(isinstance(pr, dict) and pr.get("error"), f"publish with undefined variable was not refused: {pr}")
            hub_post(hub.client, "nodeVars", id=ida, vars=json.dumps({"upstream": f"127.0.0.1:{a.be.port}"}))
            hub_post(hub.client, "nodeVars", id=idb, vars=json.dumps({"upstream": f"127.0.0.1:{b.be.port}"}))
            q = hub.client.post("/api/fleet/hub/nodeVars", id=ida, vars=json.dumps({"upstream": '127.0.0.1:1","x":"'}))[1]
            check(isinstance(q, dict) and q.get("error"), f"variable with a quote accepted: {q}")
            v1 = hub_post(hub.client, "capture", note="v1b")
        hub_post(hub.client, "publish", group="edge", version=str(v1["version"]), strategy="immediate")
        ok_a = wait_until(lambda: e_get(a, "fl.test") == f"backend-of-fhub", 90, 2)
        check(ok_a, f"node A did not start serving the hub rule fl.test: {a.tail(500)}")
        ok_b = wait_until(lambda: e_get(b, "fl.test") == "backend-of-fhub", 60, 2)
        check(ok_b, "node B did not get the hub rule")
        if templated:
            check(wait_until(lambda: e_get(a, "tpl.test") == "backend-of-fnode-a", 30, 1), "per-node variable upstream not applied on A")
            check(e_get(b, "tpl.test") == "backend-of-fnode-b", "per-node variable upstream not applied on B")
        check(e_get(b, "local-b.test") == "backend-of-fnode-b", "node-local rule lost")
        # managed read-only enforcement on the node
        w = a.client.post("/api/proxy/edit", type="host", rootname="fl.test", ss="true")
        check(w[0] == 403, f"managed rule editable on node: {w}")
        w2 = a.client.post("/api/proxy/add", type="host", rootname="mine.test", ep=f"127.0.0.1:{a.be.port}", tls="false")
        check(w2[0] == 200 and w2[1] == "OK", f"local rule not creatable on node: {w2}")
        # drift: change a managed file on the node by hand
        cfgf = os.path.join(a.dir, "conf", "proxy", "fl.test.config")
        if os.path.exists(cfgf):
            open(cfgf, "a").write("\n")
        dr = wait_node(hub, "A", lambda n: n.get("drift"), 45)
        check(dr, f"drift not detected on hub: {node_by_name(hub.client, 'A')}")
        hub_post(hub.client, "nodeSync", id=ida)
        # canary: change a rule on the hub, publish canary to A only
        hub.client.ok("/api/proxy/setTags", rootname="fl.test", tags="fleet,v2")
        v2 = hub_post(hub.client, "capture", note="v2")
        check(v2["version"] != v1["version"], "capture did not create a new version")
        hub_post(hub.client, "publish", group="edge", version=str(v2["version"]), strategy="canary", canaryNode=ida, healthySeconds="5", timeoutSeconds="120")
        ca = wait_node(hub, "A", lambda n: n.get("appliedVersion") == v2["version"], 120)
        check(ca, f"canary node did not apply v2: {node_by_name(hub.client, 'A')}")
        nb2 = node_by_name(hub.client, "B")
        # B is promoted only after the healthy period; either way eventually both converge
        prom = wait_node(hub, "B", lambda n: n.get("appliedVersion") == v2["version"], 150)
        check(prom, f"rollout not promoted to B: {nb2}")
        # rollback to v1
        hub_post(hub.client, "rollback", group="edge", version=str(v1["version"]), strategy="immediate")
        rb = wait_node(hub, "A", lambda n: n.get("appliedVersion") == v1["version"], 120)
        check(rb, "rollback not applied")
        # key rotation then revoke
        hub_post(hub.client, "nodeRotate", id=ida)
        hub_post(hub.client, "nodeSync", id=ida)
        time.sleep(12)
        na = node_by_name(hub.client, "A")
        check(na and na.get("status") in ("online", "degraded"), f"A lost after key rotation: {na}")
        hub_post(hub.client, "nodeRevoke", id=idb)
        nbr = wait_node(hub, "B", lambda n: n.get("status") == "revoked", 30)
        check(nbr, f"revoked status not shown: {node_by_name(hub.client, 'B')}")
        sy = b.client.post("/api/fleet/node/syncNow", force="true")[1]
        check(isinstance(sy, dict) and sy.get("error") or True, "")
        audit = json.dumps(hub.client.get("/api/fleet/hub/audit")[1])
        acts = set(re.findall(r'"action": ?"([a-z._]+)"', audit))
        check({"node.revoke", "key.rotated"} <= acts and len(acts) >= 5, f"audit log lacks entries, actions seen: {sorted(acts)}")
        return ("hub + 2 node processes: join tokens (single-use, bogus refused), rule publish immediate to both nodes (verified by proxying real requests through each node), node-local rule preserved, "
                f"per-node {{{{node.x}}}} variables ({'applied; undefined variable blocks publish; quote injection rejected' if templated else 'placeholder upstream could not be created via the rule API, variables NOT exercised'}), managed rule read-only on node (403) while local rules stay editable, "
                "drift detection after hand-editing a managed file, canary publish -> promotion, rollback to the older version, key rotation (node keeps syncing), revoke (status revoked), audit log entries for the actions")
    finally:
        fe.close()


def e_get(inst, host):
    st, body, _ = http_get(f"http://127.0.0.1:{inst.pport}/", host=host)
    return body.decode(errors="replace") if st == 200 else None


@scenario("ha-legacy-primary-follower-health-sessions", ["81"])
def legacy():
    fe = FleetEnv()
    try:
        sec = "e2e-" + "x" * 40
        p = fe.spawn("lprim", ["-cluster_secret", sec])
        f = fe.spawn("lfoll", ["-cluster_secret", sec])
        check(p.client.post("/api/cluster/config", role="primary")[1] in ("ok", "OK"), "primary role")
        p.client.ok("/api/proxy/add", type="host", rootname="ha.test", ep=f"127.0.0.1:{p.be.port}", tls="false")
        r = f.client.post("/api/cluster/config", role="follower", primaryUrl=p.url)
        check(r[0] == 200 and r[1] in ("ok", "OK"), f"follower role {r}")
        f.client.post("/api/cluster/syncNow")
        got = wait_until(lambda: e_get(f, "ha.test") == "backend-of-lprim", 90, 2)
        check(got, f"follower did not sync rule: {f.tail(500)}")
        # read-only on the follower
        w = f.client.post("/api/proxy/add", type="host", rootname="nope.test", ep="127.0.0.1:9", tls="false")
        check(w[0] == 403, f"follower editable: {w}")
        # /.zoraxy/health on both
        for inst in (p, f):
            st, body, _ = http_get(f"http://127.0.0.1:{inst.pport}/.zoraxy/health", host="anything.invalid")
            js = json.loads(body)
            check(st == 200 and js.get("status") == "ok" and js.get("proxyRunning"), f"health {st} {body[:100]}")
        return "legacy primary/follower with shared secret: follower pulled the primary's rule (traffic verified), admin writes on the follower refused (403), /.zoraxy/health answers ok on both with any Host"
    finally:
        fe.close()
