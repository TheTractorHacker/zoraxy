import json
from runner import scenario
from .common import *


@scenario("proxy-rule-lifecycle-api", [])
def proxy_lifecycle():
    with Env("px") as e:
        c = e.c
        e.add_rule("a.test", tags="web,prod")
        st, body, hd = e.req("a.test", "/x")
        check(st == 200 and b"backend-ok /x" in body, f"proxied: {st} {body}")
        check(e.backend.reqs[-1]["headers"].get("Host") in ("a.test", f"127.0.0.1:{e.backend.port}"), "host header")
        # edit: change upstream to a second backend, verify traffic moves
        b2 = Recorder(lambda r: (200, {}, "second"))
        e.extra.append(b2)
        st, js = c.post("/api/proxy/edit", type="host", rootname="a.test", ss="true")
        check(st == 200 and not (isinstance(js, dict) and js.get("error")), f"edit: {st} {js}")
        check(c.post("/api/proxy/detail", type="host", epname="a.test")[1].get("UseStickySession") is True, "edit not persisted")
        c.ok("/api/proxy/upstream/add", ep="a.test", origin=f"127.0.0.1:{b2.port}", tls="false", active="true")
        c.ok("/api/proxy/upstream/remove", ep="a.test", origin=f"127.0.0.1:{e.backend.port}")
        time.sleep(0.4)
        st, body, _ = e.req("a.test")
        check(body == b"second", f"after edit: {body}")
        # toggle off => not 200 backend; on again
        c.ok("/api/proxy/toggle", ep="a.test", enable="false")
        time.sleep(0.3)
        st, body, _ = e.req("a.test")
        check(body != b"second", "disabled rule still served")
        c.ok("/api/proxy/toggle", ep="a.test", enable="true")
        time.sleep(0.3)
        check(e.req("a.test")[1] == b"second", "re-enabled rule not served")
        # tags via list
        st, lst = c.get("/api/proxy/list", type="host")
        row = [r for r in lst if r.get("RootOrMatchingDomain") == "a.test"]
        check(row and sorted(row[0].get("Tags") or []) == ["prod", "web"], f"tags {row and row[0].get('Tags')}")
        # delete
        c.ok("/api/proxy/del", ep="a.test")
        time.sleep(0.3)
        st, lst = c.get("/api/proxy/list", type="host")
        check(not [r for r in lst if r.get("RootOrMatchingDomain") == "a.test"], "rule still listed after delete")
        check(e.req("a.test")[1] != b"second", "deleted rule still served")
        return "add -> proxied traffic -> edit upstream -> toggle off/on -> tags in list -> delete, each verified with real HTTP through the proxy port"


@scenario("proxy-connection-test-and-template", [])
def conn_test_template():
    with Env("pxt") as e:
        c = e.c
        st, js = c.get("/api/proxy/testupstream", url=f"127.0.0.1:{e.backend.port}")
        check(st == 200 and js.get("ok") and js.get("protocol") == "http" and js.get("status") == 200, f"testupstream live: {js}")
        dead = alloc_port()
        free_port(dead)
        st, js = c.get("/api/proxy/testupstream", url=f"127.0.0.1:{dead}")
        check(js.get("ok") is False and js.get("error"), f"testupstream dead: {js}")
        # https upstream with self-signed cert
        import tempfile
        d = tempfile.mkdtemp()
        crt, key = selfsigned(d)
        tlsb = Recorder(tls_cert=(crt, key))
        e.extra.append(tlsb)
        st, js = c.get("/api/proxy/testupstream", url=f"https://127.0.0.1:{tlsb.port}")
        check(js.get("ok") and js.get("protocol") == "https" and js.get("selfsign") is True, f"testupstream tls selfsign: {js}")
        # templates
        st, tl = c.get("/api/proxy/templates/list")
        check(st == 200 and isinstance(tl, list) and any(t.get("Builtin") for t in tl), f"builtin templates {tl!r:.200}")
        name = tl[0]["Name"]
        # custom template save + apply on add + bulk dry run
        tpl = {"Name": "e2e-tpl", "Description": "e2e", "Tags": ["fromtpl"]}
        st, js = c.post("/api/proxy/templates/save", template=json.dumps(tpl))
        check(st == 200 and not (isinstance(js, dict) and js.get("error")), f"template save {js}")
        e.add_rule("t.test", template="e2e-tpl")
        st, lst = c.get("/api/proxy/list", type="host")
        row = [r for r in lst if r.get("RootOrMatchingDomain") == "t.test"][0]
        check("fromtpl" in (row.get("Tags") or []), f"template tag applied: {row.get('Tags')}")
        e.add_rule("t2.test")
        st, js = c.post("/api/proxy/bulk", rules=json.dumps(["t.test", "t2.test"]), action="add_tags", params=json.dumps({"Tags": ["bulk1"]}), dryrun="true")
        check(st == 200 and len(js["results"]) == 2 and all(r["OK"] for r in js["results"]), f"bulk dry {js}")
        st, lst = c.get("/api/proxy/list", type="host")
        check(not any("bulk1" in (r.get("Tags") or []) for r in lst), "dry run changed rules")
        st, js = c.post("/api/proxy/bulk", rules=json.dumps(["t.test", "t2.test"]), action="add_tags", params=json.dumps({"Tags": ["bulk1"]}))
        st, lst = c.get("/api/proxy/list", type="host")
        check(sum("bulk1" in (r.get("Tags") or []) for r in lst) == 2, "bulk apply")
        st, js = c.post("/api/proxy/bulk", rules=json.dumps(["t.test", "t2.test"]), action="disable")
        time.sleep(0.3)
        check(e.req("t2.test")[1] != b"backend-ok /", "bulk disable ineffective")
        st, js = c.post("/api/proxy/bulk", rules=json.dumps(["t.test", "t2.test"]), action="delete", params=json.dumps({"Confirm": True}))
        st, lst = c.get("/api/proxy/list", type="host")
        check(not [r for r in lst if r["RootOrMatchingDomain"] in ("t.test", "t2.test")], "bulk delete")
        c.ok("/api/proxy/templates/delete", name="e2e-tpl")
        return "testupstream (live/dead/self-signed TLS), custom template applied on add, bulk dry-run/apply/disable/delete verified via list + traffic"
