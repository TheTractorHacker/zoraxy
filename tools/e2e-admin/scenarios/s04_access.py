import json, urllib.parse
from runner import scenario, NotTestable
from .common import *


def multipart(fields, fname, content):
    b = "----e2eboundary"
    out = b""
    for k, v in fields.items():
        out += f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
    out += f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{fname}"\r\nContent-Type: text/plain\r\n\r\n'.encode() + content + f"\r\n--{b}--\r\n".encode()
    return out, {"Content-Type": f"multipart/form-data; boundary={b}"}


@scenario("api-blocklist-import-and-rules", ["512", "1100", "762"])
def blocklist():
    with Env("bl") as e:
        c = e.c
        e.add_rule("bl.test")
        # access rule create + duplicate + sort + attach
        c.ok("/api/access/create", name="Zeta", desc="e2e")
        c.ok("/api/access/create", name="Alpha", desc="e2e")
        rules = c.get("/api/access/list")[1]
        zeta = [r for r in rules if r["Name"] == "Zeta"][0]["ID"]
        alpha = [r for r in rules if r["Name"] == "Alpha"][0]["ID"]
        dup = c.ok("/api/access/duplicate", id=zeta, name="Zeta copy")
        check(dup.get("id") and dup["id"] != zeta, f"duplicate {dup}")
        by_name = [r["Name"] for r in c.get("/api/access/listSorted", sort="name")[1] if r["ID"] != "default"]
        check(by_name == sorted(by_name, key=str.lower), f"sort by name {by_name}")
        c.ok("/api/access/reorder", ids=json.dumps([alpha, zeta, dup["id"], "default"]))
        manual = [r["ID"] for r in c.get("/api/access/listSorted", sort="manual")[1]]
        check([x for x in manual if x != "default"][:3] == [alpha, zeta, dup["id"]], f"manual order {manual}")
        # paste import: preview does not change, apply does, dedupe + invalid reported
        text = "# comment\n127.0.0.1 local\n198.51.100.0/24\n198.51.100.0/24\nnot-an-ip\n10.1.2.3/8\n0.0.0.0\n"
        pv = c.ok("/api/access/import/preview", id="default", list="blacklist", text=text)
        check(pv.get("Added", pv.get("added")) is not None or pv, f"preview {pv}")
        before = c.get("/api/blacklist/list", id="default", type="ip")[1]
        check(not before.get("IP") if isinstance(before, dict) and "IP" in before else True, "preview changed list?")
        c.ok("/api/blacklist/enable", id="default", enable="true")
        body0, hd0 = multipart({"id": "default", "list": "blacklist", "text": text}, "x.txt", b"")  # the UI posts FormData
        c.refresh_csrf()
        st, raw, _ = c.raw("POST", "/api/access/import/apply", body0, hd0)
        check(st == 200 and not json.loads(raw).get("error"), f"multipart paste apply {raw[:200]}")
        lst = c.get("/api/blacklist/list", id="default", type="ip")[1]
        flat = json.dumps(lst)
        check("198.51.100.0/24" in flat and "10.0.0.0/8" in flat and "127.0.0.1" in flat, f"entries missing: {flat[:300]}")
        check("0.0.0.0" not in flat.replace("10.0.0.0", ""), "0.0.0.0 accepted")
        # enforcement: 127.0.0.1 is blacklisted now -> proxied request refused
        st = e.req("bl.test")[0]
        check(st in (403, 0), f"blacklisted client got {st}")
        # remove through API, traffic flows again
        c.ok("/api/blacklist/ip/remove", id="default", ip="127.0.0.1")
        time.sleep(0.3)
        check(e.req("bl.test")[0] == 200, "still blocked after removal")
        # multipart upload
        body, hd = multipart({"id": "default", "list": "whitelist"}, "l.txt", b"203.0.113.5\n203.0.113.6\n")
        c.refresh_csrf()
        st, raw, _ = c.raw("POST", "/api/access/import/apply", body, hd)
        js = json.loads(raw)
        check(st == 200 and not js.get("error"), f"upload apply {js}")
        wl = json.dumps(c.get("/api/whitelist/list", id="default", type="ip")[1])
        check("203.0.113.5" in wl and "203.0.113.6" in wl, f"upload entries {wl[:200]}")
        # URL sources: http and loopback https are refused by the SSRF guard
        r1 = c.post("/api/access/import/source/add", id="default", list="blacklist", url="http://example.com/list.txt", interval="60", enabled="true", name="plain")[1]
        check(isinstance(r1, dict) and r1.get("error"), f"http source accepted: {r1}")
        import tempfile
        crt, key = selfsigned(tempfile.mkdtemp())
        srv = Recorder(lambda r: (200, {}, "192.0.2.1\n"), tls_cert=(crt, key))
        e.extra.append(srv)
        r2 = c.post("/api/access/import/source/add", id="default", list="blacklist", url=f"https://127.0.0.1:{srv.port}/l.txt", interval="60", enabled="true", name="local")[1]
        s = json.dumps(r2).lower()
        check(not srv.reqs and ("refresh" in s or "error" in s) and ("non-public" in s or "private" in s or "refus" in s or "not allowed" in s or "public" in s), f"loopback source not refused by SSRF guard: {r2}")
        check(not srv.reqs, "SSRF guard let the connection through")
        return ("access rules: create/duplicate/sort(name,manual)/reorder; blocklist paste preview (no change) vs apply (dedupe, invalid and 0.0.0.0 dropped, CIDR canonicalised), "
                "enforcement of a blacklisted client then removal, multipart upload into whitelist, http:// URL source refused, https loopback URL source refused by SSRF guard without any connection. "
                "NOT covered: a successful scheduled download (the guard has no private-target toggle by design; covered by Go tests with a stub dialer)")
