"""Shared scenario fixtures."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import lib
from lib import *  # noqa
import time


class Env:
    """noauth instance + proxy on its own plain-HTTP port; context-manager cleans up."""

    def __init__(self, name="env", noauth=True, flags=(), env=None, backend_handler=None):
        self.backend = Recorder(backend_handler or (lambda r: (200, {"X-Backend": "1"}, "backend-ok " + r["path"])))
        self.pport = alloc_port()
        self.inst = Instance(name, noauth=noauth, flags=["-default_inbound_port", str(self.pport)] + list(flags), env=env)
        self.extra = []

    def __enter__(self):
        self.inst.start()
        self.c = self.inst.client
        self.c.ok("/api/cert/tls", set="false")
        return self

    def __exit__(self, *a):
        self.inst.cleanup()
        self.backend.stop()
        for x in self.extra:
            x.stop()
        free_port(self.pport)

    def add_rule(self, host, upstream=None, **kw):
        form = dict(type="host", rootname=host, ep=upstream or f"127.0.0.1:{self.backend.port}", tls="false")
        form.update(kw)
        r = self.c.post("/api/proxy/add", **form)
        check(r[0] == 200 and r[1] == "OK", f"add {host}: {r}")
        time.sleep(0.3)

    def req(self, host, path="/", headers=None, port=None):
        return http_get(f"http://127.0.0.1:{port or self.pport}{path}", headers=headers, host=host)

    def rule(self, host):
        st, js = self.c.get("/api/proxy/detail", type="host", epname=host)
        return js
