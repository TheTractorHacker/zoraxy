"""Fake identity providers used by the auth scenarios."""
import base64
import hashlib
import json
import os
import subprocess
import tempfile
import threading
import urllib.parse

from lib import Backend, openssl, send, free_port


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class FakeIdP:
    """Minimal OpenID Provider: discovery, JWKS, /authorize (auto-approves), /token (RS256 id_token).

    .users: dict code -> claims is filled by /authorize; set .claims_for(client_id) to control claims.
    """

    def __init__(self, name, claims=None):
        self.name = name
        self.dir = tempfile.mkdtemp(prefix="zx-idp-")
        openssl("genrsa", "-out", "key.pem", "2048", cwd=self.dir)
        mod = openssl("rsa", "-in", "key.pem", "-noout", "-modulus", cwd=self.dir).stdout.decode().strip().split("=")[1]
        self.n = b64u(bytes.fromhex(mod))
        self.e = "AQAB"
        self.kid = "k-" + name
        self.claims = claims or {"sub": "u-1", "email": "alice@example.com", "email_verified": True, "name": "Alice", "groups": ["staff"]}
        self.codes = {}
        self.authorize_log = []
        self.token_log = []
        outer = self

        def handler(h, rec, b):
            u = urllib.parse.urlsplit(rec["path"])
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            if u.path == "/.well-known/openid-configuration":
                base = outer.base
                send(h, 200, json.dumps({"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token",
                                         "jwks_uri": base + "/jwks", "userinfo_endpoint": base + "/userinfo", "end_session_endpoint": base + "/logout",
                                         "response_types_supported": ["code"], "id_token_signing_alg_values_supported": ["RS256"],
                                         "code_challenge_methods_supported": ["S256"], "subject_types_supported": ["public"]}), ctype="application/json")
            elif u.path == "/jwks":
                send(h, 200, json.dumps({"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": outer.kid, "n": outer.n, "e": outer.e}]}), ctype="application/json")
            elif u.path == "/authorize":
                outer.authorize_log.append(q)
                code = "code-%d" % (len(outer.codes) + 1)
                outer.codes[code] = dict(nonce=q.get("nonce"), client_id=q.get("client_id"), challenge=q.get("code_challenge"), redirect_uri=q.get("redirect_uri"))
                loc = q["redirect_uri"] + ("&" if "?" in q["redirect_uri"] else "?") + urllib.parse.urlencode({"code": code, "state": q.get("state", "")})
                send(h, 302, "", {"Location": loc})
            elif u.path == "/token":
                form = {k: v[0] for k, v in urllib.parse.parse_qs(rec["body"].decode()).items()}
                outer.token_log.append(form)
                c = outer.codes.pop(form.get("code"), None)
                if not c:
                    send(h, 400, json.dumps({"error": "invalid_grant"}), ctype="application/json")
                    return
                if c.get("challenge"):
                    ver = form.get("code_verifier", "")
                    if b64u(hashlib.sha256(ver.encode()).digest()) != c["challenge"]:
                        send(h, 400, json.dumps({"error": "invalid_grant", "error_description": "pkce"}), ctype="application/json")
                        return
                import time
                claims = dict(outer.claims, iss=outer.base, aud=c["client_id"], iat=int(time.time()), exp=int(time.time()) + 600)
                if c["nonce"]:
                    claims["nonce"] = c["nonce"]
                send(h, 200, json.dumps({"access_token": "at-" + form.get("code", ""), "token_type": "Bearer", "expires_in": 600,
                                         "id_token": outer.sign(claims)}), ctype="application/json")
            elif u.path == "/userinfo":
                send(h, 200, json.dumps(outer.claims), ctype="application/json")
            else:
                send(h, 404, "no")

        self.backend = Backend(handler, name="idp-" + name)

    @property
    def base(self):
        return "http://127.0.0.1:%d" % self.backend.port

    def sign(self, claims):
        header = b64u(json.dumps({"alg": "RS256", "typ": "JWT", "kid": self.kid}).encode())
        payload = b64u(json.dumps(claims).encode())
        msg = (header + "." + payload).encode()
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", os.path.join(self.dir, "key.pem")], input=msg, capture_output=True, check=True).stdout
        return header + "." + payload + "." + b64u(sig)

    def close(self):
        self.backend.close()
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
