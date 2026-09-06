"""OAST (out-of-band) canary -- the async / blind / egress oracle.

Synchronous sink hooks miss vulns whose effect is OUT-OF-BAND or DEFERRED: egress via a client we
didn't wrap (a spawned `curl`, a raw socket, a DNS lookup), and especially STORED / SECOND-ORDER
payloads that fire minutes later in a background worker or an admin's browser. The canary is a
listener the target can call back to: the agent plants a unique token in a payload and moves on; a
callback -- whenever it arrives -- is a HARD deterministic witness (the app reached attacker-
controlled infrastructure). Same idea as the instrumented sink, but the witness is a network hit
instead of a log line, so it survives asynchrony and non-hooked egress.

Grey-box (Mode 1): a LOCAL listener reachable from the sandbox container via `host.docker.internal`.
Black-box (Mode 2): the same interface, backed by a public canary (see §16 / §14 #22).
"""
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Host name a Docker-Desktop container uses to reach a listener on the host.
CONTAINER_TO_HOST = "host.docker.internal"


class Canary:
    def __init__(self, port=0):
        self.port = port
        self.hits = {}          # token -> [ {path, method, client, t}, ... ]
        self._srv = None

    def _handler_cls(self):
        canary = self

        class _H(BaseHTTPRequestHandler):
            def _record(self):
                # token = first path segment (case-insensitive; hosts/paths may be lowercased)
                tok = self.path.strip("/").split("/", 1)[0].split("?", 1)[0].lower()
                canary.hits.setdefault(tok, []).append(
                    {"path": self.path, "method": self.command,
                     "client": self.client_address[0], "t": time.time()})
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = _record
            do_POST = _record
            do_PUT = _record

            def log_message(self, *a):      # silence the default stderr access log
                pass

        return _H

    def start(self):
        self._srv = ThreadingHTTPServer(("0.0.0.0", self.port), self._handler_cls())
        self.port = self._srv.server_address[1]      # resolve an OS-assigned port when port=0
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self):
        if self._srv:
            try:
                self._srv.shutdown()
            except Exception:
                pass

    def new_token(self):
        return "wz" + secrets.token_hex(4)           # lowercase: survives hostname lowercasing

    def url(self, token, host=CONTAINER_TO_HOST):
        """A callback URL the TARGET (in its container) can reach on the host listener."""
        return f"http://{host}:{self.port}/{token}"

    def hit(self, token, wait=4.0):
        """Poll for a callback carrying `token` (async payloads may arrive after a delay)."""
        end = time.time() + wait
        token = token.lower()
        while time.time() < end:
            if self.hits.get(token):
                return self.hits[token]
            time.sleep(0.3)
        return self.hits.get(token)
