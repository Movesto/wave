"""IDOR / broken-object-level-authorization oracle (differential).

Injection oracles watch a SINK; IDOR has no sink -- it's a MISSING ownership check. So the candidate
source is different: routes that expose a user-OWNED resource through an id parameter. The MODEL
judges which id-routes are user-owned/private (a data-sensitivity call); the differential oracle then
proves the breach deterministically -- an authenticated attacker who can pull MULTIPLE distinct
owners' resources through the id param owns at most one, so the rest are unauthorized access.

Soundness note (per design discussion): the cross-user ACCESS is proven deterministically, but
whether it is a *vulnerability* rests on the model's "is this resource private" judgment -- so IDOR
findings carry that flag and are NOT pure Tier-1 (they warrant the owner-judgment for confirmation).
"""
import hashlib
import json
import re

from . import exploit
from .models import Candidate

_PARAM = re.compile(r"[:{]([A-Za-z_]\w*)\}?")
_ID_NAME = re.compile(r"(id$|(^|_)(id|user|account|owner|order|invoice|doc|file|record|num|key|uuid|slug))", re.I)


def id_param_routes(routes):
    """Routes with a path parameter whose name looks like a resource id (the IDOR attack surface)."""
    out = []
    for r in routes:
        m = _PARAM.search(r.path)
        if m and _ID_NAME.search(m.group(1)):
            out.append(r)
    return out


_SYS = (
    "You are triaging web routes for BROKEN OBJECT-LEVEL AUTHORIZATION (IDOR/BOLA). Each route takes "
    "an id-like path parameter. Decide which return a USER-OWNED / PRIVATE resource -- one user must "
    "NOT be able to read another user's copy (e.g. a user's allocations, invoices, messages, profile) "
    "-- versus a PUBLIC resource where any id is meant to be viewable by anyone (e.g. a product, a "
    "blog post, a public catalog entry). Output ONLY a JSON array of the PRIVATE ones (empty [] if "
    'none), each: {"method":"..","path":"..the exact path.."}. No prose.')


def flag_owned(model, id_routes):
    """Model judges which id-routes are user-owned/private. Returns the private subset of `id_routes`."""
    if not id_routes:
        return []
    listing = "\n".join(f"{r.method} {r.path}" for r in id_routes)
    txt = model.generate(_SYS, "Routes with an id parameter:\n" + listing,
                         max_new_tokens=700, temperature=0.1)
    m = re.search(r"(\[.*\])", (txt or "").split("</think>")[-1], re.S)
    private = set()
    if m:
        try:
            for d in json.loads(m.group(1)):
                if isinstance(d, dict) and d.get("path"):
                    private.add(str(d["path"]))
        except Exception:
            pass
    return [r for r in id_routes if r.path in private]


def _fp(body):
    """Fingerprint a response body by owner-content: strip long tokens (csrf/session/hex) and collapse
    whitespace, but KEEP the data (amounts/names) that differs between owners."""
    b = re.sub(r"[0-9a-fA-F]{16,}", "", body or "")     # csrf/session/hex tokens vary per-request, not per-owner
    b = re.sub(r"\s+", " ", b).strip()
    return hashlib.sha1(b.encode("utf-8", "replace")).hexdigest()


def prove_idor(rt, route, auth, id_values=range(1, 7)):
    """Differential: fire `route` as the authenticated attacker across `id_values`. If the attacker
    pulls >=2 DISTINCT real resources through the id param, they read resources they don't own -> IDOR.
    A secure app returns only the attacker's own (others denied/redirected) or ignores the id (same
    body) -> <2 distinct -> not proven."""
    pm = _PARAM.search(route.path)
    if not pm:
        return {"status": "not-proven", "cwe": "CWE-639", "notes": "no id param in route"}
    pn = pm.group(1)
    seen, detail = {}, []
    for i in id_values:
        req = exploit.assemble({"method": route.method, "route": route.path,
                                "vector": "path", "param": pn, "value": str(i)}, str(i))
        st, body = exploit.fire(rt.base_url, req["method"], req["path"], req["body"],
                                headers=dict(auth or {}))
        detail.append((i, st, len(body or "")))
        if st == 200 and body and len(body) >= 200:
            seen.setdefault(_fp(body), i)
    if len(seen) >= 2:
        ids = sorted(seen.values())
        return {"status": "proven", "cwe": "CWE-639", "oracle": "differential",
                "payload": f"{pn} in {ids}", "request": f"{route.method} {route.path}",
                "evidence": (f"attacker read {len(seen)} distinct user-owned resources via {pn} at "
                             f"ids {ids} (cross-user access proven; owner-judgment: private/model)")}
    return {"status": "not-proven", "cwe": "CWE-639",
            "notes": f"attacker saw {len(seen)} distinct resource(s); need >=2 for cross-owner. {detail[:6]}"}


def candidate_for(route):
    """A Finding-compatible Candidate for an IDOR route (no static sink -- the route IS the surface)."""
    return Candidate(file=route.file, unit=route.function or "<handler>", line=0, cwe="CWE-639",
                     family="IDOR / broken object authorization", detector="differential",
                     sink=f"{route.method} {route.path}", provable=True, rank=50,
                     route_hint=f"{route.method} {route.path}")
