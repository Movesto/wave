"""Auth Synthesizer — get an authenticated session for the DAST stage.

Registers a dummy user (best-effort common fields, covering the union across frameworks) then logs
in, capturing a session cookie (through redirects, via a cookie jar) or a bearer token. Returns auth
headers to inject into exploit requests. gap-B: can provision multiple identities for authorization
tests. Deterministic first pass; the model refines field/flow discovery for non-trivial auth (SSO)
in a later version -- SSO-only apps DEFER.
"""
import json
import http.cookiejar
import urllib.request
import urllib.parse
import urllib.error

_PW = "WavePass_123"
# union of field names across frameworks; extra fields are ignored by handlers that don't use them
_DUMMY = {"firstName": "Wave", "lastName": "User", "password": _PW, "verify": _PW,
          "confirm": _PW, "password2": _PW, "op": "basic"}


def _find(routes, *keywords):
    for r in routes:
        if r.method == "POST" and any(k in r.path.lower() for k in keywords):
            return r
    return None


def _post(opener, url, data, form):
    if form:
        body = urllib.parse.urlencode(data).encode()
        ct = "application/x-www-form-urlencoded"
    else:
        body = json.dumps(data).encode()
        ct = "application/json"
    req = urllib.request.Request(url, data=body, headers={"Content-Type": ct}, method="POST")
    try:
        with opener.open(req, timeout=8) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers
    except Exception as e:
        return None, str(e), None


def _creds(username):
    c = dict(_DUMMY)
    for k in ("userName", "username", "user", "login"):
        c[k] = username
    c["email"] = f"{username}@wave.test"
    return c


def synthesize_multi(rt, routes, n=2):
    """Register + log in `n` DISTINCT identities for the differential (IDOR/authz) oracle. Each gets
    its own cookie jar / session via a separate synthesize() call. Returns a list of
    {"username":.., "auth":{..}} for identities that authenticated (may be shorter than n)."""
    users = []
    for i in range(1, n + 1):
        uname = f"waveuser{i}"
        a = synthesize(rt, routes, username=uname)
        if a:
            users.append({"username": uname, "auth": a})
    return users


def synthesize(rt, routes, username="waveuser1"):
    """Register + log in one identity. Returns auth headers ({"Cookie":..}|{"Authorization":..}) or {}."""
    base = rt.base_url.rstrip("/")
    login = _find(routes, "login", "signin", "auth")
    signup = _find(routes, "signup", "register", "users/basic", "user/create")
    if not login:
        return {}
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    creds = _creds(username)

    if signup:
        for form in (True, False):
            _post(opener, base + "/" + signup.path.lstrip("/"), creds, form)

    login_body = {"userName": username, "username": username, "user": username,
                  "password": _PW, "op": "basic"}
    for form in (True, False):
        status, body, headers = _post(opener, base + "/" + login.path.lstrip("/"), login_body, form)
        cookie = "; ".join(f"{c.name}={c.value}" for c in jar)
        if cookie:
            return {"Cookie": cookie}
        if headers:                                        # bearer in the response header (e.g. brokencrystals)
            a = headers.get("Authorization") or headers.get("authorization")
            if a:
                return {"Authorization": a if a.lower().startswith("bearer") else "Bearer " + a}
        for key in ("auth_token", "token", "access_token", "jwt"):
            try:
                t = json.loads(body).get(key)
                if t:
                    return {"Authorization": "Bearer " + t}
            except Exception:
                pass
    return {}
