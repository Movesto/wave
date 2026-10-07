"""HTTP-layer posture + content discovery -- the red-teamer's checklist against the web endpoint itself,
beyond injection: how it identifies itself (fingerprint), what defenses it is MISSING (security headers,
cookie flags, CORS, dangerous methods), and what it should not be exposing (/.git, /.env, admin panels,
API specs, backups).

All analyzers are PURE functions over already-fetched response data (headers / bodies), so they are
unit-tested offline; the driver does the fetching. Verdict guidance per finding: concrete exposures
(source/secret/spec reachable) are `confirmed`; posture weaknesses (missing header, weak cookie, CORS
reflection) are `anomalous_state` -- real and observed, but the risk is a judgment.
"""
from __future__ import annotations

import re

# ---------- fingerprint ----------

_TECH_HEADERS = {"server": "server", "x-powered-by": "powered-by", "x-aspnet-version": "asp.net",
                 "x-aspnetmvc-version": "asp.net-mvc", "x-generator": "generator", "via": "proxy",
                 "x-runtime": "rails", "x-drupal-cache": "drupal", "x-varnish": "varnish"}
_BODY_TECH = ((re.compile(r"wp-content|wp-includes", re.I), "WordPress"),
              (re.compile(r"/sites/default/files|Drupal\.settings", re.I), "Drupal"),
              (re.compile(r"csrf-token|rails", re.I), "Rails"),
              (re.compile(r"__NEXT_DATA__", re.I), "Next.js"),
              (re.compile(r"ng-version=", re.I), "Angular"),
              (re.compile(r"window\.__NUXT__", re.I), "Nuxt"))


def fingerprint(headers, body=""):
    """Tech/stack hints from response headers + body markers (pure). Returns a sorted list of 'label=value'."""
    h = {str(k).lower(): v for k, v in (headers or {}).items()}
    out = []
    for hk, label in _TECH_HEADERS.items():
        if h.get(hk):
            out.append(f"{label}={h[hk]}")
    for rx, name in _BODY_TECH:
        if rx.search(body or ""):
            out.append(f"framework={name}")
    return sorted(set(out))


# ---------- security headers ----------

# header -> (what its absence costs, CWE). Checked on an HTML/200 response.
_SEC_HEADERS = {
    "strict-transport-security": ("no HSTS -- downgrade / SSL-strip exposure", "CWE-319"),
    "content-security-policy": ("no CSP -- no defense-in-depth against XSS/injection", "CWE-693"),
    "x-frame-options": ("no X-Frame-Options (and no CSP frame-ancestors) -- clickjacking", "CWE-1021"),
    "x-content-type-options": ("no X-Content-Type-Options: nosniff -- MIME sniffing", "CWE-693"),
    "referrer-policy": ("no Referrer-Policy -- referer leakage", "CWE-200"),
}


def security_headers(headers, is_https=True):
    """Missing protective headers (pure). Returns [(note, cwe), ...]. HSTS is only flagged on HTTPS;
    X-Frame-Options is satisfied by a CSP frame-ancestors directive."""
    h = {str(k).lower(): v for k, v in (headers or {}).items()}
    csp = h.get("content-security-policy", "")
    out = []
    for hk, (note, cwe) in _SEC_HEADERS.items():
        if hk == "strict-transport-security" and not is_https:
            continue
        if hk == "x-frame-options" and "frame-ancestors" in csp.lower():
            continue
        if hk not in h:
            out.append((note, cwe))
    return out


# ---------- cookies ----------

def cookie_flags(set_cookie_headers, is_https=True):
    """Weak cookie flags (pure). `set_cookie_headers` is a list of Set-Cookie values. Returns
    [(note, cwe), ...] for cookies missing HttpOnly / Secure / SameSite."""
    out = []
    for sc in (set_cookie_headers or []):
        name = sc.split("=", 1)[0].strip()
        low = sc.lower()
        if "httponly" not in low:
            out.append((f"cookie '{name}' missing HttpOnly -- readable by script (XSS theft)", "CWE-1004"))
        if is_https and "secure" not in low:
            out.append((f"cookie '{name}' missing Secure -- sent over plaintext HTTP", "CWE-614"))
        if "samesite" not in low:
            out.append((f"cookie '{name}' missing SameSite -- CSRF exposure", "CWE-1275"))
    return out


# ---------- CORS ----------

def cors(request_origin, resp_headers):
    """CORS misconfiguration (pure). Given the Origin WE sent and the response's ACAO/ACAC, decide if the
    policy trusts an arbitrary origin -- with credentials that is cross-origin data theft (CWE-942)."""
    h = {str(k).lower(): v for k, v in (resp_headers or {}).items()}
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower() == "true"
    if acao == request_origin and acac:
        return (f"CORS reflects arbitrary Origin ({request_origin}) with credentials -- cross-origin "
                f"data theft", "CWE-942")
    if acao == "*" and acac:
        return ("CORS allows any origin (*) with credentials", "CWE-942")
    if acao == request_origin:
        return (f"CORS reflects arbitrary Origin ({request_origin}) -- weak origin policy", "CWE-942")
    return None


# ---------- HTTP methods ----------

_DANGEROUS_METHODS = {"TRACE": "CWE-693", "TRACK": "CWE-693", "PUT": "CWE-650", "DELETE": "CWE-650",
                      "CONNECT": "CWE-441"}


def http_methods(allow_header):
    """Dangerous methods advertised in an Allow/ Access-Control-Allow-Methods header (pure)."""
    methods = {m.strip().upper() for m in (allow_header or "").split(",") if m.strip()}
    return [(f"{m} method enabled", cwe) for m, cwe in _DANGEROUS_METHODS.items() if m in methods]


# ---------- content / file discovery ----------

# path -> (what it is, CWE, a content signature that confirms a TRUE positive). The signature defeats
# SPA/catch-all 200s: we only flag when the body actually looks like the sensitive artifact.
SENSITIVE_PATHS = {
    "/.git/config": ("git repo exposed (source disclosure)", "CWE-527", re.compile(r"\[core\]|\[remote")),
    "/.git/HEAD": ("git repo exposed", "CWE-527", re.compile(r"ref:\s*refs/")),
    "/.env": ("environment file exposed (secrets)", "CWE-538", re.compile(r"^[A-Z0-9_]+=", re.M)),
    "/.svn/entries": ("svn metadata exposed", "CWE-527", re.compile(r"\d+")),
    "/.DS_Store": ("macOS DS_Store exposed (dir listing)", "CWE-527", re.compile(r"Bud1", re.I)),
    "/server-status": ("Apache server-status exposed", "CWE-200", re.compile(r"Apache Server Status", re.I)),
    "/actuator": ("Spring actuator exposed", "CWE-200", re.compile(r'"_links"|"health"', re.I)),
    "/actuator/env": ("Spring actuator /env (secrets)", "CWE-200", re.compile(r'"systemProperties"|"propertySources"')),
    "/phpinfo.php": ("phpinfo exposed", "CWE-200", re.compile(r"phpinfo\(\)|PHP Version", re.I)),
    "/swagger.json": ("API spec exposed", "CWE-200", re.compile(r'"swagger"|"openapi"')),
    "/openapi.json": ("API spec exposed", "CWE-200", re.compile(r'"openapi"|"paths"')),
    "/api-docs": ("API docs exposed", "CWE-200", re.compile(r'"swagger"|"openapi"|"paths"')),
    "/graphql": ("GraphQL endpoint (introspection?)", "CWE-200", re.compile(r'"data"|"errors"|__schema', re.I)),
    "/.well-known/security.txt": ("security.txt present", "CWE-200", re.compile(r"Contact:", re.I)),
    "/robots.txt": ("robots.txt (disallowed paths reveal surface)", "CWE-200", re.compile(r"Disallow:", re.I)),
    "/wp-login.php": ("WordPress admin exposed", "CWE-200", re.compile(r"wordpress|wp-submit", re.I)),
    "/admin": ("admin panel reachable", "CWE-200", re.compile(r"login|admin|password", re.I)),
    "/.aws/credentials": ("AWS credentials file exposed", "CWE-538", re.compile(r"aws_access_key_id", re.I)),
    "/config.json": ("config file exposed", "CWE-538", re.compile(r"[{]")),
    "/backup.sql": ("database backup exposed", "CWE-538", re.compile(r"INSERT INTO|CREATE TABLE", re.I)),
}


def classify_exposure(path, status, body, ctype=""):
    """Pure: is a probed sensitive path a TRUE exposure? Requires a 2xx AND the body to match the path's
    content signature (so a soft-404 / SPA catch-all that returns 200 for everything doesn't false-fire).
    Returns (note, cwe) or None."""
    spec = SENSITIVE_PATHS.get(path)
    if not spec or not (status and 200 <= status < 300):
        return None
    note, cwe, sig = spec
    if sig.search(body or ""):
        return (note, cwe)
    return None


def directory_listing(body):
    """Pure: does a response body look like an auto-generated directory listing (CWE-548)?"""
    b = body or ""
    if re.search(r"<title>Index of /|Directory listing for |<h1>Index of", b):
        return ("directory listing enabled (file enumeration)", "CWE-548")
    return None
