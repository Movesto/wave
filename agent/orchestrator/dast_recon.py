"""External recon -- the red-teamer's view of a host given only a URL (network / infra layer).

The app-layer oracles (dast_oracle) attack the web application; this module maps everything AROUND it,
the way an external pentester starts from a single URL: resolve the domain, read the TLS certificate
(which leaks sibling hostnames and trust problems), scan for other exposed services, and judge
email-spoofing / subdomain-takeover posture. These are findings in their own right AND they widen the
attack surface the app-layer stage then tests.

Design, as everywhere in wave: the DECISIONS are pure functions over fetched data (unit-tested offline,
no network); the thin network fetchers are guarded so a failure degrades to "couldn't determine", never
a crash. Everything here is active/observational and only runs under the DAST authorization gate.
"""
from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone

# A curated set of commonly-exposed ports. Keep it small + high-signal (polite, fast) rather than a full
# 65k sweep. service name + whether EXTERNAL exposure is itself a red flag (databases, caches, admin).
PORTS = {
    21: ("ftp", True), 22: ("ssh", False), 23: ("telnet", True), 25: ("smtp", False),
    80: ("http", False), 110: ("pop3", False), 143: ("imap", False), 443: ("https", False),
    445: ("smb", True), 1433: ("mssql", True), 1521: ("oracle-db", True), 2375: ("docker-api", True),
    3306: ("mysql", True), 3389: ("rdp", True), 5432: ("postgres", True), 5601: ("kibana", True),
    5984: ("couchdb", True), 6379: ("redis", True), 8080: ("http-alt", False), 8443: ("https-alt", False),
    9200: ("elasticsearch", True), 9300: ("es-transport", True), 11211: ("memcached", True),
    15672: ("rabbitmq-mgmt", True), 27017: ("mongodb", True),
}


# ---------- DNS ----------

def resolve(host, timeout=5):
    """DNS facts. Uses dnspython for the rich record types when available; always returns at least the
    A/AAAA addresses via the stdlib resolver. {'a':[...], 'aaaa':[...], 'cname':.., 'mx':[], 'ns':[],
    'txt':[], 'error':..}."""
    out = {"host": host, "a": [], "aaaa": [], "cname": "", "mx": [], "ns": [], "txt": []}
    try:
        for fam, key in ((socket.AF_INET, "a"), (socket.AF_INET6, "aaaa")):
            try:
                out[key] = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, fam)})
            except socket.gaierror:
                pass
    except Exception as e:
        out["error"] = str(e)[:120]
    try:
        import dns.resolver  # type: ignore
        r = dns.resolver.Resolver()
        r.lifetime = r.timeout = timeout
        for rtype, key in (("CNAME", "cname"), ("MX", "mx"), ("NS", "ns"), ("TXT", "txt")):
            try:
                ans = r.resolve(host, rtype)
                vals = [a.to_text().strip('"') for a in ans]
                out[key] = vals[0] if rtype == "CNAME" else vals
            except Exception:
                pass
    except Exception:
        out["dns_lib"] = False          # dnspython not installed -> TXT/MX/NS unavailable (A/AAAA still set)
    return out


def email_security(txt_records, dmarc_txt=()):
    """SPF / DMARC posture from TXT records (pure). Missing/weak policy => the domain is spoofable (a
    phishing / red-team angle). dmarc_txt is the TXT of _dmarc.<domain>."""
    spf = next((t for t in (txt_records or []) if t.lower().startswith("v=spf1")), None)
    dmarc = next((t for t in (list(dmarc_txt) or []) if t.lower().startswith("v=dmarc1")), None)
    issues = []
    if not spf:
        issues.append("no SPF record -- sender address is not restricted")
    elif "+all" in spf.lower() or "?all" in spf.lower():
        issues.append(f"weak SPF ('{'+all' if '+all' in spf.lower() else '?all'}') -- anyone may send as this domain")
    if not dmarc:
        issues.append("no DMARC record -- spoofed mail is not rejected/quarantined")
    else:
        pol = next((p.split("=", 1)[1].strip() for p in dmarc.split(";") if p.strip().lower().startswith("p=")), "none")
        if pol.lower() == "none":
            issues.append("DMARC p=none -- failures are only monitored, not blocked")
    return issues


# ---------- subdomain takeover ----------

# fingerprints of a dangling CNAME pointing at a DEPROVISIONED service (classic subdomain takeover).
_TAKEOVER_TARGETS = ("github.io", "herokuapp.com", "herokudns.com", "s3.amazonaws.com", "s3-website",
                     "azurewebsites.net", "cloudapp.net", "trafficmanager.net", "cloudfront.net",
                     "fastly.net", "ghost.io", "wordpress.com", "pantheonsite.io", "zendesk.com",
                     "surge.sh", "bitbucket.io", "readthedocs.io", "netlify.app", "firebaseapp.com")


def dangling_cname(cname, a_records):
    """A CNAME to a known hosting provider that NO LONGER resolves (no A records) => likely subdomain
    takeover: register the resource on that provider and you own the subdomain. Pure."""
    if not cname:
        return None
    low = cname.lower().rstrip(".")
    prov = next((t for t in _TAKEOVER_TARGETS if t in low), None)
    if prov and not a_records:
        return f"CNAME -> {low} ({prov}) but the name does not resolve -- possible subdomain takeover"
    return None


# ---------- TLS ----------

def _parse_cert_date(s):
    try:
        return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _names(cert):
    cn = ""
    for rdn in cert.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                cn = v
    sans = [v for typ, v in cert.get("subjectAltName", ()) if typ == "DNS"]
    return cn, sans


def analyze_cert(cert, host, now=None):
    """Pure TLS-cert analysis: expiry, self-signed, hostname mismatch, and the SANs (which reveal other
    hostnames = more attack surface). Returns {'issues':[...], 'san':[...], 'cn':.., 'issuer':..}."""
    now = now or datetime.now(timezone.utc)
    cn, sans = _names(cert)
    issuer = dict(x for rdn in cert.get("issuer", ()) for x in rdn)
    subject = dict(x for rdn in cert.get("subject", ()) for x in rdn)
    issues = []
    na = _parse_cert_date(cert.get("notAfter", ""))
    if na:
        days = (na - now).days
        if days < 0:
            issues.append(f"certificate EXPIRED {-days}d ago ({cert.get('notAfter')})")
        elif days < 21:
            issues.append(f"certificate expires in {days}d")
    if issuer and issuer == subject:
        issues.append("self-signed certificate (issuer == subject)")
    names = [n.lower() for n in ([cn] + sans) if n]
    if host and not any(host.lower() == n or (n.startswith("*.") and host.lower().endswith(n[1:])) for n in names):
        issues.append(f"hostname {host} not covered by the certificate (CN/SAN: {', '.join(names)[:120]})")
    return {"issues": issues, "san": sans, "cn": cn, "issuer": issuer.get("organizationName", "")}


def tls_info(host, port=443, timeout=6):
    """Fetch the peer certificate (even an invalid one -- we WANT to inspect bad certs) + the negotiated
    protocol. Best-effort: returns {'cert':{..}|None, 'protocol':.., 'error':..}."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                proto = ss.version()
                der = ss.getpeercert(binary_form=True)
        cert = _decode_der(der) if der else {}
        return {"cert": cert, "protocol": proto}
    except Exception as e:
        return {"cert": None, "protocol": None, "error": str(e)[:120]}


def _decode_der(der):
    """DER -> the same dict shape ssl.getpeercert() returns, via the stdlib decoder (works on unvalidated
    certs). Guarded: returns {} if the private helper is unavailable on this build."""
    import tempfile
    import os as _os
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(pem)
            path = f.name
        try:
            return ssl._ssl._test_decode_cert(path)          # stdlib's own cert->dict decoder
        finally:
            _os.unlink(path)
    except Exception:
        return {}


# ---------- ports ----------

def scan_ports(host, ports=None, timeout=1.0, workers=16):
    """TCP connect-scan the curated port set. Returns the sorted list of OPEN ports. Threaded + bounded
    so it stays fast and polite (not a full sweep)."""
    from concurrent.futures import ThreadPoolExecutor
    ports = list(ports or PORTS)
    open_ports = []

    from . import dast_throttle

    def _probe(p):
        dast_throttle.wait()
        try:
            with socket.create_connection((host, p), timeout):
                return p
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(_probe, ports):
            if r is not None:
                open_ports.append(r)
    return sorted(open_ports)


def analyze_ports(open_ports):
    """Pure: which OPEN ports are externally sensitive (a DB/cache/admin reachable from outside is a real
    exposure, CWE-668). Returns [(port, service, note), ...]."""
    out = []
    for p in open_ports:
        name, sensitive = PORTS.get(p, (f"port-{p}", False))
        if sensitive:
            out.append((p, name, f"{name} ({p}) reachable externally -- a data/admin service should not be internet-facing"))
    return out


def banner(host, port, timeout=3):
    """Grab a service banner (best-effort) -- version/software fingerprint for an open port."""
    try:
        with socket.create_connection((host, port), timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8080, 443, 8443):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
            data = s.recv(256)
            return data.decode("latin-1", "replace").strip()
    except Exception:
        return ""


def host_port(url):
    """Split a base URL into (host, port, is_https)."""
    from urllib.parse import urlparse
    u = urlparse(url if "://" in url else "http://" + url)
    https = u.scheme == "https"
    return u.hostname or "", (u.port or (443 if https else 80)), https


def http_fetch(url, method="GET", headers=None, timeout=8):
    """A posture-aware HTTP fetch: unlike dast_oracle._send it PRESERVES every Set-Cookie (getheaders is
    a list of tuples) and exposes the Allow header -- both needed for cookie-flag and method audits.
    Returns {status, headers(lowercased, last-wins), cookies[list], allow, body}. Best-effort/guarded."""
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, headers=dict(headers or {}), method=method.upper())
    from . import dast_throttle
    dast_throttle.wait()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            pairs, status, body = r.getheaders(), r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        pairs, status, body = list((e.headers or {}).items()), e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return {"status": None, "headers": {}, "cookies": [], "allow": "", "body": "", "error": str(e)[:120]}
    hdrs = {k.lower(): v for k, v in pairs}
    cookies = [v for k, v in pairs if k.lower() == "set-cookie"]
    return {"status": status, "headers": hdrs, "cookies": cookies,
            "allow": hdrs.get("allow", "") or hdrs.get("access-control-allow-methods", ""), "body": body}
