"""External-recon analyzer regression (dast_recon.py + dast_web.py) -- the PURE decision functions over
fetched data. No DNS, no sockets, no TLS handshakes: every network fetcher is bypassed and the analyzers
are fed canned inputs. Positive and negative cases for each.

Run: pytest tests/test_dast_recon.py -q
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import dast_recon as rec
from agent.orchestrator import dast_web as web


# ---------- host/port ----------

def test_host_port():
    assert rec.host_port("https://example.com/app") == ("example.com", 443, True)
    assert rec.host_port("http://h:8080") == ("h", 8080, False)
    assert rec.host_port("example.com")[0] == "example.com"


# ---------- email spoofing ----------

def test_email_no_spf_no_dmarc():
    issues = rec.email_security([], [])
    assert any("SPF" in i for i in issues) and any("DMARC" in i for i in issues)


def test_email_weak_spf_and_dmarc_none():
    issues = rec.email_security(["v=spf1 +all"], ["v=DMARC1; p=none; rua=mailto:x@y"])
    assert any("weak SPF" in i for i in issues)
    assert any("p=none" in i for i in issues)


def test_email_strong_is_clean():
    assert rec.email_security(["v=spf1 include:_spf.google.com -all"],
                              ["v=DMARC1; p=reject"]) == []


# ---------- subdomain takeover ----------

def test_dangling_cname_flagged():
    assert rec.dangling_cname("myapp.herokuapp.com.", a_records=[]) is not None


def test_dangling_cname_safe_when_resolves():
    assert rec.dangling_cname("myapp.herokuapp.com.", a_records=["1.2.3.4"]) is None


def test_dangling_cname_ignores_unknown_provider():
    assert rec.dangling_cname("internal.corp.example.com", a_records=[]) is None


# ---------- TLS cert ----------

def _cert(not_after, issuer_org="Lets Encrypt", subject_cn="example.com", sans=("example.com",),
          self_signed=False):
    subj = ((("commonName", subject_cn),),)
    iss = subj if self_signed else (((("organizationName", issuer_org),)),)
    return {"notAfter": not_after, "subject": subj, "issuer": iss,
            "subjectAltName": tuple(("DNS", s) for s in sans)}


def _fmt(dt):
    return dt.strftime("%b %d %H:%M:%S %Y GMT")


def test_cert_expired():
    past = datetime.now(timezone.utc) - timedelta(days=10)
    a = rec.analyze_cert(_cert(_fmt(past)), "example.com")
    assert any("EXPIRED" in i for i in a["issues"])


def test_cert_self_signed_and_mismatch():
    future = datetime.now(timezone.utc) + timedelta(days=200)
    cert = _cert(_fmt(future), subject_cn="other.com", sans=("other.com",), self_signed=True)
    a = rec.analyze_cert(cert, "example.com")
    assert any("self-signed" in i for i in a["issues"])
    assert any("not covered" in i for i in a["issues"])


def test_cert_valid_wildcard_covers_host():
    future = datetime.now(timezone.utc) + timedelta(days=200)
    a = rec.analyze_cert(_cert(_fmt(future), sans=("*.example.com",)), "api.example.com")
    assert a["issues"] == []
    assert a["san"] == ["*.example.com"]


# ---------- ports ----------

def test_analyze_ports_flags_sensitive_only():
    out = rec.analyze_ports([80, 443, 3306, 6379, 8080])
    flagged = {p for p, _, _ in out}
    assert flagged == {3306, 6379}                    # DB + cache exposed; 80/443/8080 are fine


# ---------- web: security headers ----------

def test_security_headers_all_missing():
    issues = web.security_headers({}, is_https=True)
    cwes = {c for _, c in issues}
    assert "CWE-319" in cwes and "CWE-1021" in cwes    # HSTS + clickjacking among them


def test_security_headers_hsts_skipped_on_http():
    issues = web.security_headers({}, is_https=False)
    assert all(c != "CWE-319" for _, c in issues)      # no HSTS finding over plain HTTP


def test_security_headers_csp_frame_ancestors_satisfies_xfo():
    h = {"content-security-policy": "frame-ancestors 'none'", "x-content-type-options": "nosniff",
         "referrer-policy": "no-referrer", "strict-transport-security": "max-age=1"}
    issues = web.security_headers(h, is_https=True)
    assert all(c != "CWE-1021" for _, c in issues)     # frame-ancestors covers clickjacking


# ---------- web: cookies ----------

def test_cookie_flags():
    issues = web.cookie_flags(["sid=abc; Path=/"], is_https=True)
    notes = " ".join(n for n, _ in issues)
    assert "HttpOnly" in notes and "Secure" in notes and "SameSite" in notes


def test_cookie_flags_secure_set_is_clean_for_secure():
    issues = web.cookie_flags(["sid=abc; HttpOnly; Secure; SameSite=Strict"], is_https=True)
    assert issues == []


# ---------- web: CORS ----------

def test_cors_reflects_origin_with_credentials():
    res = web.cors("https://wave.invalid",
                   {"Access-Control-Allow-Origin": "https://wave.invalid",
                    "Access-Control-Allow-Credentials": "true"})
    assert res and res[1] == "CWE-942" and "credentials" in res[0]


def test_cors_same_origin_is_clean():
    assert web.cors("https://wave.invalid", {"Access-Control-Allow-Origin": "https://self.example"}) is None


# ---------- web: methods ----------

def test_http_methods_flags_trace_and_put():
    issues = web.http_methods("GET, POST, PUT, TRACE, OPTIONS")
    methods = {n.split()[0] for n, _ in issues}
    assert "TRACE" in methods and "PUT" in methods


# ---------- web: fingerprint ----------

def test_fingerprint_headers_and_body():
    fp = web.fingerprint({"Server": "nginx", "X-Powered-By": "PHP/8.1"}, body="<link href=/wp-content/x>")
    joined = " ".join(fp)
    assert "server=nginx" in joined and "powered-by=PHP/8.1" in joined and "WordPress" in joined


# ---------- web: content discovery ----------

def test_classify_exposure_true_positive():
    hit = web.classify_exposure("/.git/config", 200, "[core]\n\trepositoryformatversion = 0")
    assert hit and hit[1] == "CWE-527"


def test_classify_exposure_soft_404_rejected():
    # a 200 that does NOT match the content signature (SPA catch-all) must not fire
    assert web.classify_exposure("/.env", 200, "<html><body>app</body></html>") is None


def test_classify_exposure_non_2xx_rejected():
    assert web.classify_exposure("/.git/config", 404, "[core]") is None


def test_directory_listing():
    assert web.directory_listing("<title>Index of /uploads</title>") is not None
    assert web.directory_listing("<html>normal page</html>") is None
