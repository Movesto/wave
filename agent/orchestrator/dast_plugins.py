"""Optional external-tool plugins -- PERCEPTION and lead-generation, never the proof authority.

A plugin wraps a free pentest tool (nuclei, ffuf, ... ZAP next) and normalizes its output into the same
CaseFile vocabulary wave uses everywhere. The grounding rule holds: a third-party tool's output is a
LEAD (believed / anomalous_state) or a surface FACT (entity) -- it never mints a tool-witnessed
`confirmed` finding; only wave's own oracles do that. So a tool's unsoundness can widen recall but can
never manufacture a false confirm.

Design, mirroring the rest of DAST:
 - PARSERS are pure functions over canned tool output -> unit-tested offline (no tool needed).
 - RUNNERS are thin subprocess wrappers, guarded + timeout'd, and no-op when the binary is absent.
 - external tools do their OWN requests, so our in-process dast_throttle can't pace them -> we pass each
   tool its NATIVE rate flag derived from `delay`.
 - everything is opt-in (`--plugins`) and still behind the DAST `--authorized` gate.

Normalized finding: {tool, class, cwe, severity, tier, evidence, provenance, [routes], [targets]}
  tier: "fact"      -> entity/confirmed (surface intel: a discovered path)
        "confirmed" -> confirmation/confirmed (reserved; tools don't use it today)
        "anomalous" -> confirmation/anomalous_state (an external lead; severity is a judgment)
        "believed"  -> hypothesis/believed
"""
from __future__ import annotations

import json
import shutil
import subprocess
from urllib.parse import urlparse

# ---- tier -> (recorder kind, status) ----
_TIER = {"fact": ("entity", "confirmed"), "confirmed": ("confirmation", "confirmed"),
         "anomalous": ("confirmation", "anomalous_state"), "believed": ("hypothesis", "believed")}


def _which(name):
    return bool(shutil.which(name))


# ================================ nuclei ================================

def nuclei_available():
    return _which("nuclei")


def nuclei_rate_flags(delay):
    """Map our per-request delay to nuclei's native rate flags (pure). <1s -> N req/s; >=1s -> N req/min."""
    if not delay or delay <= 0:
        return []
    rps = 1.0 / delay
    if rps >= 1:
        return ["-rate-limit", str(max(1, int(rps)))]
    return ["-rate-limit-minute", str(max(1, int(60 * rps)))]


def parse_nuclei(jsonl):
    """nuclei -jsonl output -> normalized leads (pure). Every nuclei hit is a LEAD (anomalous_state):
    real coverage, but wave's oracle still owns confirmation."""
    out = []
    for line in (jsonl or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        info = d.get("info") or {}
        cl = info.get("classification") or {}
        cwe = ""
        cwes = cl.get("cwe-id") or cl.get("cwe_id")
        if isinstance(cwes, list) and cwes:
            cwe = str(cwes[0]).upper()
        elif isinstance(cwes, str):
            cwe = cwes.upper()
        tid = d.get("template-id") or d.get("templateID") or ""
        name = info.get("name") or tid
        sev = (info.get("severity") or "info").lower()
        at = d.get("matched-at") or d.get("matched_at") or d.get("host") or ""
        out.append({"tool": "nuclei", "class": d.get("type") or "nuclei", "cwe": cwe,
                    "severity": sev, "tier": "anomalous",
                    "evidence": f"{name} [{sev}] at {at}"[:200], "provenance": f"nuclei:{tid}"})
    return out


def run_nuclei(target, authorized=False, delay=0.0, timeout=900):
    if not authorized or not nuclei_available():
        return []
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-no-color", "-timeout", "10"]
    cmd += nuclei_rate_flags(delay)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return []
    return parse_nuclei(r.stdout)


# ================================ ffuf ================================

# a small, high-signal builtin wordlist (dirs/files worth probing) -- no external wordlist dependency.
FFUF_WORDS = ("admin", "login", "api", "api/v1", "api/v2", "config", "config.json", ".env", ".git",
              "backup", "backup.sql", "dump.sql", "uploads", "files", "static", "assets", "debug",
              "test", "dev", "status", "health", "metrics", "actuator", "swagger", "swagger.json",
              "openapi.json", "graphql", "robots.txt", "sitemap.xml", "server-status", "phpinfo.php",
              "wp-login.php", "wp-admin", ".svn", ".DS_Store", "old", "tmp", "private", "internal")


def ffuf_available():
    return _which("ffuf")


def ffuf_rate_flags(delay):
    """ffuf native throttle (pure): a per-request delay in seconds."""
    if not delay or delay <= 0:
        return []
    return ["-p", str(delay)]


def parse_ffuf(json_text):
    """ffuf -of json output -> discovered paths as surface FACTS + GET routes for recall (pure)."""
    out = []
    try:
        data = json.loads(json_text or "{}")
    except Exception:
        return out
    for res in (data.get("results") or []):
        url = res.get("url") or ""
        status = res.get("status")
        path = urlparse(url).path or ("/" + str((res.get("input") or {}).get("FUZZ", "")).lstrip("/"))
        if not path:
            continue
        out.append({"tool": "ffuf", "class": "discovery", "cwe": "", "severity": "info",
                    "tier": "fact", "evidence": f"HTTP {status} {path} (len {res.get('length')})",
                    "provenance": "ffuf", "routes": [("GET", path)]})
    return out


def run_ffuf(target, authorized=False, delay=0.0, timeout=600):
    if not authorized or not ffuf_available():
        return []
    import os
    import tempfile
    wl = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    out = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    wl.write("\n".join(FFUF_WORDS))
    wl.close()
    out.close()
    cmd = ["ffuf", "-u", target.rstrip("/") + "/FUZZ", "-w", wl.name, "-of", "json", "-o", out.name,
           "-mc", "200,201,204,301,302,307,401,403,405,500", "-s"]
    cmd += ffuf_rate_flags(delay)
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        with open(out.name, encoding="utf-8") as f:
            return parse_ffuf(f.read())
    except Exception:
        return []
    finally:
        for p in (wl.name, out.name):
            try:
                os.unlink(p)
            except OSError:
                pass


# ================================ ZAP (daemon + REST API) ================================
# OWASP ZAP driven headlessly: boot `zap.sh -daemon` on an ephemeral port with a random API key, spider
# the target (discovery), let the passive scanner drain (posture), OPTIONALLY active-scan (injection,
# gated by WAVE_ZAP_ACTIVE because it is slow + intrusive), pull the alerts, shut down. Per wave's rule,
# every ZAP alert is a LEAD -- High/Medium -> believed (our oracle re-verifies), Low/Info -> anomalous;
# spidered URLs become GET routes that widen wave's own surface.

ZAP_IMPLEMENTED = True
_ZAP_RISK_TIER = {"high": "believed", "medium": "believed", "low": "anomalous",
                  "informational": "anomalous", "info": "anomalous"}


def zap_available():
    import os
    return bool(_which("zap.sh") or _which("zaproxy") or os.environ.get("WAVE_ZAP"))


def zap_delay_ms(delay):
    """Our per-request delay -> ZAP active-scanner delay in milliseconds (pure)."""
    return max(0, int((delay or 0) * 1000))


def _zap_cwe(raw):
    try:
        n = int(raw)
        return f"CWE-{n}" if n > 0 else ""
    except (TypeError, ValueError):
        return ""


def parse_zap(alerts_json):
    """ZAP core/alerts JSON -> normalized leads (pure). Risk sets the tier; cweid<=0 means 'no CWE'."""
    data = alerts_json if isinstance(alerts_json, dict) else _loads(alerts_json)
    out = []
    for a in (data.get("alerts") or []):
        risk = (a.get("risk") or "info").split()[0].lower()
        name = a.get("alert") or a.get("name") or "zap alert"
        url = a.get("url") or ""
        pid = a.get("pluginId") or a.get("pluginid") or a.get("alertRef") or ""
        out.append({"tool": "zap", "class": "zap", "cwe": _zap_cwe(a.get("cweid") or a.get("cweId")),
                    "severity": risk, "tier": _ZAP_RISK_TIER.get(risk, "anomalous"),
                    "evidence": f"{name} [{risk}] at {url}"[:200], "provenance": f"zap:{pid}"})
    return out


def parse_zap_urls(spider_json):
    """ZAP spider results -> deduped GET routes (recall). Pure."""
    data = spider_json if isinstance(spider_json, dict) else _loads(spider_json)
    seen, out = set(), []
    for u in (data.get("results") or []):
        p = urlparse(u).path
        if p and ("GET", p) not in seen:
            seen.add(("GET", p))
            out.append(("GET", p))
    return out


def _loads(text):
    try:
        return json.loads(text or "{}")
    except Exception:
        return {}


def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _zap_get(base, key, path, timeout=30, **params):
    import urllib.parse
    import urllib.request
    params["apikey"] = key
    url = base + path + "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def run_zap(target, authorized=False, delay=0.0, timeout=1800):
    """Boot ZAP in daemon mode, spider + passive (+ optional active via WAVE_ZAP_ACTIVE), collect alerts,
    shut down. Heavily guarded: any failure returns whatever was gathered so far (or [])."""
    import os
    import secrets
    import subprocess
    import time
    if not authorized or not zap_available():
        return []
    exe = _which("zap.sh") or _which("zaproxy") or os.environ.get("WAVE_ZAP")
    port, key, base = _free_port(), secrets.token_hex(8), None
    base = f"http://127.0.0.1:{port}"
    proc = None
    try:
        proc = subprocess.Popen([exe, "-daemon", "-host", "127.0.0.1", "-port", str(port),
                                 "-config", f"api.key={key}"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + min(timeout, 120)
        up = False
        while time.time() < deadline:
            try:
                _zap_get(base, key, "/JSON/core/view/version/")
                up = True
                break
            except Exception:
                time.sleep(2)
        if not up:
            return []
        try:
            _zap_get(base, key, "/JSON/core/action/accessUrl/", url=target)
        except Exception:
            pass
        routes = []
        try:
            sid = str(_zap_get(base, key, "/JSON/spider/action/scan/", url=target).get("scan", "0"))
            sdl = time.time() + min(timeout, 300)
            while time.time() < sdl:
                if str(_zap_get(base, key, "/JSON/spider/view/status/", scanId=sid).get("status", "0")) == "100":
                    break
                time.sleep(3)
            routes = parse_zap_urls(_zap_get(base, key, "/JSON/spider/view/results/", scanId=sid))
        except Exception:
            pass
        try:
            pdl = time.time() + 120
            while time.time() < pdl:
                if str(_zap_get(base, key, "/JSON/pscan/view/recordsToScan/").get("recordsToScan", "0")) == "0":
                    break
                time.sleep(2)
        except Exception:
            pass
        if os.environ.get("WAVE_ZAP_ACTIVE"):
            try:
                if delay > 0:
                    _zap_get(base, key, "/JSON/ascan/action/setOptionDelayInMs/", Integer=str(zap_delay_ms(delay)))
                aid = str(_zap_get(base, key, "/JSON/ascan/action/scan/", url=target, recurse="true").get("scan", "0"))
                adl = time.time() + min(timeout, 900)
                while time.time() < adl:
                    if str(_zap_get(base, key, "/JSON/ascan/view/status/", scanId=aid).get("status", "0")) == "100":
                        break
                    time.sleep(5)
            except Exception:
                pass
        alerts = []
        try:
            alerts = parse_zap(_zap_get(base, key, "/JSON/core/view/alerts/", baseurl=target))
        except Exception:
            pass
        facts = [{"tool": "zap", "class": "discovery", "cwe": "", "severity": "info", "tier": "fact",
                  "evidence": f"spidered {m} {p}", "provenance": "zap:spider", "routes": [(m, p)]}
                 for (m, p) in routes]
        return facts + alerts
    except Exception:
        return []
    finally:
        if proc is not None:
            try:
                _zap_get(base, key, "/JSON/core/action/shutdown/")
            except Exception:
                pass
            try:
                proc.terminate()
            except Exception:
                pass


# ================================ mitmproxy (traffic capture -> recall) ================================
# Unlike the scanners, mitmproxy CAPTURES real traffic -- the richest surface source for a JS-heavy or
# authenticated app or an API client: whatever the user (or a tool) actually exercised becomes routes +
# injection targets for wave's own oracles. The reliable, universal core is a HAR parser (mitmproxy's
# `hardump`, or any proxy/browser HAR export); a live timed `mitmdump` capture is an opt-in bonus.

def mitmproxy_available():
    import os
    return bool(_which("mitmdump") or os.environ.get("WAVE_HAR"))


def parse_har(har, host=None):
    """HAR (1.2) -> one 'capture' FACT finding carrying the observed routes + injection targets (pure).
    Query params and form/JSON body keys become targets; `host` (when given) filters to the target."""
    data = har if isinstance(har, dict) else _loads(har)
    entries = (data.get("log") or {}).get("entries") or []
    routes, targets, sr, st = [], [], set(), set()

    def add_route(m, p):
        if p and (m, p) not in sr:
            sr.add((m, p))
            routes.append((m, p))

    def add_target(m, p, v, n):
        if n and (m, p, v, n) not in st:
            st.add((m, p, v, n))
            targets.append((m, p, v, n))

    for e in entries:
        req = e.get("request") or {}
        m = (req.get("method") or "GET").upper()
        pr = urlparse(req.get("url") or "")
        if host and pr.hostname and pr.hostname != host:
            continue
        path = pr.path or "/"
        add_route(m, path)
        for q in (req.get("queryString") or []):
            add_target(m, path, "query", q.get("name"))
        pd = req.get("postData") or {}
        params = pd.get("params") or []
        for p in params:
            add_target(m, path, "body", p.get("name"))
        if not params and pd.get("text"):
            try:
                body = json.loads(pd["text"])
                if isinstance(body, dict):
                    for k in body:
                        add_target(m, path, "body", k)
            except Exception:
                pass
    if not (routes or targets):
        return []
    return [{"tool": "mitmproxy", "class": "capture", "cwe": "", "severity": "info", "tier": "fact",
             "evidence": f"captured {len(routes)} routes, {len(targets)} params from HAR",
             "provenance": "mitmproxy:har", "routes": routes, "targets": targets}]


def run_mitmproxy(target, authorized=False, delay=0.0, timeout=600):
    """Import a captured HAR (WAVE_HAR), or -- if WAVE_MITM_SECS is set and mitmdump is present -- run a
    live timed capture while the operator drives traffic through the printed proxy. Guarded."""
    import os
    if not authorized:
        return []
    host = urlparse(target).hostname if target else None
    har_path = os.environ.get("WAVE_HAR")
    if har_path and os.path.isfile(har_path):
        try:
            with open(har_path, encoding="utf-8") as f:
                return parse_har(f.read(), host=host)
        except Exception:
            return []
    secs = os.environ.get("WAVE_MITM_SECS")
    if secs and _which("mitmdump"):
        try:
            return _mitm_capture(target, host, int(secs))
        except Exception:
            return []
    return []


def _mitm_capture(target, host, secs):
    import os
    import subprocess
    import tempfile
    import time
    port = _free_port()
    har = tempfile.NamedTemporaryFile(suffix=".har", delete=False)
    har.close()
    proc = None
    try:
        proc = subprocess.Popen(["mitmdump", "-p", str(port), "-q", "--set", f"hardump={har.name}"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[mitmproxy] proxy on 127.0.0.1:{port} -- route your browser/app through it and exercise "
              f"{target}; capturing {secs}s...", flush=True)
        time.sleep(secs)
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=10)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    try:
        with open(har.name, encoding="utf-8") as f:
            return parse_har(f.read(), host=host)
    except Exception:
        return []
    finally:
        try:
            os.unlink(har.name)
        except OSError:
            pass


# ================================ registry / orchestration ================================

PLUGINS = {
    "nuclei": (nuclei_available, run_nuclei),
    "ffuf": (ffuf_available, run_ffuf),
    "zap": (zap_available, run_zap),
    "mitmproxy": (mitmproxy_available, run_mitmproxy),
}


def resolve(selected):
    """Normalize the --plugins selection ('all' or a list/comma-string) to known plugin names."""
    if not selected:
        return []
    if isinstance(selected, str):
        selected = [s.strip() for s in selected.split(",")]
    if any(s.lower() == "all" for s in selected):
        return list(PLUGINS)
    return [s.lower() for s in selected if s.lower() in PLUGINS]


def collect(selected, url, authorized=False, delay=0.0):
    """Run the selected+available plugins; return (records, routes, targets). routes/targets widen the
    attack surface for wave's own oracles (recall); records are the normalized leads/facts to ingest."""
    records, routes, targets = [], [], []
    status = {}
    for name in resolve(selected):
        avail, runner = PLUGINS[name]
        if not avail():
            status[name] = "not installed"
            continue
        try:
            fs = runner(url, authorized=authorized, delay=delay)
        except Exception as e:
            status[name] = f"error: {e}"
            fs = []
        else:
            status[name] = f"{len(fs)} findings"
        for f in fs:
            routes += f.pop("routes", None) or []
            targets += f.pop("targets", None) or []
            records.append(f)
    return records, routes, targets, status


def ingest(case, records):
    """Record normalized plugin findings into the CaseFile under wave's verdict tiers."""
    for f in records:
        kind, st = _TIER.get(f.get("tier", "believed"), ("hypothesis", "believed"))
        subject = f"{f.get('tool', 'tool')}: {f.get('class', '')} {f.get('evidence', '')}".strip()[:120]
        case.record(kind, subject, "tool", st, provenance=f.get("provenance", ""),
                    cwe=f.get("cwe", ""), evidence=f.get("evidence", ""))
