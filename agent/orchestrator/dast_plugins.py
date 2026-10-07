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


# ================================ ZAP (opt-in, stub) ================================

ZAP_IMPLEMENTED = False


def zap_available():
    return _which("zap.sh") or _which("zaproxy")


def run_zap(target, authorized=False, delay=0.0, timeout=1800):
    """Placeholder for the heavyweight ZAP plugin (daemon + REST API: spider/ajax-spider/passive as
    perception, active-scan alerts demoted to leads our oracles re-verify). Not implemented yet."""
    return []


# ================================ registry / orchestration ================================

PLUGINS = {
    "nuclei": (nuclei_available, run_nuclei),
    "ffuf": (ffuf_available, run_ffuf),
    "zap": (zap_available, run_zap),
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
