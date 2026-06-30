# ============================================================
# cot/shapes/exemplars.py
#
# Hand-picked exemplar pairs that demonstrate the SPECIFICITY
# we want from gpt-oss. The generator sees 1-2 of these in the
# prompt and tends to mimic the style — quoting variable names,
# tracing data flow, naming sinks by their actual function call.
#
# Curated from the best of the existing hand-crafted pilot
# records.
# ============================================================
from typing import Sequence


# ---- SHAPE 1 exemplars ----

SHAPE1_EXEMPLARS = [
    # Vulnerable, Python, SQL injection — shows data-flow tracing
    {
        "code": """import sqlite3
def get_user(conn, user_id):
    q = f"SELECT * FROM users WHERE id = '{user_id}'"
    return conn.execute(q).fetchone()""",
        "language": "python",
        "label": "vuln",
        "cwe": "CWE-89",
        "response": """<think>
get_user reads `user_id` from its parameter — call sites likely fill it from request.args or a route param, so it's attacker-controlled.

The function builds the SQL via f-string: `f"SELECT * FROM users WHERE id = '{user_id}'"`. The value gets pasted into the SQL TEXT itself, not as a bound parameter. The driver has no way to distinguish data from code in this construction.

Inject `user_id="1' OR '1'='1"` → query becomes `SELECT * FROM users WHERE id = '1' OR '1'='1'` → returns every row. A UNION SELECT against the credentials table is also reachable, leaking password hashes.

The `conn.execute(q)` single-string form (no parameter tuple) confirms the binding path is not used.
</think>

status: confirmed
cwe: CWE-89
severity: HIGH
line: 3
trace: user_id → f-string interpolation into SQL string → conn.execute(single-string form); driver receives pre-formatted SQL, parameter binding bypassed
fix: conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # parameterized — the driver binds user_id as a literal regardless of contents
""",
    },
    # Safe, Python, parameterized query
    {
        "code": """import sqlite3
def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()""",
        "language": "python",
        "label": "safe",
        "cwe": None,
        "response": """<think>
The function calls `cur.execute` with two arguments: a SQL string containing the `?` placeholder, and the values tuple `(user_id,)`. This is the parameterized form — sqlite3 sends the SQL text and the bound value separately to the engine, and the engine treats `user_id` as a literal value regardless of what bytes it contains.

An input like `"1' OR '1'='1"` becomes the literal string compared against the `id` column via equality. No equality match → no rows returned. SQL keywords inside `user_id` are just text.

This is the textbook safe pattern for sqlite3.
</think>

status: safe
cwe: none
severity: none
line: 4
trace: user_id passed via the (user_id,) values tuple to cur.execute alongside a static SQL template; driver binds it as a literal — injection surface closed
fix: none
""",
    },
]


# ---- SHAPE 3 exemplars (cross-file) ----

SHAPE3_EXEMPLARS = [
    # confirm — unsafe SSRF helper
    {
        "caller_code": """from flask import Flask, request, jsonify
from services.http_client import fetch_url

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    target_url = request.args.get('url')
    if not target_url:
        return jsonify({"error": "url required"}), 400
    body = fetch_url(target_url)
    return body""",
        "helper_code": """import requests

def fetch_url(target_url):
    resp = requests.get(target_url, timeout=10)
    resp.raise_for_status()
    return resp.text""",
        "language": "python",
        "disposition": "confirm",
        "response": """<think>
Caller side: `/proxy` reads `target_url` from `request.args.get('url')`. That's a public-facing endpoint where the URL parameter is attacker-controlled.

target_url is passed verbatim to `fetch_url`. Now examining `fetch_url`:
1. `requests.get(target_url, timeout=10)` with no URL parsing at all.
2. No scheme allowlist — `file://`, `gopher://`, `http://` are all reachable.
3. No hostname check — `http://169.254.169.254/latest/meta-data/` (AWS metadata) or `http://localhost:6379/` (internal Redis) reach.
4. `allow_redirects` defaults to True, so a 302 to an internal host is followed without re-checking.

Attacker submits `?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name` → server fetches cloud credentials and returns them as the response body. Or `?url=file:///etc/passwd` to leak filesystem content.

Verdict: confirmed. CWE-918 SSRF.
</think>

status: confirmed
cwe: CWE-918
severity: HIGH
trace: request.args['url'] → target_url → fetch_url → requests.get with no scheme/host validation; cloud metadata and internal services reachable
fix: parse with urlparse, require scheme in {'http','https'}, resolve the hostname and reject RFC1918/loopback/cloud-metadata ranges, set allow_redirects=False
""",
    },
]


# ---- SHAPE 4 exemplars (synthesis) ----

SHAPE4_EXEMPLARS = [
    {
        "input": """PROJECT MAP
  api/orders.py
  api/orders_v2.py
  auth/jwt.py
  auth/login.py
  media/proxy.py

FINDINGS (5):
  [1] SQL injection in get_user_orders (CWE-89, sev=HIGH, file=api/orders.py)
  [2] Hardcoded JWT secret in auth helper (CWE-798, sev=HIGH, file=auth/jwt.py)
  [3] SSRF in image proxy endpoint (CWE-918, sev=HIGH, file=media/proxy.py)
  [4] Open redirect in /login?next= flow (CWE-601, sev=MEDIUM, file=auth/login.py)
  [5] SQL injection in get_user_orders (CWE-89, sev=HIGH, file=api/orders_v2.py)
""",
        "response": """<think>
First pass: cluster duplicates. Findings #1 and #5 share the same title and CWE-89 across api/orders.py and api/orders_v2.py — a copy-pasted SQL injection in a duplicated module. Cluster them.

After dedup: 4 logical findings. Severity tally: 3 HIGH (SQLi clustered, JWT secret, SSRF), 1 MEDIUM (open redirect).

Within HIGH, I rank by exploitation cost: Hardcoded JWT secret is the worst — anyone reading the source forges arbitrary tokens, total auth bypass with no other prerequisites. SQL injection in get_user_orders gives direct data exfiltration via UNION/blind injection on a normal API endpoint. SSRF in the image proxy reaches internal services and cloud metadata.

Open redirect on /login?next= is MEDIUM, but it compounds with the JWT issue — phishing victims to a forged-token-protected fake page becomes a complete account-compromise chain.

Systemic patterns: (1) code duplication in api/orders*.py meaning a fix in one file misses the other; (2) the auth surface holds two of four findings (JWT + redirect) and they amplify each other.
</think>

executive_summary: Three HIGH-severity findings span auth (hardcoded JWT secret), data exfiltration (SQL injection clustered across api/orders.py + api/orders_v2.py), and the outbound HTTP layer (SSRF). The open redirect adds a phishing amplifier that compounds with the JWT issue. Code duplication is the dominant systemic pattern.

ranked_findings:
  - rank: 1
    title: Hardcoded JWT secret in auth helper
    severity: HIGH
    rationale: Source-readable signing key in auth/jwt.py permits arbitrary token forgery — total auth bypass, no other prerequisites.
  - rank: 2
    title: SQL injection in get_user_orders
    severity: HIGH
    rationale: Direct data exfiltration via UNION/blind injection on api/orders.py; clustered with api/orders_v2.py — both copies must be fixed in lockstep.
  - rank: 3
    title: SSRF in image proxy endpoint
    severity: HIGH
    rationale: media/proxy.py allows attacker-controlled URLs reaching cloud metadata and internal services.
  - rank: 4
    title: Open redirect in /login?next= flow
    severity: MEDIUM
    rationale: auth/login.py's redirect handling compounds with the JWT finding — phishing + forged token = full account compromise chain.

systemic_observations:
  - Code duplication in api/orders*.py carries the same SQL injection across two files; deduplication should accompany the patch.
  - Two of four logical findings live in the auth surface (auth/jwt.py + auth/login.py) and reinforce each other — review the auth flow as one design rather than per-file.

dedup_notes: SQL injection in get_user_orders clusters across api/orders.py and api/orders_v2.py (findings 1 and 5).
""",
    },
]


# ---- Formatters ----

import os as _os


def _few_shot_enabled() -> bool:
    return _os.environ.get("WAVE_FEW_SHOT", "false").lower() in ("1", "true", "yes")


def format_shape1_exemplars(count: int = 1) -> str:
    """Render shape1 exemplars as a prompt-ready string. Opt-in via
    WAVE_FEW_SHOT=true. Returns empty string when off."""
    if not _few_shot_enabled():
        return ""
    chosen = SHAPE1_EXEMPLARS[:count] if count == 1 else SHAPE1_EXEMPLARS[:2]
    parts = ["=== EXEMPLAR(S) — match this style of specificity ==="]
    for i, ex in enumerate(chosen, 1):
        parts.append(f"\n--- Example {i} ({ex['language']}, label={ex['label']}) ---")
        parts.append(f"CODE:\n```{ex['language']}\n{ex['code']}\n```")
        parts.append(f"OUTPUT:\n{ex['response']}")
    parts.append("=== END EXEMPLARS ===\n")
    return "\n".join(parts)


def format_shape3_exemplars(count: int = 1) -> str:
    if not _few_shot_enabled():
        return ""
    chosen = SHAPE3_EXEMPLARS[:count]
    parts = ["=== EXEMPLAR(S) — match this style of cross-file tracing ==="]
    for i, ex in enumerate(chosen, 1):
        parts.append(f"\n--- Example {i} (disposition={ex['disposition']}) ---")
        parts.append(f"CALLER CODE:\n```{ex['language']}\n{ex['caller_code']}\n```")
        parts.append(f"HELPER CODE:\n```{ex['language']}\n{ex['helper_code']}\n```")
        parts.append(f"OUTPUT:\n{ex['response']}")
    parts.append("=== END EXEMPLARS ===\n")
    return "\n".join(parts)


def format_shape4_exemplars(count: int = 1) -> str:
    if not _few_shot_enabled():
        return ""
    chosen = SHAPE4_EXEMPLARS[:count]
    parts = ["=== EXEMPLAR(S) — match this style of synthesis ==="]
    for i, ex in enumerate(chosen, 1):
        parts.append(f"\n--- Example {i} ---")
        parts.append(f"INPUT:\n{ex['input']}")
        parts.append(f"OUTPUT:\n{ex['response']}")
    parts.append("=== END EXEMPLARS ===\n")
    return "\n".join(parts)
