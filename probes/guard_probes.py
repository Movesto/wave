"""Hand-authored guard-discrimination probes — YOU write these, the model is scored on them.

WHY THIS EXISTS
The v2p test uses real CVE patches, and they are noisy: 27 of 40 pairs had no CWE tag,
several were comment-only diffs or refactors that matched a sink regex. It also cannot be
proven leak-free, because the same patches feed the training corpus.

Probes you author by hand fix both problems at once:
  * LEAK-PROOF BY CONSTRUCTION — this code has never existed in any corpus.
  * VARIABLE-ISOLATED — you control exactly what differs between the two sides.
  * IT TESTS THE ACTUAL HYPOTHESIS — the model learned "raw SQL / exec / innerHTML means
    vulnerable" (topic) instead of "is this flow guarded?" (mechanism). A minimal pair
    keeps the topic identical and moves only the guard, so a topic-matcher scores 0 on
    pair accuracy no matter how confident it sounds.

TWO KINDS OF PROBE

  kind="pair"  — same function twice, once unguarded, once guarded. The ONLY difference
                 should be the control. Keep names, structure and imports identical, or
                 you are testing something else by accident.

  kind="trap"  — safe code that LOOKS vulnerable (raw SQL vocabulary, md5, eval-ish
                 names). A topic-matcher flags it; a mechanism-reader does not. Traps are
                 the highest-signal probes here, because false positives on innocent code
                 are this scanner's real-world failure mode.

HOW TO WRITE A GOOD ONE
  1. Keep it SHORT — one function, under ~15 lines. Long code tests attention, not
     reasoning.
  2. Make the vulnerable side genuinely exploitable, and say how in `note`.
  3. Make the safe side genuinely safe — the guard must actually defeat the attack, not
     merely look defensive. A logging line is not a guard.
  4. Prefer the families the model is weakest on: missing access control (CWE-284/639),
     crypto (CWE-327), open redirect (CWE-601), deserialization (CWE-502). Injection
     (89/78/79) is already saturated in training.
  5. Write in whatever language you actually ship. Python and JS/TS are best supported.

Aim for 30-40 probes. Twelve are seeded below as worked examples — extend the list.

    python smoke_probes.py --stub          # validate the harness, no GPU
    WAVE_ADAPTER_PATH=data/qwen_cot_v12_best python smoke_probes.py
"""

PROBES = [

    # ---------- injection: the model's home turf; these should pass ----------
    {
        "id": "sqli_fstring",
        "kind": "pair",
        "cwe": "CWE-89",
        "language": "python",
        "guard": "parameterized query",
        "note": "uid is a request parameter; f-string interpolation lets it alter the query.",
        "vuln": '''
def get_user(uid):
    q = f"SELECT * FROM users WHERE id = {uid}"
    return db.execute(q).fetchone()
'''.strip(),
        "safe": '''
def get_user(uid):
    q = "SELECT * FROM users WHERE id = %s"
    return db.execute(q, (uid,)).fetchone()
'''.strip(),
    },
    {
        "id": "cmdi_shell_concat",
        "kind": "pair",
        "cwe": "CWE-78",
        "language": "python",
        "guard": "argument list instead of a shell string",
        "note": "host='1.1.1.1; rm -rf /' executes a second command through the shell.",
        "vuln": '''
def ping(host):
    return subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
'''.strip(),
        "safe": '''
def ping(host):
    return subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True)
'''.strip(),
    },

    # ---------- missing access control: the weakest family, most valuable probes ----------
    {
        "id": "idor_order_lookup",
        "kind": "pair",
        "cwe": "CWE-639",
        "language": "python",
        "guard": "ownership check binding the record to the caller",
        "note": ("No sink is 'dangerous' here — the flaw is a MISSING control. Topic-matching "
                 "cannot see this class at all, which is why it matters."),
        "vuln": '''
@app.get("/orders/{order_id}")
def get_order(order_id: int, user = Depends(current_user)):
    order = db.query(Order).filter(Order.id == order_id).first()
    return order
'''.strip(),
        "safe": '''
@app.get("/orders/{order_id}")
def get_order(order_id: int, user = Depends(current_user)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if order is None or order.user_id != user.id:
        raise HTTPException(status_code=404)
    return order
'''.strip(),
    },
    {
        "id": "authz_role_change",
        "kind": "pair",
        "cwe": "CWE-284",
        "language": "python",
        "guard": "privilege check before mutation",
        "note": "Any authenticated user can escalate themselves to admin on the vulnerable side.",
        "vuln": '''
@app.post("/users/{uid}/role")
def set_role(uid: int, role: str, user = Depends(current_user)):
    target = db.get(User, uid)
    target.role = role
    db.commit()
    return {"ok": True}
'''.strip(),
        "safe": '''
@app.post("/users/{uid}/role")
def set_role(uid: int, role: str, user = Depends(current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403)
    target = db.get(User, uid)
    target.role = role
    db.commit()
    return {"ok": True}
'''.strip(),
    },

    # ---------- path traversal ----------
    {
        "id": "path_traversal_download",
        "kind": "pair",
        "cwe": "CWE-22",
        "language": "python",
        "guard": "resolved path confined to the base directory",
        "note": "name='../../etc/passwd' escapes UPLOAD_DIR on the vulnerable side.",
        "vuln": '''
def download(name):
    path = os.path.join(UPLOAD_DIR, name)
    return open(path, "rb").read()
'''.strip(),
        "safe": '''
def download(name):
    path = os.path.realpath(os.path.join(UPLOAD_DIR, name))
    if not path.startswith(os.path.realpath(UPLOAD_DIR) + os.sep):
        raise ValueError("path escapes upload directory")
    return open(path, "rb").read()
'''.strip(),
    },

    # ---------- open redirect ----------
    {
        "id": "open_redirect_next",
        "kind": "pair",
        "cwe": "CWE-601",
        "language": "python",
        "guard": "allowlist of internal targets / relative-path check",
        "note": "next='//evil.example.com' sends the user off-site after login.",
        "vuln": '''
@app.get("/login")
def login(next: str = "/"):
    session["user"] = authenticate(request)
    return RedirectResponse(next)
'''.strip(),
        "safe": '''
@app.get("/login")
def login(next: str = "/"):
    session["user"] = authenticate(request)
    if not next.startswith("/") or next.startswith("//"):
        next = "/"
    return RedirectResponse(next)
'''.strip(),
    },

    # ---------- deserialization ----------
    {
        "id": "deser_pickle_session",
        "kind": "pair",
        "cwe": "CWE-502",
        "language": "python",
        "guard": "a data-only format that cannot construct objects",
        "note": "pickle.loads on attacker bytes is remote code execution.",
        "vuln": '''
def load_session(blob):
    return pickle.loads(base64.b64decode(blob))
'''.strip(),
        "safe": '''
def load_session(blob):
    return json.loads(base64.b64decode(blob).decode("utf-8"))
'''.strip(),
    },

    # ---------- crypto ----------
    {
        "id": "crypto_password_hash",
        "kind": "pair",
        "cwe": "CWE-327",
        "language": "python",
        "guard": "slow salted KDF instead of a fast digest",
        "note": "Unsalted MD5 is trivially reversed by rainbow tables.",
        "vuln": '''
def store_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()
'''.strip(),
        "safe": '''
def store_password(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
'''.strip(),
    },
    {
        "id": "timing_token_compare",
        "kind": "pair",
        "cwe": "CWE-208",
        "language": "python",
        "guard": "constant-time comparison",
        "note": "== on secrets leaks length/prefix information through timing.",
        "vuln": '''
def check_token(supplied, expected):
    return supplied == expected
'''.strip(),
        "safe": '''
def check_token(supplied, expected):
    return hmac.compare_digest(supplied, expected)
'''.strip(),
    },

    # ---------- XSS (JS) ----------
    {
        "id": "xss_innerhtml",
        "kind": "pair",
        "cwe": "CWE-79",
        "language": "javascript",
        "guard": "textContent, which does not parse markup",
        "note": "name='<img src=x onerror=alert(1)>' executes on the vulnerable side.",
        "vuln": '''
function renderGreeting(name) {
  document.getElementById("greeting").innerHTML = "Hello " + name;
}
'''.strip(),
        "safe": '''
function renderGreeting(name) {
  document.getElementById("greeting").textContent = "Hello " + name;
}
'''.strip(),
    },

    # ---------- TRAPS: safe code that looks dangerous ----------
    {
        "id": "trap_orm_filter",
        "kind": "trap",
        "cwe": None,
        "language": "python",
        "note": ("Reads like SQL injection — user input, a query, the word 'filter' — but the "
                 "ORM parameterizes it. Memory records this exact false positive from v10."),
        "safe": '''
def search_users(term):
    return db.query(User).filter(User.name.contains(term)).all()
'''.strip(),
    },
    {
        "id": "trap_md5_cache_key",
        "kind": "trap",
        "cwe": None,
        "language": "python",
        "note": ("MD5, but for a cache key, not a security decision. Flagging this is the "
                 "classic context-blind CWE-327 false positive."),
        "safe": '''
def cache_key(url, params):
    raw = url + "?" + urlencode(sorted(params.items()))
    return "page:" + hashlib.md5(raw.encode()).hexdigest()
'''.strip(),
    },

    # >>> ADD YOURS BELOW <<<
    # Copy a block above and edit it. Traps and access-control pairs are worth the most.

]
