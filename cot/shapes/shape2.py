# ============================================================
# cot/shapes/shape2.py
#
# Shape 2 — Request missing context (anti-hallucination).
#
# Construction strategy for the pilot: SYNTHETIC seeds. Each
# seed is (vuln_category, helper_function, fake_file, language,
# user_input_source). The generator:
#   (a) writes a realistic caller snippet importing the helper
#   (b) writes a <think> trace concluding "I can't see the
#       helper, so I must ask for context"
#   (c) emits status: needs_context + open_refs: [helper_function (file)]
#
# Verifier checks status==needs_context AND open_refs names the
# expected helper. Substring-tolerant on the helper match.
#
# Why synthetic instead of constructed-from-data: pilot needs
# ~40 cases; multi_function.jsonl only has 20, and AST-rewriting
# adds complexity. Seeds give clean ground truth for verification.
# For the full 500-target run we can fold in constructed pairs.
# ============================================================
import random
from typing import Optional

from .common import parse_verdict


name = "shape2"

random.seed(43)


# (category, helper_fn, file_path, language, input_source, sink_call_arg_pattern)
SEED_PATTERNS = [
    # Python
    ("SQL injection", "query_user", "db/queries.py", "python", "request.args.get('user_id')", "user_id"),
    ("Command injection", "run_command", "utils/shell.py", "python", "request.json.get('cmd')", "cmd"),
    ("SSRF", "fetch_url", "services/http_client.py", "python", "request.args.get('url')", "target_url"),
    ("XSS via template", "render_html", "templates/render.py", "python", "request.form.get('comment')", "comment"),
    ("Path traversal", "load_file", "io/files.py", "python", "request.args.get('name')", "filename"),
    ("Insecure deserialization", "deserialize_payload", "serializers/blob.py", "python", "request.data", "raw_blob"),
    ("LDAP injection", "search_user", "ldap/search.py", "python", "request.args.get('q')", "query_str"),
    ("XML XXE", "parse_xml_doc", "parsers/xml.py", "python", "request.data", "xml_bytes"),
    ("Open redirect", "build_redirect", "auth/redirect.py", "python", "request.args.get('next')", "next_url"),
    ("Insecure JWT verify", "verify_token", "auth/jwt.py", "python", "request.cookies.get('jwt')", "token"),

    # JavaScript / Node
    ("SQL injection", "queryByEmail", "db/users.js", "javascript", "req.body.email", "email"),
    ("SSRF", "proxyRequest", "lib/http.js", "javascript", "req.query.url", "target"),
    ("RCE via shell", "execCommand", "lib/exec.js", "javascript", "req.body.cmd", "command"),
    ("Prototype pollution", "mergeOptions", "utils/merge.js", "javascript", "req.body", "user_opts"),
    ("Path traversal", "serveFile", "files/serve.js", "javascript", "req.params.name", "filename"),

    # TypeScript
    ("SQL injection", "findOrderById", "db/orders.ts", "typescript", "req.params.id", "orderId"),
    ("SSRF", "fetchAvatar", "services/avatar.ts", "typescript", "req.body.url", "url"),
    ("Insecure deserialization", "parseToken", "auth/token.ts", "typescript", "req.cookies.session", "raw"),
    ("XSS via dangerous markdown", "renderMarkdown", "render/md.ts", "typescript", "req.body.content", "markdown_input"),

    # React (client-side)
    ("XSS via dangerouslySetInnerHTML", "renderBio", "components/Profile.tsx", "react", "profile.bio from API response", "html_blob"),
    ("Open redirect", "navigateAfterLogin", "auth/postLogin.ts", "react", "URLSearchParams.get('next')", "next_url"),

    # ----- v2 expansion: security-loaded helper names (v1 eval revealed model -----
    # ----- hallucinates verdicts when the helper has a vuln-suggestive name.  -----
    # ----- Goal: force "needs_context" even when the name screams "I know!"   -----

    # Python — auth/crypto (high prior to hallucinate)
    ("Insecure password hash", "hash_password", "auth/passwords.py", "python", "request.form.get('password')", "raw_pwd"),
    ("Weak signature check", "verify_signature", "crypto/sig.py", "python", "request.headers.get('X-Sig')", "sig"),
    ("Constant-time compare missing", "compare_tokens", "auth/tokens.py", "python", "request.json.get('csrf')", "submitted"),
    ("MAC verification skipped", "validate_mac", "messaging/mac.py", "python", "request.data", "mac_payload"),
    ("Crypto IV reuse", "encrypt_session", "crypto/sessions.py", "python", "request.cookies.get('uid')", "plaintext"),
    ("Authorization bypass", "check_authorization", "perms/check.py", "python", "request.user.id", "actor"),
    ("Permission elevation", "has_permission", "perms/rbac.py", "python", "request.json.get('role')", "requested_role"),
    ("Insecure password reset", "reset_password_for", "auth/reset.py", "python", "request.form.get('email')", "user_email"),

    # Python — sanitizer/validator names (look safe but may not be)
    ("Sanitizer bypass", "sanitize_html", "html/sanitize.py", "python", "request.form.get('comment')", "raw_html"),
    ("Validation bypass", "validate_filename", "io/validate.py", "python", "request.args.get('name')", "candidate"),
    ("Allowlist bypass", "is_allowed_url", "network/allow.py", "python", "request.json.get('webhook')", "url"),
    ("Path normalization fail", "resolve_safe_path", "fs/resolve.py", "python", "request.args.get('p')", "candidate_path"),
    ("Email normalization", "normalize_email", "users/normalize.py", "python", "request.form.get('email')", "raw_email"),

    # Python — risky-named (model may assume vuln)
    ("Pickle deserialization", "load_pickle", "cache/pickle_store.py", "python", "request.data", "pickled_blob"),
    ("YAML unsafe load", "parse_yaml", "configs/loader.py", "python", "request.data", "yaml_text"),
    ("Eval-like exec", "eval_expression", "scripting/exec.py", "python", "request.json.get('expr')", "expression"),
    ("Shell exec via wrapper", "run_subprocess", "ops/runner.py", "python", "request.json.get('args')", "argv"),
    ("XML signature wrap", "verify_xml_signature", "xml/sig.py", "python", "request.data", "signed_xml"),

    # JavaScript / Node — auth/crypto + sanitizers
    ("Weak JWT verification", "verifyJwt", "auth/jwt.js", "javascript", "req.headers.authorization", "bearer_token"),
    ("HMAC compare", "compareHmac", "crypto/hmac.js", "javascript", "req.body.signature", "client_sig"),
    ("Password hash", "hashUserPassword", "auth/hash.js", "javascript", "req.body.password", "pwd"),
    ("Sanitizer pass-through", "sanitizeUserInput", "filters/sanitize.js", "javascript", "req.body.bio", "bio_text"),
    ("URL validation", "isValidRedirectUrl", "auth/redirect_check.js", "javascript", "req.query.return_to", "candidate"),
    ("Webhook signature", "verifyWebhookSignature", "webhooks/verify.js", "javascript", "req.headers['x-hub-signature']", "header_sig"),

    # TypeScript — auth/perm + serialization
    ("Authorization decorator", "requirePermission", "middleware/authz.ts", "typescript", "req.session.user", "user_obj"),
    ("Session decrypt", "decryptSessionToken", "auth/session.ts", "typescript", "req.cookies.sid", "encrypted"),
    ("CSP nonce check", "validateNonce", "security/csp.ts", "typescript", "req.headers['x-csp-nonce']", "nonce"),
    ("YAML config load", "loadYamlConfig", "config/load.ts", "typescript", "req.body.config", "yaml_str"),

    # React — sanitizer / auth on client side
    ("Markdown sanitizer", "sanitizeMarkdown", "render/markdown.tsx", "react", "post.body from fetch", "markdown_src"),
    ("Auth-gated component prop", "authorizeRender", "components/Authz.tsx", "react", "props.user from redux store", "user_payload"),
    ("Redirect builder", "buildSafeRedirect", "auth/redirectBuilder.ts", "react", "URLSearchParams.get('returnUrl')", "candidate_url"),
]


def prepare_tasks(limit: int) -> list[dict]:
    """Deterministic across limits: prepare_tasks(N)[:M] == prepare_tasks(M)."""
    rng = random.Random(43)
    tasks = []
    pool = list(SEED_PATTERNS)
    # Build up to MAX_POOL once with deterministic shuffling, then slice.
    MAX_POOL = max(limit, 64)
    i = 0
    while len(tasks) < MAX_POOL:
        seed = pool[i % len(pool)]
        category, helper_fn, file_path, language, input_source, arg_name = seed
        tasks.append({
            "task_id": f"shape2:{category.lower().replace(' ', '_')}:{helper_fn}:{i}",
            "category": category,
            "helper_fn": helper_fn,
            "file_path": file_path,
            "language": language,
            "input_source": input_source,
            "arg_name": arg_name,
        })
        i += 1
    rng.shuffle(tasks)
    return tasks[:limit]


SYSTEM = (
    "You generate chain-of-thought training data for a vulnerability scanner. "
    "Specifically, you produce examples where the model MUST ASK for missing "
    "context instead of guessing — the verdict depends on code that's been "
    "imported from another file but not shown. The correct behavior is to "
    "emit status: needs_context and name the symbol that needs to be fetched."
)


def build_prompt(task: dict) -> tuple[Optional[str], str]:
    lang = task["language"]
    helper = task["helper_fn"]
    fp = task["file_path"]
    cat = task["category"]
    input_src = task["input_source"]
    arg = task["arg_name"]

    instruction = f"""You are constructing a Shape-2 training example.

The example must show: user input flows into a helper function that is IMPORTED FROM ANOTHER FILE.
Since the model cannot see the helper, the correct behavior is to ask for context, not guess.

PARAMETERS for this example:
  language: {lang}
  vulnerability category: {cat}
  helper function name: {helper}
  file the helper is imported from: {fp}
  user input source: {input_src}
  argument name passed to the helper: {arg}

TASK 1 — Write a short, realistic caller snippet ({lang}) that:
  - Imports {helper} from {fp}
  - Receives user input from {input_src}
  - Passes that input into {helper}({arg}) without further validation
  - Does NOT define {helper} in this snippet
  - Reads like real production code (route handler, controller, etc.)
  - 6–18 lines of code

TASK 2 — Write a <think> trace that:
  - Identifies the input source as untrusted
  - Follows the data flow to the call site of {helper}
  - Notes that {helper} is imported from another file and not visible
  - Concludes that the verdict depends on whether {helper} sanitizes/validates
    its argument, and that GUESSING would be wrong — the correct action is to ASK

TASK 3 — Emit the verdict in EXACTLY this format:

<<<CALLER_CODE>>>
[the {lang} caller snippet from TASK 1, no markdown fence inside this block]
<<<END_CALLER_CODE>>>

<think>
[the trace from TASK 2 — concrete, code-anchored, 4–10 short sentences]
</think>

status: needs_context
open_refs:
  - {helper} ({fp})
partial_trace: user input from {input_src} flows into {helper}({arg}) — verdict depends on {helper}'s implementation
"""
    return SYSTEM, instruction


CALLER_RE = None  # set lazily

def _extract_caller(generated: str) -> Optional[str]:
    import re as _re
    m = _re.search(r"<<<CALLER_CODE>>>\s*\n(.*?)\n<<<END_CALLER_CODE>>>", generated, _re.DOTALL)
    if not m:
        return None
    code = m.group(1).strip()
    return code if code else None


def _extract_open_refs(generated: str) -> list[str]:
    """Parse the open_refs block lines (after the `open_refs:` header)."""
    import re as _re
    m = _re.search(r"open_refs\s*:\s*\n((?:\s*-\s*[^\n]+\n?)+)", generated, _re.IGNORECASE)
    if not m:
        return []
    refs = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if line.startswith("-"):
            refs.append(line.lstrip("-").strip())
    return refs


def verify(task: dict, generated_text: str) -> Optional[dict]:
    parsed = parse_verdict(generated_text)
    # parse_verdict's status normalization will turn "needs_context" into None
    # (it only knows confirmed/safe). Re-detect manually.
    status_raw = None
    import re as _re
    m = _re.search(r"^\s*status\s*:\s*(.+?)\s*$", generated_text, _re.IGNORECASE | _re.MULTILINE)
    if m:
        status_raw = m.group(1).strip().lower()

    if status_raw != "needs_context" and "needs_context" not in (status_raw or ""):
        return None

    refs = _extract_open_refs(generated_text)
    helper = task["helper_fn"].lower()
    helper_seen = any(helper in r.lower() for r in refs)
    if not helper_seen:
        return None

    caller = _extract_caller(generated_text)
    if not caller:
        return None
    if len(caller) < 60:  # too short to be a real caller
        return None

    # Build the final training record. The user message wraps the caller code
    # in <SCAN>; the assistant message is everything EXCEPT the caller block.
    assistant_payload = generated_text
    # Strip the caller block from the assistant message — it belongs in the user
    # message at training time.
    assistant_payload = _re.sub(
        r"<<<CALLER_CODE>>>.*?<<<END_CALLER_CODE>>>\s*",
        "",
        assistant_payload,
        flags=_re.DOTALL,
    ).strip()

    record = {
        "messages": [
            {"role": "user", "content": f"<SCAN>\n{caller}\n</SCAN>"},
            {"role": "assistant", "content": assistant_payload},
        ],
        "_meta": {
            "shape": "shape2",
            "language": task["language"],
            "category": task["category"],
            "helper_fn": task["helper_fn"],
            "file_path": task["file_path"],
            "label": "needs_context",
            "cwes": [],
        },
    }
    return record
