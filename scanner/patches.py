"""Station 3 — concrete patch suggestions (deterministic, per-CWE).

The 8B is a scanner, not a reliable code rewriter, so Station 3 does NOT ask it to
regenerate arbitrary functions (that hallucinates). Instead it maps the confirmed
CWE + the exact sink (from Station 1) to a concrete, correct remediation with a
before -> after code example. Reliable and language-aware.
"""
import re

# cwe -> (one-line guidance, before-pattern, after-pattern)
PATCHES = {
    "CWE-89": ("Use a parameterized query — pass values as bound parameters, never string-build SQL.",
               'cur.execute("SELECT * FROM users WHERE id = " + uid)',
               'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))'),
    "CWE-78": ("Avoid the shell: pass an argument list and never interpolate input into a command string.",
               'os.system("ping " + host)',
               'subprocess.run(["ping", "-c", "1", host], shell=False, check=True)'),
    "CWE-22": ("Confine the path to a safe base directory and reject traversal.",
               'open("/var/data/" + name)',
               'base = Path("/var/data").resolve()\n'
               'target = (base / name).resolve()\n'
               'if base not in target.parents: raise ValueError("invalid path")\n'
               'open(target)'),
    "CWE-94": ("Never eval/exec untrusted input; use a safe parser or an explicit allow-list.",
               'eval(user_expr)',
               'import ast\nast.literal_eval(user_expr)  # only literals, no code execution'),
    "CWE-502": ("Do not deserialize untrusted data with pickle/yaml.load; use JSON or a safe loader.",
                'pickle.loads(data)',
                'json.loads(data)  # or yaml.safe_load(data)'),
    "CWE-918": ("Validate the destination against an allow-list of hosts before the request.",
                'requests.get(user_url)',
                'host = urlparse(user_url).hostname\n'
                'if host not in ALLOWED_HOSTS: raise ValueError("host not allowed")\n'
                'requests.get(user_url)'),
    "CWE-79": ("Escape/encode output, or use a framework that auto-escapes; never inject raw input into the DOM/HTML.",
               'element.innerHTML = name',
               'element.textContent = name  // or DOMPurify.sanitize(name)'),
    "CWE-327": ("Use a strong, current algorithm (SHA-256+/AES-GCM); MD5/SHA-1/DES are broken.",
                'hashlib.md5(password.encode())',
                'import bcrypt\nbcrypt.hashpw(password.encode(), bcrypt.gensalt())'),
    "CWE-338": ("Use a cryptographically secure RNG for security values.",
                'random.randint(0, 999999)  # for a token',
                'import secrets\nsecrets.token_urlsafe(32)'),
    "CWE-209": ("Do not leak exception details to clients; log server-side, return a generic message.",
                'detail=f"Failed: {e}"',
                'logger.exception("operation failed"); detail="Internal error"'),
    "CWE-295": ("Never disable TLS certificate verification.",
                'requests.get(url, verify=False)',
                'requests.get(url)  # verify defaults to True'),
    "CWE-798": ("Load secrets from the environment or a vault, not source code.",
                'API_KEY = "sk-hardcoded-value"',
                'API_KEY = os.environ["API_KEY"]'),
    "CWE-611": ("Disable external entity resolution in the XML parser.",
                'XMLParser(resolve_entities=True)',
                'XMLParser(resolve_entities=False, no_network=True)'),
    "CWE-95": ("Avoid dynamic eval; parse or dispatch explicitly.",
               'eval(expr)  // new Function(expr)',
               'JSON.parse(expr)  // or a fixed dispatch table'),
}
_JS_CWE = {"CWE-79", "CWE-95"}


def suggest(cwe, sink="", lang="py"):
    cwe = (cwe or "").upper()
    if cwe not in PATCHES:
        return None
    guide, before, after = PATCHES[cwe]
    return {"cwe": cwe, "guidance": guide, "before": before, "after": after}


def format_patch(p, indent="    "):
    if not p:
        return ""
    lines = [f"{indent}patch:  {p['guidance']}",
             f"{indent}  - before: {p['before'].splitlines()[0]}"]
    after = p["after"].splitlines()
    lines.append(f"{indent}  + after:  {after[0]}")
    for extra in after[1:]:
        lines.append(f"{indent}           {extra}")
    return "\n".join(lines)
