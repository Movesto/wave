"""Guard-witness evaluator: does a proposed guard actually stop the attack?

The core defect this project keeps hitting is COMPLETENESS -- the model (and the old
data) declares a guard sufficient without checking what it admits. On signin.tsx the
guard was `raw.startsWith("/") && !raw.startsWith("//")`; it looks like it blocks open
redirect and does not -- a backslash form starts with `/`, is not `//`, and browsers
normalises a backslash to a forward slash, so it resolves to `//evil.com`.

A claim like "this guard is sufficient" is only worth anything if it can be checked. This
checks it the one way that cannot be fooled: run the guard's logic against a battery of
known bypass inputs and report which get through.

SAFETY: we do NOT execute scanned code. We recognise a small set of guard SHAPES and
reimplement THEIR SEMANTICS in Python, then evaluate our reimplementation against the
witnesses. Unknown shapes return `unknown`, never a false "safe".

This is deliberately small and verifiable. It is the seed of three things: a runtime
check for the scanner (no retrain), a verifier for witness-based training pairs, and a
reward signal for any later RL.

    from guard_witness import assess_guard
    assess_guard('raw.startsWith("/") && !raw.startsWith("//")', kind="redirect")
"""
import re
import urllib.parse
from dataclasses import dataclass, field


# Witness inputs per weakness class: strings that a SUFFICIENT guard must reject and an
# insufficient one lets through. Each has a note explaining why it is dangerous.
WITNESSES = {
    # Only RELIABLE, browser-universal bypasses belong here -- a witness has to be a proof,
    # not a maybe. `/%2f%2fevil.com` (needs the app to decode %2f) and control-char strip
    # tricks are parser/framework dependent, so they were removed: keeping them made the
    # battery flag a backslash-hardened guard on a bypass it actually blocks.
    "redirect": [
        ("//evil.com", "protocol-relative -> another origin"),
        (r"/\evil.com", "backslash normalises to //evil.com in the authority"),
        ("https://evil.com", "absolute URL to another origin"),
        ("javascript:alert(1)", "javascript: scheme"),
    ],
    "path": [
        ("../../etc/passwd", "classic traversal"),
        ("..%2f..%2fetc%2fpasswd", "url-encoded traversal"),
        ("....//....//etc/passwd", "doubled dots survive a single '..' strip"),
        ("/etc/passwd", "absolute path escapes the base dir"),
        (r"..\..\windows\win.ini", "backslash traversal on Windows"),
    ],
    "ssrf": [
        ("http://127.1/", "127.1 is a valid short form of 127.0.0.1"),
        ("http://2130706433/", "decimal form of 127.0.0.1"),
        ("http://0x7f000001/", "hex form of 127.0.0.1"),
        ("http://[::1]/", "IPv6 loopback, not the IPv4 literal"),
        ("http://0.0.0.0/", "0.0.0.0 routes to localhost on Linux"),
        ("http://169.254.169.254/latest/meta-data/",
         "cloud metadata endpoint -- the real SSRF prize"),
    ],
    # Two ways to reach Object.prototype: the direct `__proto__` key (one hop), or the
    # `constructor` -> `prototype` chain (two hops). A per-level key check is sufficient
    # iff it blocks `__proto__` AND at least one of {constructor, prototype} -- blocking
    # EITHER breaks the two-hop chain. So `prototype` is not an independent witness.
    "proto": [
        ("__proto__", "the direct prototype accessor"),
        ("constructor", "constructor.prototype chain, open unless constructor OR "
                        "prototype is blocked"),
    ],
    "command": [
        ("; id", "command separator"),
        ("| cat /etc/passwd", "pipe to another command"),
        ("$(whoami)", "command substitution"),
        ("`id`", "backtick substitution"),
        ("&& rm -rf /", "chained command"),
        ("x\nid", "newline injects a second command"),
        # argument injection: no shell metacharacters, so escapeshellcmd/metachar
        # escaping lets it straight through -- it becomes a FLAG to the program.
        ("--output=/etc/passwd", "argument injection: parsed as a flag, not data"),
        ("-oProxyCommand=id", "argument injection via a short option"),
    ],
}

# A safe redirect target / safe filename, to check the guard does not also reject valid
# input (a guard that rejects everything is not 'sufficient', it is broken).
BENIGN = {"redirect": "/library", "path": "chapter1.jpg", "command": "report.pdf",
          "ssrf": "https://images.example.com/cat.jpg", "proto": "username"}


@dataclass
class GuardVerdict:
    kind: str
    recognised: bool
    admits: list = field(default_factory=list)     # (witness, why) that get through
    blocks_benign: bool = False
    note: str = ""

    @property
    def sufficient(self):
        return self.recognised and not self.admits and not self.blocks_benign


# ---- semantic reimplementations of recognised guard shapes ------------------

def _redirect_predicate(guard: str):
    """Return a function value->bool ('is this value ACCEPTED as safe by the guard'),
    or None if the guard shape is not recognised."""
    g = " ".join(guard.split())

    # startsWith("/") && !startsWith("//")   (the signin.tsx shape)
    if re.search(r'startsWith\(\s*[\'"]/[\'"]\s*\)', g) and \
       re.search(r'!\s*\w+\.startsWith\(\s*[\'"]//[\'"]\s*\)', g):
        # honour a refining clause that also rejects backslashes (!includes("\\") /
        # indexOf("\\") / a regex), so we do NOT claim /\evil.com bypasses a guard that
        # blocks it. Without this the witness makes a false claim on a hardened guard.
        blocks_backslash = bool(re.search(
            r'(includes|indexOf|test|match|search|replace|contains)\s*\([^)]*\\', g))

        def accept(v):
            if not (v.startswith("/") and not v.startswith("//")):
                return False
            if blocks_backslash and "\\" in v:
                return False
            return True
        return accept

    # startsWith("/") ALONE, with no !startsWith("//") clause -- STRICTLY WEAKER than the
    # shape above, so it admits //evil.com directly. Recognise it so the weaker guard is
    # also proven insufficient (it was silently unrecognised before).
    if re.search(r'startsWith\(\s*[\'"]/[\'"]\s*\)', g):
        def accept(v):
            return v.startswith("/")     # //evil.com and /\evil.com both pass
        return accept

    # A proper `new URL(raw, base)` + origin/host check IS sufficient here; we do not
    # reimplement it, because a crude stand-in over-flagged correct code (a false
    # claim). Anything not on the known-bad list below returns None == UNKNOWN, and the
    # witness stays silent rather than accuse a good guard.
    return None


def _path_predicate(guard: str):
    g = " ".join(guard.split())

    # blocks '..' by substring only  ('..' in name / includes('..') / indexOf)
    if re.search(r'(includes|indexOf|__contains__|\bin\b|find|strpos|search)\s*'
                 r'[\(\s][\'"]\.\.[\'"]', g) or re.search(r'[\'"]\.\.[\'"]\s+in\b', g):
        # honour a co-present absolute-path reject (startsWith('/'), isabs, ^/ ...): with
        # it, /etc/passwd is already blocked, so we must NOT claim it as a bypass. Without
        # this the witness makes a false claim on `startswith('/') or '..' in name`.
        blocks_abs = bool(re.search(
            r"startswith\(\s*[\'\"]/|isabs|isAbsolute|indexOf\(\s*[\'\"]/[\'\"]\s*\)\s*===?\s*0"
            r"|charAt\(\s*0\s*\)\s*===?\s*[\'\"]/|^\s*\^/|\[\s*0\s*\]\s*===?\s*[\'\"]/", g))

        def accept(v):
            # the guard REJECTS when '..' present -> accepts otherwise. On its own it never
            # checks encoding or backslashes -- which is the whole point. If it ALSO rejects
            # absolute paths, an absolute witness is no longer admitted.
            if ".." in v:
                return False
            if blocks_abs and v.startswith("/"):
                return False
            return True
        return accept

    # rejects any '/' in the name  (the Juice Shop fileServer shape)
    if re.search(r'(includes|indexOf|__contains__)\s*[\(\s][\'"]/[\'"]', g):
        def accept(v):
            return "/" not in v    # misses %2f and backslash
        return accept

    # A proper canonicalise-then-contains guard (realpath/resolve + prefix) is treated
    # as UNKNOWN, not verified -- reimplementing it crudely flagged correct code. Only
    # the two provably-insufficient substring checks above are judged.
    return None


# shell metacharacters that escapeshellcmd / a metachar-escaping guard neutralises
_SHELL_META = set(";|&$`<>(){}[]*?~#\n\\!")


def _command_predicate(guard: str):
    g = " ".join(guard.split())

    # escapeshellcmd(...) -- the classic INSUFFICIENT guard. It escapes shell
    # metacharacters but does NOT stop a value that begins with `-` from being read as
    # an OPTION, so argument injection walks straight through. This is exactly the
    # "guard present but insufficient" completeness case.
    if re.search(r"escapeshellcmd\s*\(", g):
        def accept(v):
            # accepted-as-safe == the value survives escapeshellcmd unchanged, i.e. it
            # carries no metacharacter for escapeshellcmd to neutralise. The argument-
            # injection witnesses (`--output=...`, `-o...`) have none, so they pass.
            return not any(c in _SHELL_META for c in v)
        return accept

    # a STRICT allowlist -- only word chars / a fixed set -- is sufficient here.
    m = re.search(r"(?:preg_match|match|fullmatch|test)\s*\(\s*['\"]?/?\^?"
                  r"\[([^\]]+)\]\+?\$?", g)
    if m and "-" not in m.group(1) and "." not in m.group(1).replace("\\.", ""):
        allowed = m.group(1).replace("\\w", "A-Za-z0-9_")
        pat = re.compile("^[" + allowed + "]+$")
        def accept(v):
            return bool(pat.match(v))
        return accept

    # escapeshellarg(...) and shlex.quote(...) are the CORRECT primitives (single-quote
    # the whole value). Treated as UNKNOWN, never flagged -- reimplementing them crudely
    # risks a false claim against correct code.
    return None


# loopback / link-local hosts a denylist tends to enumerate, as BARE host strings
_SSRF_DENY_LITERALS = ("localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254")
# tokens that mean the guard RESOLVES the host to an IP first -- a fundamentally
# different (and defensible) design we must not second-guess
_SSRF_RESOLVE = ("gethostby", "getaddrinfo", "ip_address", "ipaddress", "socket.",
                 "resolve", "dns.", "is_private", "is_loopback", "inet_")
# a quoted string whose whole value is a host (optionally with a port), so a URL literal
# like 'http://127.0.0.1:8099/x' does NOT count -- that is a hardcoded sink, not a denylist
_SSRF_QUOTED = re.compile(r"""['"]([^'"/\s]+)['"]""")
# the literals must actually be COMPARED against something (membership / equality), else
# they are config or a request target, not a guard
_SSRF_CMP = re.compile(r"\bin\b|in_array|\.includes|\.indexof|===?|!==?|\bnot in\b", re.I)


def _ssrf_denylist(guard: str):
    """Bare loopback hosts used as a denylist in `guard`, or [] if this is not that shape."""
    g = "\n".join(ln for ln in guard.lower().splitlines()
                  if not re.search(r"\.(run|listen|bind)\s*\(|host\s*=\s*['\"]0\.0\.0\.0", ln))
    if any(t in g for t in _SSRF_RESOLVE):
        return []                                  # resolves the host first -> not this shape
    quoted = {q.strip().rstrip(".") for q in _SSRF_QUOTED.findall(g)}
    # keep only quoted tokens whose whole value is a denied host (drops URL/config strings)
    literals = sorted(h for h in _SSRF_DENY_LITERALS
                      if any(q == h or q.split(":")[0] == h for q in quoted))
    if not literals or not _SSRF_CMP.search(g):
        return []                                  # not compared -> a sink/config, not a guard
    return literals


def _ssrf_predicate(guard: str):
    # A DENYLIST of literal loopback hosts blocks the exact strings it names and NOTHING
    # else, so every alternate encoding of the same address is admitted -- the provably
    # insufficient SSRF shape. An allowlist / resolve-then-check design yields no bare-host
    # denylist and lands as UNKNOWN, never flagged.
    literals = _ssrf_denylist(guard)
    if not literals:
        return None

    def accept(v):
        return not any(lit in v.lower() for lit in literals)
    return accept


# a dangerous key named as a STRING LITERAL in a guard -- quoted, so a JS `constructor(){}`
# method definition or a `.prototype` property access is NOT mistaken for a blocklist entry
_PP_KEY = re.compile(r"""['"](__proto__|constructor|prototype)['"]""")


def _proto_predicate(guard: str):
    # Only a quoted dangerous-key literal counts as a blocklist entry. This is what keeps
    # `constructor(owner, apikey)` (a class method) from being read as a guard.
    blocked = {m.lower() for m in _PP_KEY.findall(guard)}
    if not blocked:
        # No key blocklist here. Object.create(null), a Map, hasOwnProperty, or
        # Object.freeze(Object.prototype) all land here: UNKNOWN, never flagged.
        return None

    chain_open = "constructor" not in blocked and "prototype" not in blocked

    def accept(v):
        # A witness is admitted iff the capability it exercises is still open:
        #   __proto__    -> the direct key is not blocked
        #   constructor  -> the two-hop chain is open (neither constructor nor prototype
        #                   is blocked; blocking either one is enough to stop it)
        v = v.lower()
        if v == "__proto__":
            return "__proto__" not in blocked
        if v == "constructor":
            return chain_open
        return v not in blocked
    return accept


_PREDICATE = {"redirect": _redirect_predicate, "path": _path_predicate,
              "command": _command_predicate, "ssrf": _ssrf_predicate,
              "proto": _proto_predicate}


# ---- XSS is context-dominated: the SAME encoder is right in one sink and wrong in
# another, so this class only fires where the sink CONTEXT makes a guard provably useless.
# htmlspecialchars in an HTML body, DOMPurify, React {value} -> UNKNOWN, never flagged. The
# htmlspecialchars-in-JS-string breakout is deliberately NOT modelled: it turns on PHP's
# ENT_QUOTES default (changed in 8.1), so claiming it would be a version-dependent guess.

# a sanitiser that only removes ANGLE BRACKETS -- strip_tags, or a replace targeting <>
_XSS_ANGLE_ONLY = re.compile(
    r"strip_tags\s*\(|"
    r"preg_replace\s*\(\s*['\"]/\s*\[?\s*<>?\s*\]?|"        # /[<>]/ or /</
    r"preg_replace\s*\(\s*['\"]/\s*[<>]|"
    r"str_replace\s*\(\s*\[?[^)]*['\"][<>]['\"]", re.I)
# the sanitiser's output embedded INSIDE a JS string literal (PHP echo into <script>)
_XSS_JS_EMBED = re.compile(
    r"(?:new\s+\w+\s*\(|[\w.]+\s*=)\s*['\"][^'\"\n]*<\?", re.I)
# a blocklist that targets ONLY the <script> tag
_XSS_SCRIPT_ONLY = re.compile(
    r"(?:str_replace|preg_replace|\.replace)\s*\([^)]*<\s*script", re.I)
# an HTML sink that writes into the document body
_XSS_HTML_SINK = re.compile(r"innerhtml|document\.write|\.html\s*\(|\becho\b|\bprint\b", re.I)
# any HTML-entity encoder (correct for a BODY context)
_XSS_ENTITY_ENC = re.compile(
    r"htmlspecialchars\s*\(|htmlentities\s*\(|escapehtml|escape_html|_\.escape\(", re.I)


def _xss_scan(code: str):
    """Provably-insufficient XSS guard in `code`, as a finding dict, or None.

    Only two context-tied shapes are judged; everything else (proper body encoding, a real
    sanitiser, or a raw no-guard sink that belongs to the taint layer) returns None.
    """
    c = code or ""

    # (A) a strip-<> / strip_tags sanitiser whose output lands INSIDE a JS string. Removing
    # angle brackets does nothing to a quote breakout -- `";alert(1)//` closes the string.
    if _XSS_ANGLE_ONLY.search(c) and _XSS_JS_EMBED.search(c):
        return {"kind": "xss", "guard": "strips <> / strip_tags in a JS-string context",
                "bypass": '";alert(1)//',
                "why": "inside a JS string the payload breaks out with a quote; removing "
                       "<> is irrelevant"}

    # (B) a blocklist that removes only <script> in an HTML sink. Event-handler vectors
    # need no <script> tag, so `<img src=x onerror=alert(1)>` fires anyway.
    if _XSS_SCRIPT_ONLY.search(c) and _XSS_HTML_SINK.search(c) and not _XSS_ENTITY_ENC.search(c):
        return {"kind": "xss", "guard": "blocklists <script> only",
                "bypass": "<img src=x onerror=alert(1)>",
                "why": "event-handler / non-script tags bypass a <script>-only blocklist"}

    return None


def assess_guard(guard: str, kind: str) -> GuardVerdict:
    """Run `guard`'s recognised semantics against the witness battery for `kind`."""
    v = GuardVerdict(kind=kind, recognised=False)
    build = _PREDICATE.get(kind)
    if not build:
        v.note = f"no witness battery for kind={kind}"
        return v
    accept = build(guard)
    if accept is None:
        v.note = "guard shape not recognised -- cannot verify, treat as UNKNOWN"
        return v
    v.recognised = True
    for w, why in WITNESSES[kind]:
        try:
            if accept(w):          # guard accepts a malicious input == it admits it
                v.admits.append((w, why))
        except Exception:
            pass
    try:
        v.blocks_benign = not accept(BENIGN[kind])
    except Exception:
        v.blocks_benign = True
    return v


_GUARD_LINE = re.compile(r"\b(if|includes|indexOf|startsWith|realpath|resolve"
                         r"|normpath|match|test|filter|preg_match|escapeshellcmd"
                         r"|escapeshellarg|fullmatch|shlex|__proto__|constructor"
                         r"|prototype)\b")


def witness_scan(code: str, kind: str):
    """First insufficient guard in `code` for `kind`, as a dict, or None.

    A single call the scanner can make: scans every guard-shaped line, runs the witness
    battery, returns the first proven-insufficient guard with its concrete bypass.
    """
    # SSRF and prototype-pollution guards span multiple lines (a denied-host list and its
    # membership test; a key check and a recursive walk), so both classes are assessed
    # against the whole block rather than one guard-shaped line.
    if kind == "ssrf":
        v = assess_guard(code or "", kind)
        if v.recognised and not v.sufficient and v.admits:
            w, why = v.admits[0]
            deny = ", ".join(_ssrf_denylist(code or ""))
            return {"kind": kind, "guard": f"denylist of literal hosts [{deny}]"[:80],
                    "bypass": w, "why": why}
        return None

    if kind == "proto":
        v = assess_guard(code or "", kind)
        if v.recognised and not v.sufficient and v.admits:
            w, why = v.admits[0]
            blocked = ", ".join(sorted({m for m in _PP_KEY.findall(code or "")}))
            return {"kind": kind, "guard": f"key blocklist [{blocked}]"[:80],
                    "bypass": w, "why": why}
        return None

    if kind == "xss":
        return _xss_scan(code or "")

    for ln in (code or "").splitlines():
        if not _GUARD_LINE.search(ln):
            continue
        v = assess_guard(ln.strip(), kind)
        if v.recognised and not v.sufficient and v.admits:
            w, why = v.admits[0]
            return {"kind": kind, "guard": ln.strip()[:80], "bypass": w, "why": why}
    return None


if __name__ == "__main__":
    # the signin.tsx guard, and a corrected version
    for g in ('raw.startsWith("/") && !raw.startsWith("//")',
              'raw.startsWith("/") && !raw.startsWith("//") && !raw.includes("\\\\")'):
        r = assess_guard(g, "redirect")
        print(f"\nguard: {g}")
        print(f"  recognised={r.recognised}  sufficient={r.sufficient}")
        for w, why in r.admits:
            print(f"  ADMITS {w!r:24s} -- {why}")
