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
    "redirect": [
        ("//evil.com", "protocol-relative -> another origin"),
        (r"/\evil.com", "backslash normalises to //evil.com in the authority"),
        ("https://evil.com", "absolute URL to another origin"),
        ("/%2f%2fevil.com", "encoded //"),
        ("/\thttps://evil.com", "leading control char, some parsers strip it"),
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
          "ssrf": "https://images.example.com/cat.jpg"}


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
        def accept(v):
            return v.startswith("/") and not v.startswith("//")
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
        def accept(v):
            # the guard REJECTS when '..' present -> accepts otherwise. It never checks
            # absolute paths, encoding, or backslashes -- which is the whole point.
            return ".." not in v
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


# loopback / link-local literals a denylist tends to enumerate
_SSRF_DENY_LITERALS = ("localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254",
                       "10.", "192.168", "172.16")
# tokens that mean the guard RESOLVES the host to an IP first -- a fundamentally
# different (and defensible) design we must not second-guess
_SSRF_RESOLVE = ("gethostby", "getaddrinfo", "ip_address", "ipaddress", "socket.",
                 "resolve", "dns.", "is_private", "is_loopback", "inet_")


def _ssrf_predicate(guard: str):
    # Drop server-bind lines (`app.run(host='0.0.0.0')`, `.listen(...)`) -- a bind address
    # is not a denylist entry, and harvesting it would misname the guard.
    g = "\n".join(ln for ln in guard.lower().splitlines()
                  if not re.search(r"\.(run|listen|bind)\s*\(|host\s*=\s*['\"]0\.0\.0\.0", ln))

    # If the guard resolves the host before deciding, it is not the literal-denylist
    # shape this battery proves against -- leave it UNKNOWN, never flag it.
    if any(t in g for t in _SSRF_RESOLVE):
        return None

    # A DENYLIST of literal loopback/private hosts. It blocks the exact strings it names
    # and NOTHING ELSE, so every alternate encoding of the same address is admitted. This
    # is the provably-insufficient SSRF shape.
    literals = [lit for lit in _SSRF_DENY_LITERALS if lit in g]
    if literals:
        def accept(v):
            # admitted == the URL carries none of the denied literals verbatim
            return not any(lit in v.lower() for lit in literals)
        return accept

    # An allowlist of external hosts (the correct design) carries no loopback literals,
    # so it lands here: UNKNOWN, not flagged.
    return None


_PREDICATE = {"redirect": _redirect_predicate, "path": _path_predicate,
              "command": _command_predicate, "ssrf": _ssrf_predicate}


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
                         r"|escapeshellarg|fullmatch|shlex)\b")


def witness_scan(code: str, kind: str):
    """First insufficient guard in `code` for `kind`, as a dict, or None.

    A single call the scanner can make: scans every guard-shaped line, runs the witness
    battery, returns the first proven-insufficient guard with its concrete bypass.
    """
    # SSRF denylists split the blocked-host list and the check across lines, so this
    # class is assessed against the whole block rather than one guard-shaped line.
    if kind == "ssrf":
        v = assess_guard(code or "", kind)
        if v.recognised and not v.sufficient and v.admits:
            w, why = v.admits[0]
            _g = "\n".join(ln for ln in (code or "").lower().splitlines()
                           if not re.search(r"\.(run|listen|bind)\s*\(|"
                                             r"host\s*=\s*['\"]0\.0\.0\.0", ln))
            deny = ", ".join(lit for lit in _SSRF_DENY_LITERALS if lit in _g)
            return {"kind": kind, "guard": f"denylist of literal hosts [{deny}]"[:80],
                    "bypass": w, "why": why}
        return None

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
