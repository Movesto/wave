"""Regression smoke for the guard-witness battery after the proto/ssrf fixes.

Runs every class over the real YWH snippets + the known DVNA/Juice guard cases and the
proper-guard controls, and asserts the EXPECTED verdict for each. A snippet with no
recognisable guard is expected to return None (that is the taint layer's job, not a miss).
"""
from guard_witness import witness_scan

SNIP = "data/ywh-snippets"


def code(path):
    return open(path, encoding="utf-8", errors="replace").read()


# (label, code, kind, expect_flag) -- expect_flag True == a bypass must be proven
CASES = [
    # ---- command injection ----
    ("YWH escapeshellcmd", code(f"{SNIP}/CommandInjection/command-injection-escapeshellcmd/"
                                f"vsnippet/41-command-injection-escapeshellcmd.php"),
     "command", True),
    ("YWH saint_patrick escapeshellcmd", code(f"{SNIP}/CommandInjection/"
        "command-injection-saint_patrick/vsnippet/command-injection-saint_patrick.php"),
     "command", True),
    ("YWH cmdi classic (no guard)", code(f"{SNIP}/CommandInjection/"
        "command-injection-classic/vsnippet/42-command-injection-classic.py"),
     "command", False),
    ("DVNA ping (no guard)", "exec('ping -c 2 ' + req.body.address)", "command", False),
    ("proper escapeshellarg", "$s=escapeshellarg($x); shell_exec('ls '.$s);", "command", False),
    ("proper shlex.quote", "import shlex; os.system('ls '+shlex.quote(n))", "command", False),

    # ---- ssrf ----
    ("YWH ssrf denylist", code(f"{SNIP}/SSRF/ssrf-regex-bypass/vsnippet/"
                               f"2-ssrf-regex-bypass.py"), "ssrf", True),
    ("YWH ssrf XFH (no denylist)", code(f"{SNIP}/SSRF/ssrf-XFH-header/vsnippet/"
                                        f"37-ssrf-XFH-header.php"), "ssrf", False),
    ("hardcoded 127.0.0.1 sink", "requests.get(f'http://127.0.0.1:{p}/shutdown')", "ssrf", False),
    ("hardcoded localhost base", "self._baseUrl='http://localhost:%d'%port", "ssrf", False),
    ("proper host allowlist", "if host not in ['api.example.com']: abort()\nrequests.get(u)",
     "ssrf", False),
    ("proper resolve+private", "ip=ipaddress.ip_address(socket.gethostbyname(h))\n"
                               "if ip.is_private: abort()", "ssrf", False),

    # ---- prototype pollution ----
    ("PP unguarded merge (no guard)", code(f"{SNIP}/PrototypePollution/pp-classic/"
                                           f"vsnippet/pp-classic.js"), "proto", False),
    ("PP __proto__-only blocklist", "if (key === '__proto__') continue;", "proto", True),
    ("PP block __proto__+constructor", "if (key==='__proto__'||key==='constructor'){}", "proto", False),
    ("PP block __proto__+prototype", "if (key==='__proto__'||key==='prototype'){}", "proto", False),
    ("PP full blocklist", "['__proto__','constructor','prototype'].includes(key)", "proto", False),
    ("PP Object.create(null)", "const t=Object.create(null); merge(t,src)", "proto", False),

    # ---- path ----
    ("path includes-slash only", "if (!file.includes('/')) { res.sendFile(file) }", "path", True),
    ("path '..' substring only", "if '..' in name: raise\nopen(base+name)", "path", True),
    ("proper realpath+prefix", "p=realpath(f)\nif not p.startswith(base): raise", "path", False),

    # ---- redirect ----
    ("redirect startsWith only", 'raw.startsWith("/") && !raw.startsWith("//")', "redirect", True),
    ("redirect proper hardened",
     'raw.startsWith("/") && !raw.startsWith("//") && !raw.includes("\\\\")', "redirect", False),

    # ---- xss ----
    ("YWH strip<> in JS ctx", code(f"{SNIP}/XSS/xss-ethical-hackers-day/vsnippet/"
                                   f"xss-ethical-hackers-day.php"), "xss", True),
    # script-tag: value in a <script> string with a quote-only strip -- vulnerable via
    # </script> close-tag (context shape D). Was 'expect none' before D existed.
    ("YWH xss script-context close-tag",
     code(f"{SNIP}/XSS/xss-script-tag/vsnippet/4-xss-script-tag.py"), "xss", True),
    ("YWH xss attribute context (csp-bypass)",
     code(f"{SNIP}/XSS/xss-csp-bypass/vsnippet/25-xss-csp-bypass.php"), "xss", True),
    ("YWH htmlspecialchars in JS (version-ambiguous -> silent)",
     code(f"{SNIP}/XSS/xss-string-outbreak/vsnippet/xss-string-outbreak.php"), "xss", False),
    ("script-only blocklist (html)", 'echo str_replace("<script>","",$_GET["x"]);', "xss", True),
    ("proper htmlspecialchars body", 'echo htmlspecialchars($_GET["x"]);', "xss", False),
    ("proper DOMPurify", 'el.innerHTML = DOMPurify.sanitize(dirty)', "xss", False),
    ("proper escapeHTML body", 'el.innerHTML = escapeHTML(name)', "xss", False),
]


def main():
    ok = bad = 0
    for label, c, kind, expect in CASES:
        r = witness_scan(c, kind)
        got = r is not None
        status = "PASS" if got == expect else "**FAIL**"
        if got == expect:
            ok += 1
        else:
            bad += 1
        detail = (f"bypass={r['bypass']!r}" if r else "no-witness")
        print(f"  {status}  [{kind:8s}] {label:34s} expect={'FLAG' if expect else 'none':4s} "
              f"-> {detail}")
    print(f"\n{ok}/{ok+bad} cases as expected"
          + ("" if bad == 0 else f"  ({bad} REGRESSION(S))"))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
