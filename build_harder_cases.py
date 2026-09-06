"""Build a HARDER bench: 8 pairs where surface heuristics fail on BOTH sides.

Each pair = one 'looks-safe-but-VULN' + one 'looks-dangerous-but-SAFE' of the same sink
type. So a model that scores by "guard present -> safe" or "dangerous sink -> vuln" gets
BOTH wrong -> 0 pairs. Only knowing what the CONSTRUCT actually does succeeds.

  looks-guarded but VULN : the guard is present but bypassable / on the wrong variable
  looks-dangerous but SAFE: the sink is real but a construct neutralises it (execFile
                            arg-array, parameterised query, basename, textContent, ...)

Witness-checkable labels are cross-verified against guard_witness so they are not just
assertions. Writes harder_cases.jsonl (same schema as bench_cases.jsonl).
"""
import json
from guard_witness import witness_scan

# (pair, label, cwe, why, code) -- realistic TS/JS
CASES = [
 # P1 path -----------------------------------------------------------------
 ("path1", "vuln", "CWE-22", "includes('..') check runs BEFORE decodeURIComponent, so %2e%2e%2f bypasses it",
  "function read(name){\n"
  "  if (name.includes('..')) throw new Error('bad');\n"
  "  const p = decodeURIComponent(name);\n"
  "  return fs.readFileSync(path.join(BASE, p));\n}"),
 ("path1", "safe", "CWE-22", "path.basename strips every directory component, so traversal cannot survive",
  "function read(name){\n"
  "  const f = path.basename(name);\n"
  "  return fs.readFileSync(path.join(BASE, f));\n}"),

 # P2 path (absolute) ------------------------------------------------------
 ("path2", "vuln", "CWE-22", "blocks '..' but not an absolute path, so /etc/passwd escapes the base",
  "function load(name){\n"
  "  if (name.indexOf('..') !== -1) throw new Error('bad');\n"
  "  return fs.readFileSync(BASE + name);\n}"),
 ("path2", "safe", "CWE-22", "resolve() canonicalises, then the prefix check rejects anything outside base",
  "function load(name){\n"
  "  const p = path.resolve(BASE, name);\n"
  "  if (!p.startsWith(BASE + path.sep)) throw new Error('bad');\n"
  "  return fs.readFileSync(p);\n}"),

 # P3 sql ------------------------------------------------------------------
 ("sql", "vuln", "CWE-89", "validates userId but concatenates a DIFFERENT variable (userName) into the query",
  "function find(userId, userName){\n"
  "  if (!/^[0-9]+$/.test(userId)) throw new Error('bad');\n"
  "  return db.query(\"SELECT * FROM users WHERE name = '\" + userName + \"'\");\n}"),
 ("sql", "safe", "CWE-89", "value is a bound parameter (placeholder + arg), so it cannot alter the query",
  "function find(userName){\n"
  "  return db.query('SELECT * FROM users WHERE name = ?', [userName]);\n}"),

 # P4 command --------------------------------------------------------------
 ("command", "vuln", "CWE-78", "strips ; | & but not $() or backticks, and passes through a shell string",
  "function convert(file){\n"
  "  const clean = file.replace(/[;|&]/g, '');\n"
  "  return child_process.execSync('convert ' + clean);\n}"),
 ("command", "safe", "CWE-78", "execFile with an argument array invokes no shell, so metacharacters are inert",
  "function convert(file){\n"
  "  return child_process.execFileSync('convert', [file, '-resize', '100x100']);\n}"),

 # P5 ssrf -----------------------------------------------------------------
 ("ssrf", "vuln", "CWE-918", "denylist of literal hosts; 127.1 / [::1] / 2130706433 reach localhost anyway",
  "function fetchUrl(url){\n"
  "  const host = new URL(url).hostname;\n"
  "  if (host === 'localhost' || host === '127.0.0.1') throw new Error('bad');\n"
  "  return fetch(url);\n}"),
 ("ssrf", "safe", "CWE-918", "allowlist of external hosts; anything not on it is rejected before the request",
  "const ALLOWED = ['api.example.com', 'cdn.example.com'];\n"
  "function fetchUrl(url){\n"
  "  const host = new URL(url).hostname;\n"
  "  if (!ALLOWED.includes(host)) throw new Error('bad');\n"
  "  return fetch(url);\n}"),

 # P6 prototype pollution --------------------------------------------------
 ("proto", "vuln", "CWE-1321", "blocklist stops __proto__ but not constructor, so constructor.prototype still pollutes",
  "function merge(t, s){\n"
  "  for (const k in s){\n"
  "    if (k === '__proto__') continue;\n"
  "    if (typeof s[k] === 'object') merge(t[k], s[k]); else t[k] = s[k];\n"
  "  }\n}"),
 ("proto", "safe", "CWE-1321", "blocklist covers __proto__ AND constructor, breaking both routes to Object.prototype",
  "function merge(t, s){\n"
  "  for (const k in s){\n"
  "    if (k === '__proto__' || k === 'constructor') continue;\n"
  "    if (typeof s[k] === 'object') merge(t[k], s[k]); else t[k] = s[k];\n"
  "  }\n}"),

 # P7 open redirect --------------------------------------------------------
 ("redirect", "vuln", "CWE-601", "startsWith('/') is true for '//evil.com', a protocol-relative URL to another origin",
  "function go(res, next){\n"
  "  if (next.startsWith('/')) return res.redirect(next);\n"
  "  return res.redirect('/home');\n}"),
 ("redirect", "safe", "CWE-601", "requires startsWith('/'), not startsWith('//'), AND no backslash, so protocol-relative and /\\ are both rejected",
  "function go(res, next){\n"
  "  if (next.startsWith('/') && !next.startsWith('//') && !next.includes('\\\\')) return res.redirect(next);\n"
  "  return res.redirect('/home');\n}"),

 # P8 xss ------------------------------------------------------------------
 ("xss", "vuln", "CWE-79", "strips <script> only; an event-handler tag like <img onerror> still fires",
  "function render(el, input){\n"
  "  el.innerHTML = input.replace(/<script>/gi, '');\n}"),
 ("xss", "safe", "CWE-79", "textContent assigns text, never parsed as HTML, so no markup executes",
  "function render(el, input){\n"
  "  el.textContent = input;\n}"),
]

_WK = {"CWE-22": "path", "CWE-78": "command", "CWE-918": "ssrf", "CWE-1321": "proto",
       "CWE-601": "redirect", "CWE-79": "xss"}


def main():
    rows, checks = [], []
    for pair, label, cwe, why, code in CASES:
        rows.append({"pair_id": f"hard_{pair}", "label": label, "cwe": cwe,
                     "language": "typescript", "why": why, "code": code})
        # cross-check with the witness where it applies
        k = _WK.get(cwe)
        if k:
            w = witness_scan(code, k)
            if label == "vuln" and w:
                checks.append(f"OK  {pair:9s} vuln -> witness proves bypass {w['bypass']!r}")
            elif label == "vuln" and not w:
                checks.append(f"..  {pair:9s} vuln (witness silent -- shape outside battery, label by reasoning)")
            elif label == "safe" and w:
                checks.append(f"XX  {pair:9s} SAFE but witness FLAGGED it -- LABEL SUSPECT: {w['bypass']!r}")
            else:
                checks.append(f"OK  {pair:9s} safe -> witness silent (proper guard)")

    with open("harder_cases.jsonl", "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows)} cases ({len(rows)//2} pairs) -> harder_cases.jsonl\n")
    print("witness cross-check of labels:")
    for c in checks:
        print("  " + c)
    bad = [c for c in checks if c.startswith("  XX") or "XX" in c]
    print("\nlabel conflicts:", "NONE" if not any('XX' in c for c in checks) else "SEE ABOVE")


if __name__ == "__main__":
    main()
