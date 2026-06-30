# Report: vuln-type taxonomy sanity + what's available per type vs already covered.
import os, json, re
from collections import Counter
os.environ.setdefault("WAVE_VERIFIED_LANGS", "python,javascript,typescript,react")
from cot.vuln_types import classify, ALL_TYPES
from cot.fix_pairs import iter_fix_pairs

# 1. sanity check the classifier
tests = {
    "cursor.execute('SELECT * FROM u WHERE id='+x)": "sql_injection",
    "os.system('rm '+name)": "command_injection",
    "el.innerHTML = userInput": "xss",
    "eval(data)": "code_injection",
    "fetch('http://'+host)": "ssrf",
    "pickle.loads(blob)": "deserialization",
    "send_file('/x/'+name)": "path_traversal",
    "res.redirect(req.query.next)": "open_redirect",
    "target[key]=obj['__proto__']": "prototype_pollution",
    "hashlib.md5(pw)": "crypto_weak",
}
print("=== classifier sanity ===")
ok = 0
for code, exp in tests.items():
    got = classify(code)[0]
    flag = "OK" if got == exp else f"X (got {got})"
    ok += got == exp
    print(f"  {flag:<20} {code[:45]}")
print(f"  {ok}/{len(tests)} correct\n")

# 2. available per type across the patch corpus (capped scan)
avail = Counter()
by_lang_type = Counter()
n = 0
for fp in iter_fix_pairs(languages={"python", "javascript", "typescript", "react"}):
    n += 1
    if n > 8000:
        break
    avail[fp["vuln_type"]] += 1
print(f"=== available vuln hunks by TYPE (scanned {n}) ===")
for t, c in avail.most_common():
    print(f"  {t:<22} {c}")

# 3. what the current verified set already covers (classify its codes)
have = Counter()
p = "data/cot/pilot/shape1_verified.jsonl"
if os.path.exists(p):
    for line in open(p, encoding="utf-8"):
        try:
            r = json.loads(line)
            m = re.search(r"<SCAN>\s*(.*?)\s*</SCAN>", r["messages"][0]["content"], re.S)
            if m:
                have[classify(m.group(1))[0]] += 1
        except Exception:
            pass
print(f"\n=== current verified set coverage by TYPE (total {sum(have.values())}) ===")
for t in ALL_TYPES:
    a = avail.get(t, 0)
    print(f"  {t:<22} have={have.get(t,0):<4} available~={a}")
