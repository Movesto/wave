"""Full corpus audit (2026-07-24). Answers: what data do we actually have, is it
repetitive, what's missing, is it one-sided (language/label/source skew), and where
are the levers for complex-vuln reasoning. Reads data/cot/pilot_clean/*.jsonl once.

Uses _meta where present (language/label/source/cwes); falls back to parsing the
assistant text for status/cwe when _meta is absent.
"""
import json, glob, re, collections, hashlib

PILOT = "data/cot/pilot_clean"

def norm_code(s):
    return re.sub(r"\s+", " ", s or "").strip().lower()

def get_code(user):
    m = re.search(r"<SCAN>\n?(.*?)\n?</SCAN>", user, re.S)
    return m.group(1) if m else user

def status_from_asst(a):
    if re.search(r"status:\s*(vuln|confirmed)", a): return "vuln"
    if "status: safe" in a: return "safe"
    return "context"

def think_of(a):
    m = re.search(r"<think>(.*?)</think>", a, re.S)
    return m.group(1).strip() if m else ""

rows = []
for path in glob.glob(f"{PILOT}/*.jsonl"):
    fname = path.replace("\\","/").split("/")[-1]
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line: continue
        try: r = json.loads(line)
        except: continue
        msgs = r.get("messages") or []
        if len(msgs) < 2: continue
        user, asst = msgs[0].get("content",""), msgs[1].get("content","")
        meta = r.get("_meta") or {}
        lang = (meta.get("language") or "unknown").lower()
        label = meta.get("label") or status_from_asst(asst)
        if label == "confirmed": label = "vuln"
        source = meta.get("source") or "?"
        cwes = meta.get("cwes") or []
        if not cwes:
            m = re.search(r"cwe:\s*(CWE-\d+)", asst)
            if m: cwes = [m.group(1)]
        code = get_code(user)
        think = think_of(asst)
        rows.append(dict(file=fname, lang=lang, label=label, source=source,
                         cwes=cwes, code=code, ncode=norm_code(code),
                         think=think, asst=asst, ulen=len(user)))

N = len(rows)
print(f"TOTAL RECORDS: {N}\n")

# ---------- 1. COMPOSITION BY FILE ----------
print("="*70, "\n1. COMPOSITION BY SOURCE FILE (label split)\n", "="*70)
byfile = collections.defaultdict(lambda: collections.Counter())
for r in rows: byfile[r["file"]][r["label"]] += 1
for f in sorted(byfile, key=lambda x:-sum(byfile[x].values())):
    c = byfile[f]; tot = sum(c.values())
    print(f"  {f:34s} {tot:6d}  vuln={c['vuln']:5d} safe={c['safe']:5d} ctx={c['context']:4d}")

# ---------- 2. LANGUAGE SKEW ----------
print("\n"+"="*70, "\n2. LANGUAGE DISTRIBUTION (one-sidedness)\n", "="*70)
lang = collections.Counter(r["lang"] for r in rows)
for l,n in lang.most_common():
    print(f"  {l:14s} {n:6d}  {100*n/N:5.1f}%")

# ---------- 3. LABEL BALANCE OVERALL + PER LANGUAGE ----------
print("\n"+"="*70, "\n3. VULN:SAFE BALANCE (overall + per language)\n", "="*70)
lab = collections.Counter(r["label"] for r in rows)
print(f"  OVERALL vuln={lab['vuln']} safe={lab['safe']} ctx={lab['context']}  "
      f"vuln:safe = {lab['vuln']/max(lab['safe'],1):.2f}")
perlang = collections.defaultdict(lambda: collections.Counter())
for r in rows: perlang[r["lang"]][r["label"]] += 1
for l in sorted(perlang, key=lambda x:-sum(perlang[x].values())):
    c = perlang[l]
    ratio = c['vuln']/max(c['safe'],1)
    flag = "  <-- SKEW" if (ratio>2 or ratio<0.5) and (c['vuln']+c['safe'])>50 else ""
    print(f"  {l:14s} vuln={c['vuln']:5d} safe={c['safe']:5d}  v:s={ratio:5.2f}{flag}")

# ---------- 4. CWE COVERAGE ----------
print("\n"+"="*70, "\n4. CWE COVERAGE (missing / thin / concentrated)\n", "="*70)
cwe = collections.Counter()
for r in rows:
    for c in r["cwes"]: cwe[c] += 1
print(f"  distinct CWEs: {len(cwe)}  | top 12:")
for c,n in cwe.most_common(12): print(f"    {c:10s} {n:5d}")
thin = [c for c,n in cwe.items() if n < 10]
print(f"  THIN CWEs (<10 records): {len(thin)}")
# vuln-type-level view if present
vt = collections.Counter()
# infer coarse type from CWE for a gap picture
FAM = {"injection":{"CWE-89","CWE-78","CWE-94","CWE-79","CWE-90","CWE-91","CWE-611","CWE-917"},
       "auth/authz":{"CWE-284","CWE-287","CWE-306","CWE-862","CWE-863","CWE-639","CWE-285"},
       "crypto":{"CWE-327","CWE-328","CWE-326","CWE-916","CWE-321","CWE-330","CWE-338"},
       "memory":{"CWE-119","CWE-125","CWE-787","CWE-416","CWE-476","CWE-122","CWE-190"},
       "path/ssrf":{"CWE-22","CWE-918","CWE-601","CWE-23"},
       "deserialize":{"CWE-502","CWE-915"},
       "info-exposure":{"CWE-200","CWE-209","CWE-312","CWE-532","CWE-117"}}
fam = collections.Counter()
for c,n in cwe.items():
    hit=False
    for name,members in FAM.items():
        if c in members: fam[name]+=n; hit=True
    if not hit: fam["other/uncategorized"]+=n
print("  BY FAMILY:")
for name,n in fam.most_common(): print(f"    {name:22s} {n:6d}")

# ---------- 5. REPETITION / DUPLICATION ----------
print("\n"+"="*70, "\n5. REPETITION & TEMPLATE REGURGITATION\n", "="*70)
codehash = collections.Counter(r["ncode"] for r in rows)
exact_dup = sum(v-1 for v in codehash.values() if v>1)
print(f"  distinct normalized code: {len(codehash)} / {N}  "
      f"(near-dup collisions: {exact_dup})")
# most-cloned snippets
clones = [(c,n) for c,n in codehash.items() if n>3]
print(f"  snippets appearing >3x: {len(clones)} (top:")
for c,n in sorted(clones,key=lambda x:-x[1])[:5]:
    print(f"    {n:4d}x  {c[:70]}")
# template boilerplate in <think>
PHRASES = ["the fix adds a control the vulnerable code lacks",
           "no dangerous sink, no untrusted input",
           "data flow is therefore",
           "without any validation or sanitization",
           "this constitutes a direct flow from an untrusted source"]
for p in PHRASES:
    k = sum(p in r["think"].lower() for r in rows)
    print(f"  think contains \"{p[:45]}...\": {k} ({100*k/N:.1f}%)")
# trace-length distribution (reasoning depth proxy)
tl = [len(r["think"]) for r in rows]
tl.sort()
print(f"  <think> length chars: p10={tl[N//10]} median={tl[N//2]} p90={tl[9*N//10]} max={tl[-1]}")
short = sum(1 for x in tl if x<120)
print(f"  very short traces (<120 chars, shallow reasoning): {short} ({100*short/N:.1f}%)")

# ---------- 6. SOURCE CONCENTRATION ----------
print("\n"+"="*70, "\n6. SOURCE CONCENTRATION (single-source dependence)\n", "="*70)
src = collections.Counter(r["source"] for r in rows)
for s,n in src.most_common(12): print(f"  {s:24s} {n:6d}  {100*n/N:4.1f}%")

# ---------- 7. COMPLEXITY / CROSS-FILE ----------
print("\n"+"="*70, "\n7. COMPLEXITY SIGNAL (single vs multi-file/hop)\n", "="*70)
xfile = sum(1 for r in rows if "codeql" in r["file"] or r["file"].startswith("shape3") or r["file"].startswith("shape4"))
print(f"  cross-file / multi-hop records (shape3/4/codeql): {xfile} ({100*xfile/N:.1f}%)")
print(f"  single-file records: {N-xfile} ({100*(N-xfile)/N:.1f}%)")
EOF_MARKER = None
