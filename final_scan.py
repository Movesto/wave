"""Final authoritative corpus scan (2026-07-24). One pass over every file in
pilot_clean + every integrity check + config-wiring check. Prints PASS/FAIL per
check so the corpus can be signed off before the v12 run.
"""
import json, glob, re, collections, hashlib, os

PILOT="data/cot/pilot_clean"; EVAL="data/cot/eval"; TRAINER="train_qwen_cot.py"
def norm(s): return re.sub(r"\s+"," ",s or "").strip().lower()
def code_of(u):
    m=re.search(r"<SCAN>\n?(.*?)\n?</SCAN>",u,re.S); return m.group(1) if m else u
def uhash(u): return hashlib.sha256(u.encode()).hexdigest()

PASS=[]; FAIL=[]
def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' — '+detail) if detail else ''}")

# ---------- load ----------
rows=[]; bad_json=0; malformed=0
files=sorted(glob.glob(f"{PILOT}/*.jsonl"))
for p in files:
    fn=os.path.basename(p)
    for ln,line in enumerate(open(p,encoding="utf-8"),1):
        line=line.strip()
        if not line: continue
        try: r=json.loads(line)
        except: bad_json+=1; continue
        m=r.get("messages") or []
        if len(m)<2 or m[0].get("role")!="user" or m[1].get("role")!="assistant":
            malformed+=1; continue
        a=m[1].get("content",""); meta=r.get("_meta") or {}
        st="vuln" if re.search(r"status:\s*(vuln|confirmed)",a) else ("safe" if "status: safe" in a else "ctx")
        rows.append(dict(fn=fn,user=m[0].get("content",""),asst=a,meta=meta,
                         status=st,code=norm(code_of(m[0].get("content",""))),
                         think=(re.search(r"<think>(.*?)</think>",a,re.S) or re.match("$","")).group(1) if re.search(r"<think>(.*?)</think>",a,re.S) else ""))
N=len(rows)
print(f"\n{'='*66}\nFINAL SCAN — {len(files)} files, {N} records\n{'='*66}")

print("\n[1] FILE INTEGRITY")
check("no invalid JSON lines", bad_json==0, f"{bad_json} bad")
check("all records well-formed (user+assistant)", malformed==0, f"{malformed} malformed")

print("\n[2] PER-RECORD FIELD VALIDITY")
vuln_bad=safe_bad=0
for r in rows:
    if r["status"]=="vuln":
        if not (re.search(r"cwe:\s*CWE-\d+",r["asst"]) and "trace:" in r["asst"]
                and re.search(r"severity:\s*(HIGH|MEDIUM|LOW)",r["asst"],re.I)): vuln_bad+=1
    elif r["status"]=="safe":
        if "cwe: none" not in r["asst"]: safe_bad+=1
check("vuln records have cwe+severity+trace", vuln_bad==0, f"{vuln_bad} incomplete")
check("safe records have cwe:none", safe_bad==0, f"{safe_bad} bad")

print("\n[3] CROSS-RECORD CONSISTENCY")
cl=collections.defaultdict(set)
for r in rows: cl[r["code"]].add(r["status"])
contra=sum(1 for s in cl.values() if {'vuln','safe'}<=s)
check("no same-code-both-label contradictions", contra==0, f"{contra}")
# Key on the full user INPUT (prompt+code), not code alone: the multi-task aux
# shapes (localize/fixgen) intentionally reuse the same code under different
# instructions — different training examples, not duplicates.
dup=collections.Counter((uhash(r["user"]),r["status"]) for r in rows)
ndup=sum(v-1 for v in dup.values() if v>1)
check("no exact (input,label) duplicates", ndup==0, f"{ndup}")

print("\n[4] EVAL LEAK")
evalh=set()
for p in glob.glob(f"{EVAL}/*.jsonl"):
    for line in open(p,encoding="utf-8"):
        line=line.strip()
        if line:
            try: evalh.add(uhash((json.loads(line).get("messages") or [{}])[0].get("content","")))
            except: pass
leak=sum(1 for r in rows if uhash(r["user"]) in evalh)
check("no eval records leaked into train", leak==0, f"{leak} leaked")

print("\n[5] REASONING QUALITY")
boiler=sum(1 for r in rows if "the fix adds a control the vulnerable code lacks" in r["asst"].lower())
empty=sum(1 for r in rows if r["status"]!="ctx" and len(r["think"].strip())<40)
overlen=sum(1 for r in rows if len(r["user"])>6000)
check("no over-templated boilerplate reused at scale", boiler< N*0.05, f"{boiler} ({100*boiler/N:.1f}%)")
check("no empty/near-empty reasoning", empty==0, f"{empty}")
check("no over-length (NaN-mask risk >6000 char)", overlen==0, f"{overlen}")

print("\n[6] CONTRASTIVE INTEGRITY")
con=[r for r in rows if "contrastive" in r["fn"]]
g=collections.defaultdict(dict)
for r in con: g[r["meta"].get("pair_id")][r["meta"].get("label")]=r
orphan=sum(1 for pid,d in g.items() if set(d)!={"vuln","safe"})
ident=giv=noguard=0
for pid,d in g.items():
    if set(d)!={"vuln","safe"}: continue
    vc=d["vuln"]["code"]; fc=d["safe"]["code"]
    if vc==fc: ident+=1
    m=re.search(r"neutralized by `([^`]*)`",d["safe"]["asst"]); gd=norm(m.group(1)) if m else ""
    if not gd: noguard+=1
    elif len(gd)>8 and gd in vc: giv+=1
check("all pairs complete (vuln+safe)", orphan==0, f"{orphan} orphaned")
check("no identical-code pairs", ident==0, f"{ident}")
check("no guard-already-in-vuln pairs", giv==0, f"{giv}")
check("all safe sides quote a guard", noguard==0, f"{noguard} missing")

print("\n[7] CONFIG WIRING")
src=open(TRAINER,encoding="utf-8").read()
mshapes=re.search(r'"shapes":\s*\[(.*?)\]',src,re.S)
shapes=set(re.findall(r'"([^"]+)"',mshapes.group(1))) if mshapes else set()
mweights=re.search(r'"shape_weights":\s*\{(.*?)\}',src,re.S)
weights=set(re.findall(r'"([^"]+)":',mweights.group(1))) if mweights else set()
diskfiles={os.path.basename(p)[:-6] for p in files}
missing_file=[s for s in shapes if s not in diskfiles]
missing_weight=[s for s in shapes if s not in weights]
unwired=[d for d in diskfiles if d not in shapes]
check("every configured shape has a file", not missing_file, str(missing_file))
check("every configured shape has a weight", not missing_weight, str(missing_weight))
check("no on-disk file is left unwired", not unwired, str(unwired))
check("contrastive shapes wired", {"shape1_contrastive","shape1_contrastive_syn"}<=shapes)

print("\n[8] DISTRIBUTION")
lab=collections.Counter(r["status"] for r in rows)
print(f"  vuln:safe = {lab['vuln']}:{lab['safe']} = {lab['vuln']/max(lab['safe'],1):.2f}  (ctx {lab['ctx']})")
lang=collections.Counter(r["meta"].get("language","?") for r in rows)
print(f"  langs: {dict(lang.most_common(8))}")
origin=collections.Counter(r["meta"].get("origin") for r in con)
print(f"  contrastive pairs: {len(g)}  origin(records): {dict(origin)}")
cwe=collections.Counter()
for r in rows:
    for c in (r["meta"].get("cwes") or []): cwe[c]+=1
print(f"  top CWEs: {dict(cwe.most_common(6))}")

print(f"\n{'='*66}")
print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed" + (f" -> {FAIL}" if FAIL else " -> ALL CHECKS PASS"))
print('='*66)
