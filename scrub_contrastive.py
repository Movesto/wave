"""Post-stage contrastive scrub (2026-07-24) — the cross-pair/global checks that
can't be done in the streaming builder. Always run AFTER dedup_and_stage. Makes
the contrastive files clean by construction so the defects can't recur:
  - incomplete pairs (missing a side)
  - identical-after-normalize (cosmetic 'fix')
  - guard already present in vuln (false 'neutralized by')
  - empty/missing guard quote
  - record-level duplicates (same code across pairs)
  - whole-corpus contradictions (code labelled both vuln and safe anywhere)
"""
import json, glob, re, collections
PILOT="data/cot/pilot_clean"
def norm(s): return re.sub(r"\s+"," ",s or "").strip().lower()
def code_of(u):
    m=re.search(r"<SCAN>\n?(.*?)\n?</SCAN>",u,re.S); return m.group(1) if m else u

# labels present for every code across the WHOLE corpus (to catch contradictions)
corpus_lab=collections.defaultdict(set)
for p in glob.glob(f"{PILOT}/*.jsonl"):
    if "contrastive" in p: continue
    for line in open(p,encoding="utf-8"):
        line=line.strip()
        if not line: continue
        r=json.loads(line); m=r.get("messages") or []
        if len(m)<2: continue
        a=m[1].get("content","")
        st="vuln" if re.search(r"status:\s*(vuln|confirmed)",a) else ("safe" if "status: safe" in a else "ctx")
        corpus_lab[norm(code_of(m[0].get("content","")))].add(st)

for fname in ["shape1_contrastive.jsonl","shape1_contrastive_syn.jsonl"]:
    path=f"{PILOT}/{fname}"
    recs=[json.loads(l) for l in open(path,encoding="utf-8")]
    g=collections.OrderedDict()
    for r in recs: g.setdefault(r["_meta"]["pair_id"],{})[r["_meta"]["label"]]=r
    seen=set(); keep=set(); drop=collections.Counter()
    for pid,d in g.items():
        if set(d)!={"vuln","safe"}: drop["incomplete"]+=1; continue
        vc=norm(code_of(d["vuln"]["messages"][0]["content"]))
        fc=norm(code_of(d["safe"]["messages"][0]["content"]))
        if vc==fc: drop["identical"]+=1; continue
        m=re.search(r"neutralized by `([^`]*)`",d["safe"]["messages"][1]["content"])
        gd=norm(m.group(1)) if m else ""
        if not gd: drop["empty_guard"]+=1; continue
        if len(gd)>8 and gd in vc: drop["guard_in_vuln"]+=1; continue
        if vc in seen or fc in seen: drop["dup"]+=1; continue
        # contradiction: this pair's vuln code is elsewhere 'safe', or safe code elsewhere 'vuln'
        if "safe" in corpus_lab.get(vc,set()) or "vuln" in corpus_lab.get(fc,set()):
            drop["contradiction"]+=1; continue
        seen.add(vc); seen.add(fc); keep.add(pid)
        corpus_lab[vc].add("vuln"); corpus_lab[fc].add("safe")
    out=[r for r in recs if r["_meta"]["pair_id"] in keep]
    open(path,"w",encoding="utf-8").write("".join(json.dumps(r,ensure_ascii=False)+"\n" for r in out))
    print(f"{fname}: kept {len(out)} records ({len(keep)} pairs) | dropped {dict(drop)}")
