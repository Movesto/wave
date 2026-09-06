"""Deep-enrich the templated sources in place (2026-07-24).

The audit found the template_reason-generated <think> traces (cvefixes, wave3,
fixjs, and template-shaped sft) were shallow + carried the "the fix adds a
control..." boilerplate. This rewrites those traces with the deep engine
(mechanism -> attacker -> impact), grounded in the record's own source/sink/cwe
and a re-derived real source, WITHOUT touching R2Vul/verified/codeql/contrastive
(already good or handled). Fields (status/cwe/severity/line) are preserved.

Detects template records by their generator signature so file boundaries don't
matter. Vuln traces (which carry `trace: src -> sink`) get full depth; safe
template traces get a deeper family-grounded safe explanation.
"""
import json, glob, re, collections
from cot.deep_trace import deep_vuln_think, deep_safe_think, FAMILY_DEPTH
from cot.cwe_contracts import family_of, CONTRACTS

PILOT="data/cot/pilot_clean"
VULN_SIG="is untrusted input entering this code"          # template_reason.build_vuln_trace
SAFE_SIG=re.compile(r"does not reach a dangerous sink unguarded|The code applies a control")
_SINK_STOP={"if","for","while","return","print","len","func","function","def","class"}
_ARG=re.compile(r"\(\s*([^)]*)")

def code_of(u):
    m=re.search(r"<SCAN>\n?(.*?)\n?</SCAN>",u,re.S); return m.group(1) if m else u
def field(a,k):
    m=re.search(rf"{k}:\s*(.+)",a); return m.group(1).strip() if m else ""
def better_source(source, sink, code):
    if source and source.lower() not in {"untrusted input","input","data","user","value","none",""}:
        return source
    base=(sink or "").split(".")[-1]
    for line in code.split("\n"):
        if base and base in line:
            m=_ARG.search(line[line.find(base):])
            if m:
                for tok in re.findall(r"[A-Za-z_$][\w$.]*",m.group(1)):
                    if len(tok)>2 and not tok.isdigit() and tok.split(".")[0].lower() not in _SINK_STOP:
                        return tok
    return source or "untrusted input"

def enrich_vuln(rec):
    a=rec["messages"][1]["content"]; code=code_of(rec["messages"][0]["content"])
    cwe=field(a,"cwe"); tr=field(a,"trace")
    m=re.match(r"(.+?)\s*->\s*(.+)",tr)
    if not m or not family_of(cwe): return False
    source=m.group(1).strip("`$ "); sink=m.group(2).strip("`$ ").split(" ")[0]
    source=better_source(source,sink,code)
    line=field(a,"line"); line=line if line and line!="none" else None
    new_think=deep_vuln_think(source,sink,line,cwe)
    rec["messages"][1]["content"]=re.sub(r"<think>.*?</think>",lambda _:new_think,a,count=1,flags=re.S)
    # keep trace source consistent with the (possibly improved) source
    rec["messages"][1]["content"]=re.sub(r"trace:\s*.+",f"trace: {source} -> {sink}",rec["messages"][1]["content"],count=1)
    return True

def enrich_safe(rec):
    a=rec["messages"][1]["content"]; cwe_hint=None
    # safe template has no cwe; infer family from control text if possible
    fam=None
    for f,d in CONTRACTS.items():
        if d["control"].split(";")[0][:20].lower() in a.lower(): fam=f; break
    control = CONTRACTS[fam]["control"] if fam else "the input is validated/neutralized before any sink"
    why = FAMILY_DEPTH[fam]["guard_why"] if fam in FAMILY_DEPTH else "validates or neutralizes the input before it reaches any sink"
    new_think=(f"<think>\nUntrusted input is present, but trace the path to the sink for a control. "
               f"The code applies a control: {control}. Because that {why}, the tainted value cannot "
               f"subvert the operation, so the code is safe.\n</think>")
    rec["messages"][1]["content"]=re.sub(r"<think>.*?</think>",lambda _:new_think,a,count=1,flags=re.S)
    return True

def main():
    changed=collections.Counter()
    for p in sorted(glob.glob(f"{PILOT}/*.jsonl")):
        if "contrastive" in p: continue                     # already deep
        recs=[json.loads(l) for l in open(p,encoding="utf-8")]
        dirty=False
        for r in recs:
            m=r.get("messages") or []
            if len(m)<2: continue
            a=m[1]["content"]
            if VULN_SIG in a:
                if enrich_vuln(r): changed["vuln"]+=1; dirty=True
            elif SAFE_SIG.search(a):
                if enrich_safe(r): changed["safe"]+=1; dirty=True
        if dirty:
            open(p,"w",encoding="utf-8").write("".join(json.dumps(r,ensure_ascii=False)+"\n" for r in recs))
    print(f"enriched templated traces: {dict(changed)}")

if __name__=="__main__":
    main()
