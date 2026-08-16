"""Scale reasoning generation with DeepSeek V4 Flash (via OpenRouter), gated.

The verdict is NOT handed to the model. The bridge knows the true side (vuln = patch pre-image,
safe = post-image); the model is shown ONLY the code (plus the CWE class to consider) and must
decide for itself -- vuln, safe, or unsure. We then GATE on agreement:

  - model agrees with the bridge + grounded + cites a changed token  -> KEPT training pair
  - model DISAGREES (safe-side code judged vuln, or vice-versa)       -> regen_suspect.jsonl
      (a label-audit signal: an incomplete fix labelled 'safe', etc. -- do NOT train on it)
  - model says 'unsure'                                               -> regen_unsure.jsonl
  - the safe side is a witness-covered kind and witness_scan PROVES a bypass -> suspect
      (the fix is provably insufficient, so the 'safe' label is wrong)

This turns the old verdict-rationalisation pressure (which manufactured 'airtight' safe traces)
into a mechanism that surfaces mislabelled records instead of memorising them.

  python gen_regen.py --n 2      # smoke
  python gen_regen.py --n 20     # pilot
Reads OPENROUTER_API_KEY from env or .env. Model: deepseek/deepseek-v4-flash-0731.
"""
import argparse, hashlib, json, os, re, sys, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, "."); sys.path.insert(0, "scanner")
from patch_extract import views_both, changed, alignment
from star_ts import grounded
from safe_veto import prove_safe
from guard_witness import witness_scan

_TID = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
ALIGN_MIN = 0.5

# CWE -> witness/prove_safe kind (the classes the verifier can actually reason about).
CWE2KIND = {
    "CWE-22": "path", "CWE-23": "path", "CWE-36": "path", "CWE-59": "path",
    "CWE-78": "command", "CWE-77": "command",
    "CWE-89": "sql", "CWE-943": "sql",
    "CWE-918": "ssrf", "CWE-1321": "proto", "CWE-915": "proto",
    "CWE-601": "redirect",
    "CWE-79": "xss", "CWE-80": "xss", "CWE-83": "xss",
}


def cites_change(trace, changed_idents):
    """diff-aware grounding: the trace must reference a token the FIX actually touched,
    not just any identifier in the file."""
    return bool({t for t in _TID.findall(trace)} & changed_idents)


# A trace must reach its verdict from the CODE SHOWN, not from memorised knowledge of the CVE.
# These phrases are appeals to an EXTERNAL authority (the advisory / changelog / CVE record /
# README / "known vulnerability") -- when a trace leans on one, it is recalling the answer, not
# analysing the snippet (e.g. CVE-2023-1255: "the advisory places the bug squarely in this region";
# CVE-2022-39227: "the historical acceptance of alg=none"). Unambiguous authority terms only, to
# avoid punishing legitimate teaching language ("this is a classic overread") or a grounded
# "the snippet contains no sink" observation.
_LEAK = re.compile(
    r"\bCVE-\d{4}-\d{3,}\b"
    r"|\bGHSA-[a-z0-9]{4}"
    r"|\badvisor(?:y|ies)\b"
    r"|\bchangelog\b"
    r"|\b(?:release|update|patch)\s+notes\b"
    r"|\bsecurity\s+(?:bulletin|advisory)\b"
    r"|\bthe\s+README\b"
    r"|\b(?:NVD|MITRE)\b"
    r"|\bthe\s+(?:vulnerability|CVE)\s+(?:database|record|report|entry)\b"
    r"|\bas\s+(?:reported|disclosed|publicly\s+documented)\b"
    r"|\bhistorical\w*\s+(?:accept|known|vulnerab)"
    r"|\bknown\s+vulnerabilit"
    r"|\bwell-known\s+(?:CVE|vulnerab)"
    r"|\bthe\s+(?:security\s+)?(?:patch|fix|update)\s+notes\b",
    re.I)


def grounding_leak(trace, code=""):
    """Return the offending phrase if the trace appeals to external CVE/advisory knowledge to
    reach its verdict, else None. A leaking trace is rejected even when it agrees with the label:
    it got the right answer for an ungrounded reason, which is exactly what we must not train on.

    Context-aware: an authority word that ALSO appears in the code shown is describing the snippet
    (some patch hunks ARE changelog/README/notes edits), not appealing outside it -- not a leak."""
    lc = (code or "").lower()
    for m in _LEAK.finditer(trace or ""):
        term = m.group(0)
        toks = re.findall(r"[a-z]{4,}", term.lower()) or [term.lower()]
        if term.lower() in lc or any(t in lc for t in toks):
            continue                       # the word is in the analysed code -> describing it
        return term
    return None


# Sink-plausibility: does the extracted code even contain a construct that could be a sink/mechanism
# for the labelled CWE? If a MODELLED CWE class has NO matching construct, the extraction likely
# missed the vuln locus (a CWE-434 label on pure rendering code, an SQLi label on code with no
# query) -> a verdict on it is vacuous, so drop the CVE BEFORE spending an API call. Families cover
# only classes we can pattern with high recall; anything unmodelled (memory-safety, calc, locking)
# passes by default -- we never drop what we cannot assess.
_SINK_FAMILIES = {
    "sqli":     (["CWE-89", "CWE-564", "CWE-943"],
                 r"execute|executemany|\bquery\b|cursor|prepare|mysqli|pg_query|sqlite|"
                 r"SELECT\s|INSERT\s|UPDATE\s|DELETE\s|WHERE\s|\.raw\(|Sprintf|knex|sequelize"),
    "cmd":      (["CWE-77", "CWE-78", "CWE-88", "CWE-94", "CWE-95"],
                 r"\bsystem\(|popen|\bexec[lv]?\(|execFile|\bspawn|subprocess|shell_exec|"
                 r"passthru|proc_open|Runtime\.getRuntime|os\.system|child_process|\beval\(|`"),
    "xss":      (["CWE-79", "CWE-80", "CWE-83", "CWE-116"],
                 r"innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|insertAdjacentHTML|"
                 r"\.html\(|render|echo\s|print|escapetool|htmlspecialchars|htmlentities|<script|"
                 r"response\.write|\.send\("),
    "path":     (["CWE-22", "CWE-23", "CWE-36", "CWE-59", "CWE-73"],
                 r"\bopen\(|fopen|readFile|writeFile|File\(|Paths\.get|os\.path|\binclude|"
                 r"require\(|\bfs\.|readdir|sendFile|realpath|basename|unlink|__dirname|file_get"),
    "upload":   (["CWE-434"],
                 r"move_uploaded_file|\$_FILES|multipart|unzip|extract|ZipFile|\bsave\(|upload|"
                 r"\bcopy\(|putObject|createWriteStream|write\("),
    "ssrf":     (["CWE-918"],
                 r"requests\.(get|post)|urlopen|urllib|fetch\(|axios|http\.get|HttpClient|"
                 r"curl_exec|file_get_contents\s*\(\s*\$|\.open\("),
    "deser":    (["CWE-502"],
                 r"unserialize|pickle\.load|yaml\.load|Marshal\.load|readObject|ObjectInputStream|"
                 r"__reduce__|deserialize"),
    "xxe":      (["CWE-611", "CWE-827"],
                 r"parseXML|DocumentBuilder|SAXParser|etree|loadXML|XMLReader|simplexml|libxml"),
    "proto":    (["CWE-1321", "CWE-915"],
                 r"__proto__|constructor|prototype|\bmerge\(|extend\(|Object\.assign|deepMerge"),
    "redirect": (["CWE-601"],
                 r"redirect|Location:|sendRedirect|res\.redirect|header\s*\(\s*[\"']Location|"
                 r"window\.location"),
}
# NOTE: only POSITIVE-SINK classes are gated above -- ones where the vulnerable code MUST contain a
# dangerous operation (a query, an output sink, an exec, a file op). "Absence-of-control" classes
# (CSRF-352, missing authz/auth, improper-privilege) are deliberately NOT gated: their vuln is a
# MISSING check, so the fix ADDS the construct and the pre-fix code legitimately has none -- gating
# them would false-drop every one. Those CWEs fall through has_plausible_sink as unmodelled -> pass.
_CWE_SINK = {}
for _fam, (_cwes, _pat) in _SINK_FAMILIES.items():
    _rx = re.compile(_pat, re.I)
    for _c in _cwes:
        _CWE_SINK[_c] = _rx


def has_plausible_sink(code, cwes):
    """True if `code` contains a plausible sink for at least one labelled CWE we model. CWEs we do
    NOT model (memory-safety, incorrect-calc, race) return True -- never drop what we can't assess.
    Only a MODELLED CWE with zero matching constructs returns False = likely mislabel/mis-extraction."""
    modeled = [c for c in cwes if (c or "").upper() in _CWE_SINK]
    if not modeled:
        return True
    return any(_CWE_SINK[c.upper()].search(code or "") for c in modeled)


def kind_of(cwes):
    for c in cwes:
        k = CWE2KIND.get((c or "").upper())
        if k:
            return k
    return None


MODEL = "deepseek/deepseek-v4-flash-0731"
URL   = "https://openrouter.ai/api/v1/chat/completions"
WORKLIST = "data/cot/staging/regen_worklist.jsonl"
GOLD     = "data/cot/staging/regen_gold.jsonl"
OUT      = "data/cot/staging/regen_deepseek.jsonl"
SUSPECT  = "data/cot/staging/regen_suspect.jsonl"
UNSURE   = "data/cot/staging/regen_unsure.jsonl"
LEAK     = "data/cot/staging/regen_leak.jsonl"
SINGLES  = "data/cot/staging/regen_singles.jsonl"

SYSTEM = (
 "You are writing a worked security-analysis example that will TRAIN a vulnerability detector. "
 "That detector will later see ONLY code -- no verdict, no CWE, no hint -- and must decide for "
 "itself. So do NOT assume an answer and argue back to it. Investigate THIS specific code and "
 "reach your OWN conclusion: is the untrusted input actually reachable at the sink? is there a "
 "guard or encoder in the way? does it neutralise EVERY input that matters, or only the obvious "
 "one -- and is it even the RIGHT defense for this sink and this context (e.g. backslash-escaping "
 "a value that lands inside a SQL identifier, or HTML-body encoding a value that lands in an "
 "attribute)? Name the real variables and functions. If you judge it vulnerable, give the concrete "
 "attacker payload that gets through. If you judge it safe, name the exact guard or encoder, state "
 "the specific bypass it blocks AND the context that makes it the correct defense; if a nearby "
 "context or a sibling input would defeat that same construct, say so and lower your confidence "
 "rather than overstating it. Mention what you seriously considered and ruled out. Be honest when a "
 "sink or helper is out of view: if the snippet does not show enough to prove it either way, the "
 "correct answer is 'unsure' -- say what you would need to see. Do NOT overstate certainty; a "
 "hedged, accurate read is worth more than a confident wrong one. Write in plain CONTINUOUS PROSE "
 "-- no section headers, labels, bullet lists, or fixed template, and vary how you open and "
 "structure it. Do not recite textbook definitions. End with EXACTLY one line: 'status: vuln', "
 "'status: safe', or 'status: unsure'.")

# per-record rotation so the corpus teaches MANY reasoning approaches, not one skeleton
STANCES = [
 "Trace it forward: start from the untrusted input and follow it to the dangerous operation.",
 "Work backwards: start from what the attacker ends up able to do, then find the flaw that allows it.",
 "Center on the control -- the guard or encoder -- and decide whether it is present, sufficient, and the RIGHT one for this sink.",
 "Anchor on the one concrete input that would flip the outcome, and walk through exactly what it does at the sink.",
 "Read it the way you would in code review, focusing on the specific line that decides it.",
 "Start from the sink and ask what has to be true of everything flowing into it for this to be safe.",
]
# an OPTIONAL generalization angle -- only if it fits, so it is not bolted on every trace
GEN_ANGLES = [
 "If -- and only if -- it fits naturally, you may in one clause connect the root cause to a DIFFERENT language or framework.",
 "If it fits, note in passing a sibling input or code path that would reach the SAME sink -- the kind an incomplete fix misses.",
 "If it fits, note how an attacker could vary the payload or its encoding to slip past a naive version of this guard.",
 "You need not generalize; if a broader principle is genuinely illuminated here, state it in one plain clause, no textbook definition.",
 "",
]


def _pick(lst, *seed):
    h = int(hashlib.md5("|".join(map(str, seed)).encode()).hexdigest(), 16)
    return lst[h % len(lst)]


def build_user(code, cwe, stance, gen_angle):
    """Neutral framing: the model is NOT told which side it is (vuln pre-image vs safe post-image).
    It gets the code and the CWE class to consider, and must reach its own verdict."""
    tail = (" " + gen_angle) if gen_angle else ""
    return (f"<SCAN>\n{code}\n</SCAN>\n"
            f"Analyze this code for a possible {cwe} vulnerability. It may or may not be present -- "
            f"decide for yourself from the code shown. Approach for this one: {stance}{tail} "
            f"Write it as natural continuous prose with no headers or labels, and end with "
            f"'status: vuln', 'status: safe', or 'status: unsure'.")


def load_key():
    k = os.environ.get("OPENROUTER_API_KEY")
    if k:
        return k
    if os.path.exists(".env"):
        for line in open(".env", encoding="utf-8"):
            if line.strip().startswith("OPENROUTER_API_KEY"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("OPENROUTER_API_KEY not found in env or .env")


def fewshot():
    """Two gold exemplars, framed with the SAME neutral request as build_user, so the few-shot
    models the flowing, no-header style AND the self-reached verdict (no pre-stated answer)."""
    ex = [json.loads(l) for l in open(GOLD, encoding="utf-8")]
    v = next(e for e in ex if e["_meta"]["label"] == "vuln")
    s = next(e for e in ex if e["_meta"]["label"] == "safe")
    msgs = []
    for e in (v, s):
        m = e["_meta"]
        code = e["messages"][0]["content"].replace("<SCAN>", "").replace("</SCAN>", "").strip()
        stance = _pick(STANCES, m["cve"], m["label"])
        gen = _pick(GEN_ANGLES, m["cve"], m["label"], "g")
        msgs.append({"role": "user", "content": build_user(code, m["cwe"], stance, gen)})
        msgs.append({"role": "assistant", "content": e["messages"][1]["content"]})
    return msgs


def call(messages, key, timeout=120, retries=3):
    # deepseek-v4-flash is a REASONING model. On hard cases (memory-safety C/C++/rust) it will
    # otherwise burn the ENTIRE budget on hidden reasoning and emit ZERO visible content
    # (finish=length, content='', reasoning_tokens==max_tokens). Two-part fix: cap reasoning so
    # budget is reserved for the answer, AND keep max_tokens high enough for reasoning + trace.
    body = json.dumps({"model": MODEL, "messages": messages, "temperature": 0.3,
                       "max_tokens": 4500, "reasoning": {"max_tokens": 1800}}).encode()
    for attempt in range(retries):
        try:
            req = urllib.request.Request(URL, data=body, headers={
                "Content-Type": "application/json", "Authorization": f"Bearer {key}",
                "X-Title": "wave-regen"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                d = json.loads(r.read())
            return d["choices"][0]["message"]["content"], d.get("usage", {})
        except urllib.error.HTTPError as e:
            msg = e.read().decode()[:200]
            if attempt == retries - 1:
                raise SystemExit(f"HTTP {e.code}: {msg}")
            time.sleep(2 * (attempt + 1))
        except Exception as e:
            if attempt == retries - 1:
                raise
            time.sleep(2 * (attempt + 1))


_VERDICT = re.compile(r"status:\s*(vuln|safe|unsure)", re.I)


def verdict_of(t):
    ms = list(_VERDICT.finditer(t or ""))
    return ms[-1].group(1).lower() if ms else None


def trim_to_verdict(t):
    if not t:
        return ""
    ms = list(_VERDICT.finditer(t))
    return t[:ms[-1].end()].strip() if ms else t.strip()


def one_side(code, cwe, key, fs, stance, gen_angle):
    user = build_user(code, cwe, stance, gen_angle)
    msgs = [{"role": "system", "content": SYSTEM}] + fs + [{"role": "user", "content": user}]
    txt, usage = call(msgs, key)
    # retry-on-truncation: an empty body or a trace that never reached a 'status:' line (ran past
    # the token budget mid-analysis) is unusable -- one retry nudging brevity + an explicit verdict.
    if not txt or verdict_of(txt) is None:
        nudge = dict(msgs[-1])
        nudge["content"] += ("\nKeep the analysis tight -- a few sentences of reasoning -- and be "
                             "sure to finish with the single 'status:' line.")
        txt2, usage2 = call(msgs[:-1] + [nudge], key)
        if txt2 and verdict_of(txt2) is not None:
            txt = txt2
            for k, v in (usage2 or {}).items():
                usage[k] = usage.get(k, 0) + v if isinstance(v, (int, float)) else v
    return trim_to_verdict(txt), usage


def verifier_check(code, kind, side_label):
    """Run the sound verifiers on this side. Returns (tag, detail).
      tag in {confirmed-safe, witness-bypass, inconclusive, no-kind}
    witness-bypass on a SAFE side means the 'safe' label is provably wrong."""
    if not kind:
        return "no-kind", None
    try:
        ws = witness_scan(code, kind)
    except Exception:
        ws = None
    if ws:
        return "witness-bypass", ws
    try:
        ps = prove_safe(code, kind)
    except Exception:
        ps = None
    if ps:
        return "confirmed-safe", ps
    return "inconclusive", None


def _gen_item(item, key, fs):
    """Thread worker: generate ONE side's trace and compute all gates. No shared mutable state,
    so it is safe to run many of these concurrently (the calls are I/O-bound on the API)."""
    code = item["code"]
    trace, usage = one_side(code, item["cwe"], key, fs, item["stance"], item["gen_angle"])
    return {**item, "trace": trace, "usage": usage or {},
            "v": verdict_of(trace), "g": grounded(trace, code),
            "d": cites_change(trace, item["cidents"]), "leak": grounding_leak(trace, code),
            "verif": verifier_check(code, item["kind"], item["label"])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2)
    ap.add_argument("--offset", type=int, default=0, help="skip the first OFFSET worklist CVEs (test NEW ones)")
    ap.add_argument("--workers", type=int, default=6, help="concurrent API calls")
    ap.add_argument("--show", action="store_true", help="print each trace")
    ap.add_argument("--dry", action="store_true", help="print the assembled prompts, NO API calls")
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    key = None if args.dry else load_key()
    fs = fewshot()
    done = set()
    if os.path.exists(GOLD):
        done = {json.loads(l)["_meta"].get("cve") for l in open(GOLD, encoding="utf-8")}
    rows = [json.loads(l) for l in open(WORKLIST, encoding="utf-8")]
    rows = [r for r in rows if r.get("cve") not in done][args.offset:]

    # ---- pass 1 (sequential, cheap-local): build the work items past the misalignment filter ----
    items, misaligned, tries, nosink = [], 0, 0, 0
    for r in rows:
        if tries >= args.n:
            break
        vcode, scode = views_both(r["patch"])            # WIDE view -> fed to the model
        if not vcode.strip() or not scode.strip():
            continue
        # pair-coherence gate on the NARROW top-hunk view: the wide view legitimately has many
        # changed lines (low overlap), so alignment must be judged on the core hunk, not the whole
        # context, or every rich patch gets wrongly skipped.
        nv, ns = views_both(r["patch"], max_chars=1600, max_hunks=2)
        al = alignment(nv, ns)
        if al < ALIGN_MIN:
            misaligned += 1
            print(f"  {r['cve']} MISALIGNED (overlap {al:.2f}) -> skip")
            continue
        # sink-plausibility: if a modelled CWE has no matching construct in the vuln (pre-fix) code,
        # the extraction missed the vuln locus -> a verdict would be vacuous. Skip before generating.
        if not has_plausible_sink(vcode, r["cwes"]):
            nosink += 1
            print(f"  {r['cve']} NO-SINK for {r['cwes']} -> skip (extraction missed the vuln locus)")
            continue
        cidents, _anchor = changed(r["patch"])
        tries += 1
        cwe, kind = r["cwes"][0], kind_of(r["cwes"])
        for label, code in (("vuln", vcode), ("safe", scode)):
            items.append({"r": r, "label": label, "code": code, "cwe": cwe, "kind": kind,
                          "cidents": cidents, "stance": _pick(STANCES, r["cve"], label),
                          "gen_angle": _pick(GEN_ANGLES, r["cve"], label, "g")})

    if args.dry:
        for it in items:
            print(f"\n=== {it['r']['cve']} {it['label']} {it['cwe']} {it['r']['primary_lang']} ===")
            print(build_user(it["code"], it["cwe"], it["stance"], it["gen_angle"]))
        return

    # ---- pass 2 (parallel): generate every side concurrently ----
    print(f"generating {len(items)} sides with {args.workers} workers...")
    results = {}
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(_gen_item, it, key, fs): it for it in items}
        for fu in as_completed(futs):
            it = futs[fu]
            try:
                res = fu.result()
            except Exception as e:
                print(f"  {it['r']['cve']} {it['label']} ERROR: {e}")
                continue
            results[(it["r"]["cve"], it["label"])] = res

    # ---- pass 3 (sequential): route in stable CVE order, pair up KEEP sides ----
    kept_pairs, suspects, unsures, leaks, singles = [], [], [], [], []
    kept, toks = 0, 0
    seen_cve = []
    for it in items:
        if it["r"]["cve"] not in seen_cve:
            seen_cve.append(it["r"]["cve"])
    for cve in seen_cve:
        rec = []
        side_bucket, side_v = {}, {}               # per-side bucket + model verdict, for singles
        for label in ("vuln", "safe"):
            res = results.get((cve, label))
            if not res:
                continue
            r, code = res["r"], res["code"]
            v, g, d, leak = res["v"], res["g"], res["d"], res["leak"]
            vtag, vdetail = res["verif"]
            toks += (res["usage"] or {}).get("total_tokens", 0)
            meta = {"label": label, "cwe": res["cwe"], "cwes": r["cwes"], "cve": cve,
                    "language": r["primary_lang"], "source": "regen_deepseek",
                    "pair_id": cve, "contrastive": True, "patch": r["patch"],
                    "n_files": r["n_files"], "multi_file": r["multi_file"],
                    "model_verdict": v, "verifier": vtag, "verifier_detail": vdetail,
                    "gates": {"grounded": g, "diff": d, "leak": leak}}
            row = {"messages": [{"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                                {"role": "assistant", "content": res["trace"]}], "_meta": meta}

            disagree = v is not None and v != "unsure" and v != label
            witness_kills_safe = (label == "safe" and vtag == "witness-bypass")
            if v == "unsure":
                bucket = "UNSURE"; unsures.append(row)
            elif disagree or witness_kills_safe:
                bucket = "SUSPECT"; suspects.append(row)
            elif leak:
                # right verdict but reached from memorised CVE knowledge, not the code -> reject.
                # The silent poison: it would otherwise pass agree+grounded straight to KEEP.
                bucket = "LEAK"; leaks.append(row)
            elif v == label and g and d:
                bucket = "KEEP"; rec.append(row)
            else:
                bucket = "DROP"                    # right verdict but ungrounded / no diff cite
            side_bucket[label] = bucket; side_v[label] = v
            print(f"  {cve} {label:4s} {res['cwe']:8s} {r['primary_lang']:10s} "
                  f"verdict={str(v):6s} grounded={g} diff={d} leak={str(leak):8s} "
                  f"verif={vtag:14s} -> {bucket}")
            if args.show:
                print("     " + res["trace"].replace("\n", "\n     "))
        if len(rec) == 2:                          # both sides clean -> contrastive PAIR
            kept_pairs.extend(rec); kept += 1
        elif len(rec) == 1:
            # one side passed the full KEEP gate but its partner was flagged (suspect/unsure/drop),
            # so there is no contrastive pair. Don't discard the good side -- save it as a
            # non-contrastive SINGLE. Teaches detection, not vuln-vs-safe discrimination, so it is a
            # supplement to pairs; the SAFE singles are the scarce, high-value ones. See north-star.
            row = rec[0]
            kept_label = row["_meta"]["label"]
            partner = "safe" if kept_label == "vuln" else "vuln"
            # STRENGTH: if the model gave the partner the SAME verdict as this side, it did NOT
            # discriminate (said e.g. 'safe' to both -> under-flag) -> WEAK. If the partner verdict
            # differs (typically 'unsure' = out of view), the model discriminated as far as it could
            # see -> STRONG. Weak singles are kept but flagged so training can down-weight/filter.
            same = side_v.get(partner) == row["_meta"]["model_verdict"]
            row["_meta"]["contrastive"] = False
            row["_meta"]["single"] = True
            row["_meta"]["partner_bucket"] = side_bucket.get(partner)
            row["_meta"]["partner_verdict"] = side_v.get(partner)
            row["_meta"]["single_strength"] = "weak" if same else "strong"
            singles.append(row)

    def dump(path, rows):
        if not rows:
            return
        mode = "a" if os.path.exists(path) else "w"
        with open(path, mode, encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    if not args.dry:
        dump(OUT, kept_pairs); dump(SUSPECT, suspects); dump(UNSURE, unsures)
        dump(LEAK, leaks); dump(SINGLES, singles)
        n_safe_single = sum(1 for r in singles if r["_meta"]["label"] == "safe")
        n_strong = sum(1 for r in singles if r["_meta"].get("single_strength") == "strong")
        print(f"\nMISALIGNED {misaligned} | NO-SINK {nosink} | TRIED {tries} -> KEPT {kept} pairs "
              f"({len(kept_pairs)} rec) | SINGLES {len(singles)} ({n_safe_single} safe, "
              f"{n_strong} strong) | SUSPECT {len(suspects)} | UNSURE {len(unsures)} "
              f"| LEAK {len(leaks)} | ~{toks} tok")
        print(f"  KEEP    -> {OUT}")
        print(f"  SINGLES -> {SINGLES}   (clean side, partner flagged: detection only, non-contrastive)")
        print(f"  SUSPECT -> {SUSPECT}   (label-audit: model or witness disagrees with the bridge)")
        print(f"  UNSURE  -> {UNSURE}")
        print(f"  LEAK    -> {LEAK}   (rejected: reasoned from CVE/advisory memory, not the code)")


if __name__ == "__main__":
    main()
