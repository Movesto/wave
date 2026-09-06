"""Rebuild shape4's synthesis inputs from real findings.

shape4 asks the model to triage a findings list into a ranked report. The TASK is
legitimate and it is the one shape that matches what the scanner interface actually
emits. The INPUT was not: 273 of 321 records list files named `unknown_1088.py`, and 78
present findings whose CWE is literally `CWE-?` or `CWE-UNK` -- asking the model to
reason about a finding that says nothing.

The old assistant text had a second problem. Its think block is a fixed ranking rubric,
so a record with four findings still explains how it ordered "stored XSS (needs victim
view)" and "predictable tokens (needs reset flow)" -- neither of which is in the list.
Reasoning that describes absent findings is reasoning the model learns to produce
without looking.

Both are fixed from data we already have: 7,358 attested vulnerable records carry a real
repo, a real repo-relative path and a CISA/OSV-sourced CWE, across 379 repos with at
least three distinct files. A synthesis record is one repo's real findings, and the
reasoning is computed FROM those findings -- counts, tallies and ordering that a reader
can check against the list above it.

    python rebuild_shape4_inputs.py --write
"""
import argparse
import collections
import hashlib
import json
import os
import random
import re
import sys

from scan_ts_standard import trace_of

SRC = ("shape1_contrastive_attested", "shape1_contrastive_ts_osv",
       "shape1_contrastive_js_osv", "shape1_contrastive_r2vul",
       "shape1_contrastive_react_osv", "shape1_wave3_attested",
       "shape_completeness_osv", "shape1_r2vul_clean")
OUT = "data/cot/pilot/shape4.jsonl"
TARGET = 321

# CWE -> (short name, severity). Only CWEs we actually emit; anything absent is skipped
# rather than guessed, because a finding the model cannot name is the defect being fixed.
CWE_INFO = {
    "CWE-20": ("Improper input validation", "MEDIUM"),
    "CWE-22": ("Path traversal", "HIGH"),
    "CWE-23": ("Relative path traversal", "HIGH"),
    "CWE-59": ("Link following", "MEDIUM"),
    "CWE-74": ("Injection", "HIGH"),
    "CWE-77": ("Command injection", "HIGH"),
    "CWE-78": ("OS command injection", "HIGH"),
    "CWE-79": ("Cross-site scripting", "HIGH"),
    "CWE-88": ("Argument injection", "HIGH"),
    "CWE-89": ("SQL injection", "HIGH"),
    "CWE-94": ("Code injection", "HIGH"),
    "CWE-116": ("Improper encoding or escaping", "MEDIUM"),
    "CWE-119": ("Buffer bounds error", "HIGH"),
    "CWE-120": ("Buffer overflow", "HIGH"),
    "CWE-125": ("Out-of-bounds read", "HIGH"),
    "CWE-190": ("Integer overflow", "MEDIUM"),
    "CWE-200": ("Information exposure", "MEDIUM"),
    "CWE-269": ("Improper privilege management", "HIGH"),
    "CWE-284": ("Improper access control", "HIGH"),
    "CWE-287": ("Improper authentication", "HIGH"),
    "CWE-295": ("Improper certificate validation", "MEDIUM"),
    "CWE-306": ("Missing authentication", "HIGH"),
    "CWE-352": ("Cross-site request forgery", "MEDIUM"),
    "CWE-362": ("Race condition", "MEDIUM"),
    "CWE-400": ("Uncontrolled resource consumption", "MEDIUM"),
    "CWE-416": ("Use after free", "HIGH"),
    "CWE-434": ("Unrestricted file upload", "HIGH"),
    "CWE-476": ("Null pointer dereference", "LOW"),
    "CWE-502": ("Insecure deserialization", "HIGH"),
    "CWE-601": ("Open redirect", "MEDIUM"),
    "CWE-611": ("XML external entity", "HIGH"),
    "CWE-639": ("Insecure direct object reference", "HIGH"),
    "CWE-732": ("Incorrect permission assignment", "MEDIUM"),
    "CWE-770": ("Allocation without limits", "MEDIUM"),
    "CWE-787": ("Out-of-bounds write", "HIGH"),
    "CWE-798": ("Hardcoded credentials", "HIGH"),
    "CWE-863": ("Incorrect authorization", "HIGH"),
    "CWE-918": ("Server-side request forgery", "HIGH"),
    "CWE-1321": ("Prototype pollution", "HIGH"),
}
RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def collect():
    """Real vulnerable findings grouped by repo."""
    byrepo = collections.defaultdict(list)
    for s in SRC:
        path = f"data/cot/staging/{s}.jsonl"
        if not os.path.exists(path):
            continue
        for line in open(path, encoding="utf-8"):
            r = json.loads(line)
            m = r["_meta"]
            if m.get("label") != "vuln" or m.get("held"):
                continue
            f = m.get("src_file") or m.get("file")
            cwe = m.get("ground_truth_cwe")
            if not (f and cwe and m.get("repo") and cwe in CWE_INFO):
                continue
            tm = re.search(r"^trace:\s*(\S+)\s*->\s*(\S+)", trace_of(r), re.M)
            byrepo[m["repo"]].append(dict(
                file=f, cwe=cwe, lang=m.get("language", ""), cve=m.get("cve", ""),
                src=tm.group(1).strip("`") if tm else None,
                snk=tm.group(2).strip("`") if tm else None))
    return byrepo


def build_record(repo, findings, rng):
    n = len(findings)
    for i, f in enumerate(findings, 1):
        name, sev = CWE_INFO[f["cwe"]]
        # The path is already its own column; repeating it in the title made every
        # line a duplicate of itself for deep source trees.
        base = f["file"].rsplit("/", 1)[-1]
        f["title"] = (f"{name} — `{f['src']}` reaches `{f['snk']}` in {base}"
                      if f["src"] and f["snk"] else f"{name} in {base}")
        f["sev"] = sev
        f["n"] = i

    files = sorted({f["file"] for f in findings})
    lines = [f"  [{f['n']}] {f['title']}  (CWE={f['cwe']}, sev={f['sev']}, "
             f"file={f['file']}, lang={f['lang']})" for f in findings]
    user = ("<SYNTHESIZE>\nPROJECT MAP\n"
            + "\n".join(f"  {p}" for p in files)
            + f"\n\nFINDINGS ({n}):\n" + "\n".join(lines) + "\n</SYNTHESIZE>")

    tally = collections.Counter(f["sev"] for f in findings)
    ordered = sorted(findings, key=lambda f: (RANK[f["sev"]], f["n"]))
    bycwe = collections.Counter(f["cwe"] for f in findings)
    byfile = collections.Counter(f["file"] for f in findings)
    repeated_cwe = [c for c, k in bycwe.items() if k > 1]
    repeated_file = [p for p, k in byfile.items() if k > 1]

    # Reasoning computed FROM the list above, so every sentence is checkable against it.
    think = [f"{n} findings across {len(files)} files in {repo}.",
             "Severity tally: " + ", ".join(f"{tally[s]} {s}" for s in
                                            ("HIGH", "MEDIUM", "LOW") if tally[s]) + "."]
    if repeated_cwe:
        think.append("Same weakness class in more than one place: "
                     + ", ".join(f"{c} x{bycwe[c]}" for c in sorted(repeated_cwe))
                     + " — these are one systemic gap, not independent bugs.")
    else:
        think.append("Every finding is a distinct weakness class, so none of them "
                     "collapse into a shared root cause.")
    if repeated_file:
        think.append("Files carrying more than one finding: "
                     + ", ".join(sorted(repeated_file)) + ".")
    top = ordered[0]
    think.append(f"Ranking by severity first: {top['cwe']} in {top['file']} leads "
                 f"because it is {top['sev']} and needs no prerequisite beyond reaching "
                 f"the entry point.")
    think.append("Within a tier I keep the order the findings arrived in — nothing in "
                 "this list distinguishes them further without seeing the code.")

    body = ["executive_summary: " + ", ".join(
                f"{tally[s]} {s}" for s in ("HIGH", "MEDIUM", "LOW") if tally[s])
            + f" findings across {len(files)} files in {repo}.",
            "", "ranked_findings:"]
    for rank, f in enumerate(ordered, 1):
        body += [f"  - rank: {rank}", f"    title: {f['title']}",
                 f"    severity: {f['sev']}", f"    file: {f['file']}",
                 f"    cwe: {f['cwe']}"]
    body += ["", "systemic_observations:"]
    if repeated_cwe:
        for c in sorted(repeated_cwe):
            body.append(f"  - {CWE_INFO[c][0]} appears {bycwe[c]} times; fix the shared "
                        f"handling rather than each call site.")
    else:
        body.append("  - No weakness class repeats, so there is no single control to "
                    "add that would close more than one finding.")
    body.append("")
    body.append("dedup_notes: " + ("none" if not repeated_cwe else
                f"{len(repeated_cwe)} class(es) seen in multiple files"))

    meta = dict(shape="shape4", label="synthesis", num_findings=n, language="mixed",
                source="shape4_real_findings", repo=repo,
                cwes=[f["cwe"] for f in findings],
                cves=sorted({f["cve"] for f in findings if f["cve"]}),
                # NOT `pair_id`: a synthesis record has no counterpart, and calling this
                # a pair id made every shape4 record read as half of a broken pair to
                # the integrity check.
                record_id=hashlib.sha1(f"shape4|{repo}|{n}|{files[0]}".encode()
                                       ).hexdigest()[:12])
    return {"messages": [
        {"role": "user", "content": user},
        {"role": "assistant",
         "content": "<think>\n" + "\n".join(think) + "\n</think>\n\n"
                    + "\n".join(body)}], "_meta": meta}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    rng = random.Random(11)

    byrepo = collect()
    usable = {k: v for k, v in byrepo.items() if len({x["file"] for x in v}) >= 3}
    print(f"real findings: {sum(len(v) for v in byrepo.values())} "
          f"across {len(byrepo)} repos; {len(usable)} repos usable")

    out, seen = [], set()
    repos = sorted(usable)
    rng.shuffle(repos)
    for repo in repos:
        if len(out) >= TARGET:
            break
        pool, byfile = usable[repo], {}
        for f in pool:                       # one finding per file, keeps the map honest
            byfile.setdefault(f["file"], f)
        picks = list(byfile.values())
        rng.shuffle(picks)
        k = min(len(picks), rng.randint(3, 8))
        chosen = picks[:k]
        key = (repo, tuple(sorted(f["file"] for f in chosen)))
        if key in seen:
            continue
        seen.add(key)
        out.append(build_record(repo, chosen, rng))

    print(f"built {len(out)} synthesis records")
    sizes = collections.Counter(r["_meta"]["num_findings"] for r in out)
    print("findings per record:", dict(sorted(sizes.items())))
    if args.write:
        with open(OUT, "w", encoding="utf-8") as fh:
            for r in out:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"-> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
