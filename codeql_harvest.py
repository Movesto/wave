"""Harvest CROSS-FILE taint traces with CodeQL. For each target (repo, fix-commit):
clone (cached) -> checkout vuln state (parent) -> build DB -> run security taint
queries -> keep findings whose code-flow spans >=2 files -> assemble shape3 traces.

Robust: skips any target that fails (invalid paths, build error, no cross-file path).
Deletes each DB after analysis to save disk. Runs alongside GPU training (CPU/disk).
"""
import os, re, io, json, subprocess, shutil, argparse, hashlib
from pathlib import Path
from collections import Counter

CODEQL = str(Path("tools/codeql/codeql.exe").resolve())  # abs path for Windows subprocess
WORK = Path("tools/codeql_work")
REPOS = WORK / "repos"
OUT = Path("data/cot/pilot/shape3_codeql.jsonl")
SUITE = {"python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
         "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls"}
PYEXT = {"python": ["*.py"], "javascript": ["*.js", "*.ts", "*.jsx", "*.tsx", "*.vue"]}
_CWE = re.compile(r"cwe-(\d+)", re.I)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def cwe_from_rule(rule):
    for t in (rule.get("properties", {}) or {}).get("tags", []):
        m = _CWE.search(t)
        if m:
            return f"CWE-{int(m.group(1))}"
    return None


def extract(sarif_path):
    """Yield (cwe, steps, message) for cross-file findings. Each step =
    (uri, line, step_message) — CodeQL's own per-hop taint explanation."""
    d = json.load(open(sarif_path, encoding="utf-8"))
    for run_ in d.get("runs", []):
        rules = {r["id"]: r for r in run_.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run_.get("results", []):
            for cf in res.get("codeFlows", []):
                for tf in cf.get("threadFlows", []):
                    locs = tf.get("locations", [])
                    steps = []
                    for L in locs:
                        loc = L.get("location", {})
                        pl = loc.get("physicalLocation", {})
                        uri = pl.get("artifactLocation", {}).get("uri")
                        line = pl.get("region", {}).get("startLine")
                        smsg = (loc.get("message", {}) or L.get("message", {})).get("text", "")
                        if uri:
                            steps.append((uri, line, smsg.strip()))
                    files = {s[0] for s in steps}
                    if len(files) >= 2 and len(steps) >= 2:
                        rule = rules.get(res.get("ruleId"), {})
                        cwe = cwe_from_rule(rule) or "CWE-20"
                        msg = res.get("message", {}).get("text", "")
                        yield cwe, steps, msg


def read_lines(repo, uri, line, ctx=4):
    try:
        path = repo / uri
        L = path.read_text(encoding="utf-8", errors="replace").splitlines()
        a = max(0, (line or 1) - 1 - ctx); b = min(len(L), (line or 1) + ctx)
        return "\n".join(L[a:b])
    except Exception:
        return ""


def make_trace(repo, cwe, steps):
    srcf, srcl, _ = steps[0]
    sinkf, sinkl, _ = steps[-1]
    files = []
    for f, _, _ in steps:
        if f not in files:
            files.append(f)
    blocks = []
    for f in files[:4]:
        ln = next(s[1] for s in steps if s[0] == f)
        blocks.append(f"# {f} (line {ln})\n{read_lines(repo, f, ln)}")
    code = "\n\n".join(blocks)
    flow = " -> ".join(f"{os.path.basename(f)}:{ln}" for f, ln, _ in steps[:8])
    # Reasoning woven from CodeQL's OWN per-step taint messages (the WHY of each hop).
    rlines = []
    for i, (f, ln, m) in enumerate(steps[:8]):
        role = "Source" if i == 0 else ("Sink" if i == len(steps) - 1 else "Step")
        desc = m or ("untrusted input enters here" if i == 0 else
                     "the tainted value reaches a dangerous operation" if i == len(steps) - 1
                     else "the value propagates unchanged")
        rlines.append(f"{i+1}. [{role} — {os.path.basename(f)}:{ln}] {desc}")
    think = ("<think>\n" + "\n".join(rlines) +
             f"\nThe tainted value flows across {len(files)} files — from `{srcf}` to the sink in "
             f"`{sinkf}` — with no sanitizing step in between, so this cross-file data flow is "
             f"exploitable ({cwe}).\n</think>")
    fields = (f"status: confirmed\ncwe: {cwe}\nseverity: HIGH\nline: {sinkl}\n"
              f"trace: {flow}\nfix: Validate/neutralize the tainted value before it reaches the sink in {os.path.basename(sinkf)}.")
    return {"messages": [{"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                         {"role": "assistant", "content": think + "\n" + fields}],
            "_meta": {"shape": "shape3", "source": "codeql", "language": None,
                      "label": "vuln", "cwes": [cwe], "ground_truth_cwe": cwe, "multi_hop": True}}


def process(owner_repo, lang, commit, out_f, seen):
    safe = owner_repo.replace("/", "__")
    repo = REPOS / safe
    if not repo.exists():
        r = run(["git", "clone", "--quiet", f"https://github.com/{owner_repo}.git", str(repo)])
        if not repo.exists():
            return 0
    # checkout vuln state (parent of fix), source files only
    run(["git", "-C", str(repo), "reset", "--hard", "--quiet"])
    run(["git", "-C", str(repo), "checkout", "--quiet", f"{commit}^", "--"] + PYEXT[lang])
    db = WORK / f"db_{safe}"
    if db.exists():
        shutil.rmtree(db, ignore_errors=True)
    b = run([CODEQL, "database", "create", str(db), f"--language={lang}",
             f"--source-root={repo}", "--overwrite"])
    if not (db / f"db-{lang}").exists() and b.returncode != 0:
        shutil.rmtree(db, ignore_errors=True); return 0
    sarif = WORK / f"{safe}.sarif"
    run([CODEQL, "database", "analyze", str(db), SUITE[lang],
         "--format=sarif-latest", f"--output={sarif}", "--threads=4"])
    n = 0
    if sarif.exists():
        for cwe, steps, msg in extract(sarif):
            rec = make_trace(repo, cwe, steps)
            rec["_meta"]["language"] = lang
            h = hashlib.sha256(rec["messages"][0]["content"].encode()).hexdigest()
            if h in seen:
                continue
            seen.add(h)
            out_f.write(json.dumps(rec, ensure_ascii=False) + "\n"); out_f.flush(); n += 1
        sarif.unlink()
    shutil.rmtree(db, ignore_errors=True)
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", default="codeql_targets.tsv")
    ap.add_argument("--lang", default="python", help="python or javascript")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--skip", type=int, default=0, help="skip first N targets (continue a prior run)")
    ap.add_argument("--max-per-repo", type=int, default=3)
    args = ap.parse_args()
    REPOS.mkdir(parents=True, exist_ok=True)

    rows = [l.rstrip("\n").split("\t") for l in open(args.targets, encoding="utf-8")]
    rows = [r for r in rows if len(r) >= 4 and r[1] == args.lang][args.skip:]

    # persistent done-log so re-runs never re-analyze a (repo, commit)
    done_log = WORK / "harvested.txt"
    already = set()
    if done_log.exists():
        already = {l.strip() for l in open(done_log, encoding="utf-8") if l.strip()}
    dlog = io.open(done_log, "a", encoding="utf-8")

    seen, per_repo = set(), Counter()
    done = made = 0
    with io.open(OUT, "a", encoding="utf-8") as out_f:
        for owner_repo, lang, commit, fn in rows:
            key = f"{owner_repo}\t{commit}"
            if key in already:
                continue
            if per_repo[owner_repo] >= args.max_per_repo:
                continue
            per_repo[owner_repo] += 1
            dlog.write(key + "\n"); dlog.flush(); already.add(key)
            try:
                got = process(owner_repo, lang, commit, out_f, seen)
            except Exception as e:
                print(f"  ERR {owner_repo}@{commit[:8]}: {e}", flush=True)
                got = 0
            made += got; done += 1
            print(f"[{done}/{args.limit}] {owner_repo}@{commit[:8]} -> +{got} cross-file (total {made})", flush=True)
            if done >= args.limit:
                break
    print(f"\nDONE: {made} cross-file traces from {done} targets -> {OUT}")


if __name__ == "__main__":
    main()
