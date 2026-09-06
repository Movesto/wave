"""Harvest CONTRASTIVE cross-file pairs with CodeQL — the safe cross-file traces
the corpus has none of.

codeql_harvest.py only ever analyzed `{commit}^` (the vulnerable state) and
hardcoded label=vuln, so all 7,048 cross-file records are vuln. The model learned
"cross-file-shaped => vuln", and the cross-file eval (150/150 vuln) cannot detect
that: an always-say-vuln stub scores the same 100% recall v11 did.

This harvester analyzes BOTH states of each fix commit:

    {commit}^  -> flows_vuln     (the CVE is present)
    {commit}   -> flows_fixed    (the CVE is patched)

A flow present in the first and absent in the second is one the fix KILLED. That
gives a genuine contrastive cross-file pair: the same files and the same taint
path, differing only in the guard the patch added. The safe side quotes that
guard, so "safe" is grounded in a control rather than in the absence of one.

Flows are matched across states by (cwe, source file, sink file) — line numbers
shift under a patch, file roles don't.

  python codeql_harvest_pairs.py --lang python --limit 60
  python codeql_harvest_pairs.py --lang javascript --limit 40 --max-per-repo 2
"""
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from build_contrastive import _CALL, _GUARD, _SINK_STOP, _pick_guard, _leak_hashes
from cot.deep_trace import deep_safe_think, deep_vuln_think
from codeql_harvest import CODEQL, PYEXT, REPOS, SUITE, WORK, extract, read_lines, run

OUT = Path("data/cot/pilot/shape3_codeql_pairs.jsonl")
DONE_LOG = WORK / "harvested_pairs.txt"

# Where candidates die. The funnel is the whole story for tuning this harvester:
# a flow only becomes a pair if CodeQL saw it in the vuln state, the patch removed
# it, and the patch added a quotable guard.
REASONS: Counter = Counter()

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")
_IDENT = re.compile(r"\b([a-z_][a-z0-9_]{2,})\b", re.I)
_KEYWORDS = {"self", "this", "return", "import", "from", "class", "def", "function",
             "const", "let", "var", "true", "false", "none", "null", "value", "data"}


def flow_key(cwe: str, steps: list) -> tuple:
    """Identity of a taint flow that survives a patch. Line numbers move when the
    fix inserts a guard, so key on the CWE and the endpoints' FILES instead."""
    return (cwe, steps[0][0], steps[-1][0])


def sink_symbol(line_text: str) -> str | None:
    """The salient call on the sink line — what the guard is protecting."""
    best = None
    for m in _CALL.finditer(line_text or ""):
        tok = m.group(1)
        base = tok.split(".")[-1]
        if base.lower() in _SINK_STOP or len(base) < 3:
            continue
        if best is None or len(tok) > len(best):
            best = tok
    return best


def source_symbol(line_text: str, step_msg: str) -> str | None:
    """The tainted value's name. CodeQL's step message often names it; fall back
    to the first non-keyword identifier on the source line."""
    for text in (step_msg or "", line_text or ""):
        for m in _IDENT.finditer(text):
            tok = m.group(1)
            if tok.lower() not in _KEYWORDS and tok.lower() not in _SINK_STOP:
                return tok
    return None


def line_at(repo: Path, uri: str, line: int) -> str:
    try:
        lines = (repo / uri).read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[line - 1] if 1 <= line <= len(lines) else ""
    except Exception:
        return ""


def added_lines(repo: Path, commit: str, uri: str) -> tuple[list[str], int | None]:
    """Lines the fix commit ADDED to this file, plus the first new-side hunk line
    (used to anchor the fixed-state code block, since the patch shifts numbering)."""
    r = run(["git", "-C", str(repo), "diff", "--unified=0", f"{commit}^", commit, "--", uri])
    added, anchor = [], None
    for line in (r.stdout or "").splitlines():
        m = _HUNK.match(line)
        if m:
            if anchor is None:
                anchor = int(m.group(1))
            continue
        if line.startswith("+") and not line.startswith("+++"):
            body = line[1:]
            if body.strip():
                added.append(body)
    return added, anchor


def code_blocks(repo: Path, steps: list, anchor_file: str | None, anchor_line: int | None) -> str:
    """Same multi-file presentation the vuln harvester uses, so both sides of the
    pair are structurally identical and only the guard differs."""
    files = []
    for f, _, _ in steps:
        if f not in files:
            files.append(f)
    blocks = []
    for f in files[:4]:
        ln = next(s[1] for s in steps if s[0] == f)
        if anchor_file and f == anchor_file and anchor_line:
            ln = anchor_line
        blocks.append(f"# {f} (line {ln})\n{read_lines(repo, f, ln)}")
    return "\n\n".join(blocks)


def make_pair(repo: Path, commit: str, lang: str, cwe: str, steps: list,
              vuln_code: str, pair_id: str) -> tuple[dict, dict] | None:
    """Build the vuln/safe record pair for one killed flow. Returns None when the
    fix has no quotable guard — an unexplained 'safe' is exactly the reasoning
    theater this corpus is trying to get rid of."""
    src_file, src_line, src_msg = steps[0]
    sink_file, sink_line, _ = steps[-1]

    added, anchor = added_lines(repo, commit, sink_file)
    if not added:
        REASONS["sink_file_untouched_by_commit"] += 1
        return None
    guard = _pick_guard(added)
    if not guard or not _GUARD.search(guard):
        REASONS["no_quotable_guard"] += 1
        return None

    sink = sink_symbol(line_at(repo, sink_file, anchor or sink_line)) or os.path.basename(sink_file)
    source = source_symbol(line_at(repo, src_file, src_line), src_msg) or "the request value"

    safe_code = code_blocks(repo, steps, sink_file, anchor)
    if not safe_code.strip():
        return None

    flow = " -> ".join(f"{os.path.basename(f)}:{ln}" for f, ln, _ in steps[:8])
    vuln_fields = (f"status: confirmed\ncwe: {cwe}\nseverity: HIGH\nline: {sink_line}\n"
                   f"trace: {flow}\nfix: Neutralize `{source}` before it reaches "
                   f"`{sink}` in {os.path.basename(sink_file)}.")
    safe_fields = ("status: safe\ncwe: none\nseverity: none\nline: none\n"
                   f"trace: the {os.path.basename(src_file)} -> {os.path.basename(sink_file)} "
                   f"flow is guarded by `{guard}`\nfix: none")

    def rec(code, think, fields, label):
        return {"messages": [{"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                             {"role": "assistant", "content": think + "\n" + fields}],
                "_meta": {"shape": "shape3", "source": "codeql_pair", "language": lang,
                          "label": label, "cwes": [cwe] if label == "vuln" else [],
                          "ground_truth_cwe": cwe, "multi_hop": True,
                          "pair_id": pair_id, "cross_file": True}}

    return (rec(vuln_code, deep_vuln_think(source, sink, sink_line, cwe), vuln_fields, "vuln"),
            rec(safe_code, deep_safe_think(source, sink, guard, cwe), safe_fields, "safe"))


def analyze(repo: Path, safe_name: str, lang: str, state: str, commit: str):
    """Check out one state of the repo and return its cross-file findings."""
    run(["git", "-C", str(repo), "reset", "--hard", "--quiet"])
    run(["git", "-C", str(repo), "checkout", "--quiet", state, "--"] + PYEXT[lang])
    db = WORK / f"dbp_{safe_name}"
    shutil.rmtree(db, ignore_errors=True)
    b = run([CODEQL, "database", "create", str(db), f"--language={lang}",
             f"--source-root={repo}", "--overwrite"])
    if not (db / f"db-{lang}").exists() and b.returncode != 0:
        shutil.rmtree(db, ignore_errors=True)
        return None
    sarif = WORK / f"{safe_name}_{'v' if state.endswith('^') else 'f'}.sarif"
    run([CODEQL, "database", "analyze", str(db), SUITE[lang],
         "--format=sarif-latest", f"--output={sarif}", "--threads=4"])
    shutil.rmtree(db, ignore_errors=True)
    if not sarif.exists():
        return None
    findings = list(extract(sarif))
    sarif.unlink()
    return findings


def process(owner_repo: str, lang: str, commit: str, out_f, seen: set, leak: set) -> tuple[int, int]:
    safe_name = owner_repo.replace("/", "__")
    repo = REPOS / safe_name
    if not repo.exists():
        run(["git", "clone", "--quiet", f"https://github.com/{owner_repo}.git", str(repo)])
        if not repo.exists():
            return 0, 0

    # Vulnerable state first, capturing code while it is checked out.
    vuln_findings = analyze(repo, safe_name, lang, f"{commit}^", commit)
    if not vuln_findings:
        REASONS["no_crossfile_flow_in_vuln_state"] += 1
        return 0, 0
    vuln_by_key = {}
    for cwe, steps, _ in vuln_findings:
        vuln_by_key.setdefault(flow_key(cwe, steps), (cwe, steps, code_blocks(repo, steps, None, None)))

    # Fixed state: whatever is gone here, the patch removed.
    fixed_findings = analyze(repo, safe_name, lang, commit, commit)
    if fixed_findings is None:
        return 0, 0
    fixed_keys = {flow_key(cwe, steps) for cwe, steps, _ in fixed_findings}
    killed = [k for k in vuln_by_key if k not in fixed_keys]
    REASONS["flow_survived_the_fix"] += len(vuln_by_key) - len(killed)
    if not killed:
        return 0, len(vuln_by_key)
    REASONS["flow_killed_by_fix"] += len(killed)

    # The repo is currently at the fixed state — required for the safe-side blocks.
    made = 0
    for key in killed:
        cwe, steps, vuln_code = vuln_by_key[key]
        pair_id = hashlib.sha1(f"{owner_repo}{commit}{key}".encode()).hexdigest()[:16]
        pair = make_pair(repo, commit, lang, cwe, steps, vuln_code, pair_id)
        if not pair:
            continue
        hashes = [hashlib.sha256(r["messages"][0]["content"].encode()).hexdigest() for r in pair]
        if any(h in seen or h in leak for h in hashes):
            REASONS["duplicate_or_eval_leak"] += 1
            continue
        seen.update(hashes)
        REASONS["PAIR_KEPT"] += 1
        for r in pair:
            out_f.write(json.dumps(r, ensure_ascii=False) + "\n")
        out_f.flush()
        made += 1
    return made, len(vuln_by_key)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", default="codeql_targets.tsv")
    ap.add_argument("--lang", default="python")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--skip", type=int, default=0)
    ap.add_argument("--max-per-repo", type=int, default=2)
    args = ap.parse_args()

    REPOS.mkdir(parents=True, exist_ok=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)

    rows = [l.rstrip("\n").split("\t") for l in open(args.targets, encoding="utf-8")]
    rows = [r for r in rows if len(r) >= 4 and r[1] == args.lang][args.skip:]

    already = set()
    if DONE_LOG.exists():
        already = {l.strip() for l in open(DONE_LOG, encoding="utf-8") if l.strip()}
    dlog = io.open(DONE_LOG, "a", encoding="utf-8")

    leak = _leak_hashes()
    print(f"eval-leak guard: {len(leak)} hashes")

    seen: set = set()
    if OUT.exists():
        with open(OUT, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                seen.add(hashlib.sha256(rec["messages"][0]["content"].encode()).hexdigest())
        print(f"resuming: {len(seen)} records already harvested")

    per_repo: Counter = Counter()
    done = pairs = flows = 0
    with io.open(OUT, "a", encoding="utf-8") as out_f:
        for owner_repo, lang, commit, _fn in rows:
            key = f"{owner_repo}\t{commit}"
            if key in already or per_repo[owner_repo] >= args.max_per_repo:
                continue
            per_repo[owner_repo] += 1
            dlog.write(key + "\n"); dlog.flush(); already.add(key)
            try:
                got, seen_flows = process(owner_repo, lang, commit, out_f, seen, leak)
            except Exception as e:
                print(f"  ERR {owner_repo}@{commit[:8]}: {e}", flush=True)
                got, seen_flows = 0, 0
            pairs += got; flows += seen_flows; done += 1
            print(f"[{done}/{args.limit}] {owner_repo}@{commit[:8]} -> +{got} pairs "
                  f"({seen_flows} cross-file flows in vuln state; total {pairs})", flush=True)
            if done >= args.limit:
                break

    print(f"\nDONE: {pairs} contrastive cross-file pairs ({pairs*2} records) "
          f"from {done} targets -> {OUT}")
    print("\nfunnel (where candidates died):")
    for reason, count in REASONS.most_common():
        print(f"  {reason:34} {count}")


if __name__ == "__main__":
    main()
