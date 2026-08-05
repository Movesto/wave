"""Cross-file pairs where the fix REMOVED the dangerous construct.

`shape3_codeql` is 8,938 records and 100% vulnerable, so it teaches "cross-file
shape => vuln" -- an unfalsifiable lesson, and the reason an always-say-vuln stub
scored 100% cross-file recall. `shape3_crossfile_pairs` is the only counterweight
and holds 36 pairs.

Scaling that builder stalls at `no_quotable_guard`: 745 of 1,022 candidates (73%)
in a 600-commit run. Those are not failures, they are the RESTRUCTURE class --
fixes that delete the dangerous call instead of guarding it (`eval` -> a parser,
`os.system` -> `subprocess` with a list, `pickle.loads` -> `json.loads`). The
shape for them already exists and passes the standard; it had simply never been
applied cross-file.

Everything about the presentation is reused from build_crossfile_pairs so the two
sets are directly comparable: caller file + fixed file, before and after, so the
tainted value enters in one file and reaches the sink in another. Both sides carry
identical cross-file structure, which is what stops the model keying on the shape.

    python build_crossfile_restructure.py --lang python --limit 600
"""
import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from build_contrastive import _leak_hashes
from build_crossfile_pairs import (EXTS, REPOS, _MINIFIED_PATH, changed_files,
                                   enclosing_symbol, excerpt, find_caller,
                                   patch_facts, show)
from build_r2vul_pairs import pick_sink, pick_source, standalone
from build_r2vul_restructure import pick_removal
from build_r2vul_restructure import record as restructure_record
from codeql_harvest_pairs import source_symbol
from filter_corpus import is_test_code

OUT = Path("data/cot/pilot/shape3_crossfile_restructure.jsonl")
MAX_RECORD = 5000
REASONS: Counter = Counter()


def build_pair(repo, owner_repo, commit, lang, path, exts):
    if _MINIFIED_PATH.search(path):
        REASONS["minified_or_bundled_file"] += 1
        return None
    hunks = patch_facts(repo, commit, path)
    if not hunks:
        REASONS["no_added_lines"] += 1
        return None

    vuln_lines = show(repo, f"{commit}^", path)
    fixed_lines = show(repo, commit, path)
    if not vuln_lines or not fixed_lines:
        REASONS["unreadable_blob"] += 1
        return None
    vfull, ffull = "\n".join(vuln_lines), "\n".join(fixed_lines)

    # What the fix took OUT, and it must really be gone -- pick_removal verifies
    # absence rather than trusting the diff, because a token that merely moved is
    # not a construct that was removed.
    construct, _ = pick_removal(vfull, ffull)
    if not construct:
        REASONS["no_removed_construct"] += 1
        return None

    anchor = symbol = None
    for h in hunks:
        if any(construct in l for l in h.get("added", [])) or anchor is None:
            anchor, symbol = h["line"], h["symbol"]
            if any(construct in l for l in h.get("added", [])):
                break
    symbol = symbol or enclosing_symbol(fixed_lines, anchor)
    if not symbol:
        REASONS["no_enclosing_symbol"] += 1
        return None

    caller = find_caller(repo, commit, symbol, path, exts)
    if not caller:
        REASONS["no_cross_file_caller"] += 1
        return None
    caller_path, caller_line = caller
    caller_lines = show(repo, commit, caller_path)
    if not caller_lines:
        REASONS["unreadable_blob"] += 1
        return None

    caller_block = f"# {caller_path} (line {caller_line})\n{excerpt(caller_lines, caller_line)}"
    vuln_block = f"# {path} (line {anchor})\n{excerpt(vuln_lines, anchor)}"
    fixed_block = f"# {path} (line {anchor})\n{excerpt(fixed_lines, anchor)}"
    vuln_code = f"{caller_block}\n\n{vuln_block}"
    safe_code = f"{caller_block}\n\n{fixed_block}"

    if max(len(vuln_code), len(safe_code)) > MAX_RECORD:
        REASONS["record_too_long"] += 1
        return None
    if is_test_code(vuln_code) or is_test_code(safe_code):
        REASONS["test_code"] += 1
        return None
    # The claim is that the construct is GONE. If the excerpt does not show it in
    # the vulnerable side, or still shows it in the safe side, the claim is not
    # readable from what the model is given and the pair would assert on faith.
    if not standalone(construct, vuln_code):
        REASONS["construct_outside_excerpt"] += 1
        return None
    if standalone(construct, safe_code):
        REASONS["construct_still_present"] += 1
        return None

    caller_text = caller_lines[caller_line - 1] if caller_line <= len(caller_lines) else ""
    args = re.search(re.escape(symbol) + r"\s*\(([^)]*)\)", caller_text)
    src = source_symbol(args.group(1) if args else "", "") or pick_source(
        construct, vuln_code, safe_code)
    if not src or src == construct or src == symbol:
        REASONS["degenerate_source"] += 1
        return None
    if not (standalone(src, vuln_code) and standalone(src, safe_code)):
        REASONS["source_not_in_both"] += 1
        return None
    safe_sink = pick_sink(safe_code, src)
    if not safe_sink or safe_sink == src:
        REASONS["no_sink_in_safe_revision"] += 1
        return None

    cwe = _CWE_FOR.get(re.split(r"[.(]", construct)[0].lower())
    if not cwe:
        REASONS["no_cwe_for_construct"] += 1
        return None

    pid = hashlib.sha1(f"xfile-restr|{owner_repo}|{commit}|{path}".encode()).hexdigest()[:12]
    meta = dict(language=lang, cve="", repo=owner_repo, sha=commit, src_file=path,
                cwe_source="construct_class", cross_file=True, multi_hop=True,
                fix_status="crossfile_restructure")
    REASONS["PAIR_KEPT"] += 1
    return (restructure_record(vuln_code, "vuln", cwe, src, construct, construct, meta, pid),
            restructure_record(safe_code, "safe", cwe, src, construct, safe_sink, meta, pid))


# The CWE follows from WHICH construct was removed -- a fact about the code, not a
# guess from a classifier. The contrastive set's classifier-derived CWEs agreed
# with CISA/OSV only 19.7% of the time, so nothing here is inferred from vocabulary.
_CWE_FOR = {
    "eval": "CWE-95", "exec": "CWE-95", "execsync": "CWE-78", "system": "CWE-78",
    "popen": "CWE-78", "shell_exec": "CWE-78", "passthru": "CWE-78",
    "innerhtml": "CWE-79", "outerhtml": "CWE-79", "document": "CWE-79",
    "insertadjacenthtml": "CWE-79", "dangerouslysetinnerhtml": "CWE-79",
    "pickle": "CWE-502", "cpickle": "CWE-502", "marshal": "CWE-502",
    "yaml": "CWE-502",
    "strcpy": "CWE-120", "strcat": "CWE-120", "sprintf": "CWE-120",
    "gets": "CWE-120", "memcpy": "CWE-120", "alloca": "CWE-770", "scanf": "CWE-120",
    "md5": "CWE-328", "sha1": "CWE-328", "des": "CWE-327", "rc4": "CWE-327",
    "ecb": "CWE-327", "random": "CWE-338", "rand": "CWE-338", "srand": "CWE-338",
    "authorization": "CWE-522", "printstacktrace": "CWE-209",
    # TLS verification disabled -- removing it is certificate validation, NOT the
    # SSRF the classifier guessed. Three of the four restructure_contrastive pairs
    # carried CWE-918 for exactly this, at the highest weight in the training file.
    "verify": "CWE-295", "insecurerequestwarning": "CWE-295",
    "trustallcerts": "CWE-295", "http": "CWE-319",
}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", default="codeql_targets.tsv")
    ap.add_argument("--lang", default="python")
    ap.add_argument("--limit", type=int, default=600)
    ap.add_argument("--max-per-repo", type=int, default=3)
    ap.add_argument("--max-files-per-commit", type=int, default=2)
    args = ap.parse_args()

    exts = EXTS[args.lang]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    leak = _leak_hashes()
    print(f"eval-leak guard: {len(leak)} hashes")

    seen = set()
    if OUT.exists():
        for line in open(OUT, encoding="utf-8"):
            try:
                seen.add(hashlib.sha256(
                    json.loads(line)["messages"][0]["content"].encode()).hexdigest())
            except Exception:
                continue
        print(f"resuming: {len(seen)} records present")

    rows = [l.rstrip("\r\n").split("\t") for l in open(args.targets, encoding="utf-8")]
    rows = [r[:3] for r in rows if len(r) >= 3 and r[1] == args.lang]

    per_repo, pairs, scanned = Counter(), 0, 0
    with open(OUT, "a", encoding="utf-8") as out_f:
        for owner_repo, lang, commit in rows:
            if scanned >= args.limit:
                break
            repo = REPOS / owner_repo.replace("/", "__")
            if not repo.exists():
                REASONS["repo_not_cloned"] += 1
                continue
            if per_repo[owner_repo] >= args.max_per_repo:
                continue
            per_repo[owner_repo] += 1
            scanned += 1
            try:
                for path in changed_files(repo, commit, exts)[:args.max_files_per_commit]:
                    pair = build_pair(repo, owner_repo, commit, lang, path, exts)
                    if not pair:
                        continue
                    hs = [hashlib.sha256(r["messages"][0]["content"].encode()).hexdigest()
                          for r in pair]
                    if any(h in seen or h in leak for h in hs):
                        REASONS["duplicate_or_eval_leak"] += 1
                        REASONS["PAIR_KEPT"] -= 1
                        continue
                    seen.update(hs)
                    for r in pair:
                        out_f.write(json.dumps(r, ensure_ascii=False) + "\n")
                    out_f.flush()
                    pairs += 1
            except Exception as e:
                REASONS[f"error:{type(e).__name__}"] += 1
            if scanned % 50 == 0:
                print(f"  [{scanned}/{args.limit}] {pairs} pairs", flush=True)

    print(f"\nDONE: {pairs} pairs ({pairs*2} records) from {scanned} commits -> {OUT}")
    print("\nfunnel:")
    for reason, count in REASONS.most_common():
        print(f"  {reason:30} {count}")


if __name__ == "__main__":
    main()
