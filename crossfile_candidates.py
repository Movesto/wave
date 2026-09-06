"""Stage 1 of clone-and-carve: find commits where a FUNCTION GAINED A REAL GUARD.

This is offline and reads only the patch corpus. It produces the shortlist of repos
worth cloning, so we never clone 32,008 repos to find a few hundred usable ones.

Why a new guard predicate. `build_crossfile_real.py` reused `pick_guard`, which was
written for single-function contrastive pairs where an added line in a security fix is
almost always the check. Across files it accepted anything added, and the hand-read of
its 28 pairs found the "guard" was frequently an assignment, a `return`, a `def` line or
a call to `error_log`. So here a guard must LOOK LIKE A GUARD: a conditional, a raise/
throw on a condition, or a call to a recognised validator/escaper.

Why a bigger callee blocklist. The same hand-read showed callees like `close`,
`constructor`, `request`, `response`, `parse`, `extend`, `purge` -- generic names that
collide across unrelated files, so "file A calls file B's function" was often a name
coincidence rather than a real edge. Stage 2 confirms the call in the cloned tree, but
filtering the obvious ones here keeps the clone list short.

    python crossfile_candidates.py                 # report
    python crossfile_candidates.py --write
"""
import argparse
import collections
import csv
import os
import re
import sys

from build_crossfile_real import (MAX_HUNKS_PER_COMMIT, MAX_PATCH_BYTES, _NAME,
                                  defined_names, hunks_by_file)

OUT = "data/osv/crossfile_candidates.tsv"

# A guard CONSTRAINS a value. These are the forms that do; an assignment, a bare return
# or a definition line does not, and those are what polluted the previous attempt.
_GUARD_SHAPES = (
    re.compile(r"^\s*(?:if|elif|unless|else\s+if)\s*[\(!]"),
    re.compile(r"^\s*(?:if|unless)\b.*\b(?:not|!|===|!==|==|!=|<|>|in\b|instanceof)\b"),
    re.compile(r"^\s*(?:raise|throw)\s+\w*(?:Error|Exception|Invalid|Denied|Forbidden)"),
    re.compile(r"\b(?:validate|sanitiz|sanitis|escape|encode|quote|allowlist|whitelist"
               r"|is_safe|isSafe|check_|verify|assert_valid|normalize|canonical|realpath"
               r"|startsWith|hasPermission|authorize|authenticate)\w*\s*\(", re.I),
)
# ...and these disqualify a line outright, however it looks.
_NOT_GUARD = re.compile(
    r"^\s*(?:def|function|class|public|private|protected|@|//|#|/\*|\*)"
    r"|^\s*(?:var|let|const)\s+\w+\s*=\s*(?!.*(?:validate|sanitiz|escape|check))"
    r"|^\s*\w+\s*=\s*(?!.*(?:validate|sanitiz|escape|check|filter))"
    r"|error_log\s*\(|console\.log\s*\(|logger?\.\w+\s*\(|printf\s*\(")

GENERIC_CALLEES = {
    "close", "open", "read", "write", "send", "recv", "start", "stop", "run", "call",
    "parse", "format", "render", "build", "create", "update", "delete", "remove",
    "request", "response", "handle", "process", "execute", "connect", "constructor",
    "extend", "merge", "clone", "copy", "purge", "flush", "reset", "clear", "load",
    "save", "get", "set", "add", "put", "post", "index", "show", "edit", "list",
    "next", "prev", "value", "data", "name", "size", "count", "length", "toString",
}


def added_guard(old, new):
    """The first added line that is genuinely a guard, else None."""
    old_lines = set(l.strip() for l in old.splitlines())
    for line in new.splitlines():
        s = line.strip()
        if not s or s in old_lines or len(s) < 8 or len(s) > 200:
            continue
        if _NOT_GUARD.search(line):
            continue
        if any(p.search(line) for p in _GUARD_SHAPES):
            return s
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    files = sorted(f for f in os.listdir(
        "data/downloads/morefixes-patches/cvedataset-patches") if f.endswith(".patch"))
    if args.limit:
        files = files[:args.limit]

    rows, f = [], collections.Counter()
    for n, fname in enumerate(files):
        if n % 4000 == 0:
            print(f"  {n}/{len(files)}, {len(rows)} candidates", flush=True)
        m = _NAME.match(fname)
        if not m:
            continue
        repo, sha = m.group(1), m.group(2)
        full = os.path.join("data/downloads/morefixes-patches/cvedataset-patches", fname)
        try:
            if os.path.getsize(full) > MAX_PATCH_BYTES:
                f["too_large"] += 1
                continue
            text = open(full, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        byfile = hunks_by_file(text)
        if not byfile or sum(len(v) for v in byfile.values()) > MAX_HUNKS_PER_COMMIT:
            f["skip"] += 1
            continue
        for path, hunks in byfile.items():
            for old, new, lang in hunks:
                if old == new:
                    continue
                names = defined_names(new) & defined_names(old)
                names = {x for x in names if x.lower() not in GENERIC_CALLEES}
                if not names:
                    continue
                guard = added_guard(old, new)
                if not guard:
                    f["no_real_guard"] += 1
                    continue
                for callee in sorted(names)[:2]:
                    rows.append(dict(repo=repo.replace("_", "/", 1), sha=sha, lang=lang,
                                     callee_file=path, callee=callee, guard=guard[:180]))
                    f["CANDIDATE"] += 1

    for k, v in f.most_common():
        print(f"  {k:20s} {v:6d}")
    repos = {r["repo"] for r in rows}
    print(f"\ncandidates: {len(rows)} across {len(repos)} repos, "
          f"{len({r['sha'] for r in rows})} commits")
    if args.write and rows:
        with open(OUT, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(rows)
        print(f"-> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
