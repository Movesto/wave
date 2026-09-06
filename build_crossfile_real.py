"""Build REAL cross-file contrastive pairs: a call site in file A, its callee in file B.

Why this exists. The corpus is almost entirely one function, one file, one hunk -- "is
there a guard on this path". That makes a good guard-checker and a poor vulnerability
solver, because real work is multi-file: input arrives in A, is handed to a helper in B,
and reaches a sink there. Our only interprocedural data was `shape3_codeql_localize`,
which is a localisation task and never states a verdict.

The previous attempt (`shape3_crossfile_pairs`, held) failed because it cut LINE WINDOWS
from two files of a commit and narrated the CVE's CWE onto them: 17 of 38 pairs named a
sink that was not in the excerpt at all. The lesson is that the cross-file LINK has to be
proven, not assumed.

So a pair is emitted only when all of this holds:

  1. the commit touches >= 2 code files
  2. file B defines a function `f` (def/function/const f = ...)
  3. file A CALLS `f` -- verified with the scanner's own `occurs`, so a substring of a
     longer identifier cannot pass
  4. the fix ADDED A GUARD inside `f` in file B -- `pick_guard` finds a control present
     in the post-fix body and absent from the pre-fix body
  5. a caller-controlled SOURCE is visible in file A
  6. neither side is test code, both fit the size cap, neither leaks into eval_v2

Then:
    VULN = A's call site  +  B's PRE-fix callee   (no guard)
    SAFE = A's call site  +  B's POST-fix callee  (guard added)

Both sides show both files, so the verdict genuinely cannot be reached from one file:
the call site is identical in both, and only the callee differs. That is the property
`shape3_crossfile_pairs` claimed and did not have.

    python build_crossfile_real.py --write
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import re
import sys

from build_r2vul_pairs import MAX_CODE_CHARS, pick_guard, pick_source, standalone
from filter_corpus import is_test_code, load_eval_codes
from scan_ts_standard import occurs

PATCH_DIR = "data/downloads/morefixes-patches/cvedataset-patches"
OUT = "data/cot/staging/shape_crossfile_real.jsonl"
REPORT = "data/osv/crossfile_real.tsv"
MIN_CHARS = 80
# One pair per commit, and skip sprawling commits entirely -- see the note at the
# guard below. This also stops a single large refactor from dominating the set.
MAX_FILES_PER_COMMIT = 12
MAX_HUNKS_PER_COMMIT = 120
# A few pairs per commit, not one and not unbounded: one-per-commit gave ~32 pairs
# total, unbounded let a single commit contribute dozens of near-identical ones.
MAX_PAIRS_PER_COMMIT = 3
MAX_PATCH_BYTES = 300_000
MAX_SIDE = 2000          # each file's excerpt; the pair shows two of them

_NAME = re.compile(r"^github\.com_(.+)_([0-9a-f]{40})\.patch$")

# a function definition, per language family
_DEF = re.compile(
    r"(?:^|\n)\s*(?:async\s+)?def\s+([A-Za-z_]\w+)\s*\("           # python
    r"|(?:^|\n)\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_]\w+)\s*\("  # js/ts
    r"|(?:^|\n)\s*(?:export\s+)?const\s+([A-Za-z_]\w+)\s*=\s*(?:async\s*)?\("  # arrow
    # java/c-like. The modifier group is BOUNDED and does not contain `\s` as an
    # alternative. The original `(?:public|private|protected|static|\s)*` put `\s`
    # inside a starred alternation, which is a catastrophic-backtracking bomb: on a
    # heavily-indented or minified line the engine explores exponentially many ways to
    # split the whitespace. That stalled the run for an hour at a patch well under the
    # size cap, which is why the size cap alone did not fix it.
    r"|(?:^|\n)[ \t]*(?:(?:public|private|protected|static|final|synchronized)[ \t]+)"
    r"{0,4}[A-Za-z_][\w<>\[\]]*[ \t]+([A-Za-z_]\w+)[ \t]*\([^)\n]{0,300}\)[ \t]*\{")

# a caller-controlled entry point visible in the CALLER file
_SOURCE_HINT = re.compile(
    r"\b(request|req|params|query|body|argv|environ|getParameter|form|"
    r"GET|POST|input|stdin|payload|headers|cookies|url)\b", re.I)


# Keywords that a definition regex will happily capture as a function name. `func`
# slipped through the java/c-like branch on Go source and produced pairs whose "callee"
# was the `func` keyword -- the same failure as the `elif`/`main` sinks that got
# shape3_crossfile_pairs held.
_KEYWORDS = {
    "if", "for", "while", "switch", "catch", "return", "new", "func", "function", "def",
    "class", "struct", "interface", "package", "import", "const", "var", "let", "else",
    "elif", "try", "finally", "with", "async", "await", "defer", "go", "select", "case",
    "default", "public", "private", "protected", "static", "void", "int", "string",
    "bool", "error", "map", "make", "type", "range", "main", "init", "self", "this",
    "print", "printf", "sprintf", "log", "test", "assert",
}


def defined_names(code):
    out = set()
    for m in _DEF.finditer(code):
        name = next((g for g in m.groups() if g), None)
        if name and len(name) > 3 and name.lower() not in _KEYWORDS:
            out.add(name)
    return out


def hunks_by_file(text):
    """path -> [(old, new)] for every code file in the patch."""
    from cot.fix_pairs import _EXT_LANG, _SKIP_PATH, _TEST_PATH, _reconstruct_hunks
    out = collections.defaultdict(list)
    for part in re.split(r"^diff --git ", text, flags=re.M)[1:]:
        head = re.match(r"a/(.+?) b/(.+?)\s*$", part.split("\n", 1)[0])
        if not head:
            continue
        path = head.group(2)
        ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
        if not _EXT_LANG.get(ext):
            continue
        if _TEST_PATH.search(path) or _SKIP_PATH.search(path):
            continue
        for old, new in _reconstruct_hunks(part):
            out[path].append((old, new, _EXT_LANG[ext]))
    return out


def trim(code, limit=MAX_SIDE):
    return code if len(code) <= limit else code[:limit].rsplit("\n", 1)[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--every", type=int, default=2000)
    args = ap.parse_args()

    evalcodes = load_eval_codes()
    files = sorted(f for f in os.listdir(PATCH_DIR) if f.endswith(".patch"))
    if args.start:
        files = files[args.start:]
    if args.limit:
        files = files[:args.limit]

    out, report, f = [], [], collections.Counter()
    seen = set()

    for n, fname in enumerate(files):
        if n % args.every == 0:
            print(f"  {n}/{len(files)} patches, {f['PAIR']} pairs", flush=True)
        m = _NAME.match(fname)
        if not m:
            continue
        repo, sha = m.group(1), m.group(2)
        full = os.path.join(PATCH_DIR, fname)
        # Check the SIZE before reading. The commit-level bounds below cannot help here
        # because the blowup is in parsing itself: a 39 MB patch (a vendored-dependency
        # dump) stalled the whole run for an hour twice, at the same file, because
        # `_reconstruct_hunks` never got far enough for the bounds to apply.
        # A patch this large is a bulk import, not a vulnerability fix.
        try:
            if os.path.getsize(full) > MAX_PATCH_BYTES:
                f["patch_too_large"] += 1
                continue
            text = open(full, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        byfile = hunks_by_file(text)
        if len(byfile) < 2:
            f["single_file_commit"] += 1
            continue
        # The search below is files x hunks x names x files x hunks. On a sprawling
        # commit that is quadratic in the patch and one refactor spanning 200 files
        # stalled the whole run for an hour. A vulnerability fix that touches dozens of
        # files is also the LEAST likely to give a clean caller/callee pair, so bounding
        # this costs almost nothing and makes the run finite.
        if len(byfile) > MAX_FILES_PER_COMMIT:
            f["commit_too_broad"] += 1
            continue
        if sum(len(v) for v in byfile.values()) > MAX_HUNKS_PER_COMMIT:
            f["commit_too_many_hunks"] += 1
            continue
        f["multifile_commit"] += 1
        here = 0

        # CALLEE side: a file whose hunk both defines a function and gains a guard.
        for cal_path, cal_hunks in byfile.items():
            for old, new, lang in cal_hunks:
                if old == new:
                    continue
                names = defined_names(new) & defined_names(old)
                if not names:
                    continue
                guard = pick_guard(old, new)
                if not guard:
                    f["no_guard_added"] += 1
                    continue

                # CALLER side: a DIFFERENT file that calls one of those functions.
                for callee in sorted(names):
                    # The CALL LINE must be identical before and after the fix. A diff
                    # only carries changed hunks, so requiring the caller's whole hunk to
                    # be unchanged matched nothing -- but the guarantee we actually need
                    # is narrower: the call site itself must not move, or the verdict
                    # could be read off the caller and the pair stops being cross-file.
                    callpat = re.compile(r"^.*\b" + re.escape(callee) + r"\s*\(.*$", re.M)
                    hit = None
                    for path2, hunks2 in byfile.items():
                        if path2 == cal_path:
                            continue
                        for old2, new2, _lang2 in hunks2:
                            if not occurs(callee, old2):
                                continue
                            lines_old = set(x.strip() for x in callpat.findall(old2))
                            lines_new = set(x.strip() for x in callpat.findall(new2))
                            if lines_old and lines_old & lines_new:
                                hit = (path2, old2)
                                break
                        if hit:
                            break
                    if not hit:
                        continue
                    call_path, call_code = hit
                    if not _SOURCE_HINT.search(call_code):
                        f["no_caller_source"] += 1
                        continue

                    # The source has to be a real identifier visible in the CALLER. The
                    # fallback string "the caller-supplied value" produced traces that
                    # named nothing and could not be checked against the code.
                    src = pick_source(guard, old, new)
                    if not src or not occurs(src, call_code):
                        f["no_grounded_source"] += 1
                        continue
                    vuln = (f"# {call_path}\n{trim(call_code)}\n\n"
                            f"# {cal_path}\n{trim(old)}")
                    safe = (f"# {call_path}\n{trim(call_code)}\n\n"
                            f"# {cal_path}\n{trim(new)}")
                    if not (MIN_CHARS <= len(vuln) <= MAX_CODE_CHARS
                            and MIN_CHARS <= len(safe) <= MAX_CODE_CHARS):
                        f["size"] += 1
                        continue
                    if is_test_code(vuln) or is_test_code(safe):
                        f["test_code"] += 1
                        continue
                    if any(re.sub(r"\s+", " ", x).strip().lower() in evalcodes
                           for x in (vuln, safe)):
                        f["eval_leak"] += 1
                        continue
                    if guard in old:
                        f["guard_already_in_vuln"] += 1
                        continue
                    key = hashlib.sha1(re.sub(r"\s+", "", vuln).encode()).hexdigest()
                    if key in seen:
                        f["duplicate"] += 1
                        continue
                    seen.add(key)

                    pid = hashlib.sha1(
                        f"xfile|{sha}|{cal_path}|{callee}".encode()).hexdigest()[:12]
                    meta = dict(shape="shape_crossfile", source="crossfile_real",
                                repo=repo, sha=sha, language=lang, cross_file=True,
                                multi_hop=True, caller_file=call_path,
                                callee_file=cal_path, callee=callee,
                                pair_id=pid, fix_status="crossfile_guard_added")

                    vt = (f"Hypothesis: `{src}` enters in `{call_path}` and is handed to "
                          f"`{callee}`, which is defined in `{cal_path}` - so the verdict "
                          f"depends on what `{callee}` does, not on the call site.\n"
                          f"Trigger path: the call site passes the value straight to "
                          f"`{callee}`; I read `{callee}` in the second file to see what "
                          f"constrains it.\n"
                          f"Defensive check: inside `{callee}` there is no control on the "
                          f"value - the body uses it as received.\n"
                          f"Nothing on the path between the two files stops the value, so "
                          f"the hypothesis stands.")
                    st = (f"Hypothesis: `{src}` enters in `{call_path}` and reaches "
                          f"`{callee}` in `{cal_path}` - the same two-file path as before, "
                          f"so the call site alone cannot settle it.\n"
                          f"Trigger path: the call site is unchanged; the value still "
                          f"arrives at `{callee}`.\n"
                          f"Defensive check: `{callee}` now contains "
                          f"`{guard[:90]}`, which constrains the value inside the callee "
                          f"before it is used.\n"
                          f"The control is on the path itself, so the hypothesis is "
                          f"refuted.")

                    for label, code, think, tail in (
                        ("vuln", vuln, vt,
                         f"status: confirmed\nseverity: HIGH\n"
                         f"trace: {call_path} calls {callee} -> {cal_path}:{callee} "
                         f"uses the value unconstrained\n"
                         f"fix: constrain the value inside `{callee}`"),
                        ("safe", safe, st,
                         f"status: safe\nseverity: none\n"
                         f"trace: {call_path} calls {callee} -> {cal_path}:{callee} "
                         f"constrains it with `{guard[:60]}`\nfix: none")):
                        mm = dict(meta)
                        mm["label"] = label
                        out.append({"messages": [
                            {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                            {"role": "assistant",
                             "content": f"<think>\n{think}\n</think>\n{tail}"}],
                            "_meta": mm})
                    report.append(dict(pair_id=pid, repo=repo, sha=sha[:12], lang=lang,
                                       caller=call_path, callee_file=cal_path,
                                       callee=callee, guard=guard[:70]))
                    f["PAIR"] += 1
                    here += 1
                    break
                if here >= MAX_PAIRS_PER_COMMIT:
                    break
            if here >= MAX_PAIRS_PER_COMMIT:
                break

    for k, v in f.most_common():
        print(f"  {k:26s} {v:6d}")
    if args.write and out:
        with open(OUT, "w", encoding="utf-8") as fh:
            for r in out:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        with open(REPORT, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(report[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(report)
        print(f"\n-> {OUT} ({len(out)//2} pairs)\n-> {REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
