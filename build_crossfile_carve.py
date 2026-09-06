"""Stage 2 of clone-and-carve: find the REAL caller of a guarded function.

The diff-only builder capped at 28 pairs because it needed the caller and the callee to
appear in the SAME commit. In a real repository the caller usually is not touched by the
fix at all -- that is the whole point of a cross-file vulnerability -- so the pool was
never going to be large. Here we fetch the repo at the fix commit and its parent, and
search the entire tree for callers.

    VULN = caller (unchanged)  +  callee body at sha^   (before the guard)
    SAFE = caller (unchanged)  +  callee body at sha    (after the guard)

The caller is byte-identical on both sides, so a verdict cannot be read off it -- the
only difference between the two records is the guard inside the callee, in a different
file. That is the property the held `shape3_crossfile_pairs` claimed and never had.

Fetching is `git fetch --depth 2 <sha>`, which GitHub serves for an arbitrary commit and
returns the commit plus its parent. WordPress fetches in under 3 seconds this way.

    python build_crossfile_carve.py --repos 60 --write
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

from filter_corpus import is_test_code, is_test_path, load_eval_codes
from scan_ts_standard import occurs

CANDS = "data/osv/crossfile_candidates.tsv"
OUT = "data/cot/staging/shape_crossfile_carved.jsonl"
REPORT = "data/osv/crossfile_carved.tsv"
WORK = os.environ.get("WAVE_CLONE_DIR", "data/clones")
MIN_CHARS, MAX_SIDE = 80, 1800
# One WordPress commit produced all 40 pairs of the first run.
MAX_PAIRS_PER_COMMIT = 3
MAX_TREE_FILES = 6000
EXTS = {".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "react",
        ".jsx": "react", ".php": "php", ".java": "java", ".rb": "ruby", ".go": "go"}


def git(args, cwd, timeout=180):
    return subprocess.run(["git"] + args, cwd=cwd, timeout=timeout,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode


def fetch(repo, sha, dest):
    """Fetch the commit AND its parent. Returns True on success."""
    os.makedirs(dest, exist_ok=True)
    if git(["init", "-q", "."], dest):
        return False
    git(["remote", "add", "origin", f"https://github.com/{repo}.git"], dest)
    return git(["fetch", "-q", "--depth", "2", "origin", sha], dest) == 0


def changed_files(dest):
    """Paths the fix commit touched -- one git call, not one per candidate file.

    The caller must be UNCHANGED by the fix or the verdict leaks into it. Checking that
    with `git show FETCH_HEAD^:<path>` per file spawned a subprocess for every file in
    the tree, which on WordPress meant thousands and never finished.
    """
    p = subprocess.run(["git", "diff", "--name-only", "FETCH_HEAD^", "FETCH_HEAD"],
                       cwd=dest, timeout=120, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL)
    if p.returncode:
        return None
    return set(p.stdout.decode("utf-8", "replace").split("\n"))


def show(dest, ref, path):
    p = subprocess.run(["git", "show", f"{ref}:{path}"], cwd=dest, timeout=60,
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if p.returncode:
        return None
    return p.stdout.decode("utf-8", "replace")


def extract_function(code, name):
    """The body of the function DEFINED as `name`, or None.

    The first version searched for `name` followed by `(` or `=`, which matched the
    first CALL to the function as often as its definition -- so the body handed back
    was some unrelated caller and the guard was not in it. 47 candidates were lost that
    way, more than the import rule rejected. Now the definition forms are explicit.
    """
    pats = (
        r"(?:^|\n)([ \t]*)(?:async[ \t]+)?def[ \t]+" + re.escape(name) + r"[ \t]*\(",
        r"(?:^|\n)([ \t]*)(?:export[ \t]+)?(?:async[ \t]+)?function[ \t]+"
        + re.escape(name) + r"[ \t]*\(",
        r"(?:^|\n)([ \t]*)(?:export[ \t]+)?(?:const|let|var)[ \t]+" + re.escape(name)
        + r"[ \t]*=[ \t]*(?:async[ \t]*)?(?:\([^)]*\)|[\w$]+)[ \t]*=>",
        r"(?:^|\n)([ \t]*)(?:export[ \t]+)?(?:const|let|var)[ \t]+" + re.escape(name)
        + r"[ \t]*=[ \t]*(?:async[ \t]+)?function",
        r"(?:^|\n)([ \t]*)" + re.escape(name) + r"[ \t]*:[ \t]*(?:async[ \t]*)?"
        r"(?:function|\([^)]*\)[ \t]*=>)",
        r"(?:^|\n)([ \t]*)(?:(?:public|private|protected|static|final|async)[ \t]+)*"
        r"[\w<>\[\].]+[ \t]+" + re.escape(name) + r"[ \t]*\([^)\n]*\)[ \t]*\{",
    )
    m = None
    for pat in pats:
        m = re.search(pat, code)
        if m:
            break
    if not m:
        return None
    indent = m.group(1) or ""
    start = m.start(1) if m.group(1) is not None else m.start()
    tail = code[start:]

    head = tail[:tail.find("\n") if "\n" in tail else len(tail)]
    if "{" in tail[:len(head) + 200]:            # brace languages
        depth, out, seen = 0, [], False
        for ch in tail[:20000]:
            out.append(ch)
            if ch == "{":
                depth += 1
                seen = True
            elif ch == "}":
                depth -= 1
                if seen and depth <= 0:
                    break
        return "".join(out)

    lines = tail.splitlines()                    # python: until dedent
    body = [lines[0]]
    for line in lines[1:]:
        if line.strip() and not line.startswith(indent + " ") \
                and not line.startswith(indent + "\t"):
            break
        body.append(line)
    return "\n".join(body)


def trim(code):
    return code if len(code) <= MAX_SIDE else code[:MAX_SIDE].rsplit("\n", 1)[0]


def walk_code_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "node_modules", "vendor", "dist", "build")]
        for fn in filenames:
            ext = os.path.splitext(fn)[1]
            if ext in EXTS:
                yield os.path.join(dirpath, fn), EXTS[ext]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--repos", type=int, default=60)
    ap.add_argument("--keep", action="store_true", help="keep clones on disk")
    args = ap.parse_args()

    evalcodes = load_eval_codes()
    cands = list(csv.DictReader(open(CANDS, encoding="utf-8"), delimiter="\t"))
    by_commit = collections.defaultdict(list)
    for c in cands:
        by_commit[(c["repo"], c["sha"])].append(c)
    commits = sorted(by_commit, key=lambda k: -len(by_commit[k]))[:args.repos]
    print(f"{len(cands)} candidates; trying {len(commits)} commits", flush=True)

    out, report, f = [], [], collections.Counter()
    seen = set()
    os.makedirs(WORK, exist_ok=True)

    for i, (repo, sha) in enumerate(commits):
        dest = os.path.join(WORK, repo.replace("/", "__") + "_" + sha[:8])
        print(f"  [{i+1}/{len(commits)}] {repo} @ {sha[:10]}", flush=True)
        try:
            if not fetch(repo, sha, dest):
                f["fetch_failed"] += 1
                shutil.rmtree(dest, ignore_errors=True)
                continue
        except subprocess.TimeoutExpired:
            f["fetch_timeout"] += 1
            shutil.rmtree(dest, ignore_errors=True)
            continue
        if git(["checkout", "-q", "FETCH_HEAD"], dest):
            f["checkout_failed"] += 1
            shutil.rmtree(dest, ignore_errors=True)
            continue

        # Read the tree ONCE per repo. Walking and re-reading every file for each
        # candidate meant WordPress (>10k code files) never finished a single commit.
        tree = []
        for path, lang in walk_code_files(dest):
            rel = os.path.relpath(path, dest).replace("\\", "/")
            if is_test_path(rel):
                continue
            try:
                if os.path.getsize(path) > 400_000:
                    continue
                tree.append((rel, lang,
                             open(path, encoding="utf-8", errors="replace").read()))
            except OSError:
                continue
            if len(tree) >= MAX_TREE_FILES:
                break

        touched = changed_files(dest)
        if touched is None:
            f["diff_failed"] += 1
            shutil.rmtree(dest, ignore_errors=True)
            continue

        made_here = 0
        for c in by_commit[(repo, sha)]:
            if made_here >= MAX_PAIRS_PER_COMMIT:
                break
            callee, cal_path, guard = c["callee"], c["callee_file"], c["guard"]
            safe_file = show(dest, "FETCH_HEAD", cal_path)
            vuln_file = show(dest, "FETCH_HEAD^", cal_path)
            if not (safe_file and vuln_file):
                f["callee_file_missing"] += 1
                continue
            safe_fn = extract_function(safe_file, callee)
            vuln_fn = extract_function(vuln_file, callee)
            if not (safe_fn and vuln_fn) or safe_fn == vuln_fn and guard not in safe_fn:
                f["callee_body_not_found"] += 1
                continue
            gnorm = re.sub(r"\s+", " ", guard).strip()
            if gnorm not in re.sub(r"\s+", " ", safe_fn):
                f["guard_not_in_safe_body"] += 1
                continue
            if gnorm in re.sub(r"\s+", " ", vuln_fn):
                f["guard_already_in_vuln_body"] += 1
                continue

            # find a CALLER anywhere in the tree, in a different file
            found = None
            for rel, lang, body in tree:
                if rel == cal_path:
                    continue
                if callee not in body or not occurs(callee, body):
                    continue
                # The match must be a CALL, not a DEFINITION of the same name. In OO
                # code a base class and its subclasses all declare `get_item(...)`, so
                # matching `name(` anywhere made an abstract base method look like a
                # caller -- every WordPress pair in the first run was that mistake.
                if not is_real_call(body, callee):
                    continue
                if rel in touched:
                    continue          # the fix changed this file; verdict would leak
                snippet = extract_function_containing(body, callee)
                if snippet:
                    found = (rel, snippet, lang)
                    break
            if not found:
                f["no_caller_found"] += 1
                continue
            call_path, call_code, lang = found

            vuln = f"# {call_path}\n{trim(call_code)}\n\n# {cal_path}\n{trim(vuln_fn)}"
            safe = f"# {call_path}\n{trim(call_code)}\n\n# {cal_path}\n{trim(safe_fn)}"
            if not (MIN_CHARS <= len(vuln) <= 4500 and MIN_CHARS <= len(safe) <= 4500):
                f["size"] += 1
                continue
            if is_test_code(vuln) or is_test_code(safe):
                f["test_code"] += 1
                continue
            if any(re.sub(r"\s+", " ", x).strip().lower() in evalcodes
                   for x in (vuln, safe)):
                f["eval_leak"] += 1
                continue
            key = hashlib.sha1(re.sub(r"\s+", "", vuln).encode()).hexdigest()
            if key in seen:
                f["duplicate"] += 1
                continue
            seen.add(key)

            pid = hashlib.sha1(f"carve|{sha}|{cal_path}|{callee}".encode()).hexdigest()[:12]
            meta = dict(shape="shape_crossfile", source="crossfile_carved", repo=repo,
                        sha=sha, language=lang, cross_file=True, multi_hop=True,
                        caller_file=call_path, callee_file=cal_path, callee=callee,
                        guard=guard[:160], pair_id=pid,
                        fix_status="carved_caller_unchanged")
            vt = (f"Hypothesis: `{call_path}` calls `{callee}`, which is defined in "
                  f"`{cal_path}` - the verdict depends on what `{callee}` does to the "
                  f"value, and that is in the other file.\n"
                  f"Trigger path: the call site hands the value to `{callee}`; I read "
                  f"`{callee}` rather than assume.\n"
                  f"Defensive check: inside `{callee}` nothing constrains the value "
                  f"before it is used.\n"
                  f"The control is missing on the path, so the hypothesis stands.")
            st = (f"Hypothesis: `{call_path}` calls `{callee}` in `{cal_path}` - the "
                  f"same two-file path, so the call site alone cannot settle it.\n"
                  f"Trigger path: the call site is byte-identical to the vulnerable "
                  f"version; only the callee differs.\n"
                  f"Defensive check: `{callee}` contains `{guard[:90]}`, which "
                  f"constrains the value inside the callee.\n"
                  f"The control is on the path, so the hypothesis is refuted.")
            for label, code, think, tail in (
                ("vuln", vuln, vt,
                 f"status: confirmed\nseverity: HIGH\n"
                 f"trace: {call_path} calls {callee} -> {cal_path}:{callee} uses the "
                 f"value unconstrained\nfix: constrain the value inside `{callee}`"),
                ("safe", safe, st,
                 f"status: safe\nseverity: none\n"
                 f"trace: {call_path} calls {callee} -> {cal_path}:{callee} constrains "
                 f"it with `{guard[:60]}`\nfix: none")):
                mm = dict(meta)
                mm["label"] = label
                out.append({"messages": [
                    {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                    {"role": "assistant",
                     "content": f"<think>\n{think}\n</think>\n{tail}"}], "_meta": mm})
            report.append(dict(pair_id=pid, repo=repo, sha=sha[:12], lang=lang,
                               caller=call_path, callee_file=cal_path, callee=callee,
                               guard=guard[:90]))
            f["PAIR"] += 1
            made_here += 1

        if not args.keep:
            shutil.rmtree(dest, ignore_errors=True)

    for k, v in f.most_common():
        print(f"  {k:26s} {v:5d}")
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


# A declaration prologue: only bare words / types may sit before the name.
# A real call site has `->`, `.`, `::`, `$`, `(` or `=` in front of it instead.
_DECL_PROLOGUE = re.compile(
    r"^[ \t]*(?:(?:public|private|protected|static|final|abstract|async|export|"
    r"synchronized)[ \t]+)*[\w<>\[\],.\t ]*$")
_DECL_KEYWORDS = ("def", "function", "func", "sub", "fn")


def is_real_call(code, callee):
    """True if `callee` is INVOKED in this file, not merely declared.

    Matching `name(` anywhere made every WordPress base class look like a caller of
    its own subclasses' methods: `class-wp-rest-controller.php` DECLARES
    `get_item_permissions_check`, it does not call it. All 40 pairs of the first carve
    run were that mistake, so declaration sites are now rejected explicitly.
    """
    for m in re.finditer(r"\b" + re.escape(callee) + r"\s*\(", code):
        line_start = code.rfind("\n", 0, m.start()) + 1
        prefix = code[line_start:m.start()].rstrip()
        toks = prefix.split()
        if toks and toks[-1] in _DECL_KEYWORDS:
            continue                       # `def foo(` / `function foo(`
        if _DECL_PROLOGUE.match(prefix):
            continue                       # `public WP_Error get_item(`
        return True
    return False


def extract_function_containing(code, callee):
    """The enclosing function of the first call to `callee`."""
    m = re.search(r"\b" + re.escape(callee) + r"\s*\(", code)
    if not m:
        return None
    head = code[:m.start()]
    starts = [x.start() for x in re.finditer(
        r"(?:^|\n)[ \t]*(?:def |function |async def |public |private |protected |"
        r"func |const \w+\s*=\s*(?:async\s*)?\()", head)]
    begin = starts[-1] if starts else max(0, m.start() - 600)
    end = min(len(code), m.end() + 600)
    return code[begin:end].strip()


if __name__ == "__main__":
    sys.exit(main())
