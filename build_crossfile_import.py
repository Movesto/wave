"""Cross-file pairs where the call edge is PROVEN BY AN IMPORT (python / js / ts only).

Why this exists, and why it is not another tuning pass on the previous builder.

Name matching cannot establish a call edge in an OO language. `class-wp-rest-attachments-
controller.php` calls `parent::update_item()`, and `class-wp-rest-comments-controller.php`
defines `update_item()`; they are sibling subclasses, not caller and callee. Every carve
attempt produced pairs like that, because "A mentions a name that B defines" is simply
not evidence, and no regex fixes it -- it needs type resolution.

An IMPORT is different: it is textual, and it names the file. If `caller.py` says
`from app.util import clean_path`, the reference provably resolves to `app/util.py`.
So this builder is restricted to languages with module-scoped imports and requires:

  1. the callee file defines `f`, and the fix ADDED A GUARD inside `f`
  2. the caller file IMPORTS `f` from the callee's module -- resolved as a path, not
     guessed from the name
  3. the caller CALLS `f`
  4. the caller is UNCHANGED by the fix, so no verdict can be read off it

PHP and Java are excluded on purpose: they have no import that binds a method to a file.
That costs yield and buys the one property the previous four attempts never had.

    python build_crossfile_import.py --repos 40 --write
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys

from build_crossfile_carve import (changed_files, extract_function,
                                   extract_function_containing, fetch, git, is_real_call,
                                   show, trim)
from filter_corpus import is_test_code, is_test_path, load_eval_codes
from scan_ts_standard import occurs

CANDS = "data/osv/crossfile_candidates.tsv"
OUT = "data/cot/staging/shape_crossfile_import.jsonl"
REPORT = "data/osv/crossfile_import.tsv"
WORK = os.environ.get("WAVE_CLONE_DIR", "data/clones")
LANGS = {"python", "javascript", "typescript", "react"}
EXTS = {".py": "python", ".js": "javascript", ".ts": "typescript",
        ".tsx": "react", ".jsx": "react", ".mjs": "javascript"}
MIN_CHARS, MAX_TREE_FILES, MAX_PAIRS_PER_COMMIT = 80, 6000, 3

_PY_FROM = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+([^\n#]+)", re.M)
_PY_IMPORT = re.compile(r"^\s*import\s+([\w.]+)", re.M)
_JS_FROM = re.compile(r"""^\s*import\s+([^;\n]+?)\s+from\s*['"]([^'"]+)['"]""", re.M)
_JS_REQ = re.compile(
    r"""(?:const|let|var)\s+([^=\n]+?)\s*=\s*require\(\s*['"]([^'"]+)['"]""", re.M)


def module_of(path):
    """`app/util.py` -> `app.util`"""
    return re.sub(r"\.py$", "", path).replace("/", ".")


def py_imports_callee(caller_src, caller_path, callee_path, callee):
    """True if caller imports `callee` from the file `callee_path`."""
    target = module_of(callee_path)
    tail = target.split(".")[-1]
    for m in _PY_FROM.finditer(caller_src):
        mod, names = m.group(1), m.group(2)
        if callee not in re.split(r"[,\s]+", names.replace("(", " ").replace(")", " ")):
            continue
        # absolute (`from app.util import f`) or relative (`from .util import f`)
        if target.endswith(mod.lstrip(".")) or mod.lstrip(".").endswith(tail):
            return True
    for m in _PY_IMPORT.finditer(caller_src):
        mod = m.group(1)
        if (target.endswith(mod) or mod.endswith(tail)) and \
                re.search(r"\b" + re.escape(mod.split(".")[-1]) + r"\." +
                          re.escape(callee) + r"\s*\(", caller_src):
            return True
    return False


def js_resolves(spec, caller_path, callee_path):
    """Does an import specifier resolve to the callee file?"""
    callee_base = re.sub(r"\.(js|ts|tsx|jsx|mjs)$", "", callee_path)
    if spec.startswith("."):
        resolved = posixpath.normpath(
            posixpath.join(posixpath.dirname(caller_path), spec))
        return resolved == callee_base or resolved == posixpath.dirname(callee_base) \
            and posixpath.basename(callee_base) == "index"
    # non-relative: treat as a path suffix (aliased or package-root import)
    spec = spec.lstrip("@/")
    return bool(spec) and (callee_base.endswith("/" + spec) or callee_base == spec)


def js_imports_callee(caller_src, caller_path, callee_path, callee):
    for rx in (_JS_FROM, _JS_REQ):
        for m in rx.finditer(caller_src):
            names, spec = m.group(1), m.group(2)
            if not js_resolves(spec, caller_path, callee_path):
                continue
            bound = set(re.findall(r"[A-Za-z_$][\w$]*", names))
            if callee in bound:
                return True
            # default/namespace import used as `ns.callee(`
            for b in bound:
                if re.search(r"\b" + re.escape(b) + r"\." + re.escape(callee) +
                             r"\s*\(", caller_src):
                    return True
    return False


def imports_callee(lang, caller_src, caller_path, callee_path, callee):
    if lang == "python":
        return py_imports_callee(caller_src, caller_path, callee_path, callee)
    return js_imports_callee(caller_src, caller_path, callee_path, callee)


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in
                       (".git", "node_modules", "vendor", "dist", "build", "__pycache__")]
        for fn in filenames:
            ext = os.path.splitext(fn)[1]
            if ext in EXTS:
                yield os.path.join(dirpath, fn), EXTS[ext]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--repos", type=int, default=40)
    ap.add_argument("--skip", type=int, default=0,
                    help="skip the first N commits (already used for training)")
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--shards", type=int, default=1)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--report", default=REPORT)
    ap.add_argument("--exclude-training-repos", action="store_true",
                    help="drop every repo that appears in ANY wired training shape")
    args = ap.parse_args()

    evalcodes = load_eval_codes()
    cands = [c for c in csv.DictReader(open(CANDS, encoding="utf-8"), delimiter="\t")
             if c["lang"] in LANGS]
    by_commit = collections.defaultdict(list)
    for c in cands:
        by_commit[(c["repo"], c["sha"])].append(c)
    commits = sorted(by_commit, key=lambda k: -len(by_commit[k]))
    if args.skip:
        commits = commits[args.skip:]

    if args.exclude_training_repos:
        # Repo-level disjointness, not code-level. A DIFFERENT function from a repo the
        # model trained on is still that project; the first TS/JS holdout leaked exactly
        # this way (3 code overlaps, 13 repo overlaps).
        train = set()
        for d in ("data/cot/pilot", "data/cot/staging"):
            if not os.path.isdir(d):
                continue
            for fn in os.listdir(d):
                if not fn.endswith(".jsonl"):
                    continue
                for line in open(os.path.join(d, fn), encoding="utf-8"):
                    if not line.strip():
                        continue
                    try:
                        m = json.loads(line).get("_meta", {})
                    except ValueError:
                        continue
                    r = m.get("repo")
                    if r:
                        train.add(r.lower().replace("_", "/", 1))
                        train.add(r.lower())
        before = len(commits)
        commits = [k for k in commits if k[0].lower() not in train]
        print(f"repo holdout: {before - len(commits)} commits dropped "
              f"({len(train)} training repos)", flush=True)

    if args.shards > 1:
        commits = [k for i, k in enumerate(commits) if i % args.shards == args.shard]
    commits = commits[:args.repos]
    print(f"{len(cands)} py/js/ts candidates in {len(by_commit)} commits; "
          f"trying {len(commits)}", flush=True)

    out, report, f = [], [], collections.Counter()
    seen = set()
    os.makedirs(WORK, exist_ok=True)

    for i, (repo, sha) in enumerate(commits):
        dest = os.path.join(WORK, repo.replace("/", "__") + "_" + sha[:8])
        print(f"  [{i+1}/{len(commits)}] {repo} @ {sha[:10]}", flush=True)
        try:
            if not fetch(repo, sha, dest) or git(["checkout", "-q", "FETCH_HEAD"], dest):
                f["fetch_failed"] += 1
                shutil.rmtree(dest, ignore_errors=True)
                continue
        except subprocess.TimeoutExpired:
            f["fetch_timeout"] += 1
            shutil.rmtree(dest, ignore_errors=True)
            continue
        touched = changed_files(dest)
        if touched is None:
            shutil.rmtree(dest, ignore_errors=True)
            continue

        tree = []
        for path, lang in walk(dest):
            rel = os.path.relpath(path, dest).replace("\\", "/")
            if is_test_path(rel) or rel in touched:
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

        made = 0
        for c in by_commit[(repo, sha)]:
            if made >= MAX_PAIRS_PER_COMMIT:
                break
            callee, cal_path, guard = c["callee"], c["callee_file"], c["guard"]
            safe_file = show(dest, "FETCH_HEAD", cal_path)
            vuln_file = show(dest, "FETCH_HEAD^", cal_path)
            if not (safe_file and vuln_file):
                f["callee_file_missing"] += 1
                continue
            safe_fn = extract_function(safe_file, callee)
            vuln_fn = extract_function(vuln_file, callee)
            if not (safe_fn and vuln_fn):
                f["callee_body_not_found"] += 1
                continue
            gnorm = re.sub(r"\s+", " ", guard).strip()
            if gnorm not in re.sub(r"\s+", " ", safe_fn):
                f["guard_not_in_safe_body"] += 1
                continue
            if gnorm in re.sub(r"\s+", " ", vuln_fn):
                f["guard_already_in_vuln"] += 1
                continue

            found = None
            for rel, lang, body in tree:
                if rel == cal_path or callee not in body:
                    continue
                if not imports_callee(lang, body, rel, cal_path, callee):
                    continue
                if not (occurs(callee, body) and is_real_call(body, callee)):
                    continue
                snippet = extract_function_containing(body, callee)
                if snippet:
                    found = (rel, snippet, lang)
                    break
            if not found:
                f["no_importing_caller"] += 1
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

            pid = hashlib.sha1(f"imp|{sha}|{cal_path}|{callee}".encode()).hexdigest()[:12]
            meta = dict(shape="shape_crossfile", source="crossfile_import", repo=repo,
                        sha=sha, language=lang, cross_file=True, multi_hop=True,
                        caller_file=call_path, callee_file=cal_path, callee=callee,
                        guard=guard[:160], pair_id=pid,
                        fix_status="import_edge_verified")
            vt = (f"Hypothesis: `{call_path}` imports `{callee}` from `{cal_path}` and "
                  f"calls it, so the verdict depends on what `{callee}` does - and that "
                  f"is in the other file.\n"
                  f"Trigger path: the call site hands its value to `{callee}`; I read "
                  f"`{callee}` rather than assume it is safe.\n"
                  f"Defensive check: inside `{callee}` nothing constrains the value "
                  f"before it is used.\n"
                  f"The control is missing on the path, so the hypothesis stands.")
            st = (f"Hypothesis: `{call_path}` imports `{callee}` from `{cal_path}` - the "
                  f"same two-file path, so the call site alone cannot settle it.\n"
                  f"Trigger path: the call site is byte-identical to the vulnerable "
                  f"version; only the imported function differs.\n"
                  f"Defensive check: `{callee}` contains `{guard[:90]}`, which "
                  f"constrains the value inside the callee.\n"
                  f"The control is on the path, so the hypothesis is refuted.")
            for label, code, think, tail in (
                ("vuln", vuln, vt,
                 f"status: confirmed\nseverity: HIGH\ntrace: {call_path} imports "
                 f"{callee} from {cal_path}; {callee} uses the value unconstrained\n"
                 f"fix: constrain the value inside `{callee}`"),
                ("safe", safe, st,
                 f"status: safe\nseverity: none\ntrace: {call_path} imports {callee} "
                 f"from {cal_path}; {callee} constrains it with `{guard[:60]}`\n"
                 f"fix: none")):
                mm = dict(meta)
                mm["label"] = label
                out.append({"messages": [
                    {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                    {"role": "assistant",
                     "content": f"<think>\n{think}\n</think>\n{tail}"}], "_meta": mm})
            report.append(dict(pair_id=pid, repo=repo, lang=lang, caller=call_path,
                               callee_file=cal_path, callee=callee, guard=guard[:80]))
            f["PAIR"] += 1
            made += 1

        shutil.rmtree(dest, ignore_errors=True)

    for k, v in f.most_common():
        print(f"  {k:26s} {v:5d}")
    if args.write and out:
        with open(args.out, "w", encoding="utf-8") as fh:
            for r in out:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        with open(args.report, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(report[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(report)
        print(f"\n-> {args.out} ({len(out)//2} pairs)\n-> {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
