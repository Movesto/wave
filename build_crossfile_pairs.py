"""Contrastive CROSS-FILE pairs derived from the CVE patch, not from CodeQL.

Attempt 1 (codeql_harvest_pairs.py) tried to find safe cross-file code by
diffing CodeQL findings between `{commit}^` and `{commit}` and keeping the flows
the fix removed. It yields ~nothing — 0 pairs from 118 flows — because CodeQL's
security queries do not detect the CVE being fixed. Its findings are incidental
flows scattered through the repo while the fix is a surgical one-liner somewhere
else, so the intersection is empty.

This builder uses the ground truth we already trust: the patch itself. A record
is cross-file by PRESENTATION, not by the patch spanning files. For a fix in
file F, the `<SCAN>` shows the CALLER file plus F, so the tainted value enters in
one file and reaches the sink in another:

    vuln  = caller + F at {commit}^   (guard absent)
    safe  = caller + F at {commit}    (guard present, quoted in the trace)

Both sides carry identical cross-file structure, so the only thing distinguishing
them is the guard — which is exactly the shortcut ("cross-file shape => vuln")
that the all-vuln shape3_codeql corpus taught the model.

Reads file content with `git show`, so it never touches the working tree and can
run against the 561 already-cloned repos while the GPU trains.

  python build_crossfile_pairs.py --lang python --limit 400
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path

from build_contrastive import _GUARD, _cwe_from_guard, _leak_hashes, _pick_guard
from cot.deep_trace import deep_safe_think, deep_vuln_think
from codeql_harvest_pairs import sink_symbol, source_symbol

REPOS = Path("tools/codeql_work/repos")
OUT = Path("data/cot/pilot/shape3_crossfile_pairs.jsonl")
EXTS = {"python": (".py",), "javascript": (".js", ".ts", ".jsx", ".tsx", ".vue")}
# Hunk headers carry the enclosing definition, e.g. "@@ -108,6 +108,7 @@ def foo("
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@\s*(.*)$")
_DEFNAME = re.compile(r"(?:def|function|func|class)\s+([A-Za-z_]\w+)|([A-Za-z_]\w+)\s*[:=]\s*(?:async\s*)?\(")
_TESTISH = re.compile(r"(^|/)(tests?|spec|__tests__|testing|examples?|docs?|vendor|node_modules)/", re.I)
# Minified/bundled JS: one line holds an entire module, so _pick_guard latches onto
# a namespace initialiser and calls it a security control. Caught in QA at 4/17 JS
# pairs (jsrsasign, drawio, sulu). Filter by path AND by line length, because plenty
# of bundles are not named *.min.js.
_MINIFIED_PATH = re.compile(r"(\.min\.|[-.]bundle\.|(^|/)(dist|build|static|assets)/)", re.I)
_MAX_GUARD_LEN = 200
# A guard whose code content is only a string literal is an error MESSAGE, not the
# check that produced it (QA: nightscout config text, tiny-csrf error template).
_STRINGS = re.compile(r"""(`[^`]*`|"[^"]*"|'[^']*')""")
# An import makes a control AVAILABLE; it is not the control. `import hmac` as the
# quoted guard is the reasoning-theater this corpus keeps having to purge, and the
# _GUARD vocabulary matches it happily, so it has to be excluded structurally.
# Also excludes docstring/doc-comment body lines: a `:param allow_url: Allow `s`
# to be a URL.` line matches the _GUARD vocabulary ("allow", "url") but documents
# a control rather than being one — caught in QA at 1/33 pairs.
_NOT_A_GUARD = re.compile(r"^\s*(import\s|from\s+\S+\s+import|@|\"|'|\]|\}|\)|#|//|\*|require\(|use\s"
                          r"|:param|:returns?|:rtype|:raises?|>>>|\.\.\s|Args:|Returns:|Raises:)")
# A name inside __all__, an export list or an import is a re-export, not a caller.
_NOT_A_CALL = re.compile(r"^\s*(from\s|import\s|export\s|__all__|\"|'|\]|\})")
REASONS: Counter = Counter()


def git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True, errors="replace")
    return r.stdout or ""


def changed_files(repo: Path, commit: str, exts: tuple) -> list[str]:
    out = git(repo, "diff", "--name-only", f"{commit}^", commit)
    return [f for f in out.splitlines()
            if f.strip() and f.endswith(exts) and not _TESTISH.search(f)]


def patch_facts(repo: Path, commit: str, path: str) -> list[dict]:
    """One entry per hunk: its new-side start line, the lines it added, and the
    enclosing symbol (git puts that in the hunk header, saving an AST parse).
    Per-hunk rather than per-file so the excerpt can be anchored on the hunk that
    actually contains the guard — anchoring on the first hunk lands on the import
    block and shows code that has nothing to do with the fix."""
    diff = git(repo, "diff", "--unified=0", f"{commit}^", commit, "--", path)
    hunks: list[dict] = []
    for line in diff.splitlines():
        m = _HUNK.match(line)
        if m:
            symbol = None
            if m.group(2):
                d = _DEFNAME.search(m.group(2))
                if d:
                    symbol = d.group(1) or d.group(2)
            hunks.append({"line": int(m.group(1)), "added": [], "symbol": symbol})
            continue
        if hunks and line.startswith("+") and not line.startswith("+++") and line[1:].strip():
            hunks[-1]["added"].append(line[1:])
    return hunks


# Enclosing-definition forms, scanning upward from the patched line. git's hunk
# header names the function for Python but usually not for JS/TS (that needs a
# configured diff driver), which killed 62 JS candidates on `no_enclosing_symbol`
# before this fallback existed.
_ENCLOSING = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?"
    r"(?:def|function|class|func)\s+([A-Za-z_]\w+)"                  # def/function/class NAME
    r"|^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_]\w+)\s*=\s*"  # const NAME = (…) =>
    r"(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_]\w*\s*=>)"
    r"|^\s*([A-Za-z_]\w+)\s*:\s*(?:async\s*)?function\b"             # NAME: function()
    r"|^\s*(?:async\s+)?([A-Za-z_]\w+)\s*\([^)]*\)\s*\{"             # method shorthand
)


def enclosing_symbol(lines: list[str], anchor: int | None) -> str | None:
    """Nearest enclosing definition at or above the patched line."""
    if not lines or not anchor:
        return None
    for i in range(min(anchor, len(lines)) - 1, -1, -1):
        m = _ENCLOSING.match(lines[i])
        if m:
            name = next((g for g in m.groups() if g), None)
            if name and name not in ("if", "for", "while", "switch", "catch", "return"):
                return name
    return None


def show(repo: Path, commit: str, path: str) -> list[str]:
    txt = git(repo, "show", f"{commit}:{path}")
    return txt.splitlines() if txt else []


def excerpt(lines: list[str], line: int | None, ctx: int = 6) -> str:
    if not lines:
        return ""
    centre = line or 1
    a, b = max(0, centre - 1 - ctx), min(len(lines), centre + ctx)
    return "\n".join(lines[a:b])


def find_caller(repo: Path, commit: str, symbol: str, exclude: str,
                exts: tuple) -> tuple[str, int] | None:
    """A file other than the patched one that references the patched symbol —
    this is what makes the presented flow genuinely cross-file."""
    out = git(repo, "grep", "-n", "--fixed-strings", symbol, commit, "--", *[f"*{e}" for e in exts])
    for row in out.splitlines()[:60]:
        # format: <commit>:<path>:<line>:<text>
        parts = row.split(":", 3)
        if len(parts) < 4:
            continue
        _, path, lineno, text = parts
        if path == exclude or _TESTISH.search(path) or not path.endswith(exts):
            continue
        if f"def {symbol}" in text or f"function {symbol}" in text or f"class {symbol}" in text:
            continue  # the definition, not a use
        if _NOT_A_CALL.match(text) or f"{symbol}(" not in text:
            continue  # must be an actual call site, not a re-export or mention
        try:
            return path, int(lineno)
        except ValueError:
            continue
    return None


def build_pair(repo: Path, owner_repo: str, commit: str, lang: str,
               path: str, exts: tuple) -> tuple[dict, dict] | None:
    hunks = patch_facts(repo, commit, path)
    if not hunks:
        REASONS["no_added_lines"] += 1
        return None

    # Pick the guard and keep the hunk it came from, so the excerpt shows the fix.
    if _MINIFIED_PATH.search(path):
        REASONS["minified_or_bundled_file"] += 1
        return None

    guard = anchor = symbol = None
    for h in hunks:
        real = [l for l in h["added"]
                if not _NOT_A_GUARD.match(l) and len(l) <= _MAX_GUARD_LEN]
        g = _pick_guard(real)
        if g and _GUARD.search(g):
            # Strip string literals: what remains must still contain a call or a
            # comparison, otherwise the "guard" is just an error message.
            bare = _STRINGS.sub("", g)
            if not re.search(r"[A-Za-z_]\w*\s*\(|[=!<>]=|\binstanceof\b|\bin\b", bare):
                REASONS["guard_is_string_literal"] += 1
                continue
            guard, anchor, symbol = g, h["line"], h["symbol"]
            break
    if not guard:
        REASONS["no_quotable_guard"] += 1
        return None
    cwe = _cwe_from_guard(guard, [l for h in hunks for l in h["added"]])
    if not cwe:
        REASONS["no_cwe_from_guard"] += 1
        return None
    vuln_lines = show(repo, f"{commit}^", path)
    fixed_lines = show(repo, commit, path)
    if not vuln_lines or not fixed_lines:
        REASONS["unreadable_blob"] += 1
        return None

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

    # Size gate. A fixed line-count window still explodes on files with very long
    # lines (bundled sources the path filter misses — mozilla/nunjucks produced a
    # 24,703-char record). Over ~6000 chars the record exceeds max_len at train
    # time, ALL its labels get masked, and it contributes a NaN loss instead of
    # gradient — the defect harden_corpus.py exists to remove.
    if max(len(caller_block) + len(vuln_block), len(caller_block) + len(fixed_block)) > 5000:
        REASONS["record_too_long"] += 1
        return None
    if guard not in fixed_block:
        REASONS["guard_outside_excerpt"] += 1
        return None
    if guard in vuln_block:
        REASONS["guard_already_in_vuln"] += 1   # same defect build_contrastive hit
        return None

    sink = sink_symbol(guard) or symbol
    caller_text = caller_lines[caller_line - 1] if caller_line <= len(caller_lines) else ""
    # The tainted value is what the caller passes in, so look inside the call's
    # arguments — not at the function name, which would make source == sink and
    # produce the nonsense "`X` reaches `X` unchanged".
    args = re.search(re.escape(symbol) + r"\s*\(([^)]*)\)", caller_text)
    source = source_symbol(args.group(1) if args else "", "")
    if not source or source == sink or source == symbol:
        REASONS["degenerate_source_sink"] += 1
        return None
    flow = f"{os.path.basename(caller_path)}:{caller_line} -> {os.path.basename(path)}:{anchor}"
    pair_id = hashlib.sha1(f"{owner_repo}{commit}{path}".encode()).hexdigest()[:16]

    vuln_fields = (f"status: confirmed\ncwe: {cwe}\nseverity: HIGH\nline: {anchor}\n"
                   f"trace: {flow}\nfix: Neutralize `{source}` in `{symbol}` before it is used.")
    safe_fields = ("status: safe\ncwe: none\nseverity: none\nline: none\n"
                   f"trace: the {flow} flow is guarded by `{guard.strip()}`\nfix: none")

    def rec(blocks, think, fields, label):
        return {"messages": [{"role": "user", "content": "<SCAN>\n" + "\n\n".join(blocks) + "\n</SCAN>"},
                             {"role": "assistant", "content": think + "\n" + fields}],
                "_meta": {"shape": "shape3", "source": "crossfile_pair", "language": lang,
                          "label": label, "cwes": [cwe] if label == "vuln" else [],
                          "ground_truth_cwe": cwe, "multi_hop": True, "cross_file": True,
                          "pair_id": pair_id, "repo": owner_repo, "commit": commit}}

    REASONS["PAIR_KEPT"] += 1
    return (rec([caller_block, vuln_block], deep_vuln_think(source, sink, anchor, cwe),
                vuln_fields, "vuln"),
            rec([caller_block, fixed_block], deep_safe_think(source, sink, guard.strip(), cwe),
                safe_fields, "safe"))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", default="codeql_targets.tsv")
    ap.add_argument("--lang", default="python")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--max-per-repo", type=int, default=3)
    ap.add_argument("--max-files-per-commit", type=int, default=2)
    args = ap.parse_args()

    exts = EXTS[args.lang]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    leak = _leak_hashes()
    print(f"eval-leak guard: {len(leak)} hashes")

    seen: set = set()
    if OUT.exists():
        with open(OUT, encoding="utf-8") as f:
            for line in f:
                try:
                    seen.add(hashlib.sha256(
                        json.loads(line)["messages"][0]["content"].encode()).hexdigest())
                except Exception:
                    continue
        print(f"resuming: {len(seen)} records present")

    # Tolerates the 4-column codeql_targets.tsv and the 3-column guard-prefiltered
    # candidate list. Strips \r — these files are written on Windows.
    rows = [l.rstrip("\r\n").split("\t") for l in open(args.targets, encoding="utf-8")]
    rows = [r[:3] for r in rows if len(r) >= 3 and r[1] == args.lang]

    per_repo: Counter = Counter()
    pairs = scanned = 0
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
                files = changed_files(repo, commit, exts)[:args.max_files_per_commit]
                for path in files:
                    pair = build_pair(repo, owner_repo, commit, lang, path, exts)
                    if not pair:
                        continue
                    hashes = [hashlib.sha256(r["messages"][0]["content"].encode()).hexdigest()
                              for r in pair]
                    if any(h in seen or h in leak for h in hashes):
                        REASONS["duplicate_or_eval_leak"] += 1
                        REASONS["PAIR_KEPT"] -= 1
                        continue
                    seen.update(hashes)
                    for r in pair:
                        out_f.write(json.dumps(r, ensure_ascii=False) + "\n")
                    out_f.flush()
                    pairs += 1
            except Exception as e:
                REASONS[f"error:{type(e).__name__}"] += 1
            if scanned % 25 == 0:
                print(f"  [{scanned}/{args.limit}] {pairs} pairs", flush=True)

    print(f"\nDONE: {pairs} cross-file pairs ({pairs*2} records) from {scanned} commits -> {OUT}")
    print("\nfunnel:")
    for reason, count in REASONS.most_common():
        print(f"  {reason:30} {count}")


if __name__ == "__main__":
    main()
