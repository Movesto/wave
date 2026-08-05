"""Generate `needs_context` traces — teaching the model to ASK instead of GUESS.

WHY THIS IS THE LEVER FOR COMPLEX VULNERABILITIES
The v11 guided-prompt experiment produced the sharpest failure in this project: of 32
missed vulnerabilities, **32 confabulated a guard** — "it's parameterized", "validation
present" — on code that had none. Asked to check for a control it could not see, the model
invented one. It has no representation of "I cannot tell from here."

That is precisely what a complex vulnerability requires. Real flaws span files: the sink is
here, the control is somewhere else. A model that guesses when the decisive code is out of
view cannot reason about them — it can only pattern-match the fragment in front of it.

`shape2` (needs_context) is the shape that teaches this, and the corpus has **80 records,
0.16%**. It is the single most under-invested capability relative to the stated goal.

CONSTRUCTION (grounded, not speculative)
For a CVE fix that modified function `F` in file A:
  * the security-decisive logic is IN `F` — that is a fact, the patch proves it;
  * find a caller in file B that passes a value into `F`;
  * show ONLY file B.
The correct verdict is then necessarily `needs_context`, naming `F` as the thing to fetch.
No judgement call is being invented: the record is correct *because* the patch touched the
callee, and the caller is checked to contain no guard of its own.

  python build_needs_context.py --lang python --limit 600
"""
import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from build_contrastive import _GUARD, _leak_hashes
from build_crossfile_pairs import (EXTS, REPOS, _TESTISH, changed_files, excerpt,
                                   find_caller, git, patch_facts, show)
from cot.deep_trace import FAMILY_DEPTH, family_of
from cot.vuln_types import classify

OUT = Path("data/cot/pilot/shape2_needs_context.jsonl")
REASONS: Counter = Counter()
_ARGS = re.compile(r"\(([^)]*)\)")
_TRIVIAL = {"self", "this", "true", "false", "none", "null", "0", "1", "", "cls"}

# The caller must plausibly carry UNTRUSTED data. Without this the builder emits
# "needs_context" for any cross-file call — teaching the model to stall on ordinary
# internal plumbing, which would make indecision worse rather than better. A record is
# only honest if the value's origin is genuinely a security question.
# Deliberately STRICT. A looser version matched `.get(` in `app.router.add_get('/')`
# and accepted a locally generated crypto key as "untrusted" — the generic tokens
# (`url`, `client`, `read(`, `.get(`) fire constantly on ordinary code.
_SOURCE = re.compile(
    r"\b(request\.|req\.|\.args\b|\.form\b|\.cookies\b|\.headers\b|request\.get_json"
    r"|input\(|sys\.argv|os\.environ|getenv|user_?input|user_?data|request\.data"
    r"|\.POST\b|\.GET\b|params\[|query_?string|path_?info|form_?data"
    r"|readline\(|recv\(|request\.files|upload(ed)?_?file)", re.I)
# Documentation is not code. A call site inside a docstring or doctest is an example,
# not a data flow (caught: an ansible-runner `:Example:` block with `>>>` lines).
_DOCISH = re.compile(r">>>|:param|:Example:|:returns?:|^\s*\.\.\s|\"\"\"|'''", re.M)
# Mojibake / wrong-decoding guard: a block full of replacement characters is garbage
# input regardless of what it says (hit on a Chinese-commented file read as cp1252).
_BAD_CHARS = re.compile(r"[�﻿]")


def _pick(seed: str, options: list[str]) -> str:
    return options[int(hashlib.md5(seed.encode()).hexdigest(), 16) % len(options)]


def call_argument(caller_line: str, symbol: str) -> str | None:
    """The value handed to the callee — the thing whose fate is undecidable from here."""
    m = re.search(re.escape(symbol) + r"\s*" + _ARGS.pattern, caller_line)
    if not m:
        return None
    for arg in m.group(1).split(","):
        arg = arg.strip()
        base = arg.split("=")[-1].strip()
        if base.lower() not in _TRIVIAL and not base.startswith(('"', "'")) and len(base) > 1:
            return base
    return None


def build_think(arg: str, symbol: str, callee_file: str, cwe: str | None) -> str:
    """Reasoning that stops at the boundary of what the file can support.

    The shape of this trace is the lesson: follow the value, reach the call, then state
    plainly that the verdict lives elsewhere and name it — rather than inventing an
    outcome for code that is not shown.
    """
    fam = family_of(cwe) if cwe else None
    d = FAMILY_DEPTH.get(fam) if fam else None

    obs = _pick(arg + symbol, [
        f"`{arg}` is not constrained in this file before it is handed to `{symbol}`.",
        f"This file passes `{arg}` straight into `{symbol}` without acting on it first."])
    flow = f"Trigger path: `{arg}` flows into `{symbol}()`, which is defined in `{callee_file}`."

    if d:
        risk = (f"If `{symbol}` {d['mech'].rstrip('.')}, this is exploitable "
                f"({cwe}) — an attacker could {d['attack']}.")
        safe_if = f"If instead it {d['guard_why']}, the flow is already contained."
    else:
        risk = f"If `{symbol}` uses `{arg}` in a sensitive operation without checking it, this is exploitable."
        safe_if = f"If `{symbol}` validates or neutralizes `{arg}` first, the flow is contained."

    check = ("Defensive check: no validation, sanitization, or authorization is applied to "
             f"`{arg}` anywhere in this file — but the decisive control would live inside "
             f"`{symbol}`, which is not shown.")
    close = _pick(symbol + "close", [
        f"Both outcomes are consistent with what is visible here, so I cannot decide. "
        f"I need the body of `{symbol}`.",
        f"Nothing in this file distinguishes the two cases. The verdict depends on "
        f"`{symbol}`'s implementation."])
    return (f"<think>\n{obs}\n{flow}\n{check}\n{risk} {safe_if}\n{close}\n</think>")


def build_record(repo: Path, owner_repo: str, commit: str, lang: str,
                 path: str, exts: tuple) -> dict | None:
    hunks = patch_facts(repo, commit, path)
    if not hunks:
        REASONS["no_added_lines"] += 1
        return None
    symbol = anchor = None
    for h in hunks:
        if h["symbol"]:
            symbol, anchor = h["symbol"], h["line"]
            break
    if not symbol:
        REASONS["no_patched_symbol"] += 1
        return None

    caller = find_caller(repo, commit, symbol, path, exts)
    if not caller:
        REASONS["no_cross_file_caller"] += 1
        return None
    caller_path, caller_line = caller
    caller_lines = show(repo, commit, caller_path)
    if not caller_lines or caller_line > len(caller_lines):
        REASONS["unreadable_caller"] += 1
        return None

    arg = call_argument(caller_lines[caller_line - 1], symbol)
    if not arg:
        REASONS["no_argument_passed"] += 1
        return None

    block = excerpt(caller_lines, caller_line, ctx=8)
    if len(block) > 4000:
        REASONS["caller_block_too_long"] += 1
        return None
    # If the caller itself guards the value, the answer is decidable here and the
    # record would be teaching the model to stall on code it could have judged.
    if _GUARD.search(block):
        REASONS["caller_already_guards"] += 1
        return None
    if symbol not in block:
        REASONS["call_site_outside_excerpt"] += 1
        return None
    if _BAD_CHARS.search(block):
        REASONS["mojibake_or_bad_encoding"] += 1
        return None
    if _DOCISH.search(block):
        REASONS["docstring_or_doctest_context"] += 1
        return None
    # The SOURCE must reach the ARGUMENT, not merely appear somewhere in the block.
    # Either the call line itself carries it, or a nearby line assigns it to `arg`.
    base = arg.split(".")[0].split("[")[0].strip()
    assign = re.compile(rf"^\s*{re.escape(base)}\s*(?::[^=]+)?=\s*(.+)$", re.M)
    origin = " ".join(assign.findall(block))
    if not (_SOURCE.search(caller_lines[caller_line - 1]) or _SOURCE.search(origin)):
        REASONS["argument_not_traceable_to_source"] += 1
        return None
    # Non-ASCII-heavy blocks are usually non-English source that decoded poorly.
    if sum(ord(c) > 127 for c in block) > len(block) * 0.05:
        REASONS["non_ascii_heavy"] += 1
        return None

    cwe = classify(" ".join(l for h in hunks for l in h["added"])) or None
    if isinstance(cwe, (list, tuple)):
        cwe = cwe[0] if cwe else None

    user = f"<SCAN>\n# {caller_path} (line {caller_line})\n{block}\n</SCAN>"
    fields = (f"status: needs_context\n"
              f"open_refs:\n  - {symbol} ({path})\n"
              f"partial_trace: `{arg}` flows into {symbol}() in {path} — "
              f"verdict depends on {symbol}'s implementation")
    REASONS["KEPT"] += 1
    return {"messages": [{"role": "user", "content": user},
                         {"role": "assistant", "content": build_think(arg, symbol, path, cwe)
                          + "\n" + fields}],
            "_meta": {"shape": "shape2", "source": "needs_context_mined", "language": lang,
                      "label": "needs_context", "cwes": [], "ground_truth_cwe": None,
                      "open_refs": [f"{symbol} ({path})"], "repo": owner_repo,
                      "commit": commit, "multi_hop": True}}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", default="codeql_targets.tsv")
    ap.add_argument("--lang", default="python")
    ap.add_argument("--limit", type=int, default=400)
    ap.add_argument("--max-per-repo", type=int, default=3)
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
    rows = [r for r in rows if len(r) >= 3 and r[1] == args.lang]

    per_repo: Counter = Counter()
    made = scanned = 0
    with open(OUT, "a", encoding="utf-8") as out_f:
        for row in rows:
            owner_repo, lang, commit = row[0], row[1], row[2]
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
                for path in changed_files(repo, commit, exts)[:2]:
                    rec = build_record(repo, owner_repo, commit, lang, path, exts)
                    if not rec:
                        continue
                    h = hashlib.sha256(rec["messages"][0]["content"].encode()).hexdigest()
                    if h in seen or h in leak:
                        REASONS["duplicate_or_leak"] += 1
                        REASONS["KEPT"] -= 1
                        continue
                    seen.add(h)
                    out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    out_f.flush()
                    made += 1
            except Exception as e:
                REASONS[f"error:{type(e).__name__}"] += 1
            if scanned % 50 == 0:
                print(f"  [{scanned}/{args.limit}] {made} records", flush=True)

    print(f"\nDONE: {made} needs_context records from {scanned} commits -> {OUT}")
    print("\nfunnel:")
    for reason, count in REASONS.most_common():
        print(f"  {reason:28} {count}")


if __name__ == "__main__":
    main()
