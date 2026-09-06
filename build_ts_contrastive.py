"""Build TypeScript contrastive pairs from the OSV/npm harvest.

Both sides are reconstructed from the SAME unified-diff hunk, so the vulnerable
and fixed excerpts are byte-identical apart from the fix itself. That is the
property the whole shape depends on -- if anything else differs, the model can
learn a shortcut instead of the guard.

Two things here are better than the morefixes-derived pairs:
  * CWE comes from the GHSA advisory, not guessed from guard vocabulary
    (`_GUARD_CWE`). One whole class of mislabelling disappears.
  * The trace names identifiers that actually occur in the code, instead of
    rotating one of ~15 family templates. 77% of the existing TS records share a
    top-20 boilerplate sentence; those teach the sentence, not the reasoning.

Every pair must pass ALL gates below or it is dropped -- never repaired:
  guard_in_fixed / guard_not_in_vuln  the fix must actually ADD the control
  sides_differ                        not a whitespace-only reformat
  identifiers_real                    every name in the trace occurs in the code
  size                                long enough to reason about, short enough
                                      that labels are not masked at train time

Usage:
    python build_ts_contrastive.py [--limit N] [--out PATH]
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import re
import subprocess
import sys

import ts_guard_gates as G
from build_contrastive import _CALL, _GUARD_CWE, _SINK_STOP, _norm
from harvest_osv_ts import find_local_clone

# String/template literals. A word inside one is not a value the
# model can use, so it must not satisfy an identifier search.
_STR_LIT = re.compile(
    r"'(?:\\.|[^'\\])*'"          # single-quoted
    r'|"(?:\\.|[^"\\])*"'         # double-quoted
    r"|`(?:\\.|[^`\\])*`"          # template literal
)

OUT_DEFAULT = "data/cot/staging/shape1_contrastive_ts_osv.jsonl"
CLEAN_TSV = "data/osv/ts_guard_enriched.tsv"   # CISA CWEs + provenance + fix_status

MIN_CODE_CHARS = 120
# Labels get masked (-> NaN instead of gradient) somewhere above ~6000 chars for
# the assembled record. 2600 was needlessly tight and cost 80 pairs; 4000 leaves
# comfortable headroom once the trace is added.
MAX_CODE_CHARS = 4500

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")


def parse_hunks(patch_text):
    """Yield (file_path, [raw hunk lines]) for every hunk in the patch."""
    cur_file, cur_hunk = None, None
    for line in patch_text.splitlines():
        if line.startswith("+++ b/"):
            cur_file = line[6:].strip()
            cur_hunk = None
            continue
        if _HUNK.match(line):
            if cur_file and cur_hunk:
                yield cur_file, cur_hunk
            cur_hunk = []
            continue
        if cur_hunk is not None:
            if line.startswith(("diff --git", "--- ", "index ")):
                if cur_file and cur_hunk:
                    yield cur_file, cur_hunk
                cur_hunk = None
                continue
            cur_hunk.append(line)
    if cur_file and cur_hunk:
        yield cur_file, cur_hunk


def file_at(repo_dir, rev, path):
    """File contents at a revision, or None. Read-only: never touches the tree."""
    try:
        out = subprocess.run(["git", "show", f"{rev}:{path}"], cwd=repo_dir,
                             capture_output=True, timeout=60)
        if out.returncode != 0:
            return None
        return out.stdout.decode("utf-8", errors="replace")
    except Exception:
        return None


# Declarations we accept as "the enclosing function". TS hides functions behind
# several spellings, and a method (`protected async foo(`) is the one the earlier
# heuristic missed entirely.
_DECL_AT = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:public\s+|private\s+|protected\s+|static\s+)*"
    r"(?:async\s+)?(?:function\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*"
    r"(?:<[^>]*>)?\s*\([^;]*$"
)
_ASSIGN_FN = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*"
    r"(?:async\s+)?(?:function\b|\()"
)


def enclosing_function(lines, idx):
    """(start, end, name) of the function containing line `idx`, by brace balance.

    Scanning upward for a declaration and then forward to balance is what makes
    the SAME semantic unit extractable from both revisions -- which is the whole
    point: the two excerpts must differ only by the fix.
    """
    for start in range(idx, -1, -1):
        line = lines[start]
        m = _ASSIGN_FN.match(line) or _DECL_AT.match(line)
        if not m:
            continue
        name = m.group("name")
        if name in _KEYWORDS or name in ("if", "for", "while", "switch", "catch", "return"):
            continue
        depth, seen_open, end = 0, False, None
        for j in range(start, min(len(lines), start + 400)):
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                seen_open = True
            if seen_open and depth <= 0:
                end = j
                break
        if end is None or end < idx:
            continue
        return start, end, name
    return None


def excerpt_for(text, needle):
    """The enclosing function containing `needle`, else a window around it."""
    lines = text.splitlines()
    idx = next((i for i, l in enumerate(lines) if needle in l), None)
    if idx is None:
        return None, None
    got = enclosing_function(lines, idx)
    if got:
        s, e, name = got
        return "\n".join(lines[s:e + 1]), name
    lo, hi = max(0, idx - 12), min(len(lines), idx + 13)
    return "\n".join(lines[lo:hi]), None


def changed_line_texts(hunks):
    """Added/removed line bodies across hunks -- used to locate changed regions."""
    out = []
    for h in hunks:
        for l in h:
            if l[:1] in "+-" and not l.startswith(("+++", "---")) and l[1:].strip():
                out.append(l[1:])
    return out


def regions_for_file(text, needles, budget_lines=60):
    """Enclosing functions in `text` that contain any of `needles`.

    Measured on the harvest: the median fix touches 5 files and 4 TypeScript
    files, while we were emitting ONE function from ONE file. A model shown only
    part of the fix cannot decide exploitability from the excerpt, so the only
    thing left for it to use is its topic prior -- which is precisely the failure
    we are trying to train out. So take every changed function, not just the
    guard's.
    """
    lines = text.splitlines()
    if not lines:
        return None
    spans = []
    for nd in needles:
        nd = nd.strip()
        if len(nd) < 8:
            continue
        idx = next((i for i, l in enumerate(lines) if nd in l), None)
        if idx is None:
            continue
        got = enclosing_function(lines, idx)
        if got:
            s, e, _ = got
        else:
            s, e = max(0, idx - 8), min(len(lines) - 1, idx + 8)
        if e - s > budget_lines:          # runaway function; clip around the hit
            s, e = max(s, idx - budget_lines // 2), min(e, idx + budget_lines // 2)
        spans.append((s, e))
    if not spans:
        return None
    # merge overlapping/adjacent spans so we never repeat lines
    spans.sort()
    merged = [list(spans[0])]
    for s, e in spans[1:]:
        if s <= merged[-1][1] + 3:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    parts = []
    for s, e in merged:
        parts.append("\n".join(lines[s:e + 1]))
    return "\n    // ...\n".join(parts)


def sides_from_hunk(hunk):
    """Reconstruct the before/after text of one hunk."""
    vuln, fixed = [], []
    for l in hunk:
        if not l:
            vuln.append("")
            fixed.append("")
            continue
        tag, body = l[0], l[1:]
        if tag == " ":
            vuln.append(body)
            fixed.append(body)
        elif tag == "-":
            vuln.append(body)
        elif tag == "+":
            fixed.append(body)
    return "\n".join(vuln).rstrip(), "\n".join(fixed).rstrip()


# Node built-ins are MODULES, not tainted values. Naming `path` as the
# attacker-controlled source (from `path.resolve(...)`) is simply false.
NODE_MODULES = {"path", "fs", "os", "url", "crypto", "http", "https", "net",
                "util", "stream", "buffer", "process", "child_process", "zlib",
                "dns", "tls", "querystring", "console", "JSON", "Math", "Object"}

_DECLARES = re.compile(
    r"(?:^|\n)\s*(?:export\s+)?(?:async\s+)?(?:function\s+|const\s+|let\s+|var\s+)(\w+)"
)


def declared_names(code):
    """Functions/consts DEFINED in this excerpt -- these enclose the code, so a
    parameter cannot 'flow into' them; they are not sinks."""
    return set(_DECLARES.findall(code))


def near_guard(text, needles, guard, window):
    """Needles within `window` lines of the guard, for tightening an excerpt.

    Returns them unchanged if the guard cannot be located, so a failure to find
    it can never silently narrow the excerpt to something unrepresentative.
    """
    lines = text.splitlines()
    anchor = next((i for i, l in enumerate(lines) if guard in l), None)
    if anchor is None:
        return needles
    keep = []
    for nd in needles:
        i = next((j for j, l in enumerate(lines) if nd.strip() and nd.strip() in l), None)
        if i is not None and abs(i - anchor) <= window:
            keep.append(nd)
    return keep


def extract_sides(by_file, chosen, clone, sha, guard, files="all", focus=None):
    """Both revisions of the changed regions, using ONE needle set for each side.

    The two sides must be cut identically or R3/R4 would be comparing excerpts
    that differ for reasons unrelated to the fix.
    """
    order = [chosen] if files == "one" else [chosen] + [p for p in by_file if p != chosen]
    v_parts, f_parts, used = [], [], 0
    for p2 in order:
        f_txt, v_txt = file_at(clone, sha, p2), file_at(clone, f"{sha}^", p2)
        if not (f_txt and v_txt):
            continue
        needles = changed_line_texts(by_file[p2])
        if focus is not None:
            needles = near_guard(f_txt, needles, guard, focus)
            if not needles:
                continue
        f_reg, v_reg = regions_for_file(f_txt, needles), regions_for_file(v_txt, needles)
        if not f_reg or not v_reg:
            continue
        # "budget" keeps as many files as FIT rather than falling all the way back
        # to one. A fix spans a median of 2 non-test source files, so dropping
        # straight to the guard's file throws away context the model needs to see
        # that the fix is not local. The guard's file is always kept.
        if files == "budget" and v_parts and used + len(f_reg) + len(v_reg) > MAX_CODE_CHARS:
            break
        hdr = "// " + p2
        v_parts.append(hdr + "\n" + v_reg)
        f_parts.append(hdr + "\n" + f_reg)
        used += len(f_reg) + len(v_reg)
    return v_parts, f_parts


# Widest first: keep all the context that fits, and only tighten when the excerpt
# would otherwise blow the size limit. Tightening the CUT is a quality gain;
# raising the LIMIT to admit a sprawling excerpt would not be.
FOCUS_LADDER = (("all", None), ("budget", None), ("all", 60), ("budget", 60),
                ("one", None), ("one", 40), ("one", 20))


def pick_sink(code, guard, near=None, window=25):
    """The salient call in the changed region -- what the tainted value reaches.

    Scoped to the source's own neighbourhood, and required to satisfy the same
    `_standalone` predicate R6 checks. Searching a whole excerpt picks the
    LONGEST name anywhere in it, which on a large file means the trace can pair a
    source with a call it never reaches; requiring groundedness here makes a sink
    ghost impossible by construction instead of a scanner catch. Returning None
    is correct when nothing near the source qualifies -- a distant sink would be
    a fabricated flow.
    """
    bare = _STR_LIT.sub("''", code)
    enclosing = declared_names(code)

    lines = bare.splitlines()
    if near:
        anchors = [i for i, l in enumerate(lines)
                   if re.search(r"(?<![\w.])" + re.escape(near) + r"(?![\w])", l)]
        if not anchors:
            return None
        keep = set()
        for a in anchors:
            keep.update(range(max(0, a - window), min(len(lines), a + window + 1)))
        scope = "\n".join(l if i in keep else "" for i, l in enumerate(lines))
    else:
        scope = bare

    best = None
    for m in _CALL.finditer(scope):
        name = m.group(1)
        base = name.split(".")[-1]
        if base.lower() in _SINK_STOP or name.lower() in _SINK_STOP:
            continue
        if len(base) < 3:
            continue
        if name in enclosing or base in enclosing:
            continue                       # the enclosing function, not a sink
        if name == near or not _standalone(name, code):
            continue
        if best is None or len(name) > len(best):
            best = name
    return best


_KEYWORDS = {"if", "return", "const", "let", "var", "await", "async", "true",
             "false", "null", "undefined", "typeof", "new", "throw", "function",
             "this", "else", "catch", "try", "for", "while", "case", "break",
             "import", "export", "class", "extends", "string", "number", "boolean"}


def _standalone(ident, code):
    """Identifier present as a real value, not inside a string or a longer name.

    Without stripping literals, `'__proto__'` satisfies a search for `__proto__`
    and `plivoReplayCache` satisfies one for `plivo` -- so the picker named things
    the model cannot see as values. Every R6 ghost in both languages came from
    this: the source was a word lifted out of a string or a camelCase name.
    """
    bare = _STR_LIT.sub("''", code)
    return re.search(r"(?<![\w.])" + re.escape(ident) + r"(?![\w])", bare) is not None


def pick_source(guard, vuln, fixed):
    """A variable the guard inspects that ALSO exists in the vulnerable code.

    The guard is ADDED by the fix, so identifiers it introduces need not exist
    on the vulnerable side. The pair only teaches anything if the value being
    constrained is present in BOTH -- otherwise the trace names something the
    vulnerable excerpt never mentions.
    """
    inner = guard
    m = re.search(r"\(([^)]*)\)", guard)
    if m:
        inner = m.group(1)
    # identifiers named by the guard, innermost first, that survive on both sides
    for ident in _IDENT.findall(inner):
        if ident in _KEYWORDS or len(ident) < 3 or ident in NODE_MODULES:
            continue
        if _standalone(ident, vuln) and _standalone(ident, fixed):
            return ident
    # fall back to any identifier the guard mentions anywhere, still requiring both
    for ident in _IDENT.findall(guard):
        if ident in _KEYWORDS or len(ident) < 3 or ident in NODE_MODULES:
            continue
        if _standalone(ident, vuln) and _standalone(ident, fixed):
            return ident
    return None


def build_trace(label, source, sink, guard, cwe):
    """A trace grounded in THIS code: every name below occurs in the excerpt."""
    if label == "vuln":
        return (
            "<think>\n"
            f"Hypothesis: `{source}` is attacker-influenced and reaches `{sink}` in this excerpt "
            f"without an intervening control - a possible {cwe}.\n"
            f"Trigger path: `{source}` flows into `{sink}` exactly as written; nothing on that path "
            f"constrains its value, so whatever the caller supplies arrives at the sink unchanged.\n"
            "Defensive check: I look for a validation, sanitisation or authorisation step between "
            f"`{source}` and `{sink}` and find none in this code.\n"
            f"Because the path is unguarded, an attacker who controls `{source}` decides what `{sink}` "
            f"operates on. Confirmed {cwe}.\n"
            "</think>\n"
            f"status: confirmed\ncwe: {cwe}\nseverity: HIGH\n"
            f"trace: {source} -> {sink}\n"
            f"fix: constrain `{source}` before it reaches `{sink}`"
        )
    return (
        "<think>\n"
        f"Hypothesis: `{source}` reaches `{sink}` here, which would be {cwe} if the value were "
        "unconstrained - check whether this version constrains it.\n"
        f"Trigger path: `{source}` still flows toward `{sink}`, the same path as the vulnerable version.\n"
        f"Defensive check: this version contains `{guard}`, which constrains `{source}` before it "
        f"reaches `{sink}`.\n"
        f"That control sits on the trigger path, so the value arriving at `{sink}` can no longer be "
        "chosen freely by an attacker; the hypothesis is refuted.\n"
        "</think>\n"
        "status: safe\ncwe: none\nseverity: none\n"
        f"trace: {source} -> {sink} is constrained by `{guard}`\n"
        "fix: none"
    )


def make_record(code, trace, cwe, label, pair_id, prov=None):
    return {
        "messages": [
            {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
            {"role": "assistant", "content": trace},
        ],
        "_meta": {
            "shape": "shape1", "source": "contrastive_ts_osv", "origin": "real",
            "language": "typescript", "label": label,
            "cwes": [cwe] if cwe else [], "ground_truth_cwe": cwe,
            "pair_id": pair_id, "contrastive": True, "synthetic": False,
            "cleaned": True,
            # provenance: the old TS records carried none, so they could never be
            # audited against NVD/CISA. Always keep the lineage.
            **(prov or {}),
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default=OUT_DEFAULT)
    a = ap.parse_args()

    rows = list(csv.DictReader(open(CLEAN_TSV, encoding="utf-8"), delimiter="\t"))
    if a.limit:
        rows = rows[: a.limit]
    print(f"clean guards: {len(rows)}", flush=True)

    funnel = collections.Counter()
    out = []
    seen_code = set()

    for r in rows:
        guard = r["guard"].strip()
        try:
            patch = open(r["patch"], encoding="utf-8", errors="replace").read()
        except OSError:
            funnel["patch_unreadable"] += 1
            continue

        # Group hunks by file so we can use the WHOLE changed region of the file
        # the guard lives in. A single hunk carries only 3 context lines, which
        # left many excerpts too small to reason about.
        by_file = collections.OrderedDict()
        for path, hunk in parse_hunks(patch):
            if G.is_ts_source(path):
                by_file.setdefault(path, []).append(hunk)

        chosen = None
        for path, hunks in by_file.items():
            if any(guard in l[1:] for h in hunks for l in h if l.startswith("+")):
                chosen = (path, hunks)
                break
        if not chosen:
            funnel["guard_hunk_not_found"] += 1
            continue
        path, hunks = chosen

        # PREFERRED: pull both revisions from a local clone and cut the changed
        # functions from EVERY TypeScript file the fix touched, guard's file
        # first. One function from one file was a fragment of a median-5-file fix.
        vuln = fixed = None
        owner, repo = r["repo"].split("/", 1) if "/" in r["repo"] else (None, None)
        stem = os.path.splitext(os.path.basename(r["patch"]))[0]
        sha = stem.rsplit("__", 1)[-1] if "__" in stem else None
        clone = find_local_clone(owner, repo) if (owner and sha) else None
        if clone:
            for files, focus in FOCUS_LADDER:
                v_parts, f_parts = extract_sides(by_file, path, clone, sha, guard,
                                                 files=files, focus=focus)
                if not v_parts:
                    continue
                if not (any(guard in x for x in f_parts)
                        and not any(guard in x for x in v_parts)):
                    continue
                v, fx = "\n\n".join(v_parts).rstrip(), "\n\n".join(f_parts).rstrip()
                if max(len(v), len(fx)) > MAX_CODE_CHARS:
                    continue          # too sprawling -- try a tighter cut
                vuln, fixed = v, fx
                funnel["excerpt_from_clone"] += 1
                funnel[f"files_in_excerpt_{min(len(v_parts),5)}"] += 1
                if focus is not None or files == "one":
                    funnel["excerpt_tightened"] += 1
                break

        if vuln is None:                      # FALLBACK: reconstruct from hunks
            v_parts, f_parts = [], []
            for p2, hunks2 in by_file.items():
                for h in hunks2:
                    v, f = sides_from_hunk(h)
                    if v.strip():
                        v_parts.append(v)
                    if f.strip():
                        f_parts.append(f)
            vuln, fixed = "\n".join(v_parts).rstrip(), "\n".join(f_parts).rstrip()
            funnel["excerpt_from_hunks"] += 1

        # --- correctness gates -------------------------------------------
        if guard not in fixed:
            funnel["guard_not_in_fixed"] += 1
            continue
        if guard in vuln:
            funnel["guard_already_in_vuln"] += 1      # fix did not ADD the control
            continue
        if _norm(vuln) == _norm(fixed):
            funnel["sides_identical"] += 1            # whitespace-only reformat
            continue
        if not (MIN_CODE_CHARS <= len(vuln) <= MAX_CODE_CHARS):
            funnel["vuln_size"] += 1
            continue
        if not (MIN_CODE_CHARS <= len(fixed) <= MAX_CODE_CHARS):
            funnel["fixed_size"] += 1
            continue

        source = pick_source(guard, vuln, fixed)
        if not source:
            funnel["no_source"] += 1
            continue
        # Anchored on the source: a sink it never reaches is not a flow.
        sink = pick_sink(vuln, guard, near=source)
        if not sink or sink == source:
            funnel["no_distinct_sink"] += 1
            continue
        # Every identifier the trace names must really occur in BOTH sides, as a
        # standalone token. A substring test is not enough: openclaw's fix renamed
        # `stat` to `rootLstat`, and `stat.isDirectory` is a substring of
        # `rootLstat.isDirectory`, so the naive check passed a sink the safe side
        # does not contain. Same class as the string-literal ghosts -- match the
        # predicate R6 actually applies, not a weaker one.
        if not (_standalone(source, vuln) and _standalone(source, fixed)):
            funnel["source_not_in_both"] += 1
            continue
        if not (_standalone(sink, vuln) and _standalone(sink, fixed)):
            funnel["sink_not_in_both"] += 1
            continue

        # cwe_final already prefers CISA vulnrichment, which names the MECHANISM
        # (CWE-59 symlink following) over the family (CWE-22 path traversal) and
        # resolves multi-CWE advisories authoritatively -- no more guessing which
        # of three listed CWEs applies.
        adv = [c for c in r.get("cwe_final", "").split("|") if c.startswith("CWE-")]
        cwe = adv[0] if adv else None
        if not cwe:
            funnel["no_advisory_cwe"] += 1
            continue

        key = _norm(vuln)
        if key in seen_code:
            funnel["dup_code"] += 1
            continue
        seen_code.add(key)

        pid = hashlib.sha1(f"{r['repo']}{r['n']}{guard}".encode()).hexdigest()[:12]
        prov = {"cve": r.get("cve", ""), "ghsa": r.get("ghsa", ""),
                "repo": r.get("repo", ""), "sha": r.get("sha", ""),
                "src_file": r.get("file", ""), "fix_status": r.get("fix_status", ""),
                "cwe_source": "cisa" if r.get("cwe_cisa") else "advisory"}
        out.append(make_record(vuln, build_trace("vuln", source, sink, guard, cwe), cwe, "vuln", pid, prov))
        out.append(make_record(fixed, build_trace("safe", source, sink, guard, cwe), cwe, "safe", pid, prov))
        funnel["PAIR_BUILT"] += 1

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        for rec in out:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print("\n=== funnel ===")
    for k, v in funnel.most_common():
        print(f"  {k:24s} {v}")
    print(f"\npairs: {funnel['PAIR_BUILT']}  records: {len(out)} -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
