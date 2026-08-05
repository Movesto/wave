"""Build JavaScript contrastive pairs. Follows docs/TS_DATA_STANDARD.md.

Reuses the TS builder's machinery -- hunk parsing, `git show` revision reads,
brace-balanced region extraction, the correctness gates -- and replaces only what
is language-specific: which files count as JS source, and how a function is
declared.

JS declaration forms the TS regexes do not cover:
    module.exports.foo = function (a, b) {
    exports.foo = async (a) => {
    Foo.prototype.bar = function () {
    foo: function (a) {            <- object-literal method
    var foo = function () {

Correctness gates are unchanged from TS, because they encode the STANDARD rather
than the language:
    guard must be in the fixed side and ABSENT from the vulnerable side
    sides must differ after normalisation
    named source/sink must occur in BOTH sides
    size within the label-masking limit

    python build_js_contrastive.py
"""
import collections
import csv
import hashlib
import json
import os
import re
import sys

import js_guard_gates as JG
from build_contrastive import _CALL, _SINK_STOP, _norm
from build_ts_contrastive import (
    MAX_CODE_CHARS,
    MIN_CODE_CHARS,
    changed_line_texts,
    file_at,
    parse_hunks,
    sides_from_hunk,
)
from harvest_osv_ts import find_local_clone

# String/template literals. A word inside one is not a value the
# model can use, so it must not satisfy an identifier search.
_STR_LIT = re.compile(
    r"'(?:\\.|[^'\\])*'"          # single-quoted
    r'|"(?:\\.|[^"\\])*"'         # double-quoted
    r"|`(?:\\.|[^`\\])*`"          # template literal
)

CLEAN = "data/osv/js_guard_enriched.tsv"
OUT = "data/cot/staging/shape1_contrastive_js_osv.jsonl"

# JS function/method declaration forms, including the CommonJS and prototype
# assignment styles that have no TypeScript equivalent.
_JS_DECL = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(?P<name>[\w$]*)\s*\("
    r"|^\s*(?:module\.)?exports\.(?P<name2>[\w$]+)\s*=\s*(?:async\s+)?(?:function|\()"
    r"|^\s*(?:var|let|const)\s+(?P<name3>[\w$]+)\s*=\s*(?:async\s+)?(?:function\b|\()"
    r"|^\s*(?P<name4>[\w$]+)\.prototype\.(?P<name5>[\w$]+)\s*=\s*(?:async\s+)?function"
    r"|^\s*(?P<name6>[\w$]+)\s*:\s*(?:async\s+)?function\s*\("
    r"|^\s*(?:static\s+)?(?:async\s+)?(?P<name7>[\w$]+)\s*\([^;{]*\)\s*\{\s*$"
)
_NOT_A_NAME = {"if", "for", "while", "switch", "catch", "return", "do", "else",
               "with", "typeof", "new", "await", "throw", "case", "function"}
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_KEYWORDS = {"if", "return", "const", "let", "var", "await", "async", "true", "false",
             "null", "undefined", "typeof", "new", "throw", "function", "this", "else",
             "catch", "try", "for", "while", "case", "break", "require", "module",
             "exports", "class", "extends"}


def js_enclosing(lines, idx):
    """(start, end, name) of the JS function containing `idx`, by brace balance."""
    for start in range(idx, -1, -1):
        m = _JS_DECL.match(lines[start])
        if not m:
            continue
        name = next((g for g in m.groups() if g), "") or ""
        if name in _NOT_A_NAME:
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


def js_regions(text, needles, budget=60):
    """Changed functions in `text`, merged so no line repeats."""
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
        got = js_enclosing(lines, idx)
        if got:
            s, e, _ = got
        else:
            s, e = max(0, idx - 8), min(len(lines) - 1, idx + 8)
        if e - s > budget:
            s, e = max(s, idx - budget // 2), min(e, idx + budget // 2)
        spans.append((s, e))
    if not spans:
        return None
    spans.sort()
    merged = [list(spans[0])]
    for s, e in spans[1:]:
        if s <= merged[-1][1] + 3:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    return "\n    // ...\n".join("\n".join(lines[s:e + 1]) for s, e in merged)


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
        ft, vt = file_at(clone, sha, p2), file_at(clone, f"{sha}^", p2)
        if not (ft and vt):
            continue
        needles = changed_line_texts(by_file[p2])
        if focus is not None:
            needles = near_guard(ft, needles, guard, focus)
            if not needles:
                continue
        fr, vr = js_regions(ft, needles), js_regions(vt, needles)
        if not fr or not vr:
            continue
        # "budget" keeps as many files as FIT rather than falling all the way back
        # to one, so a multi-file fix does not get presented as a local one.
        # The guard's file is always kept.
        if files == "budget" and v_parts and used + len(fr) + len(vr) > MAX_CODE_CHARS:
            break
        v_parts.append("// " + p2 + "\n" + vr)
        f_parts.append("// " + p2 + "\n" + fr)
        used += len(fr) + len(vr)
    return v_parts, f_parts


# Widest first: keep all the context that fits, and only tighten when the excerpt
# would otherwise blow the size limit. Tightening the CUT is a quality gain;
# raising the LIMIT to admit a sprawling excerpt would not be.
FOCUS_LADDER = (("all", None), ("budget", None), ("all", 60), ("budget", 60),
                ("one", None), ("one", 40), ("one", 20))


def pick_sink(code, near=None, window=25):
    """The dangerous call the source reaches, taken from the source's OWN region.

    Two rules, both learned from bad traces:

    * Locality. Searching the whole excerpt let MeshCentral's trace claim a 2FA
      config `split` was constrained by an origin check -- two unrelated parts of
      a 9,000-char file. A source and a sink that never meet are not a flow, so
      when `near` is given the sink must sit within `window` lines of it. If
      nothing qualifies we return None: no sink is honest, a distant one is not.
    * Groundedness. The name must satisfy the same `_standalone` predicate R6
      checks, so a sink ghost becomes impossible by construction rather than
      something the scanner catches afterwards. This also drops mid-chain
      fragments -- `obj.config.domains[i].passwordrequirements.skip2factor.split`
      matches from the middle, and that fragment is not what the code says.
    """
    bare = _STR_LIT.sub("''", code)
    declared = set(m.group(1) for m in re.finditer(
        r"(?:function\s+|const\s+|let\s+|var\s+|exports\.)([\w$]+)", bare))

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
        if base.lower() in _SINK_STOP or name.lower() in _SINK_STOP or len(base) < 3:
            continue
        if name in declared or base in declared:
            continue
        if name == near or not _standalone(name, code):
            continue
        if best is None or len(name) > len(best):
            best = name
    return best


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
    inner = guard
    m = re.search(r"\(([^)]*)\)", guard)
    if m:
        inner = m.group(1)
    for pool in (inner, guard):
        for ident in _IDENT.findall(pool):
            if ident in _KEYWORDS or len(ident) < 3:
                continue
            if _standalone(ident, vuln) and _standalone(ident, fixed):
                return ident
    return None


def trace_vuln(src, snk, cwe):
    return ("<think>\n"
            f"Hypothesis: `{src}` is influenced by the caller and reaches `{snk}` - a possible {cwe}.\n"
            f"Trigger path: `{src}` flows into `{snk}` as written, and nothing on that path "
            "restricts what the value can be.\n"
            f"Defensive check: I look along the path from `{src}` to `{snk}` for a control that "
            "constrains it, and there is none.\n"
            f"The mechanism is intact and the value is attacker-chosen, so this is exploitable. "
            f"Confirmed {cwe}.\n"
            "</think>\n"
            f"status: confirmed\ncwe: {cwe}\nseverity: HIGH\n"
            f"trace: {src} -> {snk}\n"
            f"fix: constrain `{src}` before it reaches `{snk}`")


def trace_safe(src, snk, cwe, guard):
    return ("<think>\n"
            f"Hypothesis: `{src}` reaches `{snk}`, which is the shape of {cwe} - check whether the "
            "mechanism is present.\n"
            f"Trigger path: the call structure is the dangerous one, so shape alone does not settle "
            "it.\n"
            f"Defensive check: this version applies `{guard}`, which constrains `{src}` before it "
            f"reaches `{snk}`.\n"
            f"Because that control sits on the path, the value arriving at `{snk}` can no longer be "
            f"chosen freely, so the hypothesis is refuted.\n"
            "</think>\n"
            "status: safe\ncwe: none\nseverity: none\n"
            f"trace: {src} -> {snk} is constrained by `{guard}`\n"
            "fix: none")


def rec(code, trace, cwe, label, pid, r):
    return {
        "messages": [
            {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
            {"role": "assistant", "content": trace},
        ],
        "_meta": {
            "shape": "shape1", "source": "contrastive_js_osv", "origin": "real",
            "language": "javascript", "label": label,
            "cwes": [cwe] if label == "vuln" else [], "ground_truth_cwe": cwe,
            "pair_id": pid, "contrastive": True, "synthetic": False, "cleaned": True,
            "cve": r.get("cve", ""), "ghsa": r.get("ghsa", ""), "repo": r.get("repo", ""),
            "sha": r.get("sha", ""), "src_file": r.get("file", ""),
            "fix_status": r.get("fix_status", ""), "cwe_source": r.get("cwe_status", ""),
            "cwe_all": r.get("cwe_all", ""),
        },
    }


def main():
    rows = list(csv.DictReader(open(CLEAN, encoding="utf-8"), delimiter="\t"))
    print(f"enriched guards: {len(rows)}", flush=True)
    f, out, seen = collections.Counter(), [], set()

    for r in rows:
        guard = r["guard"].strip()
        try:
            patch = open(r["patch"], encoding="utf-8", errors="replace").read()
        except OSError:
            f["patch_unreadable"] += 1
            continue

        by_file = collections.OrderedDict()
        for path, hunk in parse_hunks(patch):
            if JG.is_js_source(path):
                by_file.setdefault(path, []).append(hunk)
        chosen = next((p for p, hs in by_file.items()
                       if any(guard in l[1:] for h in hs for l in h if l.startswith("+"))), None)
        if not chosen:
            f["guard_hunk_not_found"] += 1
            continue

        vuln = fixed = None
        owner, repo = r["repo"].split("/", 1) if "/" in r["repo"] else (None, None)
        clone = find_local_clone(owner, repo) if owner else None
        sha = r.get("sha", "")
        if clone and sha:
            for files, focus in FOCUS_LADDER:
                v_parts, f_parts = extract_sides(by_file, chosen, clone, sha, guard,
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
                f["excerpt_from_clone"] += 1
                if focus is not None or files == "one":
                    f["excerpt_tightened"] += 1
                break

        if vuln is None:
            v_parts, f_parts = [], []
            for p2, hunks in by_file.items():
                for h in hunks:
                    v, fx = sides_from_hunk(h)
                    if v.strip():
                        v_parts.append(v)
                    if fx.strip():
                        f_parts.append(fx)
            vuln, fixed = "\n".join(v_parts).rstrip(), "\n".join(f_parts).rstrip()
            f["excerpt_from_hunks"] += 1

        # --- correctness gates (identical to TS: they encode the standard) ---
        if guard not in fixed:
            f["guard_not_in_fixed"] += 1
            continue
        if guard in vuln:
            f["guard_already_in_vuln"] += 1
            continue
        if _norm(vuln) == _norm(fixed):
            f["sides_identical"] += 1
            continue
        if not (MIN_CODE_CHARS <= len(vuln) <= MAX_CODE_CHARS):
            f["vuln_size"] += 1
            continue
        if not (MIN_CODE_CHARS <= len(fixed) <= MAX_CODE_CHARS):
            f["fixed_size"] += 1
            continue

        src = pick_source(guard, vuln, fixed)
        if not src:
            f["no_source"] += 1
            continue
        # Anchored on the source: a sink it never reaches is not a flow.
        snk = pick_sink(vuln, near=src)
        if not snk or snk == src:
            f["no_distinct_sink"] += 1
            continue
        if not (_standalone(src, vuln) and _standalone(src, fixed)):
            f["source_not_in_both"] += 1
            continue
        if not (_standalone(snk, vuln) and _standalone(snk, fixed)):
            f["sink_not_in_both"] += 1
            continue

        cwe = r.get("cwe_final") or ""
        if not cwe:
            f["no_cwe"] += 1
            continue
        key = _norm(vuln)
        if key in seen:
            f["dup_code"] += 1
            continue
        seen.add(key)

        pid = hashlib.sha1(f"{r['repo']}{r['n']}{guard}".encode()).hexdigest()[:12]
        out.append(rec(vuln, trace_vuln(src, snk, cwe), cwe, "vuln", pid, r))
        out.append(rec(fixed, trace_safe(src, snk, cwe, guard), cwe, "safe", pid, r))
        f["PAIR_BUILT"] += 1

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        for x in out:
            fh.write(json.dumps(x, ensure_ascii=False) + "\n")

    print("\n=== funnel ===")
    for k, v in f.most_common():
        print(f"  {k:24s} {v}")
    print(f"\npairs: {f['PAIR_BUILT']}  records: {len(out)} -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
