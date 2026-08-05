"""The car wash — the full multi-stage scanner.

  Station 1  flag.py taint engine  -> source->sink candidates   (CPU, fast, precise)
  Station 2  8B model triage        -> "is this real?" + reason  (GPU, only on candidates)
  Station 3  8B model fix           -> remediation

The model NEVER scans the whole repo — only the handful of flagged functions. A
finding is HIGH-CONFIDENCE when BOTH the taint engine and the model agree; when the
taint engine flags but the model thinks it's handled, it's surfaced for REVIEW
(the two-signal gate that kills the false positives the model alone produced).

  python pipeline.py app.py
  python pipeline.py backend/ --json
"""
import ast, re, argparse, json, sys, os
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # cot/ + eval/ at root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))                    # sibling flag.py
from flag import gather, scan_file, EXT_LANG      # Station 1 (reused)
from patches import suggest, format_patch         # Station 3

_JS_FN_START = re.compile(
    r"function\s+[\w$]+\s*\(|(?:const|let|var)\s+[\w$]+\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|"
    r"[\w$]+\s*\([^)]*\)\s*\{|(?:async\s+)?[\w$]+\s*=\s*(?:async\s*)?function")




# ---- Station 2b: localise and validate what the model claimed ---------------
# The model cites a guard as TEXT and never a location -- it has never seen a line
# number in training input or output, so it cannot produce one. But the scanner has
# the file, so the line is a string search, not a thing the model must recite.
#
# The same pass applies R18 at runtime: a claimed guard must BE a control. Measured
# on the training corpus, 21% of guard claims were not (SQL string-building, HTML
# building, a docstring line), and the model reproduced that on real code -- on
# Manga_Ryu it cited `const raw = new URL(request.url).searchParams.get("next")`,
# the assignment, instead of the `startsWith` check on the next line.
#
# A runtime filter cannot invent reasoning the model lacks. It can refuse to present
# a claim that is checkably wrong, and point at the real control instead.
from scan_ts_standard import guard_claim, guard_is_a_control, _GUARD_COND, _GUARD_SANI


def _is_control_line(line: str) -> bool:
    return bool(_GUARD_COND.search(line) or _GUARD_SANI.search(line))


def localise_guard(file_path: str, trace: str, fn_line: int):
    """(guard_text, guard_line, verdict) for the guard a trace claims.

    verdict is one of:
      'located'    -- the claim is a control and we found its line
      'relocated'  -- the claim was NOT a control; we report the nearest real one
      'unlocated'  -- the claimed text is not in the file
      'no_claim'   -- the trace claimed no guard
    """
    claimed = guard_claim(trace or "")
    if not claimed:
        # The training traces backtick the guard; the model's live output does not
        # ("...is only partly constrained by const raw = new URL(...)"). The data
        # rule stays strict; the runtime extractor has to accept what is actually
        # emitted or it silently sees no claim at all.
        m = re.search(r"constrained by\s+(.+?)\s*$", trace or "", re.S)
        claimed = m.group(1).strip().strip("`") if m else None
    if not claimed:
        return None, None, "no_claim"
    try:
        lines = Path(file_path).read_text(encoding="utf-8",
                                          errors="replace").splitlines()
    except OSError:
        return claimed, None, "unlocated"

    def find(text):
        needle = " ".join(text.split())
        for i, l in enumerate(lines, 1):
            if needle and needle in " ".join(l.split()):
                return i
        return None

    line = find(claimed)
    if guard_is_a_control(claimed):
        return claimed, line, "located" if line else "unlocated"

    # The claim is not a control. Look for the nearest real one around the function,
    # so the finding still points somewhere useful instead of at an assignment.
    anchor = line or fn_line or 1
    best, best_d = None, 10 ** 9
    for i, l in enumerate(lines, 1):
        if _is_control_line(l) and abs(i - anchor) < best_d:
            best, best_d = i, abs(i - anchor)
    if best is not None and best_d <= 25:
        return lines[best - 1].strip(), best, "relocated"
    return claimed, line, "unlocated"


def _js_function_source(code, line):
    """Brace-match the function enclosing `line` (1-indexed)."""
    lines = code.splitlines()
    offset = sum(len(l) + 1 for l in lines[:line - 1])          # char offset of the line
    starts = [m.start() for m in _JS_FN_START.finditer(code) if m.start() <= offset]
    if not starts:
        a, b = max(0, line - 15), min(len(lines), line + 15)     # window fallback
        return "\n".join(lines[a:b])
    start = max(starts)
    i = code.find("{", start)
    if i < 0:
        return code[start:start + 1500]
    depth, j = 0, i
    while j < len(code):
        if code[j] == "{":
            depth += 1
        elif code[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    return code[start:j + 1]


def enumerate_functions(path):
    """Yield (unit, line, source) for every function in a file (Python + JS)."""
    code = Path(path).read_text(encoding="utf-8", errors="replace")
    if EXT_LANG.get(Path(path).suffix.lower()) == "py":
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return
        for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            src = ast.get_source_segment(code, fn)
            if src:
                yield fn.name, fn.lineno, src
    else:
        for m in _JS_FN_START.finditer(code):
            line = code[:m.start()].count("\n") + 1
            src = _js_function_source(code, line)
            if src and len(src) > 40:
                nm_m = re.search(r"function\s+([\w$]+)|(?:const|let)\s+([\w$]+)", m.group(0))
                nm = next((g for g in nm_m.groups() if g), f"line{line}") if nm_m else f"line{line}"
                yield nm, line, src


def function_source(path, unit, line):
    """Return the source of the function in `path` that spans `line` (Python or JS)."""
    code = Path(path).read_text(encoding="utf-8", errors="replace")
    if EXT_LANG.get(Path(path).suffix.lower()) == "py":
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return None
        for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            if fn.lineno <= line <= getattr(fn, "end_lineno", fn.lineno):
                return ast.get_source_segment(code, fn)
        return None
    return _js_function_source(code, line)


def apply_fixes(results):
    """Non-destructive --fix: insert a security review comment above each CONFIRMED
    finding's line. Backs up each file to <file>.bak first. Does NOT rewrite code
    (the patches are generic templates, not transforms of the exact line)."""
    confirmed = [r for r in results if r["confidence"].startswith(("HIGH", "MEDIUM"))]
    by_file = defaultdict(list)
    for r in confirmed:
        by_file[r["file"]].append(r)
    annotated = 0
    for fname, rs in by_file.items():
        p = Path(fname)
        original = p.read_text(encoding="utf-8", errors="replace")
        lines = original.splitlines(keepends=True)
        comment = "//" if EXT_LANG.get(p.suffix.lower()) != "py" else "#"
        indent_re = re.compile(r"^(\s*)")
        # insert from the bottom up so earlier line numbers stay valid
        for r in sorted(rs, key=lambda x: -x["line"]):
            i = max(0, r["line"] - 1)
            if i >= len(lines):
                continue
            above = "".join(lines[max(0, i - 3):i])        # a 2-line annotation may sit above
            if "SECURITY [" in above:
                continue                                   # already annotated
            indent = indent_re.match(lines[i]).group(1)
            cwe = (r["model_cwe"] or (r["taint_cwe"][0] if r["taint_cwe"] else "CWE-20"))
            guide = r["patch"]["guidance"] if r.get("patch") else "review this finding"
            note = (f"{indent}{comment} SECURITY [{cwe}] ({r['confidence'].split(' ')[0]}): "
                    f"{guide}\n"
                    f"{indent}{comment}   fix: {r['patch']['after'].splitlines()[0]}\n"
                    if r.get("patch") else
                    f"{indent}{comment} SECURITY [{cwe}]: {guide}\n")
            lines.insert(i, note)
            annotated += 1
        p.with_suffix(p.suffix + ".bak").write_text(original, encoding="utf-8")   # backup original
        p.write_text("".join(lines), encoding="utf-8")
        print(f"  annotated {fname}  (backup: {fname}.bak)")
    print(f"\n--fix: inserted {annotated} security comment(s). Review, then remove .bak when satisfied.")


def main():
    ap = argparse.ArgumentParser(description="Car-wash scanner: taint flag -> model triage + fix")
    ap.add_argument("target")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-recall", action="store_true",
                    help="disable Layer B (neural CVE-resemblance recall net)")
    ap.add_argument("--fix", action="store_true",
                    help="annotate files with security review comments above confirmed findings "
                         "(non-destructive; backs up each file to .bak)")
    args = ap.parse_args()

    files = gather(args.target)

    # --- Station 1a: taint + pattern flagging (fast, CPU) ---
    candidates = []
    for f in files:
        candidates.extend(scan_file(f))
    by_fn = defaultdict(list)
    for c in candidates:
        by_fn[(c.file, c.unit, c.line)].append(c)
    flagged_units = {(c.file, c.unit) for c in candidates}   # dedup recall by function, not line

    # --- Station 1b: Layer B recall net — functions taint missed that SEMANTICALLY
    #     resemble known CVEs (neural retrieval). Adds candidates, doesn't replace. ---
    recall_hits = {}
    if not args.no_recall:
        try:
            from embed import flag_by_retrieval          # neural Layer B (CPU)
            for f in files:
                for unit, line, src in enumerate_functions(f):
                    if (str(f), unit) in flagged_units:      # already found by taint
                        continue
                    hit = flag_by_retrieval(src, threshold=0.72, min_votes=3)
                    if hit:
                        recall_hits[(str(f), unit, line)] = hit
        except Exception as e:
            print(f"(Layer B recall skipped: {e})")

    total = len(by_fn) + len(recall_hits)
    if total == 0:
        print("Station 1: no taint candidates and no CVE-resemblance hits. Nothing to triage.")
        return
    print(f"Station 1: {len(by_fn)} taint + {len(recall_hits)} CVE-resemblance candidate(s) "
          f"in {total} function(s). Loading model for triage...\n")

    # merge recall hits into by_fn so the model triages them too
    for key, hit in recall_hits.items():
        by_fn[key]  # touch to create the group
    _recall = recall_hits

    # --- Station 2/3: model triage + fix (GPU, only on candidates) ---
    from eval.inference import QwenLoraPredictor
    from eval.parsers import parse_shape1
    model = QwenLoraPredictor()

    results = []
    for (file, unit, line), cs in by_fn.items():
        code = function_source(file, unit, line)
        if not code:
            continue
        out = model.predict(f"<SCAN>\n{code}\n</SCAN>")
        p = parse_shape1(out)
        model_vuln = p.get("status") in ("vuln", "confirmed")
        taint_cwes = sorted({c.cwe for c in cs})
        rhit = _recall.get((file, unit, line))
        # confidence: taint+model = strongest; retrieval+model = medium; single signal = review
        if cs and model_vuln:
            confidence = "HIGH (taint + model agree)"
        elif rhit and model_vuln:
            confidence = "MEDIUM (CVE-resemblance + model agree)"
        elif cs:
            confidence = "REVIEW (taint flags, model unsure)"
        else:
            confidence = "REVIEW (CVE-resemblance only)"
        detectors = (["taint"] if cs else []) + (["retrieval"] if rhit else [])
        primary_cwe = (p.get("cwe") or (taint_cwes[0] if taint_cwes else None)
                       or (rhit["cwe"] if rhit else "CWE-20")).upper()
        patch = suggest(primary_cwe, cs[0].sink if cs else "")
        results.append({
            "file": file, "function": unit, "line": line,
            "detectors": detectors,
            "taint_cwe": taint_cwes,
            "taint_sink": cs[0].sink if cs else "",
            "retrieval": (f"{rhit['cwe']} score {rhit['score']}" if rhit else ""),
            "model_status": p.get("status"), "model_cwe": p.get("cwe"),
            "confidence": confidence,
            "trace": p.get("trace", ""), "fix": p.get("fix", ""),
            "patch": patch,
        })
        # localise + validate the guard claim (no model involved)
        g_text, g_line, g_verdict = localise_guard(file, p.get("trace", ""), line)
        results[-1].update({"guard": g_text, "guard_line": g_line,
                            "guard_check": g_verdict})
        if g_verdict in ("relocated", "unlocated") and \
                results[-1]["confidence"].startswith(("HIGH", "MEDIUM")):
            results[-1]["confidence"] += "  [guard claim failed R18]"

    if args.json:
        print(json.dumps(results, indent=2))
        return

    high = [r for r in results if r["confidence"].startswith(("HIGH", "MEDIUM"))]
    review = [r for r in results if r["confidence"].startswith("REVIEW")]
    for label, group in (("CONFIRMED", high), ("FOR REVIEW", review)):
        if not group:
            continue
        print(f"===== {label} =====")
        for r in group:
            print(f"\n  {r['file']}  {r['function']}()  line {r['line']}  [{r['confidence']}]")
            print(f"    detectors: {'+'.join(r['detectors']) or 'model'}")
            if r["taint_sink"]:
                print(f"    taint:  {', '.join(r['taint_cwe'])}  via  {r['taint_sink']}")
            if r["retrieval"]:
                print(f"    resembles known CVE:  {r['retrieval']}")
            print(f"    model:  {r['model_status']} / {r['model_cwe']}")
            if r["trace"]:
                print(f"    trace:  {r['trace']}")
            if r.get("guard_check") and r["guard_check"] != "no_claim":
                loc = f"line {r['guard_line']}" if r.get("guard_line") else "not found in file"
                tag = {"located": "guard", "relocated": "guard (RELOCATED - model cited a non-control)",
                       "unlocated": "guard (UNVERIFIED)"}[r["guard_check"]]
                print(f"    {tag}: {loc}"
                      + (f"  {r['guard'][:70]}" if r.get("guard") else ""))
            if r.get("patch"):
                print(format_patch(r["patch"]))
    print(f"\n{len(high)} confirmed, {len(review)} for review "
          f"(model ran on {len(by_fn)} functions, not the whole repo).")

    if args.fix and high:
        print("\n--- Applying --fix (security review annotations) ---")
        apply_fixes(results)


if __name__ == "__main__":
    main()
