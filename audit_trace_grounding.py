"""Hold records whose stated trace names a flow that is not in their own excerpt.

The `trace:` line is the record's claim: "this source reaches this sink". If the
expressions it names do not appear in the code shown, the record is teaching the model
to assert a dataflow it cannot see -- a false claim, which is the single behaviour this
project exists to avoid. Those records are HELD (not deleted) and logged with the
expressions that were missing, so the judgement is auditable.

MEASUREMENT NOTE, because this took three attempts to get right:

  * Do NOT tokenise the trace into bare words and check those -- prose words ("input",
    "flows", "from") are not identifiers and score every record as ungrounded.
  * Do NOT feed member names to `scan_ts_standard.occurs()`. That function rejects
    member positions ON PURPOSE (it is the fix for the `nextToken` ghost), so asking it
    about `.body` in `req.body.bio` correctly returns False and wrongly reads as
    "ungrounded". Two of my three measurements were wrong this way, and they made the
    C-tier traces look 1-40% grounded when they are 80-92%.

  The correct check is the one a hand-read does: take the expression AS WRITTEN
  (`req.body.bio`, `subprocess.run`, `sanitizeUserInput`) and look for that string in
  the whitespace-normalised excerpt.

Partially-grounded records are KEPT and logged. A trace naming one real sink and one
paraphrase is imprecise; it is not a fabricated flow, and holding it would cost real
data for a wording problem.

    python audit_trace_grounding.py            # report only
    python audit_trace_grounding.py --write
"""
import argparse
import collections
import csv
import json
import os
import re
import sys

from scan_ts_standard import code_of, trace_of

MANIFEST = "data/osv/ungrounded_traces.tsv"

# dotted path | call head | snake_case | camelCase -- the shapes an identifier takes
EXPR = re.compile(
    r"\b[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)+"
    r"|\b[A-Za-z_][A-Za-z_0-9]*(?=\s*\()"
    r"|\b[a-z]+_[a-z_0-9]+\b"
    r"|\b[a-z]+[A-Z][A-Za-z0-9]+\b")

# Prose that happens to match one of the shapes above. Kept small and explicit: every
# word here is one the trace line uses as English, not as code.
STOP = {"e.g", "i.e", "etc", "input", "output", "user", "data", "value", "the", "and",
        "or", "not", "use", "using", "via", "with", "from", "into", "flows", "reaches",
        "depends", "verdict", "implementation", "sanitize", "validate", "escape",
        "encode", "check", "none", "true", "false", "null", "constrained", "partly"}


def expressions(trace_line):
    """Code-shaped expressions named by a trace line, as written."""
    return {m.group(0) for m in EXPR.finditer(trace_line)
            if len(m.group(0)) > 2 and m.group(0).lower() not in STOP}


def present(expr, code):
    """Is this expression grounded in the excerpt?

    A dotted expression is QUALIFIED-NAME NOTATION as often as it is literal source.
    The trace writes `dangerouslySetInnerHTML.__html` for code that reads
    `dangerouslySetInnerHTML={{ __html: x }}`, `configProvider.error.unexpectedToken`
    for a nested object literal, and `SearchState.replaceText` for a field of an
    interface. Requiring the dotted string verbatim flagged all of those as fabricated
    -- they are not. So: the whole expression, or every component of it, must appear.
    """
    if expr in code:
        return True
    if "." in expr:
        parts = expr.split(".")
        # A leading RECEIVER is notation too: the trace writes `props.url` for a prop
        # the component destructures as `({ url })`, so `props` never appears literally.
        # The member is the claim; the receiver is how the trace addresses it.
        if len(parts) > 1 and parts[0] in ("props", "this", "self"):
            parts = parts[1:]
        return all(re.search(r"\b" + re.escape(part) + r"\b", code)
                   for part in parts if len(part) > 2)
    return False


def grounding(rec):
    """(missing, total) expressions, or None if the record states no trace."""
    body = trace_of(rec)
    m = re.search(r"^(?:partial_)?trace:(.+)$", body, re.M)
    if not m:
        return None
    exprs = expressions(m.group(1))
    if not exprs:
        return None
    code = re.sub(r"\s+", " ", code_of(rec))
    return sorted(e for e in exprs if not present(e, code)), len(exprs)


# An excerpt with no executable construct -- only imports, type aliases and interface
# declarations -- contains no dataflow, so "this code is vulnerable" cannot be checked
# against it either way. 47 such records sit in shape1_verified/_safe. Holding them is
# not a style judgement: there is no statement present for a verdict to be about.
EXECUTABLE = re.compile(r"\b(def|class|function|await|return|if|for|while)\b"
                        r"|=>|=[^=]|\w\s*\(")


def path_of(shape):
    for d in ("pilot", "staging"):
        p = f"data/cot/{d}/{shape}.jsonl"
        if os.path.exists(p):
            return p
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--shapes", nargs="*")
    args = ap.parse_args()

    shapes = args.shapes or [
        "shape1_verified", "shape1_verified_safe", "shape1_ts", "shape1_ts_safe",
        "shape1_react", "shape1_react_safe", "shape2", "shape3", "shape1_unique",
        "shape_react_syn", "shape3_crossfile_pairs"]

    rows, f = [], collections.Counter()
    print(f"{'shape':24s}{'traced':>8s}{'full':>7s}{'partial':>9s}{'NONE':>7s}")
    for shape in shapes:
        path = path_of(shape)
        if not path:
            continue
        recs = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
        full = part = none = traced = 0
        changed = 0
        for i, r in enumerate(recs):
            # Never overwrite an earlier audit's reason. These scripts run in sequence
            # over the same files, and a second `held = ...` silently replaced the first
            # -- a CWE-1135 record held as `nonsecurity_cwe` came back as
            # `ungrounded_trace`, so its manifest row no longer matched the corpus. The
            # record stayed held either way; the reason for holding it did not.
            prior = r.get("_meta", {}).get("held")
            if prior:
                # Re-emit rows this audit is responsible for, so a re-run reproduces the
                # whole manifest instead of truncating it to whatever is newly held.
                if prior in ("ungrounded_trace", "no_executable_construct"):
                    rows.append(dict(shape=shape, index=i,
                                     cwe=r["_meta"].get("ground_truth_cwe", ""),
                                     missing="(held by an earlier run)"))
                    f[f"HELD_{prior}"] += 1
                else:
                    f["held_elsewhere"] += 1
                continue
            if not EXECUTABLE.search(code_of(r)):
                r.setdefault("_meta", {})["held"] = "no_executable_construct"
                rows.append(dict(shape=shape, index=i,
                                 cwe=r["_meta"].get("ground_truth_cwe", ""),
                                 missing="excerpt is imports/type declarations only -- "
                                         "no statement for a verdict to be about"))
                changed += 1
                f["HELD_no_executable"] += 1
                continue
            g = grounding(r)
            if g is None:
                continue
            missing, total = g
            traced += 1
            if not missing:
                full += 1
            elif len(missing) < total:
                part += 1
                f["partial_kept"] += 1
            else:
                none += 1
                r.setdefault("_meta", {})["held"] = "ungrounded_trace"
                rows.append(dict(shape=shape, index=i,
                                 cwe=r["_meta"].get("ground_truth_cwe", ""),
                                 missing="; ".join(missing)[:200]))
                changed += 1
                f["HELD_ungrounded"] += 1
        print(f"{shape:24s}{traced:8d}{100*full//max(1,traced):6d}%"
              f"{100*part//max(1,traced):8d}%{none:7d}")
        if changed and args.write:
            with open(path, "w", encoding="utf-8") as fh:
                for r in recs:
                    fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    print()
    for k, v in f.most_common():
        print(f"  {k:22s} {v:6d}")
    if args.write and rows:
        os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
        with open(MANIFEST, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(rows)
        print(f"\n-> {MANIFEST} ({len(rows)} held)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
