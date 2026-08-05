"""Convert shape3_codeql from a VERDICT task to a LOCALIZATION task.

shape3_codeql is 8,938 records and 100% vulnerable. As a verdict task that is
unfalsifiable -- an always-say-vuln stub scores 100% on it, which is how this
project once reported "100% cross-file recall" -- and at 16.7% of effective
sampling it is the largest single source of the "cross-file shape => vuln"
shortcut. Balancing it needs safe cross-file records, and that pool is exhausted:
600 python commits yielded 2 pairs and 881 javascript commits yielded 0.

But the imbalance is only a defect for a task whose ANSWER is the verdict. Asked
"where does the tainted value reach a sink", an all-vulnerable set is exactly
right -- every record has an answer, and no bias is learnable because "vulnerable"
is never the thing being predicted.

The data supports it: 8,338 of 8,938 records carry a parseable sink `file:line`
and a full flow path, and in ALL 8,338 the sink location appears as a header in
the record's own excerpt, so the answer is checkable against what the model was
shown rather than taken on faith.

This keeps what CodeQL genuinely verified -- interprocedural taint paths, the
corpus's best-grounded shape at 2.6% ungrounded identifiers -- and discards only
the verdict that was never falsifiable.

    python build_codeql_localize.py --write
"""
import argparse
import collections
import hashlib
import json
import os
import re
import sys

from filter_corpus import is_test_code

SRC = "data/cot/pilot/shape3_codeql.jsonl"
OUT = "data/cot/staging/shape3_codeql_localize.jsonl"
MIN_CHARS, MAX_CHARS = 120, 6000

# A "sink" that is a comment, an import, a decorator or a bare definition is not an
# operation the tainted value reaches -- it is wherever CodeQL's path record happened
# to land. Measured at ~6% of records, including a Flask `@bp.route(...)` decorator
# named as the sink when that is where input ENTERS, not where it goes.
_NOT_A_SINK = re.compile(
    r"^\s*(@|#|//|\*|'''|\"\"\"|from\s+\S+\s+import\b|import\b|"
    r"(async\s+)?def\s|class\s|function\s|package\s|use\s)")

_SINK = re.compile(r"reaches a sink in `([^`]+)` \(line (\d+)\)")
_FLOW = re.compile(r"flows across files: (.+)")
_SRC = re.compile(r"traces untrusted input from `([^`]+)` \(line (\d+)\)")
_HDR = re.compile(r"^# (\S+) \(line (\d+)\)", re.M)


def _sink_statement(code, sink_base, sink_line):
    """The source line at the claimed sink, or None if it cannot be located."""
    blocks = re.split(r"^# (\S+) \(line (\d+)\)$", code, flags=re.M)
    for i in range(1, len(blocks), 3):
        if not (blocks[i].endswith(sink_base) and blocks[i + 1] == str(sink_line)):
            continue
        lines = [l for l in blocks[i + 2].splitlines() if l.strip()]
        ln = int(sink_line)
        idx = 4 if ln > 5 else ln - 1       # read_lines uses ctx=4
        return lines[idx].strip() if idx < len(lines) else None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    out, f, seen = [], collections.Counter(), set()
    for line in open(SRC, encoding="utf-8"):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        code = r["messages"][0]["content"]
        trace = r["messages"][1]["content"]
        m = r.get("_meta") or {}
        f["total"] += 1

        sink = _SINK.search(trace)
        flow = _FLOW.search(trace)
        src = _SRC.search(trace)
        if not (sink and flow and src):
            f["unparseable_flow"] += 1
            continue
        sink_file, sink_line = sink.group(1), sink.group(2)
        src_file, src_line = src.group(1), src.group(2)
        path = flow.group(1).strip().rstrip(".")

        # The sink must be locatable in what the model is actually shown.
        headers = {(os.path.basename(h), l) for h, l in _HDR.findall(code)}
        if (os.path.basename(sink_file), sink_line) not in headers:
            f["sink_not_in_excerpt"] += 1
            continue

        # ...and it must be an OPERATION. The excerpt is centred on the sink with
        # four lines of leading context (codeql_harvest.read_lines, ctx=4), so the
        # sink is the 5th non-blank line of its block unless clipped at the top.
        sink_stmt = _sink_statement(code, os.path.basename(sink_file), sink_line)
        if sink_stmt is None:
            f["sink_line_unreadable"] += 1
            continue
        if _NOT_A_SINK.match(sink_stmt):
            f["sink_is_not_an_operation"] += 1
            continue

        body = code.replace("<SCAN>", "").replace("</SCAN>", "").strip()
        if not (MIN_CHARS <= len(body) <= MAX_CHARS):
            f["size"] += 1
            continue
        if is_test_code(body):
            f["test_code"] += 1
            continue
        cwe = m.get("ground_truth_cwe") or ""
        if not cwe:
            f["no_cwe"] += 1
            continue
        key = hashlib.sha256(body.encode()).hexdigest()
        if key in seen:
            f["duplicate"] += 1
            continue
        seen.add(key)

        # The recorded path is a PREFIX, not the whole flow: codeql_harvest.py
        # builds it as `steps[:8]` while taking the sink from `steps[-1]`. On 62.9%
        # of records the last shown hop is in a different file from the sink, which
        # reads as a contradiction unless the truncation is stated. The sink is the
        # trustworthy field -- it is present in the excerpt on all 8,338 records --
        # so it is the answer, and the path is offered as the opening steps only.
        hops = len([h for h in path.split("->") if h.strip()])
        # File AND line: a path ending at phoenix.py:90 does not reach a sink at
        # phoenix.py:96, and comparing only the filename called 25.5% of truncated
        # paths complete.
        ends_at_sink = (path.split("->")[-1].strip()
                        == f"{os.path.basename(sink_file)}:{sink_line}")
        path_label = ("path" if ends_at_sink
                      else f"path (first {hops} steps of a longer flow)")
        answer = (f"source: {os.path.basename(src_file)}:{src_line}\n"
                  f"sink: {os.path.basename(sink_file)}:{sink_line}\n"
                  f"{path_label}: {path}\n"
                  f"why: untrusted input enters at {os.path.basename(src_file)}:"
                  f"{src_line} and reaches {os.path.basename(sink_file)}:{sink_line} "
                  f"with no sanitiser between them. This is a {cwe} flow.")

        nm = dict(m)
        nm.update(shape="shape3_codeql_localize", source="codeql_localize",
                  task="localize", label="locate", cross_file=True, multi_hop=True,
                  sink_file=os.path.basename(sink_file), sink_line=sink_line,
                  hops=hops, cleaned=True,
                  converted_from="shape3_codeql (verdict task, 100% vuln)")
        out.append({"messages": [
            {"role": "user",
             "content": code.replace("</SCAN>",
                                     "</SCAN>\nLocate the tainted flow: name the "
                                     "source, the sink, and the path between them.")},
            {"role": "assistant", "content": answer}], "_meta": nm})
        f["BUILT"] += 1

    for k, v in f.most_common():
        print(f"  {k:24s} {v:6d}")
    if args.write and out:
        with open(OUT, "w", encoding="utf-8") as fh:
            for r in out:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"\n-> {OUT} ({len(out)} records)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
