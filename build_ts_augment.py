"""Emit + verify the augmentation pilot records.

Verification is the same gate that caught the 42% defect rate in the heuristic
traces: every identifier the trace names must actually occur in the code, outside
string literals. A trace that names something absent from the excerpt is the
confabulation we are trying to train out, so it must never ship.

    python build_ts_augment.py
"""
import collections
import hashlib
import json
import os
import re
import sys

from ts_augment_pilot import PILOT

OUT = "data/cot/staging/shape1_ts_augment_pilot.jsonl"
_STR = re.compile(r"""(['"`])(?:\\.|(?!\1).)*\1""")


_INTERP = re.compile(r"\$\{([^{}]*)\}")


def occurs(ident, code):
    """Identifier present as real code, not only inside a string literal.

    A template literal's `${...}` interpolation IS code, so its contents are kept
    before the surrounding literal is stripped -- otherwise
    `execAsync(`${TOOL_BINARIES[tool]} --version`)` looks like a bare string.
    """
    kept = " ".join(_INTERP.findall(code))
    bare = _STR.sub("''", code) + " " + kept
    head = ident.split("[")[0].split(".")[0]
    return re.search(r"(?<![\w.])" + re.escape(head) + r"(?![\w])", bare) is not None


def vuln_trace(source, sink, cwe, why):
    return (
        "<think>\n"
        f"Hypothesis: `{source}` is attacker-influenced and reaches `{sink}` - a possible {cwe}.\n"
        f"Trigger path: {why}.\n"
        f"Defensive check: I look for a control constraining `{source}` before `{sink}` "
        "and find none that holds.\n"
        f"The mechanism is therefore intact, so this is exploitable. Confirmed {cwe}.\n"
        "</think>\n"
        f"status: confirmed\ncwe: {cwe}\nseverity: HIGH\n"
        f"trace: {source} -> {sink}\n"
        f"fix: constrain `{source}` before it reaches `{sink}`"
    )


def safe_trace(source, sink, cwe, why, because):
    return (
        "<think>\n"
        f"Hypothesis: `{source}` reaches `{sink}`, which is the shape of {cwe} - "
        "check whether the mechanism is actually present.\n"
        f"Trigger path: the call structure matches the vulnerable pattern, so shape alone "
        "does not settle it.\n"
        f"Defensive check: {why}.\n"
        f"Because {because}, the mechanism {cwe} depends on is absent and the hypothesis "
        "is refuted.\n"
        "</think>\n"
        "status: safe\ncwe: none\nseverity: none\n"
        f"trace: {source} -> {sink} is not exploitable ({because})\n"
        "fix: none"
    )


def rec(code, trace, cwe, label, pid, kind, base):
    return {
        "messages": [
            {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
            {"role": "assistant", "content": trace},
        ],
        "_meta": {
            "shape": "shape1", "source": "ts_augment_pilot", "origin": "authored",
            "language": "typescript", "label": label,
            "cwes": [cwe] if label == "vuln" else [], "ground_truth_cwe": cwe,
            "pair_id": pid, "contrastive": True,
            # authored variants of REAL cve code -- not invented textbook code, but
            # flag it honestly so it can be weighted or dropped independently.
            "synthetic": True, "record_kind": kind, "base_cve": base, "cleaned": True,
        },
    }


def main():
    out, f = [], collections.Counter()
    problems = []
    for b in PILOT:
        cwe, base = b["cwe"], b["base_cve"]
        for kind, items in (("variant_vuln", b["variant_vuln"]),
                            ("nearmiss_safe", b["nearmiss_safe"])):
            for it in items:
                code, src, snk = it["code"], it["source"], it["sink"]
                bad = [n for n in (src, snk) if not occurs(n, code)]
                if bad:
                    problems.append((kind, cwe, bad, it["code"].splitlines()[0]))
                    f["REJECTED_identifier_absent"] += 1
                    continue
                pid = hashlib.sha1((base + kind + code[:80]).encode()).hexdigest()[:12]
                if kind == "variant_vuln":
                    tr = vuln_trace(src, snk, cwe, it["why"])
                    out.append(rec(code, tr, cwe, "vuln", pid, kind, base))
                else:
                    tr = safe_trace(src, snk, cwe, it["why"], it["safe_because"])
                    out.append(rec(code, tr, cwe, "safe", pid, kind, base))
                f[kind] += 1

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        for r in out:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    print("=== pilot ===")
    for k, v in f.most_common():
        print(f"  {k:30s} {v}")
    print(f"\nbases: {len(PILOT)}   records: {len(out)} -> {OUT}")
    if problems:
        print("\nREJECTED (trace named something absent from the code):")
        for p in problems:
            print("  ", p)
    lab = collections.Counter(r["_meta"]["label"] for r in out)
    print(f"\nlabel balance: {dict(lab)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
