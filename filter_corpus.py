"""Apply the data standard as a FILTER over the existing corpus.

docs/TS_DATA_STANDARD.md has been used to BUILD records. Read as a filter, the
subset of its rules that need no base record and no provenance applies to every
record we already hold -- including the ~54K that have no path back to a commit.

    R6  every identifier the reasoning names must occur in the code
    R7  mechanism stated, not boilerplate, reasoning not trivially thin
    R10 no eval leakage
    R11 size within the label-masking limit

R4 (provenance) is recorded as a LABEL, not a gate: gating on it would delete
99.6% of the corpus and tells us nothing about whether a record teaches the goal.

GROUNDING IS TESTED AGAINST THE RAW CODE, string literals included. Stripping
them is correct when PICKING a source or sink -- a word inside a string is not a
value the model can use -- but wrong when asking "is this identifier present in
what the model was shown". A trace discussing `__proto__` where the code contains
`'__proto__'` is grounded; scoring it a ghost would punish correct reasoning.

NOTHING IS DELETED. Records that fail are written to a manifest with the rule and
the offending identifier, and shapes listed in HOLD are never dropped at all.

    python filter_corpus.py --measure    # report only
    python filter_corpus.py --write      # emit data/cot/filtered/ + manifest
"""
import argparse
import collections
import csv
import glob
import json
import os
import re
import sys

from scan_ts_standard import BOILERPLATE, code_of, trace_of

OUT_DIR = "data/cot/filtered/"
MANIFEST = "data/osv/corpus_filter_manifest.tsv"
# Points at the NEW eval. The 369-record bench in data/cot/eval/ is retired: it was
# drawn from provenance-free data (42 of ~1,600 records carried any), so it could not
# distinguish a model that improved from data that did not work.
EVAL_GLOB = os.environ.get("WAVE_EVAL_DIR", "data/cot/eval_v2")
MIN_CHARS, MAX_CHARS = 120, 6000

# Shapes never dropped, only reported. shape1_sft is the largest block in the
# corpus and is entirely generated data with no upstream commit, so it cannot be
# repaired the way a harvested shape can -- it gets rated on its own terms first.
HOLD = {"shape1_sft"}

# Auxiliary tasks with a different output contract: `localize` answers "which
# line", `fixgen` answers "produce the patch". Neither emits a <think> block, so
# R7's mechanism/length test is the wrong rule and rejected 100% of both -- a
# false positive, not a finding. R6 grounding still applies and still bites.
AUX_SHAPES = {"shape1_fixgen", "shape1_localize", "shape3_codeql_localize"}

_TICKED = re.compile(r"`([^`\n]{2,60})`")
_PROSE = {"think", "vuln", "safe", "none", "true", "false", "null", "undefined",
          "int", "str", "string", "char", "bool", "void", "return", "if", "else",
          "for", "while", "yes", "no", "n/a", "cwe", "high", "low", "medium",
          # ordinary English that turns up inside emphasis backticks
          "and", "the", "this", "that", "with", "from", "into", "not", "but",
          "use", "used", "using", "specifically", "problematic", "example",
          "parameter", "parameters", "value", "values", "input", "output",
          "function", "method", "code", "line", "note", "however", "therefore",
          "because", "which", "where", "when", "what", "should", "would",
          "could", "must", "may", "might", "also", "more", "most", "other",
          "another", "same", "different", "such", "since", "while", "before",
          "after", "each", "any", "all", "one", "two", "both", "then", "than",
          "only", "just", "even", "still", "yet", "own", "via", "per", "etc"}

# A trace that predicts an exception is reasoning correctly ABOUT code that does
# not contain it. `NullPointerException` appearing in a Java trace is a
# consequence, not a claim of presence, and requiring it in the excerpt punished
# 606 r2vul records for being right.
_EXC_TYPE = re.compile(r"(Exception|Error|Throwable|Fault)s?$")

# Naming the dangerous alternative is how you say a fix is correct -- "uses
# `strncpy` rather than `strcpy`". Requiring `strcpy` to be present inverted the
# test on 636 records.
_UNSAFE_FN = {"printf", "sprintf", "malloc", "strcpy", "realloc", "eval",
              "strcat", "gets", "system", "exec", "memcpy", "alloca", "scanf",
              "vsprintf", "free", "atoi", "rand", "tmpnam", "popen", "strncat"}

# Phrasing that marks the NEXT backticked span as counterfactual: something the
# code deliberately does not do, or a consequence that has not happened.
_COUNTERFACTUAL = re.compile(
    r"(instead of|rather than|unlike|as opposed to|not\s+|no\s+|avoids?|"
    r"replaced?\s+(?:by|with)|would (?:throw|raise|be|have|allow|permit)|"
    r"could (?:throw|raise|be|allow)|prevents?|protects? against|"
    r"vulnerable to|susceptible to|such as|e\.g\.|instead)\W{0,20}$",
    re.I)


# Test code teaches nothing about production risk: its "vulnerabilities" are
# fixtures, its guards are assertions, and a stub server exists to be broken. One
# reached the contrastive set as CVE-2023-27582 -- a SASL stub full of `t.Run` and
# `t.Error` -- carrying a CWE and a verdict.
#
# STRICT on purpose. The loose form (`it(`, `expect(`, `mock.`) flags 1.9% of the
# corpus against this pattern's 0.3%, because those tokens appear throughout real
# application code. Every construct here is one that only test code contains.
_TEST_CODE = re.compile(
    r"(^|\n)\s*(def test_\w|func Test[A-Z]\w*\s*\(|@Test\b|#\[test\]|TEST_F?\s*\()"
    r"|\bt\.Run\s*\(|\bt\.Error|\bt\.Fatal"
    r"|\bself\.assert\w+\s*\(|\bassertEquals\s*\(|\bassertThat\s*\("
    r"|\bunittest\.|@pytest\."
    # chai / jest / should style. `assert.include(err.message, ...)` from tiny-csrf
    # reached the completeness candidates as five separate "guards" because none of
    # the patterns above matched a JS assertion library.
    # CHAI-ONLY assert methods. A bare `assert.\w+` is wrong: `assert.ok(...)` and
    # `assert.equal(...)` are Node's runtime preconditions and appear in PRODUCTION
    # code -- set-in's `assert.ok(!POLLUTED_KEYS.includes(key))` is the guard the
    # completeness pair exists to teach, and a broad pattern deleted it.
    r"|\bassert\.(include|isTrue|isFalse|isNull|isUndefined|lengthOf|sameMembers"
    r"|deepInclude|closeTo|isAbove|isBelow)\s*\("
    r"|\bexpect\s*\([^)]*\)\s*\.\s*(to|toBe|toEqual|toHave|not)\b"
    r"|\bshould\.\w+\s*\(|\bchai\.|\bsinon\.")


# Test files by PATH. The old pattern used `\.(test|spec)\.`, which only catches the
# dot form -- `error-sanitization-test.ts` (hyphen) and `foo_test.py` (underscore)
# both slipped through, and the first of those was about to become training data from
# the react harvest. Content detection catches most of the rest, but a test file with
# no assertion in the excerpted hunk is invisible to it, so the path check matters.
_TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|e2e|fixtures?|testdata)/"
    r"|[._-](test|spec|e2e)\.[a-z]+$"
    r"|(^|/)test[_-]"
    r"|_test\.[a-z]+$",
    re.I)


def is_test_path(path):
    """True when the FILE PATH marks it as a test, independent of its contents."""
    return bool(path) and _TEST_PATH.search(path) is not None


def is_test_code(code):
    """True when the excerpt is test code rather than the software under test."""
    return _TEST_CODE.search(code) is not None


def named_identifiers(text):
    """Identifiers a trace ASSERTS ARE PRESENT in the code it is reasoning about.

    Not every backticked token is such a claim. Excluded here, each because it
    was measured as a false positive on r2vul (28.6% of all R6 flags):
    ordinary English in emphasis backticks, exception types the trace predicts,
    unsafe functions named as the alternative that was avoided, and any span
    introduced by counterfactual phrasing. Scoring those as ghosts marks correct
    reasoning as hallucination -- the opposite of what R6 is for.
    """
    out = []
    for m in _TICKED.finditer(text):
        s = m.group(1).strip()
        if not s or s.lower() in _PROSE:
            continue
        if _COUNTERFACTUAL.search(text[max(0, m.start() - 40):m.start()]):
            continue
        idents = re.findall(r"[A-Za-z_$][\w$]*", s)
        if not idents:
            continue
        cand = max(idents, key=len)
        if len(cand) < 3 or cand.lower() in _PROSE:
            continue
        if _EXC_TYPE.search(cand) or cand.lower() in _UNSAFE_FN:
            continue
        out.append(cand)
    return out


def load_eval_codes():
    codes = set()
    for p in glob.glob(os.path.join(EVAL_GLOB, "*.jsonl")):
        for line in open(p, encoding="utf-8"):
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("messages"):
                codes.add(re.sub(r"\s+", " ", code_of(r)).strip().lower())
    return codes


def judge(r, evalcodes, shape=""):
    """Rules this record breaks. Empty list == keeps."""
    bad = []
    code, t = code_of(r), trace_of(r)

    think = re.search(r"<think>(.*?)</think>", t, re.S)

    # R6 splits by WHERE the ungrounded name sits. The `trace:` line is the
    # load-bearing claim -- the source->sink assertion the verdict rests on -- and
    # a ghost there means the record is reasoning about code that is not present.
    # A ghost in surrounding prose is a blemish on an otherwise sound claim.
    # Measured on r2vul: 92.8% of ghosts are prose-only, and treating those as
    # equal to a broken claim would reject 5,126 records whose verdict is fine.
    claim = re.search(r"^trace:.*$", t, re.M)
    claim_txt = claim.group(0) if claim else ""

    # A restructure record NAMES the construct the fix removed, and on the safe
    # side that construct is absent BY DESIGN -- that is the whole claim, and R8
    # verifies the absence directly. Flagging it as a ghost would reject the shape
    # for doing exactly what it exists to do. (`0o644` also mangles to `o644`,
    # since an identifier cannot start with a digit.)
    removed = (r.get("_meta") or {}).get("removed_construct") or ""
    exempt = {x.lower() for x in re.findall(r"[A-Za-z_][\w$]*", removed)}

    for ident in named_identifiers(think.group(1) if think else t):
        if ident.lower() in exempt:
            continue
        if not re.search(r"(?<![\w])" + re.escape(ident) + r"(?![\w])", code):
            if ident in claim_txt:
                bad.append(("R6a", ident))     # broken claim -> reject
                break
            bad.append(("R6b", ident))         # prose only -> flag, keep
            break

    # R7 is TWO tests, and they have different scopes. Lumping them under one
    # AUX_SHAPES exemption meant `shape3_codeql_localize` got NO boilerplate check at
    # all, and it sat on a single templated sentence across 100% of 7,149 records
    # while passing every rule we own.
    #
    # Case-INSENSITIVE. The corpus writes "The fix adds a control the vulnerable code
    # lacks"; the pattern list stores it lowercase, so an exact-case test missed
    # ~13,700 records sitting on that one template.
    tl = t.lower()
    if any(b.lower() in tl for b in BOILERPLATE):
        bad.append(("R7", "boilerplate"))       # applies to EVERY shape
    elif shape not in AUX_SHAPES:
        # The length test needs a <think> block. `localize` answers "which line" and
        # `fixgen` answers "produce the patch"; neither emits one, so this half of R7
        # is genuinely the wrong rule for them and rejected 100% as a false positive.
        if not think or len(think.group(1).split()) < 45:
            bad.append(("R7", "reasoning too thin"))

    if re.sub(r"\s+", " ", code).strip().lower() in evalcodes:
        bad.append(("R10", "eval leakage"))

    if not (MIN_CHARS <= len(code) <= MAX_CHARS):
        bad.append(("R11", f"{len(code)} chars"))

    if is_test_code(code):
        bad.append(("R14", "test code, not the software under test"))
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    print("loading eval set for leakage check...", flush=True)
    evalcodes = load_eval_codes()
    print(f"  {len(evalcodes)} eval codes", flush=True)

    if args.write:
        os.makedirs(OUT_DIR, exist_ok=True)

    stats = collections.defaultdict(lambda: collections.Counter())
    manifest = []
    for d in ("data/cot/pilot/", "data/cot/staging/"):
        for f in sorted(os.listdir(d)):
            if not f.endswith(".jsonl"):
                continue
            shape = f[:-6]
            kept, out = 0, []
            for i, line in enumerate(open(d + f, encoding="utf-8")):
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not r.get("messages") or len(r["messages"]) < 2:
                    continue
                stats[shape]["total"] += 1
                bad = judge(r, evalcodes, shape)
                # R6b alone never drops a record -- the claim is sound.
                hard = [b for b in bad if b[0] != "R6b"]
                held = shape in HOLD or (bad and not hard)
                if hard and not held:
                    for rule, why in bad:
                        stats[shape][rule] += 1
                    stats[shape]["dropped"] += 1
                    manifest.append(dict(shape=shape, line=i,
                                         rules="|".join(x[0] for x in bad),
                                         detail="; ".join(f"{a}:{b}" for a, b in bad),
                                         action="dropped"))
                    continue
                if bad and held:
                    for rule, why in bad:
                        stats[shape][rule] += 1
                    stats[shape]["flagged_kept"] += 1
                    manifest.append(dict(shape=shape, line=i,
                                         rules="|".join(x[0] for x in bad),
                                         detail="; ".join(f"{a}:{b}" for a, b in bad),
                                         action="flagged_kept(HOLD)"))
                kept += 1
                out.append(line)
            if args.write and out:
                with open(OUT_DIR + f, "w", encoding="utf-8") as fh:
                    fh.writelines(out)
            stats[shape]["kept"] = kept

    print(f"\n{'shape':30s} {'total':>7s} {'kept':>7s} {'drop':>6s} {'R6':>6s} "
          f"{'R7':>6s} {'R10':>4s} {'R11':>6s}")
    print("-" * 82)
    T = collections.Counter()
    for shape in sorted(stats, key=lambda s: -stats[s]["total"]):
        c = stats[shape]
        tag = "  [HOLD]" if shape in HOLD else ""
        print(f"  {shape:28s} {c['total']:7d} {c['kept']:7d} {c['dropped']:6d} "
              f"{c['R6a']:6d} {c['R6b']:6d} {c['R7']:6d} {c['R10']:4d} {c['R11']:6d}{tag}")
        for k, v in c.items():
            T[k] += v
    print("-" * 82)
    print(f"  {'TOTAL':28s} {T['total']:7d} {T['kept']:7d} {T['dropped']:6d} "
          f"{T['R6a']:6d} {T['R6b']:6d} {T['R7']:6d} {T['R10']:4d} {T['R11']:6d}")
    print(f"\n  kept {100*T['kept']/T['total']:.1f}% | "
          f"flagged-but-held {T['flagged_kept']}")

    if args.write:
        with open(MANIFEST, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["shape", "line", "rules", "detail", "action"],
                               delimiter="\t")
            w.writeheader()
            w.writerows(manifest)
        print(f"\n-> {OUT_DIR}\n-> {MANIFEST} ({len(manifest)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
