"""Authoritative gate for TS contrastive data. See docs/TS_DATA_STANDARD.md.

Exits 0 only if every requirement passes. Nothing ships on a non-zero exit.

When you fix something, ADD ITS CHECK HERE IN THE SAME CHANGE. Every regression
in this project so far shipped through a gate that tested what its author thought
to test.

    python scan_ts_standard.py data/cot/staging/<file>.jsonl
"""
import collections
import difflib
import json
import os
import re
import statistics as st
import sys

REAL = "data/cot/staging/shape1_contrastive_ts_osv.jsonl"

# Rules R3/R5/R9/R13 compare a record against the BASE it was derived from, so they
# apply only to AUGMENTATION sets. A harvested set has no base; reporting those as
# PASS would be a silent skip, so they are reported N/A and excluded from the tally.
# R2 is augmentation-only: for an authored edit a large diff means carelessness,
# but for a harvested pair the diff is what the maintainer actually wrote, and
# forcing it minimal makes the study material cleaner than the exam.
AUGMENTATION_ONLY = ("R2", "R3", "R5", "R9", "R13")
# Points at the NEW eval. The 369-record bench in data/cot/eval/ is retired: it was
# drawn from provenance-free data (42 of ~1,600 records carried any), so it could not
# distinguish a model that improved from data that did not work.
EVAL_GLOB = os.environ.get("WAVE_EVAL_DIR", "data/cot/eval_v2")

MIN_CHARS, MAX_CHARS = 120, 4500
# The 4500 ceiling exists for LABEL MASKING during training, which does not apply to
# a held-out eval -- and the standard's own principle is that the exam must not be
# cleaner than the wild. Eval sets declare their own ceiling via WAVE_MAX_CHARS so the
# relaxation is explicit and visible in the scan header, never silent.
MAX_CHARS = int(os.environ.get("WAVE_MAX_CHARS", MAX_CHARS))
MAX_CHANGED_LINES = 12

_STR = re.compile(r"""(['"`])(?:\\.|(?!\1).)*\1""")
_INTERP = re.compile(r"\$\{([^{}]*)\}")

# Sentences that appear in >=39 existing TS records; emitting them again teaches
# the sentence rather than the reasoning.
BOILERPLATE = [
    "I look for validation/sanitization/authorization between source and sink and find none",
    "Because the guard covers the trigger path",
    "the fix adds a control the vulnerable code lacks",
    # shape3_codeql_localize carried this on 100% of 7,149 records. It names a source
    # and a sink and then says nothing about why arriving there is dangerous, so it
    # teaches recitation. Listed here so it cannot come back in a rebuild.
    "with no sanitiser between them",
]



# ---- R18: the quoted guard must BE a control ----------------------------
# A trace that says "constrained by `X`" is making a claim about X. Measured on the
# shipped sets, 21% of those X's were not controls at all: SQL string-building
# (`$update = "UPDATE ... "`), HTML building (`$btnGo = "<input ..."`), a docstring
# line (`:raises ValidationError:`), a DNS query. The model learned from that and, on a
# real project, quoted `const raw = new URL(request.url).searchParams.get("next")` --
# the ASSIGNMENT -- as the guard, instead of the `startsWith` check on the next line.
#
# A guard is a CONDITIONAL or a call to a recognised sanitiser/validator. Note the
# sanitiser names carry no word-boundary prefix on purpose: they are embedded inside
# identifiers like `mysqli_real_escape_string` and `getCanonicalPath`, where a word
# boundary never matches and the rule would reject real controls.
_GUARD_COND = re.compile(
    r"^\s*(if|elif|unless|assert|raise|throw|while|return\s+[^;]*[<>=!])\b", re.I)
_GUARD_SANI = re.compile(
    r"(validate|sanitiz|sanitis|escape|quote|encode|htmlspecial|canonical|realpath"
    r"|normpath|abspath|startsWith|endsWith|fullmatch|isinstance|allowlist|whitelist"
    r"|verify|authoriz|authenticat|hasPermission|deny|reject|block|forbid|require"
    r"|ensure|guard|purify|bleach|strip_tags|\.test|\.match|\.search|\.includes"
    r"|\.indexOf|parseInt|strip|trim|filter)\w*\s*\(", re.I)
_GUARD_JUNK = re.compile(
    r"^\s*[:#*]|=\s*['\"].*(SELECT|INSERT|UPDATE|DELETE|<input|<div|<a )", re.I)
_GUARD_CLAIM = re.compile(
    r"constrained by `([^`]+)`|control is `([^`]+)`|now contains `([^`]+)`"
    r"|find `([^`]+)` on it")


def guard_claim(trace_text):
    """The guard a trace claims, or None."""
    m = _GUARD_CLAIM.search(trace_text)
    if not m:
        return None
    return next(x for x in m.groups() if x).strip()


def guard_is_a_control(guard):
    """Is the claimed guard actually a control?"""
    if not guard:
        return True                       # no claim made, nothing to check
    if _GUARD_JUNK.search(guard):
        return False
    return bool(_GUARD_COND.search(guard) or _GUARD_SANI.search(guard))


def code_of(r):
    return r["messages"][0]["content"].replace("<SCAN>", "").replace("</SCAN>", "").strip()


def trace_of(r):
    return r["messages"][1]["content"]


def occurs(ident, code):
    kept = " ".join(_INTERP.findall(code))
    bare = _STR.sub("''", code) + " " + kept
    head = ident.split("[")[0].split(".")[0]
    return re.search(r"(?<![\w.])" + re.escape(head) + r"(?![\w])", bare) is not None


def metrics(code):
    lines = [l for l in code.splitlines() if l.strip()]
    if not lines:
        return None
    n = len(lines)
    return {
        "avg_line_len": st.mean(len(l.rstrip()) for l in lines),
        "max_indent": max((len(l) - len(l.lstrip())) for l in lines),
        "type_annots": len(re.findall(r":\s*[A-Z][\w<>\[\]|]*", code)) / n,
        "comment_ratio": sum(1 for l in lines if l.strip().startswith(("//", "*", "/*"))) / n,
    }


def load(p):
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]


# Changed lines that carry no mechanism: imports, comments, braces, blanks.
# Measured at 33% (TS) / 31% (JS) of every diff, so counting them made real fixes
# look non-minimal for reasons that have nothing to do with the guard.
INCIDENTAL = re.compile(
    r"^\s*(//|/\*|\*|import\b|export\b|const\s+\w+\s*=\s*require|\}|\{|\)\s*;?|\]\s*,?)\s*;?\s*$"
    r"|^\s*$"
)


def semantic_diff(a, b):
    """Changed lines that actually carry mechanism.

    R2 exists so the model cannot key on a feature cheaper than the guard. An
    added import is not such a feature, so it should not count against a pair.

    NOTE: the BOUND stays at 12. A Tukey fence derived from the observed
    distribution came out at 110, which would have accepted 99% of pairs and
    abandoned the rule's purpose -- "typical" is not the same as "safe" when the
    whole distribution is large.
    """
    ch = [l[1:] for l in difflib.unified_diff(a.splitlines(), b.splitlines(),
                                              lineterm="", n=0)
          if l[:1] in "+-" and not l.startswith(("+++", "---"))]
    return sum(1 for l in ch if not INCIDENTAL.match(l))


def main():
    if len(sys.argv) < 2:
        print("usage: scan_ts_standard.py <records.jsonl>")
        return 2
    path = sys.argv[1]
    real_path = sys.argv[2] if len(sys.argv) > 2 else REAL
    recs = load(path)
    real = load(real_path)
    real_by_pid = collections.defaultdict(dict)
    for r in real:
        real_by_pid[r["_meta"]["pair_id"]][r["_meta"]["label"]] = r

    results = []      # (id, ok, detail)
    fails = collections.defaultdict(list)

    is_aug = any(r["_meta"].get("base_pair_id") for r in recs)

    def check(rid, ok, detail=""):
        if not is_aug and rid.split()[0] in AUGMENTATION_ONLY:
            results.append((rid, None, "n/a - harvested set, no base record"))
            return
        results.append((rid, ok, detail))

    # ---- R1 paired -------------------------------------------------------
    byp = collections.defaultdict(list)
    for r in recs:
        byp[r["_meta"]["pair_id"]].append(r["_meta"]["label"])
    bad = {k: v for k, v in byp.items() if sorted(v) != ["safe", "vuln"]}
    check("R1 paired (one vuln + one safe per pair_id)", not bad,
          f"{len(bad)} bad of {len(byp)} pairs")
    for k in list(bad)[:5]:
        fails["R1"].append(f"{k}: {bad[k]}")

    # ---- R2 minimal difference ------------------------------------------
    over = []
    for pid, _ in byp.items():
        rs = [r for r in recs if r["_meta"]["pair_id"] == pid]
        v = next((r for r in rs if r["_meta"]["label"] == "vuln"), None)
        s = next((r for r in rs if r["_meta"]["label"] == "safe"), None)
        if not (v and s):
            continue
        d = semantic_diff(code_of(v), code_of(s))
        if d == 0 or d > MAX_CHANGED_LINES:
            over.append((pid, d))
    check(f"R2 minimal difference (1..{MAX_CHANGED_LINES} SEMANTIC lines)", not over,
          f"{len(over)} pairs outside")
    for pid, d in over[:5]:
        fails["R2"].append(f"{pid}: {d} changed lines")

    # ---- R3 realism vs the base record ----------------------------------
    drift = []
    for r in recs:
        bp = r["_meta"].get("base_pair_id")
        b = real_by_pid.get(bp, {}).get("safe") or real_by_pid.get(bp, {}).get("vuln")
        if not b:
            continue
        mb, mr = metrics(code_of(b)), metrics(code_of(r))
        if not (mb and mr):
            continue
        for k in mb:
            tol = max(0.05, abs(mb[k]) * 0.35)
            if abs(mr[k] - mb[k]) > tol:
                drift.append((r["_meta"]["pair_id"], k, round(mb[k], 3), round(mr[k], 3)))
    check("R3 realism within tolerance of base", not drift, f"{len(drift)} metric drifts")
    for d in drift[:6]:
        fails["R3"].append(str(d))

    # ---- R4 auditable provenance ----------------------------------------
    # `repo`+`sha`+`src_file` pin the exact fix commit; the vuln id may be either
    # a CVE or a GHSA, because 17/223 GHSA advisories carry no CVE alias and a
    # GHSA is equally re-verifiable. See the amendment log in the standard doc.
    need = ("repo", "sha", "src_file")
    missing = []
    for r in recs:
        m = r["_meta"]
        gaps = [k for k in need if not m.get(k)]
        if not (m.get("cve") or m.get("ghsa")):
            gaps.append("cve|ghsa")
        if gaps:
            missing.append((m["pair_id"], gaps))
    check("R4 provenance (repo,sha,src_file + cve|ghsa)", not missing,
          f"{len(missing)} records missing fields")
    for m in missing[:5]:
        fails["R4"].append(str(m))

    # ---- R5 CWE taken from base -----------------------------------------
    mism = []
    for r in recs:
        bp = r["_meta"].get("base_pair_id")
        b = real_by_pid.get(bp, {}).get("vuln")
        if b and b["_meta"]["ground_truth_cwe"] != r["_meta"]["ground_truth_cwe"]:
            mism.append((r["_meta"]["pair_id"], r["_meta"]["ground_truth_cwe"],
                         b["_meta"]["ground_truth_cwe"]))
    check("R5 CWE matches base record", not mism, f"{len(mism)} mismatches")
    for m in mism[:5]:
        fails["R5"].append(str(m))

    # ---- R6 identifiers real --------------------------------------------
    ghost = []
    for r in recs:
        m = re.search(r"trace: (\S+) -> (\S+)", trace_of(r))
        if not m:
            ghost.append((r["_meta"]["pair_id"], "no trace line"))
            continue
        for nm in (m.group(1), m.group(2)):
            if not occurs(nm, code_of(r)):
                ghost.append((r["_meta"]["pair_id"], nm))
    check("R6 trace identifiers occur in code", not ghost, f"{len(ghost)} ghosts")
    for g in ghost[:6]:
        fails["R6"].append(str(g))

    # ---- R7 mechanism, not boilerplate ----------------------------------
    weak = []
    for r in recs:
        t = trace_of(r)
        if "->" not in t:
            weak.append((r["_meta"]["pair_id"], "no source->sink"))
        if any(b.lower() in t.lower() for b in BOILERPLATE):
            weak.append((r["_meta"]["pair_id"], "boilerplate sentence"))
        body = re.search(r"<think>(.*?)</think>", t, re.S)
        if not body or len(body.group(1).split()) < 45:
            weak.append((r["_meta"]["pair_id"], "reasoning too thin"))
    check("R7 mechanism stated, no boilerplate", not weak, f"{len(weak)} weak traces")
    for w in weak[:6]:
        fails["R7"].append(str(w))

    # ---- R8 safe side justified, and guard-justification only on real code ---
    # Source-justified ("not exploitable (...)") is checkable by reading.
    # Guard-justified ("is covered by ...") asserts a guard is ADEQUATE, which is a
    # judgement -- so it is permitted ONLY when the record is the untouched real
    # post-fix code, whose safety the CVE fix itself establishes.
    nj = []
    for r in recs:
        m = r["_meta"]
        if m["label"] != "safe":
            continue
        t = trace_of(r)
        by_source = "not exploitable" in t
        by_guard = ("is covered by" in t) or ("is constrained by" in t)
        # Structure-justified: the safe side is safe because the construct the
        # vulnerability depends on is GONE, not because a check was added. This is
        # the one justification we can verify outright -- guard adequacy is a
        # judgement, but absence is a fact -- so it is accepted only after
        # confirming the named construct really is missing from this code.
        by_structure = "no longer present" in t
        if by_structure:
            gone = m.get("removed_construct", "")
            head = re.split(r"[.(]", gone)[0] if gone else ""
            if not head or occurs(head, code_of(r)):
                nj.append((m["pair_id"],
                           f"claims `{gone}` removed but it is still in the code"))
            continue
        if not (by_source or by_guard):
            nj.append((m["pair_id"], "states no reason"))
            continue
        if by_guard and is_aug:
            # For an AUGMENTATION record, guard-justification asserts that a guard
            # is adequate -- a judgement -- so it is allowed only when the code is
            # byte-identical to the base's real post-fix side.
            #
            # For a HARVESTED record there is nothing to compare against, because
            # the safe side IS the maintainer's post-fix code. The CVE fix itself
            # establishes its safety, which is exactly the condition this rule
            # requires, so the check is satisfied by construction.
            b = real_by_pid.get(m.get("base_pair_id"), {}).get("safe")
            if not b or code_of(b).strip() != code_of(r).strip():
                nj.append((m["pair_id"],
                           "guard-justified but code is not untouched real post-fix"))
    check("R8 safe side justified (guard-justified => real post-fix only)", not nj,
          f"{len(nj)} unjustified")
    for x in nj[:5]:
        fails["R8"].append(str(x))

    # ---- R9 safe side derives from post-fix code ------------------------
    bad9 = [r["_meta"]["pair_id"] for r in recs
            if r["_meta"]["label"] == "safe"
            and r["_meta"].get("derived_from") not in ("real_safe", None)]
    check("R9 safe side derived from real post-fix code", not bad9, f"{len(bad9)} not derived")

    # ---- R10 no eval leakage --------------------------------------------
    import glob
    import os
    evalcodes = set()
    for p in glob.glob(os.path.join(EVAL_GLOB, "*.jsonl")):
        for r in load(p):
            evalcodes.add(re.sub(r"\s+", " ", code_of(r)).strip().lower())
    leaks = [r["_meta"]["pair_id"] for r in recs
             if re.sub(r"\s+", " ", code_of(r)).strip().lower() in evalcodes]
    check("R10 no eval leakage", not leaks, f"{len(leaks)} leaked")

    # ---- R11 size --------------------------------------------------------
    sz = [(r["_meta"]["pair_id"], len(code_of(r))) for r in recs
          if not (MIN_CHARS <= len(code_of(r)) <= MAX_CHARS)]
    check(f"R11 size {MIN_CHARS}..{MAX_CHARS} chars", not sz, f"{len(sz)} out of range")
    for s in sz[:5]:
        fails["R11"].append(str(s))

    # ---- R12 balance -----------------------------------------------------
    lab = collections.Counter(r["_meta"]["label"] for r in recs)
    check("R12 balanced vuln/safe", lab.get("vuln", 0) == lab.get("safe", 0), str(dict(lab)))

    # ---- R15 no mass-duplicated reasoning --------------------------------
    # R7 only knows three blocklisted sentences, so it cannot see a NEW template.
    # shape1_cvefixes repeats one byte-identical <think> body 1,406 times (42%) and
    # shape1_sft 8,010 times (43%), and both sail through R7 because the text is
    # long enough and not on the list. A trace that is identical across thousands of
    # different files is not reasoning about any of them.
    #
    # Our own generated sets are templated too, but they INTERPOLATE the source,
    # sink, guard and CWE, so every trace differs: the largest duplicate in any
    # shipped set is 4 records. The threshold separates the two cleanly.
    # A shape with NO <think> block used to be skipped entirely here, so
    # shape3_codeql_localize -- whose answer is `source/sink/path/why` -- was never
    # checked for duplication at all. The reasoning of such a shape is its answer
    # body, so that is what gets hashed; the volatile parts (paths, line numbers,
    # CWE ids) are normalised first, because a template with locations swapped in is
    # still one template. <think> bodies keep the byte-identical test: those sets
    # interpolate the source, sink and guard, so their text genuinely differs.
    bodies = collections.Counter()
    for r in recs:
        t = trace_of(r)
        b = re.search(r"<think>(.*?)</think>", t, re.S)
        if b:
            bodies[b.group(1).strip()] += 1
        else:
            bodies[re.sub(r"\s+", " ", t).strip()] += 1
    worst = bodies.most_common(1)[0] if bodies else ("", 0)
    cap = max(3, int(0.05 * len(recs)))
    check("R15 reasoning not mass-duplicated",
          worst[1] <= cap,
          f"largest identical trace: {worst[1]} records (cap {cap})")
    if worst[1] > cap:
        fails["R15"].append(f"{worst[1]}x: {worst[0][:90]!r}")

    # ---- R17 reasoning is not ONE template -------------------------------
    # R15 compares text byte-for-byte, so a template with the file paths swapped in
    # slips past it: shape3_codeql_localize said "untrusted input enters at X and
    # reaches Y with no sanitiser between them" on 100% of 7,149 records and every
    # one was unique, because X and Y differed. R7 only catches templates already on
    # its blocklist, so a NEW one is invisible to both.
    #
    # So: normalise the volatile parts and ask what share of the set collapses onto a
    # single sentence. The threshold is deliberately loose. Legitimate reasoning DOES
    # repeat -- the mechanism of log injection at `logging.debug` is the same sentence
    # every time it is true, and the diversity of a mechanism text is bounded by the
    # number of (weakness class, sink) pairs, not by the record count. 60% separates
    # "this set has one thing to say" from "this set says the same thing about
    # everything": the old codeql sat at 92%, the repaired one at 11%.
    shapes_norm = collections.Counter()
    for r in recs:
        n = re.sub(r"[\w./-]+:\d+", "<loc>", trace_of(r))
        n = re.sub(r"CWE-\d+", "<cwe>", n)
        n = re.sub(r"`[^`\n]*`", "<tok>", n)
        shapes_norm[re.sub(r"\s+", " ", n).strip()] += 1
    # Threshold calibrated against the whole corpus rather than guessed. Measured
    # largest-template share on all 23 shipped shapes: `shape1_r2vul_clean` 0.0%,
    # most attested sets under 3%, `shape3_codeql_localize` 26.2% (its worst class is
    # log-injection-at-`logging.debug`, where the mechanism genuinely is one sentence),
    # against the old codeql template at 91.7%. 35% clears the worst legitimate set by
    # nine points and still fails the known-bad one by a wide margin.
    #
    # MIN_FOR_TEMPLATE exists because share is meaningless on a tiny set:
    # `shape_completeness_js` has 2 records, so one of them is "50%" and any threshold
    # under that would fail a set with no template in it at all.
    MIN_FOR_TEMPLATE = 20
    tw = shapes_norm.most_common(1)[0] if shapes_norm else ("", 0)
    share = tw[1] / len(recs) if recs else 0
    too_templated = len(recs) >= MIN_FOR_TEMPLATE and share > 0.35
    check("R17 reasoning not one template",
          not too_templated,
          f"largest template covers {tw[1]}/{len(recs)} ({share:.0%})"
          + ("" if len(recs) >= MIN_FOR_TEMPLATE else " -- set too small to judge"))
    if too_templated:
        fails["R17"].append(f"{share:.0%}: {tw[0][:90]!r}")

    # ---- R14 not test code -----------------------------------------------
    # A test's "vulnerability" is a fixture and its guard is an assertion, so a
    # verdict on it teaches nothing about production risk. CVE-2023-27582 reached
    # the contrastive set as a SASL stub full of `t.Run`/`t.Error`, labelled and
    # CWE'd like real code. Applies to every set, harvested or authored.
    from filter_corpus import is_test_code
    tests = [r["_meta"]["pair_id"] for r in recs if is_test_code(code_of(r))]
    check("R14 code under test, not test code", not tests, f"{len(tests)} test excerpts")
    for t in tests[:6]:
        fails["R14"].append(str(t))

    # ---- R13 coverage: no candidate silently skipped ----------------------
    # A scanner over EMITTED records cannot see a record that was never emitted.
    # CWE-59 (openclaw browser/paths.ts) was skipped on the assumption that its
    # comparison site was not in the excerpt -- it was, and nothing noticed.
    # So: enumerate the candidate bases independently, and require every one to be
    # either BUILT or listed in EXCLUSIONS with a reason.
    if any(r["_meta"].get("base_pair_id") for r in recs):
        try:
            from ts_augment_edits import EXCLUSIONS
        except Exception:
            EXCLUSIONS = {}
        # A set may ship its own accounting alongside it. R13 exists so nothing is
        # skipped SILENTLY -- a machine-written sidecar with a per-base reason meets
        # that as well as a hand-written registry, and is the only workable form when
        # the candidate pool is in the hundreds.
        side = os.path.splitext(path)[0] + ".exclusions.tsv"
        if os.path.exists(side):
            import csv as _csv
            EXCLUSIONS = dict(EXCLUSIONS)
            for row in _csv.DictReader(open(side, encoding="utf-8"), delimiter="\t"):
                EXCLUSIONS[row["base_pair_id"]] = row["reason"]
        # a base is a candidate if the FIX introduced one of these sanitisers
        SANITISERS = {
            "global_replace": re.compile(r"\.replace\(\s*/[^/]+/[a-z]*g"),
            "finite_guard": re.compile(r"Number\.isFinite|isNaN\(|Number\.isInteger"),
            "startswith": re.compile(r"\.startsWith\("),
            "realpath": re.compile(r"realpath"),
            "timing_safe": re.compile(r"timingSafeEqual|safeEqualSecret"),
            "allowlist": re.compile(r"(allow|Allow)[\w]*\.(includes|has)\("),
            "quote_fn": re.compile(r"\bquote\("),
            "basename": re.compile(r"basename\("),
            "proto_block": re.compile(r"__proto__|hasOwnProperty"),
            "sanitize_fn": re.compile(r"encodeURI|escapeHtml|escapeHTML|sanitize"),
        }
        candidates = {}
        for pid, sides in real_by_pid.items():
            if "safe" not in sides or "vuln" not in sides:
                continue
            sc, vc = code_of(sides["safe"]), code_of(sides["vuln"])
            hit = [k for k, rx in SANITISERS.items() if len(rx.findall(sc)) > len(rx.findall(vc))]
            if hit:
                candidates[pid] = (sides["vuln"]["_meta"]["ground_truth_cwe"],
                                   sides["vuln"]["_meta"].get("repo", ""), hit)
        built = {r["_meta"].get("base_pair_id") for r in recs}
        unaccounted = [(pid,) + candidates[pid] for pid in candidates
                       if pid not in built and pid not in EXCLUSIONS]
        n_built = len([p for p in candidates if p in built])
        n_excl = len([p for p in candidates if p in EXCLUSIONS])
        check(f"R13 coverage ({len(candidates)} candidates: {n_built} built, {n_excl} excluded)",
              not unaccounted, f"{len(unaccounted)} unaccounted for")
        for u in unaccounted[:8]:
            fails["R13"].append(f"{u[0]} {u[1]} {u[2]} {u[3]} - build it or add to EXCLUSIONS")
        # an exclusion must carry a real reason, not a placeholder
        thin = [k for k, v in EXCLUSIONS.items() if len(v.split()) < 12]
        check("R13b exclusion reasons are substantive", not thin,
              f"{len(thin)} reasons under 12 words")
        for t in thin[:5]:
            fails["R13b"].append(f"{t}: reason too thin")

    # ---- report ----------------------------------------------------------
    print(f"=== {path} : {len(recs)} records, {len(byp)} pairs ===\n")
    npass = nappl = 0
    for rid, ok, detail in results:
        # None means the rule does not apply to this kind of set. Printed as N/A
        # and excluded from the tally -- reporting it as PASS would be a silent skip.
        tag = "N/A " if ok is None else ("PASS" if ok else "FAIL")
        print(f"  [{tag}] {rid:52s} {detail}")
        if ok is not None:
            nappl += 1
            npass += 1 if ok else 0
    print(f"\n  {npass}/{nappl} applicable requirements pass"
          f"  ({len(results) - nappl} n/a)")
    if fails:
        print("\n--- examples ---")
        for k, v in fails.items():
            for line in v[:4]:
                print(f"  {k}: {line}")
    ok_all = npass == nappl
    print("\nRESULT:", "PASS - safe to ship" if ok_all else "FAIL - do not ship")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
