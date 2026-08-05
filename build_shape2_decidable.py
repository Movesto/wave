"""Counter-cases for shape2: an unresolved import that does NOT block the verdict.

`shape2` is 113 records and every one is labelled `needs_context`. Nothing in the corpus
shows a case where a module is imported and unresolved and the answer is still decidable,
so "I cannot see the helper, therefore I withhold" is learnable as a shortcut -- the
mirror image of "the topic looks dangerous, therefore vulnerable". A model that withholds
whenever an import appears is as wrong as one that guesses; it just fails quietly.

These records are MINED, not authored. Each is an already-attested contrastive record
(real CVE, CISA/OSV CWE) that happens to contain an unresolved import, re-framed to say
why the import does not matter here.

The honesty condition, which is what makes this a fair counter-case rather than a trick:
the unresolved import must NOT lie on the source -> sink path. If the sink itself came
from the module we cannot see, withholding would be the RIGHT answer and this record
would teach the opposite. So a candidate is rejected when the source or the sink is one
of the names the import binds.

    python build_shape2_decidable.py --write
"""
import argparse
import collections
import csv
import json
import os
import re
import sys

from filter_corpus import is_test_code, load_eval_codes
from scan_ts_standard import code_of, trace_of

SOURCES = ("shape1_contrastive_attested", "shape1_contrastive_ts_osv",
           "shape1_contrastive_js_osv", "shape1_contrastive_r2vul",
           "shape1_contrastive_react_osv")
OUT = "data/cot/staging/shape2_decidable.jsonl"
REPORT = "data/osv/shape2_decidable.tsv"
MIN_CHARS, MAX_CHARS = 120, 4500

# import forms, and the names each binds
IMPORT_LINE = re.compile(
    r"^\s*(?:import\s+(?P<a>[^;\n]+?)\s+from\s*['\"](?P<m1>[^'\"]+)['\"]"
    r"|from\s+(?P<m2>[\w.]+)\s+import\s+(?P<b>[^\n]+)"
    r"|(?:const|let|var)\s+(?P<c>[^=\n]+?)\s*=\s*require\(\s*['\"](?P<m3>[^'\"]+)['\"])",
    re.M)


# Modules that ARE the dangerous capability. If the unresolved import is one of these,
# "what the module does cannot change the flow" is not a claim we can make: a CWE-77
# record importing `child_process`, or a CWE-918 record importing `@/utils/got`, has its
# sink behind exactly the import being dismissed. Caught on a hand-read after the record
# passed the source/sink and guard conditions.
SINK_MODULES = re.compile(
    r"(^|/)(child_process|fs|fs/promises|vm|got|axios|request|node-fetch|undici|"
    r"superagent|sqlite3|mysql|mysql2|pg|knex|mongodb|redis|shelljs|execa|"
    r"serialize-javascript|js-yaml|xml2js|libxmljs|dompurify|ejs|pug|handlebars"
    # python: `os` carries os.system, `subprocess` the exec family, and the
    # deserialisers are sinks in their own right.
    r"|os|os\.path|subprocess|commands|popen2|pickle|cPickle|shelve|marshal|yaml|"
    r"lxml|xml|xml\.etree|xml\.sax|requests|urllib|urllib2|urllib\.request|"
    r"httplib|http\.client|sqlite3|psycopg2|MySQLdb|jinja2|mako)$")


def imported_names(code):
    """(bound names, module specifiers) for every import in the excerpt."""
    names, mods = set(), set()
    for m in IMPORT_LINE.finditer(code):
        mods.update(x for x in (m.group("m1"), m.group("m2"), m.group("m3")) if x)
        blob = next((x for x in (m.group("a"), m.group("b"), m.group("c")) if x), "")
        blob = blob.replace("{", " ").replace("}", " ").replace("*", " ")
        for part in re.split(r"[,\s]+", blob):
            part = part.strip()
            if part and part.lower() not in ("as", "default", "type"):
                names.add(part)
    return names, mods


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    evalcodes = load_eval_codes()
    out, report, f = [], [], collections.Counter()
    seen = set()

    for shape in SOURCES:
        path = f"data/cot/staging/{shape}.jsonl"
        if not os.path.exists(path):
            continue
        for line in open(path, encoding="utf-8"):
            r = json.loads(line)
            m = r["_meta"]
            code = code_of(r)
            names, mods = imported_names(code)
            if not mods:
                continue
            f["has_import"] += 1

            body = trace_of(r)
            tm = re.search(r"^trace:\s*(\S+)\s*->\s*(\S+)", body, re.M)
            if not tm:
                f["no_trace_line"] += 1
                continue
            src, snk = tm.group(1).strip("`"), tm.group(2).strip("`")

            # The whole point: the flow must be visible HERE.
            if not (re.search(r"\b" + re.escape(src.split(".")[0]) + r"\b", code)
                    and re.search(r"\b" + re.escape(snk.split(".")[0]) + r"\b", code)):
                f["flow_not_visible"] += 1
                continue
            # ...and the unresolved module must not be what the flow runs through.
            if {src.split(".")[0], snk.split(".")[0]} & names:
                f["sink_or_source_is_imported"] += 1
                continue

            # On a SAFE record the guard is what decides the verdict, so it is subject
            # to the same condition as the sink. Without this, RSSHub's safe side --
            # which imports `@/utils/valid-host`, the very SSRF host validator that
            # makes it safe -- was claiming the unresolved module could not matter,
            # while the module was the entire reason for the verdict.
            guard = None
            if m.get("label") == "safe":
                gm = re.search(r"constrained by `([^`]+)`", body) or \
                     re.search(r"control is `([^`]+)`", body)
                if not gm:
                    f["safe_without_stated_guard"] += 1
                    continue
                guard = gm.group(1)
                gidents = set(re.findall(r"[A-Za-z_][A-Za-z_0-9]*", guard))
                if gidents & names:
                    f["guard_is_imported"] += 1
                    continue
                if guard.split("(")[0].strip() not in code:
                    f["guard_not_in_excerpt"] += 1
                    continue
            if not (MIN_CHARS <= len(code) <= MAX_CHARS) or is_test_code(code):
                f["size_or_test"] += 1
                continue
            if re.sub(r"\s+", " ", code).strip().lower() in evalcodes:
                f["eval_leakage"] += 1
                continue
            key = re.sub(r"\s+", "", code)
            if key in seen:
                f["duplicate"] += 1
                continue
            seen.add(key)

            # Report an import that is genuinely incidental. If every import in the
            # excerpt is a capability module, there is no honest counter-case to make.
            benign = sorted(x for x in mods if not SINK_MODULES.search(x))
            if not benign:
                f["all_imports_are_sink_modules"] += 1
                continue

            cwe = m.get("ground_truth_cwe", "")
            label = m.get("label")
            unresolved = benign[0]
            vuln = label == "vuln"
            verdict = ("status: confirmed\n"
                       f"cwe: {cwe}\nseverity: HIGH\n"
                       f"trace: {src} -> {snk}\n"
                       f"fix: constrain `{src}` before it reaches `{snk}`") if vuln else (
                      "status: safe\ncwe: none\nseverity: none\n"
                      f"trace: {src} -> {snk} is constrained by `{guard[:80]}`\n"
                      f"fix: none")
            outcome = (f"and find none, so the value arrives as the caller chose it "
                       f"and the hypothesis stands. Confirmed {cwe}."
                       if vuln else
                       f"and find `{guard[:80]}` on it -- present in this excerpt, not "
                       f"behind the import -- so the hypothesis is refuted.")
            think = (
                f"Hypothesis: `{src}` reaches `{snk}` - the shape of {cwe}.\n"
                f"Unresolved import: `{unresolved}` is imported and its body is not in "
                f"this excerpt. That is only a reason to withhold if the verdict depends "
                f"on it, so I check whether it lies on this path.\n"
                f"Trigger path: `{src}` flows to `{snk}` entirely within the code shown, "
                f"and `{unresolved}` binds none of the names on that path. What the "
                f"module does cannot change the flow I can already see.\n"
                f"Defensive check: I read the path for a control on `{src}`, {outcome}")

            mm = dict(m)
            mm.update(shape="shape2_decidable", source="shape2_decidable_mined",
                      carved_from=shape, unresolved_import=unresolved)
            mm.pop("pair_id", None)   # re-framed singles, not a pair set
            out.append({"messages": [
                {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                {"role": "assistant",
                 "content": f"<think>\n{think}\n</think>\n{verdict}"}], "_meta": mm})
            report.append(dict(carved_from=shape, cve=m.get("cve", ""), cwe=cwe,
                               label=label, unresolved=unresolved,
                               src=src[:40], snk=snk[:40]))
            f["BUILT"] += 1

    for k, v in f.most_common():
        print(f"  {k:28s} {v:5d}")
    if args.write and out:
        with open(OUT, "w", encoding="utf-8") as fh:
            for r in out:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        with open(REPORT, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(report[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(report)
        print(f"\n-> {OUT} ({len(out)} records)\n-> {REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
