"""Produce the r2vul set we are willing to train on. Fix what can be fixed, drop the rest.

Three repairs, in order of how much they recover:

  PROSE REPAIR   a record whose `trace:` claim is grounded but whose prose names
                 an absent identifier loses that SENTENCE, not the record. If what
                 remains still states a mechanism (R7's 45-word floor), the record
                 is clean; if removing it guts the reasoning, the record is dropped
                 rather than shipped thin.
  CWE RESOLUTION records with no CWE take one from CISA vulnrichment, keyed on the
                 CVE recovered during re-identification. Authoritative, not guessed.
  DROP           excerpts outside the size limit and claims that name absent code.
                 A 52-char minified function cannot teach reasoning at any label,
                 and a broken claim actively teaches the wrong thing.

    python finalize_r2vul.py --write
"""
import argparse
import collections
import csv
import json
import os
import re
import sys

from filter_corpus import is_test_code, load_eval_codes, named_identifiers
from scan_ts_standard import BOILERPLATE, code_of, trace_of

OUT = "data/cot/staging/shape1_r2vul_clean.jsonl"
DROPPED = "data/osv/r2vul_dropped.tsv"
MIN_CHARS, MAX_CHARS = 120, 6000
MIN_WORDS = 45


def cwe_from_vulnrichment(cve):
    if not cve or not cve.startswith("CVE-"):
        return []
    try:
        _, year, num = cve.split("-", 2)
    except ValueError:
        return []
    bucket = f"{num[:-3]}xxx" if len(num) > 3 else "0xxx"
    path = f"data/downloads/vulnrichment/{year}/{bucket}/{cve}.json"
    if not os.path.exists(path):
        return []
    try:
        d = json.load(open(path, encoding="utf-8"))
    except Exception:
        return []
    out = []
    for c in d.get("containers", {}).get("adp", []) + [d.get("containers", {}).get("cna", {})]:
        for p in (c or {}).get("problemTypes", []):
            for desc in p.get("descriptions", []):
                cid = desc.get("cweId")
                if cid and cid.startswith("CWE-"):
                    out.append(cid)
    return sorted(set(out))


def split_sentences(text):
    return re.split(r"(?<=[.;])\s+|\n", text)


def prose_repair(assistant, code):
    """WITHDRAWN. Deleting sentences damaged the reasoning instead of fixing it.

    This removed any sentence naming a backticked identifier absent from the code.
    Reading what it actually deleted from 4,211 records settled it:

        CVE-2023-43256  "if an attacker provides `../../etc/` as the `folder`
                         parameter and `passwd` as the `file` parameter..."
        CVE-2021-32641  "Specifically, the line `return html ? React.createElement(
                         'span', { dangerouslySetInnerHTML: ... })` takes..."
        CVE-2022-31083  "The introduction of the `rootCertificateUrl` property in
                         later versions ... addresses this issue by..."

    The first is the exploit example, the second quotes the vulnerable line, the
    third explains the fix. `../../etc/` and `passwd` are ATTACKER-SUPPLIED values
    -- they are absent from the source precisely because they are the attack --
    and `rootCertificateUrl` belongs to the fixed revision. All three are signs of
    good reasoning that the test scored as hallucination, the same class of error
    as counting a predicted exception or a contrasted unsafe function as a ghost.

    These traces are the R2Vul authors' text, not ours. A prose-only ungrounded
    name is now flagged by R6b and kept, because the `trace:` claim the verdict
    rests on is grounded either way. Nothing is edited.
    """
    return assistant


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    tri = {(r["shape"], int(r["line"])): r
           for r in csv.DictReader(open("data/osv/r2vul_triage.tsv", encoding="utf-8"),
                                   delimiter="\t")}

    evalcodes = load_eval_codes()
    kept, dropped, tally = [], [], collections.Counter()
    for d in ("data/cot/pilot/", "data/cot/staging/"):
        for f in sorted(os.listdir(d)):
            if not f.endswith(".jsonl"):
                continue
            shape = f[:-6]
            for i, line in enumerate(open(d + f, encoding="utf-8")):
                t = tri.get((shape, i))
                if not t:
                    continue
                r = json.loads(line)
                m = r["_meta"]
                code = code_of(r)
                v = t["verdict"]

                if v in ("RECUT_EXCERPT", "TRACE_UNREBUILDABLE"):
                    tally["drop:size_or_unrebuildable"] += 1
                    dropped.append(dict(shape=shape, line=i, why=v, cve=t["cve"],
                                        chars=len(code), ghost=t["ghost"]))
                    continue
                if v == "REGENERATE_TRACE":
                    tally["drop:claim_names_absent_code"] += 1
                    dropped.append(dict(shape=shape, line=i, why=v, cve=t["cve"],
                                        chars=len(code), ghost=t["ghost"]))
                    continue

                if v == "PROSE_BLEMISH_ONLY":
                    fixed = prose_repair(r["messages"][1]["content"], code)
                    if not fixed:
                        tally["drop:prose_repair_guts_reasoning"] += 1
                        dropped.append(dict(shape=shape, line=i, why="prose_unrepairable",
                                            cve=t["cve"], chars=len(code), ghost=t["ghost"]))
                        continue
                    m["note"] = ("R6b: claim grounded; prose names an identifier "
                                 "absent from the code (exploit value, fixed-revision "
                                 "construct, or contrasted alternative)")
                    tally["kept:prose_flagged_not_edited"] += 1

                if not m.get("ground_truth_cwe"):
                    got = cwe_from_vulnrichment(t["cve"])
                    if len(got) == 1:
                        m["ground_truth_cwe"], m["cwes"] = got[0], got
                        m["cwe_source"] = "cisa_vulnrichment"
                        tally["fix:cwe_from_vulnrichment"] += 1
                    else:
                        up = [c.strip() for c in (t["cwe_upstream"] or "").split("|")
                              if c.strip().startswith("CWE-")]
                        if len(up) == 1:
                            m["ground_truth_cwe"], m["cwes"] = up[0], up
                            m["cwe_source"] = "r2vul_upstream"
                            tally["fix:cwe_from_upstream"] += 1
                        else:
                            tally["drop:no_resolvable_cwe"] += 1
                            dropped.append(dict(shape=shape, line=i, why="no_cwe",
                                                cve=t["cve"], chars=len(code), ghost=""))
                            continue

                # final gate: the record must now actually pass
                a = r["messages"][1]["content"]
                th = re.search(r"<think>(.*?)</think>", a, re.S)
                # Grounding is required of the CLAIM -- the `trace:` line the
                # verdict rests on. Prose may legitimately name an exploit value,
                # a construct from the fixed revision, or a dangerous alternative
                # being contrasted; none of those are in the code and none are
                # defects. R6b records that and the record is kept.
                claim = re.search(r"^trace:.*$", a, re.M)
                claim_txt = claim.group(0) if claim else ""
                bad = (is_test_code(code)          # R14
                       or re.sub(r"\s+", " ", code).strip().lower() in evalcodes
                       or not (MIN_CHARS <= len(code) <= MAX_CHARS)
                       or any(b.lower() in a.lower() for b in BOILERPLATE)
                       or not th or len(th.group(1).split()) < MIN_WORDS
                       or any(not re.search(r"(?<![\w])" + re.escape(x) + r"(?![\w])", code)
                              for x in named_identifiers(claim_txt)))
                if bad:
                    tally["drop:failed_final_gate"] += 1
                    dropped.append(dict(shape=shape, line=i, why="failed_final_gate",
                                        cve=t["cve"], chars=len(code), ghost=t["ghost"]))
                    continue

                if t["cve"]:
                    m["cve"], m["repo"], m["sha"] = t["cve"], t["repo"], t["sha"]
                    m["src_file"] = t["file"]
                m["source"] = "r2vul_clean"
                kept.append(r)
                tally["KEPT"] += 1

    for k, v in tally.most_common():
        print(f"  {k:36s} {v:6d}")
    lab = collections.Counter(r["_meta"].get("label") for r in kept)
    print(f"\n  kept {len(kept)} / {len(kept)+len(dropped)} = "
          f"{100*len(kept)/(len(kept)+len(dropped)):.1f}%   labels {dict(lab)}")

    if args.write:
        with open(OUT, "w", encoding="utf-8") as fh:
            for r in kept:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        with open(DROPPED, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(dropped[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(dropped)
        print(f"\n-> {OUT}\n-> {DROPPED} ({len(dropped)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
