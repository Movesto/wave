"""Rebuild the contrastive pairs to the standard, split by what they actually are.

The set is three different things under one name:

    real              12,390   upstream unidentified -> R4 cannot pass
    vuln_fix_dataset   2,000   ALL Java, synthetic:True -> quarantined, not mixed in
    primevul             304   carries cve/cwe/commit_id upstream -> R4 recoverable

Regenerating these traces is legitimate: they came from cot/deep_trace.py, which is
ours. That is the distinction the r2vul revert established -- the R2Vul prose is the
authors' and must not be edited, this is our own template output and may be.

The guard is re-derived by DIFFING the two revisions rather than trusted from the
existing trace, because 2,408 pairs re-derive a different source than they claim --
`TSS2_SYS_CONTEXT`, a TPM2 struct type, was named as an attacker-controlled value.

Pairs whose fix adds no quotable control go to the restructure shape instead of
being dropped; that shape exists precisely for them.

    python rebuild_contrastive.py --write
"""
import argparse
import collections
import hashlib
import json
import os
import re
import sys

from build_r2vul_pairs import (added_lines, pick_guard, pick_sink, pick_source,
                               standalone)
from build_r2vul_pairs import record as guard_record
from build_crossfile_restructure import _CWE_FOR
from build_r2vul_restructure import pick_removal
from build_r2vul_restructure import record as restructure_record
from cwe_disambiguation import resolve as resolve_cwe
from scan_ts_standard import code_of

SRC = "data/cot/staging/shape1_contrastive.jsonl"
OUT_GUARD = "data/cot/staging/shape1_contrastive_rebuilt.jsonl"
# Split by whether R4 can pass. Mixing them makes the whole file read as
# FAIL and hides that some pairs are fully attested.
OUT_GUARD_ATT = "data/cot/staging/shape1_contrastive_attested.jsonl"
OUT_RESTR = "data/cot/staging/shape_restructure_contrastive.jsonl"
OUT_SYN = "data/cot/staging/shape1_contrastive_syn_java.jsonl"
REPORT = "data/osv/contrastive_rebuild.tsv"
HELD = "data/osv/contrastive_held.tsv"
MIN_CHARS, MAX_CHARS = 120, 4500


def norm(code):
    return hashlib.sha1(re.sub(r"\s+", "", code).encode("utf-8", "replace")).hexdigest()


def primevul_index():
    """func text -> provenance. PrimeVul stores everything R4 wants; the original
    builder simply never carried it across."""
    idx = {}
    for p in ("data/downloads/PrimeVul/primevul_train_paired.jsonl",
              "data/downloads/PrimeVul/primevul_valid_paired.jsonl"):
        if not os.path.exists(p):
            continue
        for line in open(p, encoding="utf-8"):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            fn = (r.get("func") or "").strip()
            if len(fn) < 40:
                continue
            cwes = r.get("cwe") or []
            idx[norm(fn)] = {
                "cve": r.get("cve") or "",
                "repo": r.get("project") or "",
                "sha": r.get("commit_id") or "",
                "src_file": r.get("file_name") or "",
                "cwe_upstream": "|".join(cwes) if isinstance(cwes, list) else str(cwes),
            }
    return idx


def load_lineage():
    """pair_id -> cve + authoritative CWE, from both resolvers.

    CISA vulnrichment first (it cites the fix commit directly), then OSV, which
    answers the opposite question -- which advisories CONTAIN this commit -- and
    resolved 57% of shas against vulnrichment's 12%.
    """
    import csv as _csv
    out = {}
    for path, src in (("data/osv/sha_to_cve_osv.tsv", "osv"),
                      ("data/osv/sha_to_cve.tsv", "cisa_vulnrichment")):
        if not os.path.exists(path):
            continue
        for r in _csv.DictReader(open(path, encoding="utf-8"), delimiter="\t"):
            r["cwe_source"] = src
            out[r["pair_id"]] = r          # cisa listed last so it wins
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    from filter_corpus import is_test_code, load_eval_codes
    evalcodes = load_eval_codes()
    pv = primevul_index()
    print(f"primevul index: {len(pv)} functions", flush=True)

    lineage = load_lineage()
    print(f"lineage (cve + authoritative cwe): {len(lineage)} pairs", flush=True)

    pairs = collections.defaultdict(dict)
    for line in open(SRC, encoding="utf-8"):
        r = json.loads(line)
        pairs[r["_meta"]["pair_id"]][r["_meta"]["label"]] = r

    guard_out, restr_out, syn_out, report, held = [], [], [], [], []
    f = collections.Counter()

    for pid, sides in pairs.items():
        v, s = sides.get("vuln"), sides.get("safe")
        if not v or not s:
            f["incomplete_pair"] += 1
            continue
        m = v["_meta"]
        origin = m.get("origin", "")

        # Synthetic Java is quarantined, never blended. shape_react_syn scored 100%
        # while real react scored 41.2% in the same eval -- synthetic data flatters
        # itself and does not transfer, so it must stay separable and low-weight.
        if origin == "vuln_fix_dataset" or m.get("synthetic"):
            syn_out.extend([v, s])
            f["quarantined_synthetic"] += 1
            continue

        vc, sc = code_of(v), code_of(s)
        if not (MIN_CHARS <= len(vc) <= MAX_CHARS and MIN_CHARS <= len(sc) <= MAX_CHARS):
            f["size"] += 1
            held.append(dict(pair_id=pid, reason="size", detail="",
                             language=m.get("language", ""), cve="",
                             repo="", sha=""))
            continue
        if any(re.sub(r"\s+", " ", x).strip().lower() in evalcodes for x in (vc, sc)):
            f["eval_leakage"] += 1
            held.append(dict(pair_id=pid, reason="eval_leakage", detail="",
                             language=m.get("language", ""), cve="",
                             repo="", sha=""))
            continue
        # R14: a test's vulnerability is a fixture and its guard is an assertion.
        if is_test_code(vc) or is_test_code(sc):
            f["test_code"] += 1
            held.append(dict(pair_id=pid, reason="test_code",
                             detail="excerpt is test code, not the software under test",
                             language=m.get("language", ""), cve="", repo="", sha=""))
            continue
        if not (1 <= len(added_lines(vc, sc)) <= 24):
            f["diff_too_large_or_empty"] += 1
            held.append(dict(pair_id=pid, reason="diff_too_large_or_empty", detail="",
                             language=m.get("language", ""), cve="",
                             repo="", sha=""))
            continue

        prov = pv.get(norm(vc)) or pv.get(norm(sc)) or {}
        if prov:
            f["provenance_recovered"] += 1
        derived = m.get("ground_truth_cwe") or ""
        cwe, cwe_src, lin = derived, "derived_by_classifier", lineage.get(pid)

        up = [c for c in (prov.get("cwe_upstream") or "").split("|") if c.startswith("CWE-")]
        if not cwe and len(up) == 1:
            cwe, cwe_src = up[0], "primevul"
            f["cwe_from_primevul"] += 1

        # An authoritative CWE REPLACES the derived one, it does not sit beside it.
        # The classifier agreed with CISA/OSV on only 20.1% of 3,215 records -- it
        # put CWE-78 on SSRF fixes and CWE-22 on SQL injection -- so keeping the
        # guess where a real label exists would preserve a 4-in-5 error rate.
        if lin:
            auth = [c for c in (lin.get("cwe_authoritative") or "").split("|")
                    if c.startswith("CWE-")]
            if len(auth) == 1:
                if derived and auth[0] != derived:
                    f["cwe_CORRECTED"] += 1
                cwe, cwe_src = auth[0], lin["cwe_source"]
            elif len(auth) > 1:
                # Ambiguous advisory. Falling back to the classifier would keep a
                # label that is wrong 4 times in 5, so instead let the classifier
                # act only as a TIEBREAK: if its guess is one of the authoritative
                # options, that option is corroborated and we take it. If not, the
                # record has no trustworthy label and must not claim one.
                if derived in auth:
                    cwe, cwe_src = derived, lin["cwe_source"] + "_corroborated"
                    f["cwe_tiebroken_by_agreement"] += 1
                    hand = None
                else:
                    hand, _why = resolve_cwe(lin.get("cve", ""))
                if hand:
                    cwe, cwe_src = hand, "hand_resolved_by_reading"
                    f["cwe_hand_resolved"] += 1
                elif derived not in auth:
                    cwe, cwe_src = "", "unresolved_ambiguous"
                    f["cwe_ambiguous_no_trustworthy_label"] += 1
                    held.append(dict(pair_id=pid, reason="cwe_ambiguous",
                                     detail=f"advisory lists {len(auth)} CWEs "
                                            f"({lin.get('cwe_authoritative')}) and the "
                                            f"classifier's {derived or 'none'} is not "
                                            f"among them",
                                     language=m.get("language", ""),
                                     cve=(lin or {}).get("cve", ""),
                                     repo=(lin or {}).get("repo", ""),
                                     sha=(lin or {}).get("sha", "")))
        if not cwe:
            f["no_cwe"] += 1
            continue

        meta = dict(language=m.get("language", ""),
                    cve=(lin or {}).get("cve") or prov.get("cve", ""),
                    repo=(lin or {}).get("repo") or prov.get("repo", ""),
                    sha=(lin or {}).get("sha") or prov.get("sha", ""),
                    src_file=(lin or {}).get("src_file") or prov.get("src_file", ""),
                    cwe_source=cwe_src,
                    cwe_derived_was=derived if (lin and derived != cwe) else "",
                    upstream_origin=origin,
                    provenance=("osv/cisa" if lin else
                                ("primevul" if prov else "unidentified")),
                    fix_status="rebuilt_from_pair")

        guard = pick_guard(vc, sc)
        if guard:
            src = pick_source(guard, vc, sc)
            snk = pick_sink(vc, src) if src else None
            if src and snk and snk != src and standalone(snk, vc) and standalone(snk, sc):
                guard_out.append(guard_record(vc, "vuln", cwe, src, snk, guard, meta, pid))
                guard_out.append(guard_record(sc, "safe", cwe, src, snk, guard, meta, pid))
                f["GUARD_PAIR"] += 1
                report.append(dict(pair_id=pid, kind="guard", origin=origin,
                                   language=m.get("language", ""), cwe=cwe,
                                   source=src, sink=snk, guard=guard[:100],
                                   provenance=meta["provenance"]))
                continue
            f["guard_found_but_no_grounded_flow"] += 1
            held.append(dict(pair_id=pid, reason="guard_found_but_no_grounded_flow", detail="",
                             language=m.get("language", ""), cve="",
                             repo="", sha=""))
            continue

        construct, _ = pick_removal(vc, sc)
        if construct and standalone(construct, vc):
            # For a restructure pair the CWE follows from WHICH construct was
            # removed -- a fact about the code. The classifier's guess agreed with
            # CISA/OSV only 19.7% of the time and put CWE-918 on a `verify=False`
            # removal, which is certificate validation.
            by_construct = _CWE_FOR.get(re.split(r"[.(=]", construct)[0].lower())
            if by_construct:
                if by_construct != cwe:
                    f["restructure_cwe_CORRECTED"] += 1
                cwe, cwe_src = by_construct, "removed_construct_class"
                meta["cwe_source"] = cwe_src      # meta was built before this branch
            elif cwe_src == "derived_by_classifier":
                f["restructure_no_trustworthy_cwe"] += 1
                held.append(dict(pair_id=pid, reason="restructure_cwe_unresolved",
                                 detail=f"removed {construct!r}; no construct-class CWE "
                                        f"and the classifier's guess is not trustworthy",
                                 language=m.get("language", ""), cve="", repo="", sha=""))
                continue
            src = pick_source(construct, vc, sc)
            snk = pick_sink(sc, src) if src else None
            if src and snk and snk != src and src != construct:
                restr_out.append(restructure_record(vc, "vuln", cwe, src, construct,
                                                    construct, meta, pid))
                restr_out.append(restructure_record(sc, "safe", cwe, src, construct,
                                                    snk, meta, pid))
                f["RESTRUCTURE_PAIR"] += 1
                report.append(dict(pair_id=pid, kind="restructure", origin=origin,
                                   language=m.get("language", ""), cwe=cwe,
                                   source=src, sink=snk, guard=construct[:100],
                                   provenance=meta["provenance"]))
                continue
        f["no_guard_no_removal"] += 1
        held.append(dict(pair_id=pid, reason="no_guard_no_removal",
                         detail="fix adds no quotable control and removes no known"
                                " dangerous construct",
                         language=m.get("language", ""), cve="", repo="", sha=""))

    print("\n=== funnel ===")
    for k, val in f.most_common():
        print(f"  {k:34s} {val:6d}")

    if args.write:
        import csv
        def _auth(r):
            return (r["_meta"].get("cve")
                    and r["_meta"].get("cwe_source", "").startswith(
                        ("osv", "cisa", "primevul", "hand_resolved")))
        att = [r for r in guard_out if _auth(r)]
        unatt = [r for r in guard_out if not _auth(r)]
        for r in unatt:
            mm = r["_meta"]
            why = ("no CVE resolved for this commit" if not mm.get("cve")
                   else "CWE is the classifier's guess, not an authority's")
            mm["hold"] = "not_attested"
            mm["hold_reason"] = (why + " -- held, not dropped: the code, the diff and "
                                 "the repo+sha are real, only the attestation is missing")
        for path, rows in ((OUT_GUARD_ATT, att), (OUT_GUARD, unatt),
                           (OUT_RESTR, restr_out), (OUT_SYN, syn_out)):
            if rows:
                with open(path, "w", encoding="utf-8") as fh:
                    for r in rows:
                        fh.write(json.dumps(r, ensure_ascii=False) + "\n")
                print(f"  -> {path} ({len(rows)//2} pairs)")
        if report:
            with open(REPORT, "w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=list(report[0].keys()), delimiter="\t")
                w.writeheader()
                w.writerows(report)
            print(f"  -> {REPORT}")
        if held:
            with open(HELD, "w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=list(held[0].keys()), delimiter="	")
                w.writeheader()
                w.writerows(held)
            print(f"  -> {HELD} ({len(held)} pairs held, none dropped)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
