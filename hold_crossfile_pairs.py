"""Hold `shape3_crossfile_pairs` in full. It was wired at weight 8.0 and is fabricated.

Why the whole set and not a repair:

The pairs were carved as LINE WINDOWS from two files of a fix commit, then narrated with
the CVE's CWE. The excerpt was never checked to contain the vulnerability, so:

  * 17 of 38 pairs (45%) state a sink that does not appear in the vulnerable excerpt at
    all. Example `710552dd6c9ff277`: the excerpt is a click CLI command that creates a
    plugin directory; the trace claims `name` reaches `urlparse` as CWE-601 open
    redirect. `urlparse` is not in the excerpt -- it belongs to `is_safe_redirect_url`,
    an unrelated function that happened to land in the SAFE side's window.
  * Of the 21 that name a present identifier, most "sinks" are not sinks: `elif`,
    `main`, `Form`, `Parser`, `Cache`, `__init__`, `JWT`, `getter`. And one "guard" is
    `assert('polluted' in obj)` -- a test assertion.
  * Because the window is arbitrary, even a correctly-named sink is no evidence the
    excerpt contains the flaw.

This is the topic-vs-guard defect in its purest form -- a verdict assigned from repo and
CVE context rather than from visible code -- and it was weighted 8.0, so it sampled at
roughly thirteen times its record share.

It also passed my grounding audit at 100%, because its `trace:` line is
`cli.py:175 -> helpers.py:234`: filenames, no identifiers, nothing for the check to
falsify. Recorded here because that is the kind of blind spot worth remembering.

Repair is not prose-deep. It needs re-carving from the commits (the clones exist --
`clone_crossfile_repos.sh`) with the sink verified present before the window is cut.
The pool is known to be thin: 600 python commits previously yielded 2 pairs.

    python hold_crossfile_pairs.py --write
"""
import argparse
import csv
import json
import sys

PATH = "data/cot/pilot/shape3_crossfile_pairs.jsonl"
MANIFEST = "data/osv/crossfile_pairs_held.tsv"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    recs = [json.loads(l) for l in open(PATH, encoding="utf-8") if l.strip()]
    rows = []
    for r in recs:
        m = r.setdefault("_meta", {})
        m["held"] = "fabricated_crossfile_window"
        rows.append(dict(pair_id=m.get("pair_id", ""), label=m.get("label", ""),
                         repo=m.get("repo", ""), commit=m.get("commit", "")[:12],
                         cwe=m.get("ground_truth_cwe", ""),
                         reason="line-window carving; sink not verified present in the "
                                "excerpt before the CWE was narrated onto it"))
    print(f"holding {len(recs)} records "
          f"({len({r['_meta'].get('pair_id') for r in recs})} pairs)")
    if args.write:
        with open(PATH, "w", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        with open(MANIFEST, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(rows)
        print(f"-> {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
