"""Guard-present-but-incomplete pairs: the class the corpus is starved of.

Every shape1 contrastive pair teaches the same lesson -- control absent means
vulnerable, control present means safe. A model can score well on those by
learning "is there a check near the sink", which is the shortcut we are trying to
break. These pairs are the counterexample: on the VULNERABLE side the control is
present, correct, and often written for an earlier CVE -- it just does not cover
the path that matters.

Both cases here were read line by line against the real pre- and post-fix files;
neither was accepted on the strength of its diff. They are hand-authored for that
reason, and the registry records why each one is exploitable despite its guard.

    python build_js_completeness.py
"""
import csv
import hashlib
import json
import re
import sys

from build_ts_contrastive import MAX_CODE_CHARS, MIN_CODE_CHARS, file_at
from harvest_osv_ts import find_local_clone

OUT = "data/cot/staging/shape_completeness_js.jsonl"
UNRESOLVED = "data/osv/js_cwe_unresolved.tsv"

CASES = [
    {
        "id": "set-in-prototype-segments",
        "repo": "ahdinosaur/set-in",
        "sha": "d87c1a09fa2edb55cd76440a67d83d1cb828df11",
        "file": "index.js",
        "cve": "CVE-2026-26021",
        "ghsa": "GHSA-2c4m-g7rx-63q7",
        "cwe": "CWE-1321",
        "cwe_source": "advisory",
        "source": "path",
        "sink": "recursivelySetIn",
        # verified: the pre-fix file already carries the CVE-2020-28273 assert in
        # `set`, so the guard is present, named, and looks complete.
        "vuln_side": "clone_pre",
        "safe_side": "clone_post",
        "vuln_think": (
            "Hypothesis: `path` is caller-controlled and its segments are used to walk and "
            "assign into `object` - the shape of CWE-1321.\n"
            "Trigger path: `recursivelySetIn` reads `object[key]` for each segment before "
            "recursing, and the final assignment happens in `set`.\n"
            "Defensive check: a control IS present - `set` asserts "
            "`!POLLUTED_KEYS.includes(key)`, written for CVE-2020-28273. I check what it "
            "covers rather than that it exists: it runs on the key of the final assignment "
            "only, not on the intermediate segments `recursivelySetIn` walks through.\n"
            "So `setIn(obj, ['__proto__', 'x'], v)` descends into `object['__proto__']` "
            "unchecked and reaches `set` with the innocent key `x`, which passes the assert.\n"
            "The control is real but does not cover the path, so the hypothesis stands."
        ),
        "vuln_fix": "apply the same key check to every path segment, not only the final assignment",
        "safe_think": (
            "Hypothesis: `path` is caller-controlled and its segments walk and assign into "
            "`object` - the shape of CWE-1321.\n"
            "Trigger path: the traversal is the dangerous structure, so shape alone does not "
            "settle it.\n"
            "Defensive check: `recursivelySetIn` asserts `!POLLUTED_KEYS.includes(key)` on "
            "each segment as it descends, and `set` asserts the same on the final key.\n"
            "Every segment the caller supplies is checked before it indexes `object`, so no "
            "segment can reach `__proto__`, `constructor` or `prototype`."
        ),
        "guard_quote": "assert.ok(!POLLUTED_KEYS.includes(key)",
        "severity": "HIGH",
    },
    {
        "id": "ezforms-captcha-no-return",
        "repo": "excl-networks/strapi-plugin-ezforms",
        "sha": "a8372190b7122e5dda32d5b71b2513fd5352656a",
        "file": "server/controllers/submit-controller.js",
        "cve": "",
        "ghsa": "GHSA-8mgq-6r2q-82w9",
        # The advisory says "Captcha Bypass" and assigns NO cwe; there is no CVE and
        # therefore no CISA record. CWE-670 is read off the code -- the check runs,
        # computes the right answer, and control flow proceeds regardless -- but it
        # is OUR reading, not an authority's, and is marked as such.
        "cwe": "CWE-670",
        "cwe_source": "proposed_by_analysis",
        # HELD: CWE-670 is our reading, not an authority's. The record is built
        # and verified but routed to the unresolved queue instead of the shipped
        # set, so a proposed CWE never reaches training as if it were attested.
        "hold": "cwe_proposed_not_authoritative",
        "source": "ctx.request.body.formData",
        "sink": "strapi.query",
        # The commit is a repo-wide restyle (2->4 spaces, quotes, semicolons) whose
        # only semantic content is three `return` keywords. Cutting the real post-fix
        # text would make the model read reindentation as the fix, so the safe side
        # applies just that semantic change to the pre text.
        "vuln_side": "clone_pre",
        "safe_side": "edit_pre",
        "edits": [
            ('          ctx.internalServerError("There was an error, check Strapi logs for '
             'more details. " + verification.message)',
             '          return ctx.internalServerError("There was an error, check Strapi '
             'logs for more details. " + verification.message)'),
            ("          ctx.badRequest(verification.message)",
             "          return ctx.badRequest(verification.message)"),
            ('          ctx.internalServerError("There was an error")',
             '          return ctx.internalServerError("There was an error")'),
        ],
        "vuln_think": (
            "Hypothesis: `ctx.request.body.formData` is request-controlled and is persisted "
            "by `strapi.query`, which should only happen once the captcha has passed.\n"
            "Trigger path: the handler validates the submitted token and computes "
            "`verification.valid`.\n"
            "Defensive check: a control IS present - when `!verification.valid` the handler "
            "logs the error and calls `ctx.badRequest` or `ctx.internalServerError`. I check "
            "whether it stops the flow: none of those branches returns, so `index` continues "
            "past the block.\n"
            "Execution therefore reaches the notification providers and "
            "`strapi.query(...).create`, and the handler still returns the submitted body - "
            "the same outcome as a passing captcha.\n"
            "The check runs and its result is discarded, so the hypothesis stands."
        ),
        "vuln_fix": "return from each captcha-failure branch so the handler stops before persisting",
        "safe_think": (
            "Hypothesis: `ctx.request.body.formData` is request-controlled and is persisted "
            "by `strapi.query`, so the captcha result has to gate it.\n"
            "Trigger path: the handler validates the token and computes `verification.valid`.\n"
            "Defensive check: each failure branch now returns the error response, so control "
            "leaves `index` at the point the captcha fails.\n"
            "Nothing after the block executes on a failed captcha, so the value never reaches "
            "`strapi.query`."
        ),
        "guard_quote": "if (!verification.valid) {",
        "severity": "MODERATE",
    },
]


def apply_edits(text, edits):
    for old, new in edits:
        if text.count(old) != 1:
            raise SystemExit(f"edit anchor not unique ({text.count(old)}x): {old[:70]}")
        text = text.replace(old, new)
    return text


def cosmetic_norm(t):
    """Drop the things a restyle changes and semantics do not."""
    return re.sub(r"\s+", "", t).replace('"', "'").replace(";", "")


def attest_edit(edited, post, case_id):
    """An authored safe side must reproduce the maintainer's fix, not resemble it.

    R8/R9 let a harvested set pass on the premise that its safe side IS the real
    post-fix code. When we author the safe side that premise is false, so the
    premise has to be re-established: the edited text must equal the true post-fix
    file once the cosmetic churn is normalised away. Without this the shape could
    pass the scanner on a technicality, which is the failure mode the standard
    exists to prevent.
    """
    if cosmetic_norm(edited) != cosmetic_norm(post):
        raise SystemExit(
            f"{case_id}: authored safe side does NOT match the real post-fix file; "
            "the edit is not the maintainer's semantic change")
    return True


def record(c, label, code, pair_id):
    if label == "vuln":
        think, status, cwe, sev = c["vuln_think"], "confirmed", c["cwe"], c["severity"]
        trace = (f"{c['source']} -> {c['sink']} is only partly constrained by "
                 f"`{c['guard_quote']}`")
        fix = c["vuln_fix"]
    else:
        think, status, cwe, sev = c["safe_think"], "safe", "none", "none"
        trace = f"{c['source']} -> {c['sink']} is constrained by `{c['guard_quote']}`"
        fix = "none"
    completion = (f"<think>\n{think}\n</think>\n"
                  f"status: {status}\ncwe: {cwe}\nseverity: {sev}\n"
                  f"trace: {trace}\nfix: {fix}")
    return {
        "messages": [
            {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
            {"role": "assistant", "content": completion},
        ],
        "_meta": {
            "shape": "shape_completeness",
            "source": "completeness_js",
            "origin": "real" if c["safe_side"] == "clone_post" else "edited",
            "language": "javascript",
            "label": label,
            "cwes": [c["cwe"]],
            "ground_truth_cwe": c["cwe"],
            "pair_id": pair_id,
            "contrastive": True,
            "synthetic": False,
            "cleaned": True,
            "guard_present_in_vuln": True,
            "cve": c["cve"],
            "ghsa": c["ghsa"],
            "repo": c["repo"],
            "sha": c["sha"],
            "src_file": c["file"],
            "fix_status": "verified_by_hand",
            "cwe_source": c["cwe_source"],
            "safe_side_attestation": c["_attested"],
            "cwe_all": c["cwe"],
        },
    }


def main():
    out, held = [], []
    for c in CASES:
        owner, repo = c["repo"].split("/", 1)
        clone = find_local_clone(owner, repo)
        if not clone:
            raise SystemExit(f"no clone for {c['repo']}")
        pre = file_at(clone, c["sha"] + "^", c["file"])
        post = file_at(clone, c["sha"], c["file"])
        if not pre:
            raise SystemExit(f"cannot read pre-fix {c['file']}")
        vuln = pre
        if c["safe_side"] == "clone_post":
            safe = post
            c["_attested"] = "real_post_fix_text"
        else:
            safe = apply_edits(pre, c["edits"])
            if not post:
                raise SystemExit(f"{c['id']}: cannot attest edit without post-fix file")
            attest_edit(safe, post, c["id"])
            c["_attested"] = f"semantically_equals_post_fix@{c['sha'][:12]}"

        # the defining property of this shape: the control is on BOTH sides
        if c["guard_quote"] not in vuln or c["guard_quote"] not in safe:
            raise SystemExit(f"{c['id']}: guard must be present on both sides")
        for nm in (c["source"], c["sink"]):
            if nm not in vuln or nm not in safe:
                raise SystemExit(f"{c['id']}: {nm!r} missing from a side")
        for side, t in (("vuln", vuln), ("safe", safe)):
            if not (MIN_CODE_CHARS <= len(t) <= MAX_CODE_CHARS):
                raise SystemExit(f"{c['id']}: {side} is {len(t)} chars")
        if vuln.strip() == safe.strip():
            raise SystemExit(f"{c['id']}: sides identical")

        pid = hashlib.sha1(f"{c['repo']}|{c['sha']}|{c['id']}".encode()).hexdigest()[:12]
        if c.get("hold"):
            held.append(c)
            print(f"  {c['id']:34s} {c['cwe']:9s} HELD -> {c['hold']}")
            continue
        out.append(record(c, "vuln", vuln.rstrip(), pid))
        out.append(record(c, "safe", safe.rstrip(), pid))
        print(f"  {c['id']:34s} {c['cwe']:9s} ({c['cwe_source']}) "
              f"vuln={len(vuln)} safe={len(safe)}")

    with open(OUT, "w", encoding="utf-8") as fh:
        for r in out:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\npairs: {len(out) // 2}  records: {len(out)} -> {OUT}")

    # Held cases are labelled and queued, never dropped -- the record is built and
    # verified, it just does not ship while its CWE is only our reading.
    if held:
        cols = ["n", "cve", "ghsa", "repo", "sha", "file", "cwe_final", "cwe_all",
                "cwe_advisory", "cwe_cisa", "cwe_status", "fix_status", "guard", "patch"]
        existing = list(csv.DictReader(open(UNRESOLVED, encoding="utf-8"), delimiter="\t"))
        keys = {(r["repo"], r["sha"], r["file"]) for r in existing}
        added = updated = 0
        for c in held:
            key = (c["repo"], c["sha"], c["file"])
            if key in keys:
                # Already queued, but from before the case was analysed. Refresh it
                # so the queue records what we now know rather than a stale "none".
                for r in existing:
                    if (r["repo"], r["sha"], r["file"]) == key:
                        r["cwe_status"] = f"proposed:{c['cwe']} ({c['hold']})"
                        r["fix_status"] = "verified_by_hand"
                        r["guard"] = c["guard_quote"]
                        updated += 1
                continue
            existing.append({
                "n": f"completeness-{c['id']}", "cve": c["cve"], "ghsa": c["ghsa"],
                "repo": c["repo"], "sha": c["sha"], "file": c["file"],
                "cwe_final": "", "cwe_all": "", "cwe_advisory": "", "cwe_cisa": "",
                "cwe_status": f"proposed:{c['cwe']} ({c['hold']})",
                "fix_status": "verified_by_hand", "guard": c["guard_quote"], "patch": ""})
            added += 1
        with open(UNRESOLVED, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, delimiter="\t", extrasaction="ignore")
            w.writeheader()
            w.writerows(existing)
        print(f"held: {len(held)}  (+{added} new, {updated} refreshed) -> {UNRESOLVED}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
