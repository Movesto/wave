"""Turn a morefixes .patch (unified diff) into (vulnerable-code view, fix view).

For authoring a trace we need the PRE-change (vulnerable) code to reason about, and the
added lines (the fix) to confirm the mechanism -- exactly how the Go/Java gold examples were
written. A patch's context + '-' lines reconstruct the vulnerable region; '+' lines are the fix.
"""
import re, os

MOREFIXES = "data/downloads/morefixes-patches/cvedataset-patches"
_FILE = re.compile(r"^\+\+\+ b/(.+?)\s*$")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")


def parse(patch_text):
    """Yield dicts: {file, pre, post, added, removed} per hunk."""
    cur_file = None
    lines = patch_text.splitlines()
    i = 0
    while i < len(lines):
        ln = lines[i]
        mf = _FILE.match(ln)
        if mf:
            cur_file = mf.group(1)
            i += 1
            continue
        if _HUNK.match(ln):
            pre, post, added, removed = [], [], [], []
            i += 1
            while i < len(lines) and not _HUNK.match(lines[i]) and not lines[i].startswith("diff ") \
                    and not lines[i].startswith("+++ ") and not lines[i].startswith("--- "):
                h = lines[i]
                if h.startswith("+"):
                    post.append(h[1:]); added.append(h[1:])
                elif h.startswith("-"):
                    pre.append(h[1:]); removed.append(h[1:])
                elif h.startswith(" "):
                    pre.append(h[1:]); post.append(h[1:])
                i += 1
            yield {"file": cur_file, "pre": "\n".join(pre), "post": "\n".join(post),
                   "added": added, "removed": removed}
            continue
        i += 1


_KW = ("valid","escap","saniti","auth","permiss","token","csrf","encod","filter","allow",
       "deni","check","secure","htmlspecial","quote","role","access","prepar","bind")


def _ranked_hunks(patch_file):
    path = patch_file if os.path.isabs(patch_file) else os.path.join(MOREFIXES, patch_file)
    txt = open(path, encoding="utf-8", errors="ignore").read()
    hunks = list(parse(txt))
    def score(h):
        blob = (h["pre"] + h["post"]).lower()
        fp = (h["file"] or "").lower()
        not_test = not any(t in fp for t in ("test", "spec", "__tests__", "/fixtures/", ".test.", ".spec."))
        return (not_test, sum(k in blob for k in _KW), len(h["removed"]) + len(h["added"]))
    hunks.sort(key=score, reverse=True)
    return hunks


def views(patch_file, max_chars=1600):
    """Return (vuln_code, fix_summary). vuln_code = pre-image of the security-relevant hunks;
    fix_summary = the added lines (what the patch introduced), trimmed."""
    vuln, fix, seen = [], [], set()
    for h in _ranked_hunks(patch_file):
        if not h["file"] or (h["file"] in seen and len(vuln) > 2):
            continue
        seen.add(h["file"])
        if h["pre"].strip():
            vuln.append(f"// {h['file']}\n{h['pre']}")
        if h["added"]:
            fix.append(f"// {h['file']}: + " + " | ".join(a.strip() for a in h["added"] if a.strip())[:300])
        if sum(len(v) for v in vuln) > max_chars:
            break
    return ("\n\n".join(vuln)[:max_chars], "\n".join(fix)[:900])


def views_both(patch_file, max_chars=1600):
    """Return (vuln_code, safe_code): pre-image (vulnerable) and post-image (fixed) of the same
    security-relevant hunks -- the two sides of a contrastive pair."""
    vuln, safe, seen = [], [], set()
    for h in _ranked_hunks(patch_file):
        if not h["file"] or (h["file"] in seen and len(vuln) > 2):
            continue
        # only regions present on BOTH sides -> vuln and safe describe the SAME code, not a
        # pure-addition hunk elsewhere in the file (which made pairs semantically misaligned).
        if not (h["pre"].strip() and h["post"].strip()):
            continue
        seen.add(h["file"])
        vuln.append(f"// {h['file']}\n{h['pre']}")
        safe.append(f"// {h['file']}\n{h['post']}")
        if sum(len(v) for v in vuln) > max_chars:
            break
    return ("\n\n".join(vuln)[:max_chars], "\n\n".join(safe)[:max_chars])


_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")


def changed(patch_file):
    """Return (changed_idents:set, fix_anchor:str) from the patch's added/removed lines.
    changed_idents = identifiers touched by the fix (for diff-aware grounding); fix_anchor =
    the added (fix) lines, to SHOW the model the real change so it anchors instead of confabulating."""
    path = patch_file if os.path.isabs(patch_file) else os.path.join(MOREFIXES, patch_file)
    txt = open(path, encoding="utf-8", errors="ignore").read()
    added, removed = [], []
    for h in parse(txt):
        fp = (h["file"] or "").lower()
        if any(t in fp for t in ("test", "spec", "__tests__", "/fixtures/")):
            continue
        added += h["added"]; removed += h["removed"]
    idents = set()
    for ln in added + removed:
        idents |= set(_IDENT.findall(ln))
    anchor = "\n".join(a.strip() for a in added if a.strip())[:700]
    return idents, anchor


def alignment(vuln_code, safe_code):
    """Fraction of the smaller side's lines shared with the other -- a clean fix leaves the two
    near-identical except the changed lines (~1.0); a misaligned pair (different code regions) is low."""
    def norm(c):
        return {l.strip() for l in c.splitlines() if l.strip() and not l.strip().startswith("//")}
    a, b = norm(vuln_code), norm(safe_code)
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a), len(b))


if __name__ == "__main__":
    import sys, json
    for r in [json.loads(l) for l in open("data/cot/staging/regen_pilot.jsonl", encoding="utf-8")][:2]:
        vc, fx = views(r["patch"])
        print("="*70, "\n", r["cwes"], r["patch"][:50])
        print("--- VULN VIEW ---\n", vc[:900])
        print("--- FIX ---\n", fx[:400])
