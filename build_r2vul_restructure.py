"""Pairs where the fix REMOVED the dangerous construct instead of guarding it.

The documented blind spot: our pipeline requires a quotable guard, so it cannot
represent a fix that restructures the code so the bug cannot arise. That is not a
rare shape -- it is 120 of the 242 r2vul map_id candidates, and it covers most of
CWE-400/770, races, ordering bugs, and every "use the safe API instead" fix.

    innerHTML  -> innerText      the sink is replaced, not sanitised
    0o644      -> 0o600          the permission is tightened
    md5        -> sha256         the primitive is swapped

The safe side is justified STRUCTURALLY, not by a guard: the construct the
vulnerable side relies on is ABSENT. That is machine-checkable in a way "is this
guard adequate?" never was -- we assert the token is gone and verify it.

Each side's trace names identifiers from ITS OWN revision, because the whole point
is that they differ: the vulnerable side names the construct, the safe side names
what replaced it.

    python build_r2vul_restructure.py --write
"""
import argparse
import collections
import difflib
import hashlib
import json
import re
import sys

from build_r2vul_pairs import (MAX_CODE_CHARS, _KEYWORDS, added_lines, bare,
                               pick_guard, pick_sink, pick_source, standalone)

OUT = "data/cot/staging/shape_restructure_r2vul.jsonl"

# Constructs whose REMOVAL is itself the security fix.
_DANGEROUS = re.compile(
    r"\b("
    r"innerHTML|outerHTML|document\.write|insertAdjacentHTML|dangerouslySetInnerHTML"
    r"|eval|exec|execSync|system|popen|shell_exec|passthru|assert"
    r"|strcpy|strcat|sprintf|gets|scanf|alloca|memcpy"
    r"|pickle\.loads?|yaml\.load|marshal\.loads?|cPickle"
    r"|md5|sha1|MD5|SHA1|DES|RC4|ECB"
    r"|Random\(\)|rand\(\)|srand"
    r"|Authorization|X-Forwarded-For"
    r"|http://|verify=False|InsecureRequestWarning|TrustAllCerts"
    r"|printStackTrace|console\.trace"
    r")\b", re.I)

# An octal file mode -- tightening it is a fix with no guard to quote.
_MODE = re.compile(r"0o?[0-7]{3,4}\b")


def removed_lines(vuln, safe):
    out = []
    for l in difflib.unified_diff(vuln.splitlines(), safe.splitlines(),
                                  lineterm="", n=0):
        if l.startswith("-") and not l.startswith("---"):
            out.append(l[1:])
    return out


def pick_removal(vuln, safe):
    """(construct, replacement) -- what the fix took out, and what took its place.

    The construct must be GONE from the safe side, not merely moved: a token that
    still appears elsewhere was not removed, and claiming otherwise would be the
    same false-positive class as matching a substring.
    """
    sbare, vbare = bare(safe), bare(vuln)
    best = None
    for l in removed_lines(vuln, safe):
        s = l.strip()
        if len(s) < 8 or s.startswith(("//", "#", "*", "/*")):
            continue
        for m in _DANGEROUS.finditer(s):
            tok = m.group(1)
            head = re.split(r"[.(]", tok)[0]
            if len(head) < 3:
                continue
            if re.search(r"(?<![\w])" + re.escape(head) + r"(?![\w])", sbare):
                continue                       # still present -> not removed
            best = best or (tok, head)
        if best:
            break
    if best:
        tok, head = best
        repl = None
        for l in added_lines(vuln, safe):
            for m in _DANGEROUS.finditer(l):
                pass
            for cand in re.findall(r"[A-Za-z_][\w.]{2,}", l):
                h = cand.split(".")[0]
                if h in _KEYWORDS or len(h) < 3:
                    continue
                if not re.search(r"(?<![\w])" + re.escape(h) + r"(?![\w])", vbare):
                    repl = cand
                    break
            if repl:
                break
        return tok, repl
    # permission/mode tightening
    for l in removed_lines(vuln, safe):
        mv = _MODE.search(l)
        if not mv:
            continue
        for a in added_lines(vuln, safe):
            ma = _MODE.search(a)
            if ma and ma.group(0) != mv.group(0):
                return mv.group(0), ma.group(0)
    return None, None


def record(code, label, cwe, src, construct, repl, meta, pid):
    if label == "vuln":
        think = (f"Hypothesis: `{src}` reaches `{construct}` - the shape of {cwe}.\n"
                 f"Trigger path: `{src}` is passed to `{construct}` as written, and "
                 f"`{construct}` interprets what it is given rather than treating it "
                 f"as inert data.\n"
                 f"Defensive check: I look for a control constraining `{src}` on that "
                 f"path and find none - and note that no guard would settle this on "
                 f"its own, because the danger is the construct itself.\n"
                 f"The construct is present and the value is caller-chosen, so it is "
                 f"exploitable. Confirmed {cwe}.")
        tail = (f"status: confirmed\ncwe: {cwe}\nseverity: HIGH\n"
                f"trace: {src} -> {construct}\n"
                f"fix: replace `{construct}` with a form that cannot interpret `{src}`")
    else:
        # Naming a "replacement" produced TODO, Overrides and RZ_API -- the first
        # unfamiliar token on an added line, which is not what took its place.
        # What we can actually verify is the REMOVAL, so the trace claims only
        # that, and R8 checks the construct really is gone.
        think = (f"Hypothesis: `{src}` is caller-influenced, so I check what it "
                 f"reaches - this is where {cwe} would live.\n"
                 f"Trigger path: the construct that class depends on, `{construct}`, "
                 f"is not in this revision at all.\n"
                 f"Defensive check: there is no added guard here, and none is "
                 f"required - the fix removed the operation that interpreted "
                 f"`{src}` rather than constraining what reached it.\n"
                 f"Safety comes from the construct being absent, which I can confirm "
                 f"by reading, so the hypothesis is refuted.")
        tail = ("status: safe\ncwe: none\nseverity: none\n"
                f"trace: {src} -> {repl} ; `{construct}` is no longer present\n"
                "fix: none")
    m = dict(meta)
    m.update(shape="shape_restructure", source="restructure_r2vul", origin="real",
             label=label, cwes=[cwe], ground_truth_cwe=cwe, pair_id=pid,
             contrastive=True, synthetic=False, cleaned=True,
             removed_construct=construct, replacement=repl or "")
    return {"messages": [{"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                         {"role": "assistant",
                          "content": f"<think>\n{think}\n</think>\n{tail}"}],
            "_meta": m}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    from datasets import load_from_disk

    from filter_corpus import load_eval_codes
    evalcodes = load_eval_codes()
    ds = load_from_disk("data/r2vul_dataset")
    groups = collections.defaultdict(lambda: collections.defaultdict(list))
    for split in ds:
        for r in ds[split]:
            groups[r.get("map_id")][r.get("vulnerable")].append(r)

    out, f = [], collections.Counter()
    for mid, sides in groups.items():
        if 1 not in sides or 0 not in sides:
            continue
        v, s = sides[1][0], sides[0][0]
        vuln, safe = v.get("function") or "", s.get("function") or ""
        if not (120 <= len(vuln) <= MAX_CODE_CHARS and 120 <= len(safe) <= MAX_CODE_CHARS):
            continue
        if not (1 <= len(added_lines(vuln, safe)) <= 24):
            continue
        if pick_guard(vuln, safe):
            continue                       # a guard exists: the other builder owns it
        f["candidate"] += 1

        construct, repl = pick_removal(vuln, safe)
        if not construct:
            f["no_removed_construct"] += 1
            continue
        if any(re.sub(r"\s+", " ", x).strip().lower() in evalcodes for x in (vuln, safe)):
            f["eval_leakage"] += 1
            continue
        src = pick_source(construct, vuln, safe) or pick_source(
            " ".join(removed_lines(vuln, safe)), vuln, safe)
        if not src or src == construct:
            f["no_source"] += 1
            continue
        if not standalone(construct, vuln):
            f["construct_not_groundable"] += 1
            continue
        vuln_sink = construct
        safe_sink = pick_sink(safe, src)
        if not safe_sink or safe_sink == src:
            f["no_sink_in_safe_revision"] += 1
            continue
        cwes = v.get("cwe_id") or []
        cwe = next((c for c in cwes if str(c).startswith("CWE-")), "")
        if not cwe:
            f["no_cwe"] += 1
            continue

        pid = hashlib.sha1(f"r2vul-restructure|{mid}".encode()).hexdigest()[:12]
        meta = dict(language=v.get("lang", ""), cve=v.get("cve_id", ""),
                    repo=v.get("repo", ""), sha=v.get("parent_commit_sha", ""),
                    src_file=v.get("file", ""), cwe_source="r2vul_upstream",
                    map_id=str(mid), fix_status="r2vul_map_id")
        out.append(record(vuln, "vuln", cwe, src, construct, vuln_sink, meta, pid))
        out.append(record(safe, "safe", cwe, src, construct, safe_sink, meta, pid))
        f["PAIR_BUILT"] += 1

    print("=== funnel ===")
    for k, val in f.most_common():
        print(f"  {k:26s} {val:5d}")
    if args.write and out:
        with open(OUT, "w", encoding="utf-8") as fh:
            for r in out:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"\npairs: {len(out)//2}  records: {len(out)} -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
