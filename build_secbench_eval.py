"""Build a PAIRED evaluation set from SecBench.js.

Why paired: SecBench.js ships 600 VULNERABLE samples and no safe counterparts.
Scored as-is it repeats this project's worst measurement mistake -- an
always-say-vuln stub scores 100% on an all-vulnerable set, which is how
`shape3_codeql` produced an unfalsifiable "100% cross-file recall". Every entry
carries `fixedVersion`, so the safe side can be fetched and the metric made
failable.

Why SecBench.js is worth the trouble: its ground truth was established by
RUNNING an exploit against an oracle, not inferred from a CVE label. It also
records an exact `sink: path/file.js:LINE:COL`, so the excerpt can be centred on
the real vulnerable line instead of a guessed region.

Code comes from the npm registry rather than git: the `sink` path refers to the
PUBLISHED package layout, which often differs from the repository layout, and
the registry has no API rate limit.

    python build_secbench_eval.py --stage fetch [--limit N]
    python build_secbench_eval.py --stage build
"""
import argparse
import collections
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import time
import urllib.error
import urllib.request

SEC_DIR = "data/downloads/SecBench.js"
PKG_CACHE = "data/secbench/pkgs"
OUT_EVAL = "data/cot/eval/shape1_secbench_pairs.jsonl"
CLASSES = ["code-injection", "command-injection", "path-traversal",
           "prototype-pollution", "redos"]

CLASS_CWE = {
    "code-injection": "CWE-94",
    "command-injection": "CWE-78",
    "path-traversal": "CWE-22",
    "prototype-pollution": "CWE-1321",
    "redos": "CWE-1333",
}

MIN_CHARS, MAX_CHARS = 120, 4000
_SEMVER = re.compile(r"^\d+\.\d+\.\d+")


def log(m):
    print(m, flush=True)


def entries():
    """Yield (class, dir, package_name, vuln_version, fixed_version, sink)."""
    for cls in CLASSES:
        d = os.path.join(SEC_DIR, cls)
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name, "package.json")
            if not os.path.exists(p):
                continue
            try:
                j = json.load(open(p, encoding="utf-8"))
            except Exception:
                continue
            deps = j.get("dependencies") or {}
            if len(deps) != 1:
                continue
            pkg, ver = list(deps.items())[0]
            fixed = (j.get("fixedVersion") or "").strip()
            if not _SEMVER.match(fixed) or not _SEMVER.match(ver or ""):
                continue
            if fixed == ver:                      # nothing to contrast
                continue
            yield cls, name, pkg, ver, fixed, (j.get("sink") or "").strip()


def tarball_url(pkg, version):
    base = pkg.split("/")[-1]                     # @scope/name -> name
    return f"https://registry.npmjs.org/{pkg}/-/{base}-{version}.tgz"


def fetch_pkg(pkg, version):
    """Download+cache one package version. Returns cache path or None."""
    safe = pkg.replace("/", "__").replace("@", "")
    dest = os.path.join(PKG_CACHE, f"{safe}-{version}.tgz")
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return dest
    os.makedirs(PKG_CACHE, exist_ok=True)
    req = urllib.request.Request(tarball_url(pkg, version),
                                 headers={"User-Agent": "wave-secbench"})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            data = r.read()
    except urllib.error.HTTPError as e:
        return f"__HTTP{e.code}"
    except Exception:
        return None
    with open(dest, "wb") as fh:
        fh.write(data)
    return dest


def read_from_tgz(tgz_path, member_rel):
    """Read `package/<member_rel>` out of the tarball."""
    try:
        with tarfile.open(tgz_path, "r:gz") as tf:
            want = "package/" + member_rel.lstrip("./")
            for m in tf.getmembers():
                if m.name == want or m.name.endswith("/" + member_rel.lstrip("./")):
                    f = tf.extractfile(m)
                    if f:
                        return f.read().decode("utf-8", errors="replace")
    except Exception:
        return None
    return None


def excerpt_around(text, line_no, want=28):
    """Window centred on the sink line -- the line the exploit actually hit."""
    lines = text.splitlines()
    if not lines:
        return None
    i = max(0, min(len(lines) - 1, line_no - 1))
    lo = max(0, i - want // 2)
    hi = min(len(lines), i + want // 2 + 1)
    return "\n".join(lines[lo:hi]).rstrip()


def aligned_excerpt(fixed_text, vuln_excerpt, want=28):
    """Find the region of the FIXED file corresponding to `vuln_excerpt`.

    The two sides are different PUBLISHED VERSIONS, not one commit, so the fixed
    file has usually drifted by many lines. Reusing the vulnerable line number
    lands on unrelated code -- which produces a record labelled "safe" that is
    not the fix at all, but a different function entirely (observed on `djv`:
    the vulnerable side showed `new Function(...)`, the "safe" side showed an
    unrelated `link()`/`visit()` block).

    So align by CONTENT: slide a window over the fixed file and keep the one
    most similar to the vulnerable excerpt. Returns (excerpt, similarity).
    """
    import difflib

    v_lines = vuln_excerpt.splitlines()
    if not v_lines:
        return None, 0.0
    f_lines = fixed_text.splitlines()
    if not f_lines:
        return None, 0.0

    # Anchor on the most distinctive vulnerable line to keep this cheap.
    anchor = max(v_lines, key=lambda l: len(l.strip()))
    matcher = difflib.SequenceMatcher(autojunk=False)
    matcher.set_seq2(v_lines)

    best, best_score = None, 0.0
    cands = [i for i, l in enumerate(f_lines) if anchor.strip() and anchor.strip()[:40] in l]
    if not cands:
        # no exact anchor survives the fix (expected -- the fix CHANGED it), so
        # scan coarsely instead
        cands = range(0, len(f_lines), max(1, want // 3))
    for i in cands:
        lo = max(0, i - want // 2)
        hi = min(len(f_lines), lo + want + 1)
        window = f_lines[lo:hi]
        matcher.set_seq1(window)
        score = matcher.quick_ratio()
        if score > best_score:
            best_score, best = score, "\n".join(window).rstrip()
    return best, best_score


def stage_fetch(limit, sleep_s):
    rows = list(entries())
    log(f"resolvable entries: {len(rows)}")
    f = collections.Counter()
    done = 0
    for cls, name, pkg, ver, fixed, sink in rows:
        if limit and done >= limit:
            break
        for v in (ver, fixed):
            r = fetch_pkg(pkg, v)
            if r is None:
                f["fetch_failed"] += 1
            elif isinstance(r, str) and r.startswith("__HTTP"):
                f[f"http_{r[6:]}"] += 1
            elif os.path.getmtime(r) > time.time() - 5:
                f["downloaded"] += 1
                time.sleep(sleep_s)
            else:
                f["cached"] += 1
        done += 1
    log("\n=== fetch funnel ===")
    for k, v in f.most_common():
        log(f"  {k:16s} {v}")
    return 0


def rec(code, label, cwe, pair_id, cls, pkg):
    verdict = ("status: confirmed\ncwe: %s\nseverity: HIGH" % cwe) if label == "vuln" \
        else "status: safe\ncwe: none\nseverity: none"
    return {
        "messages": [
            {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
            {"role": "assistant", "content": verdict},
        ],
        "_meta": {
            "shape": "shape1", "source": "secbench", "origin": "real",
            "language": "javascript", "label": label,
            "cwes": [cwe], "ground_truth_cwe": cwe,
            "pair_id": pair_id, "contrastive": True, "synthetic": False,
            "vuln_class": cls, "package": pkg, "execution_verified": True,
        },
    }


def stage_build():
    f = collections.Counter()
    out = []
    for cls, name, pkg, ver, fixed, sink in entries():
        if not sink:
            f["no_sink"] += 1
            continue
        m = re.match(r"(.+?):(\d+)", sink)
        if not m:
            f["unparsable_sink"] += 1
            continue
        rel, line_no = m.group(1), int(m.group(2))

        vt = fetch_pkg(pkg, ver)
        ft = fetch_pkg(pkg, fixed)
        if not (isinstance(vt, str) and os.path.exists(vt)):
            f["vuln_pkg_missing"] += 1
            continue
        if not (isinstance(ft, str) and os.path.exists(ft)):
            f["fixed_pkg_missing"] += 1
            continue

        v_src = read_from_tgz(vt, rel)
        f_src = read_from_tgz(ft, rel)
        if not v_src:
            f["sink_file_absent_vuln"] += 1
            continue
        if not f_src:
            f["sink_file_absent_fixed"] += 1
            continue

        v_ex = excerpt_around(v_src, line_no)
        if not v_ex:
            f["excerpt_failed"] += 1
            continue
        # align the safe side by CONTENT, never by line number
        f_ex, sim = aligned_excerpt(f_src, v_ex)
        if not f_ex:
            f["excerpt_failed"] += 1
            continue
        # Too dissimilar means we matched a different part of the file; that
        # would label unrelated code as "the fix". Drop rather than mislabel.
        if sim < 0.55:
            f["no_aligned_region"] += 1
            continue
        # Near-identical means the fix is not inside this window at all.
        if sim > 0.995:
            f["sides_identical"] += 1
            continue
        if v_ex.strip() == f_ex.strip():
            f["sides_identical"] += 1        # fix is elsewhere in the file
            continue
        if not (MIN_CHARS <= len(v_ex) <= MAX_CHARS):
            f["vuln_size"] += 1
            continue
        if not (MIN_CHARS <= len(f_ex) <= MAX_CHARS):
            f["fixed_size"] += 1
            continue

        cwe = CLASS_CWE[cls]
        pid = hashlib.sha1(f"{pkg}{ver}{fixed}{rel}".encode()).hexdigest()[:12]
        out.append(rec(v_ex, "vuln", cwe, pid, cls, pkg))
        out.append(rec(f_ex, "safe", cwe, pid, cls, pkg))
        f["PAIR_BUILT"] += 1

    os.makedirs(os.path.dirname(OUT_EVAL), exist_ok=True)
    with open(OUT_EVAL, "w", encoding="utf-8") as fh:
        for r in out:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    log("\n=== build funnel ===")
    for k, v in f.most_common():
        log(f"  {k:24s} {v}")
    log(f"\npairs: {f['PAIR_BUILT']}  records: {len(out)} -> {OUT_EVAL}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=["fetch", "build"], required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--sleep", type=float, default=0.3)
    a = ap.parse_args()
    return stage_fetch(a.limit, a.sleep) if a.stage == "fetch" else stage_build()


if __name__ == "__main__":
    sys.exit(main())
