"""Bridge vulnrichment (CVE -> CWE + fix-commit sha) to morefixes patches (sha-named files).

The code (morefixes .patch) and the CWE labels (vulnrichment CVE json) are disconnected on
disk. This joins them on the fix-commit sha, producing a selection table of REAL, CWE-labelled
patches we can pick by CWE (fill the authz/XSS gaps) and by file-count (cross-file/complex).

  python build_bridge.py            # -> data/bridge.jsonl  (+ prints coverage)

Each row: {patch, sha, cve, cwes[], n_files, n_hunks, langs[], multi_file}
"""
import json, os, re, sys
from collections import Counter

MOREFIXES = "data/downloads/morefixes-patches/cvedataset-patches"
VULNRICH  = "data/downloads/vulnrichment"
OUT       = "data/bridge.jsonl"

_EXT2LANG = {"py":"python","js":"javascript","jsx":"javascript","mjs":"javascript",
             "ts":"typescript","tsx":"typescript","php":"php","java":"java","c":"c","h":"c",
             "cpp":"cpp","cc":"cpp","cxx":"cpp","hpp":"cpp","hxx":"cpp","go":"go","rb":"ruby",
             "cs":"csharp","rs":"rust","kt":"kotlin","swift":"swift","scala":"scala","pl":"perl",
             "pm":"perl","sh":"shell","html":"html","htm":"html","vue":"vue","py3":"python"}

_SHA_IN_NAME = re.compile(r"_([0-9a-f]{40})\.patch$")
_PLUS_FILE   = re.compile(r"^\+\+\+ b/(.+?)\s*$", re.M)
_HUNK        = re.compile(r"^@@ ", re.M)
# commit shas in vulnrichment references: /commit/<sha>, /pull/.../commits/<sha>, or bare 40-hex
_COMMIT_URL  = re.compile(r"/commit[s]?/([0-9a-f]{7,40})")
_BARE_SHA    = re.compile(r"\b([0-9a-f]{40})\b")
_CWE_ID      = re.compile(r'"cweId"\s*:\s*"(CWE-[0-9]+)"')
_CVE_NAME    = re.compile(r"(CVE-[0-9]{4}-[0-9]+)")


def index_patches():
    """sha (40-hex) -> patch filename, and per-patch file/hunk/lang stats (lazy)."""
    sha2patch = {}
    for f in os.listdir(MOREFIXES):
        m = _SHA_IN_NAME.search(f)
        if m:
            sha2patch[m.group(1)] = f
    return sha2patch


def patch_stats(fname):
    try:
        txt = open(os.path.join(MOREFIXES, fname), encoding="utf-8", errors="ignore").read()
    except Exception:
        return 0, 0, []
    files = _PLUS_FILE.findall(txt)
    langs = Counter()
    for p in files:
        ext = p.rsplit(".", 1)[-1].lower() if "." in p else ""
        if ext in _EXT2LANG:
            langs[_EXT2LANG[ext]] += 1
    n_hunks = len(_HUNK.findall(txt))
    return len(files), n_hunks, [l for l, _ in langs.most_common()]


def iter_vulnrich():
    for dp, dn, fn in os.walk(VULNRICH):
        if ".git" in dp:
            continue
        for f in fn:
            if f.startswith("CVE-") and f.endswith(".json"):
                yield os.path.join(dp, f)


def main():
    print("indexing morefixes patches...", flush=True)
    sha2patch = index_patches()
    print(f"  {len(sha2patch)} patches with a 40-hex sha", flush=True)

    print("scanning vulnrichment and bridging...", flush=True)
    rows = []
    seen_patch = set()
    scanned = 0
    for path in iter_vulnrich():
        scanned += 1
        if scanned % 20000 == 0:
            print(f"  scanned {scanned}... bridged {len(rows)}", flush=True)
        try:
            txt = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        # collect candidate shas (prefer explicit commit urls, then bare 40-hex)
        shas = set(_COMMIT_URL.findall(txt)) | set(_BARE_SHA.findall(txt))
        hit = None
        for s in shas:
            if len(s) == 40 and s in sha2patch:
                hit = s
                break
            # short sha: match by prefix
            if len(s) < 40:
                for full in sha2patch:
                    if full.startswith(s):
                        hit = full
                        break
                if hit:
                    break
        if not hit or hit in seen_patch:
            continue
        seen_patch.add(hit)
        cve = _CVE_NAME.search(os.path.basename(path))
        cwes = sorted(set(_CWE_ID.findall(txt)))
        nf, nh, langs = patch_stats(sha2patch[hit])
        rows.append({"patch": sha2patch[hit], "sha": hit,
                     "cve": cve.group(1) if cve else None, "cwes": cwes,
                     "n_files": nf, "n_hunks": nh, "langs": langs,
                     "multi_file": nf >= 2})

    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")

    # coverage report
    print(f"\nBRIDGED {len(rows)} patches -> {OUT}", flush=True)
    cwe_ct = Counter(c for r in rows for c in r["cwes"])
    lang_ct = Counter(l for r in rows for l in r["langs"])
    mf = sum(1 for r in rows if r["multi_file"])
    with_cwe = sum(1 for r in rows if r["cwes"])
    print(f"  with a CWE: {with_cwe} | multi-file: {mf} ({100*mf//max(len(rows),1)}%)")
    print(f"  top CWEs: {cwe_ct.most_common(20)}")
    print(f"  langs: {lang_ct.most_common()}")
    # the gap classes we care about
    for fam, ids in [("authz","CWE-862 CWE-284 CWE-863 CWE-306 CWE-285"),
                     ("xss","CWE-79"), ("csrf","CWE-352"), ("upload","CWE-434")]:
        n = sum(cwe_ct[i] for i in ids.split())
        print(f"  gap[{fam}]: {n}")


if __name__ == "__main__":
    main()
