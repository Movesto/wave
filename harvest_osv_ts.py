"""Harvest TypeScript vulnerability fix-pairs from the OSV npm advisory database.

WHY: shape1_contrastive_ts holds only 162 pairs, and the morefixes corpus is
exhausted for TS (146 pairs out of its 607 TS patches, ~24% -- the guard-quotable
rate). More TS has to come from a NEW source. npm is where TypeScript actually
lives, and OSV publishes the whole npm advisory set as a single bulk download,
so stage 1 costs no API quota at all.

Two stages, both resumable -- a power cut costs at most one item:

  --stage advisories   download+parse the OSV npm dump -> candidates TSV.
                       Pure local work after one HTTP GET. No rate limits.

  --stage patches      resolve each candidate to a real unified diff.
                       Tries LOCAL CLONES FIRST (`git show`, zero network) since
                       ~636 JS repos are already on disk from the earlier
                       cloning campaign, and only falls back to HTTP. Caches
                       every patch to disk, so re-runs are free.

Both stages print a drop funnel -- when yield is low the funnel says why, which
is how the earlier cross-file builders were debugged.

Usage:
    python harvest_osv_ts.py --stage advisories
    python harvest_osv_ts.py --stage patches [--limit N] [--sleep 1.5]
"""
import argparse
import collections
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile

OSV_NPM_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"

OUT_DIR = "data/osv"
ZIP_CACHE = os.path.join(OUT_DIR, "npm_all.zip")
CAND_TSV = os.path.join(OUT_DIR, "npm_candidates.tsv")
PATCH_DIR = os.path.join(OUT_DIR, "patches")
TS_TSV = os.path.join(OUT_DIR, "npm_ts_targets.tsv")

# Where the earlier cloning campaign put things.
CLONE_ROOTS = ["tools/codeql_work/repos"]

_COMMIT_RE = re.compile(
    r"https?://github\.com/([^/\s]+)/([^/\s]+)/commit/([0-9a-fA-F]{7,40})"
)
# Files that look like TypeScript but teach nothing: type stubs, tests, bundles.
_TS_RE = re.compile(r"\.tsx?$", re.I)
_SKIP_PATH = re.compile(
    r"(\.d\.ts$)|(^|/)(test|tests|spec|__tests__|__mocks__|fixtures?|examples?|docs?)/"
    r"|(\.min\.)|(^|/)(dist|build|bundle|vendor|node_modules)/",
    re.I,
)
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$", re.M)


def log(msg):
    print(msg, flush=True)


# ---------------------------------------------------------------- stage 1

def download_zip():
    os.makedirs(OUT_DIR, exist_ok=True)
    if os.path.exists(ZIP_CACHE) and os.path.getsize(ZIP_CACHE) > 1_000_000:
        log(f"using cached {ZIP_CACHE} ({os.path.getsize(ZIP_CACHE)/1e6:.1f} MB)")
        return
    log(f"downloading {OSV_NPM_ZIP} ...")
    req = urllib.request.Request(OSV_NPM_ZIP, headers={"User-Agent": "wave-harvester"})
    with urllib.request.urlopen(req, timeout=180) as r, open(ZIP_CACHE, "wb") as fh:
        fh.write(r.read())
    log(f"saved {ZIP_CACHE} ({os.path.getsize(ZIP_CACHE)/1e6:.1f} MB)")


def stage_advisories():
    download_zip()
    funnel = collections.Counter()
    rows = []
    seen = set()

    with zipfile.ZipFile(ZIP_CACHE) as z:
        names = [n for n in z.namelist() if n.endswith(".json")]
        log(f"advisories in dump: {len(names)}")
        for n in names:
            try:
                adv = json.loads(z.read(n))
            except Exception:
                funnel["unparseable_json"] += 1
                continue

            if adv.get("withdrawn"):
                funnel["withdrawn"] += 1
                continue

            # CWE comes from GHSA's database_specific block when present.
            cwes = adv.get("database_specific", {}).get("cwe_ids") or []
            pkgs = sorted({
                a.get("package", {}).get("name", "")
                for a in adv.get("affected", [])
                if a.get("package", {}).get("ecosystem") == "npm"
            } - {""})

            # Fix commits live in references; accept any GitHub commit URL.
            commits = []
            for ref in adv.get("references", []):
                m = _COMMIT_RE.search(ref.get("url", ""))
                if m:
                    owner, repo, sha = m.group(1), m.group(2), m.group(3)
                    if repo.endswith(".git"):
                        repo = repo[:-4]
                    commits.append((owner, repo, sha))

            if not commits:
                funnel["no_github_fix_commit"] += 1
                continue

            for owner, repo, sha in commits:
                key = (owner.lower(), repo.lower(), sha.lower())
                if key in seen:
                    funnel["dup_commit"] += 1
                    continue
                seen.add(key)
                rows.append({
                    "id": adv.get("id", ""),
                    "owner": owner,
                    "repo": repo,
                    "sha": sha,
                    "cwes": "|".join(cwes),
                    "packages": "|".join(pkgs[:3]),
                    "summary": (adv.get("summary") or "").replace("\t", " ")[:160],
                })
                funnel["kept_commit"] += 1

    os.makedirs(OUT_DIR, exist_ok=True)
    cols = ["id", "owner", "repo", "sha", "cwes", "packages", "summary"]
    with open(CAND_TSV, "w", encoding="utf-8", newline="") as fh:
        fh.write("\t".join(cols) + "\n")
        for r in rows:
            fh.write("\t".join(str(r[c]) for c in cols) + "\n")

    log("")
    log("=== funnel ===")
    for k, v in funnel.most_common():
        log(f"  {k:26s} {v}")
    log("")
    log(f"candidate fix commits: {len(rows)} -> {CAND_TSV}")
    log(f"distinct repos: {len({(r['owner'].lower(), r['repo'].lower()) for r in rows})}")
    cwe_c = collections.Counter(c for r in rows for c in r["cwes"].split("|") if c)
    log(f"top CWEs: {dict(cwe_c.most_common(10))}")


# ---------------------------------------------------------------- stage 2

def find_local_clone(owner, repo):
    """The cloning campaign stored repos as `owner__repo`. Windows is
    case-insensitive, so compare lowercased (this cost real time before)."""
    want = f"{owner}__{repo}".lower()
    for root in CLONE_ROOTS:
        if not os.path.isdir(root):
            continue
        for d in os.listdir(root):
            if d.lower() == want:
                p = os.path.join(root, d)
                if os.path.isdir(os.path.join(p, ".git")):
                    return p
    return None


def patch_from_clone(path, sha):
    try:
        out = subprocess.run(
            ["git", "show", "--format=%H%n%s", "--unified=3", sha],
            cwd=path, capture_output=True, timeout=90,
        )
        if out.returncode != 0:
            return None
        return out.stdout.decode("utf-8", errors="replace")
    except Exception:
        return None


def patch_from_http(owner, repo, sha):
    url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
    req = urllib.request.Request(url, headers={"User-Agent": "wave-harvester"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return f"__HTTPERR__{e.code}"
    except Exception:
        return None


def ts_files_in(patch_text):
    files = [f.strip() for f in _DIFF_FILE_RE.findall(patch_text)]
    return [f for f in files if _TS_RE.search(f) and not _SKIP_PATH.search(f)]


def stage_patches(limit, sleep_s):
    if not os.path.exists(CAND_TSV):
        log(f"missing {CAND_TSV} -- run --stage advisories first")
        return 1
    os.makedirs(PATCH_DIR, exist_ok=True)

    with open(CAND_TSV, encoding="utf-8") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        cands = [dict(zip(header, l.rstrip("\n").split("\t"))) for l in fh if l.strip()]
    log(f"candidates: {len(cands)}")

    funnel = collections.Counter()
    targets = []
    processed = 0

    for c in cands:
        if limit and processed >= limit:
            break
        owner, repo, sha = c["owner"], c["repo"], c["sha"]
        cache = os.path.join(PATCH_DIR, f"{owner}__{repo}__{sha}.patch")

        if os.path.exists(cache):
            text = open(cache, encoding="utf-8", errors="replace").read()
            funnel["cached"] += 1
        else:
            processed += 1
            local = find_local_clone(owner, repo)
            text = patch_from_clone(local, sha) if local else None
            if text:
                funnel["from_local_clone"] += 1
            else:
                text = patch_from_http(owner, repo, sha)
                if text is None:
                    funnel["fetch_failed"] += 1
                    continue
                if text.startswith("__HTTPERR__"):
                    funnel[f"http_{text.replace('__HTTPERR__','')}"] += 1
                    if text.endswith("429") or text.endswith("403"):
                        log("  rate-limited -- backing off 60s")
                        time.sleep(60)
                    continue
                funnel["from_http"] += 1
                time.sleep(sleep_s)
            with open(cache, "w", encoding="utf-8") as out:
                out.write(text)

        ts = ts_files_in(text)
        if not ts:
            funnel["no_ts_file"] += 1
            continue
        funnel["TS_HIT"] += 1
        targets.append({**c, "ts_files": "|".join(ts[:5]), "patch": cache})

    cols = ["id", "owner", "repo", "sha", "cwes", "ts_files", "patch", "summary"]
    with open(TS_TSV, "w", encoding="utf-8", newline="") as fh:
        fh.write("\t".join(cols) + "\n")
        for t in targets:
            fh.write("\t".join(str(t.get(c, "")) for c in cols) + "\n")

    log("")
    log("=== funnel ===")
    for k, v in funnel.most_common():
        log(f"  {k:26s} {v}")
    log("")
    log(f"TS-touching fix commits: {len(targets)} -> {TS_TSV}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=["advisories", "patches"], required=True)
    ap.add_argument("--limit", type=int, default=0, help="max NEW patches to fetch")
    ap.add_argument("--sleep", type=float, default=1.5, help="seconds between HTTP fetches")
    a = ap.parse_args()
    if a.stage == "advisories":
        stage_advisories()
        return 0
    return stage_patches(a.limit, a.sleep)


if __name__ == "__main__":
    sys.exit(main())
