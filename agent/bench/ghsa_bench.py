"""Run wave against the Cisco GHSA vulnerability-localization-benchmark (500 real CVEs) and score.

Their task is LOCALIZATION (name the vulnerable file); ours is PROVING (run it, observe the effect). So
we repurpose the repos and measure a stricter thing: did wave CONFIRM a real vuln, and did the confirmed
file land in the ground-truth patched files? We select our lane -- npm/pip repos whose CWE is a class
wave can prove (injection/XSS/path/SSRF) -- fetch each vulnerable commit straight from GitHub's archive
URL (no full 500-repo download), run the loop, and diff proven files vs ground_truth_files.

  # ollama must be serving the agent model:
  WAVE_API_BASE=http://localhost:11434/v1  WAVE_MODEL=hf.co/.../...:Q6_K \
  python -m agent.bench.ghsa_bench --limit 8
"""
import argparse
import csv
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = _ROOT / "data" / "downloads" / "vlb" / "data" / "manifest.csv"
# CWE classes wave can PROVE today (injection / XSS / path / SSRF / template / code-eval)
OUR_CWES = {"78", "79", "89", "94", "95", "22", "918", "77", "1336", "917", "90", "611", "116", "80", "83"}
_PROVEN = re.compile(r"\[PROVEN\s+CWE-\d+\]\s+(.+?):\d+", re.I)


def _cwes(row):
    try:
        return {c.split("-")[-1] for c in json.loads(row["cwes"])}
    except Exception:
        return set(re.findall(r"CWE-(\d+)", row["cwes"]))


def _gt_files(row):
    try:
        return {f.replace("\\", "/") for f in json.loads(row["ground_truth_files"])}
    except Exception:
        return set()


def select(ecosystems, max_kb, limit):
    rows = []
    with open(MANIFEST, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["ecosystem"] not in ecosystems or not (_cwes(r) & OUR_CWES):
                continue
            kb = float(r["vulnerable_zip_kb"] or 9e9)
            if kb <= max_kb:
                rows.append(r)
    rows.sort(key=lambda r: float(r["vulnerable_zip_kb"] or 9e9))
    return rows[:limit] if limit else rows


def fetch_extract(row, workdir):
    """Download the vulnerable commit's source zip from GitHub, extract, return the repo root."""
    url = f"https://github.com/{row['repo_full_name']}/archive/{row['vulnerable_commit_sha']}.zip"
    req = urllib.request.Request(url, headers={"User-Agent": "wave-ghsa-bench/1.0"})
    data = urllib.request.urlopen(req, timeout=180).read()
    zipfile.ZipFile(io.BytesIO(data)).extractall(workdir)
    dirs = [p for p in Path(workdir).iterdir() if p.is_dir()]
    return dirs[0] if dirs else Path(workdir)


def run_wave(repo_dir, timeout):
    """Run the loop as a subprocess; return the set of proven files (repo-relative)."""
    # --reader-all: these are LIBRARIES (no web request->sink surface), so read every file, not just the
    # surface-scored ones -- otherwise prioritize_files reads 0 files and there's nothing to investigate.
    cmd = [sys.executable, "-u", "-m", "agent.orchestrator.run", "loop", str(repo_dir),
           "--reader", "--reader-all", "--investigate", "--investigate-budget", "5"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(_ROOT),
                           encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return None, "timeout"
    out = (p.stdout or "") + (p.stderr or "")
    proven = set()
    for m in _PROVEN.finditer(out):
        f = m.group(1).strip()
        try:
            proven.add(os.path.relpath(f, repo_dir).replace("\\", "/"))
        except Exception:
            proven.add(f.replace("\\", "/"))
    return proven, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ecosystems", default="npm,pip")
    ap.add_argument("--max-kb", type=float, default=2000, help="skip repos whose vulnerable zip is larger")
    ap.add_argument("--limit", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=900, help="per-repo seconds")
    a = ap.parse_args()

    if not MANIFEST.is_file():
        sys.exit(f"manifest not found at {MANIFEST} -- clone the benchmark into data/downloads/vlb first")
    lane = select(tuple(a.ecosystems.split(",")), a.max_kb, a.limit)
    print(f"selected {len(lane)} entries (ecosystems={a.ecosystems}, <= {a.max_kb}kb)\n", flush=True)

    rows_out = []
    for i, row in enumerate(lane, 1):
        gt = _gt_files(row)
        cwe = sorted(_cwes(row) & OUR_CWES)
        tag = f"[{i}/{len(lane)}] {row['alpha_id']} {row['repo_full_name']} CWE{cwe}"
        print(f"{'#' * 70}\n{tag}\n  ground-truth files: {sorted(gt)}", flush=True)
        with tempfile.TemporaryDirectory(prefix="wave_ghsa_") as wd:
            try:
                repo = fetch_extract(row, wd)
            except Exception as e:
                print(f"  download failed: {type(e).__name__}: {e}", flush=True)
                rows_out.append({"id": row["alpha_id"], "status": "download_fail"})
                continue
            proven, out = run_wave(repo, a.timeout)
            if proven is None:
                print("  wave: TIMEOUT", flush=True)
                rows_out.append({"id": row["alpha_id"], "status": "timeout"})
                continue
            hit = bool(proven & gt)
            print(f"  wave PROVEN files: {sorted(proven) or '(none)'}", flush=True)
            print(f"  => {'HIT (proven in a ground-truth file)' if hit else 'miss' if proven else 'nothing proven'}",
                  flush=True)
            rows_out.append({"id": row["alpha_id"], "cwe": cwe, "hit": hit,
                             "proven": sorted(proven), "gt": sorted(gt), "n_proven": len(proven)})

    scored = [r for r in rows_out if "hit" in r]
    hits = sum(1 for r in scored if r["hit"])
    proved_something = sum(1 for r in scored if r["n_proven"])
    print(f"\n{'=' * 70}\nSCORECARD  ({len(rows_out)} attempted, {len(scored)} ran)")
    print(f"  proved a vuln IN a ground-truth file (hit): {hits}/{len(scored)}")
    print(f"  proved SOMETHING (incl. outside gt):        {proved_something}/{len(scored)}")
    print(f"  download/timeout failures:                  {len(rows_out) - len(scored)}")


if __name__ == "__main__":
    main()
