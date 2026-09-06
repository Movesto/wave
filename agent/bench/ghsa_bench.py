"""Run wave against the Cisco GHSA vulnerability-localization-benchmark (500 real CVEs) and score.

Their task is LOCALIZATION (name the vulnerable file); ours is PROVING (run it, observe the effect). So
we repurpose the repos and measure a stricter thing: did wave CONFIRM a real vuln, and did the confirmed
file land in the ground-truth patched files? We select our lane -- npm/pip repos whose CWE is a class
wave can prove (injection/XSS/path/SSRF) -- fetch each vulnerable commit straight from GitHub's archive
URL (no full 500-repo download), run the NEW pipeline (`run all`: eyes -> detect -> prove), and diff the
confirmed (+ anomalous/human-review) files from wave_findings.jsonl against ground_truth_files.

  # ollama must be serving the agent model:
  WAVE_API_BASE=http://localhost:11434/v1  WAVE_MODEL=hf.co/.../...:Q6_K \
  python -m agent.bench.ghsa_bench --limit 8
"""
import argparse
import csv
import io
import json
import re
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = _ROOT / "data" / "downloads" / "vlb" / "data" / "manifest.csv"
# CWE classes wave can PROVE today (injection / XSS / path / SSRF / template / code-eval / deserialization)
OUR_CWES = {"78", "79", "89", "94", "95", "22", "918", "77", "1336", "917", "90", "611", "116", "80", "83",
            "502", "943", "601"}


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


def run_wave(repo_dir, timeout, notes=15, detect=40, prove=10):
    """Run the NEW pipeline (`run all`: eyes -> detect -> prove) as a subprocess and read the proven files
    from wave_findings.jsonl. Returns (confirmed_files, anomalous_files, out).

    --no-reach-gate: the GHSA targets are LIBRARIES (public-API entry, no HTTP routes), so the reachability
    gate -- tuned for routes -- would wrongly downgrade a real library vuln to anomalous_state. The notebook
    is sink-pin-driven (not route-driven), so no --reader-all hack is needed for libraries anymore.
    Budgets default SMALL: a library's vuln lives in 1-3 files, so large budgets just cause the timeouts we
    saw (the prove stage -- multi-turn model runs -- is the time sink)."""
    cmd = [sys.executable, "-u", "-m", "agent.orchestrator.run", "all", str(repo_dir),
           "--notes-budget", str(notes), "--detect-budget", str(detect), "--prove-budget", str(prove),
           "--no-reach-gate"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(_ROOT),
                           encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return None, None, "timeout"
    out = (p.stdout or "") + (p.stderr or "")
    confirmed, anomalous = set(), set()
    findings = Path(repo_dir) / "wave_findings.jsonl"
    if findings.exists():
        # last verdict per (file,line,class); files are already repo-relative in the findings log
        last = {}
        for line in findings.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue
            last[(d.get("file"), d.get("line"), d.get("class"))] = d
        for d in last.values():
            f = str(d.get("file", "")).replace("\\", "/")
            if d.get("verdict") == "confirmed":
                confirmed.add(f)
            elif d.get("verdict") == "anomalous_state":
                anomalous.add(f)
    return confirmed, anomalous, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ecosystems", default="npm,pip")
    ap.add_argument("--max-kb", type=float, default=2000, help="skip repos whose vulnerable zip is larger")
    ap.add_argument("--limit", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=900, help="per-repo seconds")
    ap.add_argument("--notes-budget", type=int, default=15, help="files the notebook deep-reads per repo")
    ap.add_argument("--detect-budget", type=int, default=40, help="findings falsified per repo")
    ap.add_argument("--prove-budget", type=int, default=10, help="survivors proven per repo (the time sink)")
    ap.add_argument("--out", default=str(_ROOT / "ghsa_bench_results.json"),
                    help="write per-CVE results + scorecard here (so a run is checkable after it ends)")
    ap.add_argument("--keep-artifacts", action="store_true",
                    help="copy each CVE's wave_* artifacts + full run log to ghsa_artifacts/<id>/ (so a "
                         "miss or timeout is diagnosable -- the temp dir is otherwise cleaned)")
    ap.add_argument("--only", default=None,
                    help="run only these alpha_ids (comma-separated) -- for focused re-runs of specific CVEs")
    a = ap.parse_args()

    if not MANIFEST.is_file():
        sys.exit(f"manifest not found at {MANIFEST} -- clone the benchmark into data/downloads/vlb first")
    lane = select(tuple(a.ecosystems.split(",")), a.max_kb, a.limit)
    if a.only:                                              # focused re-run of specific CVEs
        want = {x.strip() for x in a.only.split(",")}
        lane = [r for r in lane if r["alpha_id"] in want]
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
            proven, anomalous, out = run_wave(repo, a.timeout, notes=a.notes_budget,
                                              detect=a.detect_budget, prove=a.prove_budget)
            if a.keep_artifacts:                            # copy the per-CVE evidence out before the temp dir
                dest = _ROOT / "ghsa_artifacts" / row["alpha_id"]   # is cleaned -- so a miss is diagnosable
                dest.mkdir(parents=True, exist_ok=True)
                import shutil
                for name in ("wave_findings.jsonl", "wave_notebook.jsonl", "wave_candidates.jsonl",
                             "wave_detect.jsonl", "casefile.json"):
                    src = Path(repo) / name
                    if src.exists():
                        shutil.copy(src, dest / name)
                (dest / "run.log").write_text(out or "", encoding="utf-8")   # the full pipeline stdout
            if proven is None:
                print("  wave: TIMEOUT", flush=True)
                rows_out.append({"id": row["alpha_id"], "status": "timeout"})
                continue
            hit = bool(proven & gt)                                  # CONFIRMED in a ground-truth file
            flagged = bool((proven | anomalous) & gt)               # confirmed OR anomalous (human-review) in gt
            print(f"  wave CONFIRMED files: {sorted(proven) or '(none)'}", flush=True)
            if anomalous:
                print(f"  wave anomalous/human-review files: {sorted(anomalous)}", flush=True)
            verdict = ("HIT (confirmed in a ground-truth file)" if hit else
                       "FLAGGED (anomalous in a ground-truth file)" if flagged else
                       "miss" if (proven or anomalous) else "nothing found")
            print(f"  => {verdict}", flush=True)
            rows_out.append({"id": row["alpha_id"], "cwe": cwe, "hit": hit, "flagged": flagged,
                             "proven": sorted(proven), "anomalous": sorted(anomalous), "gt": sorted(gt),
                             "n_proven": len(proven), "n_anomalous": len(anomalous)})

    scored = [r for r in rows_out if "hit" in r]
    hits = sum(1 for r in scored if r["hit"])
    flagged = sum(1 for r in scored if r.get("flagged"))
    found_something = sum(1 for r in scored if r["n_proven"] or r["n_anomalous"])
    summary = {"attempted": len(rows_out), "ran": len(scored), "hits": hits, "flagged": flagged,
               "found_something": found_something, "failures": len(rows_out) - len(scored)}
    print(f"\n{'=' * 70}\nSCORECARD  ({len(rows_out)} attempted, {len(scored)} ran)  [new pipeline: run all]")
    print(f"  CONFIRMED a vuln IN a ground-truth file (hit): {hits}/{len(scored)}")
    print(f"  confirmed OR anomalous(review) in gt:          {flagged}/{len(scored)}")
    print(f"  found SOMETHING (incl. outside gt):            {found_something}/{len(scored)}")
    print(f"  download/timeout failures:                     {len(rows_out) - len(scored)}")
    if a.out:                                              # persist so a run is checkable after it ends
        try:
            Path(a.out).write_text(json.dumps({"summary": summary, "rows": rows_out}, indent=2),
                                   encoding="utf-8")
            print(f"\n[results saved -> {a.out}]", flush=True)
        except OSError as e:
            print(f"\n[could not save results: {e}]", flush=True)


if __name__ == "__main__":
    main()
