"""Plant known vulnerabilities in a COPY of a real project, then measure recall.

The scanner has only ever been tested on code where we did not know the answer. This
creates a controlled ground truth: N vulnerabilities at known file/line, planted into
real application code so the surrounding context is genuine rather than a toy snippet.

Deliberately mixed so the result is diagnostic rather than flattering:
  * classes the corpus trains heavily (SQLi, command injection, path traversal, XSS)
  * classes it barely covers (SSRF, insecure deserialization, weak crypto)
  * one where a guard IS present but insufficient -- the completeness class, and the
    one the whole project exists to teach
  * both languages: python backend and tsx frontend

Each plant records the exact file, the marker line, and the CWE, so recall is measured
rather than eyeballed.

    python plant_vulns.py --write
    python plant_vulns.py --report      # after scanning, score detection
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path("data/vulntest")
LEDGER = ROOT / "PLANTED.json"

# (id, relative path, anchor to insert after, code, cwe, note)
PLANTS = [
    ("P1-sqli", "backend/routes/catalog.py", None, '''

async def search_by_title_raw(db, title: str):
    """Search manga by title."""
    cur = db.cursor()
    cur.execute("SELECT id, title FROM manga WHERE title LIKE '%" + title + "%'")
    return cur.fetchall()
''', "CWE-89", "string-concatenated SQL, no parameterisation"),

    ("P2-cmdi", "backend/helpers.py", None, '''

def make_thumbnail(source_path: str, out_name: str):
    """Generate a thumbnail via imagemagick."""
    import subprocess
    subprocess.run(f"convert {source_path} -resize 200x300 /tmp/{out_name}", shell=True)
''', "CWE-78", "shell=True with interpolated caller input"),

    ("P3-path", "backend/routes/download.py", None, '''

def read_local_chapter(chapter_file: str):
    """Serve a previously downloaded chapter from disk."""
    base = "/var/lib/mangaryu/chapters/"
    with open(base + chapter_file, "rb") as fh:
        return fh.read()
''', "CWE-22", "concatenated path, no containment check"),

    ("P4-ssrf", "backend/suwayomi.py", None, '''

async def fetch_cover_from(url: str):
    """Fetch a cover image from an upstream source."""
    import requests
    resp = requests.get(url, timeout=10)
    return resp.content
''', "CWE-918", "server fetches a caller-supplied URL"),

    ("P5-deser", "backend/cache.py", None, '''

def restore_session_blob(blob: bytes):
    """Rehydrate a cached session payload."""
    import pickle
    return pickle.loads(blob)
''', "CWE-502", "pickle.loads on untrusted bytes"),

    ("P6-weakcrypto", "backend/audit.py", None, '''

def audit_token(secret: str) -> str:
    """Fingerprint for the audit log."""
    import hashlib
    return hashlib.md5(secret.encode()).hexdigest()
''', "CWE-327", "md5 used for a security fingerprint"),

    # The completeness case: a guard IS present and it is not enough.
    ("P7-incomplete-guard", "backend/routes/manga.py", None, '''

def load_cover(cover_name: str):
    """Load a cover image; only simple names are allowed."""
    if ".." in cover_name:
        raise ValueError("bad name")
    return open("/var/lib/mangaryu/covers/" + cover_name, "rb").read()
''', "CWE-22", "guard present but incomplete: blocks .. and misses an absolute path"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--report", action="store_true")
    args = ap.parse_args()

    if args.report:
        return report()

    ledger = []
    for pid, rel, _anchor, code, cwe, note in PLANTS:
        target = ROOT / rel
        if not target.exists():
            print(f"  MISSING target, skipped: {rel}")
            continue
        original = target.read_text(encoding="utf-8", errors="replace")
        start_line = original.count("\n") + 2
        target.write_text(original.rstrip() + "\n" + code, encoding="utf-8")
        ledger.append({"id": pid, "file": rel, "line": start_line,
                       "cwe": cwe, "note": note})
        print(f"  planted {pid:22s} {rel}:{start_line}  {cwe}")

    if args.write:
        LEDGER.write_text(json.dumps(ledger, indent=1), encoding="utf-8")
        print(f"\n-> {LEDGER}  ({len(ledger)} planted)")
    return 0


def report():
    """Score a scanner JSON run against the ledger. Reads findings on stdin."""
    ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    findings = json.load(sys.stdin)
    found, missed = [], []
    for pl in ledger:
        hit = None
        for f in findings:
            same_file = Path(f.get("file", "")).name == Path(pl["file"]).name
            if not same_file:
                continue
            # planted blocks sit at the end of the file; accept anything at or past
            # the marker line, or a function whose source contains our marker
            if f.get("line", 0) >= pl["line"] - 3:
                hit = f
                break
        (found if hit else missed).append((pl, hit))

    print(f"\n=== planted-vulnerability recall ===")
    print(f"  planted: {len(ledger)}   detected: {len(found)}   missed: {len(missed)}")
    for pl, hit in found:
        cwe_ok = "CWE match" if hit.get("model_cwe") == pl["cwe"] else \
                 f"CWE WRONG (said {hit.get('model_cwe')}, is {pl['cwe']})"
        print(f"  FOUND  {pl['id']:22s} {pl['cwe']:9s} {hit.get('confidence','')[:34]}  {cwe_ok}")
    for pl, _ in missed:
        print(f"  MISS   {pl['id']:22s} {pl['cwe']:9s} {pl['note']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
