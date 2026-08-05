"""Plant vulnerabilities by SUBTLY BREAKING existing correct code.

The first attempt appended announced functions (`def read_local_chapter`, with a
docstring naming the risk) at the ends of files. That is a giveaway -- a model with any
reasoning can pattern-match the shape "obviously-planted helper". This version instead
takes code that is currently CORRECT and introduces the flaw in place: a parameterised
query becomes concatenated, a guard loses a clause, an internal URL becomes
caller-controlled. No new function names, no comments, no markers. The surrounding code
is the project's own, so the vuln has to be found by reasoning about the change, not by
spotting an alien block.

Each plant is an exact string replacement, and the ledger records the file, the line the
edit lands on, and the CWE, so recall is measured.

    python plant_vulns_hard.py --write
    python plant_vulns_hard.py --report < findings.json
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path("data/vulntest")
LEDGER = ROOT / "PLANTED_HARD.json"

# (id, file, find, replace, cwe, note)
PLANTS = [
    # H1: a correctly parameterised query -> string concatenation. The single most
    # realistic plant: this is exactly the mistake a junior makes editing working code.
    ("H1-sqli", "backend/routes/manga.py",
     'cur.execute("SELECT rating FROM manga WHERE id = %s", (int(manga_id),))',
     'cur.execute("SELECT rating FROM manga WHERE id = " + manga_id)',
     "CWE-89", "parameterised query changed to concatenation"),

    # H2: safe_fetch already builds an internal URL from `endpoint`. Make the whole URL
    # caller-controlled -- SSRF hiding in a function whose docstring is about JSON errors.
    ("H2-ssrf", "backend/suwayomi.py",
     'url = f"{BASE_URL}/{endpoint}"',
     'url = endpoint if endpoint.startswith("http") else f"{BASE_URL}/{endpoint}"',
     "CWE-918", "endpoint may now be a full external URL"),

    # H3: an incomplete path guard tucked into a real image helper. Blocks '..' but not
    # an absolute path, and the value flows straight into open().
    ("H3-path-incomplete", "backend/routes/html_reader.py",
     'def _to_data_uri(raw: bytes, mime: str) -> str:',
     'def _load_cover_file(name: str) -> bytes:\n'
     '    if ".." in name:\n'
     '        raise ValueError("bad")\n'
     '    with open("/var/lib/mangaryu/cache/" + name, "rb") as _fh:\n'
     '        return _fh.read()\n\n\n'
     'def _to_data_uri(raw: bytes, mime: str) -> str:',
     "CWE-22", "guard present (blocks ..) but misses absolute path"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--report", action="store_true")
    a = ap.parse_args()
    if a.report:
        return report()

    ledger = []
    for pid, rel, find, repl, cwe, note in PLANTS:
        f = ROOT / rel
        if not f.exists():
            print(f"  MISSING {rel}")
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        if find not in text:
            print(f"  ANCHOR NOT FOUND in {rel} for {pid} -- skipped")
            continue
        line = text[:text.index(find)].count("\n") + 1
        f.write_text(text.replace(find, repl, 1), encoding="utf-8")
        ledger.append({"id": pid, "file": rel, "line": line, "cwe": cwe, "note": note})
        print(f"  planted {pid:20s} {rel}:{line}  {cwe}")

    if a.write:
        LEDGER.write_text(json.dumps(ledger, indent=1), encoding="utf-8")
        print(f"\n-> {LEDGER} ({len(ledger)} planted)")
    return 0


def report():
    ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    findings = json.load(sys.stdin)
    found = 0
    print("\n=== HARD plant recall (vulns hidden inside real functions) ===")
    for pl in ledger:
        hit = None
        for f in findings:
            if Path(f.get("file", "")).name != Path(pl["file"]).name:
                continue
            if abs(f.get("line", -99) - pl["line"]) <= 8:
                hit = f
                break
        if hit:
            found += 1
            cwe_ok = "CWE ok" if hit.get("model_cwe") == pl["cwe"] else \
                     f"CWE said {hit.get('model_cwe')}"
            print(f"  FOUND  {pl['id']:20s} {pl['cwe']:9s} "
                  f"{hit.get('confidence','')[:30]}  {cwe_ok}")
        else:
            print(f"  MISS   {pl['id']:20s} {pl['cwe']:9s} {pl['note']}")
    print(f"\n  {found}/{len(ledger)} detected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
