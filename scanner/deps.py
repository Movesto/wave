"""Station 0: dependency (SCA) scanner. Is a pinned package a known-vulnerable version?

This is the category wave's SAST stations do NOT cover -- they reason about the project's
OWN code; this checks whether a DEPENDENCY is a version with a published CVE. It is the
npm equivalent of the setuptools / msgpack findings Trivy produced on Manga_Ryu.

No network: the 223,858-advisory OSV bulk dump is already on disk (data/osv/npm_all.zip).
Build an npm-only index once (cached), then match every dependency in the repo's
package.json files against it.

Precision note, stated because it matters: a package.json range like `^2.0.35` does not
pin a version -- the installed one depends on a lockfile we may not have. Exact pins
(`colors: 1.4.0`) get a definitive answer. For a range, the FLOOR version is checked and
the finding is marked `approx` -- it means "the lowest version this range allows is
vulnerable", which is a real signal but not proof of what is installed.

    python scanner/deps.py data/juice-shop
    python scanner/deps.py data/juice-shop --json
"""
import argparse
import json
import re
import sys
import zipfile
from pathlib import Path

OSV_ZIP = Path("data/osv/npm_all.zip")
INDEX = Path("data/osv/npm_dep_index.json")


def ver_tuple(v: str):
    """Numeric (major, minor, patch...) with pre-release stripped, for comparison.

    npm semver is not PEP440, but for the introduced/fixed range checks that dominate
    advisories a numeric-tuple compare on the release segment is correct. A pre-release
    ('1.5.0-rc.1') is treated as its release for ordering, which can only make the check
    more conservative (flag rather than miss).
    """
    core = re.split(r"[-+]", v.strip().lstrip("v="))[0]
    parts = re.findall(r"\d+", core)
    return tuple(int(x) for x in parts[:4]) + (0,) * (4 - len(parts[:4]))


def build_index():
    """package-name -> [ {cve, ghsa, severity, ranges:[(introduced,fixed)], versions} ]"""
    print(f"building npm index from {OSV_ZIP} ...", flush=True)
    z = zipfile.ZipFile(OSV_ZIP)
    idx = {}
    n = 0
    for name in z.namelist():
        if not name.endswith(".json"):
            continue
        n += 1
        if n % 40000 == 0:
            print(f"  {n} advisories, {len(idx)} npm packages", flush=True)
        try:
            a = json.loads(z.read(name))
        except Exception:
            continue
        aid = a.get("id", "")
        aliases = a.get("aliases", [])
        cve = next((x for x in [aid] + aliases if x.startswith("CVE-")), "")
        ghsa = next((x for x in [aid] + aliases if x.startswith("GHSA-")), aid)
        sev = ""
        for s in a.get("severity", []):
            sev = s.get("score", "") or sev
        db = a.get("database_specific", {}) or {}
        sev = sev or db.get("severity", "")
        summary = a.get("summary", "")[:90]
        for aff in a.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("ecosystem") != "npm":
                continue
            pname = pkg.get("name")
            if not pname:
                continue
            ranges = []
            for rng in aff.get("ranges", []):
                intro = fixed = None
                for ev in rng.get("events", []):
                    if "introduced" in ev:
                        intro = ev["introduced"]
                    if "fixed" in ev:
                        fixed = ev["fixed"]
                ranges.append((intro or "0", fixed))
            idx.setdefault(pname, []).append({
                "cve": cve, "ghsa": ghsa, "severity": sev, "summary": summary,
                "ranges": ranges, "versions": aff.get("versions", []),
            })
    INDEX.write_text(json.dumps(idx), encoding="utf-8")
    print(f"-> {INDEX}  ({len(idx)} npm packages, {n} advisories scanned)")
    return idx


def load_index():
    if INDEX.exists():
        return json.loads(INDEX.read_text(encoding="utf-8"))
    return build_index()


def is_affected(version: str, adv: dict) -> bool:
    v = ver_tuple(version)
    if adv["versions"] and version.lstrip("^~>=v ") in adv["versions"]:
        return True
    for intro, fixed in adv["ranges"]:
        if v >= ver_tuple(intro) and (fixed is None or v < ver_tuple(fixed)):
            return True
    return False


def scan_manifest(path: Path, idx: dict):
    data = json.loads(path.read_text(encoding="utf-8"))
    deps = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        deps.update(data.get(key, {}) or {})
    findings = []
    for name, spec in deps.items():
        advs = idx.get(name)
        if not advs:
            continue
        exact = bool(re.fullmatch(r"\d+\.\d+\.\d+.*", spec.strip()))
        version = spec.strip().lstrip("^~>=v ")
        for adv in advs:
            if is_affected(version, adv):
                findings.append({
                    "package": name, "spec": spec, "checked_version": version,
                    "exact": exact, "cve": adv["cve"], "ghsa": adv["ghsa"],
                    "severity": adv["severity"], "summary": adv["summary"],
                    "manifest": str(path),
                })
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--rebuild", action="store_true")
    args = ap.parse_args()

    idx = build_index() if args.rebuild else load_index()

    root = Path(args.target)
    manifests = [root] if root.name == "package.json" else [
        p for p in root.rglob("package.json") if "node_modules" not in str(p)]
    all_findings = []
    for m in manifests:
        all_findings.extend(scan_manifest(m, idx))

    if args.json:
        print(json.dumps(all_findings, indent=1))
        return 0

    if not all_findings:
        print("No vulnerable dependencies matched.")
        return 0
    exact = [f for f in all_findings if f["exact"]]
    approx = [f for f in all_findings if not f["exact"]]
    print(f"\n{len(all_findings)} vulnerable dependency finding(s) across "
          f"{len(manifests)} manifest(s)  "
          f"[{len(exact)} exact-pin, {len(approx)} range-floor/approx]\n")
    for tier, rows in (("EXACT PIN (definitive)", exact),
                       ("RANGE FLOOR (approx - depends on lockfile)", approx)):
        if not rows:
            continue
        print(f"===== {tier} =====")
        for f in sorted(rows, key=lambda x: x["package"]):
            ident = f["cve"] or f["ghsa"]
            print(f"  {f['package']}@{f['spec']:12s} {ident:20s} "
                  f"{f['severity'][:20]:20s} {f['summary']}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
