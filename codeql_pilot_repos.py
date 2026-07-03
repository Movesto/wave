"""Identify CodeQL pilot repos: multi-file patches in no-build languages
(Python/JS/TS), with the (owner, repo, fix-commit) parsed from patch filenames.
Prefers Python/JS repos (CodeQL extracts them without a build)."""
import os, re
from collections import defaultdict

PD = "data/downloads/morefixes-patches/cvedataset-patches"
NOBUILD = {".py", ".js", ".ts", ".tsx", ".jsx"}
DIFF = re.compile(r"^diff --git a/(.+?) b/(.+)$", re.M)
NAME = re.compile(r"github\.com_(.+)_([0-9a-f]{40})\.patch$")

repo_patches = defaultdict(list)
lang_of = {}
for fn in os.listdir(PD):
    if not fn.endswith(".patch"):
        continue
    m = NAME.match(fn)
    if not m:
        continue
    ownerrepo, commit = m.group(1), m.group(2)
    parts = ownerrepo.split("_", 1)
    if len(parts) != 2:
        continue
    owner, repo = parts
    try:
        text = open(os.path.join(PD, fn), encoding="utf-8", errors="replace").read()
    except Exception:
        continue
    files = [g[1] for g in DIFF.findall(text)]
    exts = [os.path.splitext(f)[1].lower() for f in files]
    nobuild = [e for e in exts if e in NOBUILD]
    if len(files) >= 2 and len(nobuild) >= 2:
        key = f"{owner}/{repo}"
        repo_patches[key].append((commit, fn))
        # dominant no-build language
        py = sum(1 for e in exts if e == ".py")
        js = sum(1 for e in exts if e in (".js", ".ts", ".tsx", ".jsx"))
        lang_of[key] = "python" if py >= js else "javascript"

print(f"multi-file no-build patches across {len(repo_patches)} repos")
print(f"{'repo':<42}{'lang':<12}{'#patches'}")
for r, c in sorted(repo_patches.items(), key=lambda x: -len(x[1]))[:20]:
    print(f"  {r:<40}{lang_of[r]:<12}{len(c)}")
# write the full list for the pilot driver
with open("codeql_targets.tsv", "w", encoding="utf-8") as f:
    for r, lst in repo_patches.items():
        for commit, fn in lst:
            f.write(f"{r}\t{lang_of[r]}\t{commit}\t{fn}\n")
print(f"\nwrote codeql_targets.tsv ({sum(len(v) for v in repo_patches.values())} rows)")
