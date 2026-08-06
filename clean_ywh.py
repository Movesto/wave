"""Strip every vulnerability-naming giveaway from the YesWeHack snippets.

The snippets carry a `$title = 'Vsnippet #N - <VULN NAME>'` line and `<title>`/`<h1>`
tags that echo it, plus a YesWeHack comment block -- all of which NAME the vulnerability.
Feeding those to the model would test its reading of a label, not of code. This removes
them and writes one clean file per category, so the model sees code only.
"""
import glob
import json
import os
import re

CAT_CWE = {
    "SQLi": "CWE-89", "CommandInjection": "CWE-78", "SSRF": "CWE-918",
    "PathTraversal": "CWE-22", "SSTI": "CWE-1336", "PrototypePollution": "CWE-1321",
    "CodeInjection": "CWE-94", "OpenRedirect": "CWE-601", "LFI": "CWE-98",
    "IDOR": "CWE-639", "XSS": "CWE-79", "Deserialization": "CWE-502",
}

# Anything that names a weakness in prose -- title strings, headings, comments.
_LEAK = re.compile(
    r"server-?side request forgery|ssrf|sql\s*inject|command\s*inject|path\s*traversal"
    r"|local file inclusion|\blfi\b|template inject|\bssti\b|prototype pollut"
    r"|deserial|open\s*redirect|cross[- ]site scripting|\bxss\b|\bidor\b|code inject"
    r"|insecure direct object|yeswehack|vsnippet|vuln", re.I)

OUT = "data/ywh-snippets/_clean"


def clean(code: str) -> str:
    code = code.replace("\r", "")
    code = re.sub(r"\$title\s*=\s*'[^']*';", "$title = '';", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)          # block comments
    lines = []
    for ln in code.splitlines():
        stripped = ln.strip()
        # drop comment lines and any line that names a weakness in prose
        if stripped.startswith(("//", "#", "*", "<!--")):
            continue
        if _LEAK.search(ln) and ("<" in ln or "title" in ln.lower() or "=" not in ln
                                 or ln.lstrip().startswith(("<h", "<title"))):
            continue
        lines.append(ln)
    return "\n".join(l for l in lines).strip()


def main():
    os.makedirs(OUT, exist_ok=True)
    picks = []
    for cat, cwe in CAT_CWE.items():
        for f in sorted(glob.glob(f"data/ywh-snippets/{cat}/*/vsnippet/*.*")):
            if any(x in f for x in ("/ignore/", "/design", "/templates", "/config",
                                    ".html", ".txt", ".conf", ".yml")):
                continue
            if f.rsplit(".", 1)[-1] not in ("php", "py", "js"):
                continue
            c = clean(open(f, encoding="utf-8", errors="replace").read())
            outp = f"{OUT}/{cat}.txt"
            open(outp, "w", encoding="utf-8").write(c)
            picks.append([cat, cwe, outp, f.rsplit(".", 1)[-1]])
            break
    json.dump(picks, open("data/ywh-snippets/_manifest.json", "w"))

    # verify nothing leaked
    leaked = [p[0] for p in picks
              if _LEAK.search(open(p[2], encoding="utf-8").read())]
    print(f"{len(picks)} snippets cleaned; still leaking: {leaked or 'none'}")
    for cat, cwe, outp, lang in picks:
        print(f"  {cat:20s} {cwe:9s} {lang}")


if __name__ == "__main__":
    main()
