"""Cross-file symbol resolution for the two-pass agentic generation.

When the model (pass 1) says it can't judge a multi-file CVE because a helper is out of view, we
fetch the code it named and hand it back (pass 2). Most named symbols live in a file the patch
already TOUCHED (measured), so we fetch the touched files at the exact commit via GitHub raw and
extract the symbol's definition. No clone, no auth, bounded to what was asked.

  from resolve import resolve_symbols
  defs = resolve_symbols(patch_filename, sha, ["runScheduledRefresh"], patch_text)
  # -> {"runScheduledRefresh": ("packages/.../gateway.ts", "<definition snippet>")}
"""
import os, re, urllib.request, urllib.error

MOREFIXES = "data/downloads/morefixes-patches/cvedataset-patches"
_RAW = "https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}"
_FILE_RE = re.compile(r"^\+\+\+ b/(.+?)\s*$", re.M)
_cache = {}                                   # (owner_repo, sha, path) -> content or None


def parse_repo_sha(patch_filename):
    """github.com_<owner>_<repo>_<sha>.patch -> ('<owner>_<repo>', sha). Owner/repo may contain
    underscores, so the split is resolved later by trying each boundary against raw."""
    base = patch_filename[:-6] if patch_filename.endswith(".patch") else patch_filename
    base = base.split("github.com_", 1)[-1]
    sha = base[-40:]
    owner_repo = base[:-41]                    # drop the trailing "_<40hex>"
    return owner_repo, sha


def fetch_raw(owner_repo, sha, path, timeout=20):
    """Fetch a file at a commit. Tries each owner/repo underscore split until one resolves."""
    key = (owner_repo, sha, path)
    if key in _cache:
        return _cache[key]
    parts = owner_repo.split("_")
    content = None
    for i in range(1, len(parts)):
        owner, repo = "_".join(parts[:i]), "_".join(parts[i:])
        url = _RAW.format(owner=owner, repo=repo, sha=sha, path=path)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "wave-resolve"})
            content = urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "ignore")
            break
        except urllib.error.HTTPError:
            continue
        except Exception:
            continue
    _cache[key] = content
    return content


def touched_files(patch_filename, patch_text=None):
    if patch_text is None:
        path = patch_filename if os.path.isabs(patch_filename) else os.path.join(MOREFIXES, patch_filename)
        patch_text = open(path, encoding="utf-8", errors="ignore").read()
    # de-dup, keep order; skip test/spec/fixture files
    seen, out = set(), []
    for p in _FILE_RE.findall(patch_text):
        if p in seen:
            continue
        seen.add(p)
        low = p.lower()
        if any(t in low for t in ("test", "spec", "__tests__", "/fixtures/", ".min.")):
            continue
        out.append(p)
    return out


# a line that DEFINES `sym` across common languages (function/method/const/class/assignment)
def _def_line_re(sym):
    s = re.escape(sym)
    return re.compile(
        r"(?:^|\s)(?:def|function|func|class|interface|struct|type)\s+" + s + r"\b"      # def sym
        r"|(?:const|let|var|public|private|protected|static|final|async|export)\s+" + s + r"\b"
        r"|\b" + s + r"\s*[:=]\s*(?:async\s*)?(?:function|\([^)]*\)\s*(?:=>|\{|:))"        # sym = fn
        r"|\b" + s + r"\s*\([^)]*\)\s*(?:=>|\{|:|throws|->)"                               # sym(...) {
        r"|(?:def|fun|sub)\s+" + s + r"\b",
        re.M)


def extract_def(content, symbol, max_lines=48, max_chars=1600):
    """Return the definition block for `symbol` from `content`, or None. Brace-matched when the def
    line opens a brace; otherwise an indentation block; otherwise a bounded window."""
    m = _def_line_re(symbol).search(content or "")
    if not m:
        return None
    lines = content.splitlines()
    # locate the line index of the match
    start_off = content.count("\n", 0, m.start())
    i = start_off
    block = [lines[i]]
    if "{" in lines[i] or "{" in (lines[i + 1] if i + 1 < len(lines) else ""):
        depth = lines[i].count("{") - lines[i].count("}")
        j = i + 1
        if depth <= 0 and j < len(lines):     # brace on next line
            depth += lines[j].count("{") - lines[j].count("}"); block.append(lines[j]); j += 1
        while j < len(lines) and depth > 0 and len(block) < max_lines:
            depth += lines[j].count("{") - lines[j].count("}")
            block.append(lines[j]); j += 1
    else:                                     # indentation block (python-style) or bounded window
        base_indent = len(lines[i]) - len(lines[i].lstrip())
        j = i + 1
        while j < len(lines) and len(block) < max_lines:
            ln = lines[j]
            if ln.strip() and (len(ln) - len(ln.lstrip())) <= base_indent and j > i + 1:
                break
            block.append(ln); j += 1
    snippet = "\n".join(block)
    # reject a bare variable declaration (e.g. `let textHTML;`): no body, nothing to reason about.
    # A useful definition has a call signature or an opening block somewhere in it.
    body = "\n".join(block[:6])
    if "(" not in body and "{" not in body and len(block) <= 2:
        return None
    return snippet[:max_chars]


def resolve_symbols(patch_filename, sha, symbols, patch_text=None, max_syms=4):
    """For each symbol the model asked for, find its definition in a touched file at `sha`.
    Returns {symbol: (path, snippet)} for the ones we could resolve (capped at max_syms)."""
    owner_repo, sha0 = parse_repo_sha(patch_filename)
    sha = sha or sha0
    files = touched_files(patch_filename, patch_text)
    found, fetched = {}, {}
    for sym in symbols:
        if len(found) >= max_syms:
            break
        for p in files:
            if p not in fetched:
                fetched[p] = fetch_raw(owner_repo, sha, p)
            content = fetched[p]
            if not content:
                continue
            snip = extract_def(content, sym)
            if snip:
                found[sym] = (p, snip)
                break
    return found


if __name__ == "__main__":
    import json, sys
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    wl = {json.loads(l)["cve"]: json.loads(l)
          for l in open("data/cot/staging/regen_worklist.jsonl", encoding="utf-8")}
    for cve, syms in [("CVE-2022-23510", ["runScheduledRefresh", "queryingOptions"]),
                      ("CVE-2022-24815", ["findById", "createQuery"])]:
        r = wl[cve]
        d = resolve_symbols(r["patch"], r["sha"], syms)
        print("=" * 70, cve)
        for sym, (path, snip) in d.items():
            print(f"--- {sym}  <-  {path} ---")
            print(snip[:400])
        if not d:
            print("  (nothing resolved)")
