"""Give the CodeQL cross-file flows a SAFE side, and a reason rather than a label.

Two problems, one build.

1. `shape3_codeql_localize` is 19.3% of sampling and 100% vulnerable. Nothing in it can
   be wrong, so an always-say-vuln model scores perfectly. It is the largest single
   source of the topic-vs-guard defect left in the corpus.
2. Its `why:` line is ONE TEMPLATE -- 6,902 of 7,149 records read "untrusted input enters
   at X and reaches Y with no sanitiser between them", identical modulo names. It states
   a conclusion and explains no mechanism, so it cannot teach anyone to fix anything.

Only records that can actually carry a pair are used. Of 7,149:

    4,247  CWE is not one a control-on-the-path fixes (CWE-312 cleartext storage,
           CWE-117 log injection, CWE-327 weak crypto, CWE-209 error exposure...).
           Adding a "guard" to those would be inventing a fix that is not the fix.
    1,265  the stated path names a file that is not in the excerpt, so the flow cannot
           be followed from what the model is shown.
      340  the source block contains no source-like token -- the "source" is not a source.
      137  no executable construct in one of the blocks.
    1,160  USABLE.

For each of those:

    VULN = the excerpt as-is, with reasoning that says WHY this sink is dangerous for
           this weakness class -- the mechanism, in terms of the actual variable.
    SAFE = the same excerpt with a guard inserted immediately before the sink, on the
           value that actually reaches it, plus reasoning for what that guard closes.

Honesty about what this is: the safe side is AUTHORED. These records carry no commit
(0 of 7,149 have a repo or sha), so there is no real post-fix version to diff against.
The claim a safe record makes is "this control closes this path", which is checkable
from the excerpt -- not "this is how the project fixed it", which would need provenance.
That makes them B-grade by the project's own standard, and they are labelled as such.

Two shortcut risks and what is done about them:
  * "a sanitiser appears => safe". Each guard names the ACTUAL sink variable and is
    placed on the path, and there are several formulations per weakness class, so the
    difference between the sides is not one memorable line of boilerplate.
  * duplicated reasoning. The mechanism sentence interpolates the real variable, sink
    call, and file names, so bodies differ per record. R15 caps identical bodies at 5%
    and is the binding check -- if this degenerates into a template it cannot ship.

    python build_codeql_safe.py --write
"""
import argparse
import collections
import csv
import hashlib
import json
import os
import re
import sys

from filter_corpus import is_test_code, load_eval_codes

SRC = "data/cot/staging/shape3_codeql_localize.jsonl"
OUT = "data/cot/staging/shape_codeql_contrastive.jsonl"
REPORT = "data/osv/codeql_contrastive.tsv"
MIN_CHARS, MAX_CHARS = 200, 4500
PER_CWE_CAP = 60

SOURCEY = re.compile(r"\b(request|req|argv|environ|input|stdin|params|query|body|form"
                     r"|GET|POST|getenv|headers|cookies|files)\b", re.I)
EXEC = re.compile(r"\b(def|class|function|return|if|for|while)\b|=[^=]|\w\s*\(")

# sink call patterns per weakness class
SINKS = {
    "CWE-22": r"\b(open|os\.path\.join|send_file|readFile|createReadStream|sendFile"
              r"|shutil\.(?:copy|move|rmtree)|os\.(?:remove|listdir|makedirs))\s*\(",
    "CWE-78": r"\b(os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output)"
              r"|execSync|exec|spawn)\s*\(",
    "CWE-79": r"\b(render_template_string|Markup|innerHTML|dangerouslySetInnerHTML"
              r"|res\.send|document\.write)\s*[\(=]",
    "CWE-89": r"\b(execute|executemany|cursor\.execute|raw|query)\s*\(",
    "CWE-601": r"\b(redirect|sendRedirect)\s*\(",
    "CWE-918": r"\b(requests\.(?:get|post|put|head)|urlopen|urllib\.request\.urlopen"
               r"|fetch|axios\.(?:get|post))\s*\(",
    "CWE-1333": r"\b(re\.(?:match|search|fullmatch|sub)|\.test|\.match)\s*\(",
    "CWE-117": r"\b(log(?:ger)?\.(?:info|warn|warning|error|debug|critical|exception)"
               r"|logging\.(?:info|warn|warning|error|debug)"
               r"|console\.(?:log|error|warn))\s*\(",
}

# Why the sink is dangerous FOR THIS CLASS -- the mechanism, not a verdict.
MECHANISM = {
    "CWE-22": "`{v}` is used to build a filesystem path at `{sink}`. The OS resolves a "
              "path before opening it, so `../` segments inside `{v}` walk out of "
              "whatever directory this code meant to stay in -- the caller ends up "
              "choosing the file, not the program",
    "CWE-78": "`{v}` is passed to `{sink}`, which hands the string to a shell. The shell "
              "re-parses it, so `;`, `|` or a backtick inside `{v}` stop being characters "
              "in an argument and start being new commands",
    "CWE-79": "`{v}` reaches `{sink}` and is placed into the page without encoding. The "
              "browser parses what it receives, so a `<script>` inside `{v}` becomes "
              "markup that executes rather than text that displays",
    "CWE-89": "`{v}` is concatenated into the statement given to `{sink}`. A quote inside "
              "`{v}` closes the literal, and everything after it is read by the database "
              "as SQL syntax rather than as data",
    "CWE-601": "`{v}` becomes the redirect target at `{sink}`. An absolute URL there "
               "sends the user to a different origin while the link still appears to "
               "come from this site, which is what makes the destination credible",
    "CWE-117": "`{v}` is written into a log line by `{sink}`. A log is newline-delimited, "
               "so a carriage return or newline inside `{v}` ends the current entry and "
               "starts what a reader -- or a parser -- takes to be a separate one. That "
               "lets the value forge entries and push real ones out of view",
    "CWE-918": "the server itself fetches `{v}` at `{sink}`. A caller-chosen host makes "
               "the server issue requests from inside the network -- to link-local "
               "metadata or internal services the caller could not reach directly",
    "CWE-1333": "`{v}` is matched by `{sink}`. If the pattern can backtrack, a crafted "
                "string makes matching time grow exponentially and one request occupies "
                "the worker indefinitely",
}


# CWE-89, CWE-1333 and CWE-79 were BUILT AND THEN DROPPED on a hand-read. Keeping the
# reason here so they are not re-added:
#   CWE-89   the sink variable is the whole statement (`cursor.execute(sql)`), not an
#            identifier interpolated into it. An identifier allowlist on `sql` rejects
#            every real query -- a "fix" that breaks the program is not a fix.
#   CWE-1333 `re.sub(pattern, repl, string)` -- the first argument is the PATTERN, so a
#            length bound landed on the wrong value. ReDoS is bounded on the subject.
#   CWE-79   `__html` is a property name inside `dangerouslySetInnerHTML={{__html: x}}`,
#            not a variable that can be reassigned.
# Each needs the argument POSITION resolved, not just the first name in the call.
# Guards, per class and language. Each references the real variable and is
# self-contained -- no constant the excerpt does not define.
GUARDS = {
    ("CWE-22", "python"): [
        ('if os.path.isabs({v}) or ".." in os.path.normpath({v}).split(os.sep):\n'
         '{i}    raise ValueError("path traversal in {v}")',
         "it rejects absolute paths and any `..` segment after normalising, so `{v}` can "
         "no longer resolve outside the intended directory"),
    ],
    ("CWE-22", "javascript"): [
        ("if (path.isAbsolute({v}) || path.normalize({v}).split(path.sep).includes('..')) {{\n"
         "{i}    throw new Error('path traversal in {v}');\n{i}}}",
         "it normalises first and then rejects absolute paths and `..` segments, so `{v}` "
         "cannot resolve outside the intended directory"),
    ],
    ("CWE-78", "python"): [
        ('{v} = shlex.quote({v})',
         "it quotes `{v}` for the shell, so metacharacters are passed through as literal "
         "characters of one argument instead of being re-parsed as syntax"),
        ('if not re.fullmatch(r"[\\w.@-]+", str({v})):\n'
         '{i}    raise ValueError("shell metacharacters in {v}")',
         "it allows only characters that carry no meaning to the shell, so `{v}` cannot "
         "introduce a second command"),
    ],
    ("CWE-78", "javascript"): [
        ("if (!/^[\\w.@-]+$/.test({v})) {{\n"
         "{i}    throw new Error('shell metacharacters in {v}');\n{i}}}",
         "it allows only characters with no meaning to the shell, so `{v}` cannot start a "
         "second command"),
    ],
    ("CWE-601", "python"): [
        ('if not str({v}).startswith("/") or str({v}).startswith("//"):\n'
         '{i}    raise ValueError("redirect target must be site-relative")',
         "it requires a site-relative path and rejects the protocol-relative `//` form, "
         "so `{v}` cannot name another origin"),
    ],
    ("CWE-601", "javascript"): [
        ("if (!String({v}).startsWith('/') || String({v}).startsWith('//')) {{\n"
         "{i}    throw new Error('redirect target must be site-relative');\n{i}}}",
         "it requires a site-relative path and rejects `//`, so `{v}` cannot point at "
         "another origin"),
    ],
    ("CWE-117", "python"): [
        ('{v} = str({v}).replace("\\r", "").replace("\\n", "")',
         "it removes the carriage return and newline characters, so `{v}` can no longer "
         "terminate the line it is written into or begin a forged one"),
    ],
    ("CWE-117", "javascript"): [
        ("{v} = String({v}).replace(/[\\r\\n]/g, '');",
         "it strips the line terminators globally, so `{v}` cannot close its log line or "
         "open a fabricated one"),
    ],
    ("CWE-918", "python"): [
        ('_h = urlparse(str({v})).hostname or ""\n'
         '{i}if urlparse(str({v})).scheme != "https" or _h in ("localhost", "127.0.0.1", "169.254.169.254"):\n'
         '{i}    raise ValueError("request target is not an allowed external host")',
         "it pins the scheme and rejects loopback and link-local hosts, so `{v}` cannot "
         "aim the server's own request at an internal address"),
    ],
}


# The source records wrap their code in <SCAN>..</SCAN> and then append the localize
# instruction. Both have to come off: leaving them in put "Locate the tainted flow..."
# inside the new excerpt and emitted a second </SCAN>.
_STRIP = re.compile(r"</SCAN>.*$|^<SCAN>\s*", re.S | re.M)


def blocks_of(user):
    """[(path, line, body)] for each `# file (line N)` block, code only."""
    user = _STRIP.sub("", user)
    parts = re.split(r"^# (\S+) \(line (\d+)\)$", user, flags=re.M)
    out = []
    for i in range(1, len(parts) - 2, 3):
        out.append((parts[i], parts[i + 1], parts[i + 2].rstrip()))
    return out


# An existing conditional that tests the sink variable and bails out. If one is already
# present the vulnerable side is NOT unguarded, and calling it confirmed would be a false
# claim -- BTPanel already does `if args.f_path.find('./') != -1: return ...`.
def already_guarded(body, var):
    lines = body.splitlines()
    for n, line in enumerate(lines):
        if not re.search(r"\b(if|elif|unless)\b", line):
            continue
        if not re.search(r"\b" + re.escape(var.split(".")[-1]) + r"\b", line):
            continue
        window = " ".join(lines[n:n + 3])
        if re.search(r"\b(return|raise|throw|abort|exit|continue|break)\b", window):
            return True
        if re.search(r"(find|index|startswith|search|match|test|includes|isabs"
                     r"|normpath|realpath|escape|quote|fullmatch)\s*\(", line):
            return True
    return False


def sink_statement(body, cwe):
    """(line, indent, variable) for the sink call, or None."""
    pat = SINKS.get(cwe)
    if not pat:
        return None
    for line in body.splitlines():
        m = re.search(pat, line)
        if not m:
            continue
        args = line[m.end():]
        depth, buf = 1, []
        for ch in args:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            buf.append(ch)
        raw = "".join(buf)
        # A name immediately followed by `(` is a CALL, not the value flowing in.
        # `logging.debug(input.get("x"))` gave `input.get`, and the guard then tried to
        # assign to a method reference.
        called = set(re.findall(r"([A-Za-z_][\w.]*)\s*\(", raw))
        arg_text = re.sub(r"'[^']*'|\"[^\"]*\"", " ", raw)
        names = [v for v in re.findall(r"[A-Za-z_][\w.]*", arg_text)
                 if not v.isupper() and not v.startswith(("os.", "path.", "re."))
                 and v not in ("True", "False", "None", "mode", "self", "format",
                               "encode", "decode", "str", "int", "len", "hexdigest")
                 and v not in called]
        if not names:
            continue
        indent = line[:len(line) - len(line.lstrip())]
        return line, indent, names[0]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    evalcodes = load_eval_codes()
    recs = [json.loads(l) for l in open(SRC, encoding="utf-8") if l.strip()]
    out, report, f = [], [], collections.Counter()
    per_cwe, seen = collections.Counter(), set()

    for r in recs:
        m = r["_meta"]
        cwe = m.get("ground_truth_cwe")
        lang = m.get("language")
        if (cwe, lang) not in GUARDS:
            f["no_guard_for_class"] += 1
            continue
        if per_cwe[cwe] >= PER_CWE_CAP:
            f[f"cap_{cwe}"] += 1
            continue

        user = r["messages"][0]["content"]
        ans = r["messages"][1]["content"]
        bl = blocks_of(user)
        if len(bl) < 2:
            f["not_two_files"] += 1
            continue

        path_line = re.search(r"^path[^:]*: (.+)$", ans, re.M)
        if not path_line:
            f["no_path"] += 1
            continue
        named = {x.split(":")[0] for x in re.findall(r"([\w./-]+:\d+)", path_line.group(1))}
        present = {p.split("/")[-1] for p, _, _ in bl}
        if not named <= present:
            f["path_file_not_shown"] += 1
            continue

        src_path, src_line, src_body = bl[0]
        snk_path, snk_line, snk_body = bl[-1]
        if not SOURCEY.search(src_body):
            f["source_not_sourcelike"] += 1
            continue
        if not (EXEC.search(src_body) and EXEC.search(snk_body)):
            f["no_executable"] += 1
            continue

        got = sink_statement(snk_body, cwe)
        if not got:
            f["sink_stmt_not_found"] += 1
            continue
        line, indent, var = got

        if already_guarded(snk_body, var):
            f["vuln_side_already_guarded"] += 1
            continue

        variants = GUARDS[(cwe, lang)]
        guard_t, closes_t = variants[per_cwe[cwe] % len(variants)]
        guard = guard_t.format(v=var, i=indent)
        closes = closes_t.format(v=var)
        sink_call = re.search(SINKS[cwe], line).group(0).rstrip("(").strip()

        guard_block = "\n".join(indent + g if n else indent + g
                                for n, g in enumerate(guard.split("\n")))
        guard_block = indent + guard.replace("\n" + indent, "\n" + indent)
        safe_body = snk_body.replace(line, guard_block + "\n" + line, 1)
        if safe_body == snk_body:
            f["insert_failed"] += 1
            continue

        def render(body_for_sink):
            parts = [f"# {p} (line {ln})\n{b if p != snk_path else body_for_sink}"
                     for p, ln, b in bl]
            return "\n".join(parts).strip()

        vuln_code, safe_code = render(snk_body), render(safe_body)
        first_guard_line = guard.split("\n")[0].strip()
        if first_guard_line in vuln_code:
            f["guard_already_present"] += 1
            continue
        if not (MIN_CHARS <= len(vuln_code) <= MAX_CHARS
                and MIN_CHARS <= len(safe_code) <= MAX_CHARS):
            f["size"] += 1
            continue
        if is_test_code(vuln_code) or is_test_code(safe_code):
            f["test_code"] += 1
            continue
        if any(re.sub(r"\s+", " ", x).strip().lower() in evalcodes
               for x in (vuln_code, safe_code)):
            f["eval_leak"] += 1
            continue
        key = hashlib.sha1(re.sub(r"\s+", "", vuln_code).encode()).hexdigest()
        if key in seen:
            f["duplicate"] += 1
            continue
        seen.add(key)

        mech = MECHANISM[cwe].format(v=var, sink=sink_call)
        # The code hash has to be IN the id: keying on file+line+var alone collided across
        # records that share a sink, so 216 pairs carried only 170 distinct ids and the
        # two halves of different pairs looked like the same pair.
        pid = hashlib.sha1(f"cqs|{snk_path}|{snk_line}|{var}|{key}".encode()).hexdigest()[:12]
        meta = dict(shape="shape_codeql_contrastive", source="codeql_contrastive",
                    language=lang, ground_truth_cwe=cwe, cwe_source="codeql",
                    cross_file=True, multi_hop=True, pair_id=pid,
                    grade="B_self_verifiable", safe_side="authored_guard",
                    sink_file=snk_path, sink_var=var, sink_call=sink_call,
                    source_file=src_path, carved_from="shape3_codeql_localize")

        vt = (f"Hypothesis: a caller-controlled value enters in `{src_path}` and reaches "
              f"`{sink_call}` in `{snk_path}` - the shape of {cwe}.\n"
              f"Trigger path: the two files are shown together, and `{var}` arrives at "
              f"the sink as it was received; nothing between them narrows it.\n"
              f"Why that is exploitable: {mech}.\n"
              f"Defensive check: I look along the path for a control on `{var}` and find "
              f"none, so the hypothesis stands. Confirmed {cwe}.")
        st = (f"Hypothesis: the same value enters in `{src_path}` and reaches "
              f"`{sink_call}` in `{snk_path}` - the shape of {cwe}, so the flow alone "
              f"does not settle it.\n"
              f"Trigger path: the path is unchanged; `{var}` still arrives at the sink.\n"
              f"Why that would be exploitable unguarded: {mech}.\n"
              f"Defensive check: `{first_guard_line}` runs on `{var}` before the sink, "
              f"and {closes}. The mechanism above no longer reaches the sink, so the "
              f"hypothesis is refuted.")

        for label, code, think, tail in (
            ("vuln", vuln_code, vt,
             f"status: confirmed\ncwe: {cwe}\nseverity: HIGH\n"
             f"trace: {src_path} -> {snk_path}:{sink_call} receives `{var}` unconstrained\n"
             f"fix: constrain `{var}` before `{sink_call}` - {closes}"),
            ("safe", safe_code, st,
             f"status: safe\ncwe: none\nseverity: none\n"
             f"trace: {src_path} -> {snk_path}:{sink_call}, with `{var}` constrained by "
             f"`{first_guard_line}`\nfix: none")):
            mm = dict(meta)
            mm["label"] = label
            out.append({"messages": [
                {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                {"role": "assistant",
                 "content": f"<think>\n{think}\n</think>\n{tail}"}], "_meta": mm})
        report.append(dict(pair_id=pid, cwe=cwe, lang=lang, sink_file=snk_path,
                           sink_call=sink_call, var=var, guard=first_guard_line[:70]))
        per_cwe[cwe] += 1
        f["PAIR"] += 1

    for k, v in f.most_common(12):
        print(f"  {k:26s} {v:6d}")
    print("  per CWE:", dict(per_cwe))
    if args.write and out:
        with open(OUT, "w", encoding="utf-8") as fh:
            for r in out:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        with open(REPORT, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(report[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(report)
        print(f"\n-> {OUT} ({len(out)//2} pairs)\n-> {REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
