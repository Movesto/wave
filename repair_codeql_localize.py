"""Two repairs to the CodeQL localize set: drop non-dataflow classes, replace the template.

1. WEAKNESS CLASS. The task states a taint flow -- "untrusted input reaches this sink".
   That framing is only true for classes where reaching the sink IS the problem. It is
   not true for CWE-312 (data stored in the clear), CWE-327 (weak algorithm), CWE-209
   (error text exposed), CWE-250 (excess privilege) or CWE-377 (insecure temp file):
   those are properties of what the code DOES, not of a value arriving somewhere, and
   labelling them as a flow to a sink is simply the wrong claim. CWE-312 alone was 1,246
   of the 4,365 -- it is the class that labelled a list of subdomains "cleartext storage".

2. THE `why:` LINE. All 4,365 shared one sentence: "untrusted input enters at X and
   reaches Y with no sanitiser between them. This is a CWE-N flow." It states the
   conclusion and explains nothing, so it teaches recitation. R7/R15 never caught it
   because both gate <think> blocks and these records have none -- worth remembering:
   a set can be 100% templated and still pass every rule we own.

   The replacement says why THAT SINK is dangerous for THAT class, and names the sink
   call where one can be identified, so the sentences differ per record.

    python repair_codeql_localize.py --write
"""
import argparse
import collections
import csv
import json
import re
import sys

PATH = "data/cot/staging/shape3_codeql_localize.jsonl"
MANIFEST = "data/osv/codeql_nonflow_held.tsv"

# Classes where "an untrusted value reaches this sink" is the actual weakness.
FLOW_CLASSES = {
    "CWE-22": ("a filesystem path", "the OS resolves the path before opening it, so "
               "`../` segments in the value walk out of the directory this code meant "
               "to stay in and the caller ends up choosing the file"),
    "CWE-78": ("a shell command", "the shell re-parses the string, so `;`, `|` or a "
               "backtick stop being characters in an argument and become new commands"),
    "CWE-79": ("page markup", "the browser parses what it receives, so `<script>` in the "
               "value becomes markup that executes rather than text that displays"),
    "CWE-89": ("a SQL statement", "a quote in the value closes the literal and what "
               "follows is read by the database as syntax rather than as data"),
    "CWE-90": ("an LDAP filter", "filter metacharacters in the value restructure the "
               "query, so it can be made to match entries it was never meant to"),
    "CWE-94": ("code that gets evaluated", "the value is parsed as program text, so it "
               "runs with the privileges of the process rather than being read as data"),
    "CWE-117": ("a log line", "a log is newline-delimited, so a carriage return in the "
                "value ends the entry and starts what a reader takes to be a new one"),
    "CWE-134": ("a format string", "format directives in the value are interpreted, so "
                "it can read memory it was never passed"),
    "CWE-502": ("a deserialiser", "deserialising reconstructs objects the value names, "
                "so it chooses which constructors run"),
    "CWE-601": ("a redirect target", "an absolute URL sends the user to another origin "
                "while the link still appears to come from this site"),
    "CWE-611": ("an XML parser with entities enabled", "an external entity in the value "
                "makes the parser fetch and inline a file or URL of its choosing"),
    "CWE-807": ("a security decision", "the value is trusted to decide access, but it "
                "arrives from the caller, who can simply supply the answer"),
    "CWE-918": ("a request the server makes", "a caller-chosen host makes the server "
                "issue requests from inside the network, to addresses the caller cannot "
                "reach directly"),
    "CWE-1333": ("a backtracking regular expression", "a crafted subject makes matching "
                 "time grow exponentially and one request holds the worker"),
}

SINK_CALL = re.compile(
    r"\b(open|os\.path\.join|send_file|readFile|sendFile|os\.system|os\.popen"
    r"|subprocess\.\w+|execSync|spawn|render_template_string|Markup|innerHTML"
    r"|cursor\.execute|execute|redirect|requests\.\w+|urlopen|fetch|axios\.\w+"
    r"|logging\.\w+|log(?:ger)?\.\w+|console\.\w+|re\.\w+|eval|pickle\.loads"
    r"|yaml\.load|json\.loads)\s*\(")


def sink_call_in(block):
    m = SINK_CALL.search(block)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    recs = [json.loads(l) for l in open(PATH, encoding="utf-8") if l.strip()]
    rows, f = [], collections.Counter()
    for i, r in enumerate(recs):
        m = r.setdefault("_meta", {})
        if m.get("held"):
            continue
        cwe = m.get("ground_truth_cwe")
        if cwe not in FLOW_CLASSES:
            m["held"] = "not_a_dataflow_class"
            rows.append(dict(index=i, cwe=cwe,
                             reason="the weakness is a property of what the code does, "
                                    "not of a value reaching a sink; stating it as a "
                                    "flow is the wrong claim"))
            f[f"HELD_{cwe}"] += 1
            continue

        ans = r["messages"][1]["content"]
        src = re.search(r"^source: (\S+)", ans, re.M)
        snk = re.search(r"^sink: (\S+)", ans, re.M)
        if not (src and snk):
            f["no_source_sink"] += 1
            continue

        blocks = re.split(r"^# \S+ \(line \d+\)$", r["messages"][0]["content"], flags=re.M)
        call = sink_call_in(blocks[-1]) if len(blocks) > 1 else None
        what, mech = FLOW_CLASSES[cwe]
        at = f"`{call}`" if call else f"{snk.group(1)}"
        why = (f"the value that enters at {src.group(1)} is used as {what} at {at}. "
               f"{mech[0].upper() + mech[1:]}. Nothing on the path between the two "
               f"narrows it first, which is what makes this a {cwe} flow.")
        new = re.sub(r"^why: .+$", "why: " + why, ans, flags=re.M)
        if new == ans:
            f["why_not_replaced"] += 1
            continue
        r["messages"][1]["content"] = new
        f["REWRITTEN"] += 1

    for k, v in f.most_common(10):
        print(f"  {k:26s} {v:6d}")
    print(f"  held total: {sum(v for k, v in f.items() if k.startswith('HELD_'))}")
    if args.write:
        with open(PATH, "w", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        with open(MANIFEST, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), delimiter="\t")
            w.writeheader()
            w.writerows(rows)
        print(f"-> {MANIFEST} ({len(rows)} held)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
