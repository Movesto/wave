"""Pin the R6 identifier test against the false positives measured on r2vul."""
from filter_corpus import named_identifiers as N

CASES = [
    ("the fix uses `strncpy` instead of `strcpy`", ["strncpy"],
     "the avoided alternative is not a claim of presence"),
    ("this would throw a `NullPointerException` here", [],
     "a predicted exception need not be in the excerpt"),
    ("`userInput` flows into `execCommand` unchecked", ["userInput", "execCommand"],
     "a real source->sink claim still counts"),
    ("`and` the value is `problematic`", [],
     "English prose in emphasis backticks"),
    ("avoids `eval` by parsing with `JSON.parse`", ["parse"],
     "eval is counterfactual; JSON.parse is asserted present"),
    ("`req.body.token` reaches `db.query`", ["token", "query"],
     "dotted chains resolve to their longest identifier"),
    ("unlike `printf`, this bounds the write with `snprintf`", ["snprintf"],
     "contrast phrasing excludes the first, keeps the second"),
    ("`validateUser` is called before `deleteAccount`", ["validateUser", "deleteAccount"],
     "ordinary two-identifier claim"),
]

fails = 0
for text, expect, why in CASES:
    got = N(text)
    if got != expect:
        fails += 1
        print(f"  FAIL {text!r}\n       -> {got}, expected {expect}  ({why})")
print(f"{'PASS' if not fails else 'FAIL'}: {len(CASES) - fails}/{len(CASES)} checks")
raise SystemExit(1 if fails else 0)
