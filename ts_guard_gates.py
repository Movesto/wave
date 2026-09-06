"""Gates for picking a real security guard out of a TypeScript patch.

`build_contrastive._pick_guard` was tuned on python/php/C and leaks badly on TS.
Inspecting the first 16 guards it chose from the OSV npm harvest, only ~5 were
genuine controls. The four failure modes, and the gate that kills each:

  1. TEST CODE. TS names tests `foo.test.ts` / `foo.spec.ts` rather than putting
     them under a `tests/` directory, so a directory-only path filter misses
     them entirely -> `is_test_path` + `_TEST_CALL`.
  2. OBJECT LITERALS. `authToken: "test-token"`, `hostname: "127.0.0.1"` and
     `access: {` all match the guard VOCABULARY while being config/data, not
     controls -> `_OBJ_LITERAL`.
  3. TRUNCATED CONDITIONS. TS wraps long conditions, so a bare `if (` is a real
     added line -- and `_pick_guard` sorts SHORTEST-FIRST, so it actively
     PREFERS it -> `has_substance`.
  4. TRIVIAL CONTROL FLOW. `if (chunk) {`, `if (isPreflight) {` are flow, not
     security controls. These score 1 (conditional) but 0 on vocabulary
     -> require the vocabulary hit, i.e. score >= 2.

Keep every one of these. The recurring lesson in this project is that the
guard-picker is the weak point of every contrastive builder, so ALWAYS eyeball
~10 chosen guards after any change here.
"""
import re

from build_contrastive import _COMMENTONLY, _GUARD, _NEWCOND, _SIG_LINE

# --- path gates -----------------------------------------------------------
_TS_EXT = re.compile(r"\.tsx?$", re.I)
_TEST_SUFFIX = re.compile(
    r"\.(test|spec|suite|stories|mock|fixture|fixtures|e2e|bench)\.tsx?$|"
    r"(^|/)[\w.-]*(tests?|fixtures?|mocks?)\.tsx?$",
    re.I,
)
_DECL_ONLY = re.compile(r"\.d\.ts$", re.I)
_SKIP_DIR = re.compile(
    r"(^|/)(test|tests|spec|specs|__tests__|__mocks__|__fixtures__|fixtures?|mocks?"
    r"|examples?|demo|docs?|benchmark(s)?|e2e|cypress|dist|build|bundle|vendor"
    r"|node_modules|coverage)/",
    re.I,
)
_MINIFIED = re.compile(r"\.min\.|\bbundle\b", re.I)


def is_ts_source(path):
    """A real TypeScript source file we would be willing to learn from."""
    p = path.strip()
    if not _TS_EXT.search(p):
        return False
    if _DECL_ONLY.search(p) or _TEST_SUFFIX.search(p):
        return False
    if _SKIP_DIR.search(p) or _MINIFIED.search(p):
        return False
    return True


# --- line gates -----------------------------------------------------------
# Strip string/template literals before judging structure: an "error message"
# containing the word "token" is not a token check.
_STRINGS = re.compile(r"""(['"`])(?:\\.|(?!\1).)*\1""")

# `key: value` / `key: {` -- data, not control. Allowed only if a CALL survives
# string-stripping on the value side (e.g. `check: validateUser(x)`).
_OBJ_LITERAL = re.compile(r"^\s*(?:readonly\s+)?['\"]?[\w$]+['\"]?\s*:\s*")

_TEST_CALL = re.compile(
    r"^\s*(?:await\s+)?(test|it|describe|expect|beforeEach|afterEach|beforeAll"
    r"|afterAll|jest|vi|cy|assert\.equal|should)\s*[.(]", re.I
)

_IMPORT_EXPORT = re.compile(r"^\s*(import|export|from|require\s*\(|@[\w.]+\s*\(?)")
_TYPE_DECL = re.compile(r"^\s*(type|interface|enum|namespace|declare)\s+\w+")
# JSDoc / doc fragments masquerading as controls.
_DOC = re.compile(r"^\s*(\*|//|/\*|<!--|@param|@returns?|@throws)")

_CALL_WITH_ARGS = re.compile(r"[A-Za-z_$][\w.$]*\s*\([^)]*[^\s)]")
_COMPARISON = re.compile(r"(===|!==|==|!=|<=|>=|<|>|\bin\b|\binstanceof\b)")
# Logging reports a decision; it never enforces one.
_LOG_CALL = re.compile(r"^\s*(?:await\s+)?(console\.\w+|logger?\.\w+|log\.\w+)\s*\(", re.I)
# A `throw` is the CONSEQUENCE of a failed check; the check itself is the better
# quote. Kept as a last resort so we don't lose genuine validate-or-throw fixes.
_THROW = re.compile(r"^\s*throw\b")
_BUILTIN_ERR = re.compile(
    r"instanceof\s+(Error|AggregateError|TypeError|RangeError|SyntaxError"
    r"|ReferenceError|EvalError|URIError)\b"
)
# --- rules derived from hand-judging candidates 1-137 (labels in
# --- data/osv/ts_guard_labels.tsv). Each killed a specific observed defect.

# `instanceof Map|URL|Date|...` is a type narrowing, not a control. Custom types
# (`SafeOpenError`, `SafeValue`, `Drop`) ARE real guards, so built-ins only.
_BUILTIN_TYPE = re.compile(
    r"instanceof\s+(Map|Set|Date|URL|Headers|Promise|Array|RegExp|Buffer|Object|WeakMap)\b"
)
# Logging via any object, not just `console` -- `context.logGateway.info(...)`.
_ANY_LOG = re.compile(r"^\s*(?:await\s+)?[\w.$]*\.(info|warn|debug|log|trace)\s*\(", re.I)
# Promise plumbing: `new Promise((resolve, reject)`, `.on('error', reject)`,
# `return reject(err)`. A `reject(new Error("...only HTTPS allowed"))` IS the
# enforcement and must survive, so only bare-identifier rejects are dropped.
_PROMISE_PLUMBING = re.compile(
    r"(new\s+Promise\s*\(|\.on\s*\(\s*['\"][^'\"]*['\"]\s*,\s*reject\s*\)"
    r"|^\s*(return\s+)?[\w.$]*\.?reject\s*\(\s*[\w.$]*\s*\)\s*;?\s*$)"
)
# `if (!token)` / `if (allowed)` -- truthiness on a lone identifier. The actual
# check that produced that boolean lives elsewhere and is the better quote.
# NOTE: a LONE identifier only. `if (!scopeAuth.allowed)` is a real authz check
# -- a dotted property read off an auth object carries meaning that a bare local
# boolean does not, and an earlier version of this rule wrongly killed it.
_BARE_TRUTHY = re.compile(r"^\s*(?:\}\s*else\s+)?if\s*\(\s*!?\s*[A-Za-z_$][\w$]*\s*\)\s*\{?\s*$")
# CLI flag declarations and constructor signatures describe an interface.
_DECLARATIVE = re.compile(r"^\s*(\.option\s*\(|constructor\s*\(|for\s*\(\s*(const|let|var)\b)")

MIN_GUARD_LEN = 12
MAX_GUARD_LEN = 200


def has_substance(line):
    """After removing string literals, is there an actual call or comparison?

    Kills bare `if (` (a wrapped condition) and lines whose only content is a
    quoted message.
    """
    bare = _STRINGS.sub("''", line)
    return bool(_CALL_WITH_ARGS.search(bare) or _COMPARISON.search(bare))


def is_rejected_line(line):
    """Return a reason string if this line can never be a guard, else None."""
    s = line.strip()
    if len(s) < MIN_GUARD_LEN:
        return "too_short"
    if len(s) > MAX_GUARD_LEN:
        return "too_long"
    if _COMMENTONLY.match(line) or _DOC.match(line):
        return "comment_or_doc"
    if _SIG_LINE.match(line):
        return "signature"
    if _IMPORT_EXPORT.match(line):
        return "import_export"
    if _TYPE_DECL.match(line):
        return "type_decl"
    if _TEST_CALL.match(line):
        return "test_construct"
    if not has_substance(line):
        return "no_substance"
    if _LOG_CALL.match(line):
        return "log_line"
    # `instanceof` is in the guard vocabulary, so error-handling boilerplate
    # (`const msg = err instanceof Error ? err.message : String(err)`) scores as
    # a control. Narrowing an error for reporting is never the security check.
    # Only BUILT-IN error types are excluded -- `err instanceof SafeOpenError`
    # is a real domain guard.
    if _BUILTIN_ERR.search(line):
        return "error_handling"
    if _BUILTIN_TYPE.search(line):
        return "builtin_type_narrowing"
    if _ANY_LOG.match(line):
        return "log_line"
    if _PROMISE_PLUMBING.search(line):
        return "promise_plumbing"
    if _BARE_TRUTHY.match(line):
        return "bare_truthiness"
    if _DECLARATIVE.match(line):
        return "declarative"
    # Object literals are DATA even when the value contains a call:
    # `token: hashToken(token, opts)` and `reason: err instanceof Error ? ...`
    # both matched the vocabulary while assigning a field, not enforcing a rule.
    if _OBJ_LITERAL.match(line):
        return "object_literal"
    return None


_COMPARISON_OP = re.compile(r"(===|!==|==|!=|<=|>=|<|>)")
_INTERP = re.compile(r"\$\{([^{}]*)\}")


def strip_literals(line):
    """Remove string literals but KEEP `${...}` interpolations, which are code.

    `_STRINGS` alone deletes an entire template literal, so
    `cmd.push(`helm repo add ${quote(value.name)} ...`)` loses the `quote(...)`
    call and looks like a bare string. That cost real guards on the first attempt
    at these rules -- and it is the SECOND time this exact mistake was made, the
    first being in `build_ts_augment.occurs()`.
    """
    kept = " ".join(_INTERP.findall(line))
    return _STRINGS.sub("''", line) + " " + kept
# `err instanceof Deno.errors.Interrupted` -- a NAMESPACED built-in error type.
# `_BUILTIN_ERR` only listed bare names, so this slipped through.
_NAMESPACED_ERR = re.compile(r"instanceof\s+\w+(?:\.\w+)*\.errors?\.\w+", re.I)
# Enforcement: the message legitimately carries the vocabulary, because it is
# DESCRIBING the control being enforced. `throw new Error("...exceeds limit")`
# is the enforcement of a limit.
_ENFORCEMENT = re.compile(r"\bthrow\b|new\s+\w*Error\b|new\s+\w*Exception\b|reject\s*\(\s*new\b")


def _vocab_hit_is_real(line):
    """Does this line hit the guard vocabulary for a real reason?

    Two leaks from the NVD-only probe, each fixed as NARROWLY as the evidence
    supports. A first attempt at these rules was broader and cost 35 hand-vetted
    guards from `data/osv/ts_guard_labels.tsv` -- so the acceptance test for any
    change here is ZERO losses against that set.

    1. `err instanceof Deno.errors.Interrupted` -- namespaced built-in error type.
       Fixed by extending the error-type list, NOT by rejecting all
       `instanceof`-only lines: `!(obj instanceof Drop)` in a prototype-pollution
       guard is a genuine control and was lost by the broader rule.

    2. `res.setHeader('Access-Control-Allow-Origin', origin)` -- "Allow" matched
       inside a header-name STRING. A string-only vocabulary hit now needs either a
       comparison or to be an enforcement; without the enforcement exemption this
       rejected `throw new Error("Content too large ... limit ...")`, which is a
       real control.
    """
    if _NAMESPACED_ERR.search(line):
        return False

    stripped = strip_literals(line)
    if not _GUARD.search(stripped) and _GUARD.search(line):
        if not (_COMPARISON_OP.search(stripped) or _ENFORCEMENT.search(stripped)):
            return False
    return True


def pick_ts_guard(added):
    """Pick the guard line, requiring a SECURITY-VOCABULARY hit (score >= 2).

    Deliberately stricter than `_pick_guard`: being a conditional is not enough.
    Also prefers the LONGEST qualifying line rather than the shortest, because on
    TS the short candidates are truncated wrapped conditions.
    """
    scored, throws = [], []
    for l in added:
        if is_rejected_line(l):
            continue
        s = 0
        if _GUARD.search(l) and _vocab_hit_is_real(l):
            s += 2
        if _NEWCOND.match(l):
            s += 1
        if s < 2:                      # must hit the vocabulary, not just be an `if`
            continue
        (throws if _THROW.match(l) else scored).append((s, len(l.strip()), l.strip()))
    pool = scored or throws            # prefer a real check over its throw
    if not pool:
        return None
    pool.sort(key=lambda x: (-x[0], -x[1]))
    return pool[0][2]
