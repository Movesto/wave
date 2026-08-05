"""Deep grounded trace generation (2026-07-24).

The audit found the machine-generated <think> traces (contrastive, cvefixes,
wave3, fixjs) were SHALLOW: they stated "source -> sink, no guard -> vuln" but
never examined WHY the sink is dangerous, what an attacker crafts, or the impact
— so they teach recognition, not understanding. This module authors that depth
ONCE per vulnerability family (above the weak-model ceiling), grounded in the
real source/sink/guard tokens, and varies phrasing so it isn't memorizable.

Used by build_contrastive.py (contrastive pairs) and enrich_templated.py
(in-place upgrade of the templated sources).
"""
import hashlib, re
from .cwe_contracts import family_of, CONTRACTS

# Per-family security knowledge: what the sink DOES, how untrusted input subverts
# it, what the attacker crafts, and the concrete impact. Authored, not generated.
FAMILY_DEPTH = {
    "sql": dict(role="is executed as part of a SQL statement",
        mech="the value is concatenated into the query string, so the database parses attacker text as SQL syntax rather than data",
        attack="inject SQL such as `' OR '1'='1` or a `UNION SELECT`",
        impact="read, modify, or delete arbitrary rows in the database",
        guard_why="binds the value as a parameter, so the database treats it strictly as data and never as SQL syntax"),
    "xss": dict(role="is rendered into the HTML/DOM",
        mech="the value is written into the page without encoding, so the browser parses attacker markup as live HTML/JS",
        attack="inject a `<script>` or event-handler payload",
        impact="run arbitrary JavaScript in the victim's session, stealing cookies or acting as the user",
        guard_why="HTML-escapes/encodes the value, so the browser renders it as inert text instead of markup"),
    "command": dict(role="is passed to a shell / OS command",
        mech="the value becomes part of a command line the shell interprets, so shell metacharacters split it into extra commands",
        attack="append `; rm -rf` or `$(...)` command substitution",
        impact="execute arbitrary OS commands with the process's privileges",
        guard_why="passes arguments as a list without a shell (or validates them), so metacharacters carry no special meaning"),
    "code_injection": dict(role="is interpreted as code / merged into an object prototype",
        mech="the value reaches a dynamic evaluator (or pollutes a shared prototype), so attacker text becomes executable logic",
        attack="supply an expression, `__proto__` key, or template payload",
        impact="achieve arbitrary code execution or corrupt object behaviour process-wide",
        guard_why="removes the dynamic evaluation / allow-lists keys, so attacker input can no longer become code"),
    "path": dict(role="is used to build a filesystem path",
        mech="the value is joined into a path without confinement, so `../` sequences escape the intended directory",
        attack="supply `../../etc/passwd` or an absolute path",
        impact="read or overwrite files outside the intended directory",
        guard_why="resolves the path and confines it to a base directory, rejecting `..`, so it cannot escape"),
    "ssrf": dict(role="is used as the target of a server-side request",
        mech="the server fetches an attacker-chosen URL, so internal-only services become reachable through it",
        attack="point the URL at `169.254.169.254` or an internal host",
        impact="reach internal services, cloud metadata, or exfiltrate data",
        guard_why="validates the destination host against an allow-list, blocking internal targets"),
    "deserialization": dict(role="is deserialized from untrusted data",
        mech="the deserializer reconstructs arbitrary object graphs, invoking gadget code during construction",
        attack="supply a crafted serialized payload / gadget chain",
        impact="trigger remote code execution or object-injection attacks",
        guard_why="uses a safe format (JSON) or signed/allow-listed deserialization, so no arbitrary types are constructed"),
    "crypto": dict(role="is used in a security-sensitive cryptographic operation",
        mech="a broken or predictable primitive is applied, so the protection it should provide is trivially defeated",
        attack="exploit collisions, brute-force a weak/guessable value, or forge a signature",
        impact="recover protected data, forge tokens, or bypass integrity checks",
        guard_why="uses a strong, current algorithm with proper verification, restoring the intended guarantee"),
    "auth": dict(role="performs a privileged action / accesses a protected resource",
        mech="the action runs before any authorization check, so identity and permission are never verified",
        attack="invoke the endpoint directly or tamper with an object id (IDOR)",
        impact="access or modify other users' data and perform actions without permission",
        guard_why="enforces an explicit authentication/authorization check before the action, denying unauthorized callers"),
    "redirect": dict(role="is used as a redirect target",
        mech="the server redirects to an attacker-chosen URL that users trust because it starts on this site",
        attack="supply an external `//evil.com` target",
        impact="send victims to a phishing or malware site under the app's trust",
        guard_why="validates the target against an allow-list of internal destinations"),
    "xxe": dict(role="is parsed by an XML parser",
        mech="external entity resolution is enabled, so the parser fetches attacker-declared entities",
        attack="declare a `<!DOCTYPE>` external entity pointing at a local file or URL",
        impact="read local files, perform SSRF, or exhaust resources",
        guard_why="disables external-entity resolution, so declared entities are never fetched"),
    "csrf": dict(role="performs a state-changing request",
        mech="the request carries no unpredictable token, so another site can forge it using the victim's session",
        attack="host a hidden form/request that fires with the victim's cookies",
        impact="perform state-changing actions as the victim without their intent",
        guard_why="requires an anti-CSRF token / SameSite cookie the forging site cannot supply"),
    "info_exposure": dict(role="is written to a log or response",
        mech="sensitive data reaches an output channel unredacted, so it is exposed to anyone who can read it",
        attack="trigger the error/log path or read the response",
        impact="disclose secrets, internal details, or personal data useful for further attack",
        guard_why="redacts or omits the sensitive data before it is logged/returned"),
    "dos": dict(role="drives resource consumption",
        mech="the work is unbounded (or backtracks catastrophically), so a small input causes disproportionate cost",
        attack="supply input that maximises iterations / backtracking",
        impact="exhaust CPU or memory and deny service to other users",
        guard_why="imposes a size/iteration limit that bounds the work"),
    "input_validation": dict(role="reaches a sensitive operation",
        mech="the value is used without validation, so malformed or hostile input is processed as if trusted",
        attack="supply input outside the expected shape/range",
        impact="drive the sensitive operation into unsafe behaviour",
        guard_why="validates/neutralizes the input first, rejecting anything outside the expected shape"),
}


def _pick(seed, opts):
    return opts[int(hashlib.md5(seed.encode()).hexdigest(), 16) % len(opts)]


def deep_vuln_think(source, sink, line, cwe):
    """Hypothesis-validation vuln <think> (VulAgent-structured): observe the
    sensitive flow, state the mechanism, run an EXPLICIT defensive check that
    finds no control, then confirm with attacker action + impact. The parallel
    'Defensive check:' step (shared with the safe trace) is what teaches the
    model to look for the guard rather than pattern-match the vuln shape."""
    fam = family_of(cwe)
    d = FAMILY_DEPTH.get(fam)
    ln = f" (line {line})" if line else ""
    if not d:  # unknown family: still structured, just less specific
        return (f"<think>\nHypothesis: `{source}` is attacker-controlled and reaches `{sink}`{ln}, "
                f"which could be {cwe}.\nTrigger path: `{source}` flows to `{sink}` with no transformation. "
                f"\nDefensive check: no validation, sanitization, or authorization guards this path.\n"
                f"Since the path is unguarded, an attacker can craft `{source}` to subvert the operation. "
                f"Confirmed {cwe}.\n</think>")
    obs = _pick(source+sink+"1", [
        f"Hypothesis: `{source}` is attacker-controlled{ln} and reaches `{sink}`, which {d['role']} — a possible {cwe}.",
        f"Hypothesis: the untrusted value `{source}`{ln} flows into `{sink}`, which {d['role']}; this could be {cwe}."])
    mech = d['mech'][0].upper() + d['mech'][1:]
    trig = f"Trigger path: `{source}` reaches `{sink}` unchanged. {mech}."
    check = _pick(source+sink+"3", [
        f"Defensive check: nothing on this path validates, neutralizes, or authorizes `{source}` — no guard is present.",
        f"Defensive check: I look for validation/sanitization/authorization between source and sink and find none."])
    concl = f"Since the trigger path is unguarded, an attacker can {d['attack']}, which lets them {d['impact']}. Confirmed {cwe}."
    return f"<think>\n{obs}\n{trig}\n{check}\n{concl}\n</think>"


def deep_safe_think(source, sink, guard, cwe):
    """Hypothesis-validation safe <think>: SAME hypothesis and trigger path as the
    vuln trace, but the defensive check FINDS the guard and explains why it defeats
    the specific exploit, refuting the hypothesis. Parallel structure to the vuln
    trace so the only difference is the outcome of the defensive check."""
    fam = family_of(cwe)
    d = FAMILY_DEPTH.get(fam)
    why = d["guard_why"] if d else "validates/neutralizes the input before it reaches the sink"
    role = d["role"] if d else "is a sensitive sink"
    obs = _pick(guard+"1", [
        f"Hypothesis: `{source}` reaches `{sink}`, which {role} — check whether this is exploitable.",
        f"Hypothesis: the `{source}` -> `{sink}` flow exists here too; test whether a guard stops it."])
    trig = f"Trigger path: `{source}` flows toward `{sink}` on the same path as the vulnerable version."
    check = f"Defensive check: this version adds `{guard}`, which {why}."
    concl = _pick(guard+"3", [
        f"That control neutralizes `{source}` before it can subvert the sink, so the hypothesis is refuted — the code is safe.",
        f"Because the guard covers the trigger path, the exploit that would work on the vulnerable version is defeated here — safe."])
    return f"<think>\n{obs}\n{trig}\n{check}\n{concl}\n</think>"
