"""Pair-producing edits to REAL post-fix TypeScript. See docs/TS_DATA_STANDARD.md.

CONSTRUCTION (this is the part the first attempt got wrong -- it edited the
vulnerable side, which cannot produce a pair because there is no verified-safe
counterpart for it):

    base            = the real POST-FIX code. Verified safe by the CVE fix itself.
    unsanitise      = remove a sanitiser that code applies, recreating the
                      mechanism the CVE proves is exploitable.
    desource        = replace the value that reaches the sink with one no caller
                      controls.

    VULN record  = base + unsanitise
    SAFE record  = base + unsanitise + desource

Both sides therefore carry the DANGEROUS SHAPE -- the sanitiser is gone from
both. They differ only in whether the value reaching the sink is attacker
controlled. That is the contrast we want: it cannot be solved by looking for a
guard token, because neither side has one.

It also keeps the label checkable by reading. "Is this value attacker-reachable?"
is a fact about the code; "is this guard adequate?" is a judgement, which is why
plain guard-removal was rejected.
"""

# -----------------------------------------------------------------------------
# GUARD-COMPLETENESS pairs, from thegriffyn.me/blog/oss/twelve-cves-in-datamodel-
# code-generator: "fixing a vulnerability and fixing a vulnerability class are not
# the same thing". The author obtained 5 of his 12 CVEs by attacking patches that
# looked correct, via recurring patterns -- inconsistent escaping across similar
# positions, a gate that blocks one protocol but exempts another, validation that
# does not cover every input state.
#
# WHY THIS SHAPE IS THE ONE WE ARE MISSING. Every pair in the corpus is consistent
# with "guard present => safe", so that is the rule the model learned. Here a
# sanitiser is VISIBLY PRESENT and the code is still exploitable, because the
# guard does not cover every position or every value. Token presence cannot solve
# these; only reading what the guard actually covers can.
#
# The trace must NAME the guard that is present and say why it is insufficient.
# The existing traces claim "I look for a control and find none" even when
# `quote()` sits three lines away -- which teaches the model to ignore guards.
# EXCLUSIONS — every candidate base NOT built must be recorded here with its
# reason. R13 in scan_ts_standard.py fails if a candidate is neither built nor
# listed here.
#
# This exists because CWE-59 (openclaw src/browser/paths.ts, CVE-2026-32054) was
# skipped on the hunch that its comparison site was not visible. It was: 221 lines
# with two containment checks, both inside our excerpt. Nothing caught the
# omission, because a scanner over EMITTED records cannot see a record that was
# never emitted.
#
# A reason must state what was CHECKED, not what was assumed.
EXCLUSIONS = {
    "cda76946d2cb": "CWE-918 openclaw src/browser/client-fetch.ts - pulled the full file at that "
                    "sha (248 lines): `safeEqualSecret` occurs ZERO times. The earlier detection "
                    "was a false positive from the multi-file excerpt, where the import belonged "
                    "to a different file. There is no guard here to weaken.",
    "d3d89408fc37": "CWE-306 openclaw src/agents/sandbox/browser-bridges.ts - the file at that sha "
                    "is 11 lines, a re-export stub. The logic the advisory describes is not in "
                    "this file.",
    "f28240639854": "CWE-367 openclaw fs-bridge-mutation-helper.ts - pulled the full file (379 "
                    "lines): all 35 `basename` hits are inside an embedded PYTHON script held in "
                    "TypeScript string literals. Editing a string literal is not a code change, "
                    "and the guard is not TypeScript.",
    "d91152cfa376": "CWE-863 openclaw unwrapPnpmDlxInvocation - `token.startsWith(\"-\")` separates "
                    "flags from positionals. It is argument parsing, not a security control; "
                    "weakening it changes parsing, not exploitability.",
    "179f5eb5a1d6": "CWE-214 openclaw extensions/openshell/src/backend.ts - read both sides. The "
                    "fix introduces `sanitizeEnvVars(process.env).allowed`, which IS a real "
                    "control, but the two excerpts do not share a common function body: the "
                    "safe side is a substantially restructured module (new imports, a new "
                    "`SshSandboxSettings` type, a rewritten spawn path), so the vulnerable side "
                    "has no single line that a partial edit could weaken while leaving the rest "
                    "of the code identical. Editing it would produce a pair whose sides differ "
                    "for reasons other than the guard, which R3 realism and R2 minimality both "
                    "exist to prevent. Excluded as unbuildable, not as unimportant.",
}

COMPLETENESS_EDITS = [
    dict(
        repo="renovatebot/renovate", cwe_hint="CWE-78",
        # partial fix: credentials get quote(), the repo name does not.
        partial=(
            "    cmd.push(`helm repo add ${quote(value.name)} ${parameters.join(' ')}`);",
            "    cmd.push(`helm repo add ${value.name} ${parameters.join(' ')}`);",
        ),
        source="value.name", sink="exec",
        present_guard="quote(username)",
        partial_why=(
            "a sanitiser IS present in this function - `quote()` wraps `username` and `password` "
            "two lines above, and `value.repository` inside `parameters`. It is simply not applied "
            "to `value.name`, which is interpolated into the same `helm repo add` command string. "
            "Escaping is inconsistent across positions that are all equally shell-parsed, so the "
            "one unquoted position remains injectable and the presence of `quote()` elsewhere "
            "proves the author knew these values were dangerous"
        ),
        complete_why=(
            "`quote()` is now applied at every position that reaches the command string - "
            "`value.name`, `value.repository`, `username` and `password` - so there is no "
            "remaining position where a shell metacharacter survives into `exec`"
        ),
    ),
    dict(
        repo="openclaw/openclaw", cwe_hint="CWE-78", base_file="schtasks.ts",
        # drop the /g flag: String.replace with a non-global regex replaces only the
        # FIRST match. A language fact, not a prediction.
        partial=(
            '  return `"${value.replace(/"/g, \'\\\\"\')}"`;',
            '  return `"${value.replace(/"/, \'\\\\"\')}"`;',
        ),
        source="value", sink="quoteCmdScriptArg",
        present_guard='value.replace(/"/, \'\\\\"\')',
        partial_why=(
            "quoting IS applied - the value is wrapped in double quotes and embedded quotes are "
            "escaped. The regex has lost its `g` flag, and `String.prototype.replace` with a "
            "non-global regex replaces only the FIRST match. So the first embedded quote is "
            "escaped and every later one is not: a value like `a\"b\"&calc` has its second quote "
            "survive intact, closing the wrapper early and leaving `&calc` outside the quotes for "
            "cmd.exe to run as a separate command"
        ),
        complete_why=(
            "the regex carries the `g` flag, so `replace` escapes every embedded quote rather than "
            "only the first, and no quote can survive to close the wrapper early"
        ),
    ),
    dict(
        repo="nuxt/nuxt", cwe_hint="CWE-94", base_file="",
        # remove the resolve(): startsWith on a NON-normalised path is satisfied by
        # a string that still contains `..` and therefore refers outside the root.
        partial=(
            "    const path = resolve(query.path as string)",
            "    const path = query.path as string",
        ),
        source="query.path", sink="path.startsWith",
        present_guard="path.startsWith(devRootDir)",
        partial_why=(
            "a containment check IS present - `path.startsWith(devRootDir)` - and it is the control "
            "the fix relies on. It only means containment for a NORMALISED path, and this version "
            "no longer calls `resolve()`. A raw value such as `${devRootDir}/../../etc/passwd` "
            "literally starts with `devRootDir` and satisfies the check while referring outside it, "
            "because the `..` segments are never collapsed before the comparison"
        ),
        complete_why=(
            "`resolve()` normalises the value before the comparison, collapsing any `..` segments, "
            "so `startsWith(devRootDir)` is evaluated on the path that will actually be opened"
        ),
    ),
    dict(
        repo="openclaw/openclaw", cwe_hint="CWE-22", base_file="pi-tools.read.ts",
        # drop the isAbsolute arm: an absolute `rel` does not begin with ".." and so
        # passes a check that only looks for "..".
        partial=(
            '  return !(rel.startsWith("..") || path.isAbsolute(rel));',
            '  return !rel.startsWith("..");',
        ),
        source="rel", sink="isPathInsideHost",
        present_guard='rel.startsWith("..")',
        partial_why=(
            "a containment check IS present and it does test for traversal - `rel.startsWith(\"..\")` "
            "catches a relative path that climbs out. It does not cover the other way a relative "
            "path can be outside its base: `path.relative()` returns an ABSOLUTE path when the two "
            "arguments share no root, and an absolute string does not begin with `..`, so it passes "
            "the check while pointing anywhere on disk"
        ),
        complete_why=(
            "the check tests both ways a path can escape - `startsWith(\"..\")` for climbing out and "
            "`path.isAbsolute(rel)` for a path that was never under the base at all"
        ),
    ),
    dict(
        repo="ciscoheat/sveltekit-superforms", cwe_hint="CWE-1321", base_file="",
        # block only one of the two keys the author explicitly blocked.
        partial=(
            "\tif (key === '__proto__' || key === 'prototype') {",
            "\tif (key === '__proto__') {",
        ),
        source="key", sink="setPath",
        present_guard="key === '__proto__'",
        partial_why=(
            "a prototype-injection guard IS present and rejects `__proto__`. The original code "
            "blocks two keys, and only one remains: assigning through the `prototype` key is still "
            "permitted. On a function-valued target that reaches the same prototype chain the "
            "`__proto__` arm was added to protect, so the guard covers one spelling of the attack "
            "and not the other"
        ),
        complete_why=(
            "both keys the author identified are rejected - `__proto__` and `prototype` - so "
            "neither spelling of prototype assignment reaches the target object"
        ),
    ),
    dict(
        repo="openclaw/openclaw", cwe_hint="CWE-22", base_file="workspace.ts",
        # drop the ".." arm of a check the author wrote explicitly.
        partial=(
            '  if (!sourceDirName || sourceDirName === "." || sourceDirName === "..") {',
            '  if (!sourceDirName || sourceDirName === ".") {',
        ),
        source="sourceDirName", sink="resolveSandboxPath",
        present_guard='sourceDirName === "."',
        partial_why=(
            "a validation IS present and rejects empty names and `.`. The author rejected `..` in "
            "the same condition and that arm is gone, so `..` now survives as the directory name "
            "handed to `resolveSandboxPath`. A skill whose base directory is named `..` therefore "
            "resolves one level above the intended skills directory, writing outside it"
        ),
        complete_why=(
            "both degenerate directory names the author identified are rejected - `.` and `..` - so "
            "no name reaching `resolveSandboxPath` can refer to a parent directory"
        ),
    ),
    dict(
        repo="openclaw/openclaw", cwe_hint="CWE-829", base_file="",
        # exact membership -> prefix matching. `allow: ["safe"]` then also admits
        # "safe-malicious". A string fact.
        partial=(
            "        normalizedConfig.allow.includes(plugin.id) &&",
            "        normalizedConfig.allow.some((entry) => plugin.id.startsWith(entry)) &&",
        ),
        source="plugin.id", sink="resolveDiscoveredProviderPluginIds",
        present_guard="normalizedConfig.allow.some((entry) => plugin.id.startsWith(entry))",
        partial_why=(
            "an allowlist IS consulted, so a reader sees trust being restricted to configured "
            "plugins. The membership test is prefix matching rather than equality: an entry of "
            "`safe` now also admits `safe-malicious`, because `\"safe-malicious\".startsWith(\"safe\")` "
            "is true. Anyone able to publish a plugin whose id extends an allowed id inherits that "
            "trust without being listed"
        ),
        complete_why=(
            "`allow.includes(plugin.id)` is exact membership, so only an id written in the "
            "allowlist matches and no id can inherit trust by extending another"
        ),
    ),
    dict(
        repo="openclaw/openclaw", cwe_hint="CWE-184", base_file="",
        # drop the `option=value` spelling the author explicitly included.
        partial=(
            "    (option) => token === option || token.startsWith(`${option}=`),",
            "    (option) => token === option,",
        ),
        source="token", sink="hasDisqualifyingShellWrapperScriptOption",
        present_guard="token === option",
        partial_why=(
            "a denylist check IS present and does reject `--rcfile`, `--init-file` and "
            "`--startup-file`. The author matched two spellings of each, and only exact equality "
            "remains: `--rcfile=/tmp/evil` is no longer detected, because it is not equal to "
            "`--rcfile`. Shells accept the `option=value` form identically, so the disqualifying "
            "option passes the check and still loads the attacker's startup file"
        ),
        complete_why=(
            "both spellings are matched - bare equality and the `option=` prefix - so neither form "
            "of a disqualifying option reaches the wrapper"
        ),
    ),
    dict(
        repo="backstage/backstage", cwe_hint="CWE-59", base_file="paths.ts",
        # drop basename(): resolve() with a path containing ".." escapes the base.
        partial=(
            "  return resolvePath(resolveRealPath(parent), basename(path));",
            "  return resolvePath(resolveRealPath(parent), path);",
        ),
        source="path", sink="resolvePath",
        present_guard="resolveRealPath(parent)",
        partial_why=(
            "canonicalisation IS applied - `resolveRealPath(parent)` resolves symlinks in the base "
            "before anything is joined to it. The second argument is no longer reduced by "
            "`basename()`, and `resolvePath` treats `..` segments as navigation: "
            "`resolve('/srv/data', '../../etc/passwd')` is `/etc/passwd`. Canonicalising the base "
            "does nothing when the value joined to it is allowed to climb out of it"
        ),
        complete_why=(
            "`basename(path)` strips every directory component before the join, so the second "
            "argument cannot contain separators or `..` and the result stays under the "
            "canonicalised parent"
        ),
    ),
    dict(
        repo="openclaw/openclaw", cwe_hint="CWE-208", base_file="auth.ts",
        # constant-time compare -> `!==`. String comparison short-circuits at the
        # first differing byte, which is the documented reason Node ships
        # crypto.timingSafeEqual, and CWE-208 is "Observable Timing Discrepancy".
        partial=(
            "    if (!safeEqualSecret(connectAuth.token, auth.token)) {",
            "    if (connectAuth.token !== auth.token) {",
        ),
        source="connectAuth.token", sink="authorizeGatewayConnect",
        present_guard_partial="connectAuth.token !== auth.token",
        present_guard_complete="safeEqualSecret(connectAuth.token, auth.token)",
        present_guard="connectAuth.token !== auth.token",
        partial_why=(
            "the secret IS checked - a mismatching token is rejected and the request fails, so "
            "authentication is enforced in the functional sense. The comparison is `!==`, which "
            "stops at the first differing byte, so the time it takes correlates with how many "
            "leading bytes of the guess were correct. An attacker who can time responses recovers "
            "the token one byte at a time instead of guessing it whole, which is why Node provides "
            "`crypto.timingSafeEqual` and why this class is called an observable timing discrepancy"
        ),
        complete_why=(
            "`safeEqualSecret` compares the full length of both values regardless of where they "
            "differ, so the time taken carries no information about how many bytes matched and the "
            "byte-at-a-time recovery is not possible"
        ),
    ),
    dict(
        repo="marp-team/marp-core", cwe_hint="CWE-79", base_file="html.ts",
        # onIgnoreTag returning a string emits the tag VERBATIM; returning undefined
        # lets the xss library escape it. Removing the `html === true` gate emits raw
        # HTML for every non-allowlisted tag.
        partial=(
            "      onIgnoreTag: (_, rawHtml) => (html === true ? rawHtml : undefined),",
            "      onIgnoreTag: (_, rawHtml) => rawHtml,",
        ),
        source="rawHtml", sink="filter.process",
        present_guard_partial="onIgnoreTag: (_, rawHtml) => rawHtml",
        present_guard_complete="html === true ? rawHtml : undefined",
        present_guard="onIgnoreTag: (_, rawHtml) => rawHtml",
        partial_why=(
            "sanitisation IS configured - a `FilterXSS` instance with an allowList runs over the "
            "output, so tags are being filtered. The `onIgnoreTag` handler decides what happens to "
            "tags NOT on that list, and returning a string from it makes the library emit that "
            "string verbatim, while returning `undefined` lets the library escape it. This version "
            "returns `rawHtml` unconditionally, so every non-allowlisted tag - `<script>` included "
            "- is passed through unescaped and the allowList decides nothing"
        ),
        complete_why=(
            "`rawHtml` is returned only when `html === true`, an explicit opt-in to raw HTML; "
            "otherwise the handler returns `undefined` and the library escapes the tag, so the "
            "allowList actually governs what survives"
        ),
    ),
    dict(
        repo="openclaw/openclaw", cwe_hint="CWE-59", base_file="browser/paths.ts",
        # compare the LEXICAL parent instead of its realpath. Exploitable through the
        # not-yet-existing-target path, where the second containment check is skipped
        # by design (its ENOENT is swallowed so new files can be created).
        partial=(
            "    if (!isPathInside(rootRealPath, parentRealPath)) {",
            "    if (!isPathInside(rootRealPath, parentDir)) {",
        ),
        source="parentDir", sink="isPathInside",
        present_guard_partial="isPathInside(rootRealPath, parentDir)",
        present_guard_complete="isPathInside(rootRealPath, parentRealPath)",
        present_guard="isPathInside(rootRealPath, parentDir)",
        partial_why=(
            "a containment check IS present on the parent directory, and a second one on the "
            "target below it. This one compares the LEXICAL `parentDir` rather than its "
            "`realpath`, and a lexical string says nothing about where symlinks along the path "
            "lead - a parent such as `<root>/link/sub` is lexically inside the root while "
            "resolving outside it, and the `lstat` above only rejects `parentDir` itself being a "
            "symlink, not an ancestor. The second check would still catch it, except that its "
            "`lstat` throws ENOENT for a target that does not exist yet and that error is "
            "deliberately swallowed so new files can be created. So on the new-file path this is "
            "the only containment check, and it is the one comparing an unresolved string"
        ),
        complete_why=(
            "the comparison uses `parentRealPath`, the result of `fs.realpath(parentDir)`, so every "
            "symlink along the parent path is resolved before containment is judged - including on "
            "the new-file path where the target check is skipped"
        ),
    ),
    dict(
        repo="dicebear/dicebear", cwe_hint="CWE-770",
        # partial fix: clamps the upper bound but not NaN or non-positive values.
        partial=(
            "function sanitizeSize(size: number): number {\n"
            "  if (!Number.isFinite(size) || size <= 0) {\n"
            "    return DEFAULT_SIZE;\n"
            "  }\n\n"
            "  return Math.floor(Math.min(size, MAX_SIZE));\n"
            "}",
            "function sanitizeSize(size: number): number {\n"
            "  return Math.floor(Math.min(size, MAX_SIZE));\n"
            "}",
        ),
        source="size", sink="ensureSize",
        present_guard="Math.min(size, MAX_SIZE)",
        partial_why=(
            "a clamp IS present - `Math.min(size, MAX_SIZE)` visibly bounds the upper end, so a "
            "reader sees a limit being enforced. It does not cover every input state: "
            "`Math.min(NaN, MAX_SIZE)` is `NaN` and `Math.min(-1, MAX_SIZE)` is `-1`, both of "
            "which pass straight through into the width and height written onto the svg. The "
            "guard bounds one direction of one case and the caller can still choose a value it "
            "does not constrain"
        ),
        complete_why=(
            "the clamp is now preceded by `Number.isFinite(size) || size <= 0`, which rejects "
            "`NaN`, infinities and non-positive values before `Math.min` runs, so every input "
            "state resolves to a bounded positive dimension"
        ),
    ),

    # ------------------------------------------------------------------------
    # Added after the focus ladder enlarged the TS base 61 -> 82 pairs. R13
    # surfaced these as unaccounted candidates; each is a real containment or
    # redaction control that can be weakened at exactly one point.
    # ------------------------------------------------------------------ CWE-918
    dict(
        repo="czlonkowski/n8n-mcp", cwe_hint="CWE-918",
        base_file="http-server-single-session.ts",
        # fd00::/8 is a SUBSET of fc00::/7, so dropping the fc00 arm still looks
        # like unique-local addresses are handled.
        partial=(
            "          resolvedIP.startsWith('fc00:') || // Unique local (fc00::/7)\n",
            "",
        ),
        source="resolvedIP", sink="PRIVATE_IP_RANGES.some",
        present_guard="resolvedIP.startsWith('fe80:')",
        partial_why=(
            "a blocklist IS present and it visibly covers IPv6 - link-local `fe80:`, unique-local "
            "`fd00:` and IPv4-mapped `::ffff:` are all rejected, so a reader sees SSRF being "
            "considered for v6 addresses. `fd00::/8` is only the lower half of the unique-local "
            "range `fc00::/7`, and the arm covering the rest was removed, so a name resolving to "
            "anything in `fc00::` to `fcff::` passes every check and reaches the request"
        ),
        complete_why=(
            "both halves of the unique-local range are rejected, so no address in `fc00::/7` "
            "survives the check and the v6 blocklist covers the range it claims to cover"
        ),
    ),
    # ------------------------------------------------------------------- CWE-59
    dict(
        repo="openclaw/openclaw", cwe_hint="CWE-59", base_file="control-ui.ts",
        # resolve the root but not the file: lexical resolution does not follow
        # symlinks, so the containment comparison is made against the wrong path.
        partial=(
            "    const fileReal = fs.realpathSync(filePath);",
            "    const fileReal = path.resolve(filePath);",
        ),
        source="filePath", sink="fs.readFileSync",
        present_guard="const rootReal = fs.realpathSync(root);",
        partial_why=(
            "symlink resolution IS present - `root` is passed through `fs.realpathSync`, which is "
            "the control that makes a containment check meaningful, and its presence shows the "
            "author knew paths must be canonicalised. It is applied to only one of the two paths "
            "being compared: `path.resolve` collapses `..` lexically but does not follow links, "
            "so a symlink inside the root resolves to its own path and compares as contained "
            "while reads land wherever the link points"
        ),
        complete_why=(
            "both sides of the comparison are canonicalised with `fs.realpathSync`, so a symlink "
            "is resolved to its target before containment is tested and cannot escape the root"
        ),
    ),
    # ------------------------------------------------------------------- CWE-22
    dict(
        repo="openclaw/openclaw", cwe_hint="CWE-22", base_file="subagent-announce.ts",
        partial=(
            '  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {',
            '  if (!relative || relative.startsWith("..")) {',
        ),
        source="relative", sink="path.relative",
        present_guard='relative.startsWith("..")',
        partial_why=(
            "a traversal check IS present - `relative.startsWith(\"..\")` rejects the classic "
            "`../` escape, which is the pattern most reviewers look for. It only covers escapes "
            "expressed RELATIVELY: an absolute input makes `path.relative` return a path that "
            "walks to an unrelated root without a leading `..`, so the check passes on a value "
            "that was never inside the base at all"
        ),
        complete_why=(
            "`path.isAbsolute(relative)` is tested alongside the `..` prefix, so both the relative "
            "and the absolute route out of the base directory are rejected"
        ),
    ),
    # ------------------------------------------------------------------ CWE-183
    dict(
        repo="openclaw/openclaw", cwe_hint="CWE-183", base_file="qmd-manager.ts",
        # drop the /g flag: only the FIRST backslash is normalised.
        partial=(
            '  const normalized = relPath.trim().replace(/^\\.\\//, "").replace(/\\\\/g, "/");',
            '  const normalized = relPath.trim().replace(/^\\.\\//, "").replace(/\\\\/, "/");',
        ),
        source="relPath", sink="normalized.startsWith",
        present_guard='.replace(/\\\\/g, "/")',
        partial_why=(
            "separator normalisation IS present - backslashes are rewritten to forward slashes "
            "before the prefix test, which is the step that makes a `memory/` comparison work on "
            "Windows paths. Without the global flag `String.replace` rewrites only the FIRST "
            "match, so a path carrying more than one backslash keeps the rest and the prefix "
            "test compares against a string that is still in mixed-separator form"
        ),
        complete_why=(
            "the global flag rewrites every backslash, so the value reaching the prefix test is "
            "fully normalised and no separator variant slips past the `memory/` comparison"
        ),
    ),
    # ------------------------------------------------------------------ CWE-532
    dict(
        repo="mattermost/desktop", cwe_hint="CWE-532", base_file="callsWidgetWindow.ts",
        partial=(
            "        entries.push(sanitizeMessage(event.sourceId, "
            "`(${path.basename(event.sourceId)}:${event.lineNumber})`));",
            "        entries.push(`(${path.basename(event.sourceId)}:${event.lineNumber})`);",
        ),
        source="event", sink="log.withPrefix",
        present_guard="const entries = [sanitizeMessage(event.sourceId, event.message)];",
        partial_why=(
            "redaction IS present - the console message itself is passed through "
            "`sanitizeMessage`, which replaces the URL host with `<host>`, so the log line "
            "visibly has the host stripped. The location suffix built from the same "
            "`event.sourceId` is appended without that call, so the host the first entry took "
            "care to remove is written into the very next entry of the same log line"
        ),
        complete_why=(
            "every entry derived from `event.sourceId` goes through `sanitizeMessage`, so the "
            "host is replaced consistently and no part of the emitted line still carries it"
        ),
    ),
    # ------------------------------------------------------------------ CWE-863
    dict(
        repo="openclaw/openclaw", cwe_hint="CWE-863", base_file="monitor.ts",
        partial=(
            "    if (safeEqualSecret(guid, token)) {",
            "    if (guid === token) {",
        ),
        # sink must exist on BOTH sides -- naming the guard itself as the sink made
        # it a ghost on the vulnerable side, where this edit removes it.
        source="guid", sink="processReaction",
        present_guard="safeEqualSecret(guid, token)",
        partial_why=(
            "the secret comparison IS present and it does reject a wrong token, so authorisation "
            "is genuinely being checked rather than skipped. `===` on strings returns as soon as "
            "two characters differ, so the time it takes depends on how long a shared prefix the "
            "supplied token has; against an endpoint that can be called repeatedly that leak "
            "recovers the token one character at a time without ever guessing it whole"
        ),
        complete_why=(
            "`safeEqualSecret` compares in time independent of how much of the value matches, so "
            "a wrong token costs the same as one that shares a long prefix and the comparison "
            "leaks nothing about the secret"
        ),
    ),
    # ------------------------------------------------------------------ CWE-367
    dict(
        repo="openclaw/openclaw", cwe_hint="CWE-367",
        base_file="skills-install-download.ts",
        partial=(
            "    targetDir = path.join(canonicalSafeRoot, targetRelativePath);",
            "    targetDir = path.join(safeRoot, targetRelativePath);",
        ),
        source="safeRoot", sink="path.join",
        present_guard="canonicalSafeRoot = await fs.promises.realpath(safeRoot);",
        partial_why=(
            "canonicalisation IS present - `fs.promises.realpath(safeRoot)` is called and its "
            "result stored, so the code has already resolved what the root really is. The joined "
            "target is then built from the UNRESOLVED `safeRoot` instead, so the value that was "
            "canonicalised is not the value that gets used; if any component of `safeRoot` is a "
            "link, extraction lands outside the directory the check was performed on"
        ),
        complete_why=(
            "the target is joined onto `canonicalSafeRoot`, so the path that was resolved is the "
            "same path extraction writes under and the window between checking and using it is "
            "closed"
        ),
    ),
]

# Retired edits: authored against a base excerpt that no longer exists.
#
# The focus ladder re-cut the TS excerpts, and this edit's anchor -- a SQL keyword
# denylist in packages/api/src/routes/storage.ts -- fell outside the region that
# now fits the size limit. The remaining guards in that excerpt are ownership and
# table-allowlist checks; weakening one of those would author a CWE-863-shaped
# defect under a CWE-20 base, which R5 exists to reject. Recorded rather than
# deleted so the reasoning survives, and so the builder stops reporting it as an
# unexplained PROBLEM on every run.
RETIRED_EDITS = [
    dict(
        repo="agenticmail/agenticmail", cwe_hint="CWE-20", base_file="storage.ts",
        # remove UNION from a keyword denylist the author wrote. The separate
        # `;|--|/*|*/` check does not catch it, so UNION SELECT passes both.
        partial=(
            "  if (/\\b(DROP|DELETE|INSERT|UPDATE|UNION|ATTACH|DETACH|PRAGMA|CREATE|ALTER"
            "|REPLACE|EXEC|VACUUM)\\b/i.test(having)) {",
            "  if (/\\b(DROP|DELETE|INSERT|UPDATE|ATTACH|DETACH|PRAGMA|CREATE|ALTER"
            "|REPLACE|EXEC|VACUUM)\\b/i.test(having)) {",
        ),
        source="having", sink="sanitizeHavingClause",
        present_guard="/\\b(DROP|DELETE|INSERT|UPDATE|ATTACH",
        partial_why=(
            "a denylist IS present and it is substantial - length capped at 200, statement "
            "separators and comment markers rejected, and a list of dangerous SQL keywords "
            "refused. `UNION` is missing from that keyword list, and the separate `;|--|/*|*/` "
            "test does not catch it either. A clause such as `1=1 UNION SELECT secret FROM users` "
            "contains no semicolon, no comment marker and no listed keyword, so it passes every "
            "check and appends an attacker-chosen result set to the query"
        ),
        complete_why=(
            "`UNION` is in the keyword list alongside the other statement-introducing keywords, so "
            "a clause cannot append a second result set past the checks"
        ),
    ),
]

EDITS = [
    # ------------------------------------------------------------------ CWE-78
    # renovate's fix wrapped repo/credential values in quote() before they are
    # joined into a `helm repo add` command string that a shell parses.
    dict(
        repo="renovatebot/renovate", cwe_hint="CWE-78",
        unsanitise=(
            "    cmd.push(`helm repo add ${quote(value.name)} ${parameters.join(' ')}`);",
            "    cmd.push(`helm repo add ${value.name} ${parameters.join(' ')}`);",
        ),
        desource=(
            "    cmd.push(`helm repo add ${value.name} ${parameters.join(' ')}`);",
            "    cmd.push(`helm repo add ${BUILTIN_REPO_ALIASES[value.kind]} "
            "${parameters.join(' ')}`);",
        ),
        vuln_source="value.name", safe_source="BUILTIN_REPO_ALIASES[value.kind]", sink="exec",
        vuln_why=(
            "`value.name` comes from repository configuration and is interpolated unquoted into "
            "a `helm repo add` command string which `exec` hands to a shell. The real code wraps "
            "it in `quote()` precisely because of this; without that, a repository name "
            "containing `;` or `$( )` is parsed as a second command and runs with the process's "
            "privileges. This is the mechanism the CVE in this same function demonstrates"
        ),
        safe_why=(
            "the interpolation is still unquoted and still reaches a shell command string, so the "
            "dangerous shape is unchanged and no guard was added. What changed is where the value "
            "comes from: `BUILTIN_REPO_ALIASES` is a constant map keyed by a known repository "
            "kind, so no caller can place shell metacharacters in it"
        ),
        safe_because="the interpolated value is a constant map lookup, not caller input",
    ),
    # ----------------------------------------------------------------- CWE-770
    # dicebear's fix added sanitizeSize(), clamping the rendered dimension to
    # MAX_SIZE so a caller cannot request an unbounded canvas allocation.
    dict(
        repo="dicebear/dicebear", cwe_hint="CWE-770",
        unsanitise=(
            "  size = sanitizeSize(size);",
            "  size = Number(size);",
        ),
        desource=(
            "  size = Number(size);",
            "  size = DEFAULT_SIZE;",
        ),
        vuln_source="size", safe_source="DEFAULT_SIZE", sink="ensureSize",
        vuln_why=(
            "`size` arrives from the caller and is written straight into the svg's width and "
            "height with no upper bound, and those dimensions decide how large a canvas the "
            "converter allocates. The real code routes it through `sanitizeSize`, which clamps to "
            "`MAX_SIZE`; without that clamp a single request asking for 1e9 pixels exhausts "
            "memory and denies service to everyone else"
        ),
        safe_why=(
            "there is still no clamp anywhere on this path - `sanitizeSize` remains removed, so "
            "the unbounded-allocation shape is intact. It is not exploitable because the "
            "dimension written into the svg is the module constant `DEFAULT_SIZE`; the caller's "
            "argument never reaches the allocation, so no attacker chooses how much memory is "
            "requested"
        ),
        safe_because="the dimension is a module constant, so the caller cannot size the allocation",
    ),
]
