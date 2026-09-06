"""Hand-authored traces for the OSV TypeScript contrastive pairs.

Written by READING each diff. Heuristic extraction produced a 42%+ defect rate
(node modules named as tainted sources, enclosing functions named as sinks,
words lifted out of error-message strings, the `throw` cited instead of the
check), and the worst cases were invisible to every regex gate -- so the traces
are authored, not generated.

Each entry supplies only the FACTS about that code:
    source  the value an attacker influences, as it is spelled in the excerpt
    sink    what that value reaches, as it is spelled in the excerpt
    guard   the control the fix ADDED (the check, never its consequence)
    cwe     overridden only where the advisory's first CWE is the wrong one
    why     the mechanism: what the attacker supplies and what it gets them
    fixed   what the added control changes about that mechanism

DROP holds pairs that failed inspection, with the reason. Dropping is the
correct outcome when the diff does not actually add a control, or when the
advisory CWE does not describe the visible change -- writing a plausible trace
over either teaches confident fiction, which is worse than no data.
"""

# pair_id -> facts. `cwe` is optional and overrides the advisory's first CWE.
AUTHORED = {
    # symlink leaf must survive canonicalisation so the later symlink guard sees it
    "5ffea3a24438": dict(
        source="target",
        sink="resolveSandboxHostPathViaExistingAncestor",
        guard="const canonicalTarget = path.resolve(canonicalTargetParent, path.basename(resolvedTarget));",
        why=(
            "the whole of `target` is canonicalised in one step, so if its final segment is a "
            "symlink it is followed and replaced before any symlink check runs. The containment "
            "test then inspects the already-followed path, and an attacker who can plant a symlink "
            "leaf inside the sandbox root reaches a file outside it while the check still passes"
        ),
        fixed=(
            "canonicalises only the PARENT directory and re-attaches the literal final segment via "
            "`path.basename`, so a symlink leaf is still present when the dedicated symlink guard "
            "runs instead of having been silently resolved away"
        ),
    ),
    # unbounded request body accumulation
    "bbdf42bae781": dict(
        source="chunk",
        sink="body",
        guard="if (size > maxSize) {",
        why=(
            "every `chunk` is appended to `body` with no running total and no ceiling, so a client "
            "that keeps streaming decides how much memory the process allocates. One request can "
            "grow the string until the server exhausts memory and stops serving anyone"
        ),
        fixed=(
            "accumulates `size` per chunk and destroys the request once it passes `maxSize`, so the "
            "amount of memory a single client can cause to be allocated is bounded by configuration "
            "rather than by the client"
        ),
    ),
    # X-Forwarded-For spoofing decides local-vs-remote
    "2365b5ae0562": dict(
        source="req",
        sink="resolveViewerAccess",
        guard="const access = resolveViewerAccess(req, {",
        why=(
            "viewer access is derived from `req` without stating which proxies may be believed, so "
            "the forwarding headers on the request itself decide whether it counts as local. A "
            "remote client can set that header and be treated as a local viewer, reaching diff "
            "artifacts that are supposed to be unreachable when `allowRemoteViewer` is not set"
        ),
        fixed=(
            "passes `trustedProxies` and `allowRealIpFallback` into the resolution, so forwarding "
            "headers are only honoured when they arrive from a configured proxy and a client can no "
            "longer assert its own address"
        ),
    ),
    # shell interpolation -> argv
    "eab762a0d172": dict(
        source="filePath",
        sink="execAsync",
        cwe="CWE-77",
        why=(
            "`filePath` is interpolated into a command STRING that a shell then parses. The "
            "surrounding double quotes do not make this safe: a filename containing `\"` closes the "
            "quoted section, after which `;` or `$( )` starts a command of the attacker's choosing, "
            "running with the privileges of the server process"
        ),
        fixed=(
            "switches to `execFile`, which takes the program and its arguments as separate values "
            "and never involves a shell, so metacharacters in `filePath` stay ordinary characters "
            "of a filename"
        ),
    ),
    # non-strings bypassed HTML escaping entirely
    "b00b214b6568": dict(
        source="input",
        sink="string.escapeHTML",
        guard="return input instanceof SafeValue ? input.value : string.escapeHTML(String(input))",
        why=(
            "only a value that is already a string is escaped; anything else is returned untouched. "
            "An attacker who gets their payload into the template as a non-string -- a number, an "
            "object with a crafted `toString`, a boxed value -- skips escaping completely and their "
            "markup is rendered into the page verbatim"
        ),
        fixed=(
            "coerces with `String(input)` and escapes the result, so the type of the incoming value "
            "no longer decides whether escaping happens; only an explicit `SafeValue` opts out"
        ),
    ),
    # served path was never constrained to the base directory
    "6e1cfafc7ad4": dict(
        source="filePath",
        sink="res.end",
        guard="function isContainedPath(baseDir: string, targetPath: string): boolean {",
        why=(
            "the requested path is read and written to the response without ever being compared "
            "against the directory it is supposed to stay inside. A request carrying `../` segments "
            "walks out of the served root, so any file the process can read can be fetched over HTTP"
        ),
        fixed=(
            "adds a containment test that rejects a target whose path relative to `baseDir` starts "
            "with `..` or is absolute, so a traversal attempt fails the check before anything is read"
        ),
    ),
    # server-supplied filename used directly in a local path
    "8e5316ee86ce": dict(
        source="file.name",
        sink="join",
        guard="const hasInvalidName = !file.name || basename(file.name) !== file.name",
        why=(
            "a filename taken from the remote server's directory listing is joined straight onto the "
            "local download directory. A malicious or compromised FTP server can return a name "
            "containing path separators or `..`, and the write lands wherever that name points "
            "instead of inside the download directory"
        ),
        fixed=(
            "requires the name to be equal to its own `basename` -- true only when it contains no "
            "directory component at all -- and skips the file otherwise, so the server can no longer "
            "steer where the write happens"
        ),
    ),
    # allowlist decision keyed on a spoofable identity
    "89315cf5ffcb": dict(
        source="node",
        sink="allowBuild",
        guard="const allowed = allowBuild(node.depPath)",
        why=(
            "the build allowlist is consulted with the package's self-reported name and version. Any "
            "dependency anywhere in the tree can claim a name and version that the allowlist trusts, "
            "and its install scripts then run because the decision was made on values the package "
            "itself controls"
        ),
        fixed=(
            "keys the decision on `node.depPath`, the package's actual position in the resolved "
            "dependency graph, which a package cannot choose for itself"
        ),
    ),
    # session file path escaped its agent directory
    "76dbdc4ade64": dict(
        source="candidateAbsPath",
        sink="resolvePathFromAgentSessionsDir",
        guard='if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {',
        why=(
            "a candidate session path is resolved without checking that it stays under the agent's "
            "own sessions directory, so a crafted identifier walks up out of it and reads or writes "
            "another agent's session files"
        ),
        fixed=(
            "computes the path relative to the agent base and rejects it when that relative path is "
            "empty, starts with `..`, or is absolute -- the three ways a resolved path can land "
            "outside its base"
        ),
    ),
}

# pair_id -> why it must not be trained on
DROP = {
    "d2428d3cf604": "the added clause `&& !(obj instanceof Drop)` RELAXES the property check rather "
                    "than tightening it; the safe side is more permissive, so this teaches the "
                    "opposite of a guard",
    "34a95b12fb2b": "rewrites isPrivateIpv4 into CIDR range maths -- a real SSRF fix, but the "
                    "excerpt contains only the range helpers and no sink the address ever reaches",
    "968cba815d14": "the read is moved into a `readLocalBuffer` helper whose body is not in the "
                    "excerpt, so the control being added is not visible here",
    "26fa6a2e7f02": "pre-hashing the secret with SHA256 before PBKDF2 is not clearly the security "
                    "control, and justifying it as one would be invention",
    "05d10a227c8d": "only shows a `token_version` field being added to a payload; the invalidation "
                    "logic that makes it a control is not in the excerpt",
    "7e3e21919fde": "the fix REMOVES `await fs.realpath(rootDir)` and moves canonicalisation to the "
                    "caller via `options.canonicalRootDir` -- a refactor, not an added control, so "
                    "the safe side does not demonstrate a guard",
    "ee70f40abb86": "advisory says CWE-400 (resource exhaustion) but the visible change is a "
                    "signature-over-rawBody fix plus import churn; the excerpt does not contain the "
                    "limit the CWE describes",
    "bba445278981": "the excerpt shows the new SAFE_BIN_OPTION_POLICIES table but not the code that "
                    "enforces it, so there is no sink in this excerpt to name",
    "2bb2c07fc343": "genuine credential-masking fix, but the advisory's first CWE is CWE-352 (CSRF) "
                    "which does not describe it; the real class is CWE-532. Kept out until the CWE "
                    "selection is fixed rather than trained under a wrong label",
}
