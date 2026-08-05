"""Hand-vetted guards for the React-family OSV fix commits.

NOTE ON THE KEYS: the first version of this file carried GHSA ids written from
pattern rather than read from `data/osv/react_targets.tsv`, and all 16 were wrong --
zero matched a harvested commit. Every id below is now copied from the harvest, and
the check at the bottom of build_react_pairs asserts that each key resolves.

`pick_ts_guard` scores an added line against a fixed security vocabulary. React fixes
mostly use PROJECT-SPECIFIC helper names -- `toSafeRedirect`, `hasInvalidProtocol`,
`htmlEscapeJsonString`, `escapeTextForBrowser` -- which are obviously controls to a
reader and invisible to a wordlist. That is the documented ceiling of the regex
pre-filter (100% recall, ~70% precision), and it is why the TS set was only good
after all 410 candidates were hand-judged.

All 74 candidates from the 53 commits were read. Recorded here is the line that IS
the control, keyed by (ghsa, filename). Everything not listed was rejected, and the
common reasons are in REJECTED below so the judgement is reviewable rather than
implied by absence.

`kind`: "guard" = a control was added; "restructure" = the dangerous construct was
replaced or removed, which needs the other builder.
"""

VETTED = {
    # --- URL / protocol allowlists -------------------------------------------
    ("GHSA-399j-vxmf-hjvr", "openURLMiddleware.ts"): (
        "guard", "if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {",
        "protocol allowlist before the URL is opened -- rejects file:, javascript:"),
    ("GHSA-h8fp-f39c-q6mh", "router.ts"): (
        "guard", "return invalidProtocols.includes(new URL(location).protocol);",
        "the predicate the redirect check calls"),
    ("GHSA-h8fp-f39c-q6mh", "hooks.tsx"): (
        "guard", "if (hasInvalidProtocol(target)) {",
        "blocks javascript:/data: before window.location.href is assigned"),
    ("GHSA-jjmj-jmhj-qwj2", "utils.ts"): (
        "guard", 'toPathname = toPathname.replace(/\\/\\/+/g, "/");',
        "collapses repeated slashes so //evil.com is not treated as a host"),

    # --- HTML / script escaping ----------------------------------------------
    ("GHSA-c9vx-2g7w-rp65", "HtmlExport.tsx"): (
        "guard", "const safeExporter = escapeHtml(exporter);",
        "escapes user-controlled names before they enter exported HTML"),
    ("GHSA-xv83-x443-7rmw", "HtmlUtils.tsx"): (
        "guard", "safeBody = highlighter.applyHighlights(escapeHtml(plainBody), safeHighlights!).join(\"\");",
        "escapes the body BEFORE highlight markup is applied"),
    ("GHSA-4wx3-54gh-9fr9", "index.tsx"): (
        "guard", "} else if (key === 'href' || key === 'src') {",
        "attribute allowlist -- href/src are sanitised separately from other props"),

    # --- JSON-in-HTML injection ----------------------------------------------
    ("GHSA-997g-27x8-43rf", "HydrationStreamProvider.tsx"): (
        "guard", "const idJSON = htmlEscapeJsonString(JSON.stringify(id))",
        "escapes </script> and U+2028/9 before the JSON is inlined in a script tag"),

    # --- auth / session ------------------------------------------------------
    ("GHSA-7mpx-vg3c-cmr4", "adal.js"): (
        "guard", "if (requestNonce[i] && requestNonce[i] === user.profile.nonce) {",
        "nonce comparison -- the replay check the fix restores"),
    ("GHSA-f3fg-mf2q-fj3f", "auth-client.ts"): (
        "guard", "addCacheControlHeadersForSession(res);",
        "stops a session response being stored by a shared cache"),
    ("GHSA-p8pf-44ff-93gf", "authkit-callback-route.ts"): (
        "guard", "headers.set('Vary', 'Cookie');",
        "makes the cache key cookie-dependent so one user's page is not served to another"),

    # --- SSRF ----------------------------------------------------------------
    ("GHSA-rvpw-p7vw-wj3m", "init.ts"): (
        "guard", "const imgRemotePatterns = __IMAGES_REMOTE_PATTERNS__;",
        "remote-pattern allowlist consulted before the image URL is fetched"),

    # --- guards the wordlist misses, recovered on a second read ---------------
    ("GHSA-c9vx-2g7w-rp65", "HtmlExport.tsx"): (
        "guard", "const safeExporter = escapeHtml(exporter);",
        "escapes user-controlled names before they enter exported HTML",
        "CWE-79"),
    ("GHSA-xv83-x443-7rmw", "HtmlUtils.tsx"): (
        "guard", "safeBody = highlighter.applyHighlights(escapeHtml(plainBody), safeHighlights!).join(\"\");",
        "escapes the body BEFORE highlight markup is applied",
        "CWE-79"),
    ("GHSA-5q6m-3h65-w53x", "getProcessForPort.js"): (
        "guard", "return execFileSync('lsof', ['-i:' + port, '-P', '-t', '-sTCP:LISTEN'], execOptions)",
        "argv array instead of an interpolated shell string -- the port can no longer "
        "carry shell metacharacters"),
}

# I first recorded these three as "restructure". That was WRONG: the builder checked
# and all three constructs survive in the fixed side, because the fix NARROWS their
# use rather than deleting them (`execSync` -> `execFileSync` keeps the substring
# `exec`; the header and the token are still referenced). A removal claim that the
# code contradicts is exactly what R8's absence check exists to reject, and it
# rejected them. getProcessForPort is re-entered above as the guard it actually is.
WRONGLY_CALLED_REMOVALS = {
    "getProcessForPort.js": "execSync -> execFileSync is a narrowing, not a removal",
    "session.ts (workos CWE-294)": "sessionHeaderName is still referenced after the fix",
    "withSentry.ts": "authToken is still referenced after the delete",
}

# Read and rejected, with the reason. Kept so the judgement can be audited rather
# than inferred from what is missing.
REJECTED = {
    "regex literal rewritten": "ReDoS fixes that change a pattern constant "
        "(react-native-reanimated Colors.ts, jsx-slack escape.ts, taro-css-to-react-native, "
        "react-native URL.js). The fix is real but there is no control to quote and no "
        "construct removed -- a changed regex is neither.",
    "wiring / plumbing only": "the hunk passes a new argument or calls a helper defined "
        "elsewhere (@auth0 index.ts, @opennextjs worker.ts, @auth0 client.ts). The control "
        "is in another file the patch also touches; quoting the call site would name "
        "something that is not the check.",
    "build or test infrastructure": "gatsby cypress specs, @sentry .size-limit.js, "
        "react-devtools extension manifests. Not the software under test.",
    "type or config declaration": "@workos session.ts type aliases, swagger-ui-react "
        "variables.js defaults, @auth0 expiration plumbing.",
}


def lookup(ghsa, filename):
    """(kind, line, why[, cwe]) for a vetted fix, or None.

    The optional 4th element disambiguates an advisory that lists several CWEs --
    an eval label has to be a single value or the score cannot be read.
    """
    return VETTED.get((ghsa, filename))
