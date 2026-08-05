"""Hand-resolved CWEs for advisories that list several, decided by reading the fix.

Each of these had a real CVE and a real multi-CWE advisory, but the classifier's
guess was not among the options -- so there was nothing to corroborate and the
pairs were held. Resolving them needs a human read of what the fix actually does,
which is exactly the judgement no regex in this project has ever made well.

Every entry records the evidence. Where the listed CWEs do NOT describe the change
in front of me, the answer is UNRESOLVED -- picking the closest-sounding option
would be inventing a label, which is the thing we refuse to do.
"""

# cve -> (cwe, why). cwe of "" means: none of the advisory's CWEs fit this hunk.
RESOLVED = {
    "CVE-2023-44378": ("CWE-697",
        "guard is `if b, ok := bound.(expr.Term); ok` -- a type assertion before "
        "use. That is an incorrect-comparison bug, not the integer underflow "
        "CWE-191 describes."),
    "CVE-2023-41890": ("CWE-289",
        "fix adds `ValidateIssuer(token)`. Accepting a token minted by the wrong "
        "authority is authentication bypass by alternate name; CWE-294 would need "
        "a captured token being replayed, which is not what the check stops."),
    "CVE-2026-47351": ("CWE-200",
        "guard tests `getSessionBackend() instanceof HashableSessionBackendInterface` "
        "before trusting a stored session id -- the exposure is of the session "
        "identifier itself, not a missing authorization step."),
    "CVE-2022-31036": ("CWE-61",
        "fix retypes the path to `pathutil.ResolvedFilePath` and resolves it against "
        "the repo root before `os.Stat`. Containment against symlink escape is "
        "CWE-61 specifically, not input validation generally."),
    "CVE-2022-21646": ("CWE-155",
        "fix rejects `req.Subject.ObjectId == tuple.PublicWildcard` -- a wildcard "
        "accepted where a concrete subject was required."),
    "CVE-2023-46233": ("CWE-328",
        "fix swaps the PBKDF2 component list from sha1 to sha256. The defect is the "
        "hash primitive; CWE-916 would be about insufficient iteration count, which "
        "this diff does not touch."),
    "CVE-2023-36826": ("CWE-863",
        "fix scopes an `ArtifactBundle.objects.filter(...)` query so results are "
        "restricted to the caller's own records -- authorization performed, but "
        "performed incorrectly."),
    "CVE-2023-45128": ("CWE-565",
        "guard adds `!compareStrings(extractedToken, c.Cookies(cfg.CookieName))`. "
        "The bug was trusting the cookie without checking it against the request "
        "token -- reliance on a cookie without validation. CWE-352 names the impact; "
        "CWE-565 names the mechanism, and the standard prefers the mechanism."),
    "CVE-2021-43818": ("CWE-79",
        "guard is `if _is_unsafe_image_type(image_type)` -- blocking image types "
        "that can carry script. The consequence is cross-site scripting."),
    "CVE-2010-10006": ("CWE-208",
        "guard is `if (!safeEquals(sig, hmac))` -- a constant-time comparison "
        "replacing a short-circuiting one. That is an observable TIMING discrepancy, "
        "the specific case, not the CWE-203 parent."),
    "CVE-2022-36085": ("CWE-693",
        "guard calls `validateWithFunctionValue(c.builtins, unsafeBuiltinsMap, ...)` "
        "-- the unsafe-builtins restriction existed and could be circumvented, which "
        "is a protection mechanism failure rather than missing validation."),
    "CVE-2022-29210": ("CWE-122",
        "fix removes a `vec.reserve(s)` + `push_back` loop over attacker-sized data. "
        "The overflow is on the heap, so the specific CWE-122 applies over the "
        "generic CWE-120."),
    "CVE-2023-29194": ("CWE-20",
        "fix adds `if err := ValidateKeyspaceName(keyspace); err != nil` -- input "
        "validation added where there was none. CWE-703 would be about handling an "
        "exceptional condition, and none is being handled here."),
    "CVE-2022-31168": ("CWE-863",
        "fix adds `elif not user_profile.is_realm_admin: raise "
        "OrganizationAdministratorRequired()` -- an authorization check that ran but "
        "did not cover the owner-flag path."),

    # --- none of the advisory's CWEs describe THIS hunk -----------------------
    "CVE-2022-39369": ("",
        "the hunk is `@chmod(debugfile, 0600)` on a debug log. The advisory's "
        "CWE-1287 (improper validation of specified type) and CWE-99 (resource "
        "identifier control) describe the authentication bypass elsewhere in the "
        "commit, not this file-permission change."),
    "CVE-2022-39368": ("",
        "the hunk adds `connections.getConnectionByAddress().isExecuting()` to a "
        "liveness test. CWE-404 (improper shutdown) and CWE-459 (incomplete cleanup) "
        "are both defensible and I cannot separate them from this hunk alone."),
    "CVE-2023-27582": ("",
        "the excerpt is TEST code -- `t.Run`, `t.Error`, a stub SASL server. No "
        "production control is present, so no CWE applies and the pair should not "
        "exist regardless of labelling."),
    "CVE-2023-40021": ("",
        "the fix threads a `nonce` through token creation to stop replay. That is "
        "CWE-294; the advisory lists CWE-203/208 (observable discrepancy), which "
        "describe a different part of the change."),
    "CVE-2023-32694": ("",
        "the hunk adds webhook HMAC config and deletes `print(request.body)`. "
        "Removing a debug print of a request body is CWE-532 (log exposure); "
        "CWE-203/208 do not describe it."),
}


def resolve(cve):
    """(cwe, why) -- cwe is "" when the advisory's options do not fit the hunk."""
    return RESOLVED.get(cve, (None, ""))
