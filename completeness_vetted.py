"""Hand-vetted completeness cases: the guard was present and insufficient, and WHY.

All 51 trusted-source `identifier_changed_in_guard` candidates were read. Kept here are
the ones where the diff itself explains the insufficiency -- a fact about the language or
the API, not a judgement. That sentence IS the record's teaching value, so it has to be
true; where the diff does not explain itself the candidate is rejected rather than
narrated.

Keyed on the guard text present in the VULNERABLE side, which is what the trace quotes.
"""

# present-guard substring -> (weakness class, why the present control is insufficient)
VETTED = {
    # --- the check is on the wrong VALUE ------------------------------------
    "sanitize(html, PREVIEW_DOMPURIFY_CONFIG": (
        "sanitises_wrong_value",
        "the sanitiser runs, but on a different variable from the one that reaches the "
        "sink -- the raw input is never passed through it, so the call is present and "
        "does nothing for the value that matters"),
    "is_dir($filePath)": (
        "checks_wrong_value",
        "the directory check runs against a path that is not the one later opened, so it "
        "confirms something true about a value nobody uses"),
    "path.basename(filePath)": (
        "checks_unresolved_path",
        "the name is taken before the path is resolved, so a symlink or traversal is "
        "still present in the value that gets used"),
    "safeForSql(ps.tag)": (
        "checks_before_normalisation",
        "the check runs on the raw value, but a normalisation step afterwards can "
        "reintroduce exactly the characters it rejected"),

    # --- the check is the wrong KIND ----------------------------------------
    "getCanonicalPath().startsWith(": (
        "string_prefix_not_path_prefix",
        "containment is tested as a STRING prefix. `/tmp/foobar` starts with `/tmp/foo` "
        "as text while being outside it as a path, so the check passes for a directory "
        "that was never inside the base"),
    "os.path.join(relative_path": (
        "join_does_not_constrain",
        "`join` composes a path, it does not confine one -- an absolute or `..` component "
        "silently discards the base it was joined to"),
    "Uri.EscapeUriString(": (
        "wrong_escape_function",
        "EscapeUriString preserves the characters that are RESERVED in a URI, so `?`, `&` "
        "and `#` survive escaping and the value can still restructure the request. "
        "EscapeDataString is the one that encodes a component"),
    "if (isNaN(uid))": (
        "type_check_not_value_check",
        "rejecting non-numbers is not the same as rejecting dangerous hosts; a numeric "
        "value can still address an internal service"),
    "sig.equals(hmac)": (
        "non_constant_time_compare",
        "String equality returns as soon as two characters differ, so the time taken "
        "leaks how long a prefix matched and the signature can be recovered one "
        "character at a time"),

    # --- the check covers the wrong SCOPE -----------------------------------
    "verifyToken('user'": (
        "token_scoped_to_wrong_action",
        "a CSRF token IS verified, but against a different action's scope, so a token "
        "legitimately issued for one operation authorises another"),
    "validateURL(req.body.url, debug)": (
        "flag_wired_to_wrong_setting",
        "the parameter deciding whether local addresses are permitted is wired to the "
        "debug flag, so the control's strictness depends on an unrelated setting"),
    "REGISTER.equals(Utils.getPage(": (
        "single_value_not_allowlist",
        "only one template name is compared, so any other template reaches the same code "
        "path unchecked -- an allowlist was needed, not an equality test"),
    "$hash == $u['password']": (
        "credential_check_omits_state",
        "the comparison covers the password alone, so a token remains valid after the "
        "permissions or home directory it was issued under have changed"),
}

# Read and rejected. Recorded so the judgement is auditable rather than implied.
REJECTED = {
    "direction ambiguous": "uakfdotb/oneapp appears twice with $_SESSION['admin'] and "
        "$_SESSION['admin_id'] swapped in OPPOSITE directions across two records, so "
        "which key is correct cannot be read off the diff.",
    "case-only change": "OpenMage `_isValidSource` -> `_IsValidSource`. PHP method names "
        "are case-insensitive, so this changes nothing about the control.",
    "test assertions": "tiny-csrf contributed five candidates that were chai "
        "`assert.include(...)` calls in a spec file. is_test_code now catches them.",
    "internals not explainable from the diff": "linux ext4/ipmi, openjpeg, mongodb, "
        "jackson-databind, lsp4xml. The change is real but why the previous condition was "
        "insufficient needs the surrounding subsystem, not the hunk.",
    "refactor": "firefly-iii check()->user(), fogproject, pterodactyl, FUXA -- the guard "
        "moved or was renamed without its coverage changing.",
}


def lookup(present_guard):
    """(class, why) if this present guard is vetted as insufficient, else None."""
    for key, val in VETTED.items():
        if key in present_guard:
            return val
    return None
