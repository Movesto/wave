"""Author gold contrastive traces on bridged patches (me as teacher) + GATE both sides.

Each CVE in AUTHORED -> a vuln record (pre-image code) + a safe record (post-image code),
sharing a pair_id. Gates: grounding (identifiers cited appear in that side's code) + verdict.
Re-runnable: rewrites data/cot/staging/regen_gold.jsonl from AUTHORED each time. Add CVEs to
grow the seed. This is the shape gen_regen.py takes with DeepSeek as author instead of me.
"""
import json, sys
sys.path.insert(0, "."); sys.path.insert(0, "scanner")
from patch_extract import views_both
from star_ts import grounded

OUT = "data/cot/staging/regen_gold.jsonl"

# {cve: {"vuln": trace ending 'status: vuln', "safe": trace ending 'status: safe'}}
AUTHORED = {
"CVE-2020-25730": {
 "vuln":
  "This ZoneMinder view builds a download page. `$connkey` is taken straight from the request -- "
  "`$_REQUEST['connkey']` -- with no validation, then echoed into an HTML attribute: "
  "`value=\"<?php echo $connkey; ?>\"`. Because the value lands inside a double-quoted attribute "
  "with nothing encoding it, an attacker who supplies a connkey like `\"><script>...</script>` "
  "closes the `value=\"` attribute and the `<input>` tag, then injects markup the victim's browser "
  "executes. That is reflected XSS: the value flows request -> `$connkey` -> HTML attribute with no "
  "step in between to neutralize the quote or angle brackets.\nstatus: vuln",
 "safe":
  "The fixed version wraps the request value in `validInt(...)`: "
  "`$connkey = isset($_REQUEST['connkey']) ? validInt($_REQUEST['connkey']) : generateConnKey()`. "
  "`validInt` coerces the input to an integer, so any non-numeric payload -- quotes, angle "
  "brackets, a `<script>` tag -- cannot survive; only a bare number reaches the `value=\"...\"` "
  "attribute. An integer cannot break out of the quoted attribute or introduce markup, so the "
  "reflected XSS is closed. connkey is a numeric handle by design, so constraining it to an "
  "integer is both correct and sufficient.\nstatus: safe"},
"CVE-2021-25987": {
 "vuln":
  "This Hexo helper builds an HTML list of tags by string concatenation. For each tag it appends "
  "`transform ? transform(tag.name) : tag.name` directly into the `<a ...>...</a>` markup in "
  "`result`. `tag.name` comes from user-authored post content, and it is concatenated into HTML "
  "with no escaping. A tag named `<img src=x onerror=alert(1)>` is written verbatim into the page "
  "and runs in every visitor's browser -- stored XSS. The tag name flows content -> string "
  "concatenation -> rendered HTML with no encoder on the path (note `url_for` handles the href, "
  "not the tag text).\nstatus: vuln",
 "safe":
  "The fix imports `escapeHTML` from `hexo-util` and routes the tag name through it: "
  "`result += transform ? transform(tag.name) : escapeHTML(tag.name)`. `escapeHTML` converts `<`, "
  "`>`, `&` and quotes to HTML entities, so a tag named `<img onerror=...>` is rendered as inert "
  "text (`&lt;img...`) instead of live markup. The value now enters the `<a>` element already "
  "entity-encoded, so the browser cannot parse it as a tag -- the stored XSS is neutralized. The "
  "href still goes through `url_for`, which was already safe.\nstatus: safe"},
"CVE-2023-41046": {
 "vuln":
  "This is xwiki's `TextAreaClass.displayView`, which renders a text-area property. When "
  "`contentType` is `VELOCITY_CODE` it calls `context.getWiki().parseContent(result.toString(), "
  "context)` -- which EXECUTES the Velocity template code in that content. The flaw is what is "
  "missing: nothing checks that the author of this content is authorized to run script. A "
  "low-privilege user can save a text-area field containing Velocity/script; when a higher-"
  "privilege user later views it, `parseContent` executes that script with the viewer's rights -- "
  "a missing-authorization / privilege escalation via stored script. The dangerous step is "
  "evaluating attacker-authored content without tying execution to the author's privileges. "
  "(Caveat: the rights model spans several classes; this method is the sink where unvetted content "
  "reaches `parseContent`.)\nstatus: vuln",
 "safe":
  "The fix routes text-area content through an author-rights step before evaluation: the "
  "VELOCITY_CODE branch now calls `displayVelocityCode(...)`, and content is passed through "
  "`maybeEvaluateContent(name, isolated, content, sdoc)` with the document author pinned by "
  "`ensureContentAuthorIsMetadataAuthor(sdoc)`. Evaluation is now tied to the privileges of the "
  "content's author rather than the viewer, so a low-privilege user's stored script can no longer "
  "execute with an admin's rights when displayed. Tying evaluation to the content author's "
  "authorization is the control that was missing, so the privilege escalation is closed.\n"
  "status: safe"},
"CVE-2023-29008": {
 "vuln":
  "This is SvelteKit's `is_content_type` check, used by its CSRF protection to recognise a "
  "form-like POST that a cross-site page could forge. It reads the request's `content-type` "
  "header, strips parameters, and does `return types.includes(type)`. That comparison is "
  "case-SENSITIVE. Browsers treat header values case-insensitively, so an attacker submits "
  "`Content-Type: text/PLAIN` (or `multipart/Form-Data`): the browser sends it as a simple "
  "request, but `types.includes(type)` -- matching against lowercase entries like `'text/plain'` "
  "-- returns false, so SvelteKit fails to recognise the forgeable content type and its CSRF "
  "protection never triggers. The flaw is a case-sensitive comparison on attacker-chosen header "
  "casing.\nstatus: vuln",
 "safe":
  "The fix lowercases the header value before comparison: `return types.includes(type.toLowerCase())`. "
  "Now `text/PLAIN` and any other casing normalise to the lowercase entries in `types`, so the "
  "content-type check can no longer be evaded by changing case and the CSRF protection recognises "
  "the request. Normalising case before an allowlist comparison is the step that was missing.\n"
  "status: safe"},
"CVE-2023-4696": {
 "vuln":
  "This is a JWT auth middleware. After parsing the token it checks the audience -- "
  "`if !audienceContains(claims.Audience, auth.AccessTokenAudienceName)` -- and rejects on "
  "mismatch. But it never confirms the token itself is valid: nothing verifies the signature "
  "checked out and the token isn't expired before it trusts `claims`. Trusting `claims` from a "
  "token whose validity was never confirmed means a forged or expired token whose audience happens "
  "to match is accepted, authenticating the attacker. The missing control is a token-validity "
  "check before the claims are used.\nstatus: vuln",
 "safe":
  "The fix adds an explicit validity gate before the claims are trusted: "
  "`if !accessToken.Valid { return echo.NewHTTPError(http.StatusUnauthorized, \"Invalid access "
  "token.\") }`. A token whose signature failed or that has expired is now rejected outright, so "
  "only a properly signed, unexpired token reaches the `audienceContains` check. Verifying "
  "`accessToken.Valid` is the control that closes the authentication bypass.\nstatus: safe"},
"CVE-2017-20164": {
 "vuln":
  "After login this SilverStripe extension reads a redirect target straight from the request -- "
  "`$URL = $this->owner->getRequest()->getVar('BackURL')` -- and, if the user is logged in and "
  "`$URL` is set, redirects the browser there. Nothing checks that `$URL` points back to this "
  "site. An attacker sends a login link with `BackURL=https://evil.example/phish`; after the "
  "victim authenticates they are redirected to the attacker's page, which can phish credentials or "
  "abuse the origin's trust. That is an open redirect: user-controlled `BackURL` reaches a redirect "
  "with no same-site validation.\nstatus: vuln",
 "safe":
  "The fix adds a same-site check to the condition: "
  "`if(Member::currentUserID() && $URL && Director::is_site_url($URL))`. `Director::is_site_url` "
  "confirms `$URL` resolves to this application's own domain, so an absolute URL to `evil.example` "
  "fails the check and no redirect happens -- only internal paths are honoured. Constraining the "
  "redirect target to a site-local URL is the control that closes the open redirect.\n"
  "status: safe"},
"CVE-2015-10056": {
 "vuln":
  "This Django view runs a search. `q` comes straight from the request -- `q = request.GET['q']` "
  "-- and is concatenated into the SQL passed to `cursor.execute`: the query text is "
  "`SELECT ... WHERE title like '%' + q + '%' ...`. Because `q` is spliced directly into the query, "
  "a value like `' OR '1'='1` closes the string literal and injects attacker SQL that the database "
  "executes. This is SQL injection: input flows request -> `q` -> the SQL string with no "
  "parameterization or escaping in between.\nstatus: vuln",
 "safe":
  "The fix switches to a parameterized query -- `%s` placeholders with the values passed to "
  "`cursor.execute` separately as `[q,q,q,q]` -- and additionally strips `%`/`_` wildcards from "
  "`q`. With placeholders the driver sends `q` as a bound value, never as query text, so quotes "
  "and SQL keywords in the input are treated as literal data and cannot alter the query structure. "
  "Parameterization is the correct and complete fix for SQL injection.\nstatus: safe"},
"CVE-2022-29180": {
 "vuln":
  "These charm file handlers take a path straight from the request -- "
  "`path := pattern.Path(r.Context())` -- and hand it to the file store "
  "(`FileStore.Delete(u.CharmID, path)`, and the read/write handlers likewise) with no "
  "normalization. Because the path is never cleaned, `../` sequences walk out of the user's "
  "directory: an attacker can delete or read files outside their own storage by requesting a path "
  "that climbs upward. User-controlled path -> file operation with no traversal handling.\n"
  "status: vuln",
 "safe":
  "The fix normalizes the path before use in each handler: `path := filepath.Clean(pattern.Path"
  "(r.Context()))`. `filepath.Clean` collapses `.` and `..` segments, so an attacker's `../` runs "
  "are resolved away and the path can no longer climb out of the intended directory before it "
  "reaches the file store. Normalizing the path is the control that closes the traversal.\n"
  "status: safe"},
"CVE-2023-41330": {
 "vuln":
  "`prepareOutput` tries to block a dangerous output path with a single prefix check: "
  "`if (strpos($filename, 'phar://') === 0) throw ...`. That is a blocklist of exactly one string "
  "-- it only rejects a `$filename` that begins with lowercase `phar://`. Other PHP stream wrappers, "
  "a different-cased `PHAR://`, or a wrapper introduced another way all pass, and a phar wrapper in "
  "particular can trigger object deserialization. Blocking one literal prefix does not constrain "
  "what the output path may actually be.\nstatus: vuln",
 "safe":
  "The fix replaces the single-prefix blocklist with a scheme allowlist: it runs "
  "`parse_url($filename)`, lowercases the `scheme`, and throws unless the scheme is empty or "
  "exactly `file`. Now any wrapper other than a plain local file is rejected regardless of casing, "
  "because the code enumerates what is ALLOWED instead of trying to list everything forbidden. An "
  "allowlist of the one safe scheme is the sound fix.\nstatus: safe"},
"CVE-2023-40170": {
 "vuln":
  "This Jupyter file handler's `get` is marked `@authorized`, but that decorator only checks the "
  "user's permissions -- it does not confirm the request wasn't forged by another site. The "
  "handler reads a file by `path` and streams it (via `set_attachment_header`) with no "
  "`check_xsrf_cookie()` call. So a malicious page the victim visits can issue a cross-site request "
  "that rides the victim's session and pulls files from their server. The missing control is "
  "CSRF/XSRF protection on a state-exposing request.\nstatus: vuln",
 "safe":
  "The fix adds `self.check_xsrf_cookie()` at the top of `get`. That verifies the request carries "
  "the server's XSRF token, which a cross-site attacker cannot read or forge, so a request from "
  "another origin is rejected before any file is served. Requiring the XSRF cookie is the control "
  "that closes the cross-site request forgery.\nstatus: safe"},
"CVE-2023-42819": {
 "vuln":
  "This handler writes an uploaded file. The destination is built with "
  "`np = os.path.join(full_path, p)` where `p` derives from the user-supplied name, then the file "
  "is created there via `os.makedirs(new_file_path)` / `open(new_file_path, 'w')`. `os.path.join` "
  "gives no protection against traversal -- if the name contains `../` or an absolute path, the "
  "join walks outside `full_path`, so an attacker can create or overwrite files anywhere the "
  "process can write. User-controlled name -> os.path.join -> filesystem write with no containment.\n"
  "status: vuln",
 "safe":
  "The fix swaps `os.path.join` for `safe_join(full_path, p)` everywhere the path is built. "
  "`safe_join` resolves the combined path and verifies it stays within `full_path`, raising "
  "instead of returning a path that escapes the base directory -- so a name containing `../` is "
  "rejected rather than honored. Confining the write to a canonicalized sub-path of the intended "
  "directory is the control that closes the traversal.\nstatus: safe"},
}


def main():
    wl = {}
    for l in open("data/cot/staging/regen_worklist.jsonl", encoding="utf-8"):
        r = json.loads(l)
        if r.get("cve") in AUTHORED:
            wl[r["cve"]] = r
    out, fails = [], 0
    for cve, sides in AUTHORED.items():
        r = wl.get(cve)
        if not r:
            print(f"  {cve}: NOT in worklist"); fails += 1; continue
        vcode, scode = views_both(r["patch"])
        for label, code in (("vuln", vcode), ("safe", scode)):
            trace = sides[label]
            g = grounded(trace, code)
            vok = trace.strip().lower().endswith(label)
            status = "OK" if (g and vok) else "FAIL"
            print(f"  {cve} {label:4s} {r['cwes'][0]:8s} {r['primary_lang']:10s} "
                  f"grounded={g} verdict={vok} -> {status}")
            if g and vok:
                out.append({"messages": [
                    {"role": "user", "content": f"<SCAN>\n{code}\n</SCAN>"},
                    {"role": "assistant", "content": trace}],
                    "_meta": {"label": label, "cwe": r["cwes"][0], "cwes": r["cwes"], "cve": cve,
                              "language": r["primary_lang"], "source": "regen_gold",
                              "pair_id": cve, "contrastive": True, "patch": r["patch"],
                              "n_files": r["n_files"], "multi_file": r["multi_file"],
                              "gates": {"grounded": True, "verdict": True}}})
            else:
                fails += 1
    with open(OUT, "w", encoding="utf-8") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    npair = len({r["_meta"]["pair_id"] for r in out}) if out else 0
    print(f"\nKEPT {len(out)} gold records ({npair} full pairs), {fails} failed -> {OUT}")


if __name__ == "__main__":
    main()
