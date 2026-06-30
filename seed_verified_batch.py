# Seed batch: I (the teacher) author vuln traces for clean patch tasks; the gates
# verify; kept records are appended to data/cot/pilot/shape1_verified.jsonl.
import os, json
os.environ["WAVE_VERIFIED_LANGS"] = "typescript,javascript,python"
from cot.shapes import shape1_verified as S
from cot.gates import all_gates_pass
from cot.config import PILOT_DIR

tasks = S.prepare_tasks(200)
sel = [t for t in tasks if 90 < len(t["vuln_code"]) < 800][:34]

T = {}
T[0] = """<think>
observerWardFolder is substituted into the shell string passed to os.system via .format(): os.system('chmod 777 {}/observerWard'.format(observerWardFolder)). The value is concatenated with no quoting or validation, so a crafted observerWardFolder injects extra shell commands. The same pattern feeds observerWardUpdateCMD into os.system.
</think>
status: confirmed
cwe: CWE-78
severity: HIGH
line: 4
trace: observerWardFolder -> format -> os.system chmod shell command
fix: pass an argument list to subprocess.run with shell=False, or shlex.quote the path"""

T[1] = """<think>
q is taken directly from request.GET and concatenated into a SQL string: cursor.execute(SELECT ... WHERE title like percent q percent ...). No parameterization or escaping is applied, so attacker-controlled q alters the WHERE clause -- SQL injection.
</think>
status: confirmed
cwe: CWE-89
severity: HIGH
line: 7
trace: request.GET -> cursor.execute SELECT WHERE like q
fix: use a parameterized query instead of string concatenation"""

T[2] = """<think>
validator_string is passed to ast.parse(validator_string, mode=eval). Parsing then evaluating an attacker-supplied expression allows arbitrary expression evaluation if the scope is not strictly constrained -- code injection.
</think>
status: confirmed
cwe: CWE-94
severity: HIGH
line: 4
trace: validator_string -> ast.parse mode eval -> expression evaluation
fix: restrict to an allowlist of node types or use literal_eval, never eval untrusted input"""

T[10] = """<think>
ticker reaches GetCoinFromTicker and is concatenated into a SQL filter: selectAll(ROWID AS id, ticker= escape(ticker), ...). escape is HTML-escaping not SQL-escaping, so quotes in ticker break out of the clause -- SQL injection.
</think>
status: confirmed
cwe: CWE-89
severity: HIGH
line: 4
trace: ticker -> escape ticker -> selectAll ticker SQL filter
fix: bind ticker as a parameter, do not concatenate into the WHERE clause"""

T[4] = """<think>
currency is derived from queryStr.market (a request query parameter) and passed to utils.GetCoinFromTicker(currency, ...). GetCoinFromTicker builds a SQL filter by concatenating its argument, so this user-controlled value reaches a SQL sink.
</think>
status: confirmed
cwe: CWE-89
severity: HIGH
line: 4
trace: queryStr.market -> currency -> GetCoinFromTicker currency SQL filter
fix: validate the ticker against an allowlist and parameterize the downstream query"""

T[5] = """<think>
queryStr.currency comes straight from the parsed request query and is passed to utils.GetCoinFromTicker(queryStr.currency, ...), which concatenates it into a SQL filter. The request value flows unvalidated into a SQL sink.
</think>
status: confirmed
cwe: CWE-89
severity: HIGH
line: 4
trace: queryStr.currency -> GetCoinFromTicker currency SQL filter
fix: parameterize the query inside GetCoinFromTicker and allowlist the ticker"""

T[7] = """<think>
queryStr.currency (request-controlled) is forwarded to utils.GetCoinFromTicker(queryStr.currency, ...), whose body concatenates the value into a SQL WHERE clause. Unvalidated request data reaches a SQL sink.
</think>
status: confirmed
cwe: CWE-89
severity: HIGH
line: 4
trace: queryStr.currency -> GetCoinFromTicker currency SQL filter
fix: bind parameters in GetCoinFromTicker and reject non-allowlisted tickers"""

T[9] = """<think>
queryStr.currency from the request is passed to utils.GetCoinFromTicker(queryStr.currency, ...), which builds a SQL filter by string concatenation. The tainted value reaches a SQL sink without sanitization.
</think>
status: confirmed
cwe: CWE-89
severity: HIGH
line: 4
trace: queryStr.currency -> GetCoinFromTicker currency SQL filter
fix: parameterize the downstream SQL and validate the ticker"""

T[14] = """<think>
self.uparam[k304] is a user-supplied query parameter. It is passed into gencookie(k304, self.uparam[k304], ...) and the result is appended as a Set-Cookie response header. An attacker-controlled value can inject cookie attributes or CRLF -- header/cookie injection.
</think>
status: confirmed
cwe: CWE-113
severity: MEDIUM
line: 4
trace: self.uparam k304 -> gencookie -> Set-Cookie header
fix: validate and encode the cookie value and strip CR/LF before adding the header"""

T[16] = """<think>
self.vpath is the user-controlled request path. It is joined into a filesystem path: static_path = os.path.join(self.E.mod, web, self.vpath) and served via self.tx_file(static_path) with no containment check, so ../ sequences escape the web root -- path traversal.
</think>
status: confirmed
cwe: CWE-22
severity: HIGH
line: 4
trace: self.vpath -> os.path.join static_path -> tx_file static_path
fix: resolve the real path and verify it startswith the web root before serving"""

T[17] = """<think>
value.expression and value.analyzer come from caller-supplied search tokens and are interpolated directly into a query template by fragments.push(token TOKENS expression analyzer). The fragments are joined into query and returned, so attacker-controlled token fields inject arbitrary AQL.
</think>
status: confirmed
cwe: CWE-94
severity: HIGH
line: 8
trace: value.expression -> fragments.push TOKENS -> query
fix: bind values via the aql template tag or parameterized bindVars"""

T[18] = """<think>
tokenizationsFiltered is passed to generateTokenizationQuery, which interpolates token fields into an AQL string, and the result is executed: this.db.query(generateTokenizationQuery(tokenizationsFiltered)). The unparameterized query reaches the database driver.
</think>
status: confirmed
cwe: CWE-94
severity: HIGH
line: 4
trace: tokenizationsFiltered -> generateTokenizationQuery -> db.query
fix: build the query with bound parameters rather than string interpolation"""

T[19] = """<think>
worktree_rev is passed as an argument to subprocess.check_output([self.git_command, rev-parse, worktree_rev], ...). If worktree_rev is attacker-influenced and begins with a dash it is interpreted as a git option, enabling argument injection.
</think>
status: confirmed
cwe: CWE-88
severity: MEDIUM
line: 4
trace: worktree_rev -> subprocess.check_output git_command rev-parse worktree_rev
fix: validate worktree_rev against an allowlist or prefix arguments with -- to stop option parsing"""

T[26] = """<think>
request.REQUEST tags is concatenated into a URL which is interpolated into an HTML anchor: url = request.path + tags= + request.REQUEST tags used inside a href url. The unescaped user value is rendered into HTML, allowing reflected XSS.
</think>
status: confirmed
cwe: CWE-79
severity: HIGH
line: 4
trace: request.REQUEST tags -> url -> a href url HTML message
fix: HTML-escape the value and URL-encode the tags parameter before building the link"""

T[27] = """<think>
The merge iterates Object.keys(obj) and assigns val = obj[key] into target[key] without excluding dangerous keys. When key is __proto__ or constructor the assignment pollutes the object prototype -- prototype pollution.
</think>
status: confirmed
cwe: CWE-1321
severity: HIGH
line: 3
trace: obj keys -> target[key] = obj[key] without __proto__ constructor guard
fix: skip __proto__ constructor prototype keys or use a null-prototype target"""

T[28] = """<think>
The JWT signing secret is hard-coded in the config: lxdui.jwt.secret.key = AC8d83. A committed static secret can be read from source control and used to forge valid tokens.
</think>
status: confirmed
cwe: CWE-798
severity: HIGH
line: 4
trace: lxdui.jwt.secret.key hardcoded secret -> JWT signing
fix: load the secret from an environment variable or secrets manager, never commit it"""

T[29] = """<think>
secretKey is read from configuration: Config().get(APP, jwt.secret.key). Combined with the committed default secret the JWT secret is effectively static, so tokens can be forged by anyone with the source.
</think>
status: confirmed
cwe: CWE-798
severity: HIGH
line: 4
trace: jwt.secret.key config -> secretKey -> JWT signing
fix: require a strong secret from the environment and fail closed if unset"""

kept = 0
dropped = 0
out = []
for idx, trace in T.items():
    task = sel[idx]
    rec = S.verify(task, trace)
    if rec:
        kept += 1
        out.append(rec)
        print(f"  [{idx:>2}] KEPT  ({task['language']})")
    else:
        dropped += 1
        _, fails, _ = all_gates_pass(trace, task["vuln_code"], task["region"])
        print(f"  [{idx:>2}] DROP  {fails}")

p = PILOT_DIR / "shape1_verified.jsonl"
with open(p, "a", encoding="utf-8") as f:
    for r in out:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
print(f"\nKEPT {kept} / {len(T)} authored  (dropped {dropped})")
print("total records now in shape1_verified.jsonl:", sum(1 for _ in open(p, encoding="utf-8")))
