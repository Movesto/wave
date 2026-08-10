# Cross-file vulnerability benchmark — ground truth

A small Express-style app where **every flow's SOURCE and SINK live in different files**.
Source is in `app/routes/handlers.js`; the sink is in an `app/services/*.js` file, reached
by passing the tainted value across the file boundary. This is the pattern real frameworks
(NestJS controller→service, Express route→model) use and that **intra-file taint cannot see**.

Use it as a gate test: an interfile engine (Semgrep Pro, Joern) should catch the VULN flows
and clear the SAFE ones; free/intra-file Semgrep catches **none** of them (validated below).

| Flow | CWE | Label | Source (handlers.js) | Sink (service file) |
|------|-----|-------|----------------------|---------------------|
| F1 | 78 command | **VULN** | `ping` — `req.query.host` | `netService.runPing` → `exec('ping…'+host)` |
| F2 | 78 command | safe | `pingSafe` — `req.body.host` | `netService.runPingSafe` → `execFile('ping',[…,host])` |
| F3 | 89 sql | **VULN** | `searchUser` — `req.query.name` | `userService.findByName` → concat `db.query` |
| F4 | 89 sql | safe | `getUser` — `req.params.id` | `userService.findById` → parameterised `db.query(…,[id])` |
| F5 | 22 path | **VULN** | `readDoc` — `req.query.doc` | `fileService.readDoc` → `readFileSync(BASE+'/'+name)` |
| F6 | 22 path | safe | `readAvatar` — `req.query.avatar` | `fileService.readAvatar` → `readFileSync(join(BASE,basename(name)))` |
| F7 | 918 ssrf | **VULN** | `proxy` — `req.query.url` | `httpService.fetchUrl` → `axios.get(url)` |

**Ground truth: 4 VULN (F1,F3,F5,F7), 3 SAFE (F2,F4,F6).**

An ideal cross-file scanner scores 4/4 recall + 0 false positives on the SAFE flows.
Intra-file Semgrep scores 0/4 — it never connects a route source to a service sink.

---

## Engine results (2026-08-09)

| Engine | Type | Recall (of 4 vuln) | False positives (of 3 safe) |
|---|---|---|---|
| **CodeQL** (javascript-security-extended) | interprocedural / interfile | **4/4** | **0** |
| Semgrep OSS (intra-file taint) | intra-file only | 0/4 | 0 |

CodeQL traced every source (handlers.js) across the file boundary to its sink in the
service file, and correctly cleared the sanitised safe flows (execFile, parameterised
query, basename). Semgrep OSS caught none — it never crosses a file. **CodeQL is a FREE
interfile engine that resolves the cross-file ceiling** (no Semgrep Pro / Joern needed).

Reproduce: `codeql database create <db> --language=javascript --source-root=xfile_bench/app`
then `codeql database analyze <db> codeql/javascript-queries:codeql-suites/javascript-security-extended.qls`.
Needs the Express wiring in app/index.js so CodeQL recognises req.* as remote sources, and a
real SQL library (mysql) so a modelled SQL sink exists.
