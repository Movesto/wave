"""SQLi via a RAW SQL STRING assembled by interpolation. The dangerous `${...}` is spliced into a template
literal that holds a SQL statement/clause (e.g. TypeORM `GENERATED ALWAYS AS (${expr})`), and the DDL/DML is
executed LATER by a schema-manager / queryRunner -- so no `.query(`/`.execute(` token sits at the interpolation
site and the call-site SQLi patterns miss it. This is the twenty searchVector sink (CVE-2026-73069) wave did
not pin. The pattern stays on two-token SQL forms so ordinary template strings (GraphQL, logs, paths) don't
false-pin."""
from agent.orchestrator import repomap
from agent.orchestrator.codemap import FileInfo


def _js_sqli():
    # both the call-site SQLi and the new raw-SQL-template SQLi are labelled "SQLi"; test the new one directly.
    return [rx for name, rx in repomap._SINKS_JS if name == "SQLi"]


def _matches(line):
    return any(rx.search(line) for rx in _js_sqli())


def test_call_site_sqli_still_matches():
    for hit in ("const r = await ds.query(`SELECT * FROM t WHERE id=${id}`)",
                "knex.raw(`DELETE FROM x WHERE a=${a}`)",
                "sequelize.query(sql)"):
        assert _matches(hit), f"regressed call-site SQLi: {hit}"


def test_raw_sql_template_interpolation_is_caught():
    hits = [
        "parts.push(`GENERATED ALWAYS AS (${column.asExpression})`);",   # the twenty CVE-2026-73069 sink
        "const q = `SELECT name FROM users WHERE id = ${id}`;",
        "const i = `INSERT INTO audit (msg) VALUES (${m})`;",
        "await r.query(`ALTER TABLE ${t} ADD COLUMN c int`);",
        "const u = `UPDATE t SET name = ${n} WHERE id = ${id}`;",
        "const v = `CREATE VIEW ${name} AS SELECT 1`;",
        "const d = `DROP TABLE ${t}`;",
        "const z = `SELECT 1 UNION SELECT ${x} FROM secrets`;",
    ]
    for h in hits:
        assert _matches(h), f"missed raw-SQL template interpolation: {h}"


def test_raw_sql_template_does_not_false_pin_ordinary_strings():
    benign = [
        "const msg = `update ${count} rows done`;",                     # English word, no SQL statement shape
        "const gql = `query ($id: ID!) { user(id: $id) { name } }`;",   # GraphQL template
        "logger.info(`created ${n} items, now selecting next batch`);", # prose
        "const html = `<div>${escaped}</div>`;",
        "const path = `/api/${id}/select`;",
        "const q = `SELECT name FROM users`;",                           # SQL but NO interpolation -> not a sink
        "const label = `Delete from list?`;",                            # no interpolation
    ]
    for b in benign:
        assert not _matches(b), f"false-pinned benign line: {b}"


def test_generated_always_as_anchors_a_sqli_sink_end_to_end(tmp_path):
    """Through scan_pins: the interpolated GENERATED ALWAYS AS clause anchors a `SQLi` sink on its line, the
    shape wave previously could not see (the call-site patterns only know `.query(`/`.execute(`/knex.raw)."""
    src = (
        "export const buildSqlColumnDefinition = (column: FlatFieldMetadata): string => {\n"
        "  const parts: string[] = [column.name, column.type];\n"
        "  if (column.asExpression && column.type === 'tsvector') {\n"
        "    parts.push(`GENERATED ALWAYS AS (${column.asExpression})`);\n"
        "  }\n"
        "  return parts.join(' ');\n"
        "};\n"
    )
    f = tmp_path / "build-sql-column-definition.util.ts"
    f.write_text(src, encoding="utf-8")
    finfo = FileInfo(path=str(f), lang="typescript", imports="")
    _routes, sinks, _dyn = repomap.scan_pins(finfo)
    sqli_lines = [line for line, label, _code in sinks if label == "SQLi"]
    assert 4 in sqli_lines, f"GENERATED ALWAYS AS interpolation not anchored; SQLi sinks at {sqli_lines}"
