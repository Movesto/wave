"""Report signal-to-noise: the deterministic secrets / controls lanes (separate from the model/prove
surface) no longer let test fixtures, docs and i18n examples crowd out real findings; and the NoSQLi pin
no longer mislabels relational-ORM queries."""
import pytest

from agent.orchestrator import controls, repomap, secrets


# ---- secrets: real-code hits are primary; tests/docs/i18n grouped below (never dropped) ----
@pytest.mark.parametrize("path,low", [
    ("src/modules/auth/auth.service.ts", False),
    ("src/common/security/proxy-dispatcher.ts", False),
    ("ingress.controller.spec.ts", True),
    ("src/foo.test.ts", True),
    ("docs/06-api-specification.md", True),
    ("dashboard/src/i18n/locales/en.json", True),
    ("openapi.json", True),
])
def test_secrets_low_value_classification(path, low):
    assert secrets._is_low_value(path) is low


def test_secrets_render_segments_and_keeps_all():
    findings = [
        {"type": "Credentials in URL", "severity": "high", "commit": "aaa",
         "file": "src/common/security/proxy-dispatcher.ts", "match": "sock…"},
        {"type": "hardcoded secret", "severity": "low", "commit": "bbb",
         "file": "src/webhook/webhook.service.spec.ts", "match": "old…"},
        {"type": "Credentials in URL", "severity": "high", "commit": "ccc",
         "file": "docs/06-api-specification.md", "match": "http…"},
    ]
    out = secrets.render(findings)
    # all three are still present (nothing dropped)
    assert out.count("- **") == 3
    low_header = "### In tests / docs / examples"
    assert low_header in out
    # the real-code hit appears BEFORE the low-value section; the spec/docs hits after it
    assert out.index("proxy-dispatcher.ts") < out.index(low_header)
    assert out.index(low_header) < out.index("webhook.service.spec.ts")
    assert out.index(low_header) < out.index("06-api-specification.md")


# ---- controls: a cookie set in a test file is not a production control gap ----
def test_cookie_sites_skips_test_files(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "http.ts").write_text(
        "res.setHeader('Set-Cookie', 'sid=abc');\n", encoding="utf-8")
    (tmp_path / "app" / "http.spec.ts").write_text(
        "res.setHeader('Set-Cookie', 'sid=abc');\n", encoding="utf-8")
    sites = controls._cookie_sites(str(tmp_path))
    files = [s["file"].replace("\\", "/") for s in sites]
    assert any(f.endswith("app/http.ts") for f in files)
    assert not any(".spec." in f for f in files)


# ---- NoSQLi pin: relational ORM queries are not flagged; real Mongo shapes still are ----
@pytest.mark.parametrize("code,expected", [
    (".findOne({ where: { id } })", False),            # TypeORM
    (".find({ select: { keyHash: true } })", False),   # TypeORM
    (".findOne({ where: { id, sessionId } })", False),
    ("db.users.findOne(id)", False),                   # string arg, not operator-injectable
    (".findOne({ email: req.body.email })", True),     # Mongoose bare filter
    (".find({ $where: payload })", True),
    ("coll.aggregate(pipeline)", True),
    ("query = { $ne: null }", True),
])
def test_nosqli_pin_excludes_relational_orm(code, expected):
    rx = dict(repomap._SINKS_COMMON)["NoSQLi"]
    assert bool(rx.search(code)) is expected
