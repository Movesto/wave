"""Fix 3 (non-web class): codegen injection (CWE-94) -- attacker text built into EMITTED code that runs in
another program (the datamodel-code-generator imports.py shape). The detector pattern is deliberately
narrow (keyword immediately followed by the interpolation) so ordinary f-strings don't false-pin, and the
class is wired end-to-end into the taxonomy (canonical name, CWE recipe, severity above the budget floor)."""
from agent.orchestrator import detector, prove, repomap


def _py_codegen():
    return dict(repomap._SINKS_PY)["codegen"]


def test_codegen_pattern_catches_the_canonical_shapes():
    rx = _py_codegen()
    hits = [
        "return f\"from {from_} import {', '.join(self._set_alias(from_, imports))}\"",
        'line = f"import {module_name}"',
        'src = f"def {func_name}(self):"',
        'src = f"class {cls_name}:"',
        'deco = f"@{validator_name}"',
    ]
    for h in hits:
        assert rx.search(h), f"missed codegen shape: {h}"


def test_codegen_pattern_does_not_false_pin_ordinary_fstrings():
    rx = _py_codegen()
    benign = [
        'log.info(f"importing {n} records")',     # "importing", not "import {"
        'msg = f"{count} classes loaded"',        # keyword not at the start
        'print(f"from the cache: {value}")',      # "from the", not "from {"
        'label = f"user {uid} logged in"',
        'q = f"SELECT * FROM {table}"',            # SQL, a different class -- not codegen
    ]
    for b in benign:
        assert not rx.search(b), f"false-pinned benign f-string: {b}"


def test_codegen_is_wired_into_the_taxonomy():
    # canonical name resolves (and codegen-specific synonyms map to it; "code-injection" still -> eval)
    assert detector._canonical_class("codegen") == "codegen"
    assert detector._canonical_class("code-generation") == "codegen"
    assert detector._canonical_class("import-injection") == "codegen"
    assert detector._canonical_class("code-injection") == "eval"      # unchanged safer in-process default
    # has a CWE recipe + a severity above the prove budget-cut floor, in BOTH tables
    assert prove._CLASS_CWE["codegen"] == "CWE-94"
    assert prove._SEV["codegen"] > 1 and detector._SEV["codegen"] > 1
    assert "codegen" in detector._KNOWN_CLASSES


def test_js_codegen_pattern():
    rx = dict(repomap._SINKS_JS)["codegen"]
    assert rx.search("const line = `import ${name} from './x'`")
    assert rx.search("code += `function ${fnName}() {}`")
    assert not rx.search("const s = `importing ${n} files`")
