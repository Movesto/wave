"""Five sink classes added to the taxonomy: XXE (CWE-611), CRLF/response-splitting (CWE-113),
LDAP injection (CWE-90), XPath injection (CWE-643), weak crypto (CWE-327). A class is only useful if it
is wired END TO END -- the regex pins it (recall), the detector knows it (so a model relabel doesn't blank
it), the prover maps it to a CWE and a severity (so it isn't floored below the prove budget), and cwe_info
can describe it for the report. These tests pin every link in that chain so a half-registered class can't
regress to silent-drop (the failure mode that benched the Langflow RCE)."""
from agent.orchestrator import repomap, detector, prove, cwe_info, oracle, select
from agent.orchestrator import select as _select
from agent.orchestrator.codemap import FileInfo

NEW = ["xxe", "crlf", "ldap", "xpath", "weakcrypto"]


def _tbl(lang):
    return dict((lbl, rx) for lbl, rx in repomap._lang_sinks(lang))


def test_each_new_class_pins_in_python():
    t = _tbl("python")
    cases = {
        "xxe": "tree = etree.parse(request.files['x'])",
        "xpath": "hits = root.xpath(user_expr)",
        "ldap": "conn.search_s(base, SCOPE, user_filter)",
        "crlf": "self.send_header('X-Redirect', user_value)",
        "weakcrypto": "digest = hashlib.md5(token).hexdigest()",
    }
    for cls, line in cases.items():
        assert t[cls].search(line), f"python {cls} did not pin: {line}"


def test_each_new_class_pins_in_js():
    t = _tbl("javascript")
    cases = {
        "xxe": "const doc = libxmljs.parseXml(body, { noent: true })",
        "xpath": "const n = document.evaluate(userExpr, doc, null, 0, null)",
        "crlf": "res.setHeader('Location', req.query.next)",
        "weakcrypto": "const id = crypto.createHash('md5').update(x).digest('hex')",
    }
    for cls, line in cases.items():
        assert t[cls].search(line), f"js {cls} did not pin: {line}"


def test_classic_enterprise_langs_cover_the_injection_trio():
    # XXE / XPath / LDAP are quintessential Java / PHP / .NET bugs -- make sure those tables carry them.
    assert _tbl("java")["xxe"].search("DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();")
    assert _tbl("java")["ldap"].search("DirContext ctx = new InitialDirContext(env);")
    assert _tbl("php")["xxe"].search("$x = simplexml_load_string($_POST['xml']);")
    assert _tbl("csharp")["xpath"].search("var n = doc.SelectNodes(userXPath);")


def test_no_false_pin_on_safe_shapes():
    py = _tbl("python")
    assert not py["weakcrypto"].search("h = hashlib.sha256(data).hexdigest()")   # strong hash is fine
    assert not py["xpath"].search("self.xpather = build()")                      # attribute, not a call
    assert not py["ldap"].search("rows = df.search_sorted(key)")                 # not an LDAP search
    js = _tbl("javascript")
    assert not js["weakcrypto"].search("const r = Math.round(x)")                # not Math.random()
    assert not js["crlf"].search("thing.setHeaderless(true)")


def test_detector_knows_every_new_class():
    for cls in NEW:
        assert cls in detector._KNOWN_CLASSES, f"{cls} missing from detector._KNOWN_CLASSES"
        assert cls in detector._SEV, f"{cls} missing from detector._SEV"


def test_model_relabels_normalize_not_blank():
    # a free-text relabel must resolve back to the canonical class, never "" (which blanks CWE + floors sev).
    assert detector._canonical_class("xml-external-entity") == "xxe"
    assert detector._canonical_class("http-response-splitting") == "crlf"
    assert detector._canonical_class("ldap-injection") == "ldap"
    assert detector._canonical_class("xpath-injection") == "xpath"
    assert detector._canonical_class("insecure-randomness") == "weakcrypto"


def test_prover_maps_class_to_cwe_and_severity():
    want = {"xxe": "CWE-611", "crlf": "CWE-113", "ldap": "CWE-90", "xpath": "CWE-643",
            "weakcrypto": "CWE-327"}
    for cls, cwe in want.items():
        assert prove._CLASS_CWE.get(cls) == cwe, f"{cls} -> wrong CWE"
        assert prove._SEV.get(cls, 1) > 1, f"{cls} severity floored (would drop below prove budget)"
        assert cls in oracle.CLASS_WITNESS, f"{cls} missing from oracle.CLASS_WITNESS"
        assert cls in select._SEV, f"{cls} missing from select._SEV (would rank at the floor)"


def test_report_can_describe_every_new_cwe():
    for cwe in ("CWE-611", "CWE-113", "CWE-90", "CWE-643", "CWE-327"):
        name, sev, fix = cwe_info.describe(cwe=cwe)
        assert name and name != "Potential security issue", f"{cwe} has no description"
        assert fix


def test_end_to_end_scan_pins_anchors_xxe(tmp_path):
    src = (
        "from lxml import etree\n"
        "\n"
        "def parse_upload(request):\n"
        "    data = request.files['doc'].read()\n"
        "    return etree.fromstring(data)\n"
    )
    f = tmp_path / "xml_handler.py"
    f.write_text(src, encoding="utf-8")
    finfo = FileInfo(path=str(f), lang="python", imports="")
    _routes, sinks, _dyn = repomap.scan_pins(finfo)
    xxe_lines = [ln for ln, lbl, _c in sinks if lbl == "xxe"]
    assert 5 in xxe_lines, f"etree.fromstring not anchored as xxe; sinks={sinks}"
    assert 1 not in xxe_lines, "the `from lxml import etree` import line must not anchor a sink"
