"""Three repomap upgrades that break the 'selection is gated by the static regex dictionary' ceiling:

  1. CAPABILITY PINS -- a file that IMPORTS a risk-bearing library (mcp / an XML parser / LDAP) is
     nominated for a full read even when NO call-site matched the sink dictionary. This is the exact gap
     that hid the Langflow MCP RCE: `import mcp` was the tell, the call-site regex missed the wrapper.
  2. REACHABILITY-RANKED map stage -- build_map orders pinned files by whether untrusted input can reach a
     sink (cross-file), not by raw pin density, so the digest leads with the real attack surface.
  3. DIGEST BUDGET -- the dense digest caps the pinned-file tail on a monorepo so it can't blow the model's
     context, and (because of #2) it keeps the highest-reachability files and summarizes out the rest.
"""
from pathlib import Path

from agent.orchestrator import repomap
from agent.orchestrator.codemap import FileInfo


def _labels(sinks):
    return [lbl for _ln, lbl, _c in sinks]


# ---------------------------------------------------------------- 1. capability pins -------------------

def test_capability_pin_fires_on_mcp_import_without_a_sink_line(tmp_path):
    # mcp is imported and used through a wrapper the cmd dictionary does NOT match -> still nominated.
    src = ("import mcp\n"
           "\n"
           "def launch(cfg):\n"
           "    client = make_client(cfg)   # no subprocess/os.system/stdio_client text on this line\n"
           "    return client\n")
    f = tmp_path / "runner.py"
    f.write_text(src, encoding="utf-8")
    finfo = FileInfo(path=str(f), lang="python", imports=["import mcp"])
    _r, sinks, _d = repomap.scan_pins(finfo)
    cmd_lines = [ln for ln, lbl, _c in sinks if lbl == "cmd"]
    assert cmd_lines, f"mcp import did not nominate a cmd capability pin; sinks={sinks}"
    assert 1 not in cmd_lines, "a capability pin must not anchor on the import line"


def test_capability_pin_fires_for_xml_and_ldap(tmp_path):
    for lib, cls, imp in (("lxml", "xxe", "from lxml import etree"),
                          ("ldap3", "ldap", "import ldap3")):
        f = tmp_path / f"{lib}_mod.py"
        f.write_text(f"{imp}\n\ndef handle(data):\n    return consume(data)\n", encoding="utf-8")
        finfo = FileInfo(path=str(f), lang="python", imports=[imp])
        _r, sinks, _d = repomap.scan_pins(finfo)
        assert cls in _labels(sinks), f"{lib} import did not nominate a {cls} pin; sinks={sinks}"


def test_capability_pin_deduped_when_a_real_sink_exists(tmp_path):
    # a real subprocess.run sink already locates cmd -> the mcp capability pin must NOT add a second cmd pin.
    src = ("import mcp\n"
           "import subprocess\n"
           "def launch(c):\n"
           "    subprocess.run(c)\n")
    f = tmp_path / "both.py"
    f.write_text(src, encoding="utf-8")
    finfo = FileInfo(path=str(f), lang="python", imports=["import mcp", "import subprocess"])
    _r, sinks, _d = repomap.scan_pins(finfo)
    cmd_lines = sorted(ln for ln, lbl, _c in sinks if lbl == "cmd")
    assert cmd_lines == [4], f"expected one real cmd sink at the subprocess.run line, got {cmd_lines}"


def test_capability_pin_excludes_the_defused_xml_stack(tmp_path):
    # defusedxml IS the XXE fix -- importing it must not nominate the file as xxe.
    src = ("from defusedxml.ElementTree import parse\n"
           "def handle(data):\n"
           "    return parse(data)\n")
    f = tmp_path / "safe_xml.py"
    f.write_text(src, encoding="utf-8")
    finfo = FileInfo(path=str(f), lang="python", imports=["from defusedxml.ElementTree import parse"])
    _r, sinks, _d = repomap.scan_pins(finfo)
    assert "xxe" not in _labels(sinks), f"defusedxml must not be nominated as xxe; sinks={sinks}"


def test_capability_pin_suppressed_in_frontend_code(tmp_path):
    # xxe is a server-only class; a browser module that imports an xml parser must not be nominated.
    src = ("import xml2js from 'xml2js'\n"
           "export function parseInBrowser(s){ return build(s) }\n")
    f = tmp_path / "widget.jsx"
    f.write_text(src, encoding="utf-8")
    finfo = FileInfo(path=str(f), lang="javascript", imports=["xml2js"])
    _r, sinks, _d = repomap.scan_pins(finfo)
    assert "xxe" not in _labels(sinks), "server-only xxe must be suppressed in frontend code"


# ---------------------------------------------------------------- 2. reachability ranking --------------

def test_build_map_ranks_reachable_over_pin_dense(tmp_path):
    # api.py: ONE route + ONE sink (the real surface).  util.py: FOUR sinks, no entry reaches them.
    # Old pincount order put util first; reachability order must put api first.
    (tmp_path / "api.py").write_text(
        "from flask import request\n"
        "import os\n"
        "@app.route('/run')\n"
        "def run_it():\n"
        "    return os.system(request.args['c'])\n", encoding="utf-8")
    (tmp_path / "util.py").write_text(
        "import os\n"
        "def a(x): os.system(x)\n"
        "def b(x): os.system(x)\n"
        "def c(x): os.system(x)\n"
        "def d(x): os.system(x)\n", encoding="utf-8")
    res = repomap.build_map(str(tmp_path), out=str(tmp_path / "m.md"))
    order = [Path(p).name for p in res["pinned"]]
    assert "api.py" in order and "util.py" in order
    assert order.index("api.py") < order.index("util.py"), f"reachable file should rank first; order={order}"


# ---------------------------------------------------------------- 3. digest budget ---------------------

def test_digest_caps_pinned_tail_and_notes_omission(tmp_path):
    for i in range(6):
        (tmp_path / f"s{i}.py").write_text(f"import os\ndef f{i}(x): os.system(x)\n", encoding="utf-8")
    res = repomap.build_map(str(tmp_path), out=str(tmp_path / "m.md"))
    cmap, per_file, pinned, infra = res["cmap"], res["per_file"], res["pinned"], res["infra"]
    full = repomap._render_digest(cmap, str(tmp_path), per_file, pinned, infra, budget=1000)
    capped = repomap._render_digest(cmap, str(tmp_path), per_file, pinned, infra, budget=2)
    assert "omitted from this digest" not in full
    assert "omitted from this digest" in capped
    assert capped.count("### ") == 2, "only the budgeted number of pinned-file sections should render"
