"""MCP stdio = arbitrary-command execution (CWE-78). The process spawn lives inside the `mcp` package
(StdioServerParameters(command=...) -> stdio_client(...)), so no subprocess/os.system token appears in
first-party code -- the cmd sink taxonomy has to name the library launcher itself, or the sink never
anchors and never becomes a candidate (the Langflow MCP Tools RCE wave missed). The patterns stay
specific to the MCP launch APIs so ordinary code doesn't false-pin."""
from agent.orchestrator import repomap
from agent.orchestrator.codemap import FileInfo


def _py_cmd():
    return dict(repomap._SINKS_PY)["cmd"]


def _js_cmd():
    return dict(repomap._SINKS_JS)["cmd"]


def test_py_cmd_still_catches_stdlib_launchers():
    rx = _py_cmd()
    for hit in ("os.system(cmd)", "subprocess.run(args)", "os.popen(x)", "pty.spawn('/bin/sh')"):
        assert rx.search(hit), f"regressed stdlib cmd sink: {hit}"


def test_py_cmd_catches_mcp_stdio_launch():
    rx = _py_cmd()
    hits = [
        "server_params = StdioServerParameters(command=command[0], args=command[1:])",
        "stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))",
        "params = StdioServerParameters(command=cmd)",
    ]
    for h in hits:
        assert rx.search(h), f"missed MCP stdio launch: {h}"


def test_py_cmd_does_not_false_pin_ordinary_lines():
    rx = _py_cmd()
    benign = [
        "response = await self.session.list_tools()",   # MCP, but not a launch
        "logger.info('stdio client connected')",        # a string, not the stdio_client() call
        "command = command_str.split(' ')",             # building the list, no launcher
        "StdioServerParametersConfig = dict",            # name reference, not a call
        "transport_type = 'stdio_client'",               # a string literal, not the stdio_client() call
    ]
    for b in benign:
        assert not rx.search(b), f"false-pinned benign line: {b}"


def test_js_cmd_catches_mcp_stdio_transport():
    rx = _js_cmd()
    assert rx.search("const transport = new StdioClientTransport({ command, args });")
    assert rx.search("child_process.exec(userInput)")   # regression guard
    assert not rx.search("const t = StdioClientTransportConfig;")  # name ref, not a call


def test_nested_tools_dir_is_not_low_priority():
    """A NESTED tools/ dir holds agent/LLM runtime components (the Langflow MCP sink lived in
    components/tools/mcp_stdio.py); only a repo-ROOT tools/ is dev tooling. Getting this wrong made
    _codemap_pins skip the file so the cmd sink never became a candidate."""
    lp = repomap.is_low_priority_path
    # nested tools/ = app code -> scanned
    assert lp("src/backend/base/langflow/components/tools/mcp_stdio.py") is False
    assert lp("langchain/agents/tools/shell.py") is False
    assert lp(r"C:\x\langflow\src\langflow\components\tools\mcp_stdio.py") is False  # absolute too
    # repo-root tools/ = dev tooling -> still demoted
    assert lp("tools/gen_docs.py") is True
    # the other low-priority signals must be unchanged
    assert lp("scripts/deploy.sh") is True
    assert lp("src/pkg/tests/test_x.py") is True
    assert lp("vendor/lib/x.py") is True
    assert lp("src/backend/base/langflow/components/data/api_request.py") is False


def test_mcp_launch_anchors_a_cmd_sink_in_the_enclosing_fn(tmp_path):
    """End-to-end through scan_pins: a user command flowing into StdioServerParameters/stdio_client
    anchors a `cmd` sink on the launch lines (and the `from mcp import ...` line does NOT, since
    scan_pins skips imports)."""
    src = (
        "from mcp import StdioServerParameters, types\n"
        "from mcp.client.stdio import stdio_client\n"
        "\n"
        "async def connect_to_server(self, command_str):\n"
        "    command = command_str.split(' ')\n"
        "    server_params = StdioServerParameters(command=command[0], args=command[1:])\n"
        "    transport = await stdio_client(server_params)\n"
    )
    f = tmp_path / "mcp_stdio.py"
    f.write_text(src, encoding="utf-8")
    finfo = FileInfo(path=str(f), lang="python", imports="")
    _routes, sinks, _dyn = repomap.scan_pins(finfo)
    cmd_lines = [line for line, label, _code in sinks if label == "cmd"]
    assert 6 in cmd_lines, f"StdioServerParameters launch not anchored; cmd sinks at {cmd_lines}"
    assert 1 not in cmd_lines, "the `from mcp import ...` import line should not anchor a sink"
