"""Path-argument normalization (run._unquote). A quoted/pasted path must not carry literal quote chars
into file ops (on Windows `"` is illegal in a filename -> Errno 22 at stage 1).

Run: pytest tests/test_run_paths.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import run


def test_unquote_strips_double_quotes():
    assert run._unquote('"C:\\Users\\pscad\\Downloads\\Teach"') == "C:\\Users\\pscad\\Downloads\\Teach"


def test_unquote_strips_single_quotes_and_space():
    assert run._unquote("  '/home/u/repo'  ") == "/home/u/repo"


def test_unquote_leaves_plain_path():
    assert run._unquote("C:\\Users\\pscad\\Downloads\\Teach") == "C:\\Users\\pscad\\Downloads\\Teach"


def test_unquote_keeps_internal_quotes():
    # only a MATCHING wrapping pair is stripped; a lone/internal quote is left alone
    assert run._unquote('C:\\a"b') == 'C:\\a"b'
    assert run._unquote('"mismatch') == '"mismatch'


def test_unquote_handles_empty_and_none():
    assert run._unquote("") == "" and run._unquote(None) == ""
