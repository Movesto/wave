"""crossfsql -- SQL injection built ACROSS functions: the raw execute lives in a helper, the taint is
in the caller. The intra-procedural pattern detector misses it (no concatenation at the execute site);
the READER (model) catches it by reading the whole file, and Rung 1 micro-execution confirms it --
without booting (this app starts no server). DELIBERATELY VULNERABLE -- test target only."""
from sqlalchemy import create_engine, text

_e = create_engine("sqlite:////tmp/crossf.db")


def _run(sql):                                     # raw sink; no user input is VISIBLE here
    with _e.begin() as c:
        return c.execute(text(sql)).fetchall()


def search_items(term):                            # CWE-89: term concatenated, then handed to the helper
    return _run("SELECT id, name FROM items WHERE name = '" + term + "'")
