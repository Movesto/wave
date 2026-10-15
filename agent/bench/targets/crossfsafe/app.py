"""crossfsafe -- a SECURE control twin of crossfsql. Same cross-function shape (the raw execute lives in a
helper, the caller passes user input), but the SQL is PARAMETERIZED across the boundary: the user value
travels as a BOUND parameter alongside the static statement, never concatenated into the SQL text. The
READER may still flag the cross-function flow, and Rung 1 micro-execution must DEFER (the param is bound).
Any finding here is a FALSE POSITIVE -- test target only."""
from sqlalchemy import create_engine, text

_e = create_engine("sqlite:////tmp/crossfsafe.db")


def _run(sql, params):                             # raw sink, but params are BOUND (never string-concatenated)
    with _e.begin() as c:
        return c.execute(text(sql), params).fetchall()


def search_items(term):                            # safe: term is a bound parameter, not part of the SQL text
    return _run("SELECT id, name FROM items WHERE name = :term", {"term": term})
