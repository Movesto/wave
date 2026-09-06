"""microsql -- a Rung-1 fixture. A Python app that never starts an HTTP server (so it never becomes
healthy -> the runtime oracle, Rung 2, is UNAVAILABLE), with a directly-callable SQL-injection handler.
It demonstrates the confirmation ladder falling through to Rung 1: the vuln is confirmed by MICRO-
EXECUTION (import the handler with the DB tripwired, call it with a marked payload) WITHOUT booting.
DELIBERATELY VULNERABLE -- test target only. (Framework is declared via requirements.txt so the module
imports cleanly for Rung-1 micro-execution; it deliberately starts no server.)"""
from sqlalchemy import create_engine, text

_e = create_engine("sqlite:////tmp/microsql.db")


def run_report(owner):                                  # CWE-89: owner concatenated into the SQL string
    with _e.begin() as c:
        return c.execute(text("SELECT id, body FROM reports WHERE owner = '" + owner + "'")).fetchall()


# No app.run(): the container starts, imports this module, and exits -> never healthy -> Rung 2 can't
# prove anything. The ladder must fall through to Rung 1 (micro-execution) to confirm run_report.
