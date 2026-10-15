"""pgsafe -- a SECURE control twin of pgvuln (Postgres-backed). Same /search route and SQL sink, but the
query is PARAMETERIZED (the user value is BOUND, never concatenated into the statement), so SQL injection
is neutralized. Like pgvuln it connects at import, so it also verifies the DB-sidecar path. The detector
flags the sink; the oracle must DEFER. Any finding here is a FALSE POSITIVE -- test target only."""
import os

from flask import Flask, request
from sqlalchemy import create_engine, text

app = Flask(__name__)
_e = create_engine(os.environ["DATABASE_URL"])          # requires the wave postgres sidecar

with _e.begin() as c:                                   # runs at import -> needs a live DB to boot
    c.execute(text("CREATE TABLE IF NOT EXISTS users (name TEXT)"))
    c.execute(text("INSERT INTO users (name) VALUES ('alice')"))


@app.route("/search")
def search():
    q = request.args.get("q", "")
    with _e.begin() as c:                               # bound parameter -> the value can't alter the query
        rows = c.execute(text("SELECT name FROM users WHERE name = :q"), {"q": q}).fetchall()
    return {"rows": [r[0] for r in rows]}


@app.route("/")
def index():
    return {"app": "pgsafe"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
