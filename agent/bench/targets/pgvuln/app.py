"""pgvuln -- a controlled Postgres-backed target. It CANNOT boot without a database (it connects to
DATABASE_URL at import), so it verifies the DB-sidecar: the provisioner must spin up Postgres and wire
DATABASE_URL for the app to reach Rung 2. SQL injection via string concatenation.
DELIBERATELY VULNERABLE -- test target only."""
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
    with _e.begin() as c:
        rows = c.execute(text("SELECT name FROM users WHERE name = '" + q + "'")).fetchall()   # CWE-89
    return {"rows": [r[0] for r in rows]}


@app.route("/")
def index():
    return {"app": "pgvuln"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
