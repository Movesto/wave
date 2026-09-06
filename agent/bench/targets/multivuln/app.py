"""multivuln -- ships its OWN multi-service docker-compose (app + Postgres). Verifies wave reuses the
app's compose, injects sink hooks via sitecustomize, and boots the whole stack for Rung 2.
DELIBERATELY VULNERABLE -- test target only."""
import os
from flask import Flask, request
from sqlalchemy import create_engine, text

app = Flask(__name__)
_e = create_engine(os.environ["DATABASE_URL"])
with _e.begin() as c:
    c.execute(text("CREATE TABLE IF NOT EXISTS users (name TEXT)"))
    c.execute(text("INSERT INTO users (name) VALUES ('alice')"))

@app.route("/search")
def search():
    q = request.args.get("q", "")
    with _e.begin() as c:
        rows = c.execute(text("SELECT name FROM users WHERE name = '" + q + "'")).fetchall()
    return {"rows": [r[0] for r in rows]}

@app.route("/")
def index():
    return {"app": "multivuln"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
