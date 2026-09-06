"""fastapivuln -- a controlled FastAPI (ASGI) target: it boots via uvicorn (module:app), NOT via
`python app.py`, so it verifies the provisioner is framework-general. SQL injection via string
concatenation. DELIBERATELY VULNERABLE -- test target only."""
from fastapi import FastAPI
from sqlalchemy import create_engine, text

app = FastAPI()
_e = create_engine("sqlite:////tmp/fapi.db")


def _init():
    with _e.begin() as c:
        c.execute(text("CREATE TABLE IF NOT EXISTS users (name TEXT)"))
        c.execute(text("INSERT INTO users (name) VALUES ('alice')"))


@app.get("/search")
def search(q: str = ""):                                # CWE-89: q concatenated into the SQL string
    with _e.begin() as c:
        rows = c.execute(text("SELECT name FROM users WHERE name = '" + q + "'")).fetchall()
    return {"rows": [r[0] for r in rows]}


@app.get("/")
def index():
    return {"app": "fastapivuln"}


_init()
