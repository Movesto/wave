"""bizvuln -- a controlled BUSINESS-LOGIC target for the wave benchmark. No injection sink; the flaw
is a broken trust boundary: /checkout trusts the client-supplied `price`, so the total is whatever the
attacker sends (web parameter tampering, CWE-472). Ground truth in MANIFEST.json.
DELIBERATELY VULNERABLE -- test target only."""
import itertools

from flask import Flask, request
from sqlalchemy import create_engine, text

app = Flask(__name__)
engine = create_engine("sqlite:////tmp/biz.db")
_CATALOG = {1: ("Laptop", 999.99), 2: ("Mouse", 25.00), 3: ("Monitor", 249.50)}
_order_id = itertools.count(1)


def _init():
    with engine.begin() as c:
        c.execute(text("CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, product INTEGER, total REAL)"))


@app.route("/product/<int:pid>")                       # server-authoritative catalog price
def product(pid):
    if pid not in _CATALOG:
        return {"error": "not found"}, 404
    name, price = _CATALOG[pid]
    return {"id": pid, "name": name, "price": price}


@app.route("/checkout", methods=["POST"])              # CWE-472 trusts the client-supplied price
def checkout():
    d = request.get_json(silent=True) or request.form
    pid = int(d.get("product_id", 1))
    qty = int(d.get("quantity", 1))
    price = float(d.get("price", 0))                   # <-- price comes from the CLIENT, never re-checked
    total = price * qty
    oid = next(_order_id)
    with engine.begin() as c:
        c.execute(text("INSERT INTO orders (id, product, total) VALUES (:i, :p, :t)"),
                  {"i": oid, "p": pid, "t": total})
    return {"order_id": oid, "product_id": pid, "quantity": qty, "total": total}


@app.route("/order/<int:oid>")                         # readback
def order(oid):
    with engine.begin() as c:
        row = c.execute(text("SELECT product, total FROM orders WHERE id = :i"), {"i": oid}).fetchone()
    if not row:
        return {"error": "not found"}, 404
    return {"order_id": oid, "product_id": row[0], "total": row[1]}


@app.route("/")
def index():
    return {"app": "bizvuln", "routes": ["/product/<id>", "/checkout (POST)", "/order/<id>"]}


_init()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
