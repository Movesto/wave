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


_profiles = {}


@app.route("/profile", methods=["POST"])              # CWE-915 mass assignment (client controls role)
def profile():
    d = request.get_json(silent=True) or request.form
    uname = d.get("username", "guest")
    prof = _profiles.get(uname, {"username": uname, "role": "user"})
    for k, v in d.items():                            # <-- binds EVERY client field, incl role/is_admin
        if k != "password":
            prof[k] = v
    _profiles[uname] = prof
    return {"username": uname, "profile": prof}        # reflects the persisted record


_wallet = {}


@app.route("/claim", methods=["POST"])                # CWE-837 replay: no once-only guard, bonus stacks
def claim():
    d = request.get_json(silent=True) or request.form
    u = d.get("username", "guest")
    _wallet[u] = _wallet.get(u, 0) + 50               # <-- credited on EVERY call; replay stacks the balance
    return {"username": u, "credited": 50, "balance": _wallet[u]}


_paid = set()


@app.route("/pay", methods=["POST"])                  # workflow step 1 (prerequisite)
def pay():
    d = request.get_json(silent=True) or request.form
    o = str(d.get("order", d.get("order_id", "")))
    _paid.add(o)
    return {"order": o, "paid": True}


@app.route("/confirm", methods=["POST"])              # CWE-840 step bypass: ships without checking payment
def confirm():
    d = request.get_json(silent=True) or request.form
    o = str(d.get("order", d.get("order_id", "")))
    return {"order": o, "status": "shipped", "shipped": True}   # <-- no payment/prerequisite check


@app.route("/")
def index():
    return {"app": "bizvuln",
            "routes": ["/product/<id>", "/checkout", "/order/<id>", "/profile", "/claim", "/pay", "/confirm"]}


_init()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
