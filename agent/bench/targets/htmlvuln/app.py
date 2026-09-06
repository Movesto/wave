"""htmlvuln -- business-logic target that renders HTML (not JSON), to exercise the HTML-aware readback.
Same flaws as bizvuln, but every response is an HTML page, so the differential oracles must parse the
markup (form inputs / table cells / spans) instead of JSON. DELIBERATELY VULNERABLE -- test only."""
from flask import Flask, request

app = Flask(__name__)
_CATALOG = {1: 999.99, 2: 25.00, 3: 249.50}
_bank = {}
_profiles = {}


def _page(title, body):
    return f"<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>"


@app.route("/checkout", methods=["POST"])              # CWE-472 client-controlled price -> HTML receipt
def checkout():
    d = request.get_json(silent=True) or request.form
    price = float(d.get("price", 0))
    qty = int(d.get("quantity", 1))
    total = price * qty
    return _page("Receipt", f'<h1>Receipt</h1><table><tr><td>Quantity</td><td>{qty}</td></tr>'
                            f'<tr><td>Total</td><td>${total:.2f}</td></tr></table>')


@app.route("/order", methods=["POST"])                 # CWE-1284 server price, no quantity validation
def order():
    d = request.get_json(silent=True) or request.form
    pid = int(d.get("product_id", 1))
    qty = int(d.get("quantity", 1))
    total = _CATALOG.get(pid, 0.0) * qty
    return _page("Order", f'<table><tr><td>Total</td><td>${total:.2f}</td></tr></table>')


@app.route("/withdraw", methods=["POST"])              # CWE-682 negative amount reverses the flow
def withdraw():
    d = request.get_json(silent=True) or request.form
    u = d.get("username", "guest")
    amt = float(d.get("amount", 0))
    bal = _bank.get(u, 1000.0) - amt
    _bank[u] = bal
    return _page("Wallet", f'<div>Account: {u}</div><div>Balance: <span id="balance">{bal:.2f}</span></div>')


@app.route("/account", methods=["POST"])               # CWE-915 binds every client field (incl role) -> HTML
def account():
    d = request.get_json(silent=True) or request.form
    u = d.get("username", "guest")
    prof = _profiles.get(u, {"username": u, "role": "user"})
    for k, v in d.items():
        if k != "password":
            prof[k] = v
    _profiles[u] = prof
    role = prof.get("role", "user")
    return _page("Account", f'<h1>Account</h1><p>Username: {u}</p>'
                            f'<input name="role" value="{role}"><p>Role: {role}</p>')


@app.route("/")
def index():
    return _page("htmlvuln", "<p>htmlvuln: /checkout /order /withdraw /account</p>")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
