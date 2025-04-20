import os
import sqlite3
from hashlib import sha256
from flask import Flask, request, render_template, redirect, flash, jsonify

# ——— App setup ———
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change_this_in_prod")

DATABASE = os.path.join(os.path.dirname(__file__), "users.db")

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL
        )""")

@app.before_first_request
def initialize():
    init_db()

# ——— Routes ———

@app.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        u = request.form["username"].strip()
        p = request.form["password"].strip()
        if not u or not p:
            flash("Username and password required.", "error")
        else:
            h = sha256(p.encode()).hexdigest()
            try:
                with get_db() as db:
                    db.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (u, h)
                    )
                flash("Account created! You can now run the miner.", "success")
                return redirect("/register")
            except sqlite3.IntegrityError:
                flash("That username is already taken.", "error")
    return render_template("register.html")


@app.route("/auth_miner", methods=["POST"])
def auth_miner():
    data = request.get_json(force=True)
    u = data.get("username", "").strip()
    p = data.get("password", "").strip()
    if not u or not p:
        return jsonify({"success": False, "message": "Missing credentials"}), 400

    h = sha256(p.encode()).hexdigest()
    row = get_db().execute(
        "SELECT 1 FROM users WHERE username=? AND password_hash=?",
        (u, h)
    ).fetchone()
    if row:
        return jsonify({"success": True, "message": "Auth OK"})
    else:
        return jsonify({"success": False, "message": "Invalid username or password"}), 401


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
