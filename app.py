import os
import sqlite3
import re
import logging
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# Load environment variables from .env file (create one in your project root)
load_dotenv()

# ---------- Configuration via Environment Variables ----------
app = Flask(__name__)
# Secret key (set a strong random value in your .env file)
app.secret_key = os.getenv("SECRET_KEY", "default_very_secret_key_change_me")

# Database location and other settings
DATABASE = os.getenv("DATABASE", os.path.join("database", "users.db"))
RATE_LIMITS = os.getenv("RATE_LIMITS", "200 per day,50 per hour")

# Set up logging
logger = logging.getLogger("BlazeCoinApp")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
file_handler = logging.FileHandler("app.log")
file_handler.setFormatter(formatter)
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# Setup rate limiting
# e.g. REDIS_URL = "redis://:password@hostname:6379/0"
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.getenv("RATELIMIT_STORAGE_URL", "redis://localhost:6379/0"),
    default_limits=os.getenv("RATE_LIMITS").split(",")
)

# ---------- Input Validation Functions ----------
def is_valid_username(username):
    # Allow 3-30 alphanumeric characters or underscores.
    return bool(re.match(r'^\w{3,30}$', username))

def is_valid_password(password):
    return len(password) >= 8

# ---------- Database Helper Functions ----------
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
      CREATE TABLE IF NOT EXISTS users (
          username TEXT PRIMARY KEY,
          password TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    ''')
    conn.commit()
    conn.close()

# ---------- Routes ----------
@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for('wallet'))
    return redirect(url_for('login'))

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        if not username or not password:
            return render_template("register.html", message="Please fill in all fields.")
        if not is_valid_username(username):
            return render_template("register.html", message="Username must be 3-30 characters, alphanumeric or underscores only.")
        if not is_valid_password(password):
            return render_template("register.html", message="Password must be at least 8 characters long.")
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user:
            conn.close()
            return render_template("register.html", message="Username already exists. Please choose another.")
        password_hash = generate_password_hash(password)
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        conn.close()
        logger.info(f"Registered new user: {username}")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            logger.info(f"User {username} logged in.")
            return redirect(url_for("wallet"))
        else:
            logger.warning(f"Failed login attempt for {username}")
            return render_template("login.html", message="Invalid username or password.")
    return render_template("login.html")

@app.route("/wallet")
def wallet():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("wallet.html", username=session["username"])

@app.route("/auth_miner", methods=["POST"])
@limiter.limit("20 per minute")
def auth_miner():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"status": "fail", "message": "Invalid request"}), 400
    username = data["username"].strip()
    password = data["password"].strip()
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if user and check_password_hash(user["password"], password):
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "fail", "message": "Invalid credentials"}), 401







from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash
)
import os

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# … your existing imports, database functions, login_required decorator, etc. …

@app.route("/wallet")
def wallet():
    if "username" not in session:
        flash("You must be logged in to view your wallet", "warning")
        return redirect(url_for("login"))
    # you can look up any existing on‐chain data here if you like
    return render_template("wallet-interface.html")



# ---------- Additional Security Headers ----------
@app.after_request
def apply_security_headers(response):
    # Example headers – adjust as needed.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline';"
    return response

if __name__ == "__main__":
    os.makedirs("database", exist_ok=True)
    init_db()
    logger.info("Starting BlazeCoin app...")
    # For production, remove debug=True and serve behind a reverse proxy for SSL/TLS.
    app.run(host="0.0.0.0", port=5000, debug=True)
