
from flask import Flask, render_template, request, redirect, session, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secret"

DATABASE = "database.db"

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, first_name TEXT, last_name TEXT, username TEXT UNIQUE, password TEXT)")
    conn.commit()
    conn.close()

init_db()

@app.route("/", methods=["GET","POST"])
def login():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        if not username or not password:
            msg = "Enter username and password"
            return render_template("login.html", message=msg)
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username=?", (username,))
        user = c.fetchone()
        if user and check_password_hash(user[0], password):
            session["user"] = username
            return redirect("/dashboard")
        msg = "Invalid username or password. If new user, please sign up."
    return render_template("login.html", message=msg)

@app.route("/signup", methods=["GET","POST"])
def signup():
    msg = ""
    if request.method == "POST":
        first = request.form.get("first","").strip()
        last = request.form.get("last","").strip()
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        confirm = request.form.get("confirm","").strip()
        if not (first and last and username and password and confirm):
            msg = "All fields are required"
            return render_template("signup.html", message=msg)
        if password != confirm:
            msg = "Passwords do not match"
            return render_template("signup.html", message=msg)
        hashed = generate_password_hash(password)
        conn = get_db()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users(first_name,last_name,username,password) VALUES(?,?,?,?)", (first, last, username, hashed))
            conn.commit()
            return redirect("/")
        except Exception:
            msg = "Username already exists"
    return render_template("signup.html", message=msg)

@app.route("/forgot", methods=["GET","POST"])
def forgot():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        confirm = request.form.get("confirm","").strip()
        if not (username and password and confirm):
            msg = "All fields are required"
            return render_template("forgot.html", message=msg)
        if password != confirm:
            msg = "Passwords do not match"
            return render_template("forgot.html", message=msg)
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=?", (username,))
        user = c.fetchone()
        if not user:
            msg = "Username not found"
            return render_template("forgot.html", message=msg)
        hashed = generate_password_hash(password)
        c.execute("UPDATE users SET password=? WHERE username=?", (hashed, username))
        conn.commit()
        msg = "Password updated. You can login now."
        return render_template("forgot.html", message=msg)
    return render_template("forgot.html", message=msg)

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    username = session["user"]
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT first_name, last_name FROM users WHERE username=?", (username,))
    row = c.fetchone()
    name = username
    if row:
        name = f"{row[0]} {row[1]}"
    return render_template("dashboard.html", name=name)

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
