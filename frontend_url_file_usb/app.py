from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
import time
import requests
import psutil

app = Flask(__name__)
app.secret_key = "supersecretkey"

DB_NAME = "database.db"
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ============ VirusTotal ============
API_KEY = "d3d2d054231251b3cc12f0abb47543ea9b809adaba4cbe831dc0bf93109275e7"
VT_URL_SCAN = "https://www.virustotal.com/vtapi/v2/url/report"
VT_FILE_SCAN = "https://www.virustotal.com/vtapi/v2/file/report"
VT_FILE_UPLOAD = "https://www.virustotal.com/vtapi/v2/file/scan"

# ============ DB INIT ============
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ============ SAFE VT REQUEST ============
def safe_vt_request(url, params=None, files=None):
    try:
        if files:
            resp = requests.post(url, params=params, files=files, timeout=30)
        else:
            resp = requests.get(url, params=params, timeout=30)

        print("VT STATUS:", resp.status_code)
        print("VT RAW:", resp.text[:200])  # debug

        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}"}

        if not resp.text.strip():
            return {"error": "Empty response from VirusTotal"}

        return resp.json()

    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
    except ValueError:
        return {"error": "Invalid JSON from VirusTotal"}

# ============ HOME ============
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/about", methods=["GET", "POST"])
def about():
    return render_template("about.html")




# ============ SIGNUP ============
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                (name, email, password)
            )
            conn.commit()
            conn.close()
            flash("Signup successful! Please login.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Email already exists!")

    return render_template("signup.html")

# ============ LOGIN ============
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute(
            "SELECT * FROM users WHERE email=? AND password=?",
            (email, password)
        )
        user = c.fetchone()
        conn.close()

        if user:
            session["user_id"] = user[0]
            session["user_name"] = user[1]
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password!")

    return render_template("login.html")

# ============ LOGOUT ============
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ============ URL SCAN ============
def check_url_safety(url):
    params = {'apikey': API_KEY, 'resource': url}
    result = safe_vt_request(VT_URL_SCAN, params=params)

    if "error" in result:
        return f"⚠️ VirusTotal Error: {result['error']}"

    positives = result.get("positives", 0)
    total = result.get("total", "?")

    if positives > 0:
        return f"❌ UNSAFE — {positives}/{total} engines detected this URL"
    else:
        return f"✅ SAFE — 0/{total} detections"

# ============ FILE SCAN ============
def check_file_safety(file_path):
    params = {'apikey': API_KEY}
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}

    upload_result = safe_vt_request(VT_FILE_UPLOAD, params=params, files=files)

    if "error" in upload_result:
        return f"⚠️ Upload Error: {upload_result['error']}"

    resource = upload_result.get("resource")
    if not resource:
        return "⚠️ VirusTotal did not return a resource ID."

    for _ in range(10):
        time.sleep(10)
        report = safe_vt_request(
            VT_FILE_SCAN,
            params={'apikey': API_KEY, 'resource': resource}
        )

        if "error" in report:
            continue

        if report.get("response_code") == 1:
            positives = report.get("positives", 0)
            total = report.get("total", "?")

            if positives > 0:
                return f"❌ UNSAFE — {positives}/{total} engines detected this file"
            else:
                return f"✅ SAFE — 0/{total} detections"

    return "⏳ Scan timed out. Try again later."

# ============ USB SCAN ============
def check_usb_for_viruses():
    results = []
    for partition in psutil.disk_partitions():
        if 'removable' in partition.opts or 'cdrom' in partition.opts:
            try:
                files = os.listdir(partition.mountpoint)
                for f in files:
                    if f.lower() == "autorun.inf" or f.endswith(".lnk") or f.endswith(".exe"):
                        results.append(f"⚠️ Suspicious file: {f} in {partition.device}")
            except Exception as e:
                results.append(f"Error scanning {partition.device}: {e}")

    if not results:
        results.append("✅ No suspicious USB files found.")

    return results

# ============ DASHBOARD (3 INPUTS) ============
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    url_result = None
    file_result = None
    usb_results = []

    if request.method == "POST":

        if "scan_url" in request.form:
            url = request.form.get("url")
            if url:
                url_result = check_url_safety(url)

        if "scan_file" in request.form:
            file = request.files.get("file")
            if file and file.filename:
                filepath = os.path.join(UPLOAD_FOLDER, file.filename)
                file.save(filepath)
                file_result = check_file_safety(filepath)

        if "scan_usb" in request.form:
            usb_results = check_usb_for_viruses()

    return render_template(
        "dashboard.html",
        name=session["user_name"],
        url_result=url_result,
        file_result=file_result,
        usb_results=usb_results
    )

# ============ RUN ============
if __name__ == "__main__":
    app.run(debug=True)
