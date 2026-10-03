from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error, IntegrityError
import os
import hashlib
import csv
import io
import secrets
from datetime import datetime

load_dotenv()

BASE = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {
    "txt", "log", "csv", "json", "xml", "html", "pdf", "doc", "docx",
    "jpg", "jpeg", "png", "gif", "zip", "7z", "rar", "img", "dd",
    "raw", "e01", "aff4", "pcap", "pcapng", "evtx", "sqlite", "db",
    "bin", "dat", "ab", "tar", "gz"
}


def db():
    return mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "127.0.0.1"),
        port=int(os.getenv("MYSQL_PORT", "3306")),
        user=os.getenv("MYSQL_USER", "root"),
        password=os.getenv("MYSQL_PASSWORD", ""),
        database=os.getenv("MYSQL_DATABASE", "forensiq"),
        autocommit=False,
    )


def fetch_one(sql, params=()):
    conn = db()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(sql, params)
        return cur.fetchone()
    finally:
        cur.close(); conn.close()


def fetch_all(sql, params=()):
    conn = db()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(sql, params)
        return cur.fetchall()
    finally:
        cur.close(); conn.close()


def execute(sql, params=(), commit=True):
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(sql, params)
        result = cur.lastrowid
        if commit:
            conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close(); conn.close()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_activity(action, entity_type, entity_id=None, details=""):
    try:
        execute(
            """INSERT INTO audit_logs(user_id, action, entity_type, entity_id, details, created_at)
               VALUES(%s,%s,%s,%s,%s,%s)""",
            (session.get("user_id"), action, entity_type, entity_id, details, now())
        )
    except Exception:
        pass


def login_required():
    return "user_id" in session


def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not login_required():
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def hash_file(file_storage):
    sha = hashlib.sha256()
    file_storage.stream.seek(0)
    while True:
        chunk = file_storage.stream.read(1024 * 1024)
        if not chunk:
            break
        sha.update(chunk)
    file_storage.stream.seek(0)
    return sha.hexdigest()


def ai_analyze(text, category=""):
    t = (text or "").lower()
    indicators = []
    rules = [
        ("credential", "Credential-access indicator"),
        ("password", "Credential-related artifact"),
        ("mimikatz", "Credential dumping indicator"),
        ("powershell", "PowerShell execution indicator"),
        ("encoded", "Encoded content indicator"),
        ("suspicious", "Suspicious artifact marker"),
        ("tor", "Anonymity-network indicator"),
        ("ransom", "Ransomware-related keyword"),
        ("malware", "Malware-related keyword"),
        ("exfil", "Potential data-exfiltration indicator"),
        ("bitcoin", "Cryptocurrency-related indicator"),
        ("keylog", "Keylogging-related indicator"),
        ("powershell", "PowerShell execution indicator"),
        ("remote desktop", "Remote-access indicator"),
    ]
    for word, label in rules:
        if word in t and label not in indicators:
            indicators.append(label)
    if len(indicators) >= 3:
        risk = "Critical"
    elif len(indicators) == 2:
        risk = "High"
    elif len(indicators) == 1:
        risk = "Medium"
    elif any(x in t for x in ["download", "external", "usb", "remote", "login"]):
        risk = "Low"
    else:
        risk = "Low"
    if indicators:
        summary = "AI-assisted triage detected: " + ", ".join(indicators[:4]) + ". Manual forensic validation is recommended."
    else:
        summary = "AI-assisted triage found no immediate keyword indicators. Continue artifact correlation and timeline review."
    return risk, summary, indicators


def init_db():
    conn = db()
    cur = conn.cursor()
    try:
        with open(os.path.join(BASE, "schema.sql"), "r", encoding="utf-8") as f:
            statements = [s.strip() for s in f.read().split(";") if s.strip()]
        for statement in statements:
            cur.execute(statement)
        conn.commit()

        cur.execute("SELECT id FROM users LIMIT 1")
        if not cur.fetchone():
            cur.execute(
                """INSERT INTO users(name,email,password,role,created_at)
                   VALUES(%s,%s,%s,%s,%s)""",
                ("Demo Investigator", "admin@forensiq.local", generate_password_hash("admin123"), "Lead Investigator", now())
            )

        cur.execute("SELECT id FROM cases LIMIT 1")
        if not cur.fetchone():
            demo_cases = [
                ("CASE-2026-001", "Operation Silent Trace", "Suspected unauthorized access and data exfiltration from an enterprise workstation.", "Active", "High", "Demo Investigator"),
                ("CASE-2026-002", "Project Blackout", "Digital evidence collection from a compromised mobile device.", "Under Review", "Medium", "Demo Investigator"),
                ("CASE-2026-003", "Insider Access Review", "Audit of removable media and endpoint activity.", "Closed", "Low", "Demo Investigator"),
            ]
            cur.executemany(
                """INSERT INTO cases(case_number,title,description,status,priority,investigator,created_at)
                   VALUES(%s,%s,%s,%s,%s,%s,%s)""",
                [(a,b,c,d,e,f,now()) for a,b,c,d,e,f in demo_cases]
            )
            cur.execute("SELECT id FROM cases WHERE case_number=%s", ("CASE-2026-001",)); case1 = cur.fetchone()[0]
            cur.execute("SELECT id FROM cases WHERE case_number=%s", ("CASE-2026-002",)); case2 = cur.fetchone()[0]
            samples = [
                (case1,"EV-001","Windows Disk Image","Disk Image","Corporate workstation","Forensic image acquired for timeline and artifact analysis.","workstation.E01","a8b4e9c2f6c44a1f7d8b3c4e9f7a2d11","Verified","High","Potential credential-access artifacts and unusual execution timestamps detected."),
                (case1,"EV-002","Browser History Export","Browser Artifact","Chrome profile","Export containing visited URLs, downloads and session metadata.","browser_history.json","c2f7a2c2c84dbb8c92c04d5a7c9d31aa","Verified","Medium","Multiple suspicious domains and repeated downloads require review."),
                (case2,"EV-003","Mobile Device Backup","Mobile","Seized smartphone","Logical backup collected under documented procedure.","device_backup.ab","f31d8c7e5a9b42c6e1f04d8a7b3c9210","Verified","Low","No immediate high-risk indicators found in the initial rule scan."),
            ]
            cur.executemany(
                """INSERT INTO evidence(case_id,evidence_code,name,category,source,description,file_name,file_hash,integrity,ai_risk,ai_summary,created_at,collected_at)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                [(*e, now(), now()) for e in samples]
            )
            cur.execute("SELECT id FROM evidence WHERE evidence_code=%s", ("EV-001",)); ev1 = cur.fetchone()[0]
            cur.execute("SELECT id FROM evidence WHERE evidence_code=%s", ("EV-002",)); ev2 = cur.fetchone()[0]
            custody = [
                (ev1,"Collected","Field Team","Digital Lab","Lab Intake","Initial acquisition and hash verification."),
                (ev1,"Transferred","Digital Lab","Lead Investigator","Evidence Vault","Sealed transfer; package intact."),
                (ev2,"Collected","Field Team","Digital Lab","Lab Intake","Browser artifact export collected."),
            ]
            cur.executemany(
                """INSERT INTO custody(evidence_id,action,from_person,to_person,location,notes,timestamp)
                   VALUES(%s,%s,%s,%s,%s,%s,%s)""",
                [(*x, now()) for x in custody]
            )
        conn.commit()
    finally:
        cur.close(); conn.close()


@app.route("/")
def index():
    return redirect(url_for("dashboard")) if login_required() else render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    user = fetch_one("SELECT * FROM users WHERE email=%s", (email,))
    if user and check_password_hash(user["password"], password):
        session.update(user_id=user["id"], user_name=user["name"], role=user["role"])
        log_activity("LOGIN", "USER", user["id"], "Successful login")
        return redirect(url_for("dashboard"))
    flash("Invalid email or password. Demo: admin@forensiq.local / admin123", "error")
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    if login_required(): log_activity("LOGOUT", "USER", session.get("user_id"), "User signed out")
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@require_login
def dashboard():
    stats = {
        "cases": fetch_one("SELECT COUNT(*) c FROM cases")["c"],
        "evidence": fetch_one("SELECT COUNT(*) c FROM evidence")["c"],
        "high": fetch_one("SELECT COUNT(*) c FROM evidence WHERE ai_risk IN ('High','Critical')")["c"],
        "custody": fetch_one("SELECT COUNT(*) c FROM custody")["c"],
    }
    recent = fetch_all("""SELECT e.*,c.case_number,c.title FROM evidence e JOIN cases c ON c.id=e.case_id ORDER BY e.id DESC LIMIT 6""")
    cases = fetch_all("SELECT * FROM cases ORDER BY id DESC LIMIT 5")
    activities = fetch_all("""SELECT a.*,u.name user_name FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 8""")
    return render_template("dashboard.html", stats=stats, recent=recent, cases=cases, activities=activities)


@app.route("/cases")
@require_login
def cases():
    q = request.args.get("q", "").strip()
    rows = fetch_all("SELECT * FROM cases WHERE case_number LIKE %s OR title LIKE %s ORDER BY id DESC", (f"%{q}%", f"%{q}%")) if q else fetch_all("SELECT * FROM cases ORDER BY id DESC")
    return render_template("cases.html", cases=rows, q=q)


@app.route("/cases/new", methods=["POST"])
@require_login
def new_case():
    data = request.form
    try:
        cid = execute("""INSERT INTO cases(case_number,title,description,status,priority,investigator,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s)""", (data["case_number"],data["title"],data.get("description",""),"Active",data.get("priority","Medium"),session.get("user_name"),now()))
        log_activity("CREATE", "CASE", cid, data["case_number"])
        flash("Case created successfully.", "success")
    except IntegrityError:
        flash("Case number already exists.", "error")
    return redirect(url_for("cases"))


@app.route("/evidence")
@require_login
def evidence():
    q = request.args.get("q", "").strip(); risk = request.args.get("risk", "")
    sql = """SELECT e.*,c.case_number,c.title FROM evidence e JOIN cases c ON c.id=e.case_id WHERE 1=1"""
    params = []
    if q:
        sql += " AND (e.evidence_code LIKE %s OR e.name LIKE %s OR e.category LIKE %s OR c.case_number LIKE %s)"
        params += [f"%{q}%"] * 4
    if risk:
        sql += " AND e.ai_risk=%s"; params.append(risk)
    sql += " ORDER BY e.id DESC"
    rows = fetch_all(sql, tuple(params)); case_rows = fetch_all("SELECT id,case_number,title FROM cases ORDER BY id DESC")
    return render_template("evidence.html", evidence=rows, cases=case_rows, q=q, risk=risk)


@app.route("/evidence/new", methods=["POST"])
@require_login
def new_evidence():
    data = request.form; uploaded = request.files.get("evidence_file")
    name = data.get("name", "").strip(); category = data.get("category", "Other"); source = data.get("source", "")
    description = data.get("description", ""); content = " ".join([name, category, description, source])
    risk, summary, _ = ai_analyze(content, category)
    file_name = data.get("file_name", ""); storage_name = ""; file_size = 0; mime_type = ""
    file_hash = ""
    if uploaded and uploaded.filename:
        if not allowed_file(uploaded.filename):
            flash("File type is not allowed.", "error"); return redirect(url_for("evidence"))
        file_name = secure_filename(uploaded.filename)
        file_hash = hash_file(uploaded)
        storage_name = f"{file_hash[:16]}_{file_name}"
        path = os.path.join(app.config["UPLOAD_FOLDER"], storage_name)
        uploaded.save(path)
        file_size = os.path.getsize(path); mime_type = uploaded.mimetype or "application/octet-stream"
    else:
        file_hash = hashlib.sha256((file_name + "|" + content).encode()).hexdigest()
    try:
        eid = execute("""INSERT INTO evidence(case_id,evidence_code,name,category,source,description,file_name,storage_name,file_hash,file_size,mime_type,integrity,ai_risk,ai_summary,created_at,collected_at)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", (data["case_id"],data["evidence_code"],name,category,source,description,file_name,storage_name,file_hash,file_size,mime_type,"Verified",risk,summary,now(),data.get("collected_at") or now()))
        execute("""INSERT INTO custody(evidence_id,action,from_person,to_person,location,notes,timestamp) VALUES(%s,%s,%s,%s,%s,%s,%s)""", (eid,"Collected",session.get("user_name"),"Evidence Vault","Digital Intake","Initial evidence registration.",now()))
        log_activity("CREATE", "EVIDENCE", eid, data["evidence_code"])
        flash(f"Evidence registered. AI triage: {risk}.", "success")
    except IntegrityError:
        flash("Evidence code already exists.", "error")
    return redirect(url_for("evidence"))


@app.route("/evidence/<int:eid>")
@require_login
def evidence_detail(eid):
    e = fetch_one("SELECT e.*,c.case_number,c.title FROM evidence e JOIN cases c ON c.id=e.case_id WHERE e.id=%s", (eid,))
    custody = fetch_all("SELECT * FROM custody WHERE evidence_id=%s ORDER BY id DESC", (eid,))
    if not e: return "Evidence not found", 404
    return render_template("evidence_detail.html", e=e, custody=custody)


@app.route("/evidence/<int:eid>/download")
@require_login
def download_evidence(eid):
    e = fetch_one("SELECT file_name,storage_name FROM evidence WHERE id=%s", (eid,))
    if not e or not e["storage_name"]: return "File not available", 404
    log_activity("DOWNLOAD", "EVIDENCE", eid, e["file_name"])
    return send_from_directory(app.config["UPLOAD_FOLDER"], e["storage_name"], as_attachment=True, download_name=e["file_name"])


@app.route("/evidence/<int:eid>/verify", methods=["POST"])
@require_login
def verify_evidence(eid):
    e = fetch_one("SELECT * FROM evidence WHERE id=%s", (eid,))
    if not e: return jsonify({"error":"Not found"}), 404
    if not e["storage_name"]:
        return jsonify({"status":"Verified","message":"Metadata-only evidence record; stored fingerprint remains the reference value."})
    path = os.path.join(app.config["UPLOAD_FOLDER"], e["storage_name"])
    if not os.path.exists(path):
        execute("UPDATE evidence SET integrity='Missing' WHERE id=%s", (eid,))
        return jsonify({"status":"Missing","message":"Stored evidence file could not be found."})
    with open(path, "rb") as f:
        current = hashlib.sha256(f.read()).hexdigest()
    status = "Verified" if current == e["file_hash"] else "Mismatch"
    execute("UPDATE evidence SET integrity=%s WHERE id=%s", (status, eid))
    log_activity("VERIFY", "EVIDENCE", eid, status)
    return jsonify({"status":status,"current_hash":current,"stored_hash":e["file_hash"]})


@app.route("/evidence/<int:eid>/analyze", methods=["POST"])
@require_login
def analyze(eid):
    e = fetch_one("SELECT * FROM evidence WHERE id=%s", (eid,))
    if not e: return jsonify({"error":"Not found"}), 404
    text = " ".join([e["name"] or "",e["category"] or "",e["source"] or "",e["description"] or "",e["file_name"] or ""])
    risk, summary, indicators = ai_analyze(text)
    execute("UPDATE evidence SET ai_risk=%s,ai_summary=%s WHERE id=%s", (risk,summary,eid))
    log_activity("AI_ANALYSIS", "EVIDENCE", eid, risk)
    return jsonify({"risk":risk,"summary":summary,"indicators":indicators})


@app.route("/evidence/<int:eid>/custody", methods=["POST"])
@require_login
def add_custody(eid):
    d = request.form
    execute("""INSERT INTO custody(evidence_id,action,from_person,to_person,location,notes,timestamp) VALUES(%s,%s,%s,%s,%s,%s,%s)""", (eid,d["action"],d.get("from_person",""),d.get("to_person",""),d.get("location",""),d.get("notes",""),now()))
    log_activity("CUSTODY", "EVIDENCE", eid, d["action"])
    flash("Chain-of-custody event recorded.", "success")
    return redirect(url_for("evidence_detail", eid=eid))


@app.route("/reports")
@require_login
def reports():
    cases = fetch_all("SELECT * FROM cases ORDER BY id DESC")
    return render_template("reports.html", cases=cases)


@app.route("/reports/export")
@require_login
def export_report():
    rows = fetch_all("""SELECT e.evidence_code,e.name,e.category,e.file_hash,e.integrity,e.ai_risk,e.ai_summary,c.case_number,c.title FROM evidence e JOIN cases c ON c.id=e.case_id ORDER BY e.id""")
    out = io.StringIO(); writer = csv.writer(out)
    writer.writerow(["Evidence Code","Name","Category","SHA-256 Hash","Integrity","AI Risk","AI Summary","Case Number","Case Title"])
    for r in rows: writer.writerow([r[k] for k in r.keys()])
    log_activity("EXPORT", "REPORT", None, "Evidence CSV report")
    return out.getvalue(), 200, {"Content-Type":"text/csv", "Content-Disposition":"attachment; filename=forensiq_evidence_report.csv"}


@app.route("/api/stats")
@require_login
def api_stats():
    data = fetch_all("SELECT ai_risk,COUNT(*) n FROM evidence GROUP BY ai_risk")
    return jsonify({r["ai_risk"]: r["n"] for r in data})


@app.errorhandler(413)
def too_large(_):
    flash("Evidence file is too large. Maximum size is 50 MB.", "error")
    return redirect(url_for("evidence"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
