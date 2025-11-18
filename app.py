import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import get_db, init_db
from datetime import datetime, timedelta

# -------------------------
# App setup
# -------------------------
app = Flask(__name__)
app.secret_key = "replace-this-with-a-secure-random-key"  # change in production

# ensure instance folder & initialize db
os.makedirs("instance", exist_ok=True)
init_db()

# Ensure is_blacklisted column exists in users table (safe on startup)
def ensure_blacklist_column(db_path="instance/hospital.db"):
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("ALTER TABLE users ADD COLUMN is_blacklisted INTEGER DEFAULT 0;")
        conn.commit()
    except sqlite3.OperationalError:
        # column probably already exists - ignore
        pass
    except Exception as e:
        # print for debug but don't crash the app
        print("Warning: could not ensure is_blacklisted column:", e)
    finally:
        try:
            conn.close()
        except:
            pass

ensure_blacklist_column()

# -------------------------
# Constants
# -------------------------
BLOCKS = {
    "morning": "08:00-12:00",
    "evening": "16:00-21:00"
}

MORNING_LABEL = "08:00 - 12:00 am"
EVENING_LABEL = "04:00 - 09:00 pm"
SLOT_CAPACITY = 50

# -------------------------
# Helpers
# -------------------------
def login_user(user_row):
    session['user_id'] = user_row['id']
    session['username'] = user_row['username']
    session['role'] = user_row['role']

def logout_user():
    session.clear()

def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def require_role(role):
    return session.get('role') == role

def normalize_label(label: str) -> str:
    if not label:
        return label
    s = label.replace("–", "-").replace("—", "-")
    s = " - ".join(part.strip() for part in s.split("-"))
    s = " ".join(s.split())
    return s

def token_to_label(token: str) -> str:
    if not token:
        return token
    t = token.lower().strip()
    if t == "morning":
        return MORNING_LABEL
    if t == "evening":
        return EVEN_LABEL if (globals().get("EVEN_LABEL")) else EVEN_LABEL  # fallback (won't happen)
    return normalize_label(token)

# -------------------------
# Cache control - prevent back button showing previous form values
# -------------------------
@app.after_request
def add_no_cache_headers(response):
    # Make pages non-cacheable and attempt to disable BFCache
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, proxy-revalidate, no-transform"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

# -------------------------
# Routes - auth & index
# -------------------------
@app.route("/")
def index():
    role = session.get('role')
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    if role == 'doctor':
        return redirect(url_for('doctor_dashboard'))
    if role == 'patient':
        return redirect(url_for('patient_dashboard'))
    # show_auth_buttons variable used by base.html to show login/register
    return render_template("home.html", show_auth_buttons=True)

@app.route("/admin/login")
def admin_login():
    return render_template("login.html", role="admin")

@app.route("/doctor/login")
def doctor_login():
    return render_template("login.html", role="doctor")

@app.route("/patient/login")
def patient_login():
    return render_template("login.html", role="patient")

@app.route("/login", methods=["GET","POST"])
@app.route("/login/<role>", methods=["GET", "POST"])
def login(role=None):
    # If no role specified, redirect to index
    if role is None:
        return redirect(url_for('index'))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        if not username or not password:
            flash("Please enter both username and password", "danger")
            return redirect(url_for('login', role=role))

        db = get_db()

        # 1️⃣ find user by username
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if not user:
            flash("User does not exist", "danger")
            return redirect(url_for('login', role=role))

        # 2️⃣ role match
        if user["role"] != role:
            flash("Invalid user role — please use the correct login portal", "danger")
            return redirect(url_for('login', role=role))

        # 3️⃣ blacklist check (Option A: blocked)
        try:
            if user.get("is_blacklisted") and int(user["is_blacklisted"]) == 1:
                flash("Your account is blacklisted. Contact admin.", "danger")
                return redirect(url_for('login', role=role))
        except Exception:
            # if column missing or unexpected, ignore silently (we ensured column exists)
            pass

        # 4️⃣ password check
        if not check_password_hash(user["password"], password):
            flash("Incorrect password", "danger")
            return redirect(url_for('login', role=role))

        # success
        login_user(user)
        flash("Logged in successfully!", "success")
        if role == "admin":
            return redirect(url_for("admin_dashboard"))
        if role == "doctor":
            return redirect(url_for("doctor_dashboard"))
        return redirect(url_for("patient_dashboard"))

    return render_template("login.html", role=role)

@app.route("/logout")
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for('index'))

# -------------------------
# Register
# -------------------------
@app.route("/register/<role>", methods=["GET", "POST"])
def register(role):
    if role not in ("admin", "patient"):
        flash("Only admin and patient registration allowed.", "danger")
        return redirect(url_for('index'))

    db = get_db()

    if request.method == "GET":
        return render_template("register.html", role=role)

    # handle POST
    fullname = (request.form.get('fullname') or "").strip()
    email = (request.form.get('email') or "").strip()
    username = (request.form.get('username') or "").strip()
    password = (request.form.get('password') or "").strip()
    phone = (request.form.get('phone') or "").strip()

    if not fullname:
        flash("Full Name is required", "danger")
        return redirect(url_for('register', role=role))

    if not username:
        flash("Username is required", "danger")
        return redirect(url_for('register', role=role))

    if not password or len(password) < 4:
        flash("Password is required and must be at least 4 characters", "danger")
        return redirect(url_for('register', role=role))

    # patient-specific checks
    if role == "patient":
        if not email:
            flash("Email is required for patient registration", "danger")
            return redirect(url_for('register', role=role))

        email_exists = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if email_exists:
            flash("Email already exists", "danger")
            return redirect(url_for('register', role=role))

        if phone and (not phone.isdigit() or len(phone) < 10):
            flash("Enter a valid phone number", "danger")
            return redirect(url_for('register', role=role))

    # check username uniqueness
    existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        flash("Username already exists", "danger")
        return redirect(url_for('register', role=role))

    try:
        pw_hash = generate_password_hash(password)
        cur = db.cursor()
        cur.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                    (username, pw_hash, email, role))
        user_id = cur.lastrowid

        if role == "patient":
            cur.execute("INSERT INTO patients (user_id, fullname, phone) VALUES (?, ?, ?)",
                        (user_id, fullname, phone))

        db.commit()
        flash("Registered successfully! Please login.", "success")
        return redirect(url_for("login", role=role))
    except Exception as e:
        db.rollback()
        print("REGISTER ERROR:", e)
        flash("Registration failed due to an internal error.", "danger")
        return redirect(url_for('register', role=role))

# -------------------------
# Admin routes
# -------------------------
@app.route("/admin/dashboard")
def admin_dashboard():
    if not require_role('admin'):
        return redirect(url_for('admin_login'))

    db = get_db()
    q = (request.args.get("q") or "").strip()

    # Base queries - include user_id and is_blacklisted for doctors/patients
    doctor_query = """
        SELECT d.id,
               d.fullname,
               d.user_id,
               dept.name AS department,
               COALESCE(u.is_blacklisted, 0) AS is_blacklisted
        FROM doctors d
        JOIN users u ON d.user_id = u.id
        LEFT JOIN departments dept ON d.department_id = dept.id
    """

    patient_query = """
        SELECT p.*,
               u.username,
               COALESCE(u.is_blacklisted, 0) AS is_blacklisted
        FROM patients p
        JOIN users u ON p.user_id = u.id
    """

    appointment_query = """
        SELECT a.*,
               p.fullname AS patient_name,
               d.fullname AS doctor_name,
               dept.name AS department,
               p.id AS patient_id
        FROM appointments a
        LEFT JOIN patients p ON a.patient_id = p.id
        LEFT JOIN doctors d ON a.doctor_id = d.id
        LEFT JOIN departments dept ON d.department_id = dept.id
        ORDER BY a.date DESC, a.time DESC
    """

    if q:
        # search across doctor name, department, patient name, username
        doctors = db.execute(doctor_query + " WHERE d.fullname LIKE ? OR dept.name LIKE ?",
                             (f"%{q}%", f"%{q}%")).fetchall()
        patients = db.execute(patient_query + " WHERE p.fullname LIKE ? OR u.username LIKE ?",
                              (f"%{q}%", f"%{q}%")).fetchall()
        appointments = db.execute("""
            SELECT a.*,
                   p.fullname AS patient_name,
                   d.fullname AS doctor_name,
                   dept.name AS department,
                   p.id AS patient_id
            FROM appointments a
            LEFT JOIN patients p ON a.patient_id = p.id
            LEFT JOIN doctors d ON a.doctor_id = d.id
            LEFT JOIN departments dept ON d.department_id = dept.id
            WHERE p.fullname LIKE ?
               OR d.fullname LIKE ?
               OR dept.name LIKE ?
            ORDER BY a.date DESC, a.time DESC
        """, (f"%{q}%", f"%{q}%", f"%{q}%")).fetchall()
    else:
        doctors = db.execute(doctor_query).fetchall()
        patients = db.execute(patient_query).fetchall()
        appointments = db.execute(appointment_query).fetchall()

    return render_template(
        "admin/admin_dashboard.html",
        doctors=doctors,
        patients=patients,
        appointments=appointments,
        total_doctors=len(doctors),
        total_patients=len(patients),
        total_appts=len(appointments),
        q=q
    )

@app.route("/admin/doctors/create", methods=["GET", "POST"])
def admin_create_doctor():
    if not require_role('admin'):
        return redirect(url_for('admin_login'))
    db = get_db()
    departments = db.execute("SELECT * FROM departments").fetchall()
    if request.method == "POST":
        fullname = request.form.get('fullname')
        department = request.form.get('department') or None
        experience = request.form.get('experience', 0)
        username = request.form.get('username')
        password = request.form.get('password') or "doctor123"
        if not fullname or not username:
            flash("Full name and username required", "danger")
            return redirect(url_for('admin_create_doctor'))
        try:
            cur = db.cursor()
            cur.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                        (username, generate_password_hash(password), f"{username}@hms.com", "doctor"))
            user_id = cur.lastrowid
            cur.execute("INSERT INTO doctors (user_id, fullname, department_id, experience) VALUES (?, ?, ?, ?)",
                        (user_id, fullname, department, experience))
            db.commit()
            flash("Doctor created successfully!", "success")
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.rollback()
            print("admin_create_doctor error:", e)
            flash("Error creating doctor. Username may exist.", "danger")
    return render_template("admin/admin_create_doctor.html", departments=departments)

@app.route("/admin/doctors/delete/<int:doctor_id>")
def admin_delete_doctor(doctor_id):
    if not require_role('admin'):
        return redirect(url_for('admin_login'))
    db = get_db()
    doc = db.execute("SELECT * FROM doctors WHERE id=?", (doctor_id,)).fetchone()
    if doc:
        db.execute("DELETE FROM doctors WHERE id=?", (doctor_id,))
        db.execute("DELETE FROM users WHERE id=?", (doc['user_id'],))
        db.commit()
        flash("Doctor removed", "info")
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/patient/<int:patient_id>/history")
def admin_view_patient_history(patient_id):
    if not require_role("admin"):
        return redirect(url_for("admin_login"))
    db = get_db()
    patient = db.execute("SELECT * FROM patients WHERE id=?", (patient_id,)).fetchone()
    if not patient:
        flash("Patient not found", "danger")
        return redirect(url_for("admin_dashboard"))
    history = db.execute("""
        SELECT a.date, a.time, a.status,
               d.fullname AS doctor_name,
               t.tests, t.diagnosis, t.prescription, t.notes
        FROM appointments a
        LEFT JOIN treatments t ON t.appointment_id = a.id
        LEFT JOIN doctors d ON a.doctor_id = d.id
        WHERE a.patient_id=?
        ORDER BY a.date DESC, a.time DESC
    """, (patient_id,)).fetchall()
    return render_template("admin/admin_patient_history.html", patient=patient, history=history)

@app.route("/admin/doctor/edit/<int:doctor_id>", methods=["GET", "POST"])
def admin_edit_doctor(doctor_id):
    if not require_role('admin'):
        return redirect(url_for('admin_login'))

    db = get_db()
    doctor = db.execute("""
        SELECT d.*, u.username, u.email, dept.id AS dept_id
        FROM doctors d
        JOIN users u ON d.user_id = u.id
        LEFT JOIN departments dept ON d.department_id = dept.id
        WHERE d.id=?
    """, (doctor_id,)).fetchone()

    if not doctor:
        flash("Doctor not found", "danger")
        return redirect(url_for('admin_dashboard'))

    departments = db.execute("SELECT * FROM departments").fetchall()

    if request.method == "POST":
        fullname = request.form.get("fullname")
        email = request.form.get("email")
        department_id = request.form.get("department")
        experience = request.form.get("experience")
        bio = request.form.get("bio")

        db.execute("""
            UPDATE doctors
            SET fullname=?, department_id=?, experience=?, bio=?
            WHERE id=?
        """, (fullname, department_id, experience, bio, doctor_id))

        db.execute("""
            UPDATE users
            SET email=?
            WHERE id=?
        """, (email, doctor["user_id"]))

        db.commit()
        flash("Doctor updated successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template("admin/admin_edit_doctor.html", doctor=doctor, departments=departments)

@app.route("/admin/patient/delete/<int:patient_id>")
def admin_delete_patient(patient_id):
    if not require_role('admin'):
        return redirect(url_for('admin_login'))
    db = get_db()
    patient = db.execute("SELECT * FROM patients WHERE id=?", (patient_id,)).fetchone()
    if not patient:
        flash("Patient not found", "danger")
        return redirect(url_for('admin_dashboard'))
    db.execute("DELETE FROM patients WHERE id=?", (patient_id,))
    db.execute("DELETE FROM users WHERE id=?", (patient['user_id'],))
    db.commit()
    flash("Patient deleted successfully!", "success")
    return redirect(url_for('admin_dashboard'))

# Blacklist toggle route
@app.route("/admin/blacklist/<int:user_id>")
def admin_toggle_blacklist(user_id):
    if not require_role('admin'):
        return redirect(url_for('admin_login'))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        flash("User not found", "danger")
        return redirect(url_for("admin_dashboard"))

    is_bl = user["is_blacklisted"] if "is_blacklisted" in user.keys() else 0
    new_value = 0 if is_bl else 1

    db.execute("UPDATE users SET is_blacklisted=? WHERE id=?", (new_value, user_id))
    db.commit()

    if new_value == 1:
        flash("User has been blacklisted", "warning")
    else:
        flash("User has been removed from blacklist", "success")

    return redirect(url_for("admin_dashboard"))

# -------------------------
# Doctor routes
# -------------------------
@app.route("/doctor/dashboard")
def doctor_dashboard():
    if not require_role('doctor'):
        return redirect(url_for('doctor_login'))
    db = get_db()
    user = current_user()
    if not user:
        return redirect(url_for('doctor_login'))
    doctor = db.execute("""
        SELECT d.*, dept.name AS department
        FROM doctors d
        LEFT JOIN departments dept ON d.department_id = dept.id
        WHERE d.user_id=?
    """, (user['id'],)).fetchone()
    if not doctor:
        flash("Doctor profile not found.", "danger")
        return redirect(url_for('index'))

    appts = db.execute("""
        SELECT a.*, p.fullname patient_name, p.id as patient_id
        FROM appointments a
        JOIN patients p ON a.patient_id=p.id
        WHERE a.doctor_id = ? AND a.status='Booked'
        ORDER BY date ASC, time ASC
    """, (doctor['id'],)).fetchall()

    availability = db.execute("SELECT * FROM availability WHERE doctor_id=? ORDER BY date ASC", (doctor['id'],)).fetchall()

    return render_template("doctor/doctor_dashboard.html", doctor=doctor, appointments=appts, availability=availability)

@app.route("/doctor/availability", methods=["GET", "POST"])
def doctor_availability():
    if not require_role('doctor'):
        return redirect(url_for('doctor_login'))
    db = get_db()
    user = current_user()
    doctor = db.execute("SELECT * FROM doctors WHERE user_id=?", (user['id'],)).fetchone()

    if request.method == "POST":
        date = request.form.get("date")
        blocks = request.form.getlist("blocks")
        if not date or not blocks:
            flash("Select date and at least one block", "danger")
            return redirect(url_for('doctor_availability'))

        blocks_str = ",".join(blocks)
        existing = db.execute("SELECT * FROM availability WHERE doctor_id=? AND date=?", (doctor['id'], date)).fetchone()
        if existing:
            db.execute("UPDATE availability SET slots=? WHERE id=?", (blocks_str, existing['id']))
        else:
            db.execute("INSERT INTO availability (doctor_id, date, slots) VALUES (?, ?, ?)", (doctor['id'], date, blocks_str))
        db.commit()
        flash("Availability saved", "success")
        return redirect(url_for('doctor_availability'))

    today = datetime.today().date()
    dates = [(today + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(0, 30)]

    existing_availability = db.execute("SELECT date, slots FROM availability WHERE doctor_id=? ORDER BY date ASC", (doctor['id'],)).fetchall()

    return render_template("doctor/doctor_schedule.html", doctor=doctor, dates=dates, existing_availability=existing_availability)

# -------------------------
# Slot generation helper
# -------------------------
def generate_half_hour_slots(start_time, end_time):
    fmt = "%H:%M"
    start = datetime.strptime(start_time, fmt)
    end = datetime.strptime(end_time, fmt)

    slots = []
    curr = start
    while curr < end:
        next_slot = curr + timedelta(minutes=30)
        label = f"{curr.strftime(fmt)} - {next_slot.strftime(fmt)}"
        slots.append(label)
        curr = next_slot
    return slots

# -------------------------
# Doctor appointment update routes
# -------------------------
@app.route("/doctor/appointment/<int:appointment_id>", methods=["GET","POST"])
def doctor_update_appointment(appointment_id):
    if not require_role('doctor'):
        return redirect(url_for('doctor_login'))
    db = get_db()
    user = current_user()
    doctor = db.execute("""
        SELECT d.*, dept.name AS department
        FROM doctors d
        LEFT JOIN departments dept ON d.department_id = dept.id
        WHERE d.user_id=?
    """, (user['id'],)).fetchone()
    appt = db.execute("""
        SELECT a.*, p.fullname patient_name
        FROM appointments a
        JOIN patients p ON a.patient_id=p.id
        WHERE a.id=?
    """, (appointment_id,)).fetchone()
    if not appt:
        flash("Appointment not found", "danger")
        return redirect(url_for('doctor_dashboard'))
    if request.method == "POST":
        diagnosis = request.form.get('diagnosis','')
        tests = request.form.get('tests','')
        prescription = request.form.get('prescription','')
        notes = request.form.get('notes','')
        cur = db.cursor()
        cur.execute("INSERT INTO treatments (appointment_id,diagnosis,tests,prescription,notes) VALUES (?,?,?,?,?)",
                    (appointment_id, diagnosis, tests, prescription, notes))
        cur.execute("UPDATE appointments SET status='Completed' WHERE id=?", (appointment_id,))
        db.commit()
        flash("Treatment saved and appointment marked completed","success")
        return redirect(url_for('doctor_dashboard'))
    treatments = db.execute("SELECT * FROM treatments WHERE appointment_id=?", (appointment_id,)).fetchall()
    return render_template("doctor/doctor_update_history.html", appointment=appt, treatments=treatments, doctor=doctor)

@app.route("/doctor/patient/<int:patient_id>")
def doctor_view_patient_history(patient_id):
    if not require_role('doctor'):
        return redirect(url_for('doctor_login'))
    db = get_db()
    user = current_user()
    doctor = db.execute("""
        SELECT d.*, dept.name AS department
        FROM doctors d
        LEFT JOIN departments dept ON d.department_id = dept.id
        WHERE d.user_id=?
    """, (user['id'],)).fetchone()
    patient = db.execute("SELECT * FROM patients WHERE id=?", (patient_id,)).fetchone()
    if not patient:
        flash("Patient not found", "danger")
        return redirect(url_for('doctor_dashboard'))
    history = db.execute("""
        SELECT a.id AS visit_no, a.date, a.time,
               t.tests, t.diagnosis, t.prescription, t.notes
        FROM appointments a
        LEFT JOIN treatments t ON t.appointment_id = a.id
        WHERE a.patient_id=?
        ORDER BY a.date ASC, a.time ASC
    """, (patient_id,)).fetchall()
    return render_template("doctor/doctor_patient_history.html", doctor=doctor, patient=patient, history=history)

@app.route("/doctor/appointment/complete/<int:appointment_id>")
def doctor_mark_complete(appointment_id):
    if not require_role('doctor'):
        return redirect(url_for('doctor_login'))
    db = get_db()
    appt = db.execute("SELECT * FROM appointments WHERE id=?", (appointment_id,)).fetchone()
    if not appt:
        flash("Appointment not found", "danger")
        return redirect(url_for('doctor_dashboard'))
    db.execute("UPDATE appointments SET status='Completed' WHERE id=?", (appointment_id,))
    db.commit()
    flash("Appointment marked as completed", "success")
    return redirect(url_for('doctor_dashboard'))

# -------------------------
# Patient routes
# -------------------------
@app.route("/patient/dashboard")
def patient_dashboard():
    if not require_role('patient'):
        return redirect(url_for('patient_login'))
    db = get_db()
    user = current_user()
    patient = db.execute("SELECT * FROM patients WHERE user_id=?", (user['id'],)).fetchone()
    appts = db.execute("""
        SELECT a.*, d.fullname doctor_name, dept.name dept
        FROM appointments a
        JOIN doctors d ON a.doctor_id=d.id
        LEFT JOIN departments dept ON d.department_id=dept.id
        WHERE a.patient_id=? AND a.status='Booked' ORDER BY a.date DESC, a.time DESC
    """, (patient['id'],)).fetchall()
    departments = db.execute("SELECT * FROM departments").fetchall()
    return render_template("patient/patient_dashboard.html", patient=patient, appointments=appts, departments=departments)

@app.route("/patient/doctors/<int:dept_id>")
def patient_doctors(dept_id):
    db = get_db()
    doctors = db.execute("SELECT d.*, dept.name as department FROM doctors d JOIN departments dept ON d.department_id=dept.id WHERE dept.id=?", (dept_id,)).fetchall()
    return render_template("patient/patient_doctor_list.html", doctors=doctors)
@app.route("/patient/profile/edit")
def patient_edit_profile():
    if not require_role('patient'):
        return redirect(url_for('patient_login'))

    db = get_db()
    user = current_user()
    patient = db.execute("SELECT * FROM patients WHERE user_id=?", (user['id'],)).fetchone()

    return render_template("patient/patient_edit_profile.html", user=user, patient=patient)

@app.route("/patient/profile/update", methods=["POST"])
def patient_update_profile():
    if not require_role('patient'):
        return redirect(url_for('patient_login'))

    db = get_db()
    user = current_user()

    fullname = request.form.get("fullname").strip()
    email = request.form.get("email").strip()
    phone = request.form.get("phone").strip()
    username = request.form.get("username").strip()
    password = request.form.get("password").strip()

    # validations
    if not fullname:
        flash("Full name is required", "danger")
        return redirect(url_for("patient_edit_profile"))

    if not email:
        flash("Email is required", "danger")
        return redirect(url_for("patient_edit_profile"))

    # Check email uniqueness
    email_exists = db.execute(
        "SELECT id FROM users WHERE email=? AND id!=?",
        (email, user["id"])
    ).fetchone()

    if email_exists:
        flash("Email already taken", "danger")
        return redirect(url_for("patient_edit_profile"))

    # Check username uniqueness
    username_exists = db.execute(
        "SELECT id FROM users WHERE username=? AND id!=?",
        (username, user["id"])
    ).fetchone()

    if username_exists:
        flash("Username already taken", "danger")
        return redirect(url_for("patient_edit_profile"))

    # Update users table
    if password:
        hashed = generate_password_hash(password)
        db.execute("""
            UPDATE users 
            SET username=?, email=?, password=?
            WHERE id=?
        """, (username, email, hashed, user['id']))
    else:
        db.execute("""
            UPDATE users 
            SET username=?, email=?
            WHERE id=?
        """, (username, email, user['id']))

    # Update patients table
    db.execute("""
        UPDATE patients
        SET fullname=?, phone=?
        WHERE user_id=?
    """, (fullname, phone, user['id']))

    db.commit()

    flash("Profile updated successfully!", "success")
    return redirect(url_for("patient_dashboard"))


@app.route("/patient/doctor/<int:doctor_id>")
def patient_doctor_profile(doctor_id):
    db = get_db()
    doctor = db.execute("SELECT d.*, dept.name as department FROM doctors d LEFT JOIN departments dept ON d.department_id=dept.id WHERE d.id=?", (doctor_id,)).fetchone()
    if not doctor:
        flash("Doctor not found", "danger")
        return redirect(url_for('patient_dashboard'))
    availability = db.execute("SELECT * FROM availability WHERE doctor_id=? ORDER BY date ASC LIMIT 7", (doctor_id,)).fetchall()
    return render_template("patient/patient_doctor_profile.html", doctor=doctor, availability=availability)

@app.route("/patient/doctor/<int:doctor_id>/availability")
def patient_doctor_availability(doctor_id):
    db = get_db()
    doctor = db.execute("""
        SELECT d.*, dept.name AS department
        FROM doctors d
        LEFT JOIN departments dept ON d.department_id = dept.id
        WHERE d.id=?
    """, (doctor_id,)).fetchone()

    today = datetime.today().date()
    seven_days_after = today + timedelta(days=7)

    availability_rows = db.execute("""
        SELECT * FROM availability
        WHERE doctor_id=? AND date BETWEEN ? AND ?
        ORDER BY date ASC
    """, (doctor_id, today.strftime("%Y-%m-%d"), seven_days_after.strftime("%Y-%m-%d"))).fetchall()

    availability_map = { row["date"]: row["slots"] for row in availability_rows }

    slot_map = {}
    for i in range(0, 7):
        date = (today + timedelta(days=i)).strftime("%Y-%m-%d")
        blocks = []
        if date in availability_map:
            blocks = (availability_map[date] or "").split(",")
        slot_map[date] = []
        if "morning" in blocks:
            slot_map[date] += generate_half_hour_slots("08:00", "12:00")
        if "evening" in blocks:
            slot_map[date] += generate_half_hour_slots("16:00", "21:00")

    booking_status = {}
    for date, slots in slot_map.items():
        for s in slots:
            booked = db.execute("""
                SELECT COUNT(*) c FROM appointments
                WHERE doctor_id=? AND date=? AND time=? AND status='Booked'
            """, (doctor_id, date, s)).fetchone()['c']
            booking_status[f"{date}|{s}"] = booked

    return render_template("patient/patient_doctor_availability.html",
                           doctor=doctor,
                           slot_map=slot_map,
                           booking_status=booking_status,
                           SLOT_CAPACITY=SLOT_CAPACITY)

@app.route("/patient/book", methods=["POST"])
def patient_book():
    if not require_role('patient'):
        return redirect(url_for('patient_login'))
    db = get_db()
    user = current_user()
    patient = db.execute("SELECT * FROM patients WHERE user_id=?", (user['id'],)).fetchone()
    if not patient:
        flash("Patient profile missing", "danger")
        return redirect(url_for('patient_dashboard'))

    doctor_id = request.form.get("doctor_id") or request.form.get("doctor") or request.args.get("doctor_id")
    slot_field = request.form.get("slot")
    date = request.form.get("date")
    block = request.form.get("block")

    if not doctor_id:
        flash("Missing doctor information", "danger")
        return redirect(url_for('patient_dashboard'))
    try:
        doctor_id = int(doctor_id)
    except Exception:
        flash("Invalid doctor information", "danger")
        return redirect(url_for('patient_dashboard'))

    time_label = None
    block_token = None
    if slot_field:
        if "|" in slot_field:
            date_part, time_label = slot_field.split("|", 1)
            date = date_part.strip()
            time_label = time_label.strip()
        else:
            flash("Invalid slot format", "danger")
            return redirect(url_for('patient_doctor_availability', doctor_id=doctor_id))
    else:
        if not date or not block:
            flash("Please select a slot before booking", "danger")
            return redirect(url_for('patient_doctor_availability', doctor_id=doctor_id))
        block_token = block

    if time_label:
        time_label = normalize_label(time_label)

    av = db.execute("SELECT * FROM availability WHERE doctor_id=? AND date=?", (doctor_id, date)).fetchone()
    if not av:
        flash("No availability for selected date", "danger")
        return redirect(url_for('patient_doctor_availability', doctor_id=doctor_id))

    slot_tokens = [s.strip() for s in (av['slots'] or "").split(",") if s.strip()]
    allowed_slots = []
    for t in slot_tokens:
        tl = t.lower()
        if tl == "morning":
            allowed_slots += generate_half_hour_slots("08:00", "12:00")
        elif tl == "evening":
            allowed_slots += generate_half_hour_slots("16:00", "21:00")
        else:
            allowed_slots.append(normalize_label(t))

    if time_label:
        if time_label not in allowed_slots:
            flash("Selected slot is not present in doctor's availability", "danger")
            return redirect(url_for('patient_doctor_availability', doctor_id=doctor_id))
    else:
        chosen_block = (block_token or "").lower()
        if chosen_block in ("morning", "evening"):
            if chosen_block == "morning":
                block_slots = generate_half_hour_slots("08:00", "12:00")
            else:
                block_slots = generate_half_hour_slots("16:00", "21:00")
            candidates = [s for s in block_slots if s in allowed_slots]
            if not candidates:
                flash("No available slots in the selected block", "danger")
                return redirect(url_for('patient_doctor_availability', doctor_id=doctor_id))
            time_label = candidates[0]
        else:
            if normalize_label(block_token) in allowed_slots:
                time_label = normalize_label(block_token)
            else:
                flash("Selected slot block is not available", "danger")
                return redirect(url_for('patient_doctor_availability', doctor_id=doctor_id))

    existing_count = db.execute("""
        SELECT COUNT(*) c FROM appointments
        WHERE doctor_id=? AND date=? AND time=? AND status='Booked'
    """, (doctor_id, date, time_label)).fetchone()['c']

    if existing_count >= SLOT_CAPACITY:
        flash(f"This slot is already full ({SLOT_CAPACITY} bookings).", "danger")
        return redirect(url_for('patient_doctor_availability', doctor_id=doctor_id))

    existing = db.execute("""
        SELECT * FROM appointments
        WHERE doctor_id=? AND date=? AND time=? AND patient_id=? AND status='Booked'
    """, (doctor_id, date, time_label, patient['id'])).fetchone()

    if existing:
        flash("You already have a booking at this slot", "info")
        return redirect(url_for('patient_dashboard'))

    db.execute("""
        INSERT INTO appointments (patient_id, doctor_id, date, time, status)
        VALUES (?, ?, ?, ?, 'Booked')
    """, (patient['id'], doctor_id, date, time_label))
    db.commit()

    flash("Appointment booked successfully!", "success")
    return redirect(url_for('patient_dashboard'))

@app.route("/patient/cancel/<int:appointment_id>")
def patient_cancel(appointment_id):
    if not require_role('patient'):
        return redirect(url_for('patient_login'))
    db = get_db()
    appt = db.execute("SELECT * FROM appointments WHERE id=?", (appointment_id,)).fetchone()
    if not appt:
        flash("Appointment not found", "danger")
        return redirect(url_for('patient_dashboard'))
    db.execute("UPDATE appointments SET status='Cancelled' WHERE id=?", (appointment_id,))
    db.commit()
    flash("Appointment cancelled", "info")
    return redirect(url_for('patient_dashboard'))

@app.route("/patient/history")
def patient_history():
    if not require_role('patient'):
        return redirect(url_for('patient_login'))
    db = get_db()
    user = current_user()
    patient = db.execute("SELECT * FROM patients WHERE user_id=?", (user['id'],)).fetchone()
    records = db.execute("""
        SELECT a.*, t.diagnosis, t.prescription, t.notes
        FROM appointments a
        LEFT JOIN treatments t ON t.appointment_id=a.id
        WHERE a.patient_id=?
        ORDER BY a.date DESC, a.time DESC
    """, (patient['id'],)).fetchall()
    return render_template("patient/patient_history.html", records=records)

# -------------------------
# Utility
# -------------------------
@app.route("/pages")
def pages():
    return render_template("pages_list.html")

# Debug route - remove in production
@app.route("/debug/my_appts")
def debug_my_appts():
    if not session.get('user_id'):
        return "NOT LOGGED IN"
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    if not user:
        return "NO USER FOUND"
    patient = db.execute("SELECT * FROM patients WHERE user_id=?", (user['id'],)).fetchone()
    if not patient:
        return "NO PATIENT FOUND"
    appts = db.execute("SELECT * FROM appointments WHERE patient_id=? ORDER BY id DESC", (patient['id'],)).fetchall()
    out = "<h2>DEBUG OUTPUT</h2><hr>"
    out += "<b>User:</b><br>" + str(dict(user)) + "<br><br>"
    out += "<b>Patient:</b><br>" + str(dict(patient)) + "<br><br>"
    out += "<b>Appointments:</b><br>"
    for a in appts:
        out += str(dict(a)) + "<br>"
    return out

if __name__ == "__main__":
    app.run(debug=True)
