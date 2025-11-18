import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = "instance/hospital.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Create folders/tables
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        role TEXT CHECK(role IN ('admin','doctor','patient')) NOT NULL
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS patients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE,
        fullname TEXT,
        age INTEGER,
        gender TEXT,
        phone TEXT,
        address TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS departments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        description TEXT
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS doctors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE,
        fullname TEXT,
        department_id INTEGER,
        experience INTEGER DEFAULT 0,
        bio TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(department_id) REFERENCES departments(id)
    )""")

    # availability: doctor_id, date (YYYY-MM-DD), slots (comma separated)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS availability (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        doctor_id INTEGER,
        date TEXT,
        slots TEXT,
        FOREIGN KEY(doctor_id) REFERENCES doctors(id)
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS appointments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER,
        doctor_id INTEGER,
        date TEXT,
        time TEXT,
        status TEXT CHECK(status IN ('Booked','Completed','Cancelled')) DEFAULT 'Booked',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(patient_id) REFERENCES patients(id),
        FOREIGN KEY(doctor_id) REFERENCES doctors(id)
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS treatments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        appointment_id INTEGER,
        diagnosis TEXT,
        tests TEXT,
        prescription TEXT,
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(appointment_id) REFERENCES appointments(id)
    )""")

    # Insert a default admin if not exists
    cur.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
    if not cur.fetchone():
        admin_pw = generate_password_hash("admin123")
        cur.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                    ("admin", admin_pw, "admin@hms.local", "admin"))
    # Insert sample departments if empty
    cur.execute("SELECT id FROM departments LIMIT 1")
    if not cur.fetchone():
        sample_depts = [
            ("Cardiology","Heart related treatments"),
            ("Oncology","Cancer diagnosis and treatment"),
            ("General","General physician")
        ]
        cur.executemany("INSERT INTO departments (name, description) VALUES (?,?)", sample_depts)

    conn.commit()
    conn.close()
