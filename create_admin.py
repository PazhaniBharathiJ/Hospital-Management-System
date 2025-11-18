import sqlite3
from werkzeug.security import generate_password_hash

db = "instance/hospital.db"
conn = sqlite3.connect(db)
cur = conn.cursor()

username = "admin"
password = generate_password_hash("admin123")
email = "admin@hospital.com"

cur.execute(
    "INSERT INTO users (username, password, email, role, is_blacklisted) VALUES (?, ?, ?, ?, 0)",
    (username, password, email, "admin")
)

conn.commit()
conn.close()

print("Default admin created successfully!")
