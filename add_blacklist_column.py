import sqlite3

conn = sqlite3.connect("instance/hospital.db")
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE users ADD COLUMN is_blacklisted INTEGER DEFAULT 0;")
    print("Column 'is_blacklisted' added successfully!")
except Exception as e:
    print("Error:", e)

conn.commit()
conn.close()
