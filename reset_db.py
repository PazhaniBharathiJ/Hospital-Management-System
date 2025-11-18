import sqlite3

conn = sqlite3.connect("instance/hospital.db")
cur = conn.cursor()

print("\n---- Clearing All Tables ----")

try:
    cur.execute("DELETE FROM appointments;")
    cur.execute("DELETE FROM patients;")
    cur.execute("DELETE FROM doctors;")
    cur.execute("DELETE FROM availability;")
    cur.execute("DELETE FROM treatments;")
    cur.execute("DELETE FROM departments;")
    
    # CLEAR USERS COMPLETELY
    cur.execute("DELETE FROM users;")

    conn.commit()
    print("All data cleared successfully!")
except Exception as e:
    print("Error:", e)

conn.close()
