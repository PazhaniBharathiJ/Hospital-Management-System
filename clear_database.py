import sqlite3

conn = sqlite3.connect("instance/hospital.db")
cur = conn.cursor()

tables = [
    "appointments",
    "patients",
    "doctors",
    "availability",
    "treatments",
    "departments"
]

for table in tables:
    try:
        cur.execute(f"DELETE FROM {table};")
        print(f"Cleared table: {table}")
    except Exception as e:
        print(f"Error clearing {table}: {e}")

# Clear users EXCEPT admin (optional)
cur.execute("DELETE FROM users WHERE role!='admin';")

conn.commit()
conn.close()

print("All test data cleared successfully!")
import sqlite3

conn = sqlite3.connect("instance/hospital.db")
cur = conn.cursor()

tables = [
    "appointments",
    "patients",
    "doctors",
    "availability",
    "treatments",
    "departments"
]

for table in tables:
    try:
        cur.execute(f"DELETE FROM {table};")
        print(f"Cleared table: {table}")
    except Exception as e:
        print(f"Error clearing {table}: {e}")

# Clear users EXCEPT admin (optional)
cur.execute("DELETE FROM users WHERE role!='admin';")

conn.commit()
conn.close()

print("All test data cleared successfully!")
