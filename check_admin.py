import sqlite3

conn = sqlite3.connect("database.db")
cur = conn.cursor()

cur.execute("SELECT * FROM admins")
rows = cur.fetchall()

if rows:
    print("✅ Admins found in DB:")
    for r in rows:
        print(r)
else:
    print("⚠️ No admin accounts in DB")

conn.close()
