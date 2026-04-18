import sqlite3, hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

conn = sqlite3.connect("database.db")
cur = conn.cursor()

# Insert one Admin
cur.execute("INSERT OR IGNORE INTO admins (name,email,password) VALUES (?,?,?)",
            ("Super Admin", "admin@example.com", hash_password("admin123")))
# Insert one Agency
cur.execute("INSERT OR IGNORE INTO agencies (name,email,password) VALUES (?,?,?)",
            ("Agency One", "agency@example.com", hash_password("agency123")))


conn.commit()
conn.close()
print("✅ Sample Admin and Agency inserted!")
