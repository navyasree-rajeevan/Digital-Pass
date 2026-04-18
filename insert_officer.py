import sqlite3, hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

conn = sqlite3.connect("database.db")
cur = conn.cursor()

# Insert one Officer
cur.execute("INSERT OR IGNORE INTO officers (name,email,password) VALUES (?,?,?)",
            ("Officer One", "officer@example.com", hash_password("officer123")))


conn.commit()
conn.close()
print("✅ Sample Officer inserted! Email: officer@example.com | Password: officer123")
