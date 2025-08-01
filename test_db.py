import sqlite3
import hashlib

def test_auth():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    
    print("Users in database:")
    for user in users:
        print(f"ID: {user[0]}, Username: {user[1]}, Role: {user[3]}")
    
    test_password = hashlib.sha256('admin123'.encode()).hexdigest()
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', ('admin', test_password))
    admin = cursor.fetchone()
    
    if admin:
        print("\nAdmin authentication: SUCCESS")
    else:
        print("\nAdmin authentication: FAILED")
    
    conn.close()

if __name__ == "__main__":
    test_auth()
