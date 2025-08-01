import sqlite3
import hashlib

def setup_database():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('DROP TABLE IF EXISTS users')
    
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
    cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                   ('admin', admin_password, 'admin'))
    
    test_password = hashlib.sha256('test123'.encode()).hexdigest()
    cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                   ('student1', test_password, 'student'))
    
    conn.commit()
    conn.close()
    print("Database setup complete!")

if __name__ == "__main__":
    setup_database()
