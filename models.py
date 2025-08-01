import hashlib
import sqlite3
import re

class ValidationError(Exception):
    pass

class DatabaseManager:
    def __init__(self, db_path='users.db'):
        self.db_path = db_path
        self.setup()
    
    def setup(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'student',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            admin_hash = hashlib.sha256('admin123'.encode()).hexdigest()
            cursor.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
                          ('admin', admin_hash, 'admin'))
            conn.commit()

class AuthService:
    def __init__(self, db_manager):
        self.db = db_manager
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def validate_password(self, password):
        if len(password) < 6:
            raise ValidationError("Password must be at least 6 characters")
        if not re.search(r'[0-9]', password):
            raise ValidationError("Password must contain at least one number")
        return True
    
    def authenticate(self, username, password):
        with sqlite3.connect(self.db.db_path) as conn:
            cursor = conn.cursor()
            hashed = self.hash_password(password)
            cursor.execute('SELECT id, username, role FROM users WHERE username = ? AND password = ?',
                          (username, hashed))
            return cursor.fetchone()
    
    def register_user(self, username, password, role='student'):
        if not username or not password:
            raise ValidationError("Username and password required")
        
        self.validate_password(password)
        
        with sqlite3.connect(self.db.db_path) as conn:
            cursor = conn.cursor()
            try:
                hashed = self.hash_password(password)
                cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                              (username, hashed, role))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                raise ValidationError("Username already exists")

class UserService:
    def __init__(self, db_manager):
        self.db = db_manager
    
    def get_all_users(self):
        with sqlite3.connect(self.db.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, role, created_at FROM users ORDER BY created_at DESC')
            return cursor.fetchall()
    
    def delete_user(self, user_id):
        with sqlite3.connect(self.db.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM users WHERE id = ? AND role != "admin"', (user_id,))
            return cursor.rowcount > 0
