import streamlit as st
import sqlite3
import hashlib
from datetime import datetime

class UserManager:
    def __init__(self):
        self.db_name = 'users.db'
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_name)
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
        
        admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
        cursor.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
                       ('admin', admin_password, 'admin'))
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def validate_password(self, password):
        if len(password) < 6:
            return False, "Password too short (min 6 chars)"
        return True, "Valid"
    
    def authenticate(self, username, password):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        hashed = self.hash_password(password)
        cursor.execute('SELECT id, username, role FROM users WHERE username = ? AND password = ?',
                       (username, hashed))
        user = cursor.fetchone()
        conn.close()
        
        return user
    
    def create_user(self, username, password, role):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            hashed = self.hash_password(password)
            cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                           (username, hashed, role))
            conn.commit()
            return True, "User created"
        except sqlite3.IntegrityError:
            return False, "Username exists"
        finally:
            conn.close()
    
    def get_users(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, username, role, created_at FROM users ORDER BY created_at DESC')
        users = cursor.fetchall()
        conn.close()
        
        return users
    
    def delete_user(self, user_id):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM users WHERE id = ? AND role != "admin"', (user_id,))
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return success

def main():
    st.set_page_config(page_title="Auth System", layout="wide")
    
    um = UserManager()
    
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.user = None
    
    if not st.session_state.logged_in:
        st.title("🔐 Authentication")
        
        tab1, tab2 = st.tabs(["Login", "Register"])
        
        with tab1:
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            
            if st.button("Login"):
                if username and password:
                    user = um.authenticate(username, password)
                    if user:
                        st.session_state.logged_in = True
                        st.session_state.user = {'id': user[0], 'username': user[1], 'role': user[2]}
                        st.success("Logged in!")
                        st.rerun()
                    else:
                        st.error("Invalid credentials")
                else:
                    st.error("Fill all fields")
        
        with tab2:
            reg_username = st.text_input("New Username")
            reg_password = st.text_input("New Password", type="password")
            
            if st.button("Register"):
                if reg_username and reg_password:
                    valid, msg = um.validate_password(reg_password)
                    if not valid:
                        st.error(msg)
                    else:
                        success, message = um.create_user(reg_username, reg_password, 'student')
                        if success:
                            st.success(message)
                        else:
                            st.error(message)
                else:
                    st.error("Fill all fields")
    
    else:
        user = st.session_state.user
        
        col1, col2 = st.columns([3, 1])
        with col1:
            st.title(f"Welcome {user['username']} ({user['role']})")
        with col2:
            if st.button("Logout"):
                st.session_state.logged_in = False
                st.session_state.user = None
                st.rerun()
        
        if user['role'] == 'student':
            st.info("🎓 Student Portal - You're logged in successfully!")
        
        elif user['role'] == 'admin':
            st.success("👑 Admin Dashboard")
            
            tab1, tab2, tab3 = st.tabs(["Users", "Create", "Delete"])
            
            with tab1:
                users = um.get_users()
                for user_data in users:
                    st.write(f"ID: {user_data[0]} | {user_data[1]} | {user_data[2]} | {user_data[3][:16]}")
            
            with tab2:
                new_user = st.text_input("Username", key="new")
                new_pass = st.text_input("Password", type="password", key="newpass")
                new_role = st.selectbox("Role", ["student", "admin"])
                
                if st.button("Create"):
                    if new_user and new_pass:
                        valid, msg = um.validate_password(new_pass)
                        if valid:
                            success, message = um.create_user(new_user, new_pass, new_role)
                            st.success(message) if success else st.error(message)
                        else:
                            st.error(msg)
                    else:
                        st.error("Fill all fields")
            
            with tab3:
                users = um.get_users()
                deletable = [u for u in users if u[2] != 'admin']
                
                if deletable:
                    options = {f"{u[1]} (ID: {u[0]})": u[0] for u in deletable}
                    selected = st.selectbox("Select user:", list(options.keys()))
                    
                    if st.button("Delete"):
                        if um.delete_user(options[selected]):
                            st.success("Deleted")
                            st.rerun()
                        else:
                            st.error("Failed")
                else:
                    st.info("No deletable users")

if __name__ == "__main__":
    main()
