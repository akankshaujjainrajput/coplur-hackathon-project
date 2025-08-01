import streamlit as st
import sqlite3
import hashlib
import json
from datetime import datetime

class SecureAuth:
    def __init__(self):
        self.db = 'auth.db'
        self.setup()
    
    def setup(self):
        conn = sqlite3.connect(self.db)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY, username TEXT UNIQUE, 
                     password TEXT, role TEXT, created TIMESTAMP)''')
        
        admin_hash = hashlib.sha256('admin123'.encode()).hexdigest()
        c.execute('INSERT OR IGNORE INTO users VALUES (1, ?, ?, ?, ?)', 
                 ('admin', admin_hash, 'admin', datetime.now()))
        conn.commit()
        conn.close()
    
    def auth(self, user, pwd):
        conn = sqlite3.connect(self.db)
        c = conn.cursor()
        hash_pwd = hashlib.sha256(pwd.encode()).hexdigest()
        c.execute('SELECT * FROM users WHERE username=? AND password=?', (user, hash_pwd))
        result = c.fetchone()
        conn.close()
        return result
    
    def register(self, user, pwd, role='student'):
        if len(pwd) < 6:
            return False, "Password too short"
        
        conn = sqlite3.connect(self.db)
        c = conn.cursor()
        try:
            hash_pwd = hashlib.sha256(pwd.encode()).hexdigest()
            c.execute('INSERT INTO users (username, password, role, created) VALUES (?, ?, ?, ?)', 
                     (user, hash_pwd, role, datetime.now()))
            conn.commit()
            return True, "Success"
        except:
            return False, "User exists"
        finally:
            conn.close()
    
    def get_users(self):
        conn = sqlite3.connect(self.db)
        c = conn.cursor()
        c.execute('SELECT id, username, role, created FROM users')
        users = c.fetchall()
        conn.close()
        return users
    
    def delete(self, uid):
        conn = sqlite3.connect(self.db)
        c = conn.cursor()
        c.execute('DELETE FROM users WHERE id=? AND role!="admin"', (uid,))
        success = c.rowcount > 0
        conn.commit()
        conn.close()
        return success

def main():
    st.set_page_config(page_title="Auth System")
    auth = SecureAuth()
    
    if 'logged' not in st.session_state:
        st.session_state.logged = False
        st.session_state.user = None
    
    if not st.session_state.logged:
        st.title("🔒 Login")
        
        tab1, tab2 = st.tabs(["Login", "Register"])
        
        with tab1:
            u = st.text_input("User")
            p = st.text_input("Pass", type="password")
            
            if st.button("Login"):
                result = auth.auth(u, p)
                if result:
                    st.session_state.logged = True
                    st.session_state.user = {'id': result[0], 'name': result[1], 'role': result[3]}
                    st.rerun()
                else:
                    st.error("Invalid")
        
        with tab2:
            nu = st.text_input("New User")
            np = st.text_input("New Pass", type="password")
            
            if st.button("Register"):
                ok, msg = auth.register(nu, np)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)
    
    else:
        user = st.session_state.user
        
        col1, col2 = st.columns([3, 1])
        with col1:
            st.title(f"Hi {user['name']} ({user['role']})")
        with col2:
            if st.button("Logout"):
                st.session_state.logged = False
                st.rerun()
        
        if user['role'] == 'student':
            st.success("🎓 Student Area")
            st.write("Welcome to student portal!")
        
        elif user['role'] == 'admin':
            st.success("👑 Admin Panel")
            
            tab1, tab2, tab3 = st.tabs(["Users", "Add", "Remove"])
            
            with tab1:
                users = auth.get_users()
                for u in users:
                    st.write(f"{u[0]} | {u[1]} | {u[2]} | {str(u[3])[:16]}")
            
            with tab2:
                new_u = st.text_input("Username")
                new_p = st.text_input("Password", type="password")
                new_r = st.selectbox("Role", ["student", "admin"])
                
                if st.button("Add User"):
                    ok, msg = auth.register(new_u, new_p, new_r)
                    st.success(msg) if ok else st.error(msg)
            
            with tab3:
                users = auth.get_users()
                del_users = [u for u in users if u[2] != 'admin']
                
                if del_users:
                    opts = {f"{u[1]} ({u[0]})": u[0] for u in del_users}
                    sel = st.selectbox("Delete:", list(opts.keys()))
                    
                    if st.button("Delete"):
                        if auth.delete(opts[sel]):
                            st.success("Deleted")
                            st.rerun()
                else:
                    st.info("No users to delete")

if __name__ == "__main__":
    main()
