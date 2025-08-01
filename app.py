import streamlit as st
import sqlite3
import hashlib
import re
from datetime import datetime

def init_db():
    conn = sqlite3.connect('users.db')
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

def validate_username(username):
    if not username or len(username.strip()) == 0:
        return False, "Username cannot be empty"
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    if len(username) > 30:
        return False, "Username cannot exceed 30 characters"
    if not re.search(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscore"
    if username.lower() in ['admin', 'root', 'administrator', 'system']:
        return False, "Username is reserved"
    return True, "Valid username"

def check_user_exists(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(?)', (username,))
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_password(password):
    if not password or len(password.strip()) == 0:
        return False, "Password cannot be empty"
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character (!@#$%^&*)"
    if len(password) > 50:
        return False, "Password cannot exceed 50 characters"
    return True, "Valid password"

def authenticate_user(username, password):
    if not username or not password:
        return None
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    hashed_password = hash_password(password)
    cursor.execute('SELECT id, username, role FROM users WHERE LOWER(username) = LOWER(?) AND password = ?',
                   (username.strip(), hashed_password))
    user = cursor.fetchone()
    conn.close()
    
    return user

def create_user(username, password, role):
    # Validate username
    username_valid, username_msg = validate_username(username)
    if not username_valid:
        return False, username_msg
    
    # Check if user already exists
    if check_user_exists(username):
        return False, "Username already exists (case-insensitive)"
    
    # Validate password
    password_valid, password_msg = validate_password(password)
    if not password_valid:
        return False, password_msg
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    try:
        hashed_password = hash_password(password)
        cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                       (username.strip(), hashed_password, role))
        conn.commit()
        return True, f"User '{username}' created successfully"
    except sqlite3.IntegrityError:
        return False, "Database error: Username might already exist"
    except Exception as e:
        return False, f"Error creating user: {str(e)}"
    finally:
        conn.close()

def get_all_users():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, username, role, created_at FROM users ORDER BY created_at DESC')
    users = cursor.fetchall()
    conn.close()
    
    return users

def delete_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM users WHERE id = ? AND role != "admin"', (user_id,))
    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()
    
    return rows_affected > 0

def change_password(username, old_password, new_password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    old_hashed = hash_password(old_password)
    cursor.execute('SELECT id FROM users WHERE username = ? AND password = ?',
                   (username, old_hashed))
    
    if cursor.fetchone():
        new_hashed = hash_password(new_password)
        cursor.execute('UPDATE users SET password = ? WHERE username = ?',
                       (new_hashed, username))
        conn.commit()
        conn.close()
        return True, "Password changed successfully"
    else:
        conn.close()
        return False, "Current password is incorrect"

def main():
    st.set_page_config(page_title="User Management System", layout="wide")
    
    init_db()
    
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.user_info = None
    
    if not st.session_state.logged_in:
        st.title("🔐 Login System")
        
        tab1, tab2 = st.tabs(["Login", "Register"])
        
        with tab1:
            st.subheader("Login")
            username = st.text_input("Username", key="login_username", help="Enter your username")
            password = st.text_input("Password", type="password", key="login_password", help="Enter your password")
            
            if st.button("Login", key="login_btn"):
                if not username or not password:
                    st.error("Please fill in all fields")
                elif username.strip() == "" or password.strip() == "":
                    st.error("Username and password cannot be empty")
                else:
                    user = authenticate_user(username, password)
                    if user:
                        st.session_state.logged_in = True
                        st.session_state.user_info = {
                            'id': user[0],
                            'username': user[1],
                            'role': user[2]
                        }
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        st.error("Invalid username or password. Please check your credentials.")
                        st.info("💡 Hint: Username is case-insensitive, but password is case-sensitive")
        
        with tab2:
            st.subheader("Register as Student")
            reg_username = st.text_input("Username", key="reg_username", help="3-30 characters, letters/numbers/underscore only")
            reg_password = st.text_input("Password", type="password", key="reg_password", 
                                       help="Min 8 chars, must include: letter, number, special character")
            reg_confirm = st.text_input("Confirm Password", type="password", key="reg_confirm")
            
            # Show password requirements
            with st.expander("Password Requirements"):
                st.write("• At least 8 characters long")
                st.write("• Contains at least one letter (a-z, A-Z)")
                st.write("• Contains at least one number (0-9)")
                st.write("• Contains at least one special character (!@#$%^&*)")
                st.write("• Maximum 50 characters")
            
            if st.button("Register", key="register_btn"):
                if not reg_username or not reg_password or not reg_confirm:
                    st.error("Please fill in all fields")
                elif reg_username.strip() == "" or reg_password.strip() == "":
                    st.error("Username and password cannot be empty or just spaces")
                elif reg_password != reg_confirm:
                    st.error("Passwords do not match")
                else:
                    success, message = create_user(reg_username, reg_password, 'student')
                    if success:
                        st.success(message + " You can now login.")
                    else:
                        st.error(message)
    
    else:
        user_info = st.session_state.user_info
        
        st.title(f"Welcome, {user_info['username']}!")
        st.subheader(f"Role: {user_info['role'].title()}")
        
        col1, col2, col3 = st.columns([1, 1, 1])
        
        with col1:
            if st.button("Change Password"):
                st.session_state.show_change_password = True
        
        with col2:
            if user_info['role'] == 'admin':
                if st.button("User Management"):
                    st.session_state.show_user_management = True
        
        with col3:
            if st.button("Logout"):
                st.session_state.logged_in = False
                st.session_state.user_info = None
                if 'show_change_password' in st.session_state:
                    del st.session_state.show_change_password
                if 'show_user_management' in st.session_state:
                    del st.session_state.show_user_management
                st.rerun()
        
        if user_info['role'] == 'student':
            st.write("---")
            st.info("🎓 Student Dashboard")
            st.write("Welcome to your student portal! You have successfully logged in.")
            st.write("This is your personal space where you can view your information.")
        
        if 'show_change_password' in st.session_state and st.session_state.show_change_password:
            st.write("---")
            st.subheader("Change Password")
            
            old_pass = st.text_input("Current Password", type="password", key="old_pass")
            new_pass = st.text_input("New Password", type="password", key="new_pass",
                                   help="Min 8 chars, must include: letter, number, special character")
            confirm_pass = st.text_input("Confirm New Password", type="password", key="confirm_pass")
            
            # Show password requirements
            with st.expander("Password Requirements"):
                st.write("• At least 8 characters long")
                st.write("• Contains at least one letter (a-z, A-Z)")
                st.write("• Contains at least one number (0-9)")
                st.write("• Contains at least one special character (!@#$%^&*)")
                st.write("• Maximum 50 characters")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Update Password"):
                    if not old_pass or not new_pass or not confirm_pass:
                        st.error("Please fill in all fields")
                    elif old_pass.strip() == "" or new_pass.strip() == "" or confirm_pass.strip() == "":
                        st.error("Passwords cannot be empty or just spaces")
                    elif new_pass != confirm_pass:
                        st.error("New passwords do not match")
                    else:
                        is_valid, msg = validate_password(new_pass)
                        if not is_valid:
                            st.error(msg)
                        else:
                            success, message = change_password(user_info['username'], old_pass, new_pass)
                            if success:
                                st.success(message)
                                del st.session_state.show_change_password
                                st.rerun()
                            else:
                                st.error(message)
            
            with col2:
                if st.button("Cancel"):
                    del st.session_state.show_change_password
                    st.rerun()
        
        if user_info['role'] == 'admin' and 'show_user_management' in st.session_state and st.session_state.show_user_management:
            st.write("---")
            st.subheader("👥 Admin Dashboard - User Management")
            
            tab1, tab2, tab3 = st.tabs(["View Users", "Create User", "Delete User"])
            
            with tab1:
                st.write("**All Users:**")
                users = get_all_users()
                if users:
                    for user in users:
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.write(f"**ID:** {user[0]}")
                        with col2:
                            st.write(f"**Username:** {user[1]}")
                        with col3:
                            st.write(f"**Role:** {user[2]}")
                        with col4:
                            st.write(f"**Created:** {user[3][:16]}")
                        st.write("---")
                else:
                    st.info("No users found")
            
            with tab2:
                st.write("**Create New User:**")
                new_username = st.text_input("Username", key="new_user_username", 
                                            help="3-30 characters, letters/numbers/underscore only")
                new_password = st.text_input("Password", type="password", key="new_user_password",
                                           help="Min 8 chars, must include: letter, number, special character")
                new_role = st.selectbox("Role", ["student", "admin"], key="new_user_role")
                
                # Show password requirements for admin
                with st.expander("Password Requirements"):
                    st.write("• At least 8 characters long")
                    st.write("• Contains at least one letter (a-z, A-Z)")
                    st.write("• Contains at least one number (0-9)")
                    st.write("• Contains at least one special character (!@#$%^&*)")
                    st.write("• Maximum 50 characters")
                
                if st.button("Create User", key="create_user_btn"):
                    if not new_username or not new_password:
                        st.error("Please fill in all fields")
                    elif new_username.strip() == "" or new_password.strip() == "":
                        st.error("Username and password cannot be empty or just spaces")
                    else:
                        success, message = create_user(new_username, new_password, new_role)
                        if success:
                            st.success(message)
                        else:
                            st.error(message)
            
            with tab3:
                st.write("**Delete User:**")
                users = get_all_users()
                deletable_users = [user for user in users if user[2] != 'admin']
                
                if deletable_users:
                    user_options = {f"{user[1]} (ID: {user[0]})": user[0] for user in deletable_users}
                    selected_user = st.selectbox("Select user to delete:", list(user_options.keys()))
                    
                    if st.button("Delete User", key="delete_user_btn", type="secondary"):
                        user_id = user_options[selected_user]
                        if delete_user(user_id):
                            st.success("User deleted successfully")
                            st.rerun()
                        else:
                            st.error("Failed to delete user")
                else:
                    st.info("No users available for deletion (admin users cannot be deleted)")
            
            if st.button("Back to Dashboard"):
                del st.session_state.show_user_management
                st.rerun()

if __name__ == "__main__":
    main()
