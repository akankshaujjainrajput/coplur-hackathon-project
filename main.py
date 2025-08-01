import streamlit as st
from models import DatabaseManager, AuthService, UserService, ValidationError

class SessionManager:
    @staticmethod
    def init_session():
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
            st.session_state.user_data = None
    
    @staticmethod
    def login_user(user_data):
        st.session_state.authenticated = True
        st.session_state.user_data = user_data
    
    @staticmethod
    def logout_user():
        st.session_state.authenticated = False
        st.session_state.user_data = None
    
    @staticmethod
    def is_authenticated():
        return st.session_state.get('authenticated', False)
    
    @staticmethod
    def get_user():
        return st.session_state.get('user_data')

def render_login_page(auth_service):
    st.title("🔐 Login Portal")
    
    tab1, tab2 = st.tabs(["Sign In", "Sign Up"])
    
    with tab1:
        st.subheader("Login")
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")
        
        if st.button("Sign In"):
            if username and password:
                user = auth_service.authenticate(username, password)
                if user:
                    SessionManager.login_user({
                        'id': user[0],
                        'username': user[1], 
                        'role': user[2]
                    })
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid credentials")
            else:
                st.error("Please enter username and password")
    
    with tab2:
        st.subheader("Register (Students Only)")
        reg_user = st.text_input("Choose Username", key="reg_user")
        reg_pass = st.text_input("Choose Password", type="password", key="reg_pass")
        reg_confirm = st.text_input("Confirm Password", type="password", key="reg_confirm")
        
        if st.button("Register"):
            if reg_user and reg_pass and reg_confirm:
                if reg_pass != reg_confirm:
                    st.error("Passwords don't match")
                else:
                    try:
                        auth_service.register_user(reg_user, reg_pass, 'student')
                        st.success("Registration successful! You can now login.")
                    except ValidationError as e:
                        st.error(str(e))
            else:
                st.error("Please fill all fields")

def render_student_dashboard():
    user = SessionManager.get_user()
    st.title(f"Welcome, {user['username']}! 🎓")
    
    st.info("### Student Portal")
    st.write("You have successfully logged into the student portal.")
    st.write("This is your personal dashboard where you can:")
    st.write("- View your profile")
    st.write("- Access course materials")
    st.write("- Check announcements")

def render_admin_dashboard(auth_service, user_service):
    user = SessionManager.get_user()
    st.title(f"Admin Panel - {user['username']} 👑")
    
    tab1, tab2, tab3 = st.tabs(["View Users", "Create User", "Manage Users"])
    
    with tab1:
        st.subheader("All Registered Users")
        users = user_service.get_all_users()
        
        if users:
            for user_data in users:
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.text(f"ID: {user_data[0]}")
                with col2:
                    st.text(f"User: {user_data[1]}")
                with col3:
                    st.text(f"Role: {user_data[2]}")
                with col4:
                    st.text(f"Created: {user_data[3][:10]}")
        else:
            st.info("No users found")
    
    with tab2:
        st.subheader("Create New User")
        new_username = st.text_input("Username", key="admin_new_user")
        new_password = st.text_input("Password", type="password", key="admin_new_pass")
        new_role = st.selectbox("Role", ["student", "admin"], key="admin_new_role")
        
        if st.button("Create User"):
            if new_username and new_password:
                try:
                    auth_service.register_user(new_username, new_password, new_role)
                    st.success(f"User '{new_username}' created successfully!")
                except ValidationError as e:
                    st.error(str(e))
            else:
                st.error("Please fill all fields")
    
    with tab3:
        st.subheader("Delete Users")
        users = user_service.get_all_users()
        non_admin_users = [u for u in users if u[2] != 'admin']
        
        if non_admin_users:
            user_options = {f"{u[1]} (ID: {u[0]}, Role: {u[2]})": u[0] for u in non_admin_users}
            selected_user = st.selectbox("Select user to delete:", list(user_options.keys()))
            
            if st.button("Delete User", type="secondary"):
                user_id = user_options[selected_user]
                if user_service.delete_user(user_id):
                    st.success("User deleted successfully!")
                    st.rerun()
                else:
                    st.error("Failed to delete user")
        else:
            st.info("No users available for deletion")

def main():
    st.set_page_config(page_title="Role-Based Auth System", layout="wide")
    
    db_manager = DatabaseManager()
    auth_service = AuthService(db_manager)
    user_service = UserService(db_manager)
    
    SessionManager.init_session()
    
    if not SessionManager.is_authenticated():
        render_login_page(auth_service)
    else:
        user = SessionManager.get_user()
        
        col1, col2 = st.columns([4, 1])
        with col2:
            if st.button("Logout"):
                SessionManager.logout_user()
                st.rerun()
        
        if user['role'] == 'student':
            render_student_dashboard()
        elif user['role'] == 'admin':
            render_admin_dashboard(auth_service, user_service)
        else:
            st.error("Invalid user role")

if __name__ == "__main__":
    main()
