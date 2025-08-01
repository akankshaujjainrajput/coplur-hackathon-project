# Coplur Code Challenge: Role-Based Authentication Web Application

A Django web application that supports user authentication, role-based access control, and admin operations, built for the Coplur Code Challenge.

## Tech Stack Used
- Python
- Django
- SQLite

## Features Implemented

### Authentication
- User registration (students only) with strong validation and edge case handling
- Login / Logout with enhanced error messaging
- Change Password (secure, with password strength requirements)
- Welcome Page after login showing user info and role

### Role Management
- Role-based access for "Admin" and "Student" roles
- Admin-only dashboard for user management
- Protected admin routes using custom decorators

### Admin User Management
- Initial admin user created via data seeding (`username: admin`)
- Admin dashboard with statistics
- Admin can create, delete, and view all users
- Admin can assign roles when creating new users
- Admin cannot delete their own account or last admin

### Edge Case Handling
- Prevent duplicate users during registration (username/email, case-insensitive)
- Strong password policy: minimum 8 characters, upper/lowercase, digit, special char
- Handles empty fields, malformed inputs, forbidden usernames, and invalid emails
- CSRF protection and session security
- Comprehensive error handling and custom error pages (403, 404, 500)
- Logs important events and errors for audit and debugging

### Security
- All authentication and management routes are protected and validated
- Unauthorized access is blocked and redirected with proper messaging
- Session and cookie security features enabled

## Project Setup Instructions

1. **Clone the repository:**
   ```
   git clone https://github.com/akankshaujjainrajput/coplur-hackathon-project.git
   cd coplur-hackathon-project
   ```

2. **Install dependencies:**
   ```
   pip install django
   ```

3. **Run database migrations (includes admin seeding):**
   ```
   python manage.py migrate
   ```

4. **Start the development server:**
   ```
   python manage.py runserver
   ```

5. **Access the site:**
   - Login: `http://127.0.0.1:8000/accounts/login/`
   - Admin Dashboard: `http://127.0.0.1:8000/accounts/admin_dashboard/`

## Admin Credentials

- **Username:** admin
- **Password:** [Password you set in step 3] 

## API & Routing Overview

- `/accounts/login/` - User Login
- `/accounts/register/` - Student Registration
- `/accounts/welcome/` - Welcome Page
- `/accounts/password_change/` - Change Password
- `/accounts/admin_dashboard/` - Admin Dashboard
- `/accounts/admin/create_user/` - Admin Create User
- `/accounts/admin/list_users/` - Admin List Users
- `/accounts/admin/delete_user/<user_id>/` - Admin Delete User (confirmation)
- Custom error handlers for 403, 404, 500

## Edge Case Handling

- Duplicate username/email prevention
- Strong password enforcement
- Forbidden usernames and email domains
- All form fields validated (server-side)
- Meaningful error and success messages
- Admin self-protection for deletion
- Secure session/cookie setup

## Team Member Contributions

- **Shivansh7102003:** Backend (authentication, admin management, validation), frontend templates, documentation
- **Akanksha:** Frontend UI design, testing, project board management, code review
- **Suresh Sharma** Implemented streamlit
## Project Board / Task Breakdown

- See GitHub Projects tab or Trello board for breakdown and progress.

## Important Notes

- Change the default admin password after first login for security.
- For production, set `DEBUG = False` and configure allowed hosts and session security.
- All features have been validated for edge cases and security.
- The codebase is original, well-commented, and follows good commit practices.

