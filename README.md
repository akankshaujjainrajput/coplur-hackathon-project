# Role-Based Authentication Web Application

Quick role-based auth system built with Streamlit.

## Tech Stack
- Python
- Streamlit 
- SQLite3

## Setup

```bash
pip install streamlit
streamlit run app.py
```

## Admin Credentials
- Username: admin
- Password: admin123

## Password Requirements
- Minimum 8 characters
- Must contain at least one letter
- Must contain at least one number  
- Must contain at least one special character (!@#$%^&*)
- Maximum 50 characters

## Username Requirements
- 3-30 characters long
- Only letters, numbers, and underscores allowed
- Case-insensitive (admin = ADMIN = Admin)
- No reserved names (admin, root, administrator, system)

## Features
- Login/Register with enhanced validation
- Role-based access (Admin/Student)
- User management (Admin only)
- Password change with strength requirements
- Input validation and sanitization
- Duplicate username prevention (case-insensitive)
- Reserved username protection
- Comprehensive error handling
- Password requirements display## Team Contributions
- Authentication system
- Database setup 
- UI components
- Role management
- Security validations
