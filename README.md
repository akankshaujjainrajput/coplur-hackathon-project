# Coplur Code Challenge: Role-Based Authentication

A Django web application that supports user authentication, role-based access control, and admin operations, built for the Coplur Code Challenge.

## Tech Stack Used
- Python
- Django
- SQLite

## Features Implemented
- [cite_start]User registration (students only) [cite: 13]
- [cite_start]Login / Logout [cite: 10, 11]
- [cite_start]Change Password [cite: 12]
- [cite_start]Role-based access for "Admin" and "Student" roles [cite: 16, 17]
- [cite_start]Initial admin user created via data seeding [cite: 19]
- [cite_start]Admin-only dashboard for user management [cite: 30]
- [cite_start]Protected routes to block unauthorized access [cite: 36, 42]

## Project Setup Instructions
1. Clone the repository.
2. Install dependencies: `pip install django`
3. Run database migrations to set up the database and seed the admin user: `python manage.py migrate`
4. Start the development server: `python manage.py runserver`
5. Access the site at `http://127.0.0.1:8000/accounts/login/`

## Admin Credentials
- **Username:** admin
- **Password:** YourSecureAdminPassword123 (The one you set in Step 3)

## Team Member Contributions
- **[Your Name]:** Completed all backend and frontend development, project setup, and documentation.