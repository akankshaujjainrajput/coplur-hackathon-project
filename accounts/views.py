# In accounts/views.py
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from .models import Profile, User
from .decorators import admin_only

# The logic for the student registration page
def register_student(request):
    # If the user is submitting the form (POST request)
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        # Check if the form data is valid
        if form.is_valid():
            user = form.save() # Save the new user
            Profile.objects.create(user=user, role='student') # Create their profile with the 'student' role
            return redirect('login') # Redirect them to the login page
    # If the user is just visiting the page (GET request)
    else:
        form = UserCreationForm()
    # Show the registration page with the form
    return render(request, 'accounts/register.html', {'form': form})

# The logic for the welcome page
@login_required
def welcome_page(request):
    return render(request, 'accounts/welcome.html')

# The logic for the admin-only page
@login_required
@admin_only # This protects the page
def admin_page(request):
    return render(request, 'accounts/admin_page.html')