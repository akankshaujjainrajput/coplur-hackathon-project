from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.db import IntegrityError
from .models import Profile
from .decorators import admin_only
from .forms import AdminUserCreationForm

def register_student(request):
    """Student registration - only creates student accounts"""
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            try:
                user = form.save()
                Profile.objects.create(user=user, role='student')
                messages.success(request, 'Account created successfully! You can now log in.')
                return redirect('login')
            except IntegrityError:
                messages.error(request, 'Username already exists. Please choose a different username.')
    else:
        form = UserCreationForm()
    return render(request, 'accounts/register.html', {'form': form})

@login_required
def welcome_page(request):
    """Welcome page for all authenticated users"""
    return render(request, 'accounts/welcome.html')

@login_required
@admin_only
def admin_dashboard(request):
    """Main admin dashboard with navigation"""
    users_count = User.objects.count()
    students_count = Profile.objects.filter(role='student').count()
    admins_count = Profile.objects.filter(role='admin').count()
    
    context = {
        'users_count': users_count,
        'students_count': students_count,
        'admins_count': admins_count,
    }
    return render(request, 'accounts/admin_dashboard.html', context)

@login_required
@admin_only
def create_user(request):
    """Admin can create new users with role assignment"""
    if request.method == 'POST':
        form = AdminUserCreationForm(request.POST)
        if form.is_valid():
            try:
                user = form.save()
                messages.success(request, f'User "{user.username}" created successfully with role: {user.profile.role}')
                return redirect('admin_dashboard')
            except Exception as e:
                messages.error(request, f'Error creating user: {str(e)}')
    else:
        form = AdminUserCreationForm()
    
    return render(request, 'accounts/create_user.html', {'form': form})

@login_required
@admin_only
def list_users(request):
    """Display all users with their roles and management options"""
    users = User.objects.select_related('profile').all().order_by('date_joined')
    return render(request, 'accounts/list_users.html', {'users': users})

@login_required
@admin_only
def delete_user(request, user_id):
    """Delete a user (with confirmation)"""
    user_to_delete = get_object_or_404(User, id=user_id)
    
    # Prevent admin from deleting themselves
    if user_to_delete == request.user:
        messages.error(request, 'You cannot delete your own account!')
        return redirect('list_users')
    
    if request.method == 'POST':
        username = user_to_delete.username
        user_to_delete.delete()
        messages.success(request, f'User "{username}" has been deleted successfully.')
        return redirect('list_users')
    
    return render(request, 'accounts/delete_user_confirm.html', {'user_to_delete': user_to_delete})

# Keep the old admin_page for backwards compatibility
@login_required
@admin_only
def admin_page(request):
    """Redirect to new admin dashboard"""
    return redirect('admin_dashboard')