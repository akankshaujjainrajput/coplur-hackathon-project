from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.views import LoginView
from django.contrib import messages
from django.db import IntegrityError, transaction
from django.core.exceptions import ValidationError
from django.http import Http404, HttpResponseForbidden
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator
from django.urls import reverse_lazy
import logging
from .models import Profile
from .decorators import admin_only
from .forms import EnhancedUserCreationForm, AdminUserCreationForm, EnhancedAuthenticationForm

# Set up logging for error tracking
logger = logging.getLogger(__name__)

class EnhancedLoginView(LoginView):
    """Enhanced login view with better error handling and security"""
    form_class = EnhancedAuthenticationForm
    template_name = 'accounts/login.html'
    redirect_authenticated_user = True
    
    def get_success_url(self):
        return reverse_lazy('welcome')
    
    def form_invalid(self, form):
        """Log failed login attempts"""
        username = form.cleaned_data.get('username', 'Unknown')
        logger.warning(f"Failed login attempt for username: {username} from IP: {self.get_client_ip()}")
        return super().form_invalid(form)
    
    def get_client_ip(self):
        """Get client IP address for logging"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip

@csrf_protect
def register_student(request):
    """Enhanced student registration with comprehensive validation"""
    if request.user.is_authenticated:
        messages.info(request, 'You are already logged in.')
        return redirect('welcome')
    
    if request.method == 'POST':
        form = EnhancedUserCreationForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    user = form.save()
                    messages.success(
                        request, 
                        f'Account created successfully for {user.first_name}! You can now log in.'
                    )
                    logger.info(f"New student account created: {user.username}")
                    return redirect('login')
            except IntegrityError as e:
                logger.error(f"Database error during user creation: {str(e)}")
                messages.error(request, 'An error occurred while creating your account. Please try again.')
            except Exception as e:
                logger.error(f"Unexpected error during user registration: {str(e)}")
                messages.error(request, 'An unexpected error occurred. Please try again later.')
        else:
            logger.info(f"Invalid registration form submission from IP: {get_client_ip(request)}")
    else:
        form = EnhancedUserCreationForm()
    
    return render(request, 'accounts/register.html', {'form': form})

@login_required
def welcome_page(request):
    """Enhanced welcome page with error handling"""
    try:
        # Ensure user has a profile
        if not hasattr(request.user, 'profile'):
            Profile.objects.create(user=request.user, role='student')
            logger.warning(f"Created missing profile for user: {request.user.username}")
        
        return render(request, 'accounts/welcome.html')
    except Exception as e:
        logger.error(f"Error in welcome page for user {request.user.username}: {str(e)}")
        messages.error(request, 'An error occurred loading your profile. Please contact support.')
        return render(request, 'accounts/error.html', {'error_message': 'Profile loading error'})

@login_required
@admin_only
def admin_dashboard(request):
    """Enhanced admin dashboard with error handling"""
    try:
        users_count = User.objects.count()
        students_count = Profile.objects.filter(role='student').count()
        admins_count = Profile.objects.filter(role='admin').count()
        
        context = {
            'users_count': users_count,
            'students_count': students_count,
            'admins_count': admins_count,
        }
        return render(request, 'accounts/admin_dashboard.html', context)
    except Exception as e:
        logger.error(f"Error in admin dashboard: {str(e)}")
        messages.error(request, 'Error loading dashboard data.')
        return render(request, 'accounts/error.html', {'error_message': 'Dashboard loading error'})

@login_required
@admin_only
@csrf_protect
def create_user(request):
    """Enhanced user creation with comprehensive validation"""
    if request.method == 'POST':
        form = AdminUserCreationForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    user = form.save()
                    messages.success(
                        request, 
                        f'User "{user.username}" created successfully with role: {user.profile.get_role_display()}'
                    )
                    logger.info(f"Admin {request.user.username} created user: {user.username}")
                    return redirect('admin_dashboard')
            except IntegrityError as e:
                logger.error(f"Database error during admin user creation: {str(e)}")
                messages.error(request, 'Database error occurred. Please check for duplicate entries.')
            except Exception as e:
                logger.error(f"Error creating user: {str(e)}")
                messages.error(request, f'Error creating user: {str(e)}')
        else:
            logger.info(f"Invalid user creation form submission by admin: {request.user.username}")
    else:
        form = AdminUserCreationForm()
    
    return render(request, 'accounts/create_user.html', {'form': form})

@login_required
@admin_only
def list_users(request):
    """Enhanced user listing with error handling and pagination"""
    try:
        users = User.objects.select_related('profile').all().order_by('date_joined')
        return render(request, 'accounts/list_users.html', {'users': users})
    except Exception as e:
        logger.error(f"Error loading users list: {str(e)}")
        messages.error(request, 'Error loading users list.')
        return render(request, 'accounts/error.html', {'error_message': 'Users list loading error'})

@login_required
@admin_only
@require_http_methods(["GET", "POST"])
def delete_user(request, user_id):
    """Enhanced user deletion with comprehensive validation"""
    try:
        user_to_delete = get_object_or_404(User, id=user_id)
    except Http404:
        messages.error(request, 'User not found.')
        return redirect('list_users')
    
    # Security checks
    if user_to_delete == request.user:
        messages.error(request, 'You cannot delete your own account!')
        return redirect('list_users')
    
    # Prevent deletion of last admin
    if (user_to_delete.profile.role == 'admin' and 
        Profile.objects.filter(role='admin').count() <= 1):
        messages.error(request, 'Cannot delete the last admin user!')
        return redirect('list_users')
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                username = user_to_delete.username
                user_to_delete.delete()
                messages.success(request, f'User "{username}" has been deleted successfully.')
                logger.info(f"Admin {request.user.username} deleted user: {username}")
                return redirect('list_users')
        except Exception as e:
            logger.error(f"Error deleting user: {str(e)}")
            messages.error(request, 'An error occurred while deleting the user.')
    
    return render(request, 'accounts/delete_user_confirm.html', {'user_to_delete': user_to_delete})

# Utility functions
def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

# Legacy admin page redirect
@login_required
@admin_only
def admin_page(request):
    """Redirect to new admin dashboard"""
    return redirect('admin_dashboard')

# Custom error handlers
def handle_403(request, exception=None):
    """Custom 403 error handler"""
    return render(request, 'accounts/403.html', status=403)

def handle_404(request, exception=None):
    """Custom 404 error handler"""
    return render(request, 'accounts/404.html', status=404)

def handle_500(request):
    """Custom 500 error handler"""
    return render(request, 'accounts/500.html', status=500)