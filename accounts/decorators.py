from django.shortcuts import redirect
from django.contrib import messages
from django.http import HttpResponseForbidden
from django.core.exceptions import PermissionDenied
import logging

logger = logging.getLogger(__name__)

def admin_only(view_func):
    """
    Enhanced admin-only decorator with better error handling and logging
    """
    def wrapper_func(request, *args, **kwargs):
        # Check if user is authenticated
        if not request.user.is_authenticated:
            messages.error(request, 'You must be logged in to access this page.')
            return redirect('login')
        
        try:
            # Check if user has profile
            if not hasattr(request.user, 'profile'):
                logger.warning(f"User {request.user.username} missing profile")
                messages.error(request, 'Your account profile is incomplete. Please contact support.')
                return redirect('welcome')
            
            # Check if user is admin
            if request.user.profile.role == 'admin':
                return view_func(request, *args, **kwargs)
            else:
                # Log unauthorized access attempt
                logger.warning(
                    f"Unauthorized admin access attempt by user: {request.user.username} "
                    f"from IP: {get_client_ip(request)} to view: {view_func.__name__}"
                )
                messages.error(request, 'You do not have permission to access this page.')
                return redirect('welcome')
                
        except Exception as e:
            logger.error(f"Error in admin_only decorator: {str(e)}")
            messages.error(request, 'An error occurred while checking permissions.')
            return redirect('welcome')
    
    wrapper_func.__name__ = view_func.__name__
    wrapper_func.__doc__ = view_func.__doc__
    return wrapper_func

def student_only(view_func):
    """
    Decorator for student-only views
    """
    def wrapper_func(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.error(request, 'You must be logged in to access this page.')
            return redirect('login')
        
        try:
            if not hasattr(request.user, 'profile'):
                logger.warning(f"User {request.user.username} missing profile")
                messages.error(request, 'Your account profile is incomplete. Please contact support.')
                return redirect('welcome')
            
            if request.user.profile.role == 'student':
                return view_func(request, *args, **kwargs)
            else:
                messages.info(request, 'This page is for students only.')
                return redirect('welcome')
                
        except Exception as e:
            logger.error(f"Error in student_only decorator: {str(e)}")
            messages.error(request, 'An error occurred while checking permissions.')
            return redirect('welcome')
    
    wrapper_func.__name__ = view_func.__name__
    wrapper_func.__doc__ = view_func.__doc__
    return wrapper_func

def get_client_ip(request):
    """Get client IP address for logging"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip