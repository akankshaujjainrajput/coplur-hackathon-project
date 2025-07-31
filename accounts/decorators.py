# In accounts/decorators.py
from django.shortcuts import redirect

def admin_only(view_func):
    def wrapper_func(request, *args, **kwargs):
        if request.user.profile.role == 'admin':
            # If the user is an admin, let them see the page
            return view_func(request, *args, **kwargs)
        else:
            # If they are not an admin, redirect them away
            return redirect('welcome')
    return wrapper_func