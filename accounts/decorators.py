from django.shortcuts import redirect

def admin_only(view_func):
    def wrapper_func(request, *args, **kwargs):
        if request.user.profile.role == 'admin':
            return view_func(request, *args, **kwargs)
        else:
            return redirect('welcome')
    return wrapper_func