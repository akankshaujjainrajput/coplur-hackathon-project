from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from .models import Profile, User
from .decorators import admin_only

def register_student(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        # Check if the form data is valid
        if form.is_valid():
            user = form.save() 
            Profile.objects.create(user=user, role='student') 
            return redirect('login')
   
    else:
        form = UserCreationForm()
    return render(request, 'accounts/register.html', {'form': form})

@login_required
def welcome_page(request):
    return render(request, 'accounts/welcome.html')

@login_required
@admin_only 
def admin_page(request):
    return render(request, 'accounts/admin_page.html')