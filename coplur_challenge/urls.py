from django.contrib import admin
from django.urls import path, include # Make sure 'include' is imported
from django.shortcuts import redirect

def home_redirect(request):
    return redirect('login')

urlpatterns = [
    path('', home_redirect, name='home'), 
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
]