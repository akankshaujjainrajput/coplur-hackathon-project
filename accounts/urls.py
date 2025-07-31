from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # Authentication URLs
    path('login/', auth_views.LoginView.as_view(template_name='accounts/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(template_name='accounts/logout.html'), name='logout'),
    path('register/', views.register_student, name='register'),
    path('welcome/', views.welcome_page, name='welcome'),
    path('password_change/', auth_views.PasswordChangeView.as_view(template_name='accounts/password_change_form.html'), name='password_change'),
    path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(template_name='accounts/password_change_done.html'), name='password_change_done'),
    
    # Admin URLs
    path('admin_dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin/create_user/', views.create_user, name='create_user'),
    path('admin/list_users/', views.list_users, name='list_users'),
    path('admin/delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
    
    # Legacy admin page (redirects to dashboard)
    path('admin_page/', views.admin_page, name='admin_page'),
]