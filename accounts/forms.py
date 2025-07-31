from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate
from .models import Profile
from .validators import validate_username_not_email, validate_no_profanity
import re

class EnhancedUserCreationForm(UserCreationForm):
    """Enhanced student registration form with comprehensive validation"""
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email address'
        }),
        help_text="A valid email address is required."
    )
    first_name = forms.CharField(
        max_length=30, 
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your first name'
        }),
        help_text="Required. 30 characters or fewer."
    )
    last_name = forms.CharField(
        max_length=30, 
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your last name'
        }),
        help_text="Required. 30 characters or fewer."
    )

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add CSS classes and validation attributes
        self.fields['username'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Choose a username',
            'maxlength': '150'
        })
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Create a strong password'
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Confirm your password'
        })
        
        # Add custom validators to username
        self.fields['username'].validators.extend([
            validate_username_not_email,
            validate_no_profanity
        ])

    def clean_username(self):
        username = self.cleaned_data.get('username')
        
        # Check for duplicate username (case-insensitive)
        if User.objects.filter(username__iexact=username).exists():
            raise ValidationError(
                "A user with this username already exists. Please choose a different username."
            )
        
        # Validate username format
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            raise ValidationError(
                "Username can only contain letters, numbers, and underscores."
            )
        
        # Check minimum length
        if len(username) < 3:
            raise ValidationError(
                "Username must be at least 3 characters long."
            )
        
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email')
        
        # Check for duplicate email (case-insensitive)
        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError(
                "An account with this email address already exists."
            )
        
        # Validate email domain (basic check)
        forbidden_domains = ['tempmail.com', '10minutemail.com', 'guerrillamail.com']
        domain = email.split('@')[1].lower() if '@' in email else ''
        if domain in forbidden_domains:
            raise ValidationError(
                "Please use a valid email address from a recognized provider."
            )
        
        return email.lower()

    def clean_first_name(self):
        first_name = self.cleaned_data.get('first_name')
        
        # Check if name contains only letters and spaces
        if not re.match(r'^[a-zA-Z\s]+$', first_name):
            raise ValidationError(
                "First name can only contain letters and spaces."
            )
        
        return first_name.strip().title()

    def clean_last_name(self):
        last_name = self.cleaned_data.get('last_name')
        
        # Check if name contains only letters and spaces
        if not re.match(r'^[a-zA-Z\s]+$', last_name):
            raise ValidationError(
                "Last name can only contain letters and spaces."
            )
        
        return last_name.strip().title()

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        
        if commit:
            user.save()
            Profile.objects.create(user=user, role='student')
        return user

class AdminUserCreationForm(UserCreationForm):
    """Enhanced admin user creation form with role assignment"""
    email = forms.EmailField(required=True)
    first_name = forms.CharField(max_length=30, required=False)
    last_name = forms.CharField(max_length=30, required=False)
    role = forms.ChoiceField(
        choices=[('student', 'Student'), ('admin', 'Admin')],
        initial='student',
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2', 'role')
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add CSS classes for better styling
        for fieldname in ['username', 'first_name', 'last_name', 'email', 'password1', 'password2']:
            self.fields[fieldname].widget.attrs['class'] = 'form-control'

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username__iexact=username).exists():
            raise ValidationError("A user with this username already exists.")
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError("A user with this email already exists.")
        return email.lower()
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        
        if commit:
            user.save()
            Profile.objects.create(
                user=user, 
                role=self.cleaned_data['role']
            )
        return user

class EnhancedAuthenticationForm(AuthenticationForm):
    """Enhanced login form with better error handling"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Enter your username'
        })
        self.fields['password'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Enter your password'
        })

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        if username and password:
            # Check if user exists
            try:
                user = User.objects.get(username__iexact=username)
            except User.DoesNotExist:
                raise ValidationError(
                    "Invalid username or password. Please check your credentials and try again."
                )
            
            # Check if user is active
            if not user.is_active:
                raise ValidationError(
                    "This account has been deactivated. Please contact support."
                )
            
            # Authenticate user
            self.user_cache = authenticate(
                self.request,
                username=username,
                password=password
            )
            
            if self.user_cache is None:
                raise ValidationError(
                    "Invalid username or password. Please check your credentials and try again."
                )

        return self.cleaned_data