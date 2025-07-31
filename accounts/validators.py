import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

class StrongPasswordValidator:
    """
    Custom password validator for strong password policies
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter  
    - At least one digit
    - At least one special character
    """
    
    def __init__(self, min_length=8):
        self.min_length = min_length
    
    def validate(self, password, user=None):
        if len(password) < self.min_length:
            raise ValidationError(
                _("Password must be at least %(min_length)d characters long."),
                code='password_too_short',
                params={'min_length': self.min_length},
            )
        
        if not re.search(r'[A-Z]', password):
            raise ValidationError(
                _("Password must contain at least one uppercase letter."),
                code='password_no_upper',
            )
        
        if not re.search(r'[a-z]', password):
            raise ValidationError(
                _("Password must contain at least one lowercase letter."),
                code='password_no_lower',
            )
        
        if not re.search(r'\d', password):
            raise ValidationError(
                _("Password must contain at least one digit."),
                code='password_no_digit',
            )
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError(
                _("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)."),
                code='password_no_special',
            )
    
    def get_help_text(self):
        return _(
            "Your password must be at least %(min_length)d characters long and contain "
            "at least one uppercase letter, one lowercase letter, one digit, and one special character."
        ) % {'min_length': self.min_length}

def validate_username_not_email(value):
    """Prevent users from using email addresses as usernames"""
    if '@' in value:
        raise ValidationError(
            _("Username cannot be an email address. Please choose a different username."),
            code='username_is_email'
        )

def validate_no_profanity(value):
    """Basic profanity filter for usernames"""
    profanity_list = ['admin', 'root', 'administrator', 'moderator', 'staff', 'api', 'www', 'ftp', 'mail']
    if value.lower() in profanity_list:
        raise ValidationError(
            _("This username is not allowed. Please choose a different username."),
            code='username_not_allowed'
        )