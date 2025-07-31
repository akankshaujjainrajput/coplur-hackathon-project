from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=[('student', 'Student'), ('admin', 'Admin')], default='student')

    def __str__(self):
        return f'{self.user.username} - {self.role}'