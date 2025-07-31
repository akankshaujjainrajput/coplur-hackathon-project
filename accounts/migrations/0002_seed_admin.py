# In accounts/migrations/0002_seed_admin.py

from django.db import migrations

def create_initial_admin(apps, schema_editor):
    User = apps.get_model('auth', 'User')
    Profile = apps.get_model('accounts', 'Profile')

    # Create the admin user only if it doesn't already exist
    if not User.objects.filter(username='admin').exists():
        # Create the user with a password.
        # IMPORTANT: Change 'SecureAdminPassword123' to your own secure password.
        admin_user = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='ass230730'
        )
        # Create the user's profile with the 'admin' role.
        Profile.objects.create(user=admin_user, role='admin')

class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0001_initial'),
    ]
    operations = [
        # This line tells Django to run our function
        migrations.RunPython(create_initial_admin),
    ]