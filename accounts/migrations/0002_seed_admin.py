from django.db import migrations

def create_initial_admin(apps, schema_editor):
    User = apps.get_model('auth', 'User')
    Profile = apps.get_model('accounts', 'Profile')

    if not User.objects.filter(username='admin').exists():
        admin_user = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='ass230730'
        )
        Profile.objects.create(user=admin_user, role='admin')

class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0001_initial'),
    ]
    operations = [
        migrations.RunPython(create_initial_admin),
    ]