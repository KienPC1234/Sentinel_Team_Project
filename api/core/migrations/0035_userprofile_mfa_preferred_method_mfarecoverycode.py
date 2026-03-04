from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0034_webpush_hardening_remove_onesignal'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='mfa_preferred_method',
            field=models.CharField(blank=True, choices=[('totp', 'Authenticator app (TOTP)'), ('email', 'Email OTP')], max_length=10, null=True),
        ),
        migrations.CreateModel(
            name='MFARecoveryCode',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code_hash', models.CharField(db_index=True, max_length=64)),
                ('hint', models.CharField(blank=True, max_length=8)),
                ('is_used', models.BooleanField(db_index=True, default=False)),
                ('used_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='mfa_recovery_codes', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['created_at'],
                'unique_together': {('user', 'code_hash')},
            },
        ),
    ]
