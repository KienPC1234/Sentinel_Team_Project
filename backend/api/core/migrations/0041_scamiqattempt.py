from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0040_articlecommentreaction'),
    ]

    operations = [
        migrations.CreateModel(
            name='ScamIQAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('exam_title', models.CharField(default='Scam IQ Exam', max_length=255)),
                ('score', models.IntegerField(default=0)),
                ('max_score', models.IntegerField(default=300)),
                ('correct_count', models.IntegerField(default=0)),
                ('wrong_count', models.IntegerField(default=0)),
                ('level_code', models.CharField(blank=True, max_length=40)),
                ('level_label', models.CharField(blank=True, max_length=120)),
                ('difficulty_breakdown', models.JSONField(blank=True, default=dict)),
                ('mistakes', models.JSONField(blank=True, default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scam_iq_attempts', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Scam IQ Attempt',
                'verbose_name_plural': 'Scam IQ Attempts',
                'ordering': ['-created_at'],
            },
        ),
    ]
