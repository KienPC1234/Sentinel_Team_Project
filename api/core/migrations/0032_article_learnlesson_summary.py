from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0031_add_announcement_dm_ticket'),
    ]

    operations = [
        migrations.AddField(
            model_name='article',
            name='summary',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AddField(
            model_name='learnlesson',
            name='summary',
            field=models.TextField(blank=True, default=''),
        ),
    ]
