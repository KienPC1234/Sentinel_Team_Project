from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0038_rename_core_webpus_user_id_0eef6c_idx_core_webpus_user_id_65cc10_idx'),
    ]

    operations = [
        migrations.AddField(
            model_name='articlecomment',
            name='parent',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='replies', to='core.articlecomment'),
        ),
    ]
