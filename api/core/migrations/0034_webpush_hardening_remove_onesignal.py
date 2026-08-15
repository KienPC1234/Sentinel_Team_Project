from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0033_webpushsubscription'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userprofile',
            name='onesignal_player_id',
        ),
        migrations.AlterField(
            model_name='webpushsubscription',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='webpush_subscriptions', to='auth.user'),
        ),
        migrations.AddField(
            model_name='webpushsubscription',
            name='fail_count',
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='webpushsubscription',
            name='last_success_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
