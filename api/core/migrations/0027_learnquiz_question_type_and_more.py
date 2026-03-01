from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0026_forumcomment_dislikes_count_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='learnquiz',
            name='correct_answers',
            field=models.JSONField(blank=True, default=list, help_text='List of correct choices for multi-select'),
        ),
        migrations.AddField(
            model_name='learnquiz',
            name='question_type',
            field=models.CharField(choices=[('single_choice', 'Chọn 1 đáp án'), ('multiple_choice', 'Chọn nhiều đáp án'), ('true_false', 'Đúng / Sai')], default='single_choice', max_length=30),
        ),
    ]
