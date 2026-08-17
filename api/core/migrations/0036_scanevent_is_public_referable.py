from django.db import migrations, models


def backfill_public_referable_scans(apps, schema_editor):
    ScanEvent = apps.get_model('core', 'ScanEvent')
    ForumPost = apps.get_model('core', 'ForumPost')
    ForumComment = apps.get_model('core', 'ForumComment')

    import re

    scan_ids = set()
    pattern_attr = re.compile(r'data-scan-ref="(\d+)"')
    pattern_url = re.compile(r'/scan/status/(\d+)/')

    for content in ForumPost.objects.exclude(content__isnull=True).exclude(content='').values_list('content', flat=True).iterator(chunk_size=2000):
        text = content or ''
        scan_ids.update(int(x) for x in pattern_attr.findall(text))
        scan_ids.update(int(x) for x in pattern_url.findall(text))

    for content in ForumComment.objects.exclude(content__isnull=True).exclude(content='').values_list('content', flat=True).iterator(chunk_size=2000):
        text = content or ''
        scan_ids.update(int(x) for x in pattern_attr.findall(text))
        scan_ids.update(int(x) for x in pattern_url.findall(text))

    if scan_ids:
        ScanEvent.objects.filter(id__in=scan_ids).update(is_public_referable=True)


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0035_userprofile_mfa_preferred_method_mfarecoverycode'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanevent',
            name='is_public_referable',
            field=models.BooleanField(
                db_index=True,
                default=False,
                help_text='Bật khi chính chủ đã refer scan ra forum để cho phép người khác xem/refer.',
            ),
        ),
        migrations.RunPython(backfill_public_referable_scans, migrations.RunPython.noop),
    ]
