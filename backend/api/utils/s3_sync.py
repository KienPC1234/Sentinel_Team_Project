"""Tiện ích đồng bộ media cục bộ <-> S3 (dùng cho management command & Celery Beat)."""
from __future__ import annotations

import mimetypes
import os
import shutil
import urllib.request
from typing import Callable, Dict, Optional

from django.conf import settings

# Bỏ qua các thư mục không cần đưa lên S3 (chỉ mục vector cục bộ, cache…)
_SKIP_DIRS = {'vector_index', '.cache', '__pycache__'}


def _client():
    import boto3
    from botocore.config import Config

    return boto3.client(
        's3',
        endpoint_url=settings.AWS_S3_ENDPOINT_URL,
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=getattr(settings, 'AWS_S3_REGION_NAME', 'us-east-1'),
        config=Config(s3={'addressing_style': getattr(settings, 'AWS_S3_ADDRESSING_STYLE', 'path')}),
    )


def sync_media_to_s3(
    *,
    media_root: Optional[str] = None,
    bucket: Optional[str] = None,
    prefix: str = '',
    delete: bool = False,
    dry_run: bool = False,
    log: Optional[Callable[[str], None]] = None,
) -> Dict[str, int]:
    """Tải toàn bộ file trong media_root lên bucket (key = đường dẫn tương đối).

    Trả về thống kê {uploaded, skipped, deleted, errors}.
    """
    media_root = media_root or str(settings.MEDIA_ROOT)
    bucket = bucket or settings.AWS_STORAGE_BUCKET_NAME
    say = log or (lambda _m: None)

    s3 = _client()
    acl = getattr(settings, 'AWS_DEFAULT_ACL', 'public-read') or 'public-read'

    # Danh sách object đang có trên S3 (giới hạn theo prefix nếu cần)
    existing = {}
    try:
        paginator = s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get('Contents', []):
                existing[obj['Key']] = obj['Size']
    except Exception as exc:
        say(f"[warn] Không liệt kê được S3: {exc}")

    uploaded = skipped = deleted = errors = 0
    local_keys = set()

    for root, dirs, files in os.walk(media_root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, media_root).replace('\\', '/')
            key = f"{prefix}{rel}" if prefix else rel
            local_keys.add(key)
            size = os.path.getsize(path)
            if existing.get(key) == size:
                skipped += 1
                continue
            if dry_run:
                say(f"[dry] put {key} ({size}B)")
                uploaded += 1
                continue
            try:
                ctype = mimetypes.guess_type(name)[0] or 'application/octet-stream'
                s3.upload_file(path, bucket, key, ExtraArgs={'ContentType': ctype, 'ACL': acl})
                uploaded += 1
            except Exception as exc:
                errors += 1
                say(f"[error] {key}: {exc}")

    if delete:
        for key in list(existing.keys()):
            if key in local_keys:
                continue
            if dry_run:
                say(f"[dry] delete {key}")
                deleted += 1
                continue
            try:
                s3.delete_object(Bucket=bucket, Key=key)
                deleted += 1
            except Exception as exc:
                errors += 1
                say(f"[error] delete {key}: {exc}")

    return {'uploaded': uploaded, 'skipped': skipped, 'deleted': deleted, 'errors': errors}


def storage_status() -> Dict[str, object]:
    """Trạng thái storage hiện tại (không lộ khoá bí mật)."""
    media_backend = settings.STORAGES.get('default', {}).get('BACKEND', '')
    static_backend = settings.STORAGES.get('staticfiles', {}).get('BACKEND', '')
    using_s3 = media_backend.endswith('S3Storage')
    info: Dict[str, object] = {
        'media_backend': media_backend.split('.')[-1],
        'static_backend': static_backend.split('.')[-1],
        'media_url': settings.MEDIA_URL,
        'static_url': settings.STATIC_URL,
        'using_s3': using_s3,
        'bucket': getattr(settings, 'AWS_STORAGE_BUCKET_NAME', None) if using_s3 else None,
        'endpoint': getattr(settings, 'AWS_S3_ENDPOINT_URL', None) if using_s3 else None,
        'public_domain': getattr(settings, 'AWS_S3_CUSTOM_DOMAIN', None) if using_s3 else None,
    }
    if using_s3:
        try:
            s3 = _client()
            s3.head_bucket(Bucket=info['bucket'])
            info['s3_reachable'] = True
        except Exception as exc:
            info['s3_reachable'] = False
            info['s3_error'] = str(exc)[:200]
    return info


# ──────────────────────────────────────────────────────────────────────────
# Backup / restore chỉ mục vector (vector_store) lên object storage
# ──────────────────────────────────────────────────────────────────────────
def _vector_dir() -> str:
    from django.conf import settings as _s
    return os.path.join(str(_s.BASE_DIR), 'vector_store')


def backup_vector_store(bucket: Optional[str] = None, prefix: str = 'vector_store') -> Dict[str, int]:
    """Tải các file chỉ mục (scam_index.faiss, metadata.pkl, embedding_cache.pkl) lên bucket nội bộ (private)."""
    if not getattr(settings, 'AWS_S3_ENDPOINT_URL', ''):
        return {'uploaded': 0, 'skipped': 0, 'errors': 0, 'configured': 0}
    bucket = bucket or getattr(settings, 'AWS_S3_INTERNAL_BUCKET', f"{settings.AWS_STORAGE_BUCKET_NAME}-internal")
    d = _vector_dir()
    s3 = _client()
    acl = getattr(settings, 'AWS_DEFAULT_ACL', 'public-read') or 'public-read'
    uploaded = skipped = errors = 0
    if not os.path.isdir(d):
        return {'uploaded': 0, 'skipped': 0, 'errors': 0, 'configured': 1}
    for name in os.listdir(d):
        path = os.path.join(d, name)
        if not os.path.isfile(path):
            continue
        key = f"{prefix}/{name}"
        try:
            s3.head_object(Bucket=bucket, Key=key)
            # so sánh kích thước để tránh upload lại
            if s3.head_object(Bucket=bucket, Key=key).get('ContentLength') == os.path.getsize(path):
                skipped += 1
                continue
        except Exception:
            pass
        try:
            ctype = mimetypes.guess_type(name)[0] or 'application/octet-stream'
            # Chỉ mục là artifact nội bộ → để PRIVATE (không public-read); restore dùng quyền đã xác thực.
            s3.upload_file(path, bucket, key, ExtraArgs={'ContentType': ctype, 'ACL': 'private'})
            uploaded += 1
        except Exception:
            errors += 1
    return {'uploaded': uploaded, 'skipped': skipped, 'errors': errors, 'configured': 1}


def restore_vector_store(bucket: Optional[str] = None, prefix: str = 'vector_store') -> bool:
    """Khôi phục chỉ mục từ S3 nếu thiếu file cục bộ (dùng quyền đã xác thực / presigned).

    Trả True nếu có tải về.
    """
    if not getattr(settings, 'AWS_S3_ENDPOINT_URL', ''):
        return False
    bucket = bucket or getattr(settings, 'AWS_S3_INTERNAL_BUCKET', f"{settings.AWS_STORAGE_BUCKET_NAME}-internal")
    d = _vector_dir()
    os.makedirs(d, exist_ok=True)
    s3 = _client()
    restored = False
    try:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=f"{prefix}/")
        for obj in resp.get('Contents', []):
            name = obj['Key'].split('/')[-1]
            if not name:
                continue
            local = os.path.join(d, name)
            if os.path.exists(local) and os.path.getsize(local) == obj['Size']:
                continue
            # vector_store là private → tải qua presigned URL (có xác thực của client).
            try:
                url = s3.generate_presigned_url('get_object', Params={'Bucket': bucket, 'Key': obj['Key']}, ExpiresIn=300)
                with urllib.request.urlopen(url, timeout=60) as r, open(local, 'wb') as fh:
                    shutil.copyfileobj(r, fh)
            except Exception:
                # Fallback: tải trực tiếp bằng quyền client.
                s3.download_file(bucket, obj['Key'], local)
            restored = True
    except Exception:
        return False
    return restored
