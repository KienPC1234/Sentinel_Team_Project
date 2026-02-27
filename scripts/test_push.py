#!/usr/bin/env python
"""
Test WebPush script for browser notifications.

Default mode sends WebPush directly to subscriptions (Service Worker/browser notification),
so it does not rely on WebSocket toast delivery.

Usage:
    python scripts/test_push.py                      # Send to all users with active subscriptions
    python scripts/test_push.py --user-id 5          # Send to a specific user
    python scripts/test_push.py --list               # List users with active subscriptions
    python scripts/test_push.py --mode auto          # Use app default delivery logic (WS/WebPush)
"""

import os
import sys
import argparse
from pathlib import Path

import django
from django.utils import timezone

# Setup Django environment
BASE_DIR = Path(__file__).resolve().parents[1]
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PKV.settings')
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
django.setup()

from django.contrib.auth import get_user_model
from api.core.models import WebPushSubscription
from api.utils.push_service import push_service, PushNotificationService

User = get_user_model()


def get_users_with_webpush():
    """Get users that have at least one active web push subscription."""
    user_ids = WebPushSubscription.objects.filter(is_active=True, user__isnull=False).values_list('user_id', flat=True).distinct()
    return User.objects.filter(id__in=user_ids)


def list_users():
    """List users that have active web push subscriptions."""
    users = get_users_with_webpush()
    if not users.exists():
        print("No users with active WebPush subscriptions found.")
        return

    print(f"\n{'ID':<6} {'Username':<20} {'Email':<30} {'Active subs':<12}")
    print("-" * 78)
    for user in users:
        sub_count = WebPushSubscription.objects.filter(user=user, is_active=True).count()
        print(f"{user.id:<6} {user.username:<20} {user.email:<30} {sub_count:<12}")
    print(f"\nTotal: {users.count()} user(s)")


def send_test_push(user_id=None, mode='browser'):
    """Send test push notification to user(s)."""
    if user_id:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            print(f"User with ID {user_id} not found.")
            return
        users = [user]
    else:
        users = list(get_users_with_webpush())

    if not users:
        print("No users with active WebPush subscriptions found.")
        return

    print(f"\nSending test push to {len(users)} user(s)... mode={mode}\n")

    success_count = 0
    fail_count = 0

    for user in users:
        title = "🔔 Test Push Notification"
        message = f"Xin chào {user.username}! Đây là thông báo test từ ShieldCall VN."
        url = "/dashboard/"
        notification_type = 'info'

        if mode == 'auto':
            result = push_service.send_push(
                user_id=user.id,
                title=title,
                message=message,
                url=url,
                notification_type=notification_type,
            )
        else:
            # Browser mode: send direct WebPush to each active subscription to show native notification.
            subscriptions = list(WebPushSubscription.objects.filter(user=user, is_active=True))
            sent = 0
            fail_reasons = []
            for subscription in subscriptions:
                ok, error_text, status_code = PushNotificationService.send_webpush(
                    subscription=subscription,
                    payload={
                        'title': title,
                        'body': message,
                        'message': message,
                        'url': url,
                        'notification_type': notification_type,
                        'tag': f'test-push-{user.id}',
                        'icon': '/static/logo.png',
                    },
                    ttl=3600,
                )
                if ok:
                    sent += 1
                    subscription.fail_count = 0
                    subscription.last_error = ''
                    subscription.last_success_at = timezone.now()
                    subscription.last_used_at = timezone.now()
                    subscription.is_active = True
                    subscription.save(update_fields=['fail_count', 'last_error', 'last_success_at', 'last_used_at', 'is_active', 'updated_at'])
                else:
                    reason = f"status={status_code} error={error_text[:180]}"
                    fail_reasons.append(reason)
                    subscription.last_error = error_text
                    if status_code in (404, 410):
                        subscription.is_active = False
                        subscription.save(update_fields=['is_active', 'last_error', 'updated_at'])
                    else:
                        subscription.fail_count = (subscription.fail_count or 0) + 1
                        if subscription.fail_count >= 5:
                            subscription.is_active = False
                        subscription.save(update_fields=['fail_count', 'is_active', 'last_error', 'updated_at'])
            result = sent > 0
            if not result and fail_reasons:
                print(f"     ↳ WebPush errors: {' | '.join(fail_reasons)}")
                if any('status=401' in r or 'status=403' in r for r in fail_reasons):
                    print("     ↳ Hint: subscription đang lệch VAPID key hiện tại. Hãy unsubscribe/subscribe lại trên trình duyệt rồi test lại.")

        status = "✅ OK" if result else "❌ FAIL"
        sub_count = WebPushSubscription.objects.filter(user=user, is_active=True).count()
        print(f"  {status}  User #{user.id} ({user.username}) — Active subs: {sub_count}")

        if result:
            success_count += 1
        else:
            fail_count += 1

    print(f"\nDone: {success_count} succeeded, {fail_count} failed out of {len(users)} total.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test WebPush notifications for ShieldCall VN')
    parser.add_argument('--user-id', type=int, help='Send to a specific user ID')
    parser.add_argument('--list', action='store_true', help='List all users with active subscriptions')
    parser.add_argument('--mode', choices=['browser', 'auto'], default='browser',
                        help='browser=direct WebPush (native browser notification), auto=app delivery logic')
    args = parser.parse_args()

    if args.list:
        list_users()
    else:
        send_test_push(args.user_id, args.mode)
