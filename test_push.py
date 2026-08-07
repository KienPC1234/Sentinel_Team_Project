#!/usr/bin/env python
"""
Test push notification script.
Sends a test push notification to all users who have a OneSignal Player ID.

Usage:
    python test_push.py                    # Send to all users with player IDs
    python test_push.py --user-id 5        # Send to a specific user
    python test_push.py --list             # List all users with player IDs
"""

import os
import sys
import argparse
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PKV.settings')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
django.setup()

from django.contrib.auth import get_user_model
from api.utils.push_service import push_service

User = get_user_model()


def get_users_with_player_ids():
    """Get all users that have a OneSignal player ID configured."""
    return User.objects.filter(
        profile__onesignal_player_id__isnull=False
    ).exclude(
        profile__onesignal_player_id=''
    ).select_related('profile')


def list_users():
    """List all users with OneSignal player IDs."""
    users = get_users_with_player_ids()
    if not users.exists():
        print("No users with OneSignal Player IDs found.")
        return

    print(f"\n{'ID':<6} {'Username':<20} {'Email':<30} {'Player ID':<40}")
    print("-" * 96)
    for user in users:
        pid = user.profile.onesignal_player_id
        print(f"{user.id:<6} {user.username:<20} {user.email:<30} {pid:<40}")
    print(f"\nTotal: {users.count()} user(s)")


def send_test_push(user_id=None):
    """Send test push notification to user(s)."""
    if user_id:
        try:
            user = User.objects.select_related('profile').get(id=user_id)
        except User.DoesNotExist:
            print(f"User with ID {user_id} not found.")
            return
        users = [user]
    else:
        users = list(get_users_with_player_ids())

    if not users:
        print("No users with OneSignal Player IDs found.")
        return

    print(f"\nSending test push to {len(users)} user(s)...\n")

    success_count = 0
    fail_count = 0

    for user in users:
        player_id = getattr(user.profile, 'onesignal_player_id', None)
        result = push_service.send_push(
            user_id=user.id,
            title="🔔 Test Push Notification",
            message=f"Xin chào {user.username}! Đây là thông báo test từ ShieldCall VN.",
            url="/dashboard/",
            notification_type='info'
        )

        status = "✅ OK" if result else "❌ FAIL"
        pid_display = player_id[:20] + "..." if player_id and len(player_id) > 20 else (player_id or "N/A")
        print(f"  {status}  User #{user.id} ({user.username}) — Player ID: {pid_display}")

        if result:
            success_count += 1
        else:
            fail_count += 1

    print(f"\nDone: {success_count} succeeded, {fail_count} failed out of {len(users)} total.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test push notifications for ShieldCall VN')
    parser.add_argument('--user-id', type=int, help='Send to a specific user ID')
    parser.add_argument('--list', action='store_true', help='List all users with player IDs')
    args = parser.parse_args()

    if args.list:
        list_users()
    else:
        send_test_push(args.user_id)
