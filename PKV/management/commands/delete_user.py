# myapp/management/commands/delete_user.py
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

class Command(BaseCommand):
    help = "Delete a user by email"

    def add_arguments(self, parser):
        parser.add_argument("email", type=str)

    def handle(self, *args, **options):
        email = options["email"]
        deleted, _ = User.objects.filter(email=email).delete()
        if deleted:
            self.stdout.write(self.style.SUCCESS(f"Deleted user {email}"))
        else:
            self.stdout.write(self.style.WARNING(f"No user found with email {email}"))
